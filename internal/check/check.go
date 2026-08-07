package check

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1337lean/certpulse/internal/textsafe"
	"golang.org/x/crypto/ocsp"
)

const MaxTargets = 1000

type Endpoint struct {
	Input      string `json:"input"`
	Address    string `json:"address"`
	ServerName string `json:"serverName"`
}

type Result struct {
	Target         string   `json:"target"`
	Address        string   `json:"address"`
	Status         string   `json:"status"`
	Errors         []string `json:"errors,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	Subject        string   `json:"subject,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	DNSNames       int      `json:"dnsNames,omitempty"`
	NotBefore      string   `json:"notBefore,omitempty"`
	NotAfter       string   `json:"notAfter,omitempty"`
	DaysRemaining  float64  `json:"daysRemaining,omitempty"`
	Fingerprint    string   `json:"sha256Fingerprint,omitempty"`
	TLSVersion     string   `json:"tlsVersion,omitempty"`
	CipherSuite    string   `json:"cipherSuite,omitempty"`
	VerifiedChains int      `json:"verifiedChains,omitempty"`
	OCSPStapled    bool     `json:"ocspStapled"`
	DurationMillis int64    `json:"durationMillis"`
}

type Options struct {
	Timeout        time.Duration
	Concurrency    int
	WarnBefore     time.Duration
	CriticalBefore time.Duration
	MinTLS         uint16
	RequireOCSP    bool
	Roots          *x509.CertPool
	Now            func() time.Time
	DialContext    func(context.Context, string, string) (net.Conn, error)
}

func ParseEndpoint(input string) (Endpoint, error) {
	if textsafe.HasControl(input) {
		return Endpoint{}, errors.New("target contains a control character")
	}
	original := input
	if original == "" {
		return Endpoint{}, errors.New("empty target")
	}
	if strings.IndexFunc(original, func(r rune) bool { return r == ' ' || r > 127 }) >= 0 {
		if strings.IndexFunc(original, func(r rune) bool { return r > 127 }) >= 0 {
			return Endpoint{}, errors.New("unicode hostnames are not accepted; use their ASCII IDNA form")
		}
		return Endpoint{}, errors.New("target contains whitespace")
	}
	hostport := original
	if strings.Contains(original, "://") {
		u, err := url.Parse(original)
		if err != nil {
			return Endpoint{}, err
		}
		if strings.ToLower(u.Scheme) != "https" {
			return Endpoint{}, errors.New("only https URLs are accepted")
		}
		if u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
			return Endpoint{}, errors.New("URL must not contain credentials, path, query, or fragment")
		}
		hostport = u.Host
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") && net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")) != nil {
			host, port = hostport[1:len(hostport)-1], "443"
		} else if net.ParseIP(hostport) != nil {
			host, port = hostport, "443"
		} else if strings.Contains(hostport, ":") {
			return Endpoint{}, fmt.Errorf("invalid host:port: %w", err)
		} else {
			host, port = hostport, "443"
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return Endpoint{}, errors.New("host is empty")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Endpoint{}, errors.New("port must be between 1 and 65535")
	}
	serverName := strings.TrimSuffix(host, ".")
	if net.ParseIP(serverName) == nil {
		if err := validateHostname(serverName); err != nil {
			return Endpoint{}, err
		}
	}
	return Endpoint{Input: original, Address: net.JoinHostPort(host, strconv.Itoa(portNumber)), ServerName: serverName}, nil
}

func validateHostname(host string) error {
	if len(host) > 253 {
		return errors.New("hostname exceeds 253 bytes")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("hostname contains an empty or oversized label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("hostname labels must not begin or end with a hyphen")
		}
		for _, c := range []byte(label) {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return errors.New("hostname contains a character outside letters, digits, dots, and hyphens")
		}
	}
	return nil
}

func Run(ctx context.Context, endpoints []Endpoint, opts Options) []Result {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.Concurrency > 32 {
		opts.Concurrency = 32
	}
	if opts.WarnBefore == 0 {
		opts.WarnBefore = 30 * 24 * time.Hour
	}
	if opts.CriticalBefore == 0 {
		opts.CriticalBefore = 7 * 24 * time.Hour
	}
	if opts.MinTLS == 0 {
		opts.MinTLS = tls.VersionTLS12
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.DialContext == nil {
		dialer := &net.Dialer{Timeout: opts.Timeout}
		opts.DialContext = dialer.DialContext
	}
	results := make([]Result, len(endpoints))
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := opts.Concurrency
	if workers > len(endpoints) {
		workers = len(endpoints)
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				results[index] = one(ctx, endpoints[index], opts)
			}
		}()
	}
	for i := range endpoints {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

func one(parent context.Context, endpoint Endpoint, opts Options) Result {
	start := time.Now()
	result := Result{Target: endpoint.Input, Address: endpoint.Address, Status: "ok"}
	ctx, cancel := context.WithTimeout(parent, opts.Timeout)
	defer cancel()
	raw, err := opts.DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		result.Errors = []string{"connect: " + safeError(err)}
		result.Status = "critical"
		result.DurationMillis = time.Since(start).Milliseconds()
		return result
	}
	defer raw.Close()
	config := &tls.Config{ServerName: endpoint.ServerName, MinVersion: opts.MinTLS, RootCAs: opts.Roots}
	conn := tls.Client(raw, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		result.Errors = []string{"TLS handshake: " + safeError(err)}
		result.Status = "critical"
		result.DurationMillis = time.Since(start).Milliseconds()
		return result
	}
	state := conn.ConnectionState()
	result.TLSVersion = tlsVersion(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.VerifiedChains = len(state.VerifiedChains)
	result.OCSPStapled = len(state.OCSPResponse) > 0
	if len(state.PeerCertificates) == 0 {
		result.Errors = append(result.Errors, "peer sent no certificate")
		result.Status = "critical"
	} else {
		cert := state.PeerCertificates[0]
		now := opts.Now().UTC()
		result.Subject = cert.Subject.String()
		result.Issuer = cert.Issuer.String()
		result.DNSNames = len(cert.DNSNames)
		result.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
		result.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		result.DaysRemaining = cert.NotAfter.Sub(now).Hours() / 24
		sum := sha256.Sum256(cert.Raw)
		result.Fingerprint = hex.EncodeToString(sum[:])
		if now.Before(cert.NotBefore) {
			result.Errors = append(result.Errors, "certificate is not yet valid")
		}
		remaining := cert.NotAfter.Sub(now)
		if remaining <= 0 {
			result.Errors = append(result.Errors, "certificate has expired")
		} else if remaining <= opts.CriticalBefore {
			result.Errors = append(result.Errors, "certificate expires inside critical window")
		} else if remaining <= opts.WarnBefore {
			result.Warnings = append(result.Warnings, "certificate expires inside warning window")
		}
	}
	if opts.RequireOCSP {
		if !result.OCSPStapled {
			result.Errors = append(result.Errors, "server did not staple an OCSP response")
		} else if err := validateOCSP(state, opts.Now().UTC()); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
	}
	if len(result.Errors) > 0 {
		result.Status = "critical"
	} else if len(result.Warnings) > 0 {
		result.Status = "warning"
	}
	sort.Strings(result.Errors)
	sort.Strings(result.Warnings)
	result.DurationMillis = time.Since(start).Milliseconds()
	return result
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
func safeError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS lookup failed"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(err, context.DeadlineExceeded) || opErr.Timeout() {
			return "connection timed out"
		}
		return opErr.Op + " failed"
	}
	text := err.Error()
	if len(text) > 240 {
		text = text[:240]
	}
	return textsafe.Terminal(text)
}

func validateOCSP(state tls.ConnectionState, now time.Time) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("cannot validate the OCSP staple without a leaf certificate")
	}
	leaf := state.PeerCertificates[0]
	issuer := certificateIssuer(state, leaf)
	if issuer == nil {
		return errors.New("cannot validate the OCSP staple without the leaf certificate issuer")
	}
	parsed, err := ocsp.ParseResponse(state.OCSPResponse, nil)
	if err != nil {
		return errors.New("stapled OCSP response is malformed or unsuccessful")
	}
	if parsed.SerialNumber == nil || parsed.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		return errors.New("stapled OCSP response belongs to a different certificate")
	}
	response, err := ocsp.ParseResponseForCert(state.OCSPResponse, leaf, issuer)
	if err != nil {
		return errors.New("stapled OCSP response does not validate for the leaf certificate and issuer")
	}
	switch response.Status {
	case ocsp.Good:
	case ocsp.Revoked:
		return errors.New("stapled OCSP response reports the certificate as revoked")
	case ocsp.Unknown:
		return errors.New("stapled OCSP response reports the certificate status as unknown")
	default:
		return errors.New("stapled OCSP response has an unsupported certificate status")
	}
	if response.ThisUpdate.IsZero() || response.ThisUpdate.After(now) {
		return errors.New("stapled OCSP response is not yet valid")
	}
	if !response.ProducedAt.IsZero() && response.ProducedAt.After(now) {
		return errors.New("stapled OCSP response was produced in the future")
	}
	if response.NextUpdate.IsZero() {
		return errors.New("stapled OCSP response has no expiry time")
	}
	if response.NextUpdate.Before(now) {
		return errors.New("stapled OCSP response is stale")
	}
	return nil
}

func certificateIssuer(state tls.ConnectionState, leaf *x509.Certificate) *x509.Certificate {
	for _, chain := range state.VerifiedChains {
		if len(chain) > 1 && chain[0].Equal(leaf) && leaf.CheckSignatureFrom(chain[1]) == nil {
			return chain[1]
		}
	}
	for _, candidate := range state.PeerCertificates[1:] {
		if leaf.CheckSignatureFrom(candidate) == nil {
			return candidate
		}
	}
	return nil
}

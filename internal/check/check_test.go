package check

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestParseEndpoint(t *testing.T) {
	tests := map[string]string{
		"example.com":          "example.com:443",
		"example.com:8443":     "example.com:8443",
		"https://example.com/": "example.com:443",
		"127.0.0.1":            "127.0.0.1:443",
		"[::1]":                "[::1]:443",
		"[::1]:9443":           "[::1]:9443",
	}
	for input, want := range tests {
		got, err := ParseEndpoint(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if got.Address != want {
			t.Fatalf("%s: got %s want %s", input, got.Address, want)
		}
	}
	for _, bad := range []string{
		"http://example.com",
		"https://user:pass@example.com",
		"https://example.com/path",
		"example.com:99999",
		"bad host",
		"bad\\host",
		"bad\"host",
		"-bad.example",
		"bad_.example",
		"täst.example",
	} {
		if _, err := ParseEndpoint(bad); err == nil {
			t.Errorf("expected rejection for %q", bad)
		}
	}
}

func TestParseEndpointRejectsC0AndC1Controls(t *testing.T) {
	for name, control := range map[string]string{
		"newline":  "\n",
		"carriage": "\r",
		"tab":      "\t",
		"escape":   "\x1b",
		"nul":      "\x00",
		"del":      "\x7f",
		"c1":       "\u0085",
	} {
		t.Run(name, func(t *testing.T) {
			for _, target := range []string{"example" + control + ".com", control + "example.com", "example.com" + control} {
				if _, err := ParseEndpoint(target); err == nil || !strings.Contains(err.Error(), "control") {
					t.Fatalf("target %q error=%v", target, err)
				}
			}
		})
	}
}

func TestParseEndpointIDNAExpectations(t *testing.T) {
	endpoint, err := ParseEndpoint("xn--tst-qla.example")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.ServerName != "xn--tst-qla.example" {
		t.Fatalf("server name=%q", endpoint.ServerName)
	}
}

func TestRunTrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	endpoint, err := ParseEndpoint(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	results := Run(context.Background(), []Endpoint{endpoint}, Options{Timeout: time.Second, Roots: pool, WarnBefore: 365 * 24 * time.Hour, CriticalBefore: 24 * time.Hour})
	if len(results) != 1 || results[0].Status != "ok" || results[0].TLSVersion == "" || results[0].Fingerprint == "" {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunTrustFailureDoesNotExposeAddressDetails(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	endpoint, _ := ParseEndpoint(server.URL)
	result := Run(context.Background(), []Endpoint{endpoint}, Options{Timeout: time.Second})[0]
	if result.Status != "critical" || len(result.Errors) == 0 || !strings.Contains(result.Errors[0], "TLS handshake") {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestRunConnectionFailures(t *testing.T) {
	endpoint := Endpoint{Input: "example.com", Address: "example.com:443", ServerName: "example.com"}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"DNS", &net.DNSError{Name: "attacker\nname", Err: "no such host"}, "DNS lookup failed"},
		{"refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, "dial failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Run(context.Background(), []Endpoint{endpoint}, Options{
				Timeout: time.Second,
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					return nil, test.err
				},
			})[0]
			if result.Status != "critical" || len(result.Errors) != 1 || !strings.Contains(result.Errors[0], test.want) {
				t.Fatalf("result=%#v", result)
			}
			if strings.Contains(result.Errors[0], "attacker") {
				t.Fatalf("network text leaked into error: %q", result.Errors[0])
			}
		})
	}
}

func TestRunHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	endpoint := Endpoint{Input: "127.0.0.1", Address: listener.Addr().String(), ServerName: "127.0.0.1"}
	result := Run(context.Background(), []Endpoint{endpoint}, Options{
		Timeout: 30 * time.Millisecond,
	})[0]
	select {
	case conn := <-accepted:
		conn.Close()
	default:
	}
	if result.Status != "critical" || len(result.Errors) != 1 || !strings.Contains(strings.ToLower(result.Errors[0]), "timeout") && !strings.Contains(strings.ToLower(result.Errors[0]), "deadline") {
		t.Fatalf("result=%#v", result)
	}
}

func TestRunHostnameMismatch(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	endpoint, _ := ParseEndpoint(server.URL)
	endpoint.ServerName = "mismatch.invalid"
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	result := Run(context.Background(), []Endpoint{endpoint}, Options{Timeout: time.Second, Roots: pool})[0]
	if result.Status != "critical" || len(result.Errors) == 0 || !strings.Contains(result.Errors[0], "TLS handshake") {
		t.Fatalf("result=%#v", result)
	}
}

func TestRunExpiryThresholds(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	endpoint, _ := ParseEndpoint(server.URL)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	base := Options{Timeout: time.Second, Roots: pool, WarnBefore: 48 * time.Hour, CriticalBefore: 12 * time.Hour}

	base.Now = func() time.Time { return server.Certificate().NotAfter.Add(-24 * time.Hour) }
	warning := Run(context.Background(), []Endpoint{endpoint}, base)[0]
	if warning.Status != "warning" || len(warning.Warnings) != 1 {
		t.Fatalf("warning result=%#v", warning)
	}
	base.Now = func() time.Time { return server.Certificate().NotAfter.Add(-6 * time.Hour) }
	critical := Run(context.Background(), []Endpoint{endpoint}, base)[0]
	if critical.Status != "critical" || len(critical.Errors) != 1 {
		t.Fatalf("critical result=%#v", critical)
	}
}

func TestRunProtocolFloorAndWeakCipherPolicy(t *testing.T) {
	for _, test := range []struct {
		name         string
		serverConfig func(*tls.Config)
		clientMin    uint16
	}{
		{
			name: "protocol floor",
			serverConfig: func(config *tls.Config) {
				config.MaxVersion = tls.VersionTLS12
			},
			clientMin: tls.VersionTLS13,
		},
		{
			name: "weak cipher only",
			serverConfig: func(config *tls.Config) {
				config.MinVersion = tls.VersionTLS12
				config.MaxVersion = tls.VersionTLS12
				config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}
			},
			clientMin: tls.VersionTLS12,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(nil)
			server.TLS = &tls.Config{}
			test.serverConfig(server.TLS)
			server.StartTLS()
			defer server.Close()
			endpoint, _ := ParseEndpoint(server.URL)
			pool := x509.NewCertPool()
			pool.AddCert(server.Certificate())
			result := Run(context.Background(), []Endpoint{endpoint}, Options{Timeout: time.Second, Roots: pool, MinTLS: test.clientMin})[0]
			if result.Status != "critical" || len(result.Errors) == 0 || !strings.Contains(result.Errors[0], "TLS handshake") {
				t.Fatalf("result=%#v", result)
			}
		})
	}
}

func TestRequireOCSPValidationWithTLSFixtures(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer, issuerKey, leaf, leafKey := testCertificateChain(t, now)
	otherIssuer, otherIssuerKey, _, _ := testCertificateChain(t, now)
	otherSerial := new(big.Int).Add(leaf.SerialNumber, big.NewInt(1))
	tests := []struct {
		name     string
		staple   func() []byte
		wantOK   bool
		wantText string
	}{
		{"absent", func() []byte { return nil }, false, "did not staple"},
		{"malformed", func() []byte { return []byte("not DER") }, false, "malformed"},
		{"successful current", func() []byte {
			return testOCSPResponse(t, issuer, issuerKey, leaf.SerialNumber, ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
		}, true, ""},
		{"revoked", func() []byte {
			return testOCSPResponse(t, issuer, issuerKey, leaf.SerialNumber, ocsp.Revoked, now.Add(-time.Hour), now.Add(time.Hour))
		}, false, "revoked"},
		{"unknown", func() []byte {
			return testOCSPResponse(t, issuer, issuerKey, leaf.SerialNumber, ocsp.Unknown, now.Add(-time.Hour), now.Add(time.Hour))
		}, false, "unknown"},
		{"stale", func() []byte {
			return testOCSPResponse(t, issuer, issuerKey, leaf.SerialNumber, ocsp.Good, now.Add(-2*time.Hour), now.Add(-time.Hour))
		}, false, "stale"},
		{"future dated", func() []byte {
			return testOCSPResponse(t, issuer, issuerKey, leaf.SerialNumber, ocsp.Good, now.Add(time.Hour), now.Add(2*time.Hour))
		}, false, "not yet valid"},
		{"wrong certificate", func() []byte {
			return testOCSPResponse(t, issuer, issuerKey, otherSerial, ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
		}, false, "different certificate"},
		{"wrong issuer", func() []byte {
			return testOCSPResponse(t, otherIssuer, otherIssuerKey, leaf.SerialNumber, ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
		}, false, "does not validate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := testTLSServer(t, issuer, leaf, leafKey, test.staple(), nil)
			defer server.Close()
			endpoint, err := ParseEndpoint(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			pool := x509.NewCertPool()
			pool.AddCert(issuer)
			result := Run(context.Background(), []Endpoint{endpoint}, Options{
				Timeout:        time.Second,
				Roots:          pool,
				RequireOCSP:    true,
				WarnBefore:     6 * time.Hour,
				CriticalBefore: time.Hour,
				Now:            func() time.Time { return now },
			})[0]
			if test.wantOK {
				if result.Status != "ok" || len(result.Errors) != 0 || !result.OCSPStapled {
					t.Fatalf("result=%#v", result)
				}
				return
			}
			if result.Status != "critical" || len(result.Errors) == 0 || !strings.Contains(strings.Join(result.Errors, " "), test.wantText) {
				t.Fatalf("result=%#v, want %q", result, test.wantText)
			}
		})
	}
}

func testCertificateChain(t *testing.T, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Certpulse Test Root"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-12 * time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, issuerKey, leaf, leafKey
}

func testOCSPResponse(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, serial *big.Int, status int, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	response, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
		Status:       status,
		SerialNumber: serial,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		RevokedAt:    thisUpdate,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func testTLSServer(t *testing.T, issuer, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, staple []byte, mutate func(*tls.Config)) *httptest.Server {
	t.Helper()
	certificate := tls.Certificate{
		Certificate: [][]byte{leaf.Raw, issuer.Raw},
		PrivateKey:  leafKey,
		Leaf:        leaf,
		OCSPStaple:  staple,
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	if mutate != nil {
		mutate(server.TLS)
	}
	server.StartTLS()
	return server
}

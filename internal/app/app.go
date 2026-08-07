package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/1337lean/certpulse/internal/check"
	output "github.com/1337lean/certpulse/internal/report"
	"github.com/1337lean/certpulse/internal/textsafe"
)

const (
	maxCABundleBytes int64 = 4 << 20
	maxTargetBytes   int64 = 1 << 20
)

func Run(args []string, stdout, stderr io.Writer, version string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			fmt.Fprintln(stdout, version)
			return 0
		case "help", "--help", "-h":
			usage(stdout)
			return 0
		case "check":
			args = args[1:]
		}
	}
	fs := flag.NewFlagSet("certpulse", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetsFile, format, caFile, minTLS := "", "human", "", "1.2"
	var timeout, warn, critical time.Duration
	var concurrency int
	var failWarning, requireOCSP, caOnly bool
	fs.StringVar(&targetsFile, "targets", "", "target file")
	fs.StringVar(&format, "format", format, "human, json, or prometheus")
	fs.StringVar(&caFile, "ca-file", "", "regular PEM CA bundle (maximum 4 MiB)")
	fs.StringVar(&minTLS, "min-tls", minTLS, "1.2 or 1.3")
	durationVar(fs, &timeout, "timeout", 10*time.Second, "per-target timeout")
	durationVar(fs, &warn, "warn-before", 30*24*time.Hour, "expiration warning window")
	durationVar(fs, &critical, "critical-before", 7*24*time.Hour, "critical expiration window")
	fs.IntVar(&concurrency, "concurrency", 8, "parallel checks (1-32)")
	fs.BoolVar(&failWarning, "fail-on-warning", false, "return 1 for warnings")
	fs.BoolVar(&requireOCSP, "require-ocsp", false, "require a valid, current, successful OCSP staple for the leaf certificate")
	fs.BoolVar(&caOnly, "ca-only", false, "trust only --ca-file roots")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if format != "human" && format != "json" && format != "prometheus" {
		fmt.Fprintln(stderr, "certpulse: invalid format")
		return 2
	}
	if timeout <= 0 || warn <= 0 || critical <= 0 || critical > warn || concurrency < 1 || concurrency > 32 {
		fmt.Fprintln(stderr, "certpulse: invalid timeout, expiration windows, or concurrency")
		return 2
	}
	minVersion := uint16(tls.VersionTLS12)
	if minTLS == "1.3" {
		minVersion = tls.VersionTLS13
	} else if minTLS != "1.2" {
		fmt.Fprintln(stderr, "certpulse: min-tls must be 1.2 or 1.3")
		return 2
	}
	inputs := append([]string(nil), fs.Args()...)
	if targetsFile != "" {
		fileInputs, err := readTargets(targetsFile)
		if err != nil {
			fmt.Fprintf(stderr, "certpulse: read targets: %s\n", textsafe.Terminal(err.Error()))
			return 3
		}
		inputs = append(inputs, fileInputs...)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(stderr, "certpulse: at least one target is required")
		return 2
	}
	if len(inputs) > check.MaxTargets {
		fmt.Fprintf(stderr, "certpulse: target count exceeds %d\n", check.MaxTargets)
		return 2
	}
	seen := map[string]bool{}
	endpoints := make([]check.Endpoint, 0, len(inputs))
	for _, input := range inputs {
		endpoint, err := check.ParseEndpoint(input)
		if err != nil {
			fmt.Fprintf(stderr, "certpulse: %s: %v\n", textsafe.Terminal(input), err)
			return 2
		}
		key := strings.ToLower(endpoint.Address + "|" + endpoint.ServerName)
		if seen[key] {
			fmt.Fprintf(stderr, "certpulse: duplicate target %s\n", textsafe.Terminal(input))
			return 2
		}
		seen[key] = true
		endpoints = append(endpoints, endpoint)
	}
	roots, err := loadRoots(caFile, caOnly)
	if err != nil {
		fmt.Fprintf(stderr, "certpulse: load roots: %v\n", err)
		return 3
	}
	results := check.Run(context.Background(), endpoints, check.Options{Timeout: timeout, Concurrency: concurrency, WarnBefore: warn, CriticalBefore: critical, MinTLS: minVersion, RequireOCSP: requireOCSP, Roots: roots})
	switch format {
	case "human":
		err = output.Human(stdout, results)
	case "json":
		err = output.JSON(stdout, results)
	case "prometheus":
		err = output.Prometheus(stdout, results)
	}
	if err != nil {
		fmt.Fprintf(stderr, "certpulse: write output: %v\n", err)
		return 3
	}
	for _, r := range results {
		if r.Status == "critical" || failWarning && r.Status == "warning" {
			return 1
		}
	}
	return 0
}

func readTargets(path string) ([]string, error) {
	f, err := openInputFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("target file does not exist")
		}
		return nil, errors.New("target file cannot be opened for reading")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("opened target file cannot be inspected")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("target file is not a regular file")
	}
	if info.Size() > maxTargetBytes {
		return nil, errors.New("target file is larger than 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTargetBytes+1))
	if err != nil {
		return nil, errors.New("target file cannot be read")
	}
	if int64(len(data)) > maxTargetBytes {
		return nil, errors.New("target file is larger than 1 MiB")
	}
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, scanner.Err()
}
func loadRoots(path string, only bool) (*x509.CertPool, error) {
	return loadRootsAfterOpen(path, only, nil)
}

// loadRootsAfterOpen exists so the Unix regression test can replace the path
// after it is opened and prove that all subsequent operations use the descriptor.
func loadRootsAfterOpen(path string, only bool, afterOpen func()) (*x509.CertPool, error) {
	if path == "" {
		if only {
			return nil, errors.New("--ca-only requires --ca-file")
		}
		return nil, nil
	}
	f, err := openInputFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("CA file does not exist")
		}
		return nil, errors.New("CA file cannot be opened for reading")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("opened CA file cannot be inspected")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("CA file is not a regular file")
	}
	if info.Size() > maxCABundleBytes {
		return nil, errors.New("CA file exceeds 4 MiB")
	}
	if afterOpen != nil {
		afterOpen()
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCABundleBytes+1))
	if err != nil {
		return nil, errors.New("CA file cannot be read")
	}
	if int64(len(data)) > maxCABundleBytes {
		return nil, errors.New("CA file exceeds 4 MiB")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("CA file is empty")
	}
	var pool *x509.CertPool
	if only {
		pool = x509.NewCertPool()
	} else {
		pool, err = x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
	}
	if err := appendCABundle(pool, data); err != nil {
		return nil, err
	}
	return pool, nil
}

func appendCABundle(pool *x509.CertPool, data []byte) error {
	rest := bytes.TrimSpace(data)
	count := 0
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("CA file is not a valid PEM certificate bundle")
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("CA file is not a valid PEM certificate bundle")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("CA file contains an invalid certificate")
		}
		pool.AddCert(cert)
		count++
		rest = bytes.TrimSpace(remaining)
	}
	if count == 0 {
		return errors.New("CA file contains no certificates")
	}
	return nil
}

type durationValue time.Duration

func durationVar(fs *flag.FlagSet, target *time.Duration, name string, value time.Duration, help string) {
	*target = value
	fs.Var((*durationValue)(target), name, help)
}

func (value *durationValue) Set(text string) error {
	parsed, err := parseDuration(text)
	if err != nil {
		return err
	}
	*value = durationValue(parsed)
	return nil
}

func (value *durationValue) String() string {
	if value == nil {
		return ""
	}
	return time.Duration(*value).String()
}

func parseDuration(value string) (time.Duration, error) {
	dayIndex := strings.IndexByte(value, 'd')
	if dayIndex < 0 {
		return time.ParseDuration(value)
	}
	if strings.Count(value, "d") != 1 || dayIndex == 0 {
		return 0, fmt.Errorf("invalid duration %q", value)
	}
	days, err := strconv.ParseInt(value[:dayIndex], 10, 64)
	if err != nil || days > int64(^uint64(0)>>1)/int64(24*time.Hour) || days < -int64(^uint64(0)>>1)/int64(24*time.Hour) {
		return 0, fmt.Errorf("invalid duration %q", value)
	}
	result := time.Duration(days) * 24 * time.Hour
	if remainder := value[dayIndex+1:]; remainder != "" {
		extra, err := time.ParseDuration(remainder)
		if err != nil || extra > 0 && result > time.Duration(1<<63-1)-extra || extra < 0 && result < time.Duration(-1<<63)-extra {
			return 0, fmt.Errorf("invalid duration %q", value)
		}
		result += extra
	}
	return result, nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: certpulse [check] [flags] TARGET ...
       certpulse version

Targets: IPv4, ASCII/IDNA hostname, host:port, raw or bracketed IPv6, or an HTTPS URL.

Key flags:
  --targets FILE        read additional targets from a regular file
  --format FORMAT       human, json, or prometheus (default human)
  --ca-file FILE        regular PEM CA bundle, maximum 4 MiB
  --ca-only             trust only roots from --ca-file
  --require-ocsp        require a valid, current, successful OCSP staple for the leaf
  --min-tls VERSION     1.2 or 1.3 (default 1.2)
  --timeout DURATION    per-target timeout; d, h, m, s supported (default 10s)
  --warn-before DURATION
  --critical-before DURATION
  --concurrency NUMBER  parallel checks, 1-32 (default 8)
  --fail-on-warning     return exit code 1 for warnings`)
}

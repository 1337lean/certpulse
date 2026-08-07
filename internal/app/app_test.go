package app

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUsageErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(nil, &out, &errOut, "test"); code != 2 || !strings.Contains(errOut.String(), "target") {
		t.Fatalf("code=%d err=%s", code, errOut.String())
	}
	errOut.Reset()
	if code := Run([]string{"--min-tls", "1.1", "example.com"}, &out, &errOut, "test"); code != 2 {
		t.Fatalf("code=%d", code)
	}
}
func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if Run([]string{"version"}, &out, &out, "2.0.0") != 0 || strings.TrimSpace(out.String()) != "2.0.0" {
		t.Fatal(out.String())
	}
}

func TestHelpDocumentsStrongOCSPAndCALimit(t *testing.T) {
	var output bytes.Buffer
	if code := Run([]string{"--help"}, &output, &output, "test"); code != 0 {
		t.Fatalf("code=%d", code)
	}
	for _, want := range []string{"valid, current, successful OCSP", "maximum 4 MiB", "ASCII/IDNA"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("help does not contain %q: %s", want, output.String())
		}
	}
}

func TestParseDurationSupportsDocumentedDays(t *testing.T) {
	for input, want := range map[string]time.Duration{
		"30d":    30 * 24 * time.Hour,
		"7d12h":  7*24*time.Hour + 12*time.Hour,
		"90m":    90 * time.Minute,
		"-1d":    -24 * time.Hour,
		"1d-12h": 12 * time.Hour,
	} {
		got, err := parseDuration(input)
		if err != nil || got != want {
			t.Errorf("parseDuration(%q)=%v, %v; want %v", input, got, err, want)
		}
	}
	for _, input := range []string{"d", "1dd", "1.5d", "999999999999999999d", "1dnope"} {
		if _, err := parseDuration(input); err == nil {
			t.Errorf("expected %q to be rejected", input)
		}
	}
}

func TestLoadRootsAcceptsBoundedRegularPEM(t *testing.T) {
	path := writeTestCertificate(t)
	pool, err := loadRoots(path, true)
	if err != nil {
		t.Fatal(err)
	}
	want := x509.NewCertPool()
	want.AddCert(readCertificate(t, path))
	if !pool.Equal(want) {
		t.Fatal("loaded pool does not contain exactly the test certificate")
	}
}

func TestReadTargetsBoundedRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("# comment\n\n example.com \n[::1]:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "example.com,[::1]:443" {
		t.Fatalf("targets=%q", got)
	}

	oversized := filepath.Join(t.TempDir(), "oversized.txt")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), int(maxTargetBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]string{
		"missing":   filepath.Join(t.TempDir(), "missing"),
		"directory": t.TempDir(),
		"oversized": oversized,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readTargets(invalid); err == nil {
				t.Fatalf("expected %s to be rejected", invalid)
			}
		})
	}
}

func TestLoadRootsRejectsInvalidInputs(t *testing.T) {
	oversized := filepath.Join(t.TempDir(), "oversized.pem")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), int(maxCABundleBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(t.TempDir(), "malformed.pem")
	if err := os.WriteFile(malformed, []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validWithJunk := filepath.Join(t.TempDir(), "junk.pem")
	validPEM, err := os.ReadFile(writeTestCertificate(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(validWithJunk, append(validPEM, []byte("trailing junk")...), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{"missing", filepath.Join(t.TempDir(), "missing.pem"), "does not exist"},
		{"directory", t.TempDir(), "not a regular file"},
		{"oversized", oversized, "exceeds 4 MiB"},
		{"empty", empty, "is empty"},
		{"malformed", malformed, "not a valid PEM"},
		{"trailing data", validWithJunk, "not a valid PEM"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadRoots(test.path, true)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestLoadRootsOptionErrors(t *testing.T) {
	if _, err := loadRoots("", true); err == nil || !strings.Contains(err.Error(), "requires --ca-file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCAPathControlCharactersAreNotReflected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "missing\n\x1b.pem")
	if code := Run([]string{"--ca-file", path, "example.com"}, &stdout, &stderr, "test"); code != 3 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if strings.ContainsRune(stderr.String(), '\x1b') || strings.Count(stderr.String(), "\n") != 1 {
		t.Fatalf("unsafe error output: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), path) {
		t.Fatalf("raw path was reflected: %q", stderr.String())
	}
}

func TestRunExitCodesAndFormats(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	caPath := writeCertificate(t, server.Certificate())
	warnBefore := time.Until(server.Certificate().NotAfter) + 24*time.Hour
	base := []string{"--ca-file", caPath, "--warn-before", warnBefore.String(), "--critical-before", "1h", server.URL}

	for _, format := range []string{"human", "json", "prometheus"} {
		t.Run(format+" critical", func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"--format", format, server.URL}, &stdout, &stderr, "test"); code != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
		t.Run(format+" writer failure", func(t *testing.T) {
			var stderr bytes.Buffer
			if code := Run(append([]string{"--format", format}, base...), failWriter{}, &stderr, "test"); code != 3 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
		})
	}

	var stdout, stderr bytes.Buffer
	if code := Run(base, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("warning code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(append([]string{"--fail-on-warning"}, base...), &stdout, &stderr, "test"); code != 1 {
		t.Fatalf("fail-on-warning code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func writeTestCertificate(t *testing.T) string {
	t.Helper()
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	return writeCertificate(t, server.Certificate())
}

func writeCertificate(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("test certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

var _ io.Writer = failWriter{}

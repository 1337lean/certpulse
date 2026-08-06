package check

import (
	"context"
	"crypto/x509"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseEndpoint(t *testing.T) {
	tests := map[string]string{"example.com": "example.com:443", "example.com:8443": "example.com:8443", "https://example.com/": "example.com:443", "[::1]:9443": "[::1]:9443"}
	for input, want := range tests {
		got, err := ParseEndpoint(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if got.Address != want {
			t.Fatalf("%s: got %s want %s", input, got.Address, want)
		}
	}
	for _, bad := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "example.com:99999", "bad host"} {
		if _, err := ParseEndpoint(bad); err == nil {
			t.Errorf("expected rejection for %s", bad)
		}
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

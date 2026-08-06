package app

import (
	"bytes"
	"strings"
	"testing"
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

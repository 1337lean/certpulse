package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/1337lean/certpulse/internal/check"
)

func TestHumanRendersStatusesAndEscapesUntrustedText(t *testing.T) {
	results := []check.Result{
		{Target: "ok.example", Status: "ok", DaysRemaining: 30.25, TLSVersion: "TLS 1.3", Subject: "CN=safe\n\x1b[31m"},
		{Target: "warn.example", Status: "warning", Warnings: []string{"expires soon"}},
		{Target: "bad\ntarget", Status: "critical", Errors: []string{"failed\rnow"}},
	}
	var output bytes.Buffer
	if err := Human(&output, results); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Count(got, "\n") != len(results) {
		t.Fatalf("each result must occupy one line: %q", got)
	}
	for _, want := range []string{"OK", "30.2 days", `CN=safe\n\x1b[31m`, "WARNING", "expires soon", `bad\ntarget`, `failed\rnow`} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q does not contain %q", got, want)
		}
	}
}

func TestJSONSummaryAndEscaping(t *testing.T) {
	results := sampleResults()
	var output bytes.Buffer
	if err := JSON(&output, results); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Version int            `json:"version"`
		Summary map[string]int `json:"summary"`
		Results []check.Result `json:"results"`
	}
	if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, output.String())
	}
	if payload.Version != 1 || payload.Summary["ok"] != 1 || payload.Summary["warning"] != 1 || payload.Summary["critical"] != 1 || len(payload.Results) != 3 {
		t.Fatalf("payload=%#v", payload)
	}
}

func TestPrometheusEscapesLabelValues(t *testing.T) {
	results := []check.Result{{
		Target:        "line\nquote\"slash\\tab\treturn\r",
		Status:        "ok",
		Fingerprint:   "abc",
		DaysRemaining: 12.5,
	}}
	var output bytes.Buffer
	if err := Prometheus(&output, results); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Contains(got, "line\nquote") || strings.ContainsRune(got, '\t') || strings.ContainsRune(got, '\r') {
		t.Fatalf("metrics contain raw control characters: %q", got)
	}
	if !strings.Contains(got, `target="line\nquote\"slash\\tab�return�"`) {
		t.Fatalf("label was not encoded using Prometheus escapes: %q", got)
	}
	if strings.Count(got, "certpulse_status{") != 1 || strings.Count(got, "certpulse_days_remaining{") != 1 {
		t.Fatalf("unexpected samples: %q", got)
	}
}

func TestReportWriterFailures(t *testing.T) {
	for name, write := range map[string]func() error{
		"human":      func() error { return Human(reportFailWriter{}, sampleResults()) },
		"json":       func() error { return JSON(reportFailWriter{}, sampleResults()) },
		"prometheus": func() error { return Prometheus(reportFailWriter{}, sampleResults()) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := write(); err == nil || !strings.Contains(err.Error(), "forced") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func sampleResults() []check.Result {
	return []check.Result{
		{Target: "ok.example", Status: "ok", Fingerprint: "one", DaysRemaining: 10},
		{Target: "warn.example", Status: "warning", Warnings: []string{"warning"}},
		{Target: "critical.example", Status: "critical", Errors: []string{"critical"}},
	}
}

type reportFailWriter struct{}

func (reportFailWriter) Write([]byte) (int, error) { return 0, errors.New("forced write failure") }

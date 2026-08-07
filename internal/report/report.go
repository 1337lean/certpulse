package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/1337lean/certpulse/internal/check"
	"github.com/1337lean/certpulse/internal/textsafe"
)

func Human(w io.Writer, results []check.Result) error {
	for _, r := range results {
		detail := fmt.Sprintf("%.1f days, %s, %s", r.DaysRemaining, r.TLSVersion, r.Subject)
		if r.Status == "critical" {
			detail = strings.Join(r.Errors, "; ")
		} else if r.Status == "warning" {
			detail = strings.Join(r.Warnings, "; ")
		}
		if _, err := fmt.Fprintf(w, "%-8s %-32s %s\n", strings.ToUpper(r.Status), textsafe.Terminal(r.Target), textsafe.Terminal(detail)); err != nil {
			return err
		}
	}
	return nil
}
func JSON(w io.Writer, results []check.Result) error {
	summary := map[string]int{"ok": 0, "warning": 0, "critical": 0}
	for _, r := range results {
		summary[r.Status]++
	}
	payload := map[string]any{"version": 1, "summary": summary, "results": results}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}
func Prometheus(w io.Writer, results []check.Result) error {
	if _, err := io.WriteString(w, "# HELP certpulse_status Endpoint status: 0 ok, 1 warning, 2 critical.\n# TYPE certpulse_status gauge\n# HELP certpulse_days_remaining Days until leaf certificate expiry.\n# TYPE certpulse_days_remaining gauge\n"); err != nil {
		return err
	}
	for _, r := range results {
		status := 0
		if r.Status == "warning" {
			status = 1
		} else if r.Status == "critical" {
			status = 2
		}
		label := prometheusLabel(r.Target)
		if _, err := fmt.Fprintf(w, "certpulse_status{target=%s} %d\n", label, status); err != nil {
			return err
		}
		if r.Fingerprint != "" {
			if _, err := fmt.Fprintf(w, "certpulse_days_remaining{target=%s} %.6f\n", label, r.DaysRemaining); err != nil {
				return err
			}
		}
	}
	return nil
}

func prometheusLabel(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString("\\\\")
		case '"':
			b.WriteString("\\\"")
		case '\n':
			b.WriteString("\\n")
		default:
			if r < 0x20 || r >= 0x7f && r <= 0x9f {
				b.WriteRune('\uFFFD')
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

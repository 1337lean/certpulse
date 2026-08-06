package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/1337lean/certpulse/internal/check"
	output "github.com/1337lean/certpulse/internal/report"
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
	fs.StringVar(&caFile, "ca-file", "", "PEM CA bundle")
	fs.StringVar(&minTLS, "min-tls", minTLS, "1.2 or 1.3")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "per-target timeout")
	fs.DurationVar(&warn, "warn-before", 30*24*time.Hour, "expiration warning window")
	fs.DurationVar(&critical, "critical-before", 7*24*time.Hour, "critical expiration window")
	fs.IntVar(&concurrency, "concurrency", 8, "parallel checks (1-32)")
	fs.BoolVar(&failWarning, "fail-on-warning", false, "return 1 for warnings")
	fs.BoolVar(&requireOCSP, "require-ocsp", false, "require stapled OCSP response")
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
			fmt.Fprintf(stderr, "certpulse: read targets: %v\n", err)
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
			fmt.Fprintf(stderr, "certpulse: %s: %v\n", input, err)
			return 2
		}
		key := strings.ToLower(endpoint.Address + "|" + endpoint.ServerName)
		if seen[key] {
			fmt.Fprintf(stderr, "certpulse: duplicate target %s\n", input)
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
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("target file must be regular and no larger than 1 MiB")
	}
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, scanner.Err()
}
func loadRoots(path string, only bool) (*x509.CertPool, error) {
	if path == "" {
		if only {
			return nil, errors.New("--ca-only requires --ca-file")
		}
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 4<<20 {
		return nil, errors.New("CA file exceeds 4 MiB")
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
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA file contains no certificates")
	}
	return pool, nil
}
func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: certpulse [check] [flags] TARGET ...\n       certpulse version")
}

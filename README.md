# Certpulse

[![CI](https://github.com/1337lean/certpulse/actions/workflows/ci.yml/badge.svg)](https://github.com/1337lean/certpulse/actions/workflows/ci.yml)
[![Release](https://github.com/1337lean/certpulse/actions/workflows/release.yml/badge.svg)](https://github.com/1337lean/certpulse/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/1337lean/certpulse.svg)](https://pkg.go.dev/github.com/1337lean/certpulse)

Certpulse is a single-binary Go CLI for batch TLS certificate and protocol checks. It verifies trust and hostname binding, reports expiration windows and negotiated TLS details, supports private CAs, and emits human, JSON, or Prometheus output for CI and monitoring.

## Install

Requires Go 1.25.

```sh
go install github.com/1337lean/certpulse/cmd/certpulse@latest
```

## Quick start

```sh
certpulse example.com api.example.com:8443 https://status.example.com
certpulse --targets endpoints.txt --warn-before 30d --critical-before 7d
certpulse --format json --min-tls 1.3 example.com
certpulse --ca-file internal-ca.pem internal.service:443
```

Run `certpulse --help` for all options. `--require-ocsp` enables validity checking, not a presence-only test.
Durations accept Go units (`h`, `m`, `s`, and smaller) plus a leading integer day component such as `30d` or `7d12h`.

Target files must be regular files no larger than 1 MiB and contain one endpoint per line, with blank lines and `#` comments ignored. Targets may be IPv4 addresses, ASCII hostnames, `host:port`, raw or bracketed IPv6 addresses, or `https://` URLs. Unicode hostnames must be supplied in their ASCII IDNA form (for example, `xn--...`). URL paths, queries, fragments, credentials, and non-HTTPS schemes are rejected because Certpulse checks a TLS endpoint—not an HTTP resource. C0, DEL, C1, whitespace, quotes, and backslashes are rejected so a target cannot forge terminal or metrics output.

## Checks

- Full system or custom-root chain verification and exact hostname validation.
- Certificate not-before/not-after windows, SHA-256 fingerprint, issuer, subject, and SAN count.
- Negotiated TLS version and cipher suite with a configurable minimum protocol.
- Optional requirement for a valid OCSP staple that is signed for the leaf and its issuer, reports `good`, is already valid, and has not expired.
- Bounded parallelism, per-target deadlines, stable input ordering, and duplicate rejection.

Statuses are `ok`, `warning`, and `critical`. Connection, trust, hostname, protocol, not-yet-valid, and critical-expiration failures are critical. The warning window is configurable. Exit code `1` is returned for critical results, or warnings too when `--fail-on-warning` is used.

Prometheus output exposes status and days remaining without certificate subjects or target-derived label injection. See [operations](docs/operations.md) and [threat model](docs/threat-model.md).

Custom CA bundles must be regular PEM files no larger than 4 MiB. Certpulse opens a bundle once, validates the opened descriptor, and performs a bounded read so a replaced path cannot redirect the read.

## Development

```sh
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go run github.com/goreleaser/goreleaser/v2@v2.17.0 check
go build ./cmd/certpulse
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report defects with [GitHub Issues](https://github.com/1337lean/certpulse/issues); report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

MIT. Dependency license notices are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and included in release archives.

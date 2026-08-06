# Certpulse

Certpulse is a dependency-free Go CLI for batch TLS certificate and protocol checks. It verifies trust and hostname binding, reports expiration windows and negotiated TLS details, supports private CAs, and emits human, JSON, or Prometheus output for CI and monitoring.

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

Target files contain one endpoint per line with blank lines and `#` comments ignored. Targets may be hostnames, `host:port`, bracketed IPv6 addresses, or `https://` URLs. URL paths, queries, fragments, credentials, and non-HTTPS schemes are rejected because Certpulse checks a TLS endpoint—not an HTTP resource.

## Checks

- Full system or custom-root chain verification and exact hostname validation.
- Certificate not-before/not-after windows, SHA-256 fingerprint, issuer, subject, and SAN count.
- Negotiated TLS version and cipher suite with a configurable minimum protocol.
- Optional requirement for a stapled OCSP response.
- Bounded parallelism, per-target deadlines, stable input ordering, and duplicate rejection.

Statuses are `ok`, `warning`, and `critical`. Connection, trust, hostname, protocol, not-yet-valid, and critical-expiration failures are critical. The warning window is configurable. Exit code `1` is returned for critical results, or warnings too when `--fail-on-warning` is used.

Prometheus output exposes status and days remaining without certificate subjects or target-derived label injection. See [operations](docs/operations.md) and [threat model](docs/threat-model.md).

## Development

```sh
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/certpulse
```

## License

MIT

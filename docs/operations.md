# Operations

Run Certpulse from a scheduler before certificate renewal becomes urgent. A typical policy uses a 30-day warning and 7-day critical window. JSON is appropriate for CI artifacts; Prometheus text can be written to a node-exporter textfile directory using an atomic shell-side rename.

Endpoints are checked concurrently but results retain input order. Use a small `--concurrency` when querying constrained private services. `--timeout` covers dialing and the TLS handshake for each endpoint.

Target lists must be regular files no larger than 1 MiB. Certpulse validates the opened descriptor and bounds the read, so a path replacement or growing file cannot redirect or enlarge the input.

Custom CA files must be regular files containing only valid PEM certificate blocks and are limited to 4 MiB. The limit applies to the bytes read as well as initial file metadata. They are appended to the system root pool by default; use `--ca-only` to trust only the supplied roots.

`--require-ocsp` is a validity policy, not a presence check. The TLS peer must staple a parseable, successful response for the leaf certificate and its issuer. The response must report `good`; `ThisUpdate` must not be in the future; and a nonzero `NextUpdate` must not be in the past. Absent, malformed, revoked, unknown, premature, stale, and certificate-mismatched responses make the target critical.

Targets accept IPv4, raw or bracketed IPv6, ASCII DNS hostnames, an optional port, and HTTPS URLs without credentials or resource components. Convert internationalized names to ASCII IDNA form before passing them to Certpulse. Control characters, whitespace, quotes, and backslashes are rejected.

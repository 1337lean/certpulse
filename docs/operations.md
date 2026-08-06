# Operations

Run Certpulse from a scheduler before certificate renewal becomes urgent. A typical policy uses a 30-day warning and 7-day critical window. JSON is appropriate for CI artifacts; Prometheus text can be written to a node-exporter textfile directory using an atomic shell-side rename.

Endpoints are checked concurrently but results retain input order. Use a small `--concurrency` when querying constrained private services. `--timeout` covers dialing and the TLS handshake for each endpoint.

Custom CA files must contain PEM certificates and are limited to 4 MiB. They are appended to the system root pool by default; use `--ca-only` to trust only the supplied roots.

# Threat model

Certpulse connects only to endpoints explicitly supplied by its operator. It performs certificate-chain and hostname verification, imposes timeouts, bounds target counts and concurrency, and does not send application data after the TLS handshake.

It does not validate certificate-transparency inclusion, fetch OCSP responses when a server does not staple one, check CRLs, assess application health, or validate DNSSEC. With `--require-ocsp`, a staple is verified against the leaf and issuer and checked for a successful, current `good` status. Network observers can see destination addresses and TLS metadata. Treat a custom CA file as security-sensitive configuration.

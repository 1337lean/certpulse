# Threat model

Certpulse connects only to endpoints explicitly supplied by its operator. It performs certificate-chain and hostname verification, imposes timeouts, bounds target counts and concurrency, and does not send application data after the TLS handshake.

It does not validate certificate-transparency inclusion, revocation beyond optional OCSP stapling, application health, or DNSSEC. Network observers can see destination addresses and TLS metadata. Treat a custom CA file as security-sensitive configuration.

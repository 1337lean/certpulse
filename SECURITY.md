# Security policy

Report vulnerabilities privately through GitHub Security Advisories. Include the target form and certificate metadata needed to reproduce the issue, but do not share private keys.

Certpulse always performs normal hostname and trust-chain verification. It intentionally has no insecure-skip-verification option. A custom CA file expands trust only for that invocation.

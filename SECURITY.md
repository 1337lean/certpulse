# Security policy

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/1337lean/certpulse/security/advisories/new). Do not open a public issue for a suspected vulnerability. Include the target form and certificate metadata needed to reproduce the issue, but do not share private keys.

Certpulse always performs normal hostname and trust-chain verification. It intentionally has no insecure-skip-verification option. A custom CA file expands trust only for that invocation.

The latest release receives security fixes. Maintainers will acknowledge a report as soon as practical, coordinate remediation and disclosure with the reporter, and publish an advisory when users need to take action.

# Safety Charter

1. Every test requires ownership or explicit written authorization.
2. Do not include public targets, real credentials, session tokens, or API keys in challenges, tests, reports, or examples.
3. The default mode is `dry-run`; checks must be low impact.
4. Credential theft, phishing, authentication bypass, malware, persistence, stealth, public scanning, and service disruption are prohibited.
5. Labs must be local or private, isolated, and populated with synthetic data.
6. Operations should record the operator, target, time, and result without storing secrets.
7. Every daily improvement must be documented, tested, and reviewed before merging.
8. If a real vulnerability is discovered, stop testing and follow coordinated disclosure with the system owner.

## Disclaimer

Mugin is an educational defensive tool. It is not a phishing toolkit and is not intended to reproduce `zphisher.sh` or any credential-harvesting workflow. The project deliberately excludes deceptive login pages, credential collection, authentication bypass, malware, persistence, stealth, public targeting, and destructive actions.

The operator is solely responsible for obtaining authorization, isolating the lab, protecting test data, and complying with applicable law. No feature in this repository grants permission to test a third-party system.

## Daily challenge: Defensive Security Headers

This challenge reviews a learner-supplied mapping of HTTP response headers from a local lab. It makes no network requests and does not print or persist header values. It checks for `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and `Permissions-Policy`, then provides low-impact remediation guidance. Use synthetic data or data from a lab you own. Never include session tokens, API keys, passwords, or other secrets.

## Daily challenge: Cookie Flags Review

This challenge reviews learner-supplied, synthetic `Set-Cookie` lines entirely offline. It checks only for the presence of `Secure`, `HttpOnly`, and `SameSite` attributes, never makes a network request, and never includes cookie names or values in findings. Use placeholder values in an isolated lab; do not paste real session cookies, tokens, or credentials.

## Daily challenge: Authentication Policy Review

This challenge reviews a small mapping of synthetic policy settings entirely offline: minimum password length, whether multi-factor authentication is required, and the account lockout threshold. It never accepts, compares, logs, or stores passwords, tokens, usernames, or other credentials. Use only placeholder configuration values from an isolated lab.

## Daily challenge: CORS Policy Review

This challenge reviews synthetic CORS settings entirely offline. It checks whether a wildcard origin is used, especially alongside credentialed requests, and recommends an explicit origin for a local lab. It makes no network requests, does not inspect browser traffic, and never accepts cookies, tokens, or credentials. Use placeholder values only and keep the lab isolated.

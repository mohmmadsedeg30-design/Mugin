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

## Daily challenge: CSRF Policy Review

This challenge reviews only synthetic CSRF configuration values: whether server-side protection is enabled, whether expected-origin checking is enabled, and whether a session cookie uses `SameSite=Lax` or `SameSite=Strict`. It never accepts CSRF tokens, cookies, passwords, or session data, and it makes no network requests. Use placeholder settings from an isolated local lab; do not paste real request data or secrets.

## Daily challenge: Audit Logging Policy Review

This challenge reviews only synthetic audit-logging settings: whether logging is enabled, whether retention is bounded, whether secrets are excluded, and whether the sink is local. It never accepts log entries, passwords, tokens, cookies, authorization headers, or network destinations, and it makes no network requests. Use placeholder settings from an isolated lab and keep any real operational logs out of the challenge.

## Daily challenge: Data Minimization Policy Review

This challenge reviews only synthetic privacy settings: whether collection is minimized, whether PII redaction is enabled, and whether external exports are disabled. It never accepts personal records, identifiers, log entries, destinations, passwords, tokens, or cookies, and it makes no network requests. Use boolean settings from an isolated lab and keep all real user data outside the challenge.

## Daily challenge: Rate-Limiting Policy Review

This challenge reviews only synthetic rate-limiting settings: whether limits are enabled, whether requests per minute and burst size are bounded, and whether limits use a non-sensitive synthetic client scope. It never receives traffic, client identifiers, IP addresses, credentials, or network destinations, and it makes no network requests. Use placeholder numbers from an isolated local lab; this challenge does not generate load or attempt to evade a limit.

## Daily challenge: Least-Privilege Policy Review

This challenge reviews only synthetic authorization settings: whether access defaults to deny, whether privileged access is reviewed, and whether service-account scope is bounded. It never receives identities, role names, permission lists, credentials, access requests, or live authorization data, and it makes no network requests or authorization changes. Use booleans from an isolated local lab and keep real access-control records outside the challenge.

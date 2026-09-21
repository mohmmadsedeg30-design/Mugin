# Mugin

Mugin is a defensive cybersecurity learning tool for isolated, authorized laboratories.

> **Scope:** Use Mugin only on systems you own or are explicitly authorized to test. The default mode is simulation. Mugin does not provide phishing pages, credential collection, authentication bypass, malware, persistence, stealth, or public-target scanning.

## Safe alternative to phishing toolkits

Mugin is intentionally **not** a clone of `zphisher.sh` or any phishing toolkit. It provides safe training workflows instead: local policy validation, offline security-header review, JSON reporting, and educational challenges using synthetic data. It must never be used to impersonate a service, harvest credentials, or send deceptive messages.

## Features

1. **Policy Gate:** Allows loopback, private, and link-local lab targets only, or an explicit allow-list.
2. **Safe Checks:** Runs low-impact defensive checks in dry-run mode.
3. **Challenge Catalog:** Provides local educational challenges with documented scope, including secret-free audit-logging, data-minimization, rate-limiting, and least-privilege policy reviews.
4. **Offline Reviews:** Reviews supplied HTTP headers, cookie flags, synthetic authentication settings, CSRF settings, and audit-logging settings without making network requests or storing secrets.
5. **Numbered English UI:** A simple ASCII-logo menu for local operation.
6. **Restricted Telegram Adapter:** A skeleton only; it does not execute arbitrary commands or expose secrets.
7. **Reports:** Creates local JSON reports for review.

## Installation

```bash
git clone https://github.com/mohmmadsedeg30-design/Mugin.git
cd Mugin
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pytest
```

## Run

```bash
python3 mugin.py
```

The numbered menu includes challenges, policy information, local dry-run checks, local JSON reports, offline header review, Telegram adapter status, and the safety disclaimer.

The authentication-policy challenge accepts only synthetic settings such as a minimum length, an MFA boolean, and a lockout threshold. It never accepts or processes passwords, tokens, or usernames.

The data-minimization challenge accepts only synthetic booleans for minimized collection, PII redaction, and disabled external exports. It never accepts or processes personal records, identifiers, destinations, or secrets.

The rate-limiting challenge accepts only synthetic settings for enabled limits, bounded request and burst values, and a synthetic client scope. It never accepts traffic, IP addresses, client identifiers, credentials, or destinations, and it never generates load.

The least-privilege challenge accepts only synthetic authorization settings for default-deny behavior, privileged-access review, and bounded service-account scope. It never accepts identities, role names, permissions, credentials, or access requests, and it never changes authorization state.

Command-line examples:

```bash
python3 -m mugin.cli list
python3 -m mugin.cli policy
python3 -m mugin.cli check --target http://127.0.0.1:8080 --dry-run
```

## Tests

```bash
python -m pytest -q
```

## Telegram adapter

`mugin/telegram_bot.py` is a safe adapter skeleton. It reads `TELEGRAM_BOT_TOKEN` only from the runtime environment and never stores the value in the repository. No real bot polling or webhook service is enabled by default.

## Disclaimer

This project is for authorized defensive education only. Do not use it to create fake login pages, collect passwords or tokens, bypass authentication, scan public systems, deliver malware, establish persistence, evade detection, or disrupt services. The operator is responsible for authorization, isolation, data protection, and compliance with applicable law.

See [docs/safety.md](docs/safety.md) for the complete safety charter.

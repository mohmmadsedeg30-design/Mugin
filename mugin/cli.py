from __future__ import annotations

import argparse
import json
from urllib.parse import urlparse

from .core import Finding, PolicyError, policy_summary, validate_target

CHALLENGES = [
    {"id": "web-001", "title": "Secure Headers", "level": "beginner", "scope": "local"},
    {"id": "web-002", "title": "Cookie Flags Review", "level": "beginner", "scope": "local", "mode": "offline"},
    {"id": "config-001", "title": "Secret-Free Repository", "level": "beginner", "scope": "local"},
    {"id": "web-003", "title": "Defensive Security Headers", "level": "beginner", "scope": "local", "mode": "offline"},
    {"id": "auth-001", "title": "Authentication Policy Review", "level": "beginner", "scope": "local", "mode": "offline"},
    {"id": "web-004", "title": "CORS Policy Review", "level": "beginner", "scope": "local", "mode": "offline"},
    {"id": "web-005", "title": "CSRF Policy Review", "level": "beginner", "scope": "local", "mode": "offline"},
    {"id": "ops-001", "title": "Audit Logging Policy Review", "level": "beginner", "scope": "local", "mode": "offline"},
    {"id": "ops-002", "title": "Data Minimization Policy Review", "level": "beginner", "scope": "local", "mode": "offline"},
    {"id": "ops-003", "title": "Rate-Limiting Policy Review", "level": "beginner", "scope": "local", "mode": "offline"},
    {"id": "auth-002", "title": "Least-Privilege Policy Review", "level": "beginner", "scope": "local", "mode": "offline"},
]


def safe_check(target: str, dry_run: bool = True) -> list[Finding]:
    validate_target(target)
    host = urlparse(target).hostname or ""
    findings = [Finding("scope", "info", "Target passed the scope policy", host)]
    if dry_run:
        findings.append(Finding("execution", "info", "Simulation mode: no impactful requests were sent"))
    if urlparse(target).scheme != "https":
        findings.append(Finding("transport", "medium", "Lab uses HTTP; use HTTPS outside training", remediation="Enable TLS and verify the certificate"))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(prog="mugin")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    sub.add_parser("policy")
    check = sub.add_parser("check")
    check.add_argument("--target", required=True)
    check.add_argument("--dry-run", action="store_true", default=True)
    args = parser.parse_args()
    if args.command == "list":
        print(json.dumps(CHALLENGES, ensure_ascii=False, indent=2))
    elif args.command == "policy":
        print(json.dumps(policy_summary(), ensure_ascii=False, indent=2))
    elif args.command == "check":
        try:
            print(json.dumps([f.__dict__ for f in safe_check(args.target, args.dry_run)], ensure_ascii=False, indent=2))
        except PolicyError as exc:
            parser.error(str(exc))


if __name__ == "__main__":
    main()

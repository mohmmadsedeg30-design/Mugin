from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    message: str
    evidence: str = ""
    remediation: str = ""


class PolicyError(ValueError):
    pass


def validate_target(target: str, allowed_hosts: set[str] | None = None) -> str:
    """Allow loopback/private lab hosts or an explicit host allow-list."""
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PolicyError("Target must be a valid HTTP/HTTPS URL")
    host = parsed.hostname.lower()
    allowed_hosts = {h.lower() for h in (allowed_hosts or set())}
    try:
        addr = ip_address(host)
        safe_network = addr.is_loopback or addr.is_private or addr.is_link_local
    except ValueError:
        safe_network = host in {"localhost", "host.docker.internal"} or host in allowed_hosts
    if not safe_network:
        raise PolicyError("Target is outside the lab scope or explicit allow-list")
    return target


def policy_summary() -> dict:
    return {
        "default_mode": "dry-run",
        "allowed_networks": ["loopback", "private", "link-local"],
        "requires_explicit_allowlist_for_domains": True,
        "forbidden": ["credential theft", "auth bypass", "persistence", "malware", "public scanning"],
    }


def review_security_headers(headers: Mapping[str, str]) -> list[Finding]:
    """Review supplied headers without making network requests or exposing values."""
    normalized = {str(name).lower(): str(value).strip() for name, value in headers.items()}
    checks = {
        "content-security-policy": "Add a restrictive Content-Security-Policy for the lab application",
        "x-content-type-options": "Set X-Content-Type-Options to nosniff",
        "referrer-policy": "Set an explicit, privacy-preserving Referrer-Policy",
        "permissions-policy": "Restrict unused browser capabilities with Permissions-Policy",
    }
    findings: list[Finding] = []
    for header, remediation in checks.items():
        if not normalized.get(header):
            findings.append(Finding("security-headers", "medium", f"Missing {header}", remediation=remediation))
    if normalized.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(Finding("security-headers", "low", "X-Content-Type-Options is not set to nosniff"))
    if not findings:
        findings.append(Finding("security-headers", "info", "Recommended defensive headers are present"))
    return findings


def review_cookie_flags(cookie_headers: Iterable[str]) -> list[Finding]:
    """Review local synthetic Set-Cookie lines without exposing cookie values."""
    findings: list[Finding] = []
    checked = 0
    for raw_header in cookie_headers:
        header = str(raw_header).strip()
        if not header:
            continue
        checked += 1
        attributes = {part.strip().split("=", 1)[0].lower() for part in header.split(";")[1:]}
        if "secure" not in attributes:
            findings.append(Finding("cookie-flags", "medium", "Cookie is missing Secure", remediation="Set Secure for HTTPS lab cookies"))
        if "httponly" not in attributes:
            findings.append(Finding("cookie-flags", "medium", "Cookie is missing HttpOnly", remediation="Set HttpOnly when client-side scripts do not need access"))
        if "samesite" not in attributes:
            findings.append(Finding("cookie-flags", "low", "Cookie is missing SameSite", remediation="Set SameSite=Lax or Strict according to the lab flow"))
    if checked == 0:
        return [Finding("cookie-flags", "info", "No cookie lines supplied; nothing was inspected")]
    if not findings:
        findings.append(Finding("cookie-flags", "info", "Supplied cookies include Secure, HttpOnly, and SameSite attributes"))
    return findings


__all__ = ["Finding", "PolicyError", "policy_summary", "review_cookie_flags", "review_security_headers", "validate_target"]

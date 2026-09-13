from __future__ import annotations

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
        raise PolicyError("الهدف يجب أن يكون رابط HTTP/HTTPS صالحاً")
    host = parsed.hostname.lower()
    allowed_hosts = {h.lower() for h in (allowed_hosts or set())}
    try:
        addr = ip_address(host)
        safe_network = addr.is_loopback or addr.is_private or addr.is_link_local
    except ValueError:
        safe_network = host in {"localhost", "host.docker.internal"} or host in allowed_hosts
    if not safe_network:
        raise PolicyError("الهدف خارج نطاق المختبر أو قائمة السماح")
    return target


def policy_summary() -> dict:
    return {
        "default_mode": "dry-run",
        "allowed_networks": ["loopback", "private", "link-local"],
        "requires_explicit_allowlist_for_domains": True,
        "forbidden": [
            "credential theft", "auth bypass", "persistence", "malware", "public scanning"
        ],
    }

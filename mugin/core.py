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


def review_authentication_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic authentication settings without receiving passwords or tokens."""
    findings: list[Finding] = []
    minimum_length = settings.get("minimum_password_length")
    if not isinstance(minimum_length, int) or minimum_length < 12:
        findings.append(Finding("authentication-policy", "medium", "Password minimum length is below 12 characters", remediation="Require at least 12 characters and prefer passphrases"))
    if settings.get("mfa_required") is not True:
        findings.append(Finding("authentication-policy", "medium", "Multi-factor authentication is not required", remediation="Require MFA for privileged and sensitive lab accounts"))
    lockout_threshold = settings.get("lockout_threshold")
    if not isinstance(lockout_threshold, int) or not 3 <= lockout_threshold <= 10:
        findings.append(Finding("authentication-policy", "low", "Account lockout threshold is missing or outside the 3-10 range", remediation="Use a bounded threshold and pair it with rate limiting"))
    if not findings:
        findings.append(Finding("authentication-policy", "info", "Synthetic authentication settings meet baseline guidance"))
    return findings


def review_cors_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic CORS settings without making requests or exposing values."""
    findings: list[Finding] = []
    origin = str(settings.get("allow_origin", "")).strip()
    credentials = settings.get("allow_credentials") is True

    if not origin:
        findings.append(Finding("cors-policy", "medium", "Allowed origin is missing", remediation="Set an explicit origin for the local lab"))
    elif origin == "*" and credentials:
        findings.append(Finding("cors-policy", "high", "Wildcard origin cannot be combined with credentials", remediation="Use an explicit trusted origin or disable credentials"))
    elif origin == "*":
        findings.append(Finding("cors-policy", "low", "Wildcard origin permits every browser origin", remediation="Prefer an explicit origin when the lab does not need public sharing"))

    if credentials and origin in {"", "*"}:
        findings.append(Finding("cors-policy", "medium", "Credentialed CORS requires a specific allowed origin"))
    if not findings:
        findings.append(Finding("cors-policy", "info", "Synthetic CORS settings meet the baseline guidance"))
    return findings


def review_csrf_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic CSRF controls without receiving tokens or making requests."""
    findings: list[Finding] = []
    protection_enabled = settings.get("csrf_protection_enabled") is True
    origin_check_enabled = settings.get("origin_check_enabled") is True
    same_site = str(settings.get("same_site", "")).strip().lower()

    if not protection_enabled:
        findings.append(Finding("csrf-policy", "high", "CSRF protection is not enabled", remediation="Require a server-side CSRF defense for state-changing lab actions"))
    if not origin_check_enabled:
        findings.append(Finding("csrf-policy", "medium", "Origin checking is not enabled", remediation="Validate the expected local origin for state-changing requests"))
    if same_site not in {"strict", "lax"}:
        findings.append(Finding("csrf-policy", "medium", "SameSite cookie setting is missing or not Strict/Lax", remediation="Use SameSite=Lax or Strict for session cookies in the lab"))
    if not findings:
        findings.append(Finding("csrf-policy", "info", "Synthetic CSRF settings meet the baseline guidance"))
    return findings


def review_audit_logging_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic audit-log settings without receiving log entries or secrets."""
    findings: list[Finding] = []
    enabled = settings.get("audit_logging_enabled") is True
    retention_days = settings.get("retention_days")
    excludes_secrets = settings.get("excludes_secrets") is True
    local_sink = settings.get("local_sink") is True

    if not enabled:
        findings.append(Finding("audit-logging", "medium", "Audit logging is not enabled", remediation="Enable minimal audit events for the local lab"))
    if not isinstance(retention_days, int) or not 1 <= retention_days <= 90:
        findings.append(Finding("audit-logging", "low", "Retention period is missing or outside the 1-90 day range", remediation="Choose a bounded retention period appropriate for the lab"))
    if not excludes_secrets:
        findings.append(Finding("audit-logging", "high", "Audit records are not explicitly configured to exclude secrets", remediation="Exclude passwords, tokens, cookies, and authorization headers before writing events"))
    if not local_sink:
        findings.append(Finding("audit-logging", "medium", "Audit sink is not restricted to the local lab", remediation="Keep training records on an isolated local sink"))
    if not findings:
        findings.append(Finding("audit-logging", "info", "Synthetic audit-logging settings meet the baseline guidance"))
    return findings


def review_data_minimization_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic data-minimization settings without receiving user data."""
    findings: list[Finding] = []
    minimized = settings.get("collection_minimized") is True
    redaction_enabled = settings.get("pii_redaction_enabled") is True
    exports_disabled = settings.get("external_exports_disabled") is True

    if not minimized:
        findings.append(Finding("data-minimization", "medium", "Data collection is not explicitly minimized", remediation="Collect only fields required for the local lab exercise"))
    if not redaction_enabled:
        findings.append(Finding("data-minimization", "high", "PII redaction is not enabled", remediation="Redact synthetic personal-data fields before local review or storage"))
    if not exports_disabled:
        findings.append(Finding("data-minimization", "medium", "External data exports are not disabled", remediation="Keep training data inside the isolated lab and disable external exports"))
    if not findings:
        findings.append(Finding("data-minimization", "info", "Synthetic data-minimization settings meet the baseline guidance"))
    return findings


def review_rate_limiting_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic rate-limit settings without receiving traffic or identifiers."""
    findings: list[Finding] = []
    enabled = settings.get("rate_limiting_enabled") is True
    requests_per_minute = settings.get("requests_per_minute")
    burst_limit = settings.get("burst_limit")
    per_identity = settings.get("per_identity") is True

    if not enabled:
        findings.append(Finding("rate-limiting", "medium", "Rate limiting is not enabled", remediation="Enable bounded request limits for the local lab"))
    if not isinstance(requests_per_minute, int) or not 1 <= requests_per_minute <= 600:
        findings.append(Finding("rate-limiting", "medium", "Requests-per-minute limit is missing or outside the 1-600 range", remediation="Choose a bounded rate suitable for the exercise"))
    if not isinstance(burst_limit, int) or not 1 <= burst_limit <= 60:
        findings.append(Finding("rate-limiting", "low", "Burst limit is missing or outside the 1-60 range", remediation="Keep bursts bounded so short spikes cannot overwhelm the lab"))
    if not per_identity:
        findings.append(Finding("rate-limiting", "low", "Rate limits are not scoped to a synthetic client identity", remediation="Use a non-sensitive synthetic scope such as a lab client ID"))
    if not findings:
        findings.append(Finding("rate-limiting", "info", "Synthetic rate-limiting settings meet the baseline guidance"))
    return findings


def review_least_privilege_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic authorization settings without receiving identities or permissions."""
    findings: list[Finding] = []
    default_deny = settings.get("default_deny") is True
    privileged_review = settings.get("privileged_access_reviewed") is True
    service_scope = settings.get("service_account_scope") is True

    if not default_deny:
        findings.append(Finding("least-privilege", "high", "Authorization does not default to deny", remediation="Deny access unless a local lab rule explicitly grants it"))
    if not privileged_review:
        findings.append(Finding("least-privilege", "medium", "Privileged access is not periodically reviewed", remediation="Review synthetic privileged roles and remove unnecessary access"))
    if not service_scope:
        findings.append(Finding("least-privilege", "medium", "Service-account scope is not explicitly bounded", remediation="Limit each synthetic service role to the smallest required lab capability"))
    if not findings:
        findings.append(Finding("least-privilege", "info", "Synthetic least-privilege settings meet the baseline guidance"))
    return findings


def review_backup_recovery_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic backup settings without receiving files or destinations."""
    findings: list[Finding] = []
    backups_enabled = settings.get("backups_enabled") is True
    encrypted = settings.get("encrypted_at_rest") is True
    restore_tested = settings.get("restore_tested") is True
    local_only = settings.get("local_only") is True

    if not backups_enabled:
        findings.append(Finding("backup-recovery", "high", "Backups are not enabled", remediation="Enable bounded backups for synthetic lab state"))
    if not encrypted:
        findings.append(Finding("backup-recovery", "high", "Backups are not encrypted at rest", remediation="Encrypt local lab backups and protect the key separately"))
    if not restore_tested:
        findings.append(Finding("backup-recovery", "medium", "Backup restoration has not been tested", remediation="Run a local restore drill with synthetic data and record only the result"))
    if not local_only:
        findings.append(Finding("backup-recovery", "medium", "Backup storage is not restricted to the local lab", remediation="Keep training backups in an isolated local destination and disable external exports"))
    if not findings:
        findings.append(Finding("backup-recovery", "info", "Synthetic backup and recovery settings meet the baseline guidance"))
    return findings


def review_dependency_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic dependency-integrity settings without downloading packages."""
    findings: list[Finding] = []
    lockfile_present = settings.get("lockfile_present") is True
    hashes_pinned = settings.get("hashes_pinned") is True
    trusted_sources_only = settings.get("trusted_sources_only") is True
    updates_reviewed = settings.get("updates_reviewed") is True

    if not lockfile_present:
        findings.append(Finding("dependency-integrity", "medium", "Dependency versions are not locked", remediation="Commit a reviewed lockfile for the local lab"))
    if not hashes_pinned:
        findings.append(Finding("dependency-integrity", "medium", "Dependency hashes are not pinned", remediation="Pin hashes for reproducible, tamper-evident lab installs"))
    if not trusted_sources_only:
        findings.append(Finding("dependency-integrity", "high", "Dependency sources are not restricted to trusted registries", remediation="Use an approved registry and reject unexpected sources"))
    if not updates_reviewed:
        findings.append(Finding("dependency-integrity", "low", "Dependency updates have not been reviewed", remediation="Review changelogs and test updates before merging"))
    if not findings:
        findings.append(Finding("dependency-integrity", "info", "Synthetic dependency-integrity settings meet the baseline guidance"))
    return findings


def review_secret_management_policy(settings: Mapping[str, object]) -> list[Finding]:
    """Review synthetic secret-management settings without receiving secret material."""
    findings: list[Finding] = []
    scanning_enabled = settings.get("secret_scanning_enabled") is True
    logs_redacted = settings.get("logs_redacted") is True
    local_store_approved = settings.get("local_store_approved") is True
    rotation_reviewed = settings.get("rotation_reviewed") is True

    if not scanning_enabled:
        findings.append(Finding("secret-management", "medium", "Secret scanning is not enabled", remediation="Enable repository checks that detect accidental secret commits without collecting secret values"))
    if not logs_redacted:
        findings.append(Finding("secret-management", "high", "Operational logs are not configured to redact secrets", remediation="Redact passwords, tokens, keys, and authorization headers before local logging"))
    if not local_store_approved:
        findings.append(Finding("secret-management", "high", "The secret store is not restricted to an approved local lab store", remediation="Use an authorized local secret store and prohibit external exports in the exercise"))
    if not rotation_reviewed:
        findings.append(Finding("secret-management", "low", "Secret rotation has not been reviewed", remediation="Document a bounded rotation and revocation drill using synthetic placeholders only"))
    if not findings:
        findings.append(Finding("secret-management", "info", "Synthetic secret-management settings meet the baseline guidance"))
    return findings


__all__ = ["Finding", "PolicyError", "policy_summary", "review_audit_logging_policy", "review_authentication_policy", "review_backup_recovery_policy", "review_cookie_flags", "review_cors_policy", "review_csrf_policy", "review_data_minimization_policy", "review_dependency_policy", "review_least_privilege_policy", "review_rate_limiting_policy", "review_secret_management_policy", "review_security_headers", "validate_target"]

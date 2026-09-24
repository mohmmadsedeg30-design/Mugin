import pytest

from mugin.core import PolicyError, review_audit_logging_policy, review_authentication_policy, review_backup_recovery_policy, review_cookie_flags, review_cors_policy, review_csrf_policy, review_data_minimization_policy, review_dependency_policy, review_least_privilege_policy, review_rate_limiting_policy, review_security_headers, validate_target
from mugin.menu import BANNER, MENU_OPTIONS, print_disclaimer


def test_loopback_allowed():
    assert validate_target("http://127.0.0.1:8080")


def test_private_network_allowed():
    assert validate_target("https://192.168.1.10")


def test_public_target_rejected():
    with pytest.raises(PolicyError):
        validate_target("https://example.com")


def test_invalid_scheme_rejected():
    with pytest.raises(PolicyError):
        validate_target("ftp://127.0.0.1")


def test_security_header_review_is_offline_and_finds_missing_headers():
    findings = review_security_headers({"Server": "training-lab"})
    assert any("content-security-policy" in finding.message for finding in findings)
    assert all(finding.evidence == "" for finding in findings)


def test_security_header_review_accepts_recommended_headers():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=()",
    }
    findings = review_security_headers(headers)
    assert findings[0].severity == "info"


def test_cookie_flag_review_reports_missing_attributes_without_cookie_values():
    findings = review_cookie_flags(["session=synthetic; Path=/"])
    messages = " ".join(finding.message for finding in findings)
    assert "Secure" in messages
    assert "HttpOnly" in messages
    assert "SameSite" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_cookie_flag_review_accepts_synthetic_cookie_with_recommended_attributes():
    findings = review_cookie_flags(["training=synthetic; Secure; HttpOnly; SameSite=Lax"])
    assert findings[0].severity == "info"


def test_authentication_policy_review_reports_weak_synthetic_settings_without_secrets():
    findings = review_authentication_policy({"minimum_password_length": 8, "mfa_required": False, "lockout_threshold": 20})
    messages = " ".join(finding.message for finding in findings)
    assert "12 characters" in messages
    assert "Multi-factor" in messages
    assert "3-10" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_authentication_policy_review_accepts_baseline_settings():
    findings = review_authentication_policy({"minimum_password_length": 14, "mfa_required": True, "lockout_threshold": 5})
    assert findings[0].severity == "info"


def test_cors_policy_review_rejects_wildcard_with_credentials_without_network_access():
    findings = review_cors_policy({"allow_origin": "*", "allow_credentials": True})
    messages = " ".join(finding.message for finding in findings)
    assert "Wildcard origin cannot be combined with credentials" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_cors_policy_review_accepts_explicit_origin():
    findings = review_cors_policy({"allow_origin": "http://127.0.0.1:8080", "allow_credentials": True})
    assert findings[0].severity == "info"


def test_csrf_policy_review_reports_weak_synthetic_settings_without_tokens():
    findings = review_csrf_policy({"csrf_protection_enabled": False, "origin_check_enabled": False, "same_site": "None"})
    messages = " ".join(finding.message for finding in findings)
    assert "CSRF protection" in messages
    assert "Origin checking" in messages
    assert "SameSite" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_csrf_policy_review_accepts_baseline_settings():
    findings = review_csrf_policy({"csrf_protection_enabled": True, "origin_check_enabled": True, "same_site": "Lax"})
    assert findings[0].severity == "info"


def test_audit_logging_review_reports_secret_and_scope_risks_without_log_data():
    findings = review_audit_logging_policy({"audit_logging_enabled": True, "retention_days": 120, "excludes_secrets": False, "local_sink": False})
    messages = " ".join(finding.message for finding in findings)
    assert "Retention" in messages
    assert "exclude secrets" in messages
    assert "local lab" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_audit_logging_review_accepts_bounded_secret_free_local_settings():
    findings = review_audit_logging_policy({"audit_logging_enabled": True, "retention_days": 30, "excludes_secrets": True, "local_sink": True})
    assert findings[0].severity == "info"


def test_data_minimization_review_reports_collection_redaction_and_export_risks_without_data():
    findings = review_data_minimization_policy({"collection_minimized": False, "pii_redaction_enabled": False, "external_exports_disabled": False})
    messages = " ".join(finding.message for finding in findings)
    assert "collection" in messages
    assert "redaction" in messages
    assert "exports" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_data_minimization_review_accepts_isolated_synthetic_settings():
    findings = review_data_minimization_policy({"collection_minimized": True, "pii_redaction_enabled": True, "external_exports_disabled": True})
    assert findings[0].severity == "info"


def test_rate_limiting_review_reports_unbounded_synthetic_settings_without_traffic():
    findings = review_rate_limiting_policy({"rate_limiting_enabled": False, "requests_per_minute": 1000, "burst_limit": 100, "per_identity": False})
    messages = " ".join(finding.message for finding in findings)
    assert "not enabled" in messages
    assert "1-600" in messages
    assert "1-60" in messages
    assert "synthetic client identity" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_rate_limiting_review_accepts_bounded_isolated_synthetic_settings():
    findings = review_rate_limiting_policy({"rate_limiting_enabled": True, "requests_per_minute": 120, "burst_limit": 10, "per_identity": True})
    assert findings[0].severity == "info"


def test_least_privilege_review_reports_unsafe_synthetic_settings_without_identities():
    findings = review_least_privilege_policy({"default_deny": False, "privileged_access_reviewed": False, "service_account_scope": False})
    messages = " ".join(finding.message for finding in findings)
    assert "default to deny" in messages
    assert "Privileged access" in messages
    assert "Service-account scope" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_least_privilege_review_accepts_bounded_synthetic_settings():
    findings = review_least_privilege_policy({"default_deny": True, "privileged_access_reviewed": True, "service_account_scope": True})
    assert findings[0].severity == "info"


def test_backup_recovery_review_reports_storage_and_restore_risks_without_files():
    findings = review_backup_recovery_policy({"backups_enabled": False, "encrypted_at_rest": False, "restore_tested": False, "local_only": False})
    messages = " ".join(finding.message for finding in findings)
    assert "Backups are not enabled" in messages
    assert "not encrypted" in messages
    assert "not been tested" in messages
    assert "local lab" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_backup_recovery_review_accepts_encrypted_local_synthetic_settings():
    findings = review_backup_recovery_policy({"backups_enabled": True, "encrypted_at_rest": True, "restore_tested": True, "local_only": True})
    assert findings[0].severity == "info"


def test_dependency_review_reports_integrity_and_source_risks_without_packages():
    findings = review_dependency_policy({"lockfile_present": False, "hashes_pinned": False, "trusted_sources_only": False, "updates_reviewed": False})
    messages = " ".join(finding.message for finding in findings)
    assert "not locked" in messages
    assert "not pinned" in messages
    assert "trusted registries" in messages
    assert "not been reviewed" in messages
    assert all(finding.evidence == "" for finding in findings)


def test_dependency_review_accepts_reproducible_synthetic_settings():
    findings = review_dependency_policy({"lockfile_present": True, "hashes_pinned": True, "trusted_sources_only": True, "updates_reviewed": True})
    assert findings[0].severity == "info"


def test_numbered_ui_and_disclaimer_are_english_and_safe(capsys):
    assert len(MENU_OPTIONS) == 8
    assert "SAFE ETHICAL LAB" in BANNER
    print_disclaimer()
    output = capsys.readouterr().out
    assert "credential" in output.lower()
    assert "phishing" in output.lower()
    assert not any("\u0600" <= character <= "\u06ff" for character in output)

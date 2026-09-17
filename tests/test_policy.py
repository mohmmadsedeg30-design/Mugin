import pytest

from mugin.core import PolicyError, review_authentication_policy, review_cookie_flags, review_cors_policy, review_csrf_policy, review_security_headers, validate_target
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


def test_numbered_ui_and_disclaimer_are_english_and_safe(capsys):
    assert len(MENU_OPTIONS) == 8
    assert "SAFE ETHICAL LAB" in BANNER
    print_disclaimer()
    output = capsys.readouterr().out
    assert "credential" in output.lower()
    assert "phishing" in output.lower()
    assert not any("\u0600" <= character <= "\u06ff" for character in output)

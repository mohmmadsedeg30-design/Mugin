import pytest

from mugin.core import PolicyError, review_security_headers, validate_target


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

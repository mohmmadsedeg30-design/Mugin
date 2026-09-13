import pytest

from mugin.core import PolicyError, validate_target


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

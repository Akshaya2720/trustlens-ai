"""TrustLens AI - SSRF and Safe URL Security Tests"""

import pytest
from app.services.safe_url import SafeURLInspector


def test_url_normalization():
    norm = SafeURLInspector.normalize_url("example.com/test?query=1")
    assert norm.startswith("http://example.com/test?query=1")

    norm_https = SafeURLInspector.normalize_url("HTTPS://SECURE.ORG/LOGIN")
    assert norm_https == "https://secure.org/LOGIN"


def test_reject_unsupported_schemes():
    val_file = SafeURLInspector.validate_url("file:///etc/passwd")
    assert not val_file.is_safe
    assert "Unsupported URL scheme" in val_file.reason

    val_gopher = SafeURLInspector.validate_url("gopher://127.0.0.1:70")
    assert not val_gopher.is_safe


def test_reject_localhost_and_loopback():
    val_localhost = SafeURLInspector.validate_url("http://localhost:8000/api")
    assert not val_localhost.is_safe
    assert "blocked" in val_localhost.reason.lower()

    val_127 = SafeURLInspector.validate_url("http://127.0.0.1:5432")
    assert not val_127.is_safe
    assert "blocked/private network range" in val_127.reason


def test_reject_cloud_metadata():
    val_meta = SafeURLInspector.validate_url("http://169.254.169.254/latest/meta-data/")
    assert not val_meta.is_safe
    assert "blocked" in val_meta.reason.lower()

    val_google = SafeURLInspector.validate_url("http://metadata.google.internal/computeMetadata/v1/")
    assert not val_google.is_safe
    assert "blocked" in val_google.reason.lower()


def test_reject_private_rfc1918():
    val_10 = SafeURLInspector.validate_url("http://10.0.0.5/internal/dashboard")
    assert not val_10.is_safe
    assert "blocked/private network range" in val_10.reason

    val_192 = SafeURLInspector.validate_url("http://192.168.1.1/admin")
    assert not val_192.is_safe
    assert "blocked/private network range" in val_192.reason

    val_172 = SafeURLInspector.validate_url("http://172.16.5.10/api")
    assert not val_172.is_safe
    assert "blocked/private network range" in val_172.reason


def test_allow_valid_public_domain():
    val_public = SafeURLInspector.validate_url("https://www.google.com")
    assert val_public.is_safe
    assert val_public.resolved_ip is not None

"""
Comprehensive unit tests for account lockout, HIBP k-anonymity checks,
password migration paths, and XSS HTML sanitization across the backend.
"""

import pytest
from unittest.mock import MagicMock, patch
import urllib.error

import auth.security as security_module
from auth.security import (
    check_account_lockout,
    record_failed_login,
    reset_failed_login,
    check_pwned_password,
    record_legacy_bcrypt_metric,
    verify_password_with_migration,
)
from api.routes import _sanitize_html_content


def test_account_lockout_threshold():
    mock_redis = MagicMock()
    # Less than threshold
    mock_redis.get.return_value = "4"
    with patch.object(security_module, "_redis_auth_client", mock_redis):
        with patch.object(security_module.settings, "MAX_LOGIN_ATTEMPTS", 5):
            assert check_account_lockout("test@example.com") is False

    # At or above threshold
    mock_redis.get.return_value = "5"
    with patch.object(security_module, "_redis_auth_client", mock_redis):
        with patch.object(security_module.settings, "MAX_LOGIN_ATTEMPTS", 5):
            assert check_account_lockout("test@example.com") is True


def test_record_and_reset_failed_login():
    mock_redis = MagicMock()
    mock_redis.get.return_value = "2"
    with patch.object(security_module, "_redis_auth_client", mock_redis):
        with patch.object(security_module.settings, "LOCKOUT_DURATION_SECONDS", 900):
            record_failed_login("test@example.com")
            mock_redis.incr.assert_called_once_with("login_attempts:test@example.com")
            mock_redis.expire.assert_called_once_with("login_attempts:test@example.com", 900)

            reset_failed_login("test@example.com")
            mock_redis.delete.assert_called_once_with("login_attempts:test@example.com")


def test_check_pwned_password_k_anonymity_match():
    # Mocking urlopen to return HIBP suffix lines including our match
    mock_response = MagicMock()
    mock_response.status = 200
    # Suppose sha1 of "password123" has suffix "A1C3E..."
    # We mock the return line to match whatever suffix hashlib computes for "testpwned"
    import hashlib
    sha1 = hashlib.sha1(b"testpwned").hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    mock_response.read.return_value = f"00000000000000000000000000000000000:10\n{suffix}:1337\n11111111111111111111111111111111111:5\n".encode("utf-8")

    with patch("urllib.request.urlopen", return_value=mock_response):
        assert check_pwned_password("testpwned") is True


def test_check_pwned_password_clean():
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"00000000000000000000000000000000000:10\n"

    with patch("urllib.request.urlopen", return_value=mock_response):
        assert check_pwned_password("cleanpassword999") is False


def test_check_pwned_password_fail_open_on_error():
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network unreachable")):
        assert check_pwned_password("somepassword") is False


def test_record_legacy_bcrypt_metric():
    mock_redis = MagicMock()
    with patch.object(security_module, "_redis_auth_client", mock_redis):
        record_legacy_bcrypt_metric()
        mock_redis.incr.assert_called_once_with("metric:legacy_bcrypt_authentications")


def test_xss_html_sanitization_strips_scripts_and_event_handlers():
    malicious_html = (
        '<html><head><title>Phish</title><script>alert("XSS")</script></head>'
        'body onload="stealCookies()">'
        '<a href="javascript:alert(1)">Click Me</a>'
        '<iframe src="https://evil.com"></iframe>'
        '<form action="https://evil.com/post"><input type="text" name="user"></form>'
        '</body></html>'
    )
    sanitized = _sanitize_html_content(malicious_html)
    assert "<script>" not in sanitized
    assert "stealCookies()" not in sanitized
    assert "onload" not in sanitized
    assert "javascript:" not in sanitized
    assert "<iframe" not in sanitized
    assert '<form action="https://evil.com/post">' in sanitized or "form" in sanitized

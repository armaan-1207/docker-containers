"""
auth/security.py
==================
"""

import hashlib
import hmac
import logging
import urllib.request
import urllib.error
import bcrypt
import redis

from typing import Tuple
from config import settings

logger = logging.getLogger(__name__)

_MAX_PASSWORD_BYTES = 72

try:
    _redis_auth_client = redis.from_url(settings.REDIS_SECURITY_URL)
except Exception as e:
    logger.warning("Could not initialize Redis client for account lockout: %s", e)
    _redis_auth_client = None


def check_account_lockout(email: str) -> bool:
    """
    Returns True if account is currently locked out due to excessive failed login attempts.
    """
    if not _redis_auth_client:
        if getattr(settings, "AUTH_LOCKOUT_FAIL_CLOSED", True) or settings.is_production:
            logger.error("Redis unavailable during account lockout check (fail-closed)")
            raise ValueError("Authentication store unavailable")
        return False
    normalized_email = email.lower().strip()
    try:
        attempts = _redis_auth_client.get(f"login_attempts:{normalized_email}")
        if attempts and int(attempts) >= settings.MAX_LOGIN_ATTEMPTS:
            return True
        return False
    except redis.exceptions.RedisError as e:
        logger.error("Redis error checking account lockout for %s: %s", normalized_email, e)
        if getattr(settings, "AUTH_LOCKOUT_FAIL_CLOSED", True) or settings.is_production:
            raise ValueError("Authentication store unavailable")
        return False


def record_failed_login(email: str) -> int:
    """
    Increments failed login counter for normalized email. Sets expiration on first failure.
    Returns new attempt count.
    """
    if not _redis_auth_client:
        return 0
    normalized_email = email.lower().strip()
    key = f"login_attempts:{normalized_email}"
    try:
        count = _redis_auth_client.incr(key)
        if count == 1:
            _redis_auth_client.expire(key, settings.LOCKOUT_DURATION_SECONDS)
        return count
    except redis.exceptions.RedisError as e:
        logger.error("Redis error recording failed login for %s: %s", normalized_email, e)
        return 0


def reset_failed_login(email: str) -> None:
    """
    Resets failed login counter on successful login.
    """
    if not _redis_auth_client:
        return
    normalized_email = email.lower().strip()
    try:
        _redis_auth_client.delete(f"login_attempts:{normalized_email}")
    except redis.exceptions.RedisError as e:
        logger.warning("Redis error resetting failed login for %s: %s", normalized_email, e)


def _pre_hash(password: str) -> bytes:
    # SHA-256 pre-hash converts any length password into a fixed 64-byte hex string,
    # completely bypassing bcrypt's 72-byte truncation limit while preserving full entropy.
    return hashlib.sha256(password.encode("utf-8")).hexdigest().encode("utf-8")


def hash_password(password: str) -> str:
    pw_bytes = _pre_hash(password)
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password_with_migration(plain_password: str, hashed_password: str) -> Tuple[bool, bool]:
    """
    Returns (is_valid, needs_rehash).
    needs_rehash is True when a legacy truncated-72-byte hash succeeded and
    ALLOW_LEGACY_BCRYPT is enabled, indicating the password hash should be
    upgraded to the new SHA-256 pre-hashed format immediately upon login.
    """
    hashed_bytes = hashed_password.encode("utf-8")
    try:
        # First check SHA-256 pre-hashed password (new format)
        if bcrypt.checkpw(_pre_hash(plain_password), hashed_bytes):
            return True, False
        # Backward compatibility check only if explicitly enabled
        if getattr(settings, "ALLOW_LEGACY_BCRYPT", False):
            legacy_bytes = plain_password.encode("utf-8")[:_MAX_PASSWORD_BYTES]
            if bcrypt.checkpw(legacy_bytes, hashed_bytes):
                return True, True
        return False, False
    except ValueError:
        return False, False


def verify_password(plain_password: str, hashed_password: str) -> bool:
    is_valid, _ = verify_password_with_migration(plain_password, hashed_password)
    return is_valid


def check_pwned_password(plain_password: str) -> bool:
    """
    Check if the password has appeared in known public data breaches using the
    Have I Been Pwned (HIBP) k-Anonymity API (Security finding #7).
    Only the first 5 characters of the SHA-1 hash (`prefix`) are sent over the wire.
    """
    if not plain_password:
        return False
    sha1_hash = hashlib.sha1(plain_password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "AEGIS-Security-HIBP-Checker"}
    )
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            if resp.status != 200:
                return False
            for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    count = int(parts[1]) if parts[1].isdigit() else 1
                    if count > 0:
                        logger.warning("Registration blocked: password matched HIBP k-anonymity breach list (count=%d)", count)
                        return True
        return False
    except Exception as e:
        logger.warning("HIBP k-anonymity check failed or timed out (%s) — failing open to prevent registration outage", e)
        record_hibp_failure_metric()
        return False


def record_hibp_failure_metric() -> None:
    """
    Increment telemetry counter when HIBP API reachability fails.
    Allows operations to alert on prolonged external API outages while failing open.
    """
    if _redis_auth_client:
        try:
            _redis_auth_client.incr("metric:hibp_api_failures")
        except Exception as e:
            logger.debug("Failed to record HIBP failure telemetry: %s", e)


def record_legacy_bcrypt_metric() -> None:
    """
    Increment telemetry counter for legacy bcrypt authentication events.
    Used by operations/CI checks to safely time out ALLOW_LEGACY_BCRYPT.
    """
    if _redis_auth_client:
        try:
            _redis_auth_client.incr("metric:legacy_bcrypt_authentications")
        except Exception as e:
            logger.debug("Failed to record legacy bcrypt telemetry: %s", e)

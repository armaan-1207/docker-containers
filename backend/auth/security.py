"""
auth/security.py
==================
"""

import hashlib
import bcrypt

from typing import Tuple
from config import settings

_MAX_PASSWORD_BYTES = 72


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

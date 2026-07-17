"""
auth/security.py
==================
"""

import hashlib
import bcrypt

_MAX_PASSWORD_BYTES = 72


def _pre_hash(password: str) -> bytes:
    # SHA-256 pre-hash converts any length password into a fixed 64-byte hex string,
    # completely bypassing bcrypt's 72-byte truncation limit while preserving full entropy.
    return hashlib.sha256(password.encode("utf-8")).hexdigest().encode("utf-8")


def hash_password(password: str) -> str:
    pw_bytes = _pre_hash(password)
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    hashed_bytes = hashed_password.encode("utf-8")
    try:
        # First check SHA-256 pre-hashed password (new format)
        if bcrypt.checkpw(_pre_hash(plain_password), hashed_bytes):
            return True
        # Backward compatibility check for legacy passwords truncated at 72 bytes
        legacy_bytes = plain_password.encode("utf-8")[:_MAX_PASSWORD_BYTES]
        return bcrypt.checkpw(legacy_bytes, hashed_bytes)
    except ValueError:
        return False

from datetime import datetime, timedelta, timezone
from typing import Optional
import logging
import uuid

import jwt
from jwt.exceptions import PyJWTError as JWTError
import redis

from config import settings

logger = logging.getLogger(__name__)

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

try:
    _redis_client = redis.from_url(settings.REDIS_URL)
except Exception as e:
    logger.warning("Could not initialize Redis client for JWT revocation: %s", e)
    _redis_client = None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({
        "jti": str(uuid.uuid4()),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": settings.APP_NAME,
        "aud": "aegis-clients",
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:

    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
        issuer=settings.APP_NAME,
        audience="aegis-clients",
    )
    jti = payload.get("jti")
    if jti and _redis_client:
        try:
            if _redis_client.get(f"jwt_blacklist:{jti}"):
                raise JWTError("Token has been revoked")
        except redis.exceptions.RedisError as e:
            logger.warning("Redis error during JWT blacklist check: %s", e)
    return payload


def revoke_token(token: str) -> bool:
    if not _redis_client:
        return False
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=settings.APP_NAME,
            audience="aegis-clients",
            options={"verify_exp": False}
        )
        jti = payload.get("jti")
        if not jti:
            return False
        exp = payload.get("exp")
        ttl = int(exp - datetime.now(timezone.utc).timestamp())
        if ttl > 0:
            _redis_client.setex(f"jwt_blacklist:{jti}", ttl, "revoked")
        return True
    except Exception as e:
        logger.error("Failed to revoke token: %s", e)
        return False


def get_subject_from_token(token: str) -> Optional[str]:

    try:
        payload = decode_access_token(token)
    except JWTError:
        return None

    return payload.get("sub")

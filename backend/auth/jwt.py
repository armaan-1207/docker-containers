from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from jwt.exceptions import PyJWTError as JWTError

from config import settings

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({
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
    return payload


def get_subject_from_token(token: str) -> Optional[str]:

    try:
        payload = decode_access_token(token)
    except JWTError:
        return None

    return payload.get("sub")

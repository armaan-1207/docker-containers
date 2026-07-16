"""
auth/routes.py
================
Authentication endpoints: register and login.


"""

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from auth.jwt import create_access_token
from auth.security import hash_password, verify_password
from database.database import get_db
from database.models import User
from schemas.auth import TokenResponse, UserRegisterRequest, UserRegisterAcceptedResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# ─── Pre-computed dummy hash ────────────────────────────────────────────────
# Always run verify_password() against this hash when the looked-up user is
# None. bcrypt takes the same wall-clock time regardless of whether the user
# exists, so an attacker cannot enumerate valid accounts by measuring response
# latency (security finding #5).
#
# The hash is for the string "dummy-password-that-will-never-match" and was
# generated once with hash_password(). It never changes at runtime; it exists
# only to ensure the bcrypt work-factor is always paid.
_DUMMY_HASH: str = hash_password("dummy-password-aegis-timing-guard-v1")


@router.post(
    "/register",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=UserRegisterAcceptedResponse,
)
def register(
    payload: UserRegisterRequest,
    db: Session = Depends(get_db),
) -> UserRegisterAcceptedResponse:
    """
    Register a new account.

    Always returns 202 Accepted with a generic message — never 409
    Conflict — so that unauthenticated callers cannot determine whether a
    given email address already exists in the system (security finding #6).
    
    """
    existing = db.query(User).filter(User.email == payload.email).first()

    # Always pay the bcrypt cost -- whether or not this email is already
    # registered -- so response timing cannot be used to distinguish the
    # two outcomes. The computed hash is simply discarded on the
    # duplicate-email path.
    hashed_password = hash_password(payload.password)

    if existing is not None:
        # Do NOT reveal that this email is already registered.
        # Return the same 202 shape so callers cannot tell the difference,
        # and (as of this fix) take the same amount of time to do it.
        logger.info("Registration attempted for existing email (returning 202 to caller)")
        return UserRegisterAcceptedResponse()

    user = User(
        email=payload.email,
        hashed_password=hashed_password,
    )
    db.add(user)
    db.commit()
    logger.info("New user registered: %s", payload.email)
    return UserRegisterAcceptedResponse()


@router.post("/login", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate and return a JWT access token.

    Timing-attack mitigation (security finding #5):
    verify_password() is called unconditionally.  When the user is not
    found we compare against _DUMMY_HASH, ensuring the bcrypt work-factor
    is always paid and response time does not leak whether the email exists.
    """
    user = db.query(User).filter(User.email == form_data.username).first()

    # Always run the password hash comparison — even when user is None —
    # so the response time is identical regardless of whether the account
    # exists. The result of the comparison is only used when user is not None.
    password_hash_to_check = user.hashed_password if user is not None else _DUMMY_HASH
    password_valid = verify_password(form_data.password, password_hash_to_check)

    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if user is None or not password_valid:
        raise invalid_credentials

    if hasattr(user, "is_active") and not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    access_token = create_access_token(data={"sub": user.id})
    return TokenResponse(access_token=access_token)
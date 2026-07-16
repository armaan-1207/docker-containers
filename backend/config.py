"""
config.py
==========
Central settings for the AEGIS backend. All values are loaded from
environment variables (or the backend/.env file via pydantic-settings).

Key security notes:
  - SECRET_KEY must be set to a unique 32+ char random value in production.
    The startup guard below raises RuntimeError if the placeholder value is
    detected at DEBUG=False.
  - REDIS_URL must include the password when Redis is password-protected
    (format: redis://:PASSWORD@host:port/db). The validator below injects
    REDIS_PASSWORD into the URL if it is not already present.
  - CORS_ALLOWED_ORIGINS should list Chrome extension origins and any
    dashboard domains — never use the wildcard "*" in production.
  - ARTIFACT_RETENTION_DAYS controls how long scan artifacts are kept on
    disk before the hourly file_cleanup task purges them (finding #8).
"""

from typing import Optional
from urllib.parse import urlparse, urlunparse

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# pydantic v2 — needed for typed info.data access in validators
try:
    from pydantic import ValidationInfo
except ImportError:
    ValidationInfo = object  # type: ignore[misc,assignment]


class Settings(BaseSettings):
    # -------------------------
    # Application
    # -------------------------
    APP_NAME: str = "AEGIS Backend"
    DEBUG: bool = False

    # -------------------------
    # Authentication
    # -------------------------
    SECRET_KEY: str = "change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # -------------------------
    # CORS (finding #16)
    # Comma-separated list of allowed origins, e.g.:
    #   chrome-extension://abcdef123456,https://dashboard.example.com
    # -------------------------
    CORS_ALLOWED_ORIGINS: str = ""

    # -------------------------
    # Database
    # -------------------------
    DATABASE_URL: str = "postgresql+psycopg2://aegis_user:aegis_pass@postgres:5432/aegis_db"
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_ECHO: bool = False

    # -------------------------
    # Redis / Celery
    # REDIS_PASSWORD is injected by docker-compose from .env.
    # REDIS_URL is built by the validator below if it doesn't already
    # include the password (e.g. redis://redis:6379/0 → redis://:pass@redis:6379/0).
    # -------------------------
    REDIS_PASSWORD: str = ""
    REDIS_URL: str = "redis://redis:6379/0"

    @field_validator("REDIS_URL", mode="after")
    @classmethod
    def _inject_redis_password(cls, v: str, info) -> str:
        """
        If REDIS_PASSWORD is set and the REDIS_URL does not already include
        credentials, inject the password so the Redis client authenticates.

        Input:  redis://redis:6379/0
        Output: redis://:PASSWORD@redis:6379/0

        Bug fix: original code used parsed._replace(netloc=...) which discards
        the path component (/0 = database index). We now use urlunparse with
        an explicit 6-tuple that preserves scheme, path, query, fragment.
        """
        password = (info.data or {}).get("REDIS_PASSWORD", "")
        if not password:
            return v
        parsed = urlparse(v)
        if parsed.password:
            # Credentials already present in the URL — leave as-is
            return v
        # Inject password (username is empty, Redis only uses password).
        # Build netloc as ":PASSWORD@host:port", then reconstruct full URL.
        host = parsed.hostname or "redis"
        port = parsed.port or 6379
        new_netloc = f":{password}@{host}:{port}"
        return urlunparse((
            parsed.scheme,
            new_netloc,
            parsed.path,       # preserves /0, /1, etc (DB index)
            parsed.params,
            parsed.query,
            parsed.fragment,
        ))

    # IMPORTANT — field ordering: CELERY_BROKER_URL and CELERY_RESULT_BACKEND are
    # declared HERE (after REDIS_URL) so that by the time their validator fires,
    # info.data already contains the password-injected REDIS_URL value.
    # In Pydantic v2, validators run in field declaration order; declaring these
    # fields before REDIS_URL would make info.data["REDIS_URL"] contain the raw
    # (no-password) URL, breaking Redis broker auth.
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    @field_validator("CELERY_BROKER_URL", "CELERY_RESULT_BACKEND", mode="before")
    @classmethod
    def _default_to_redis_url(cls, v, info) -> str:
        """Default Celery URLs to the (already-password-injected) REDIS_URL."""
        if v not in (None, ""):
            return v
        # At this point info.data["REDIS_URL"] has already been through
        # _inject_redis_password because REDIS_URL is declared first.
        return info.data.get("REDIS_URL") or "redis://redis:6379/0"

    # -------------------------
    # ML Model
    # -------------------------
    LIGHTGBM_MODEL_PATH: str = "models/lightgbm.pkl"

    # -------------------------
    # Shared Storage
    # -------------------------
    SHARED_DIR: str = "/shared/scans"

    # How many days to retain per-scan artifact directories on the shared
    # volume before the hourly file_cleanup task purges them (finding #8).
    ARTIFACT_RETENTION_DAYS: int = 14

    SANDBOX_IMAGE: str = "aegis-sandbox:latest"
    SHARED_SCANS_VOLUME: str = "shared_scans"
    SANDBOX_TIMEOUT_SEC: int = 120

    # -------------------------
    # Alerting
    # -------------------------
    SLACK_WEBHOOK_URL: str = ""

    # -------------------------
    # Threat Intelligence APIs
    # -------------------------
    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OPENPHISH_API_KEY: str = ""

    # -------------------------
    # Risk Thresholds
    # -------------------------
    SAFE_THRESHOLD: int = 20
    LOW_THRESHOLD: int = 40
    MEDIUM_THRESHOLD: int = 60
    HIGH_THRESHOLD: int = 80

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
    )


settings = Settings()

if not settings.DEBUG and settings.SECRET_KEY == "change-this-in-production":
    raise RuntimeError(
        "SECRET_KEY is still the default placeholder value while DEBUG=False. "
        "Set a real 32+ char random SECRET_KEY in backend/.env before running "
        "in production — this key signs every JWT, so leaving the default "
        "means anyone can forge valid auth tokens."
    )
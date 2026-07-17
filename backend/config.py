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
  - DATABASE_URL's password is now derived from AEGIS_DB_PASSWORD the same
    way (see "Database" section below) -- this fixes a real deployment
    bug: AEGIS_DB_PASSWORD (root .env, used by postgres/init.sh to create
    the aegis_user role) and DATABASE_URL's embedded password (backend/.env,
    a separate file) had to be kept in sync BY HAND with no passthrough
    connecting them, and no validation catching drift. A backend/.env
    written before -- or independently of -- the root .env silently
    authenticates with the wrong password: Postgres itself starts fine,
    the backend/Celery containers just can't log in, surfacing as
    `password authentication failed for user "aegis_user"` in a loop,
    forever, with the container marked unhealthy and every dependent
    service refusing to start. docker-compose.yml now passes
    AEGIS_DB_PASSWORD through to backend/celery_worker/celery_beat as a
    real environment variable (not just env_file), and the validator
    below makes it authoritative over whatever backend/.env's DATABASE_URL
    happens to contain -- there is now exactly one place this password is
    actually set (root .env), not two.
  - CORS_ALLOWED_ORIGINS should list Chrome extension origins and any
    dashboard domains — never use the wildcard "*" in production.
  - ARTIFACT_RETENTION_DAYS controls how long scan artifacts are kept on
    disk before the hourly file_cleanup task purges them (finding #8).
"""

import logging
from typing import Optional
from urllib.parse import urlparse, urlunparse

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# pydantic v2 — needed for typed info.data access in validators
try:
    from pydantic import ValidationInfo
except ImportError:
    ValidationInfo = object  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


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
    ALLOW_LEGACY_BCRYPT: bool = True

    # -------------------------
    # CORS (finding #16)
    # Comma-separated list of allowed origins, e.g.:
    #   chrome-extension://abcdef123456,https://dashboard.example.com
    # -------------------------
    CORS_ALLOWED_ORIGINS: str = ""
    ALLOWED_HOSTS: str = "localhost,127.0.0.1,backend,nginx"

    # -------------------------
    # Database
    # AEGIS_DB_PASSWORD is the SAME credential postgres/init.sh uses to
    # create the aegis_user role (sourced from the root .env, and now
    # passed through to this container by docker-compose.yml's
    # x-backend-common environment block -- see docker-compose.yml).
    # DATABASE_URL is declared AFTER it so the validator below can read
    # the already-resolved value via info.data (pydantic v2 validators
    # only see previously-declared fields — same ordering constraint
    # noted below for REDIS_PASSWORD/REDIS_URL).
    # -------------------------
    AEGIS_DB_PASSWORD: str = ""
    DATABASE_URL: str = "postgresql+psycopg2://aegis_user:aegis_pass@postgres:5432/aegis_db"
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_ECHO: bool = False

    @field_validator("DATABASE_URL", mode="after")
    @classmethod
    def _inject_db_password(cls, v: str, info) -> str:
        """
        Make AEGIS_DB_PASSWORD authoritative over whatever password (if
        any) is already embedded in DATABASE_URL.

        This is deliberately the OPPOSITE precedence of the Redis
        validator below (which leaves an existing embedded password
        alone). Here, the whole point is to eliminate a second place
        this credential can drift: AEGIS_DB_PASSWORD is what Postgres
        actually used to create the role (postgres/init.sh), so it's
        the one source of truth. If DATABASE_URL's embedded password
        differs from it, DATABASE_URL was wrong, not AEGIS_DB_PASSWORD --
        overriding it here is the fix, not a trade-off.

        If AEGIS_DB_PASSWORD isn't set at all (e.g. a non-Docker local
        run that just wants to point DATABASE_URL at some other
        Postgres directly), this is a no-op and DATABASE_URL is used
        exactly as given.
        """
        password = (info.data or {}).get("AEGIS_DB_PASSWORD", "")
        if not password:
            return v

        parsed = urlparse(v)
        if parsed.password and parsed.password != password:
            logger.warning(
                "DATABASE_URL's embedded password does not match "
                "AEGIS_DB_PASSWORD -- using AEGIS_DB_PASSWORD (the value "
                "postgres/init.sh actually created the aegis_user role "
                "with). If you intended to point at a different "
                "database entirely, leave AEGIS_DB_PASSWORD unset."
            )

        username = parsed.username or "aegis_user"
        host = parsed.hostname or "postgres"
        port = parsed.port or 5432
        new_netloc = f"{username}:{password}@{host}:{port}"
        return urlunparse((
            parsed.scheme,
            new_netloc,
            parsed.path,       # preserves /aegis_db
            parsed.params,
            parsed.query,
            parsed.fragment,
        ))

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

    SANDBOX_NETWORK: Optional[str] = None
    SANDBOX_IMAGE: str = "aegis-sandbox:v1.0.0@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2"
    SHARED_SCANS_VOLUME: Optional[str] = None
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

if not settings.DEBUG:
    for secret_name in ("SECRET_KEY", "AEGIS_DB_PASSWORD", "REDIS_PASSWORD"):
        val = getattr(settings, secret_name, "")
        if not val or val.startswith("CHANGE_THIS_") or val == "change-this-in-production" or len(val) < 32:
            raise RuntimeError(
                f"{secret_name} is invalid, weak, or still holds a default placeholder value ('{val}') while DEBUG=False. "
                f"Set a strong random secret (32+ characters) in backend/.env before running in production."
            )

    hosts = [h.strip() for h in settings.ALLOWED_HOSTS.split(",") if h.strip()]
    if not hosts or "*" in hosts:
        raise RuntimeError(
            "ALLOWED_HOSTS is empty or contains wildcard '*' while DEBUG=False. "
            "Explicitly define allowed domain hostnames in ALLOWED_HOSTS for production."
        )

    origins = [o.strip() for o in settings.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]
    if not origins:
        raise RuntimeError(
            "CORS_ALLOWED_ORIGINS is not set while DEBUG=False. "
            "Explicitly configure CORS_ALLOWED_ORIGINS with allowed origins before deploying."
        )

    if ":latest" in settings.SANDBOX_IMAGE or "@sha256:" not in settings.SANDBOX_IMAGE:
        raise RuntimeError(
            f"SANDBOX_IMAGE ('{settings.SANDBOX_IMAGE}') uses mutable tag or lacks @sha256 digest while DEBUG=False. "
            "Pin SANDBOX_IMAGE by immutable digest before deploying."
        )
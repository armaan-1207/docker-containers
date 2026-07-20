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
from typing import Optional, Literal
from urllib.parse import urlparse, urlunparse, quote_plus, unquote

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
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    REQUIRE_REAL_CERT: bool = False
    BACKUP_DIR: str = "/backups"
    BACKUP_ENCRYPTION_KEY: str = ""

    @property
    def is_production(self) -> bool:
        env = (self.ENVIRONMENT or "").lower().strip()
        return env not in ("development", "dev", "test", "testing", "local")

    def __repr__(self) -> str:
        return f"<Settings APP_NAME={self.APP_NAME!r} ENVIRONMENT={self.ENVIRONMENT!r} [CREDENTIALS AND URLS SCRUBBED]>"

    def __str__(self) -> str:
        return self.__repr__()

    # -------------------------
    # Authentication
    # -------------------------
    SECRET_KEY: str = "change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALLOW_LEGACY_BCRYPT: bool = False
    CLAMAV_HOST: str = "clamav"
    CLAMAV_PORT: int = 3310
    CLAMAV_FAIL_CLOSED: bool = True
    JWT_REVOCATION_FAIL_CLOSED: bool = True
    JWT_ISSUER: str = "aegis-auth-v1"
    SUPERUSER_EMAILS: list[str] = []
    HIBP_FAIL_CLOSED: bool = False
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_SECONDS: int = 900  # 15 minutes
    AUTH_LOCKOUT_FAIL_CLOSED: bool = True
    MAX_WEBSOCKET_CONNECTIONS_PER_USER: int = 5

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
        if parsed.password and unquote(parsed.password) != password:
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
        new_netloc = f"{quote_plus(username)}:{quote_plus(password)}@{host}:{port}"
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
    REDIS_SECURITY_PASSWORD: str = ""
    REDIS_URL: str = "redis://redis:6379/0"
    REDIS_SECURITY_URL: str = "redis://redis_security:6379/0"
    @field_validator("REDIS_URL", "REDIS_SECURITY_URL", mode="after")
    @classmethod
    def _inject_redis_password(cls, v: str, info) -> str:
        """
        If REDIS_PASSWORD (or REDIS_SECURITY_PASSWORD for security redis) is set and
        the URL does not already include credentials, inject the password so the Redis
        client authenticates.
        """
        data = info.data or {}
        password = data.get("REDIS_PASSWORD", "")
        if info.field_name == "REDIS_SECURITY_URL" or "redis_security" in v:
            password = data.get("REDIS_SECURITY_PASSWORD") or password

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
        new_netloc = f":{quote_plus(password)}@{host}:{port}"
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

    # How many days to retain security incident records and child IOCs
    # in the database before archival or deletion.
    INCIDENT_RETENTION_DAYS: int = 365

    SANDBOX_NETWORK: Optional[str] = "aegis_sandbox_net"
    SANDBOX_IMAGE: str = "aegis-sandbox@sha256:6a132eb6c9155b0e0b2df6d680b061fe570db4fa57ebd06579484717d038d767"
    SANDBOX_RUNNER_SECRET: str = ""
    SHARED_SCANS_VOLUME: Optional[str] = "aegis_shared_scans"
    SANDBOX_TIMEOUT_SEC: int = 120
    ALLOW_GLOB_FALLBACK: bool = False

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
    MEDIUM_THRESHOLD: int = 70
    HIGH_THRESHOLD: int = 85
    SANDBOX_PRELIMINARY_THRESHOLD: int = 0
    LOG_LEVEL: str = "INFO"

    # Trusted Domain Allowlist (`quickscan.py` finding #11)
    TRUSTED_ALLOWLIST_DOMAINS: list[str] = [
        "google.com",
        "github.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
    ]

    @field_validator("SUPERUSER_EMAILS", "TRUSTED_ALLOWLIST_DOMAINS", mode="before")
    @classmethod
    def _parse_list_str(cls, v: any) -> list[str]:
        """
        Accepts either JSON array format '["a@b.com"]' or comma-separated strings 'a@b.com,c@d.com'
        when loading from environment or .env files.
        """
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()

# Secure-by-default guardrails

if settings.is_production and not settings.REQUIRE_REAL_CERT:
    raise RuntimeError(
        f"Production secure-by-default check: ENVIRONMENT is '{settings.ENVIRONMENT}' (treated as production) but REQUIRE_REAL_CERT is False. "
        "Real TLS certificates must be enforced in production/staging deployments to prevent MITM attacks."
    )

if settings.is_production:
    for secret_name in ("SECRET_KEY", "AEGIS_DB_PASSWORD", "REDIS_PASSWORD", "REDIS_SECURITY_PASSWORD", "SANDBOX_RUNNER_SECRET"):
        val = getattr(settings, secret_name, "")
        if not val or val.startswith("CHANGE_THIS_") or val == "change-this-in-production" or len(val) < 32:
            raise RuntimeError(
                f"Secure-by-default check: {secret_name} is invalid, weak, or still holds a default placeholder value ('{val}'). "
                f"Set a strong random secret (32+ characters) in backend/.env before running in production."
            )

hosts = [h.strip() for h in settings.ALLOWED_HOSTS.split(",") if h.strip()]
_default_internal_hosts = {"localhost", "127.0.0.1", "backend", "nginx", "0.0.0.0"}  # nosec B104
if not hosts or "*" in hosts or (settings.is_production and all(h.lower() in _default_internal_hosts for h in hosts)):
    if settings.is_production:
        raise RuntimeError(
            f"Secure-by-default check: ALLOWED_HOSTS ({settings.ALLOWED_HOSTS!r}) is empty, contains wildcard '*', or only contains default internal hostnames in '{settings.ENVIRONMENT}'. "
            "Explicitly define your public domain hostname(s) (e.g. api.yourdomain.com) in ALLOWED_HOSTS before deploying to production."
        )

origins = [o.strip() for o in settings.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]
if not origins:
    if settings.is_production:
        raise RuntimeError(
            f"Secure-by-default check: CORS_ALLOWED_ORIGINS is not set in '{settings.ENVIRONMENT}'. "
            "Explicitly configure CORS_ALLOWED_ORIGINS with allowed origins before running."
        )

if ":latest" in settings.SANDBOX_IMAGE or ("@sha256:" not in settings.SANDBOX_IMAGE and not settings.SANDBOX_IMAGE.startswith("sha256:")):
    raise RuntimeError(
        f"Secure-by-default check: SANDBOX_IMAGE ('{settings.SANDBOX_IMAGE}') uses mutable tag or lacks sha256 digest. "
        "Pin SANDBOX_IMAGE by immutable digest before running."
    )

_PLACEHOLDER_SANDBOX_DIGEST = "aegis-sandbox@sha256:454a806c1149eb37e1c09003c2aa2a86ec5d9c5d5c9650a23308117eb2d00f9c"
if settings.is_production and settings.SANDBOX_IMAGE == _PLACEHOLDER_SANDBOX_DIGEST:
    raise RuntimeError(
        f"Secure-by-default check: SANDBOX_IMAGE ('{settings.SANDBOX_IMAGE}') is still set to the default placeholder digest. "
        "You must run 'make pin-sandbox' (or 'python scripts/pin_sandbox.py') to build and pin the actual local sandbox image before running in production."
    )

if not settings.CLAMAV_FAIL_CLOSED and settings.is_production:
    raise RuntimeError(
        f"Secure-by-default check: CLAMAV_FAIL_CLOSED is False in '{settings.ENVIRONMENT}'. "
        "Anti-malware scanning must be set to fail-closed to prevent un-scanned artifact ingestion."
    )
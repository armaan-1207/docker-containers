from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    # Database
    # -------------------------
    DATABASE_URL: str = "postgresql+psycopg2://aegis_user:aegis_pass@postgres:5432/aegis_db"
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_ECHO: bool = False

    # -------------------------
    # Redis / Celery
    # -------------------------
    REDIS_URL: str = "redis://redis:6379/0"

    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    @field_validator("CELERY_BROKER_URL", "CELERY_RESULT_BACKEND", mode="before")
    @classmethod
    def _default_to_redis_url(cls, v, info):
        if v not in (None, ""):
            return v
        return info.data.get("REDIS_URL") or "redis://redis:6379/0"

    # -------------------------
    # ML Model
    # -------------------------
    LIGHTGBM_MODEL_PATH: str = "models/lightgbm.pkl"

    # -------------------------
    # Shared Storage
    # -------------------------
    SHARED_DIR: str = "/shared/scans"

    # -------------------------
    # Sandbox Service
    # -------------------------
    SANDBOX_SERVICE_URL: str = "http://sandbox:9000"
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

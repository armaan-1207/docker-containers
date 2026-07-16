
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, HttpUrl, Field


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class QuickScanRequest(BaseModel):

    url: HttpUrl
    tab_id: Optional[int] = Field(
        default=None,
        description="Chrome tab id, so the extension can correlate the response back to the right tab.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://example.com/login",
                "tab_id": 12,
            }
        }
    )


class QuickScanResponse(BaseModel):

    url: str
    domain: str
    risk_level: RiskLevel
    risk_score: float = Field(..., ge=0.0, le=100.0, description="0-100 risk score from LightGBM")
    is_whitelisted: bool = False
    cached: bool = Field(default=False, description="True if this result came from Redis cache")
    reasons: list[str] = Field(default_factory=list, description="Short human-readable signals, e.g. 'domain registered 2 days ago'")
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://example.com/login",
                "domain": "example.com",
                "risk_level": "LOW",
                "risk_score": 12.5,
                "is_whitelisted": False,
                "cached": False,
                "reasons": ["Domain age > 5 years", "No blacklist matches"],
                "scanned_at": "2026-07-14T10:00:00Z",
            }
        }
    )

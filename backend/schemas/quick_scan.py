"""
schemas/quick_scan.py
======================
Pydantic models for the /api/scans/quick endpoint.

Security hardening (findings #1 & #2):
  - QuickScanResponse now includes is_placeholder: bool so the browser
    extension can structurally distinguish between a real ML verdict and a
    random-number placeholder. The extension must render a neutral
    "Processing…" state (not a definitive verdict badge) when this is True.
  - The service layer (services/quickscan.py) must NOT write placeholder
    results to Redis cache (prevents cache-poisoning with fabricated scores).
"""

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

    # ── Security finding #1 fix ──────────────────────────────────────────
    # Clients (browser extension) MUST check this flag before rendering a
    # definitive risk badge. When True the ML model is not yet wired in and
    # the score is a random placeholder — render "Scanning / Processing"
    # rather than SAFE / LOW / MEDIUM / HIGH / CRITICAL.
    is_placeholder: bool = Field(
        default=False,
        description=(
            "True when the risk_score was produced by a placeholder model "
            "(LightGBM not yet wired in). Clients must NOT display this as "
            "a definitive verdict — render a neutral 'Processing' state instead."
        ),
    )

    reasons: list[str] = Field(
        default_factory=list,
        description="Short human-readable signals, e.g. 'domain registered 2 days ago'",
    )
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
                "is_placeholder": False,
                "reasons": ["Domain age > 5 years", "No blacklist matches"],
                "scanned_at": "2026-07-14T10:00:00Z",
            }
        }
    )

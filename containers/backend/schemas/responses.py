from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field
class ErrorResponse(BaseModel):
    error: bool = True
    status_code: int
    detail: str
    path: Optional[str] = Field(default=None, description="Endpoint that raised the error")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "error": True,
                "status_code": 401,
                "detail": "Could not validate credentials",
                "path": "/api/scans/quick",
                "timestamp": "2026-07-14T10:00:00Z",
            }
        }
    )


class SuccessResponse(BaseModel):
    success: bool = True
    message: str
    data: Optional[Any] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "message": "Operation completed",
                "data": None,
            }
        }
    )


class HealthCheckResponse(BaseModel):
    status: str = "ok"
    service: str = "cyber-backend"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class JobStatusUpdate(BaseModel):

    job_id: str
    status: str = Field(..., description="PROCESSING | COMPLETE | FAILED")
    url: Optional[str] = None
    risk_level: Optional[str] = None
    risk_score: Optional[float] = None
    reasons: Optional[list[str]] = None
    error: Optional[str] = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "job_id": "c56a4180-65aa-42ec-a945-5fd21dec0538",
                "status": "COMPLETE",
                "url": "https://example.com/login",
                "risk_level": "HIGH",
                "risk_score": 82.3,
                "reasons": ["Layout mismatch vs known brand", "Form posts to unrelated domain"],
                "error": None,
                "updated_at": "2026-07-14T10:01:12Z",
            }
        }
    )

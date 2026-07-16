
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, HttpUrl, Field


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class Stage2Request(BaseModel):

    url: HttpUrl
    tab_id: Optional[int] = Field(
        default=None,
        description="Chrome tab id this screenshot belongs to.",
    )
    screenshot_base64: str = Field(
        ...,
        description="Base64-encoded PNG/JPEG from chrome.tabs.captureVisibleTab()",
    )
    html: Optional[str] = Field(
        default=None,
        description="document.documentElement.outerHTML from the scanned tab, "
        "used for DOM feature extraction. Falls back to an empty placeholder "
        "if omitted.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://example.com/login",
                "tab_id": 12,
                "screenshot_base64": "iVBORw0KGgoAAAANSUhEUgAA...",
                "html": "<html><head><title>Login</title></head><body>...</body></html>",
            }
        }
    )


class Stage2Response(BaseModel):

    scan_id: str = Field(..., description="The scan's id - use this to open /ws/scan/{scan_id}")
    job_id: str = Field(..., description="Celery task id for the queued browser_features task (polling only)")
    status: JobStatus = JobStatus.QUEUED
    url: str
    screenshot_saved_path: Optional[str] = Field(
        default=None,
        description="Path inside the shared Docker volume, e.g. /shared/scans/abc123.png",
    )
    queued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "scan_id": "fa8c3264-1111-4a2b-9c3d-abcdef123456",
                "job_id": "c56a4180-65aa-42ec-a945-5fd21dec0538",
                "status": "QUEUED",
                "url": "https://example.com/login",
                "screenshot_saved_path": "/shared/scans/c56a4180.png",
                "queued_at": "2026-07-14T10:00:05Z",
            }
        }
    )

import os
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import User, Scan
from auth.dependencies import get_current_user
from config import settings

from schemas.quick_scan import QuickScanRequest, QuickScanResponse
from schemas.stage2 import Stage2Request, Stage2Response

from services.quickscan import run_quickscan
from services.stage2_analysis import run_stage2_analysis, _validate_scan_id, _scan_dir

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Whitelist of allowed scan artifacts to prevent path traversal / sensitive data leakage
_ALLOWED_ARTIFACTS = {
    "browser.html",
    "browser.png",
    "sandbox.png",
    "risk_report.json",
    "browser_features.json",
    "consistency_report.json",
    "sandbox_metadata.json",
}


def _sanitize_html_content(html: str) -> str:
    """
    Sanitize captured raw phishing HTML for safe viewing inside an analyst iframe/dashboard.
    Strips active script execution elements, event handler attributes, and dangerous URI schemes.
    """
    try:
        import nh3
        return nh3.clean(html)
    except ImportError:
        logger.warning("nh3 not installed! Falling back to stripping text.")
        return html.replace("<", "&lt;").replace(">", "&gt;")
    except Exception as e:
        logger.warning("HTML sanitization error: %s, returning stripped text", e)
        return html.replace("<", "&lt;").replace(">", "&gt;")


@router.post("/quick", response_model=QuickScanResponse)
async def quick_scan(
    payload: QuickScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        result = await run_quickscan(payload=payload, user=current_user, db=db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        # Full details go to the server log only -- a raw str(e) in the
        # HTTP response can leak internal paths, DB errors, or stack
        # info to the caller.
        logger.exception(
            "Quick scan failed for url=%s user_id=%s", payload.url, current_user.id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Quick scan failed. Please try again shortly.",
        )

    return result


@router.post("/stage2", response_model=Stage2Response)
async def stage2_scan(
    payload: Stage2Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Asynchronous, screenshot-based deep analysis.
    Flow: validate request -> decode base64 screenshot -> save to shared
          Docker volume -> queue Celery job (sandbox_analysis / consistency /
          risk_fusion) -> return immediately with a job/status reference.
    """
    if not payload.screenshot_base64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing screenshot data.",
        )

    try:
        result = await run_stage2_analysis(payload=payload, user=current_user, db=db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        logger.exception(
            "Stage 2 scan failed for url=%s user_id=%s", payload.url, current_user.id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stage 2 scan failed. Please try again shortly.",
        )

    return result


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve metadata and risk report (if completed) for a specific scan.
    """
    try:
        _validate_scan_id(scan_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    report = None
    report_path = os.path.join(_scan_dir(scan_id), "risk_report.json")
    if os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
        except Exception:
            pass

    return {
        "scan_id": scan.id,
        "url": scan.url,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "severity": scan.severity,
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
        "risk_report": report,
    }


@router.get("/{scan_id}/artifacts/{artifact_name}")
async def get_scan_artifact(
    scan_id: str,
    artifact_name: str,
    sanitized: bool = Query(True, description="Whether to sanitize HTML artifacts against XSS before serving"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve a specific scan artifact (screenshot, DOM snapshot, or JSON report).

    Hardening analyst UI against XSS (security finding):
    When serving captured HTML (`browser.html`), strict Content-Security-Policy
    `sandbox` headers are enforced so the browser renders the DOM purely as inert
    visual HTML without script execution, network access, or cookie/origin access.
    Additionally, `sanitized=true` (default) strips script tags and event handlers.
    """
    try:
        _validate_scan_id(scan_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if artifact_name not in _ALLOWED_ARTIFACTS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requested artifact is not permitted.")

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    file_path = os.path.join(_scan_dir(scan_id), artifact_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact file not found.")

    if artifact_name == "browser.html":
        if not sanitized:
            is_su = getattr(current_user, "is_superuser", False) or (
                current_user.email in getattr(settings, "SUPERUSER_EMAILS", [])
            )
            if not is_su:
                logger.warning(
                    "[AUDIT_ALERT] Unauthorized attempt to download unsanitized HTML artifact %s by user %s (id=%s)",
                    artifact_name,
                    current_user.email,
                    current_user.id,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Serving unsanitized raw HTML artifacts requires superuser privileges.",
                )
            logger.warning(
                "[AUDIT_LOG] Superuser %s (id=%s) downloaded unsanitized HTML artifact for scan %s",
                current_user.email,
                current_user.id,
                scan_id,
            )

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw_html = f.read()
        content = _sanitize_html_content(raw_html) if sanitized else raw_html
        headers = {
            "Content-Security-Policy": "sandbox; default-src 'none'; img-src data: blob: 'self'; style-src 'unsafe-inline' 'self';",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Disposition": 'inline; filename="captured_phishing_page.html"',
        }
        return Response(content=content, media_type="text/html", headers=headers)

    return FileResponse(file_path, filename=artifact_name)
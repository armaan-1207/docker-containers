from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import User
from auth.dependencies import get_current_user

from schemas.quick_scan import QuickScanRequest, QuickScanResponse
from schemas.stage2 import Stage2Request, Stage2Response

from services.quickscan import run_quickscan
from services.stage2_analysis import run_stage2_analysis

router = APIRouter(prefix="/api/scans", tags=["scans"])


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
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Quick scan failed: {str(e)}",
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
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Stage 2 scan failed: {str(e)}",
        )

    return result

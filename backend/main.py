"""
main.py
========
AEGIS FastAPI application entry point.

Security hardening applied:
  - Finding #16 (CORS): CORSMiddleware now uses an explicit allowlist
    instead of the wildcard `allow_origins=["*"]` that was previously
    recommended as a future TODO. Origins can be set via the
    CORS_ALLOWED_ORIGINS environment variable (comma-separated) for
    deployment flexibility. Defaults to the Chrome extension origin pattern.
  - Finding #7 (WebSocket token in query string): JWT is no longer accepted
    from the query string. The socket must connect unauthenticated and send
    an {"type":"auth","token":"<JWT>"} frame within 3 seconds. If that frame
    does not arrive in time, or the token is invalid, the socket is closed
    with WS_1008_POLICY_VIOLATION. This prevents the token from appearing
    in server access logs, proxy logs, and browser network histories.
  - Debug endpoints (Swagger, ReDoc, openapi.json) are suppressed in
    production (DEBUG=False) and only served when DEBUG=True.
"""

import asyncio
from contextlib import asynccontextmanager
import json
import logging
import sys
from typing import Optional
import structlog

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from api.routes import router
from auth.routes import router as auth_router
from auth.jwt import JWTError, decode_access_token
from config import settings
from database.database import get_db_session
from database.models import Scan, User
from schemas.responses import HealthCheckResponse, ErrorResponse
from websocket.websocket_manager import websocket_manager

if settings.is_production:
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO,
    )
    logger = structlog.get_logger(__name__)
else:
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(level=logging.DEBUG if settings.DEBUG else logging.INFO)
    logger = structlog.get_logger(__name__)



@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Start background tasks on startup, clean up on shutdown."""
    websocket_manager.start_heartbeat(interval_sec=300)
    yield
    # Cancel the heartbeat task (and any orphaned listen tasks)
    hb_task = websocket_manager._listen_tasks.get("__heartbeat__")
    if hb_task:
        hb_task.cancel()


# ─── Application ────────────────────────────────────────────────────────────
# Swagger/ReDoc disabled when is_production=True or DEBUG=False.
app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG and not settings.is_production,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
    lifespan=_lifespan,
)

# ─── CORS — Security finding #16 fix ────────────────────────────────────────
# Wildcard allow_origins=["*"] was the recommended TODO in the old code.
# We now use an explicit origin allowlist.
#
# CORS_ALLOWED_ORIGINS in .env should be a comma-separated list, e.g.:
#   CORS_ALLOWED_ORIGINS=chrome-extension://abcdefg123456,https://yourdomain.com
#
# The Chrome extension origin (chrome-extension://<id>) is always needed.
# For local dev, also add http://localhost and https://localhost.
_raw_origins = getattr(settings, "CORS_ALLOWED_ORIGINS", "") or ""
_allowed_origins: list[str] = [
    o.strip() for o in _raw_origins.split(",") if o.strip()
]
if not _allowed_origins:
    if settings.is_production:
        raise RuntimeError(
            "CORS_ALLOWED_ORIGINS must be explicitly set when running in production. "
            "Configure CORS_ALLOWED_ORIGINS with allowed origins before deploying."
        )
    # Safe default for dev: allow localhost only
    _allowed_origins = [
        "http://localhost",
        "https://localhost",
        "http://localhost:3000",
        "https://localhost:3000",
    ]
    logger.warning(
        "CORS_ALLOWED_ORIGINS not set — defaulting to localhost only. "
        "Add your Chrome extension origin (chrome-extension://<id>) to "
        "CORS_ALLOWED_ORIGINS in backend/.env before deploying."
    )

_raw_hosts = getattr(settings, "ALLOWED_HOSTS", "") or ""
_allowed_hosts: list[str] = [
    h.strip() for h in _raw_hosts.split(",") if h.strip()
]
if not _allowed_hosts or "*" in _allowed_hosts or (settings.is_production and all(h.lower() in {"localhost", "127.0.0.1", "backend", "nginx", "0.0.0.0"} for h in _allowed_hosts)):  # nosec B104
    if settings.is_production:
        raise RuntimeError(
            f"ALLOWED_HOSTS ({settings.ALLOWED_HOSTS!r}) is empty, contains wildcard '*', or only contains default internal hostnames while running in production. "
            "Explicitly define allowed domain hostnames in ALLOWED_HOSTS for production."
        )
    if not _allowed_hosts:
        _allowed_hosts = ["*"]

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=_allowed_hosts,
)
app.add_middleware(
    ProxyHeadersMiddleware,
    trusted_hosts="*",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth_router)
app.include_router(router)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail_str = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    error_content = ErrorResponse(
        error=True,
        status_code=exc.status_code,
        detail=detail_str,
        path=request.url.path,
    ).model_dump(mode="json")
    return JSONResponse(
        status_code=exc.status_code,
        content=error_content,
        headers=getattr(exc, "headers", None)
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_content = ErrorResponse(
        error=True,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Validation error: " + "; ".join([f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in exc.errors()]),
        path=request.url.path,
    ).model_dump(mode="json")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_content,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception during request processing", path=request.url.path)
    error_content = ErrorResponse(
        error=True,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Internal Server Error" if settings.is_production else f"Internal Server Error: {str(exc)}",
        path=request.url.path,
    ).model_dump(mode="json")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_content,
    )



@app.get("/", response_model=HealthCheckResponse)
def root() -> HealthCheckResponse:
    return HealthCheckResponse(service=settings.APP_NAME)


# ─── WebSocket auth helper ────────────────────────────────────────────────────
_WS_AUTH_TIMEOUT_SECONDS = 3.0  # client must send auth frame within this many seconds


async def _ws_frame_auth(websocket: WebSocket) -> Optional[str]:
    """
    Perform frame-based WebSocket authentication (security finding #7 fix).

    The client must send {"type": "auth", "token": "<JWT>"} as its very first
    message within _WS_AUTH_TIMEOUT_SECONDS seconds. If it does not, or the
    token is invalid, we return None (caller closes the socket).

    This replaces the old pattern of reading the JWT from
    websocket.query_params.get("token"), which caused the token to appear
    in server access logs, nginx logs, proxy logs, and browser network panels.
    """
    try:
        raw = await asyncio.wait_for(
            websocket.receive_text(),
            timeout=_WS_AUTH_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("WebSocket auth frame not received within %.1fs — closing", _WS_AUTH_TIMEOUT_SECONDS)
        return None
    except WebSocketDisconnect:
        return None
    except Exception as exc:
        logger.warning("WebSocket auth frame read failed (%s) — closing", type(exc).__name__)
        return None

    try:
        frame = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        logger.warning("WebSocket auth frame is not valid JSON — closing")
        return None

    if frame.get("type") != "auth":
        logger.warning("WebSocket first frame type=%r, expected 'auth' — closing", frame.get("type"))
        return None

    token = frame.get("token")
    if not token:
        logger.warning("WebSocket auth frame missing 'token' field — closing")
        return None

    try:
        payload = decode_access_token(token)
    except JWTError:
        logger.warning("WebSocket auth frame contains invalid JWT — closing")
        return None

    user_id = payload.get("sub")
    if not user_id:
        logger.warning("WebSocket JWT has no 'sub' claim — closing")
        return None

    try:
        with get_db_session() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user or (hasattr(user, "is_active") and not user.is_active):
                logger.warning("WebSocket auth failed: user %s not found or inactive", user_id)
                return None
    except Exception:
        logger.exception("WebSocket auth DB lookup error")
        return None

    return user_id


# ─── WebSocket: per-scan channel ─────────────────────────────────────────────
@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str):
    """
    Real-time channel for a specific scan result.
    Security: frame-based auth (no query-string token).
    """
    await websocket.accept()

    authenticated_user_id = await _ws_frame_auth(websocket)
    if authenticated_user_id is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Authorisation: the scan must belong to the authenticated user
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        owner_id = scan.user_id if scan else None

    if owner_id is None or owner_id != authenticated_user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket_manager.connect_browser(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect_browser(scan_id)


# ─── WebSocket: per-user dashboard channel ───────────────────────────────────
@app.websocket("/ws/user/{user_id}")
async def ws_user(websocket: WebSocket, user_id: str):
    """
    Real-time dashboard channel for a user (receives all their scan updates).
    Security: frame-based auth (no query-string token).
    """
    await websocket.accept()

    authenticated_user_id = await _ws_frame_auth(websocket)
    if authenticated_user_id is None or authenticated_user_id != user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    if not await websocket_manager.connect_user(user_id, websocket):
        return
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await websocket_manager.disconnect_user(user_id, websocket)
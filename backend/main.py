from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status
from jose import JWTError

from api.routes import router
from auth.routes import router as auth_router
from auth.jwt import decode_access_token
from config import settings
from database.database import get_db_session
from database.models import Scan
from schemas.responses import HealthCheckResponse
from websocket.websocket_manager import websocket_manager


# SECURITY: Swagger/ReDoc/openapi.json were previously proxied by nginx
# unconditionally with no auth (see nginx.conf's /docs, /redoc,
# /openapi.json blocks) -- a full API schema disclosure to anyone who
# found the path. FastAPI itself now refuses to serve them unless
# DEBUG=True, so nginx's proxy_pass for those routes 404s in
# production regardless of nginx-side config. Leave DEBUG=False in
# production backend/.env; flip to True only for local dev.
app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)


app.include_router(auth_router)
app.include_router(router)


@app.get("/", response_model=HealthCheckResponse)
def root() -> HealthCheckResponse:
    return HealthCheckResponse(service=settings.APP_NAME)


def _authenticate_ws_token(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        payload = decode_access_token(token)
    except JWTError:
        return None
    return payload.get("sub")


@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str):
    token = websocket.query_params.get("token")
    user_id = _authenticate_ws_token(token)
    if user_id is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        owner_id = scan.user_id if scan else None

    if owner_id is None or owner_id != user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket_manager.connect_browser(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect_browser(scan_id)


@app.websocket("/ws/user/{user_id}")
async def ws_user(websocket: WebSocket, user_id: str):
    token = websocket.query_params.get("token")
    authenticated_user_id = _authenticate_ws_token(token)

    if authenticated_user_id is None or authenticated_user_id != user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket_manager.connect_user(user_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect_user(user_id, websocket)
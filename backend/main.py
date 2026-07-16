from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from api.routes import router
from auth.routes import router as auth_router
from config import settings
from websocket.websocket_manager import websocket_manager


app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
)


app.include_router(auth_router)
app.include_router(router)


@app.get("/")
def root():
    return {
        "message": f"{settings.APP_NAME} is running."
    }


@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str):
    await websocket_manager.connect_browser(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()  # keep the connection alive
    except WebSocketDisconnect:
        websocket_manager.disconnect_browser(scan_id)


@app.websocket("/ws/user/{user_id}")
async def ws_user(websocket: WebSocket, user_id: str):
    await websocket_manager.connect_user(user_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect_user(user_id, websocket)

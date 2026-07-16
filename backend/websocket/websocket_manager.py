"""
websocket/websocket_manager.py
================================
"""

import asyncio
import json
import logging
from typing import Dict, Optional, Set

from fastapi import WebSocket
from redis import asyncio as aioredis

from config import settings

logger = logging.getLogger(__name__)


def _scan_channel(scan_id: str) -> str:
    return f"ws:scan:{scan_id}"


def _user_channel(user_id: str) -> str:
    return f"ws:user:{user_id}"


class WebSocketManager:
    def __init__(self):
        self.browser_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, Set[WebSocket]] = {}

        self._redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        self._listen_tasks: Dict[str, asyncio.Task] = {}

    async def connect_browser(self, scan_id: str, websocket: WebSocket) -> None:
        # NOTE: websocket.accept() is called by main.py BEFORE frame-based auth.
        # Calling accept() here again would raise a Starlette RuntimeError
        # ("WebSocket is already accepted"). Do NOT call accept() here.
        self.browser_connections[scan_id] = websocket
        logger.info("[%s] browser connected", scan_id)
        self._listen_tasks[f"browser:{scan_id}"] = asyncio.create_task(
            self._forward_channel(_scan_channel(scan_id), websocket, one_shot=True)
        )

    def disconnect_browser(self, scan_id: str) -> None:
        self.browser_connections.pop(scan_id, None)
        task = self._listen_tasks.pop(f"browser:{scan_id}", None)
        if task:
            task.cancel()
        logger.info("[%s] browser disconnected", scan_id)

    async def connect_user(self, user_id: str, websocket: WebSocket) -> None:
        # NOTE: websocket.accept() is called by main.py BEFORE frame-based auth.
        # Do NOT call accept() here again.
        self.user_connections.setdefault(user_id, set()).add(websocket)
        logger.info("[%s] dashboard user connected", user_id)
        key = f"user:{user_id}:{id(websocket)}"
        self._listen_tasks[key] = asyncio.create_task(
            self._forward_channel(_user_channel(user_id), websocket, one_shot=False)
        )

    def disconnect_user(self, user_id: str, websocket: WebSocket) -> None:
        connections = self.user_connections.get(user_id)
        if connections:
            connections.discard(websocket)
            if not connections:
                self.user_connections.pop(user_id, None)
        key = f"user:{user_id}:{id(websocket)}"
        task = self._listen_tasks.pop(key, None)
        if task:
            task.cancel()
        logger.info("[%s] dashboard user disconnected", user_id)

    async def _forward_channel(self, channel: str, websocket: WebSocket, one_shot: bool) -> None:
        pubsub = self._redis.pubsub()
        try:
            await pubsub.subscribe(channel)
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    await websocket.send_text(message["data"])
                except Exception:
                    logger.exception("[%s] failed to forward message to websocket", channel)
                    break
                if one_shot:
                    break
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("[%s] pubsub listener crashed", channel)
        finally:
            try:
                await pubsub.unsubscribe(channel)
                await pubsub.close()
            except Exception:
                pass

    async def broadcast_risk_update(
        self, scan_id: str, payload: dict, user_id: Optional[str] = None
    ) -> None:
        message = json.dumps(payload, default=str)
        try:
            await self._redis.publish(_scan_channel(scan_id), message)
            if user_id:
                await self._redis.publish(_user_channel(user_id), message)
        except Exception:
            logger.exception("[%s] failed to publish risk update to redis", scan_id)


websocket_manager = WebSocketManager()

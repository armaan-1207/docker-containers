"""
websocket/websocket_manager.py
================================
"""

import asyncio
import json
import logging
import os
from typing import Dict, Optional, Set
import uuid

from fastapi import WebSocket, status
from redis import asyncio as aioredis

from config import settings

logger = logging.getLogger(__name__)


def _scan_channel(scan_id: str) -> str:
    return f"ws:scan:{scan_id}"


def _user_channel(user_id: str) -> str:
    return f"ws:user:{user_id}"


class WebSocketManager:
    def __init__(self):
        self.worker_id = f"worker:{os.getpid()}:{uuid.uuid4().hex[:8]}"
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

        # First check Redis cache (or disk fallback) to avoid hanging on late connection
        # if the scan has already finished and published its result (finding #5 / race condition fix).
        try:
            cached_data = await self._redis.get(f"risk:{scan_id}")
            if not cached_data:
                import os
                report_path = os.path.join(settings.SHARED_DIR, scan_id, "risk_report.json")
                if os.path.exists(report_path):
                    def _read_file():
                        with open(report_path, "r") as f:
                            return f.read()
                    cached_data = await asyncio.to_thread(_read_file)
            if cached_data:
                logger.info("[%s] sending cached risk report immediately to late connecting browser", scan_id)
                await websocket.send_text(cached_data)
                return
        except Exception:
            logger.exception("[%s] error checking risk cache on browser connect, falling back to pubsub", scan_id)

        self._listen_tasks[f"browser:{scan_id}"] = asyncio.create_task(
            self._forward_channel(_scan_channel(scan_id), websocket, one_shot=True, timeout_sec=300)
        )

    def disconnect_browser(self, scan_id: str) -> None:
        self.browser_connections.pop(scan_id, None)
        task = self._listen_tasks.pop(f"browser:{scan_id}", None)
        if task:
            task.cancel()
        logger.info("[%s] browser disconnected", scan_id)

    async def connect_user(self, user_id: str, websocket: WebSocket) -> bool:
        # NOTE: websocket.accept() is called by main.py BEFORE frame-based auth.
        # Do NOT call accept() here again.
        user_socks = self.user_connections.setdefault(user_id, set())
        cnt_key = f"ws_cnt:{user_id}"
        try:
            curr_cnt = await self._redis.incr(cnt_key)
            await self._redis.expire(cnt_key, 86400)  # 24h safety TTL against orphaned keys
            if curr_cnt > settings.MAX_WEBSOCKET_CONNECTIONS_PER_USER:
                await self._redis.decr(cnt_key)
                logger.warning("[%s] user exceeded global max websocket connections (%d), rejecting connection", user_id, settings.MAX_WEBSOCKET_CONNECTIONS_PER_USER)
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Too many concurrent websocket connections")
                return False
        except Exception:
            # Fallback to local worker check if Redis counter fails
            if len(user_socks) >= settings.MAX_WEBSOCKET_CONNECTIONS_PER_USER:
                logger.warning("[%s] user exceeded local max websocket connections (%d), rejecting connection", user_id, settings.MAX_WEBSOCKET_CONNECTIONS_PER_USER)
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Too many concurrent websocket connections")
                return False

        user_socks.add(websocket)
        await self._update_worker_count(user_id, len(user_socks))
        logger.info("[%s] dashboard user connected", user_id)
        key = f"user:{user_id}:{id(websocket)}"
        self._listen_tasks[key] = asyncio.create_task(
            self._forward_channel(_user_channel(user_id), websocket, one_shot=False, timeout_sec=3600)
        )
        return True

    async def disconnect_user(self, user_id: str, websocket: WebSocket) -> None:
        connections = self.user_connections.get(user_id)
        if connections:
            connections.discard(websocket)
            if not connections:
                self.user_connections.pop(user_id, None)
            await self._update_worker_count(user_id, len(connections) if connections else 0)
        else:
            await self._update_worker_count(user_id, 0)
        key = f"user:{user_id}:{id(websocket)}"
        task = self._listen_tasks.pop(key, None)
        if task:
            task.cancel()
        cnt_key = f"ws_cnt:{user_id}"
        try:
            val = await self._redis.decr(cnt_key)
            if val <= 0:
                await self._redis.delete(cnt_key)
        except Exception:
            pass
        logger.info("[%s] dashboard user disconnected", user_id)

    async def _forward_channel(
        self, channel: str, websocket: WebSocket, one_shot: bool, timeout_sec: Optional[int] = None
    ) -> None:
        pubsub = self._redis.pubsub()
        try:
            await pubsub.subscribe(channel)

            async def _listen_loop():
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

            if timeout_sec:
                await asyncio.wait_for(_listen_loop(), timeout=timeout_sec)
            else:
                await _listen_loop()
        except asyncio.TimeoutError:
            logger.warning("[%s] pubsub listener timed out after %ss, closing connection", channel, timeout_sec)
            try:
                await websocket.close()
            except Exception:
                pass
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

    async def _scan_keys(self, pattern: str) -> list[str]:
        keys = []
        cursor = "0"
        while cursor != 0:
            cursor, partial = await self._redis.scan(cursor=cursor, match=pattern, count=500)
            if isinstance(cursor, bytes):
                cursor = cursor.decode()
            cursor = int(cursor)
            keys.extend(partial)
        return keys

    async def reconcile_counters(self) -> None:
        """
        Reconcile Redis ws_cnt:{user_id} counters across multi-process workers using SCAN.

        In multi-process Uvicorn deployments (--workers > 1), each worker tracks
        its active connections under a worker-scoped Redis key:
            ws_worker:{user_id}:{self.worker_id} (TTL 600s)

        During reconciliation:
        1. Each worker refreshes its worker-scoped counts with a 600s TTL.
        2. We scan across all alive worker keys using SCAN (non-blocking) and set the
           global authoritative ws_cnt:{user_id} sum.
        """
        for user_id, sockets in list(self.user_connections.items()):
            actual = len(sockets)
            await self._update_worker_count(user_id, actual)

        try:
            keys = await self._scan_keys("ws_worker:*:*")
            user_ids = set()
            for k in keys:
                parts = k.split(":")
                if len(parts) >= 3:
                    user_ids.add(parts[1])
            user_ids.update(self.user_connections.keys())

            for user_id in user_ids:
                worker_keys = [k for k in keys if k.startswith(f"ws_worker:{user_id}:")]
                if not worker_keys:
                    # Check if there are keys that were added or missed in scan just in case
                    worker_keys = await self._scan_keys(f"ws_worker:{user_id}:*")
                if worker_keys:
                    counts = await asyncio.gather(*(self._redis.get(wk) for wk in worker_keys), return_exceptions=True)
                    total = sum(int(c) for c in counts if isinstance(c, (int, str)) and str(c).isdigit())
                    if total > 0:
                        await self._redis.set(f"ws_cnt:{user_id}", total, ex=86400)
                        logger.debug("[heartbeat] Reconciled global ws_cnt for user %s -> %d across %d workers", user_id, total, len(worker_keys))
                    else:
                        await self._redis.delete(f"ws_cnt:{user_id}")
                else:
                    await self._redis.delete(f"ws_cnt:{user_id}")
        except Exception:
            logger.exception("[heartbeat] Unexpected error during multi-worker counter aggregation")

    async def _update_worker_count(self, user_id: str, count: int) -> None:
        key = f"ws_worker:{user_id}:{self.worker_id}"
        try:
            if count > 0:
                await self._redis.set(key, count, ex=600)
            else:
                await self._redis.delete(key)
        except Exception:
            pass

    async def _heartbeat_loop(self, interval_sec: int = 300) -> None:
        """Background coroutine that reconciles counters on a fixed interval."""
        while True:
            try:
                await asyncio.sleep(interval_sec)
                await self.reconcile_counters()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("[heartbeat] Unexpected error during counter reconciliation")

    def start_heartbeat(self, interval_sec: int = 300) -> asyncio.Task:
        """
        Schedule the heartbeat reconciliation loop as a background asyncio Task.
        Should be called once the event loop is running (e.g. in a FastAPI startup handler).
        """
        task = asyncio.create_task(self._heartbeat_loop(interval_sec))
        self._listen_tasks["__heartbeat__"] = task
        logger.info("[heartbeat] WebSocket counter reconciliation started (interval=%ds)", interval_sec)
        return task


websocket_manager = WebSocketManager()

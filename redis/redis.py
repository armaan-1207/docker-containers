import json
from typing import Any, Optional

import redis

from config import settings

# decode_responses=True so we get back Python strings instead of bytes
redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


def get_redis() -> redis.Redis:

    return redis_client


def cache_get(key: str) -> Optional[dict]:
    
    raw = redis_client.get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None


def cache_set(key: str, value: dict, ttl_seconds: int = 3600) -> None:
    
    redis_client.set(key, json.dumps(value, default=str), ex=ttl_seconds)


def cache_delete(key: str) -> None:
    """Remove a cached key, e.g. to force a re-scan of a domain."""
    redis_client.delete(key)


def cache_exists(key: str) -> bool:
    """Quick existence check without fetching/decoding the value."""
    return redis_client.exists(key) == 1


def build_scan_cache_key(domain: str) -> str:
    
    return f"scan:domain:{domain}"
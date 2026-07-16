# AEGIS Redis Container

Image: redis:7.2-alpine

## Role
1. Celery message broker (task queue)
2. Celery result backend
3. URL/domain scan result cache (1h TTL, LRU eviction)

## Config
  maxmemory: 256MB
  maxmemory-policy: allkeys-lru
  persistence: DISABLED (ephemeral — restart clears cache, that's OK)

## Client code
See redis/redis.py for the Python client wrapper:
  cache_get(key)          -- fetch cached scan result
  cache_set(key, val, ttl) -- store scan result
  cache_delete(key)       -- force re-scan
  build_scan_cache_key(domain) -- canonical cache key

## Connection
  URL: redis://redis:6379/0   (Docker DNS resolves 'redis' hostname)

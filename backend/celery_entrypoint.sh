#!/bin/bash
# =======================================================
# AEGIS Celery — Entrypoint (Worker + Beat)
# 1. Wait for Redis (broker) to be ready
# 2. Wait for Postgres (models need DB)
# 3. exec the celery command passed as CMD
#
# Bug fix: the original Redis probe used the raw REDIS_URL
# (e.g. redis://redis:6379/0) without injecting REDIS_PASSWORD,
# so the probe would fail with "NOAUTH Authentication required"
# when Redis is password-protected — which is always the case in
# our hardened docker-compose.yml. The fix: build the authed URL
# in the probe script itself by reading both REDIS_URL and
# REDIS_PASSWORD and injecting the credential if absent.
# =======================================================
set -e

echo "[celery-entrypoint] Waiting for Redis..."
until python -c "
import os, sys, re

redis_url = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
redis_password = os.environ.get('REDIS_PASSWORD', '')

# Inject password into URL if REDIS_PASSWORD is set and URL has no credentials.
# Matches URLs like redis://redis:6379/0 (no creds) and injects :PASSWORD@
# to produce redis://:PASSWORD@redis:6379/0
if redis_password and '://:' not in redis_url and '@' not in redis_url:
    redis_url = re.sub(r'redis://', f'redis://:{redis_password}@', redis_url, count=1)

try:
    import redis
    r = redis.Redis.from_url(redis_url, socket_connect_timeout=3)
    r.ping()
    print('Redis is ready.')
except Exception as e:
    print(f'Not ready: {e}', file=sys.stderr)
    sys.exit(1)
"; do
    echo "[celery-entrypoint] Redis not ready, retrying in 2s..."
    sleep 2
done

echo "[celery-entrypoint] Waiting for PostgreSQL..."
until python -c "
import psycopg2, os, sys
try:
    url = os.environ.get('DATABASE_URL', '').replace('+psycopg2', '')
    psycopg2.connect(url)
    print('PostgreSQL is ready.')
except Exception as e:
    print(f'Not ready: {e}', file=sys.stderr)
    sys.exit(1)
"; do
    echo "[celery-entrypoint] PostgreSQL not ready, retrying in 2s..."
    sleep 2
done

echo "[celery-entrypoint] Starting Celery: $@"
exec "$@"

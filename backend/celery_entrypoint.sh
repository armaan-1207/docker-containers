#!/bin/bash
# =======================================================
# AEGIS Celery — Entrypoint (Worker + Beat)
# 1. Wait for Redis (broker) to be ready
# 2. Wait for Postgres (models need DB)
# 3. exec the celery command passed as CMD
# =======================================================
set -e

echo "[celery-entrypoint] Waiting for Redis..."
until python -c "
import redis, os, sys
try:
    r = redis.Redis.from_url(os.environ.get('REDIS_URL', 'redis://redis:6379/0'))
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

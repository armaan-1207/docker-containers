#!/bin/bash
# =======================================================
# AEGIS Backend — Container Entrypoint
# 1. Wait for Postgres to be ready
# 2. Run SQLAlchemy create_all (create tables if missing)
# 3. Start Uvicorn
# =======================================================
set -e

echo "[entrypoint] Waiting for PostgreSQL..."
until python -c "
import psycopg2, os, sys
try:
    psycopg2.connect(os.environ['DATABASE_URL'].replace('+psycopg2', ''))
    print('PostgreSQL is ready.')
except Exception as e:
    print(f'Not ready: {e}', file=sys.stderr)
    sys.exit(1)
"; do
    echo "[entrypoint] PostgreSQL not ready yet, retrying in 2s..."
    sleep 2
done

echo "[entrypoint] Running database init (create_all)..."
python -c "
from database.database import init_db
init_db()
print('Database tables ensured.')
"

echo "[entrypoint] Starting Uvicorn..."
exec "$@"

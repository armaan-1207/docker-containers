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
import psycopg2, sys
from config import settings
try:
    psycopg2.connect(settings.DATABASE_URL.replace('+psycopg2', ''))
    print('PostgreSQL is ready.')
except Exception:
    print('PostgreSQL connection not ready yet...', file=sys.stderr)
    sys.exit(1)
"; do
    echo "[entrypoint] PostgreSQL not ready yet, retrying in 2s..."
    sleep 2
done

echo "[entrypoint] Running database migrations (Alembic)..."
python -c "
import psycopg2
from config import settings
from alembic.config import Config
from alembic import command

url = settings.DATABASE_URL.replace('+psycopg2', '')
conn = psycopg2.connect(url)
cur = conn.cursor()
cur.execute(\"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users');\")
users_exists = cur.fetchone()[0]
cur.execute(\"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'alembic_version');\")
alembic_exists = cur.fetchone()[0]
cur.close()
conn.close()

alembic_cfg = Config('alembic.ini')
if users_exists and not alembic_exists:
    print('Existing schema without alembic_version detected. Stamping baseline...')
    command.stamp(alembic_cfg, 'head')
else:
    print('Running alembic upgrade head...')
    command.upgrade(alembic_cfg, 'head')
"

echo "[entrypoint] Starting Uvicorn..."
exec "$@"

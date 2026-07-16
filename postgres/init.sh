#!/bin/sh
# ===================================================
# AEGIS PostgreSQL Init Script
# Runs ONCE when the postgres container first starts
# (placed in /docker-entrypoint-initdb.d/)
#
# Reads AEGIS_DB_PASSWORD from the environment (set in
# docker-compose.yml, sourced from the root .env) instead of
# embedding it as a literal in this file. Only the app user's
# password moves here -- the superuser password is still handled
# natively by the postgres:16-alpine image via POSTGRES_PASSWORD.
# ===================================================
set -e

: "${AEGIS_DB_PASSWORD:?AEGIS_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" <<-EOSQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'aegis_user') THEN
        CREATE ROLE aegis_user LOGIN PASSWORD '${AEGIS_DB_PASSWORD}';
    END IF;
END
\$\$;

SELECT 'CREATE DATABASE aegis_db OWNER aegis_user'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'aegis_db')\gexec
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "aegis_db" <<-EOSQL
GRANT ALL PRIVILEGES ON DATABASE aegis_db TO aegis_user;
GRANT ALL ON SCHEMA public TO aegis_user;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
EOSQL

echo "AEGIS database initialized successfully."
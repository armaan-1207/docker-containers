-- ===================================================
-- AEGIS PostgreSQL Init Script
-- Runs ONCE when the postgres container first starts
-- (placed in /docker-entrypoint-initdb.d/)
-- ===================================================

-- Create the application user (idempotent)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'aegis_user') THEN
        CREATE ROLE aegis_user LOGIN PASSWORD 'aegis_pass';
    END IF;
END
$$;

-- Create the database (idempotent)
SELECT 'CREATE DATABASE aegis_db OWNER aegis_user'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'aegis_db')\gexec

-- Connect to the new database and set up permissions
\connect aegis_db

GRANT ALL PRIVILEGES ON DATABASE aegis_db TO aegis_user;
GRANT ALL ON SCHEMA public TO aegis_user;

-- Enable uuid-ossp extension (for UUID generation)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_trgm for fuzzy text search (domain similarity)
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

\echo 'AEGIS database initialized successfully.'

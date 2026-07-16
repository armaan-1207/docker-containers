# AEGIS PostgreSQL Container

Image: `postgres:16-alpine`

## Role
Primary relational datastore for the AEGIS platform.

## Tables (created by `init_db()` via SQLAlchemy `create_all` on backend start)

| Table | Key columns | Purpose |
|-------|-------------|---------|
| `users` | id, email, hashed_password, is_active, created_at | Auth + user management |
| `scans` | id, user_id, url, status, created_at | Scan lifecycle tracking |
| `incidents` | id, scan_id, severity, risk_score, summary | HIGH/CRITICAL alerts |
| `iocs` | id, incident_id, ioc_type, value | Extracted indicators (IPs, domains, hashes) |
| `statistics` | id=1, total_incidents, critical_count, high_count | Dashboard counters |

## Extensions enabled (by `init.sql`)
- `uuid-ossp` — UUID primary key generation
- `pg_trgm` — fuzzy text search on domains

## Connection string
```
postgresql+psycopg2://aegis_user:aegis_pass@postgres:5432/aegis_db
```

## Credentials
| Role | Username | Password | Access |
|------|----------|----------|--------|
| Superuser | `postgres` | `postgres_root_pass` | Full admin |
| App user | `aegis_user` | `aegis_pass` | `aegis_db` only |

> **Change passwords** in `backend/.env` and `docker-compose.yml` before production.

## Files
| File | Purpose |
|------|---------|
| `init.sql` | Creates `aegis_user`, `aegis_db`, grants, extensions. Runs once on first boot. |

## Volumes
- `postgres_data:/var/lib/postgresql/data` — persistent, survives container restarts

## Useful commands
```powershell
# Connect to postgres shell
docker exec -it aegis_postgres psql -U aegis_user -d aegis_db

# List tables
\dt

# Check scan status counts
SELECT status, count(*) FROM scans GROUP BY status;

# Dump database
docker exec aegis_postgres pg_dump -U aegis_user aegis_db > backup.sql
```

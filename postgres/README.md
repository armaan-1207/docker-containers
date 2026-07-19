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
postgresql+psycopg2://aegis_user:<SET_IN_ENV_AEGIS_DB_PASSWORD>@postgres:5432/aegis_db
```

## Credentials
| Role | Username | Password | Access |
|------|----------|----------|--------|
| Superuser | `postgres` | `<SET_IN_ENV_POSTGRES_ROOT_PASSWORD>` | Full admin |
| App user | `aegis_user` | `<SET_IN_ENV_AEGIS_DB_PASSWORD>` | `aegis_db` only |

> **IMPORTANT:** Credentials must be supplied via `.env` files (`POSTGRES_ROOT_PASSWORD` and `AEGIS_DB_PASSWORD`). Never commit literal credentials to version control.

## Files
| File | Purpose |
|------|---------|
| `init.sql` | Creates `aegis_user`, `aegis_db`, grants, extensions. Runs once on first boot. |

## Volumes
- `postgres_data:/var/lib/postgresql/data` — persistent live database files
- `db_backups:/backups` — dedicated volume for automated logical backups (`aegis_db_backups`)

## Backup & Retention Strategy
Automated backups are handled by Celery Beat and executed inside `celery_worker` (which includes `postgresql-client`).

### 1. Automated Daily Backups (`pg_dump`)
- **Scheduler:** Celery Beat task `daily-db-backup` (`tasks.db_backup`) runs daily at **03:00 UTC**
- **Executor:** `celery_worker` runs `pg_dump -F c -b -v` against `postgres:5432`
- **Storage:** Compressed dumps are written to the `aegis_db_backups` Docker volume, mounted at **`/backups`** in `celery_worker`
- **Filename pattern:** `aegis_db_YYYYMMDD_HHMMSS.dump`
- **Authentication:** Uses a temporary `.pgpass` file with `AEGIS_DB_PASSWORD` (never logged or committed)

Manual one-off backup (same format as the automated job):
```powershell
docker exec aegis_celery_worker pg_dump -h postgres -U aegis_user -F c -b -v -f /backups/aegis_db_manual.dump aegis_db
```

For production deployments requiring minimal RPO (Recovery Point Objective), enable Write-Ahead Log (WAL) archiving (`archive_mode = on` / `pg_waldump`) with `pg_basebackup` for Point-In-Time Recovery (PITR). Note: Regularly verify restores (`pg_restore -C -d postgres ...`) on staging to validate integrity.

### 2. Retention Policy
- **Automated DB backups:** Retain for **7 days** (default `retention_days=7` in `tasks.db_backup`; expired files under `/backups/aegis_db_*.dump` are pruned automatically)
- **Scan artifact & DB record retention (`file_cleanup` task):** Shared volume scan files (`/shared/scans/<scan_id>/`) and corresponding database records (`scans` and `incidents` tables) are automatically purged by Celery Beat's `tasks.file_cleanup` job after **14 days** by default (`ARTIFACT_RETENTION_DAYS=14`), preventing disk and database exhaustion.

## Useful commands
```powershell
# Connect to postgres shell
docker exec -it aegis_postgres psql -U aegis_user -d aegis_db

# List tables
\dt

# Check scan status counts
SELECT status, count(*) FROM scans GROUP BY status;

# Dump database (SQL format)
docker exec aegis_postgres pg_dump -U aegis_user aegis_db > backup.sql

# Restore database from dump
docker exec -i aegis_postgres pg_restore -U aegis_user -d aegis_db -v -c < backup.dump
```

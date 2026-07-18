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
- `postgres_backups:/var/backups/postgresql` — isolated volume dedicated to database dumps (protects backups from live volume corruption)

## Backup & Retention Strategy
To ensure disaster recovery (DR) preparedness without overflowing host disk space or risking backup loss if primary data corrupts:

### 1. Automated Daily Backups (`pg_dump`)
Run daily logical backups using cron or Windows Task Scheduler executing inside the container against the dedicated `/var/backups/postgresql/` mount:
```powershell
docker exec aegis_postgres pg_dump -U aegis_user -F c -b -v -f /var/backups/postgresql/aegis_db_$(date +%Y%m%d_%H%M%S).dump aegis_db
```
For production deployments requiring minimal RPO (Recovery Point Objective), enable Write-Ahead Log (WAL) archiving (`archive_mode = on` / `pg_waldump`) with `pg_basebackup` for Point-In-Time Recovery (PITR). Note: Regularly verify restores (`pg_restore -C -d postgres ...`) on staging to validate integrity.

### 2. Retention Policy
- **Daily Backups:** Retain for **7 days** locally or in encrypted cloud object storage (AWS S3 / GCP Cloud Storage with lifecycle policies).
- **Weekly Snapshots:** Retain 1 snapshot per week for **4 weeks**.
- **Monthly Snapshots:** Retain 1 snapshot per month for **1 year** (compliance audit requirements).
- **Scan Artifact & DB Record Retention (`file_cleanup` task):** Shared volume scan files (`/shared/scans/<scan_id>/`) and corresponding database records (`scans` and `incidents` tables) are automatically purged by Celery Beat's `tasks.file_cleanup` job after **14 days** by default (`RETENTION_DAYS=14`), preventing disk and database exhaustion.

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

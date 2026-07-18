# AEGIS Nginx Container

Image: `nginx:1.27-alpine`

## Role
**Receptionist** — the only container exposed to the host. Routes all traffic.

## Routes
| Path | Destination | Notes |
|------|------------|-------|
| `/api/*` | `backend:8000` | REST API (JWT auth required) |
| `/ws` | `backend:8000` | WebSocket (Upgrade header forwarded) |
| `/health` | `backend:8000/` | Backend health proxy |
| `/nginx-health` | nginx local `200 ok` | Docker health check stub |

## Key config decisions
- **No trailing slash** on `/api/` proxy_pass → FastAPI sees the full `/api/...` path
- **WebSocket**: `proxy_set_header Upgrade $http_upgrade` + `Connection "upgrade"`
- **Timeouts**: WS read/send set to 3600s to keep scanner connections alive
- **Body size**: `client_max_body_size 20M` for screenshot uploads (aligned with backend limits)
- **Gzip**: enabled for all API responses

## Files
| File | Purpose |
|------|---------|
| `Dockerfile` | Alpine Nginx + curl for healthcheck |
| `nginx.conf` | Full server config (REST + WebSocket + health) |

## Security
- Nginx runs as root internally (standard nginx pattern)
- No TLS here — add Let's Encrypt + certbot for production
- Add `limit_req` rate limiting before production deployment

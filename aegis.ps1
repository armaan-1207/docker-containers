#!/usr/bin/env pwsh
# =======================================================
# AEGIS — Docker Management Helper (PowerShell)
# Run from: C:\Users\armaa\Desktop\docker containers\
# =======================================================
# Usage:
#   .\aegis.ps1 up          - Start all core services (detached)
#   .\aegis.ps1 down        - Stop and remove containers
#   .\aegis.ps1 logs        - Follow all logs
#   .\aegis.ps1 build       - Rebuild all images (no-cache)
#   .\aegis.ps1 status      - Show container health + ports
#   .\aegis.ps1 sandbox <URL> - Run one sandbox scan
#   .\aegis.ps1 shell       - Open shell in backend container
#   .\aegis.ps1 reset       - DESTRUCTIVE: wipe all volumes + containers
# =======================================================

param(
    [Parameter(Position=0)] [string]$Command = "help",
    [Parameter(Position=1)] [string]$Arg1 = ""
)

$COMPOSE_FILE = "docker-compose.yml"

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  AEGIS | $Text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

switch ($Command) {

    "up" {
        Write-Header "Starting Core Services"
        docker compose -f $COMPOSE_FILE up -d nginx backend redis postgres celery_worker celery_beat
        Write-Host ""
        Write-Host "[OK] Core services started." -ForegroundColor Green
        Write-Host "[OK] API:       http://localhost/api/" -ForegroundColor Green
        Write-Host "[OK] WebSocket: ws://localhost/ws/" -ForegroundColor Green
        Write-Host "[OK] Health:    http://localhost/nginx-health" -ForegroundColor Green
    }

    "down" {
        Write-Header "Stopping Services"
        docker compose -f $COMPOSE_FILE down
    }

    "logs" {
        Write-Header "Following All Logs (Ctrl+C to stop)"
        docker compose -f $COMPOSE_FILE logs -f
    }

    "build" {
        Write-Header "Rebuilding All Images"
        docker compose -f $COMPOSE_FILE build --no-cache
    }

    "status" {
        Write-Header "Container Status"
        docker compose -f $COMPOSE_FILE ps
        Write-Host ""
        Write-Host "Shared volume contents:" -ForegroundColor Yellow
        docker run --rm -v desktop_shared_scans:/data alpine ls -la /data 2>&1
    }

    "sandbox" {
        if ($Arg1 -eq "") {
            Write-Host "[ERROR] Provide a URL: .\aegis.ps1 sandbox https://example.com" -ForegroundColor Red
            exit 1
        }
        Write-Header "Running Sandbox Scan: $Arg1"
        docker compose -f $COMPOSE_FILE --profile sandbox run --rm sandbox $Arg1 --output-dir /app/output
    }

    "shell" {
        Write-Header "Opening Backend Shell"
        docker exec -it aegis_backend /bin/bash
    }

    "reset" {
        Write-Header "DESTRUCTIVE RESET"
        Write-Host "[WARNING] This will DELETE ALL volumes including the database!" -ForegroundColor Red
        $confirm = Read-Host "Type 'RESET' to confirm"
        if ($confirm -eq "RESET") {
            docker compose -f $COMPOSE_FILE down -v --remove-orphans
            Write-Host "[DONE] All containers and volumes removed." -ForegroundColor Yellow
        } else {
            Write-Host "[ABORTED] Reset cancelled." -ForegroundColor Green
        }
    }

    default {
        Write-Header "Help"
        Write-Host "  .\aegis.ps1 up                Start all core services"
        Write-Host "  .\aegis.ps1 down              Stop services"
        Write-Host "  .\aegis.ps1 logs              Follow all logs"
        Write-Host "  .\aegis.ps1 build             Rebuild all images (no-cache)"
        Write-Host "  .\aegis.ps1 status            Show health + shared volume"
        Write-Host "  .\aegis.ps1 sandbox <URL>     Run one sandbox scan"
        Write-Host "  .\aegis.ps1 shell             Backend bash shell"
        Write-Host "  .\aegis.ps1 reset             Wipe everything (DESTRUCTIVE)"
        Write-Host ""
        Write-Host "  API endpoint:  http://localhost/api/"
        Write-Host "  WebSocket:     ws://localhost/ws/"
        Write-Host "  Health check:  http://localhost/nginx-health"
    }
}

"""
services/quickscan.py
======================
Quick scan service: synchronous pre-flight threat assessment.

Security hardening:
  - is_placeholder is mapped from the risk fusion result onto the response
    schema so the browser extension can render a neutral state.
  - Placeholder scores are NOT written to Redis cache:
    caching a random number would create a false consistency loop where
    every request for that domain within the TTL window receives the same
    fabricated score, giving an artificial appearance of determinism.
  - Only real, non-placeholder verdicts are cached. The cache TTL for real
    verdicts is kept at 5 minutes here (Stage 1 preliminary); the full
    1-hour cache is written by Risk Fusion (Stage 4) after the complete
    pipeline completes.
"""

import json
import logging
from urllib.parse import urlparse

import redis

from config import settings
from database.models import Scan
from risk_fusion import run_risk_fusion
from schemas.quick_scan import QuickScanRequest, QuickScanResponse, RiskLevel

logger = logging.getLogger(__name__)

_redis_client = redis.from_url(settings.REDIS_URL)

# Stage-1 preliminary cache TTL (5 min).
# Stage-4 Risk Fusion overwrites with the authoritative 1-hour verdict.
_CACHE_TTL_SECONDS = 300


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.netloc and not parsed.scheme:
        parsed = urlparse("http://" + url)
    hostname = parsed.hostname
    if hostname:
        return hostname.lower()
    netloc = parsed.netloc or url
    if "@" in netloc:
        netloc = netloc.split("@")[-1]
    return netloc.split(":")[0].lower()


def _normalize_url_for_cache(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.netloc and not parsed.scheme:
        parsed = urlparse("http://" + url)
    scheme = (parsed.scheme or "http").lower()
    netloc = (parsed.netloc or "").lower()
    if "@" in netloc:
        netloc = netloc.split("@")[-1]
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def _cache_key(url: str) -> str:
    return f"quickscan:url:{_normalize_url_for_cache(url)}"


def run_quickscan(payload: QuickScanRequest, user, db) -> QuickScanResponse:
    url = str(payload.url)
    domain = _domain_from_url(url)

    # ── Redis cache check ──────────────────────────────────────────────────
    # Only real verdicts are stored here (see caching logic below), so a
    # cache hit always contains a trustworthy is_placeholder=False result.
    cached_raw = _redis_client.get(_cache_key(url))
    if cached_raw:
        cached = json.loads(cached_raw)
        cached["url"] = url
        cached["domain"] = domain
        cached["cached"] = True
        return QuickScanResponse(**cached)

    domain_lower = domain.lower()
    is_whitelisted = any(
        domain_lower == td or domain_lower.endswith("." + td)
        for td in getattr(settings, "TRUSTED_ALLOWLIST_DOMAINS", [])
    )

    if is_whitelisted:
        risk_score = 0.0
        risk_level = RiskLevel.SAFE
        reasons = ["Domain is on the trusted allowlist."]
        is_placeholder = False
    else:
        # ── V8/V10: CyberIntel early gate (runs before LightGBM) ────────────
        # If any threat-intel feed (VT, SafeBrowsing, …) flags this URL,
        # mark it CRITICAL immediately and skip the placeholder scorer.
        # Fail-open: if CyberIntel itself is unavailable (missing API keys,
        # network timeout, etc.) we log a warning and fall through to
        # run_risk_fusion() exactly as before — zero behaviour change on
        # failure.
        cyberintel_result = {}
        try:
            from cyberintel.runner import run_cyberintel
            cyberintel_result = run_cyberintel(url)
            ci_iocs = cyberintel_result.get("iocs", [])
            if ci_iocs:
                risk_score = 100.0
                risk_level = RiskLevel.CRITICAL
                is_placeholder = False
                reasons = [
                    f"Threat intel: {ioc['type']} flagged "
                    f"{ioc.get('detail', ioc.get('value', ''))}"
                    for ioc in ci_iocs
                ]
                cyberintel_blocked = True
            else:
                cyberintel_blocked = False
        except Exception as _ci_exc:
            logger.warning(
                "[quickscan] CyberIntel check failed for %s — falling back "
                "to run_risk_fusion(): %s",
                url, _ci_exc,
            )
            cyberintel_blocked = False

        if not cyberintel_blocked:
            result = run_risk_fusion({"url": url, "domain": domain})
            risk_score = result["risk_score"]
            risk_level = RiskLevel(result["risk_level"])
            is_placeholder = result.get("is_placeholder", True)  # fail-closed: unknown → placeholder
            reasons = result.get("explanations") or []
            if not reasons:
                if is_placeholder:
                    reasons = ["Score generated by placeholder model — treat as unverified."]
                else:
                    reasons = []

    scan = Scan(
        user_id=user.id,
        url=url,
        status="quick_scan_done",
        risk_score=risk_score,
        severity=risk_level.value if risk_level != RiskLevel.SAFE else None,
    )
    db.add(scan)
    db.commit()

    # ── V8/V10: Alert pipeline dispatch from Quick Scan ──────────────────
    # Fire alert_pipeline_task for real (non-placeholder) HIGH/CRITICAL
    # findings. risk_fusion_task already does this for Stage 2 deep scans;
    # this covers the case where CyberIntel alone raises a CRITICAL flag
    # before any Stage 2 scan is ever triggered.
    # Wrapped in try/except so a Celery broker outage never breaks the
    # synchronous Quick Scan HTTP response.
    _ALERT_SEVERITIES = {"HIGH", "CRITICAL"}
    if risk_level.value in _ALERT_SEVERITIES and not is_placeholder:
        try:
            from tasks.alert_pipeline import alert_pipeline_task
            _alert_report = {
                "scan_id": scan.id,
                "risk_score": risk_score,
                "severity": risk_level.value,
                "is_placeholder": False,
                "explanations": reasons,
                "iocs": cyberintel_result.get("iocs", []) if cyberintel_result else [],
            }
            alert_pipeline_task.delay(scan.id, _alert_report)
            logger.info(
                "[quickscan] alert_pipeline_task dispatched for scan %s "
                "(severity=%s)", scan.id, risk_level.value
            )
        except Exception:
            logger.exception(
                "[quickscan] Failed to dispatch alert_pipeline_task for "
                "scan %s — alert suppressed but scan result still returned",
                scan.id,
            )

    response = QuickScanResponse(
        url=url,
        domain=domain,
        risk_level=risk_level,
        risk_score=risk_score,
        is_whitelisted=is_whitelisted,
        cached=False,
        is_placeholder=is_placeholder,
        reasons=reasons,
    )

    # ── Security Hardening: NEVER cache placeholder scores ────────────
    # Caching a random number would make every user who hits the same domain
    # within the TTL window receive the identical fabricated score, creating
    # a false appearance of deterministic confidence.
    # Only cache when is_placeholder is False (real model verdict).
    if not is_placeholder:
        _redis_client.setex(
            _cache_key(url),
            _CACHE_TTL_SECONDS,
            response.model_dump_json(),
        )
    else:
        logger.debug(
            "[quickscan] Skipping Redis cache for %s — is_placeholder=True "
            "(random score must not be persisted as a real verdict)",
            url,
        )

    return response

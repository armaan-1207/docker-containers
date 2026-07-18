"""
cyberintel/runner.py
=====================
Live threat intelligence connectors with strict timeouts, exception handling,
and concurrent execution across VirusTotal, Safe Browsing, urlscan, AbuseIPDB,
and OpenPhish.
"""

import asyncio
import logging
import ipaddress
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

import httpx
from config import settings

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = httpx.Timeout(5.0, connect=3.0)


def _domain_from_target(target: str) -> str:
    if "://" in target:
        return urlparse(target).netloc or target
    return target


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _async_query_virustotal(client: httpx.AsyncClient, domain: str) -> Optional[Dict[str, Any]]:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "status": "success",
                "reputation": data.get("reputation", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
            }
        elif resp.status_code == 404:
            return {"status": "not_found", "malicious": 0}
        else:
            logger.warning("[cyberintel] VirusTotal API error %d for %s", resp.status_code, domain)
            return {"status": "error", "code": resp.status_code}
    except (httpx.TimeoutException, httpx.HTTPError) as e:
        logger.warning("[cyberintel] VirusTotal connection failed for %s: %s", domain, e)
        return {"status": "timeout_or_error", "detail": str(e)}


async def _async_query_google_safe_browsing(client: httpx.AsyncClient, target: str) -> Optional[Dict[str, Any]]:
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return None
    try:
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "aegis-scanner", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target}],
            },
        }
        resp = await client.post(url, json=payload)
        if resp.status_code == 200:
            matches = resp.json().get("matches", [])
            return {
                "status": "success",
                "malicious": len(matches) > 0,
                "matches": matches,
            }
        else:
            logger.warning("[cyberintel] Safe Browsing API error %d for %s", resp.status_code, target)
            return {"status": "error", "code": resp.status_code}
    except (httpx.TimeoutException, httpx.HTTPError) as e:
        logger.warning("[cyberintel] Safe Browsing connection failed for %s: %s", target, e)
        return {"status": "timeout_or_error", "detail": str(e)}


async def _async_query_urlscan(client: httpx.AsyncClient, domain: str) -> Optional[Dict[str, Any]]:
    if not settings.URLSCAN_API_KEY:
        return None
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        headers = {"API-Key": settings.URLSCAN_API_KEY}
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            results = resp.json().get("results", [])
            malicious_count = sum(1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious"))
            return {
                "status": "success",
                "total_scans": len(results),
                "malicious": malicious_count,
            }
        else:
            logger.warning("[cyberintel] urlscan API error %d for %s", resp.status_code, domain)
            return {"status": "error", "code": resp.status_code}
    except (httpx.TimeoutException, httpx.HTTPError) as e:
        logger.warning("[cyberintel] urlscan connection failed for %s: %s", domain, e)
        return {"status": "timeout_or_error", "detail": str(e)}


async def _async_query_abuseipdb(client: httpx.AsyncClient, domain: str) -> Optional[Dict[str, Any]]:
    if not settings.ABUSEIPDB_API_KEY or not _is_ip_address(domain):
        return None
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": domain, "maxAgeInDays": "90"}
        resp = await client.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "status": "success",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
            }
        else:
            logger.warning("[cyberintel] AbuseIPDB API error %d for %s", resp.status_code, domain)
            return {"status": "error", "code": resp.status_code}
    except (httpx.TimeoutException, httpx.HTTPError) as e:
        logger.warning("[cyberintel] AbuseIPDB connection failed for %s: %s", domain, e)
        return {"status": "timeout_or_error", "detail": str(e)}


async def _async_query_openphish(client: httpx.AsyncClient, target: str) -> Optional[Dict[str, Any]]:
    if not settings.OPENPHISH_API_KEY:
        return None
    try:
        url = "https://openphish.com/check"
        headers = {"Authorization": f"Bearer {settings.OPENPHISH_API_KEY}"}
        params = {"url": target}
        resp = await client.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "status": "success",
                "phishing": data.get("phishing", False),
            }
        else:
            logger.warning("[cyberintel] OpenPhish API error %d for %s", resp.status_code, target)
            return {"status": "error", "code": resp.status_code}
    except (httpx.TimeoutException, httpx.HTTPError) as e:
        logger.warning("[cyberintel] OpenPhish connection failed for %s: %s", target, e)
        return {"status": "timeout_or_error", "detail": str(e)}


async def _run_all_async(target: str, domain: str) -> Dict[str, Optional[Dict[str, Any]]]:
    async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
        vt_task = _async_query_virustotal(client, domain)
        gsb_task = _async_query_google_safe_browsing(client, target)
        urlscan_task = _async_query_urlscan(client, domain)
        abuse_task = _async_query_abuseipdb(client, domain)
        openphish_task = _async_query_openphish(client, target)

        results = await asyncio.gather(
            vt_task, gsb_task, urlscan_task, abuse_task, openphish_task, return_exceptions=True
        )

    keys = ["virustotal", "google_safe_browsing", "urlscan", "abuseipdb", "openphish"]
    sources = {}
    for key, res in zip(keys, results):
        if isinstance(res, Exception):
            logger.error("[cyberintel] Unexpected exception querying %s: %s", key, res)
            sources[key] = {"status": "error", "detail": str(res)}
        else:
            sources[key] = res
    return sources


def run_cyberintel(target: str) -> Dict[str, Any]:
    """
    Synchronous wrapper to run all configured threat intelligence feeds concurrently.
    """
    domain = _domain_from_target(target)
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # If called inside an existing event loop (e.g. FastAPI/async task without thread pool),
            # run inside a new thread to avoid "This event loop is already running".
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                sources = pool.submit(asyncio.run, _run_all_async(target, domain)).result()
        else:
            sources = asyncio.run(_run_all_async(target, domain))
    except Exception as e:
        logger.error("[cyberintel] Fatal error running feeds for %s: %s", target, e, exc_info=True)
        sources = {
            "virustotal": {"status": "error", "detail": str(e)},
            "google_safe_browsing": {"status": "error", "detail": str(e)},
            "urlscan": {"status": "error", "detail": str(e)},
            "abuseipdb": {"status": "error", "detail": str(e)},
            "openphish": {"status": "error", "detail": str(e)},
        }

    iocs: List[Dict[str, Any]] = []
    # Extract IOC flags from results
    vt = sources.get("virustotal")
    if vt and vt.get("malicious", 0) > 0:
        iocs.append({"type": "virustotal", "value": domain, "detail": f"Malicious hits: {vt['malicious']}"})

    gsb = sources.get("google_safe_browsing")
    if gsb and gsb.get("malicious"):
        iocs.append({"type": "google_safe_browsing", "value": target, "detail": "Match found in Google Safe Browsing"})

    us = sources.get("urlscan")
    if us and us.get("malicious", 0) > 0:
        iocs.append({"type": "urlscan", "value": domain, "detail": f"Malicious scans: {us['malicious']}"})

    ab = sources.get("abuseipdb")
    if ab and ab.get("abuse_confidence_score", 0) >= 50:
        iocs.append({"type": "abuseipdb", "value": domain, "detail": f"High abuse confidence: {ab['abuse_confidence_score']}%"})

    op = sources.get("openphish")
    if op and op.get("phishing"):
        iocs.append({"type": "openphish", "value": target, "detail": "Flagged by OpenPhish"})

    return {
        "target": target,
        "sources": sources,
        "iocs": iocs,
    }

"""
cyberintel/runner.py
=====================
"""

import logging
from typing import Optional
from urllib.parse import urlparse

from config import settings

logger = logging.getLogger(__name__)


def _domain_from_target(target: str) -> str:
    if "://" in target:
        return urlparse(target).netloc or target
    return target


def _query_virustotal(domain: str) -> Optional[dict]:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    logger.debug("VirusTotal lookup for %s not yet implemented", domain)
    return None


def _query_google_safe_browsing(target: str) -> Optional[dict]:
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return None
    logger.debug("Safe Browsing lookup for %s not yet implemented", target)
    return None


def _query_urlscan(target: str) -> Optional[dict]:
    if not settings.URLSCAN_API_KEY:
        return None
    logger.debug("urlscan.io lookup for %s not yet implemented", target)
    return None


def _query_abuseipdb(domain: str) -> Optional[dict]:
    if not settings.ABUSEIPDB_API_KEY:
        return None
    logger.debug("AbuseIPDB lookup for %s not yet implemented", domain)
    return None


def _query_openphish(target: str) -> Optional[dict]:
    if not settings.OPENPHISH_API_KEY:
        return None
    logger.debug("OpenPhish lookup for %s not yet implemented", target)
    return None


def run_cyberintel(target: str) -> dict:
    domain = _domain_from_target(target)

    sources = {
        "virustotal": _query_virustotal(domain),
        "google_safe_browsing": _query_google_safe_browsing(target),
        "urlscan": _query_urlscan(target),
        "abuseipdb": _query_abuseipdb(domain),
        "openphish": _query_openphish(target),
    }

    return {
        "target": target,
        "sources": sources,
        "iocs": [],
    }

"""
ai_engine/dom_extractor.py
============================

Requires: pip install beautifulsoup4
"""

import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False


def extract_features(html_path: str, final_url: str = "") -> dict:

    if not _HAS_BS4:
        logger.warning("beautifulsoup4 not installed - dom_extractor returning empty features")
        return {"title": "", "forms": 0, "form_actions": [], "inputs": 0, "links": [], "scripts": 0, "final_url": final_url}

    with open(html_path, encoding="utf-8", errors="ignore") as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""

    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    scripts = soup.find_all("script")

    links = []
    for a in soup.find_all("a", href=True):
        links.append(a["href"])


    form_actions = [urljoin(final_url, f.get("action", "")) for f in forms]

    return {
        "title": title,
        "forms": len(forms),
        "form_actions": form_actions,
        "inputs": len(inputs),
        "links": links,
        "scripts": len(scripts),
        "final_url": final_url,
    }
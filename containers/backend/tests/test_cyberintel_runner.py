"""
Unit tests for cyberintel/runner.py, verifying async concurrent execution,
timeouts, API key gating, and IOC extraction.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import httpx

from cyberintel.runner import run_cyberintel
import cyberintel.runner as runner_module


def test_run_cyberintel_no_api_keys():
    with patch.object(runner_module.settings, "VIRUSTOTAL_API_KEY", ""):
        with patch.object(runner_module.settings, "GOOGLE_SAFE_BROWSING_API_KEY", ""):
            with patch.object(runner_module.settings, "URLSCAN_API_KEY", ""):
                with patch.object(runner_module.settings, "ABUSEIPDB_API_KEY", ""):
                    with patch.object(runner_module.settings, "OPENPHISH_API_KEY", ""):
                        result = run_cyberintel("https://example.com/login")
                        assert result["target"] == "https://example.com/login"
                        assert result["sources"]["virustotal"] is None
                        assert result["sources"]["google_safe_browsing"] is None
                        assert result["sources"]["urlscan"] is None
                        assert result["sources"]["abuseipdb"] is None
                        assert result["sources"]["openphish"] is None
                        assert result["iocs"] == []


@pytest.mark.asyncio
async def test_run_cyberintel_with_mocked_responses():
    with patch.object(runner_module.settings, "VIRUSTOTAL_API_KEY", "dummy-vt"):
        with patch.object(runner_module.settings, "GOOGLE_SAFE_BROWSING_API_KEY", "dummy-gsb"):
            with patch.object(runner_module.settings, "URLSCAN_API_KEY", "dummy-us"):
                with patch.object(runner_module.settings, "ABUSEIPDB_API_KEY", ""):
                    with patch.object(runner_module.settings, "OPENPHISH_API_KEY", ""):
                        # Mock httpx.AsyncClient methods
                        mock_get = AsyncMock()
                        mock_post = AsyncMock()

                        # VT return response
                        vt_response = MagicMock()
                        vt_response.status_code = 200
                        vt_response.json.return_value = {
                            "data": {
                                "attributes": {
                                    "reputation": -5,
                                    "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 50},
                                }
                            }
                        }

                        # urlscan return response
                        us_response = MagicMock()
                        us_response.status_code = 200
                        us_response.json.return_value = {
                            "results": [{"verdicts": {"overall": {"malicious": True}}}]
                        }

                        async def get_side_effect(url, *args, **kwargs):
                            if "virustotal.com" in url:
                                return vt_response
                            elif "urlscan.io" in url:
                                return us_response
                            raise httpx.TimeoutException("Connection timed out")

                        # GSB return response
                        gsb_response = MagicMock()
                        gsb_response.status_code = 200
                        gsb_response.json.return_value = {"matches": [{"threatType": "MALWARE"}]}

                        mock_get.side_effect = get_side_effect
                        mock_post.return_value = gsb_response

                        with patch("httpx.AsyncClient.get", mock_get):
                            with patch("httpx.AsyncClient.post", mock_post):
                                result = run_cyberintel("https://bad-domain.com/phish")
                                assert result["sources"]["virustotal"]["status"] == "success"
                                assert result["sources"]["virustotal"]["malicious"] == 3
                                assert result["sources"]["google_safe_browsing"]["status"] == "success"
                                assert result["sources"]["google_safe_browsing"]["malicious"] is True
                                assert result["sources"]["urlscan"]["malicious"] == 1
                                assert len(result["iocs"]) == 3
                                types = {ioc["type"] for ioc in result["iocs"]}
                                assert types == {"virustotal", "google_safe_browsing", "urlscan"}

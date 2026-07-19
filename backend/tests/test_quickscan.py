"""
Unit tests for quickscan service across domain extraction, cache hit/miss logic,
database record creation, and preventing placeholder scores from being cached.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
import asyncio

import services.quickscan as quickscan_module
from services.quickscan import run_quickscan, _domain_from_url
from schemas.quick_scan import QuickScanRequest, RiskLevel


def test_domain_from_url():
    assert _domain_from_url("https://www.example.com/login?u=1") == "www.example.com"
    assert _domain_from_url("http://sub.domain.org:8080/path") == "sub.domain.org"


def test_run_quickscan_cache_hit():
    mock_redis = MagicMock()
    cached_data = {
        "url": "https://cached.com",
        "domain": "cached.com",
        "risk_level": "LOW",
        "risk_score": 15.0,
        "is_whitelisted": False,
        "cached": True,
        "is_placeholder": False,
        "reasons": ["Verified clean"]
    }
    mock_redis.get.return_value = json.dumps(cached_data)
    
    payload = MagicMock()
    payload.url = "https://cached.com/page"
    
    mock_db = MagicMock()
    mock_user = MagicMock()
    
    with patch.object(quickscan_module, "_redis_client", mock_redis):
        response = run_quickscan(payload, mock_user, mock_db)
        assert response.cached is True
        assert response.domain == "cached.com"
        assert response.risk_level == RiskLevel.LOW
        assert response.risk_score == 15.0
        # DB should not be touched on cache hit
        mock_db.add.assert_not_called()


def test_run_quickscan_placeholder_not_cached():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    
    payload = MagicMock()
    payload.url = "https://newsite.com"
    
    mock_db = MagicMock()
    mock_user = MagicMock()
    mock_user.id = 1
    
    mock_fusion_result = {
        "risk_score": 50.0,
        "risk_level": "MEDIUM",
        "is_placeholder": True,
        "explanations": ["Placeholder explanation"]
    }
    
    with patch.object(quickscan_module, "_redis_client", mock_redis):
        with patch("services.quickscan.run_risk_fusion", return_value=mock_fusion_result):
            response = run_quickscan(payload, mock_user, mock_db)
            assert response.cached is False
            assert response.is_placeholder is True
            assert response.risk_level == RiskLevel.MEDIUM
            assert response.risk_score == 50.0
            
            # DB scan record should be added
            mock_db.add.assert_called_once()
            mock_db.commit.assert_called_once()
            
            # Redis setex should NOT be called because is_placeholder=True
            mock_redis.setex.assert_not_called()


def test_run_quickscan_real_score_is_cached():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    
    payload = MagicMock()
    payload.url = "https://realsite.com"
    
    mock_db = MagicMock()
    mock_user = MagicMock()
    mock_user.id = 2
    
    mock_fusion_result = {
        "risk_score": 85.0,
        "risk_level": "HIGH",
        "is_placeholder": False,
        "explanations": ["Phishing kit detected"]
    }
    
    with patch.object(quickscan_module, "_redis_client", mock_redis):
        with patch("services.quickscan.run_risk_fusion", return_value=mock_fusion_result):
            response = run_quickscan(payload, mock_user, mock_db)
            assert response.cached is False
            assert response.is_placeholder is False
            assert response.risk_level == RiskLevel.HIGH
            assert response.risk_score == 85.0
            
            # Redis setex SHOULD be called because is_placeholder=False
            mock_redis.setex.assert_called_once()
            assert mock_redis.setex.call_args[0][0] == "quickscan:url:https://realsite.com/"

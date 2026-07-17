"""
Unit tests for ConsistencyEngine across DOM comparison, metadata matching,
logo analysis, and dynamic weight renormalization when categories are indeterminate.
"""

import pytest
from unittest.mock import patch, MagicMock
from consistency_engine.consistency_engine import ConsistencyEngine, MISMATCH_THRESHOLD


def test_compare_dom_when_sandbox_html_not_available():
    engine = ConsistencyEngine()
    result = engine.compare_dom(
        browser_dom={"title": "Test"},
        sandbox_html_path="/fake/path/sandbox.html",
        sandbox_html_available=False
    )
    assert result["indeterminate"] is True
    assert result["similarity"] == 1.0
    assert result.get("reason") == "sandbox_html_not_available"
    assert result["sandbox_dom"] == {}


@patch("consistency_engine.consistency_engine.extract_features")
def test_compare_dom_when_sandbox_html_available(mock_extract):
    mock_extract.return_value = {"title": "Test", "forms": 1}
    engine = ConsistencyEngine()
    
    # Exact match
    result_match = engine.compare_dom(
        browser_dom={"title": "Test", "forms": 1},
        sandbox_html_path="/fake/path/sandbox.html",
        sandbox_html_available=True
    )
    assert result_match["indeterminate"] is False
    assert result_match["similarity"] == 1.0
    
    # Mismatch
    mock_extract.return_value = {"title": "Different", "forms": 2}
    result_mismatch = engine.compare_dom(
        browser_dom={"title": "Test", "forms": 1},
        sandbox_html_path="/fake/path/sandbox.html",
        sandbox_html_available=True
    )
    assert result_mismatch["indeterminate"] is False
    assert result_mismatch["similarity"] < 1.0


def test_compare_metadata_matching_and_mismatching():
    engine = ConsistencyEngine()
    
    match = engine.compare_metadata(
        browser_dom={"title": "Secure Login", "final_url": "https://example.com/login"},
        sandbox_metadata={"title": "Secure Login", "final_url": "https://example.com/login"}
    )
    assert match["similarity"] == 1.0
    assert match["final_url_match"] is True
    assert match["indeterminate"] is False
    
    mismatch = engine.compare_metadata(
        browser_dom={"title": "Secure Login", "final_url": "https://example.com/login"},
        sandbox_metadata={"title": "Hacked Site", "final_url": "https://evil.phish/login"}
    )
    assert mismatch["similarity"] < MISMATCH_THRESHOLD
    assert mismatch["final_url_match"] is False


@patch("consistency_engine.consistency_engine.analyze_screenshot")
def test_compare_logo_indeterminate_when_both_none(mock_analyze):
    mock_analyze.return_value = {"logo": None}
    engine = ConsistencyEngine()
    result = engine.compare_logo(
        browser_vision={"logo": None},
        sandbox_png_path="/fake/path.png"
    )
    assert result["indeterminate"] is True
    assert result["similarity"] == 1.0


@patch("consistency_engine.consistency_engine.analyze_screenshot")
def test_compare_logo_mismatch_triggers_zero_similarity(mock_analyze):
    mock_analyze.return_value = {"logo": {"brand": "Microsoft"}}
    engine = ConsistencyEngine()
    result = engine.compare_logo(
        browser_vision={"logo": {"brand": "PayPal"}},
        sandbox_png_path="/fake/path.png"
    )
    assert result["indeterminate"] is False
    assert result["similarity"] == 0.0


def test_generate_consistency_report_renormalizes_weights_and_detects_cloaking():
    engine = ConsistencyEngine()
    
    comparisons = {
        "screenshot": {"similarity": 0.5, "indeterminate": False},
        "ocr": {"similarity": 1.0, "indeterminate": True},  # will be excluded
        "dom": {"similarity": 1.0, "indeterminate": True},  # will be excluded
        "metadata": {"similarity": 0.5, "indeterminate": False},
        "logo": {"similarity": 0.0, "indeterminate": False},  # brand mismatch triggers cloaking
    }
    
    report = engine.generate_consistency_report(comparisons)
    assert report["cloaking_suspected"] is True
    assert "logo" in report["mismatches"]
    assert "screenshot" in report["mismatches"]
    assert report["reduced_confidence"] is True
    assert set(report["indeterminate_categories"]) == {"ocr", "dom"}

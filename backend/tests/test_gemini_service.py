"""Unit tests for Centralized CyberShield GeminiAIService error handling & enrichment."""

from __future__ import annotations

from app.services.gemini_service import GeminiAIService


def test_http_error_classification_covers_all_required_failure_modes():
    assert GeminiAIService._classify_http_error(401, "API key not valid")[0] == "invalid_api_key"
    assert GeminiAIService._classify_http_error(400, "API_KEY_INVALID")[0] == "invalid_api_key"
    assert GeminiAIService._classify_http_error(404, "models/gemini-3.8-flash is not found")[0] == "unsupported_model"
    assert GeminiAIService._classify_http_error(429, "You exceeded your current quota")[0] == "quota_exhausted"
    assert GeminiAIService._classify_http_error(429, "Too many requests")[0] == "rate_limited"
    assert GeminiAIService._classify_http_error(503, "Service unavailable")[0] == "server_error"


def test_unconfigured_key_never_fabricates_safe_result():
    svc = GeminiAIService(api_key="", model="gemini-3-flash-preview")
    assert svc.is_configured is False
    res = svc.generate_text_sync(prompt="Hello")
    assert res.ok is False
    assert res.error_code == "unconfigured"
    assert res.text == ""

    vis = svc.analyze_image_sync(image_bytes=b"\x89PNG", prompt="Extract text")
    assert vis.ok is False
    assert vis.error_code == "unconfigured"

"""Comprehensive unit tests for CyberShield's Centralized OpenRouterAIService
(NVIDIA Nemotron 3.5 Super VL).
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.services.openrouter_service import (
    DEFAULT_OPENROUTER_MODEL,
    OpenRouterAIService,
)


def _mock_httpx_response(status_code: int, payload: dict | str, headers: dict | None = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    if isinstance(payload, dict):
        resp.json.return_value = payload
        resp.text = json.dumps(payload)
    else:
        resp.text = payload
        resp.json.side_effect = ValueError("not json")
    return resp


def test_openrouter_http_error_classification():
    assert OpenRouterAIService._classify_http_error(401, "Invalid auth")[0] == "invalid_api_key"
    assert OpenRouterAIService._classify_http_error(403, "Forbidden")[0] == "invalid_api_key"
    assert OpenRouterAIService._classify_http_error(402, "Insufficient credits")[0] == "quota_exhausted"
    assert OpenRouterAIService._classify_http_error(404, "No endpoints found for model")[0] == "unsupported_model"
    assert OpenRouterAIService._classify_http_error(429, "Rate limit exceeded")[0] == "rate_limited"
    assert OpenRouterAIService._classify_http_error(503, "Upstream overloaded")[0] == "server_error"


def test_openrouter_unconfigured_never_fabricates_safe():
    svc = OpenRouterAIService(api_key="", model=DEFAULT_OPENROUTER_MODEL)
    assert not svc.is_configured

    res = svc.generate_text_sync(prompt="Hello")
    assert res.success is False
    assert res.error_code == "unconfigured"
    assert res.classification == "Unverified"
    assert res.risk_score is None


def test_openrouter_structured_json_validation_and_clamping():
    svc = OpenRouterAIService(api_key="test-key")
    fenced = """```json
    {
      "classification": "high_risk",
      "risk_score": 142,
      "severity": "HIGH",
      "explanation": "Phishing domain impersonates banking portal.",
      "findings": ["Typosquatted domain", "Credential form"],
      "recommended_actions": ["Do not enter credentials", "Block domain"]
    }
    ```"""
    valid, parsed, err = svc.validate_structured_payload(fenced)
    assert valid is True
    assert err is None
    assert parsed["classification"] == "High Risk"
    assert parsed["risk_score"] == 100  # clamped to 0..100
    assert parsed["severity"] == "high"
    assert len(parsed["findings"]) == 2
    assert len(parsed["recommended_actions"]) == 2

    bad_ok, _, bad_err = svc.validate_structured_payload("not json at all")
    assert bad_ok is False
    assert bad_err is not None


def test_openrouter_retry_on_rate_limit_and_token_usage_tracking():
    svc = OpenRouterAIService(
        api_key="test-key",
        model=DEFAULT_OPENROUTER_MODEL,
        max_retries=2,
        retry_backoff_seconds=0.0,
    )
    resp_429 = _mock_httpx_response(429, {"error": {"message": "Rate limited"}}, headers={"retry-after": "0"})
    resp_200 = _mock_httpx_response(
        200,
        {
            "model": DEFAULT_OPENROUTER_MODEL,
            "choices": [{"message": {"role": "assistant", "content": "Phishing detected."}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 12, "total_tokens": 62},
        },
    )

    with patch("httpx.Client.post", side_effect=[resp_429, resp_200]) as mock_post:
        res = svc.generate_text_sync(prompt="Analyze link")

    assert mock_post.call_count == 2
    assert res.success is True
    assert res.attempts == 2
    assert res.text == "Phishing detected."
    assert res.token_usage.prompt_tokens == 50
    assert res.token_usage.completion_tokens == 12
    assert res.token_usage.total_tokens == 62

    stats = svc.get_usage_stats()
    assert stats["total_requests"] == 1
    assert stats["successful_requests"] == 1
    assert stats["total_tokens"] == 62


def test_openrouter_multimodal_image_payload_format():
    svc = OpenRouterAIService(api_key="test-key", model=DEFAULT_OPENROUTER_MODEL, max_retries=0)
    resp_200 = _mock_httpx_response(
        200,
        {
            "model": DEFAULT_OPENROUTER_MODEL,
            "choices": [{"message": {"role": "assistant", "content": "Verify bank KYC now"}}],
            "usage": {"prompt_tokens": 200, "completion_tokens": 10, "total_tokens": 210},
        },
    )
    captured_payload = {}

    def fake_post(self_client, url, headers=None, json=None):
        captured_payload["url"] = url
        captured_payload["headers"] = headers
        captured_payload["json"] = json
        return resp_200

    with patch("httpx.Client.post", autospec=True, side_effect=fake_post):
        res = svc.analyze_image_sync(
            image_bytes=b"\x89PNG\r\n\x1a\nfake",
            mime_type="image/png",
            prompt="Extract visible text",
        )

    assert res.success is True
    assert res.text == "Verify bank KYC now"
    assert captured_payload["url"].endswith("/chat/completions")
    assert captured_payload["headers"]["Authorization"] == "Bearer test-key"
    content_parts = captured_payload["json"]["messages"][0]["content"]
    assert content_parts[0]["type"] == "text"
    assert content_parts[1]["type"] == "image_url"
    assert content_parts[1]["image_url"]["url"].startswith("data:image/png;base64,")


def test_ai_status_and_structured_analyze_endpoints_never_leak_key():
    client = TestClient(app)

    fake_catalogue = _mock_httpx_response(
        200,
        {
            "data": [
                {
                    "id": DEFAULT_OPENROUTER_MODEL,
                    "name": "NVIDIA: Nemotron 3.5 Super VL (free)",
                    "architecture": {"input_modalities": ["text", "image", "video"]},
                    "pricing": {"prompt": "0", "completion": "0"},
                    "context_length": 1000000,
                }
            ]
        },
    )
    fake_http_client = MagicMock()
    fake_http_client.__enter__.return_value.get.return_value = fake_catalogue
    with patch("app.services.openrouter_service.httpx.Client", return_value=fake_http_client):
        status_resp = client.get("/api/v1/ai/status")

    assert status_resp.status_code == 200
    body = status_resp.json()
    assert body["provider"] == "openrouter"
    assert body["model"] == DEFAULT_OPENROUTER_MODEL
    assert body["model_available"] is True
    assert body["supports_vision"] is True
    assert body["is_free"] is True
    # Ensure secret key is NEVER leaked in response body
    api_key = os.getenv("OPENROUTER_API_KEY") or ""
    if api_key:
        assert api_key not in status_resp.text
    assert "sk-or-" not in status_resp.text

    # Verify structured endpoint preserves deterministic score/classification safely during tests
    analyze_resp = client.post(
        "/api/v1/ai/analyze",
        headers={"Authorization": "Bearer test-token"},
        json={
            "module_name": "URL Scanner",
            "target": "http://192.168.1.1/login",
            "risk_score": 82,
            "classification": "Malicious",
            "findings": ["Raw IP host"],
            "base_explanation": "Raw IP phishing URL.",
        },
    )
    assert analyze_resp.status_code == 200
    data = analyze_resp.json()
    for required_field in (
        "success",
        "provider",
        "model",
        "classification",
        "risk_score",
        "severity",
        "explanation",
        "findings",
        "recommended_actions",
        "token_usage",
    ):
        assert required_field in data
    assert data["provider"] == "openrouter"
    assert data["risk_score"] == 82
    assert data["classification"] == "Malicious"
    assert data["severity"] == "critical"

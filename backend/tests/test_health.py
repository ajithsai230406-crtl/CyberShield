"""Tests for the CyberShield FastAPI Backend."""

from datetime import datetime
from fastapi.testclient import TestClient

from main import app, SCAN_HISTORY
from app.main import app as app_from_package

client = TestClient(app)
package_client = TestClient(app_from_package)


def test_app_instances_are_identical():
    """Ensure backwards-compatible main:app and app.main:app reference the same application."""
    assert app is app_from_package


def test_health_returns_200():
    """Health endpoint should return HTTP 200."""
    response = client.get("/health")
    assert response.status_code == 200


def test_package_client_health_returns_200():
    """Health endpoint should return HTTP 200 via app.main client."""
    response = package_client.get("/health")
    assert response.status_code == 200


def test_health_has_required_fields():
    """Health response should contain all required fields."""
    response = client.get("/health")
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "CyberShield API"
    assert data["version"] == "1.0.0"
    assert "timestamp" in data
    assert "active_modules" in data
    assert isinstance(data["active_modules"], list)
    assert len(data["active_modules"]) >= 5


def test_health_timestamp_is_valid_iso():
    """Health timestamp should be a valid ISO 8601 string."""
    data = client.get("/health").json()
    parsed = datetime.fromisoformat(data["timestamp"])
    assert parsed is not None


def test_url_scan_valid_https():
    """URL scan should inspect HTTPS URL and return findings."""
    response = client.post("/api/v1/scan/url", json={"url": "https://secure-bank.example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "url"
    assert data["status"] == "inspected"
    assert "findings" in data
    assert any("HTTPS" in f for f in data["findings"])


def test_url_scan_insecure_http():
    """URL scan should flag insecure HTTP transport without faking score."""
    response = client.post("/api/v1/scan/url", json={"url": "http://192.168.1.1/login"})
    assert response.status_code == 200
    data = response.json()
    assert any("Insecure plain HTTP" in f for f in data["findings"])
    assert any("IPv4 address" in f for f in data["findings"])


def test_sms_scan_detects_links_and_keywords():
    """SMS scan should extract links and urgency keywords."""
    sms_text = "URGENT: Your account suspended! Verify immediately at https://suspicious.link/verify"
    response = client.post("/api/v1/scan/sms", json={"message": sms_text})
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "sms"
    assert data["metadata"]["embedded_urls_count"] == 1
    assert "urgent" in data["metadata"]["flagged_keywords_found"]


def test_history_records_events():
    """History endpoint should return scans performed during the session."""
    response = client.get("/api/v1/history")
    assert response.status_code == 200
    data = response.json()
    assert "total_count" in data
    assert "scans" in data
    assert data["total_count"] >= 1
    assert any(s["scan_type"] in ["URL", "SMS"] for s in data["scans"])

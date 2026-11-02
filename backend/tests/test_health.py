"""Tests for the /health endpoint."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_returns_200():
    """Health endpoint should return HTTP 200."""
    response = client.get("/health")
    assert response.status_code == 200


def test_health_has_required_fields():
    """Health response should contain all required fields."""
    response = client.get("/health")
    data = response.json()
    assert "status" in data
    assert "service" in data
    assert "version" in data
    assert "timestamp" in data


def test_health_status_is_healthy():
    """Health status should be 'healthy'."""
    data = client.get("/health").json()
    assert data["status"] == "healthy"


def test_health_service_name():
    """Health service name should be 'CyberShield API'."""
    data = client.get("/health").json()
    assert data["service"] == "CyberShield API"


def test_health_version():
    """Health version should be '1.0.0'."""
    data = client.get("/health").json()
    assert data["version"] == "1.0.0"


def test_health_timestamp_is_valid_iso():
    """Health timestamp should be a valid ISO 8601 datetime string."""
    data = client.get("/health").json()
    # Should not raise
    parsed = datetime.fromisoformat(data["timestamp"])
    assert parsed is not None


def test_health_response_content_type():
    """Health endpoint should return JSON."""
    response = client.get("/health")
    assert response.headers["content-type"] == "application/json"

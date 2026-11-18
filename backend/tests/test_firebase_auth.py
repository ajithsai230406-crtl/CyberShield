"""Tests for Firebase Authentication verification in CyberShield FastAPI backend."""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from firebase_admin import auth as firebase_auth

from app.main import app
from app.auth import get_current_user, AuthenticatedUser

client = TestClient(app)


class TestFirebaseAuthUnitAndIntegration:
    """Test suite for Firebase ID token verification and endpoint protection."""

    def test_health_endpoint_is_public_without_token(self):
        """Public health endpoint must be accessible without any token (HTTP 200)."""
        app.dependency_overrides.pop(get_current_user, None)
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_swagger_documentation_accessible_without_token(self):
        """OpenAPI schema and Swagger docs must be accessible without authentication."""
        app.dependency_overrides.pop(get_current_user, None)
        openapi_resp = client.get("/openapi.json")
        assert openapi_resp.status_code == 200
        assert "components" in openapi_resp.json()
        assert "FirebaseBearerAuth" in openapi_resp.json()["components"]["securitySchemes"]

        docs_resp = client.get("/docs")
        assert docs_resp.status_code == 200

    def test_missing_token_returns_401_on_protected_endpoints(self):
        """Calling protected endpoints without Authorization header must return HTTP 401."""
        app.dependency_overrides.pop(get_current_user, None)

        endpoints = [
            ("POST", "/api/v1/url/scan", {"url": "https://example.com"}),
            ("POST", "/api/v1/scan/url", {"url": "https://example.com"}),
            ("POST", "/api/v1/sms/scan", {"message": "Hello test"}),
            ("POST", "/api/v1/scan/sms", {"message": "Hello test"}),
            ("POST", "/api/v1/qr/scan", {"payload": "https://example.com"}),
            ("POST", "/api/v1/email/scan", {"body": "Hello test email body"}),
            ("POST", "/api/v1/scan/email", {"body": "Hello test email body"}),
            ("POST", "/api/v1/community/report", {"category": "phone", "target": "+18005550199", "title": "Scam"}),
            ("GET", "/api/v1/community/reports", None),
            ("GET", "/api/v1/community/reports/rep-001", None),
            ("GET", "/api/v1/community/reputation?category=phone&target=18005550199", None),
            ("GET", "/api/v1/community/stats", None),
            ("POST", "/api/v1/assistant/chat", {"message": "Hello"}),
            ("POST", "/api/v1/assistant/explain-scan", {"scan_type": "URL", "target": "https://example.com"}),
            ("GET", "/api/v1/assistant/history", None),
            ("DELETE", "/api/v1/assistant/history", None),
            ("GET", "/api/v1/analytics/dashboard", None),
            ("GET", "/api/v1/alerts", None),
            ("GET", "/api/v1/alerts/stats", None),
            ("POST", "/api/v1/alerts", {"title": "Test", "severity": "high", "category": "URL", "target": "https://bad.com", "risk_score": 80, "explanation": "test"}),
            ("GET", "/api/v1/history", None),
            ("GET", "/api/v1/history/scan-0001", None),
            ("DELETE", "/api/v1/history/scan-0001", None),
        ]

        for method, endpoint, payload in endpoints:
            if method == "POST":
                resp = client.post(endpoint, json=payload)
            elif method == "GET":
                resp = client.get(endpoint)
            else:
                resp = client.delete(endpoint)

            assert resp.status_code == 401, f"{method} {endpoint} did not return 401 on missing token"
            assert "WWW-Authenticate" in resp.headers
            assert "Bearer" in resp.headers["WWW-Authenticate"]
            assert "credentials were not provided" in resp.json()["detail"]

    def test_invalid_scheme_returns_401(self):
        """Using a non-Bearer scheme (e.g. Basic) must return HTTP 401."""
        app.dependency_overrides.pop(get_current_user, None)
        headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        resp = client.post("/api/v1/url/scan", json={"url": "https://example.com"}, headers=headers)
        assert resp.status_code == 401
        assert "Bearer" in resp.headers["WWW-Authenticate"]
        assert "Bearer" in resp.json()["detail"]

    def test_empty_bearer_token_returns_401(self):
        """Providing an empty Bearer token must return HTTP 401."""
        app.dependency_overrides.pop(get_current_user, None)
        headers = {"Authorization": "Bearer "}
        resp = client.post("/api/v1/url/scan", json={"url": "https://example.com"}, headers=headers)
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers
        assert any(term in resp.json()["detail"].lower() for term in ["empty", "not provided", "invalid"])

    @patch("firebase_admin.auth.verify_id_token")
    def test_invalid_token_rejected_with_401(self, mock_verify):
        """Invalid ID token must be rejected with HTTP 401."""
        app.dependency_overrides.pop(get_current_user, None)
        mock_verify.side_effect = firebase_auth.InvalidIdTokenError("Signature verification failed")

        headers = {"Authorization": "Bearer invalid.jwt.token"}
        resp = client.post("/api/v1/url/scan", json={"url": "https://example.com"}, headers=headers)
        assert resp.status_code == 401
        assert "Invalid authentication token" in resp.json()["detail"]

    @patch("firebase_admin.auth.verify_id_token")
    def test_expired_token_rejected_with_401(self, mock_verify):
        """Expired ID token must return HTTP 401 with expired details."""
        app.dependency_overrides.pop(get_current_user, None)
        mock_verify.side_effect = firebase_auth.ExpiredIdTokenError("Token is expired", None)

        headers = {"Authorization": "Bearer expired.jwt.token"}
        resp = client.post("/api/v1/url/scan", json={"url": "https://example.com"}, headers=headers)
        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower()

    @patch("firebase_admin.auth.verify_id_token")
    def test_token_without_uid_rejected_with_401(self, mock_verify):
        """Token lacking a uid claim must be rejected."""
        app.dependency_overrides.pop(get_current_user, None)
        mock_verify.return_value = {"email": "no_uid@cybershield.dev"}

        headers = {"Authorization": "Bearer token.without.uid"}
        resp = client.post("/api/v1/url/scan", json={"url": "https://example.com"}, headers=headers)
        assert resp.status_code == 401
        assert "user identifier" in resp.json()["detail"]

    @patch("firebase_admin.auth.verify_id_token")
    def test_valid_token_allows_access(self, mock_verify):
        """Valid Firebase ID token successfully authorizes request and returns HTTP 200."""
        app.dependency_overrides.pop(get_current_user, None)
        mock_verify.return_value = {
            "uid": "verified-user-12345",
            "email": "verified@cybershield.dev",
            "email_verified": True,
            "aud": "cybersheild-30cc7",
        }

        headers = {"Authorization": "Bearer valid.firebase.id.token"}
        resp = client.post("/api/v1/url/scan", json={"url": "https://example.com"}, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "inspected"
        assert data["scanned_url"] == "https://example.com"

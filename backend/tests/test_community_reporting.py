"""Unit and integration tests for CyberShield Community Threat Reporting module."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app, community_repo
from app.auth import get_current_user, AuthenticatedUser
from app.services.community_service import normalize_target, hash_reporter_id, RateLimiter

client = TestClient(app)


class TestTargetNormalization:
    """Tests for validating and normalizing community threat targets."""

    def test_normalize_phone_with_formatting(self):
        norm, disp = normalize_target("phone", "+1 (800) 555-0199")
        assert norm == "+18005550199"
        assert disp == "+18005550199"

    def test_normalize_phone_without_plus(self):
        norm, disp = normalize_target("phone", "98765-43210")
        assert norm == "9876543210"

    def test_reject_too_short_phone(self):
        with pytest.raises(ValueError, match="between 7 and 15 digits"):
            normalize_target("phone", "12345")

    def test_normalize_url(self):
        norm, disp = normalize_target("url", "  HTTP://phishing-site.xyz/login/  ")
        assert norm == "http://phishing-site.xyz/login"
        assert disp == "HTTP://phishing-site.xyz/login/"

    def test_reject_dangerous_url_scheme(self):
        with pytest.raises(ValueError, match="Dangerous or unsupported"):
            normalize_target("url", "javascript:alert(1)")

    def test_normalize_email(self):
        norm, disp = normalize_target("email", " Support@PayPal-Security.XYZ ")
        assert norm == "support@paypal-security.xyz"
        assert disp == "support@paypal-security.xyz"

    def test_reject_invalid_email(self):
        with pytest.raises(ValueError, match="Invalid email address"):
            normalize_target("email", "not-an-email")

    def test_normalize_app(self):
        norm, disp = normalize_target("app", " COM.FAKE.BANK.APP ")
        assert norm == "com.fake.bank.app"

    def test_unsupported_category(self):
        with pytest.raises(ValueError, match="Unsupported category"):
            normalize_target("invalid_cat", "something")


class TestCommunityReputationLogic:
    """Tests verifying the reputation and crowd consensus algorithm."""

    def setup_method(self):
        community_repo.clear_all()

    def test_reputation_unreported_target(self):
        """Unreported targets must have 0 score, 'Unknown' status, and 'None' confidence."""
        rep = community_repo.get_reputation("phone", "+9999999999")
        assert rep["total_reports"] == 0
        assert rep["distinct_reporters"] == 0
        assert rep["suspicion_score"] == 0
        assert rep["confidence"] == "None"
        assert rep["is_verified_threat"] is False

    def test_reputation_single_reporter_low_confidence(self):
        """Single user report should have low suspicion (25) and Low confidence."""
        target = f"+1800555{pytest.test_id if hasattr(pytest, 'test_id') else '7701'}"
        community_repo.submit_report(
            category="phone",
            raw_target=target,
            title="Spam robocall lure",
            description="Automated IRS tax scam robocall",
            tags=["spam", "robocall"],
            user_uid="user_alpha",
        )
        rep = community_repo.get_reputation("phone", target)
        assert rep["distinct_reporters"] == 1
        assert rep["suspicion_score"] == 25
        assert rep["confidence"] == "Low"
        assert rep["is_verified_threat"] is False

    def test_unverified_reports_capped_at_75(self):
        """Even with many reports, unverified suspicion cannot exceed 75 (does not automatically become malware)."""
        target = "https://phish-test-cap.example.com"
        for i in range(12):
            community_repo.submit_report(
                category="url",
                raw_target=target,
                title=f"Phishing lure {i}",
                description="Credential harvest",
                tags=["phishing"],
                user_uid=f"distinct_user_{i}_{target}",
            )

        rep = community_repo.get_reputation("url", "https://phish-test-cap.example.com")
        assert rep["distinct_reporters"] >= 10
        assert rep["suspicion_score"] == 75  # Capped at 75!
        assert rep["confidence"] == "High"
        assert rep["is_verified_threat"] is False


class TestCommunityEndpoints:
    """Integration tests for community reporting endpoints."""

    def setup_method(self):
        community_repo.clear_all()

    def test_submit_report_success(self):
        """POST /api/v1/community/report creates report and returns 201 Created."""
        payload = {
            "category": "phone",
            "target": "+1-888-555-1212",
            "title": "Impersonation scam call",
            "description": "Caller claimed to be Microsoft tech support demanding gift cards.",
            "tags": ["impersonation", "tech_support_scam"],
        }
        resp = client.post("/api/v1/community/report", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["id"].startswith("rep-")
        assert data["category"] == "phone"
        assert data["target"] == "+18885551212"
        assert data["status"] == "PENDING"
        assert "reporter_hash" not in data  # Privacy protection: never expose hash or UID!
        assert "reputation" in data

    def test_duplicate_report_rejection(self):
        """Submitting the same target within 24h by the same user returns 409 Conflict."""
        payload = {
            "category": "url",
            "target": "http://duplicate-test-target.org/login",
            "title": "Fake PayPal login",
            "description": "Harvests password and 2FA",
            "tags": ["phishing"],
        }
        # First submission succeeds
        resp1 = client.post("/api/v1/community/report", json=payload)
        assert resp1.status_code == 201

        # Second submission by same user fails with 409 Conflict
        resp2 = client.post("/api/v1/community/report", json=payload)
        assert resp2.status_code == 409
        assert "duplicate" in resp2.json()["detail"].lower()

    def test_rate_limiting_enforcement(self):
        """Exceeding 10 reports in 10 minutes triggers 429 Too Many Requests."""
        for i in range(10):
            payload = {
                "category": "url",
                "target": f"http://rate-limit-test-{i}.org",
                "title": f"Test report {i}",
                "tags": ["test"],
            }
            resp = client.post("/api/v1/community/report", json=payload)
            assert resp.status_code == 201

        # 11th request must be rejected with 429
        overflow = {
            "category": "url",
            "target": "http://rate-limit-overflow.org",
            "title": "Overflow report",
            "tags": ["overflow"],
        }
        resp_blocked = client.post("/api/v1/community/report", json=overflow)
        assert resp_blocked.status_code == 429
        assert "rate limit exceeded" in resp_blocked.json()["detail"].lower()

    def test_invalid_input_rejection(self):
        """Invalid category or empty target returns 422 Unprocessable Entity."""
        # Invalid category
        resp = client.post(
            "/api/v1/community/report",
            json={"category": "invalid_type", "target": "12345", "title": "Test"},
        )
        assert resp.status_code == 422

        # Empty target
        resp2 = client.post(
            "/api/v1/community/report",
            json={"category": "phone", "target": "   ", "title": "Test"},
        )
        assert resp2.status_code == 422

    def test_list_reports_with_filter(self):
        """GET /api/v1/community/reports returns list and supports category filter."""
        resp = client.get("/api/v1/community/reports?category=phone")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_count" in data
        assert "reports" in data
        assert all(r["category"] == "phone" for r in data["reports"])

    def test_reputation_lookup_endpoint(self):
        """GET /api/v1/community/reputation returns reputation metrics for valid target."""
        resp = client.get(
            "/api/v1/community/reputation",
            params={"category": "phone", "target": "+18885551212"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["category"] == "phone"
        assert data["target"] == "+18885551212"
        assert "suspicion_score" in data
        assert "confidence" in data
        assert "disclaimer" in data

    def test_stats_endpoint(self):
        """GET /api/v1/community/stats returns macro metrics."""
        resp = client.get("/api/v1/community/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_reports" in data
        assert "distinct_targets" in data
        assert "categories" in data
        assert "phone" in data["categories"]

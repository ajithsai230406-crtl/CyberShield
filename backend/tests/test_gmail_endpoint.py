"""Unit and integration tests for CyberShield Gmail threat scan endpoint."""

from __future__ import annotations
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestGmailScanEndpoint:
    """Tests for POST /api/v1/scan/gmail-message."""

    def test_scan_phishing_gmail_message_success(self):
        """Scans ingested Gmail phishing message and returns high risk telemetry."""
        payload = {
            "message_id": "gmail-test-101",
            "sender": '"PayPal Security Alert" <support-security@freemail-auth.xyz>',
            "subject": "URGENT: Your account has been suspended within 24 hours",
            "body": (
                "Dear Customer,\n\nWe detected unauthorized login attempts from an unknown Russian IP. "
                "Your account is restricted. Confirm identity immediately at http://192.168.1.1/paypal-verify "
                "to prevent permanent termination.\n\nPayPal Support"
            ),
            "date": "Tue, 10 Nov 2026 10:14:00 +0000",
            "reply_to": "attacker-collector@freemail-auth.xyz",
        }

        response = client.post("/api/v1/scan/gmail-message", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data["scan_type"] == "email"
        assert data["risk_score"] >= 60
        assert data["classification"] in ("High Risk", "Critical")
        assert any("PayPal" in str(f) or "freemail" in str(f).lower() for f in data["findings"])
        assert "http://192.168.1.1/paypal-verify" in data["embedded_urls"]
        assert data["metadata"]["gmail_message_id"] == "gmail-test-101"
        assert data["metadata"]["email_date"] == "Tue, 10 Nov 2026 10:14:00 +0000"

    def test_scan_legitimate_gmail_message(self):
        """Scans benign corporate Gmail message and returns Safe classification."""
        payload = {
            "message_id": "gmail-test-102",
            "sender": "alex@company.org",
            "subject": "Sprint Planning Meeting Notes",
            "body": "Hi team,\n\nHere are the notes from our sprint planning. Great progress everyone.\n\nBest,\nAlex",
            "date": "Tue, 10 Nov 2026 09:00:00 +0000",
        }

        response = client.post("/api/v1/scan/gmail-message", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data["scan_type"] == "email"
        assert data["risk_score"] < 40
        assert data["classification"] == "Safe"

    def test_scan_empty_gmail_body_fails_validation(self):
        """Validates that empty body payload is rejected with HTTP 422."""
        payload = {
            "message_id": "gmail-test-103",
            "sender": "sender@test.com",
            "subject": "Empty Subject",
            "body": "   ",
        }

        response = client.post("/api/v1/scan/gmail-message", json=payload)
        assert response.status_code == 422


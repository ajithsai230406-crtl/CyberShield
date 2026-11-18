"""Unit and integration tests for CyberShield Email Threat Detection module."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.email_detector import EmailThreatDetector

client = TestClient(app)


class TestEmailDetectorUnit:
    """Unit tests for EmailThreatDetector heuristics and URL extraction."""

    def setup_method(self):
        self.detector = EmailThreatDetector()

    def test_safe_business_email(self):
        """Standard professional email should be classified as Safe."""
        result = self.detector.analyze(
            sender="alex@company.org",
            subject="Project Status Update for Q4",
            body="Hi team, please find attached the meeting notes from today's sprint review. Let me know if you have any questions.",
        )
        assert result.risk_score < 30
        assert result.classification == "Safe"
        assert len(result.findings) == 0
        assert "no significant phishing" in result.explanation.lower()

    def test_brand_display_name_spoofing(self):
        """Display name spoofing PayPal from a freemail account must be detected."""
        result = self.detector.analyze(
            sender='"PayPal Security Support" <service-alert88@gmail.com>',
            subject="Security Notice Regarding Your Account",
            body="We noticed unusual activity on your account. Please log in immediately.",
        )
        assert result.risk_score >= 30
        assert any("brand display name spoofing" in cat.lower() for cat in result.threat_categories)
        assert any("paypal" in ind.lower() for ind in result.detected_indicators)

    def test_urgency_and_account_suspension_threat(self):
        """Urgency deadlines and suspension threats must trigger coercion indicators."""
        result = self.detector.analyze(
            sender="support@account-update.xyz",
            subject="FINAL WARNING: Account Suspended within 24 hours",
            body="Your account will be terminated within 24 hours unless immediate action is taken right now.",
        )
        assert result.risk_score >= 40
        assert result.classification in ["Suspicious", "High Risk", "Critical"]
        assert any("urgency" in cat.lower() or "suspension" in cat.lower() for cat in result.threat_categories)

    def test_credential_harvesting_lure(self):
        """Requests to verify passwords or enter 2FA OTP codes must trigger high-level warnings."""
        result = self.detector.analyze(
            sender="admin@portal-verify.top",
            subject="Required: Verify your identity",
            body="Please verify your password and enter your OTP two-factor code to prevent account deactivation.",
        )
        assert result.risk_score >= 50
        assert any("credential" in cat.lower() or "2fa" in cat.lower() for cat in result.threat_categories)

    def test_embedded_malicious_url_detection(self):
        """Embedded phishing URLs (e.g. raw IP host) must be extracted and flagged."""
        result = self.detector.analyze(
            sender="support@notifications.com",
            subject="Important update",
            body="Review your billing statement at http://192.168.1.1/secure-login/verify now.",
        )
        assert len(result.embedded_urls) == 1
        assert "http://192.168.1.1/secure-login/verify" in result.embedded_urls
        assert any("malicious embedded link" in cat.lower() for cat in result.threat_categories)
        assert result.risk_score >= 40

    def test_mismatched_reply_to_header(self):
        """Mismatched reply-to domain should trigger routing anomaly warning."""
        result = self.detector.analyze(
            sender="billing@trusted-vendor.com",
            reply_to="stealth-collector@evil-hacker.xyz",
            subject="Invoice payment confirmation",
            body="Please reply to this email to confirm wire transfer receipt.",
        )
        assert any("mismatched reply-to" in cat.lower() for cat in result.threat_categories)

    def test_critical_phishing_combo(self):
        """Brand spoofing + credential request + urgency must escalate to Critical."""
        result = self.detector.analyze(
            sender='"Microsoft Office 365 Team" <noreply@freemail-service.xyz>',
            subject="URGENT: Password expired - immediate action required",
            body="Your Microsoft password will be terminated within 24 hours. Verify your password at http://192.168.1.1/ms-login immediately.",
        )
        assert result.risk_score >= 80
        assert result.classification == "Critical"
        assert len(result.recommendations) > 0


class TestEmailDetectorEndpoints:
    """Integration tests for POST /api/v1/email/scan and alias."""

    def test_scan_email_endpoint_success(self):
        """POST /api/v1/email/scan returns 200 with structured JSON response."""
        payload = {
            "sender": "news@newsletter.com",
            "subject": "Weekly Tech Digest",
            "body": "Here is this week's newsletter summarizing AI developments.",
        }
        resp = client.post("/api/v1/email/scan", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "inspected"
        assert data["scan_type"] == "email"
        assert data["classification"] == "Safe"
        assert data["risk_score"] < 30
        assert "timestamp" in data

    def test_scan_email_alias_endpoint(self):
        """POST /api/v1/scan/email alias returns identical structured response."""
        payload = {
            "sender": "support@chase-secure-update.top",
            "subject": "Urgent Security Alert: Account Compromised",
            "body": "Unauthorized activity detected. Enter your PIN and verify your identity within 24 hours.",
        }
        resp = client.post("/api/v1/scan/email", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_type"] == "email"
        assert data["risk_score"] >= 60
        assert data["classification"] in ["High Risk", "Critical"]
        assert len(data["findings"]) > 0

    def test_reject_empty_body_validation(self):
        """Empty or whitespace-only email body must return 422 Unprocessable Entity."""
        payload = {"body": "   ", "subject": "Test"}
        resp = client.post("/api/v1/email/scan", json=payload)
        assert resp.status_code == 422


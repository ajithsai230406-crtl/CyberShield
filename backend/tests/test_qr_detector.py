"""Unit and Integration Tests for CyberShield QR Code Threat Detection."""

import pytest
from fastapi.testclient import TestClient

from app.main import app, SCAN_HISTORY
from app.services.qr_detector import QRThreatDetector, QRAnalysisResult

client = TestClient(app)
qr_detector = QRThreatDetector()


class TestQRThreatDetectorUnit:
    """Unit tests for the QRThreatDetector heuristic analysis engine."""

    def test_safe_https_url(self):
        """Standard HTTPS URL (e.g. google.com) should classify as Safe."""
        result = qr_detector.analyze("https://www.google.com")
        assert result.content_type == "url"
        assert result.classification == "Safe"
        assert result.risk_score < 30
        assert "google.com" in result.metadata.get("host", "")

    def test_malicious_ip_url(self):
        """Insecure HTTP URL using bare IPv4 address should classify as Malicious."""
        result = qr_detector.analyze("http://192.168.1.1/login/verify-account")
        assert result.content_type == "url"
        assert result.classification == "Malicious"
        assert result.risk_score >= 70
        assert len(result.detected_indicators) > 0

    def test_suspicious_shortener_url(self):
        """URL shortener should trigger suspicious findings and score >= 30."""
        result = qr_detector.analyze("https://bit.ly/secure-login-claim")
        assert result.content_type == "url"
        assert result.classification in ("Suspicious", "Malicious")
        assert result.risk_score >= 30

    def test_legitimate_upi_payment(self):
        """UPI link with recognized bank handle and payee name should be Safe."""
        payload = "upi://pay?pa=trustedmerchant@okaxis&pn=TrustedStore&am=150.00&cu=INR"
        result = qr_detector.analyze(payload)
        assert result.content_type == "upi"
        assert result.classification == "Safe"
        assert result.risk_score < 30
        assert result.metadata.get("payee_address") == "trustedmerchant@okaxis"
        assert result.metadata.get("payee_name") == "TrustedStore"

    def test_suspicious_upi_random_payee(self):
        """UPI link with random payee ID or unknown handle should be Suspicious/Malicious."""
        payload = "upi://pay?pa=a8f72b3c9d@unknownpsp&pn=&am=5000&cu=INR"
        result = qr_detector.analyze(payload)
        assert result.content_type == "upi"
        assert result.classification in ("Suspicious", "Malicious")
        assert result.risk_score >= 30
        assert any("payee" in ind.lower() or "handle" in ind.lower() or "random" in ind.lower() for ind in result.detected_indicators)

    def test_suspicious_upi_non_inr_currency(self):
        """UPI link with non-INR currency should trigger threat scoring."""
        payload = "upi://pay?pa=merchant@okaxis&pn=Store&am=100&cu=USD"
        result = qr_detector.analyze(payload)
        assert result.content_type == "upi"
        assert result.risk_score >= 30
        assert any("currency" in ind.lower() or "usd" in ind.lower() for ind in result.detected_indicators)

    def test_suspicious_upi_missing_payee_name(self):
        """UPI link with amount but missing payee name should flag anonymous payee."""
        payload = "upi://pay?pa=anon@okaxis&am=2500&cu=INR"
        result = qr_detector.analyze(payload)
        assert result.content_type == "upi"
        assert any("payee name" in ind.lower() for ind in result.detected_indicators)

    def test_safe_plain_text(self):
        """Benign plain text message should classify as Safe."""
        result = qr_detector.analyze("Customer support hours: Monday to Friday 9 AM to 6 PM.")
        assert result.content_type == "text"
        assert result.classification == "Safe"
        assert result.risk_score < 30

    def test_suspicious_plain_text_phishing_keywords(self):
        """Plain text containing urgent phishing and credential keywords should be flagged."""
        result = qr_detector.analyze(
            "URGENT: Your bank account is suspended. Immediate action required. Enter your password and OTP to verify."
        )
        assert result.content_type == "text"
        assert result.classification in ("Suspicious", "Malicious")
        assert result.risk_score >= 30
        assert len(result.finding_explanations) > 0

    def test_safe_vcard_contact(self):
        """Clean vCard contact information should classify as Safe."""
        payload = (
            "BEGIN:VCARD\n"
            "VERSION:3.0\n"
            "FN:Jane Doe\n"
            "TEL:+1-555-0199\n"
            "EMAIL:jane.doe@example.com\n"
            "END:VCARD"
        )
        result = qr_detector.analyze(payload)
        assert result.content_type == "contact"
        assert result.classification == "Safe"
        assert result.risk_score < 30

    def test_vcard_with_malicious_embedded_url(self):
        """vCard embedding a bare IP phishing link should inherit high risk score."""
        payload = (
            "BEGIN:VCARD\n"
            "VERSION:3.0\n"
            "FN:Customer Helpline\n"
            "URL:http://192.168.1.1/login\n"
            "END:VCARD"
        )
        result = qr_detector.analyze(payload)
        assert result.content_type == "contact"
        assert result.classification in ("Suspicious", "Malicious")
        assert result.risk_score >= 30

    def test_suspicious_wifi_hotspot_ssid(self):
        """WiFi QR with known evil-twin hotspot pattern should be flagged."""
        payload = "WIFI:T:WPA;S:Free_Airport_WiFi;P:pass123;;"
        result = qr_detector.analyze(payload)
        assert result.content_type == "wifi"
        assert result.classification in ("Suspicious", "Malicious")
        assert any("ssid" in ind.lower() or "free" in ind.lower() or "airport" in ind.lower() for ind in result.detected_indicators)


class TestQRScanEndpoint:
    """Integration tests for POST /api/v1/qr/scan endpoint."""

    def test_endpoint_safe_url(self):
        """POST /api/v1/qr/scan with safe URL returns 200 and Safe classification."""
        response = client.post("/api/v1/qr/scan", json={"payload": "https://www.google.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "inspected"
        assert data["scan_type"] == "qr"
        assert data["content_type"] == "url"
        assert data["classification"] == "Safe"
        assert data["risk_score"] < 30
        assert "engine_status" in data

    def test_endpoint_malicious_url(self):
        """POST /api/v1/qr/scan with bare IP URL returns 200 and Malicious classification."""
        response = client.post("/api/v1/qr/scan", json={"payload": "http://192.168.1.1/login/verify-account"})
        assert response.status_code == 200
        data = response.json()
        assert data["content_type"] == "url"
        assert data["classification"] == "Malicious"
        assert data["risk_score"] >= 70

    def test_endpoint_upi_link(self):
        """POST /api/v1/qr/scan with UPI payload returns 200 and UPI content_type."""
        response = client.post(
            "/api/v1/qr/scan",
            json={"payload": "upi://pay?pa=store@okaxis&pn=Store&am=50&cu=INR"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["content_type"] == "upi"
        assert "payee_address" in data["metadata"]
        assert data["metadata"]["payee_address"] == "store@okaxis"

    def test_endpoint_empty_payload_validation(self):
        """POST /api/v1/qr/scan with empty string returns HTTP 400."""
        response = client.post("/api/v1/qr/scan", json={"payload": ""})
        assert response.status_code == 400

    def test_endpoint_whitespace_payload_validation(self):
        """POST /api/v1/qr/scan with only whitespace returns HTTP 400."""
        response = client.post("/api/v1/qr/scan", json={"payload": "    \t\n   "})
        assert response.status_code == 400

    def test_endpoint_registers_in_audit_history(self):
        """Scanning a QR code should register an event in the session audit trail."""
        initial_count = len(SCAN_HISTORY)
        response = client.post("/api/v1/qr/scan", json={"payload": "https://example.com/test-qr-history"})
        assert response.status_code == 200
        assert len(SCAN_HISTORY) == initial_count + 1
        assert SCAN_HISTORY[0]["scan_type"] == "QR"

"""Unit and integration test suite for CyberShield SMS Threat Detection Engine."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.sms_detector import SMSThreatDetector, SMSAnalysisResult

client = TestClient(app)


# ===========================================================================
# 1. Unit Tests for SMSThreatDetector Engine
# ===========================================================================

class TestSMSThreatDetectorUnit:
    @pytest.fixture(autouse=True)
    def setup_detector(self):
        self.detector = SMSThreatDetector()

    def test_safe_conversational_message(self):
        """Casual conversational message should score low and classify as Safe."""
        text = "Hey Alex, are we still meeting for lunch at 12:30 today? Let me know!"
        result: SMSAnalysisResult = self.detector.analyze(text)

        assert result.classification == "Safe"
        assert result.risk_score < 30
        assert len(result.threat_categories) == 0
        assert "No smishing" in result.findings[0]

    def test_safe_appointment_reminder(self):
        """Legitimate appointment notice without malicious links or demands."""
        text = "Your dental appointment is scheduled for tomorrow at 10 AM with Dr. Smith. Reply C to confirm."
        result: SMSAnalysisResult = self.detector.analyze(text)

        assert result.classification == "Safe"
        assert result.risk_score < 30

    def test_malicious_urgent_bank_kyc_with_ip_link(self):
        """Urgent fake KYC warning with raw IP address link is severe Malicious threat."""
        text = (
            "URGENT: Your SBI bank account will be blocked within 24 hours due to pending KYC. "
            "Update immediately at http://192.168.1.1/kyc-update or account will be permanently closed."
        )
        result: SMSAnalysisResult = self.detector.analyze(text)

        assert result.classification == "Malicious"
        assert result.risk_score >= 70
        assert "fake_bank_kyc_alert" in result.threat_categories
        assert "urgency_and_coercion" in result.threat_categories
        assert "embedded_url" in result.threat_categories
        assert any("KYC" in ind for ind in result.detected_indicators)
        assert any("IP" in ind or "Malicious" in ind for ind in result.detected_indicators)
        assert len(result.finding_explanations) >= 2
        assert len(result.recommendation) > 20

    def test_malicious_otp_theft_scam(self):
        """Explicitly asking user to share OTP to cancel a debit is Malicious."""
        text = (
            "Unauthorized transaction of Rs 45,000 detected on your debit card. "
            "Share your OTP with our executive immediately to cancel this transaction."
        )
        result: SMSAnalysisResult = self.detector.analyze(text)

        assert result.classification == "Malicious"
        assert result.risk_score >= 70
        assert "credential_harvesting" in result.threat_categories
        assert any("OTP" in ind for ind in result.detected_indicators)

    def test_malicious_lottery_prize_with_advance_fee(self):
        """Prize scam demanding advance processing fee is Malicious."""
        text = (
            "Congratulations! You won $500,000 in the International Mobile Lottery. "
            "To claim your cash reward, pay $100 processing fee to our agent right now."
        )
        result: SMSAnalysisResult = self.detector.analyze(text)

        assert result.classification == "Malicious"
        assert result.risk_score >= 70
        assert "prize_lottery_scam" in result.threat_categories

    def test_malicious_tax_authority_impersonation(self):
        """Government tax agency impersonation demanding payment under threat of arrest."""
        text = (
            "IRS Final Notice: An arrest warrant has been issued in your name for tax fraud. "
            "Pay fine of $2,500 immediately to avoid police action."
        )
        result: SMSAnalysisResult = self.detector.analyze(text)

        assert result.classification == "Malicious"
        assert result.risk_score >= 70
        assert "entity_impersonation" in result.threat_categories
        assert "urgency_and_coercion" in result.threat_categories

    def test_suspicious_moderate_urgency_without_critical_vectors(self):
        """Moderate urgency or bill reminder should classify as Suspicious."""
        text = "Reminder: Your monthly subscription bill is due immediately. Review details on your account dashboard."
        result: SMSAnalysisResult = self.detector.analyze(text)

        assert result.classification == "Suspicious"
        assert 30 <= result.risk_score < 70
        assert "urgency_and_coercion" in result.threat_categories

    def test_suspicious_package_tracking_shortener(self):
        """Unverified delivery notification with shortened link."""
        text = "Your courier package is waiting for delivery. Confirm tracking at http://bit.ly/pkg-track-99"
        result: SMSAnalysisResult = self.detector.analyze(text)

        assert result.classification in ("Suspicious", "Malicious")
        assert result.risk_score >= 30
        assert "embedded_url" in result.threat_categories


# ===========================================================================
# 2. Integration Tests for SMS Scan Endpoints
# ===========================================================================

class TestSMSScanEndpoints:
    @pytest.mark.parametrize("endpoint", ["/api/v1/sms/scan", "/api/v1/scan/sms"])
    def test_safe_sms_endpoint(self, endpoint: str):
        payload = {"message": "Hello mom, dinner was great tonight! See you on Sunday."}
        response = client.post(endpoint, json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "inspected"
        assert data["scan_type"] == "sms"
        assert data["classification"] == "Safe"
        assert data["risk_score"] < 30
        assert "recommendation" in data
        assert "explanation" in data
        assert "findings" in data
        assert "metadata" in data

    @pytest.mark.parametrize("endpoint", ["/api/v1/sms/scan", "/api/v1/scan/sms"])
    def test_malicious_sms_endpoint(self, endpoint: str):
        payload = {
            "message": (
                "FINAL NOTICE: Your HDFC bank account is suspended due to pending PAN/KYC. "
                "Verify immediately at http://192.168.1.1/login or card will be blocked."
            )
        }
        response = client.post(endpoint, json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "inspected"
        assert data["classification"] == "Malicious"
        assert data["risk_score"] >= 70
        assert len(data["detected_indicators"]) > 0
        assert len(data["finding_explanations"]) > 0
        assert data["metadata"]["embedded_urls_count"] == 1
        assert "urgent" in data["metadata"]["flagged_keywords_found"] or "suspended" in data["metadata"]["flagged_keywords_found"]

    def test_alternative_text_payload_key(self):
        """Endpoint should accept 'text' key in addition to 'message'."""
        payload = {"text": "URGENT: Verify your account immediately at http://bit.ly/my-bank"}
        response = client.post("/api/v1/sms/scan", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["classification"] in ("Suspicious", "Malicious")
        assert data["risk_score"] >= 30

    @pytest.mark.parametrize("endpoint", ["/api/v1/sms/scan", "/api/v1/scan/sms"])
    def test_empty_message_validation(self, endpoint: str):
        """Empty string should return HTTP 400."""
        response = client.post(endpoint, json={"message": ""})
        assert response.status_code == 400
        assert "cannot be empty" in response.json()["detail"].lower()

    @pytest.mark.parametrize("endpoint", ["/api/v1/sms/scan", "/api/v1/scan/sms"])
    def test_whitespace_message_validation(self, endpoint: str):
        """Whitespace-only string should return HTTP 400."""
        response = client.post(endpoint, json={"message": "    \n\t  "})
        assert response.status_code == 400
        assert "cannot be empty" in response.json()["detail"].lower()

    def test_sms_scan_registers_in_audit_history(self):
        """Performing an SMS scan should record an event in session history."""
        hist_before = client.get("/api/v1/history").json()["total_count"]

        response = client.post(
            "/api/v1/sms/scan",
            json={"message": "Congratulations! Claim your $1000 prize now at http://free-gift.top"},
        )
        assert response.status_code == 200

        hist_after = client.get("/api/v1/history").json()
        assert hist_after["total_count"] == hist_before + 1
        assert hist_after["scans"][0]["scan_type"] == "SMS"


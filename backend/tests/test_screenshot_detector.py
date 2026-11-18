"""Unit and Integration Tests for CyberShield Screenshot Threat Detection."""

import io
import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from app.main import app, SCAN_HISTORY
from app.services.screenshot_detector import (
    ScreenshotAnalysisResult,
    ScreenshotThreatDetector,
)

client = TestClient(app)
detector = ScreenshotThreatDetector()


def create_synthetic_image(text: str = "", width: int = 400, height: int = 150) -> bytes:
    """Create a synthetic PNG image with optional text drawn onto it."""
    image = Image.new("RGB", (width, height), color=(255, 255, 255))
    if text:
        draw = ImageDraw.Draw(image)
        # Use default bitmap font to render simple text
        draw.text((10, 20), text, fill=(0, 0, 0))
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


class TestScreenshotThreatDetectorUnit:
    """Unit tests for the ScreenshotThreatDetector heuristic engine."""

    def test_safe_conversational_text(self):
        """Clean conversational message in screenshot should classify as Safe."""
        text = "Hey! Let me know when you arrive at the restaurant tonight."
        result = detector.analyze_extracted_text(text, filename="chat.png")
        assert result.classification == "Safe"
        assert result.risk_score < 30
        assert len(result.extracted_urls) == 0

    def test_malicious_bank_kyc_with_ip_url(self):
        """Screenshot containing bank KYC suspension alert and bare IP URL should be Malicious."""
        text = (
            "URGENT: Your SBI Bank account is BLOCKED due to incomplete KYC! "
            "Click http://192.168.1.1/login/verify-account immediately to avoid permanent deactivation."
        )
        result = detector.analyze_extracted_text(text, filename="kyc_scam.png")
        assert result.classification == "Malicious"
        assert result.risk_score >= 70
        assert "http://192.168.1.1/login/verify-account" in result.extracted_urls
        assert any("ip" in ind.lower() or "kyc" in ind.lower() for ind in result.detected_indicators)

    def test_otp_theft_scam_text(self):
        """Screenshot soliciting OTP / PIN should trigger credential theft flags."""
        text = "Your one-time password OTP is 492019. Please share your OTP with customer care to approve refund."
        result = detector.analyze_extracted_text(text, filename="otp_request.png")
        assert result.classification in ("Suspicious", "Malicious")
        assert result.risk_score >= 30
        assert any("otp" in ind.lower() for ind in result.detected_indicators)

    def test_fake_payment_receipt_pattern(self):
        """Screenshot containing fake payment confirmation receipt should be flagged."""
        text = "Payment Successful! Rs. 15,000 paid to your account. Transaction ID: 92847291842."
        result = detector.analyze_extracted_text(text, filename="fake_receipt.png")
        assert result.classification in ("Suspicious", "Malicious")
        assert "fake_payment_receipt" in result.threat_categories

    def test_scareware_alert_pattern(self):
        """Screenshot depicting fake virus/malware infection should be flagged."""
        text = "WARNING: Critical virus detected! Your phone is infected with 3 Trojans. Call Apple Support immediately."
        result = detector.analyze_extracted_text(text, filename="scareware.png")
        assert result.classification in ("Suspicious", "Malicious")
        assert "scareware_alert" in result.threat_categories

    def test_fake_receive_pin_scam(self):
        """Screenshot deceiving user to enter UPI PIN to receive money should be flagged."""
        text = "Scan QR to receive Rs. 2,000 cashback! Enter UPI PIN to receive payment into your bank."
        result = detector.analyze_extracted_text(text, filename="receive_scam.png")
        assert result.classification in ("Suspicious", "Malicious")
        assert "fake_receive_scam" in result.threat_categories

    def test_analyze_image_bytes_blank_image(self):
        """A blank image with no readable text should safely return zero risk."""
        blank_png = create_synthetic_image(text="")
        result = detector.analyze_image_bytes(blank_png, filename="blank.png")
        assert result.classification == "Safe"
        assert result.risk_score == 0
        assert result.ocr_text == ""
        assert "width" in result.metadata

    def test_invalid_image_bytes_raises_error(self):
        """Corrupted image bytes should raise a ValueError."""
        with pytest.raises(ValueError, match="Invalid or corrupted"):
            detector.extract_text_from_bytes(b"not-an-image-payload-at-all")


class TestScreenshotScanEndpoint:
    """Integration tests for POST /api/v1/screenshot/analyze endpoint."""

    def test_upload_blank_screenshot_success(self):
        """Uploading a clean image returns HTTP 200 and Safe status."""
        img_bytes = create_synthetic_image(text="")
        response = client.post(
            "/api/v1/screenshot/analyze",
            files={"file": ("blank.png", img_bytes, "image/png")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "inspected"
        assert data["scan_type"] == "screenshot"
        assert data["classification"] == "Safe"
        assert data["risk_score"] == 0
        assert "engine_status" in data

    def test_upload_empty_file_returns_400(self):
        """Uploading a 0-byte file returns HTTP 400."""
        response = client.post(
            "/api/v1/screenshot/analyze",
            files={"file": ("empty.png", b"", "image/png")},
        )
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()

    def test_upload_unsupported_extension_returns_400(self):
        """Uploading a non-image file extension returns HTTP 400."""
        response = client.post(
            "/api/v1/screenshot/analyze",
            files={"file": ("malware.exe", b"fake binary content", "application/octet-stream")},
        )
        assert response.status_code == 400
        assert "unsupported" in response.json()["detail"].lower()

    def test_upload_corrupted_image_returns_400(self):
        """Uploading corrupt image bytes with .png extension returns HTTP 400."""
        response = client.post(
            "/api/v1/screenshot/analyze",
            files={"file": ("corrupt.png", b"GIF89a corrupt bytes", "image/png")},
        )
        assert response.status_code == 400

    def test_upload_registers_in_audit_history(self):
        """Successful screenshot analysis registers an entry in audit trail."""
        initial_count = len(SCAN_HISTORY)
        img_bytes = create_synthetic_image(text="")
        response = client.post(
            "/api/v1/screenshot/analyze",
            files={"file": ("audit_test.png", img_bytes, "image/png")},
        )
        assert response.status_code == 200
        assert len(SCAN_HISTORY) == initial_count + 1
        assert SCAN_HISTORY[0]["scan_type"] == "SCREENSHOT"


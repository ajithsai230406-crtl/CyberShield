"""Unit and integration tests for CyberShield Real-Time Android Protection endpoints.

Tests:
1. Batch installed applications permission analysis (/api/v1/permissions/analyze-batch)
2. Call screening against community threat intelligence (/api/v1/calls/screen)
3. Real-time notification threat analysis and sensitive data redaction (/api/v1/notifications/analyze)
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app, community_repo, alert_repo
from app.auth import get_current_user, AuthenticatedUser

# Mock authenticated user for testing
_MOCK_USER = AuthenticatedUser(
    uid="test-android-defender-001",
    email="defender@cybershield.security",
    name="Test Defender",
)


@pytest.fixture
def client():
    app.dependency_overrides[get_current_user] = lambda: _MOCK_USER
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ===========================================================================
# 1. Batch Installed Applications Analysis Tests
# ===========================================================================

def test_batch_permission_analysis_safe_app(client):
    """A safe utility app with minimal benign permissions yields a Safe status."""
    payload = {
        "apps": [
            {
                "package_name": "com.simple.calculator",
                "app_name": "Calculator",
                "permissions": ["android.permission.VIBRATE"],
                "version_name": "1.0.0",
                "is_system_app": False,
            }
        ]
    }
    resp = client.post("/api/v1/permissions/analyze-batch", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "analyzed"
    assert data["total_apps_analyzed"] == 1
    assert data["safe_count"] == 1
    assert data["critical_count"] == 0
    assert data["overall_classification"] == "Safe"
    assert data["overall_device_risk_score"] < 35
    assert len(data["all_apps"]) == 1
    assert data["all_apps"][0]["package_name"] == "com.simple.calculator"


def test_batch_permission_analysis_banking_trojan(client):
    """An app with SMS Interception + Accessibility + Overlay is flagged as Critical with combos."""
    payload = {
        "apps": [
            {
                "package_name": "com.fraud.banktrojan",
                "app_name": "Flash Player Update",
                "permissions": [
                    "android.permission.RECEIVE_SMS",
                    "android.permission.READ_SMS",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.INTERNET",
                ],
                "version_name": "2.4.1",
                "is_system_app": False,
            }
        ]
    }
    resp = client.post("/api/v1/permissions/analyze-batch", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["critical_count"] == 1
    assert data["overall_classification"] == "Critical"
    assert data["overall_device_risk_score"] >= 75
    assert len(data["high_risk_apps"]) == 1

    trojan = data["high_risk_apps"][0]
    assert trojan["classification"] == "Critical"
    assert len(trojan["combo_findings"]) > 0
    assert any("SMS" in c or "Trojan" in c or "Accessibility" in c for c in trojan["combo_findings"])


def test_batch_permission_analysis_mixed_inventory(client):
    """Inventory containing safe, suspicious, and high-risk applications computes correct counts."""
    payload = {
        "apps": [
            {
                "package_name": "com.safe.notes",
                "app_name": "Simple Notes",
                "permissions": [],
            },
            {
                "package_name": "com.suspicious.flashlight",
                "app_name": "Bright Torch",
                "permissions": [
                    "android.permission.CAMERA",
                    "android.permission.ACCESS_FINE_LOCATION",
                ],
            },
            {
                "package_name": "com.covert.spyware",
                "app_name": "Device Optimizer",
                "permissions": [
                    "android.permission.RECORD_AUDIO",
                    "android.permission.CAMERA",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_BACKGROUND_LOCATION",
                    "android.permission.RECEIVE_BOOT_COMPLETED",
                ],
            },
        ]
    }
    resp = client.post("/api/v1/permissions/analyze-batch", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_apps_analyzed"] == 3
    assert data["safe_count"] >= 1
    assert data["high_risk_count"] + data["critical_count"] >= 1
    assert len(data["recommendations"]) > 0


# ===========================================================================
# 2. Call Screening Tests
# ===========================================================================

def test_call_screening_clean_number(client):
    """An unknown clean number returns allow with Safe classification."""
    payload = {"phone_number": "+14155552671", "caller_name": "Local Business"}
    resp = client.post("/api/v1/calls/screen", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_known_spam"] is False
    assert data["recommended_action"] == "allow"
    assert data["classification"] == "Safe"
    assert data["spam_score"] == 0


def test_call_screening_reported_spam_number(client):
    """When a number is reported by the community, call screening returns warn or silence."""
    spam_phone = "+19005559876"
    # First submit a community report for this phone number
    rep_payload = {
        "category": "phone",
        "target": spam_phone,
        "title": "IRS Impersonation Scam",
        "description": "Robocall claiming IRS warrant. Demanded payment via gift cards.",
        "tags": ["irs", "impersonation", "robocall"],
    }
    sub_resp = client.post("/api/v1/community/report", json=rep_payload)
    assert sub_resp.status_code in (200, 201, 409)

    # Now screen the call
    resp = client.post("/api/v1/calls/screen", json={"phone_number": spam_phone})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_known_spam"] is True
    assert data["recommended_action"] in ("warn", "silence", "block")
    assert data["report_count"] >= 1
    assert data["spam_score"] >= 20


# ===========================================================================
# 3. Notification Threat Analysis & Sensitive Redaction Tests
# ===========================================================================

def test_notification_analysis_benign(client):
    """Standard calendar or work notification passes as Safe."""
    payload = {
        "package_name": "com.google.android.calendar",
        "title": "Quarterly Security Review",
        "text": "Meeting starts in 15 minutes in Boardroom B.",
    }
    resp = client.post("/api/v1/notifications/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["classification"] == "Safe"
    assert data["overall_risk_score"] < 35
    assert data["has_phishing_url"] is False
    assert data["has_financial_urgency"] is False
    assert data["redacted_sensitive_data"] is False


def test_notification_analysis_phishing_url(client):
    """Notification containing a suspicious IP-based phishing link is detected."""
    payload = {
        "package_name": "com.unknown.messenger",
        "title": "Security Notice",
        "text": "Your account has been suspended! Verify your login now at http://192.168.1.100/secure-login",
    }
    resp = client.post("/api/v1/notifications/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["has_phishing_url"] is True
    assert data["overall_risk_score"] >= 70
    assert data["classification"] in ("High Risk", "Critical")
    assert len(data["detected_urls"]) >= 1


def test_notification_analysis_sensitive_redaction(client):
    """Notification containing credit card number and 2FA OTP has them securely redacted."""
    payload = {
        "package_name": "com.bank.service",
        "title": "Account Alert",
        "text": "Your card 4532 0150 9872 3411 was charged. Your OTP code: 829143 for confirmation.",
    }
    resp = client.post("/api/v1/notifications/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["redacted_sensitive_data"] is True
    # The raw card number must not appear in the sanitized text
    assert "4532 0150 9872 3411" not in data["sanitized_text"]
    assert "[REDACTED_CARD]" in data["sanitized_text"]
    # The full raw OTP must not appear
    assert "829143" not in data["sanitized_text"]


def test_notification_analysis_scam_urgency(client):
    """Notification simulating urgent scam pressure is detected as elevated risk."""
    payload = {
        "package_name": "com.google.android.apps.messaging",
        "title": "FINAL NOTICE",
        "text": "URGENT: Legal action pending. Transfer money immediately to avoid arrest.",
    }
    resp = client.post("/api/v1/notifications/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["has_financial_urgency"] is True
    assert data["overall_risk_score"] >= 50
    assert data["classification"] in ("High Risk", "Critical")

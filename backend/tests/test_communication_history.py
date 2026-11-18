"""Comprehensive tests for CyberShield Communication History & Threat Percentage Tracking."""

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app, communication_repo, community_repo
from app.auth import get_current_user, AuthenticatedUser
from app.services.communication_service import (
    classify_communication_risk,
    redact_sensitive_communication,
)

client = TestClient(app)


def _set_user(uid: str, email: str):
    app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(
        uid=uid,
        email=email,
        email_verified=True,
        claims={"aud": "cybersheild-30cc7"},
    )


@pytest.fixture(autouse=True)
def clean_comm_users():
    """Keep test users clean before and after each test."""
    for u in ("comm-user-alpha", "comm-user-beta"):
        communication_repo.delete_records(u)
    yield
    for u in ("comm-user-alpha", "comm-user-beta"):
        communication_repo.delete_records(u)


def test_risk_classification_thresholds():
    assert classify_communication_risk(0) == "Safe"
    assert classify_communication_risk(20) == "Safe"
    assert classify_communication_risk(21) == "Low Risk"
    assert classify_communication_risk(40) == "Low Risk"
    assert classify_communication_risk(41) == "Suspicious"
    assert classify_communication_risk(60) == "Suspicious"
    assert classify_communication_risk(61) == "High Risk"
    assert classify_communication_risk(80) == "High Risk"
    assert classify_communication_risk(81) == "Critical"
    assert classify_communication_risk(100) == "Critical"


def test_privacy_redaction_strips_otp_cards_and_passwords():
    raw = "Your OTP: 482910 for card 4111 2222 3333 4444 cvv: 889 password=MySecret123"
    sanitized, redacted = redact_sensitive_communication(raw)
    assert redacted is True
    assert "482910" not in sanitized
    assert "4111 2222 3333 4444" not in sanitized
    assert "889" not in sanitized
    assert "MySecret123" not in sanitized


def test_normal_and_suspicious_sms_ingestion():
    _set_user("comm-user-alpha", "alpha@cybershield.dev")

    # 1. Normal incoming SMS
    res_safe = client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "sms",
            "source_app": "SMS",
            "sender_identifier": "+919876543210",
            "content": "Hey, are we still meeting at 6pm for dinner?",
        },
    )
    assert res_safe.status_code == 200
    d_safe = res_safe.json()
    assert d_safe["classification"] == "Safe"
    assert 0 <= d_safe["risk_score"] <= 20
    assert d_safe["analysis_status"] == "analyzed"
    assert d_safe["is_duplicate"] is False

    # 2. Suspicious / High-Risk phishing SMS
    res_phish = client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "sms",
            "source_app": "SMS",
            "sender_identifier": "AX-BNKALT",
            "content": "URGENT: Your bank account is suspended! Verify KYC immediately at http://secure-bank-verify.xyz/login or card will be blocked. OTP: 992811",
        },
    )
    assert res_phish.status_code == 200
    d_phish = res_phish.json()
    assert d_phish["risk_score"] >= 41
    assert d_phish["classification"] in ("Suspicious", "High Risk", "Critical")
    assert "992811" not in d_phish["message_preview"]


def test_normal_and_suspicious_whatsapp_notifications_and_deduplication():
    _set_user("comm-user-alpha", "alpha@cybershield.dev")
    ts = datetime.now(timezone.utc).isoformat()

    payload = {
        "communication_type": "whatsapp",
        "source_app": "WhatsApp",
        "sender_identifier": "Mom",
        "content": "Reached home safely!",
        "timestamp": ts,
    }
    first = client.post("/api/v1/communications/ingest", json=payload)
    assert first.status_code == 200
    assert first.json()["is_duplicate"] is False

    # Identical duplicate notification within the same minute
    dup = client.post("/api/v1/communications/ingest", json=payload)
    assert dup.status_code == 200
    assert dup.json()["is_duplicate"] is True
    assert dup.json()["record_id"] == first.json()["record_id"]

    # Suspicious notification
    scam_notif = client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "notification",
            "source_app": "WhatsApp",
            "sender_identifier": "+447700900123",
            "content": "Congratulations! You won a lottery prize! Claim reward now at http://bit.ly/claim-prize-now",
            "timestamp": ts,
        },
    )
    assert scam_notif.status_code == 200
    assert scam_notif.json()["risk_score"] >= 41


def test_normal_unknown_and_spam_incoming_calls():
    _set_user("comm-user-alpha", "alpha@cybershield.dev")

    # 1. Normal known contact call
    known = client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "call",
            "source_app": "Phone Call",
            "sender_identifier": "+14155550101",
            "caller_name": "Alice",
            "is_known_contact": True,
            "call_status": "incoming",
        },
    )
    assert known.status_code == 200
    assert known.json()["classification"] == "Safe"
    assert known.json()["risk_score"] == 0
    assert known.json()["metadata"]["audio_analyzed"] is False

    # 2. Unknown caller — must NOT be assumed malicious!
    unknown = client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "call",
            "source_app": "Phone Call",
            "sender_identifier": "+14155550199",
            "is_known_contact": False,
            "call_status": "missed",
        },
    )
    assert unknown.status_code == 200
    assert unknown.json()["classification"] == "Safe"
    assert unknown.json()["risk_score"] == 0
    assert unknown.json()["is_known_contact"] is False

    # 3. Known spam caller (report to community intelligence first)
    spam_number = "+19005559988"
    for idx in range(3):
        try:
            community_repo.submit_report(
                category="phone",
                raw_target=spam_number,
                title="Bank Impersonation Robocall",
                description="Automated bank impersonation scam requesting OTP",
                tags=["robocall", "fraud"],
                user_uid=f"comm-reporter-{idx}",
            )
        except Exception:
            pass

    spam_call = client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "call",
            "source_app": "Phone Call",
            "sender_identifier": spam_number,
            "is_known_contact": False,
            "call_status": "silenced",
        },
    )
    assert spam_call.status_code == 200
    sc = spam_call.json()
    assert sc["risk_score"] >= 41
    assert sc["classification"] in ("Suspicious", "High Risk", "Critical")
    assert sc["metadata"]["audio_analyzed"] is False


def test_user_isolation_across_two_accounts():
    _set_user("comm-user-alpha", "alpha@cybershield.dev")
    created = client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "sms",
            "source_app": "SMS",
            "sender_identifier": "+911111111111",
            "content": "Private message for alpha",
        },
    ).json()

    # Switch to User Beta
    _set_user("comm-user-beta", "beta@cybershield.dev")
    beta_list = client.get("/api/v1/communications/history").json()
    assert beta_list["total"] == 0

    # Beta cannot delete Alpha's record
    del_attempt = client.delete(f"/api/v1/communications/{created['record_id']}")
    assert del_attempt.status_code == 404

    # Alpha still owns and sees the record
    _set_user("comm-user-alpha", "alpha@cybershield.dev")
    alpha_list = client.get("/api/v1/communications/history").json()
    assert alpha_list["total"] == 1


def test_daily_weekly_monthly_analytics_and_retention_deletion():
    _set_user("comm-user-alpha", "alpha@cybershield.dev")

    now = datetime.now(timezone.utc)
    old_ts = (now - timedelta(days=45)).isoformat()

    # 1 old safe message (45 days ago)
    client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "sms",
            "source_app": "SMS",
            "sender_identifier": "Friend",
            "content": "Old safe check-in",
            "timestamp": old_ts,
        },
    )
    # 1 recent phishing SMS
    client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "sms",
            "source_app": "SMS",
            "sender_identifier": "SCAM-ALERT",
            "content": "URGENT: Your account is suspended! Verify immediately at http://evil-login.xyz/kyc",
            "timestamp": now.isoformat(),
        },
    )
    # 1 unanalyzed empty notification
    client.post(
        "/api/v1/communications/ingest",
        json={
            "communication_type": "notification",
            "source_app": "SystemApp",
            "sender_identifier": "Alert",
            "content": "",
            "timestamp": now.isoformat(),
        },
    )

    for period in ("daily", "weekly", "monthly"):
        an = client.get(f"/api/v1/communications/analytics?period={period}")
        assert an.status_code == 200
        data = an.json()
        assert data["overall"]["total_received"] == 3
        assert data["overall"]["total_analyzed"] == 2
        assert data["overall"]["total_unanalyzed"] == 1
        assert data["overall"]["threat_detection_rate"] == 50.0
        assert len(data["trends"]) > 0

    # Apply 30-day retention -> should delete only the 45-day-old record
    ret = client.delete("/api/v1/communications?older_than_days=30")
    assert ret.status_code == 200
    assert ret.json()["deleted_count"] == 1

    remaining = client.get("/api/v1/communications/history").json()
    assert remaining["total"] == 2

    # Full purge
    purge = client.delete("/api/v1/communications")
    assert purge.status_code == 200
    assert purge.json()["deleted_count"] == 2

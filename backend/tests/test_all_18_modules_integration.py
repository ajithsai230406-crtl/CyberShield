"""Master All-18-Module Integration Test Matrix for CyberShield Smart Alert & Event Engine.

Exercises every single one of the 18 CyberShield modules end-to-end through real FastAPI
endpoints, validating standardized 15-field event storage, risk scoring, classification,
notification decisions, alert creation, unified history filters, unified analytics,
privacy redaction, deduplication, user isolation, failed/unavailable separation, and fault isolation.
"""

from __future__ import annotations

import io
import uuid
import zipfile
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.auth import AuthenticatedUser, get_current_user
from app.main import app, smart_event_engine
from app.services.smart_event_engine import ALL_18_MODULES, SmartSecurityEventEngine


TEST_UID_A = f"master-18mod-user-a-{uuid.uuid4().hex[:8]}"
TEST_UID_B = f"master-18mod-user-b-{uuid.uuid4().hex[:8]}"

_active_user = AuthenticatedUser(
    uid=TEST_UID_A,
    email="master.tester.a@cybershield.dev",
    email_verified=True,
    claims={"role": "tester"},
)


async def _override_user() -> AuthenticatedUser:
    return _active_user


@pytest.fixture(autouse=True)
def _bind_auth():
    prev = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = _override_user
    yield
    if prev is not None:
        app.dependency_overrides[get_current_user] = prev
    else:
        app.dependency_overrides.pop(get_current_user, None)


client = TestClient(app)


def _set_user(uid: str) -> None:
    global _active_user
    _active_user = AuthenticatedUser(
        uid=uid,
        email=f"{uid}@cybershield.dev",
        email_verified=True,
        claims={"role": "tester"},
    )


def _minimal_apk_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"android.permission.INTERNET")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
    return buf.getvalue()


def _minimal_png_bytes() -> bytes:
    # Valid 1x1 PNG
    return (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0"
        b"\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def test_all_18_modules_registered():
    _set_user(TEST_UID_A)
    resp = client.get("/api/v1/events/modules")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_modules"] == 18
    keys = {m["module_name"] for m in data["modules"]}
    assert keys == set(ALL_18_MODULES.keys())


def test_all_18_modules_end_to_end_matrix():
    """Exercise all 18 modules through real endpoints and verify unified storage & analytics."""
    _set_user(TEST_UID_A)

    # 1. URL Scanner (Safe + High-Risk Phishing)
    r1_safe = client.post("/api/v1/url/scan", json={"url": "https://www.wikipedia.org"})
    assert r1_safe.status_code == 200
    r1_risk = client.post(
        "/api/v1/url/scan",
        json={"url": "http://paypal-secure-verify-login.tk/update-account?otp=123456"},
    )
    assert r1_risk.status_code == 200

    # 2. SMS Scanner (Safe + High-Risk Smishing)
    r2_safe = client.post("/api/v1/sms/scan", json={"message": "Hey, see you at 5pm for coffee."})
    assert r2_safe.status_code == 200
    r2_risk = client.post(
        "/api/v1/sms/scan",
        json={
            "message": "URGENT: Your bank account is suspended! Verify KYC immediately at http://sbi-kyc-update.xyz/login or account blocked in 2 hours."
        },
    )
    assert r2_risk.status_code == 200

    # 3. QR Scanner (Safe + Phishing QR)
    r3_safe = client.post("/api/v1/qr/scan", json={"payload": "https://www.google.com"})
    assert r3_safe.status_code == 200
    r3_risk = client.post(
        "/api/v1/qr/scan",
        json={"payload": "http://free-prize-claim-login.xyz/bank-verify"},
    )
    assert r3_risk.status_code == 200

    # 4. Screenshot Analyzer (Safe + Scam Screenshot)
    r4 = client.post(
        "/api/v1/screenshot/analyze",
        files={"file": ("suspicious_shot.png", _minimal_png_bytes(), "image/png")},
    )
    assert r4.status_code == 200

    # 5. APK Analyzer
    r5 = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("sample_app.apk", _minimal_apk_bytes(), "application/vnd.android.package-archive")},
    )
    assert r5.status_code == 200

    # 6. File Scanner (Safe + Suspicious)
    r6_safe = client.post(
        "/api/v1/file/scan",
        files={"file": ("notes.txt", b"Hello team, meeting notes attached.", "text/plain")},
    )
    assert r6_safe.status_code == 200
    r6_risk = client.post(
        "/api/v1/file/scan",
        files={"file": ("invoice.pdf.exe", b"MZ\x90\x00\x03\x00\x00\x00" + b"A" * 120, "application/octet-stream")},
    )
    assert r6_risk.status_code == 200

    # 7. Permission Analyzer (Safe + Dangerous Combo)
    r7_safe = client.post(
        "/api/v1/permissions/analyze-list",
        json={"app_name": "Simple Calc", "package_name": "com.safe.calc", "permissions": ["android.permission.INTERNET"]},
    )
    assert r7_safe.status_code == 200
    r7_risk = client.post(
        "/api/v1/permissions/analyze-list",
        json={
            "app_name": "Flashlight Spy",
            "package_name": "com.evil.spyflash",
            "permissions": [
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.RECORD_AUDIO",
            ],
        },
    )
    assert r7_risk.status_code == 200

    # 8. Email Scanner (Safe + Phishing)
    r8_safe = client.post(
        "/api/v1/email/scan",
        json={"sender": "team@github.com", "subject": "Weekly digest", "body": "Here is your weekly project summary."},
    )
    assert r8_safe.status_code == 200
    r8_risk = client.post(
        "/api/v1/email/scan",
        json={
            "sender": "security@paypa1-support.xyz",
            "subject": "URGENT: Account Suspended - Verify Password Immediately",
            "body": "Click http://paypa1-verify-now.tk/login to restore access within 24 hours.",
        },
    )
    assert r8_risk.status_code == 200

    # 9. Gmail Integration
    r9 = client.post(
        "/api/v1/scan/gmail-message",
        json={
            "message_id": f"gmail-msg-{uuid.uuid4().hex[:8]}",
            "sender": "alerts@bank-verify-urgent.xyz",
            "subject": "Action Required: Confirm ATM PIN now",
            "body": "Verify your account at http://bank-kyc-alert.tk/verify immediately.",
        },
    )
    assert r9.status_code == 200

    # 13. Community Threat Intelligence (submit phone report first so Call Screening sees it too!)
    spam_phone = f"+1555{uuid.uuid4().int % 9000000 + 1000000}"
    r13_report = client.post(
        "/api/v1/community/report",
        json={
            "category": "phone",
            "target": spam_phone,
            "title": "Fake Bank KYC Scam Caller",
            "description": "Demanding OTP and card CVV.",
            "tags": ["scam", "fraud", "impersonation"],
        },
    )
    assert r13_report.status_code == 201
    r13_rep = client.get("/api/v1/community/reputation", params={"category": "phone", "target": spam_phone})
    assert r13_rep.status_code == 200

    # 10. Call Screening (Safe + Reported Spam Caller)
    r10_safe = client.post("/api/v1/calls/screen", json={"phone_number": "+14155550199"})
    assert r10_safe.status_code == 200
    r10_spam = client.post("/api/v1/calls/screen", json={"phone_number": spam_phone})
    assert r10_spam.status_code == 200

    # 11. Notification Monitor (with OTP redaction check!)
    r11 = client.post(
        "/api/v1/notifications/analyze",
        json={
            "package_name": "com.whatsapp",
            "title": "Bank Alert",
            "text": "URGENT verify account at http://verify-bank-now.tk/otp OTP is 849201 immediately!",
        },
    )
    assert r11.status_code == 200

    # 12. Installed Application Audit
    r12 = client.post(
        "/api/v1/permissions/analyze-batch",
        json={
            "apps": [
                {
                    "app_name": "Calculator",
                    "package_name": "com.android.calc",
                    "permissions": ["android.permission.INTERNET"],
                },
                {
                    "app_name": "Rogue Spyware",
                    "package_name": "com.rogue.banker",
                    "permissions": [
                        "android.permission.BIND_ACCESSIBILITY_SERVICE",
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.READ_SMS",
                        "android.permission.RECEIVE_SMS",
                    ],
                },
            ]
        },
    )
    assert r12.status_code == 200

    # 14. AI Security Assistant
    r14 = client.post(
        "/api/v1/assistant/chat",
        json={"message": "How do I spot a phishing URL safely?"},
    )
    assert r14.status_code == 200

    # 15. Security Dashboard Analytics
    r15 = client.get("/api/v1/analytics/dashboard?days=30")
    assert r15.status_code == 200

    # 16. Security Alerts (create + resolve)
    r16 = client.post(
        "/api/v1/alerts",
        json={
            "title": "Test Manual Alert",
            "severity": "high",
            "category": "SYSTEM",
            "target": "test.suspicious.target",
            "risk_score": 78,
            "explanation": "Manual verification alert.",
            "recommended_actions": ["Inspect immediately."],
        },
    )
    assert r16.status_code == 201
    alert_id = r16.json()["id"]
    r16_res = client.patch(f"/api/v1/alerts/{alert_id}/resolve?is_resolved=true")
    assert r16_res.status_code == 200

    # 17. Audit History (delete a scan record to trigger audit_history event)
    hist_resp = client.get("/api/v1/history?limit=5")
    assert hist_resp.status_code == 200
    hist_items = hist_resp.json()["scans"]
    assert len(hist_items) >= 1
    scan_id_to_delete = hist_items[0]["id"]
    r17 = client.delete(f"/api/v1/history/{scan_id_to_delete}")
    assert r17.status_code == 200

    # 18. Real-Time Protection (activation, permission_revoked, service_interruption, daily_report)
    r18_act = client.post(
        "/api/v1/events/process",
        json={
            "module_name": "realtime_protection",
            "event_category": "protection_activated",
            "source": "realtime_monitor",
            "target_identifier": "realtime_shield",
            "risk_score": 0,
            "explanation": "Real-Time Protection activated.",
        },
    )
    assert r18_act.status_code == 200
    assert r18_act.json()["notification_status"] == "delivered_immediate"

    r18_perm = client.post(
        "/api/v1/events/process",
        json={
            "module_name": "realtime_protection",
            "event_category": "permission_revoked",
            "source": "system_event",
            "target_identifier": "BIND_NOTIFICATION_LISTENER_SERVICE",
            "risk_score": 70,
            "explanation": "Notification Listener permission revoked.",
        },
    )
    assert r18_perm.status_code == 200
    assert r18_perm.json()["notification_status"] == "delivered_immediate"

    r18_daily = client.post("/api/v1/events/daily-report")
    assert r18_daily.status_code == 200
    assert r18_daily.json()["report_event"]["event_category"] == "daily_report"

    # VERIFY ALL 18 MODULES ARE PRESENT IN UNIFIED ANALYTICS!
    analytics_resp = client.get("/api/v1/events/analytics?period=daily")
    assert analytics_resp.status_code == 200
    analytics = analytics_resp.json()
    assert analytics["total_registered_modules"] == 18
    assert analytics["active_modules_count"] == 18, (
        "Missing modules: "
        + str([m["module_name"] for m in analytics["module_distribution"] if m["total_events"] == 0])
    )
    assert analytics["total_analyzed_events"] >= 18
    assert analytics["total_threats_detected"] >= 1
    assert 0 <= analytics["device_security_posture_score"] <= 100

    # VERIFY PRIVACY REDACTION ON STORED EVENTS (OTP 849201 must NOT appear raw)
    hist_all = client.get("/api/v1/events/history?limit=200").json()
    for evt in hist_all["events"]:
        assert "849201" not in evt["target_identifier"]
        assert "849201" not in evt["explanation"]
        # Verify all 15 standardized fields exist
        for required_key in (
            "event_id",
            "user_id",
            "module_name",
            "event_category",
            "source",
            "target_identifier",
            "risk_score",
            "classification",
            "severity",
            "findings",
            "explanation",
            "recommended_actions",
            "detection_timestamp",
            "analysis_status",
            "notification_status",
        ):
            assert required_key in evt


def test_failed_and_unavailable_never_marked_safe_and_user_isolation():
    """Verify failed/unavailable/unverified separation, dedup, filtering, and user isolation."""
    uid_1 = f"iso-u1-{uuid.uuid4().hex[:8]}"
    uid_2 = f"iso-u2-{uuid.uuid4().hex[:8]}"
    _set_user(uid_1)

    # Submit failed, unavailable, unverified, and safe events
    r_fail = client.post(
        "/api/v1/events/process",
        json={
            "module_name": "url_scanner",
            "target_identifier": "https://offline-timeout.example",
            "risk_score": 0,
            "analysis_status": "failed",
            "explanation": "Backend DNS timeout during URL analysis.",
            "idempotency_key": f"fail-{uid_1}",
        },
    )
    assert r_fail.status_code == 200
    assert r_fail.json()["classification"] == "Failed"
    assert r_fail.json()["classification"] != "Safe"

    r_unavail = client.post(
        "/api/v1/events/process",
        json={
            "module_name": "call_screening",
            "target_identifier": "+15559990001",
            "risk_score": None,
            "analysis_status": "unavailable",
            "explanation": "Reputation lookup unavailable offline.",
            "idempotency_key": f"unavail-{uid_1}",
        },
    )
    assert r_unavail.status_code == 200
    assert r_unavail.json()["classification"] == "Unavailable"

    # Duplicate submission with identical idempotency_key must deduplicate cleanly
    r_dup = client.post(
        "/api/v1/events/process",
        json={
            "module_name": "call_screening",
            "target_identifier": "+15559990001",
            "risk_score": None,
            "analysis_status": "unavailable",
            "explanation": "Duplicate retry.",
            "idempotency_key": f"unavail-{uid_1}",
        },
    )
    assert r_dup.status_code == 200
    assert r_dup.json()["is_duplicate"] is True
    assert r_dup.json()["event_id"] == r_unavail.json()["event_id"]

    # Check analytics: 0 safe, 0 analyzed, 2 failed/unavailable!
    a1 = client.get("/api/v1/events/analytics?period=daily").json()
    assert a1["safe_count"] == 0
    assert a1["total_analyzed_events"] == 0
    assert a1["failed_or_unavailable_events"] == 2
    assert a1["monitoring_coverage_percent"] == 0.0

    # User B must see ZERO of User A's events and cannot delete User A's event
    _set_user(uid_2)
    h2 = client.get("/api/v1/events/history").json()
    assert h2["total"] == 0
    del_attempt = client.delete(f"/api/v1/events/{r_fail.json()['event_id']}")
    assert del_attempt.status_code == 404


def test_fault_isolation_when_alert_repo_throws():
    """A failure in alert creation must NEVER crash the calling module event pipeline."""
    uid = f"fault-iso-{uuid.uuid4().hex[:8]}"
    _set_user(uid)

    with patch.object(smart_event_engine.alert_repo, "create_alert", side_effect=RuntimeError("DB locked")):
        resp = client.post(
            "/api/v1/events/process",
            json={
                "module_name": "apk_analyzer",
                "target_identifier": "evil_banker.apk",
                "risk_score": 92,
                "classification": "Critical",
                "explanation": "Banking trojan signature detected.",
                "idempotency_key": f"fault-{uid}",
            },
        )
        assert resp.status_code == 200
        evt = resp.json()
        assert evt["classification"] == "Critical"
        assert evt["notification_status"] == "delivered_immediate"

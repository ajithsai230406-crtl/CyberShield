"""Tests for CyberShield Security Alerts Service and API Endpoints."""

import pytest
from fastapi.testclient import TestClient

from app.main import app, alert_repo
from app.auth import get_current_user, AuthenticatedUser

client = TestClient(app)


class TestSecurityAlertsServiceAndEndpoints:
    """Comprehensive test suite for alert generation, deduplication, state transitions, and filtering."""

    def setup_method(self):
        """Ensure clean alert repository for each test."""
        alert_repo.clear_all()

    def test_evaluate_and_create_scan_alert_severities(self):
        """Verify alert severity assignment based on risk score and classification."""
        # Critical alert
        crit_event = {
            "id": "scan-crit-001",
            "scan_type": "URL",
            "target": "https://phishing-banking-portal.com",
            "risk_score": 90,
            "classification": "Critical",
            "summary": "Verified credential harvester targeting online banking.",
        }
        crit_alert = alert_repo.evaluate_and_create_scan_alert(crit_event, user_id="user-123")
        assert crit_alert is not None
        assert crit_alert["severity"] == "critical"
        assert crit_alert["category"] == "URL"
        assert "Phishing" in crit_alert["title"]
        assert len(crit_alert["recommended_actions"]) >= 2

        # High risk alert
        high_event = {
            "id": "scan-high-002",
            "scan_type": "SMS",
            "target": "+18885550199",
            "risk_score": 60,
            "classification": "High Risk",
            "summary": "Urgent wire transfer smishing message detected.",
        }
        high_alert = alert_repo.evaluate_and_create_scan_alert(high_event, user_id="user-123")
        assert high_alert is not None
        assert high_alert["severity"] == "high"
        assert high_alert["category"] == "SMS"

        # Suspicious alert (medium severity)
        susp_event = {
            "id": "scan-susp-003",
            "scan_type": "FILE",
            "target": "invoice_update.vbs",
            "risk_score": 40,
            "classification": "Suspicious",
            "summary": "Obfuscated script signature found in attachment.",
        }
        susp_alert = alert_repo.evaluate_and_create_scan_alert(susp_event, user_id="user-123")
        assert susp_alert is not None
        assert susp_alert["severity"] == "medium"
        assert susp_alert["category"] == "FILE"

        # Safe finding should not trigger an alert
        safe_event = {
            "id": "scan-safe-004",
            "scan_type": "URL",
            "target": "https://google.com",
            "risk_score": 5,
            "classification": "Safe",
            "summary": "Well-known legitimate domain.",
        }
        safe_alert = alert_repo.evaluate_and_create_scan_alert(safe_event, user_id="user-123")
        assert safe_alert is None

    def test_alert_deduplication(self):
        """Verify that duplicate scan alerts for the same event key or scan_id are not created."""
        event = {
            "id": "scan-dedup-001",
            "scan_type": "APK",
            "target": "SpywareTrojan.apk",
            "risk_score": 95,
            "classification": "Critical",
            "summary": "Trojanized application with SMS interceptor backdoor.",
        }

        first_alert = alert_repo.evaluate_and_create_scan_alert(event, user_id="user-dedup")
        assert first_alert is not None

        # Re-evaluating the exact same scan event
        second_alert = alert_repo.evaluate_and_create_scan_alert(event, user_id="user-dedup")
        assert second_alert is not None
        assert second_alert["id"] == first_alert["id"]

        all_alerts = alert_repo.list_alerts(user_id="user-dedup")
        assert len(all_alerts) == 1

    def test_community_threat_alert_creation(self):
        """Verify alert creation from community threat report."""
        report_data = {
            "category": "phone",
            "target": "+18005550188",
            "report_count": 5,
        }
        comm_alert = alert_repo.evaluate_and_create_community_alert(report_data, user_id="user-comm")
        assert comm_alert is not None
        assert comm_alert["category"] == "COMMUNITY"
        assert comm_alert["severity"] == "high"
        assert "+18005550188" in comm_alert["title"]

    def test_mark_as_read_and_resolved_workflow(self):
        """Test read and resolved state transitions and timestamps."""
        alert = alert_repo.create_alert(
            title="QR Code Phishing Redirection",
            severity="high",
            category="QR",
            target="https://fake-login-qr.example",
            risk_score=75,
            explanation="Malicious redirect to spoofed banking portal.",
            recommended_actions=["Do not open link", "Block source"],
            user_id="user-state",
        )
        alert_id = alert["id"]
        assert alert["is_read"] is False
        assert alert["is_resolved"] is False
        assert alert["status"] == "unread"

        # Mark as read
        read_alert = alert_repo.mark_as_read(alert_id, user_id="user-state", is_read=True)
        assert read_alert["is_read"] is True
        assert read_alert["status"] == "read"

        # Mark as resolved
        resolved_alert = alert_repo.mark_as_resolved(alert_id, user_id="user-state", is_resolved=True)
        assert resolved_alert["is_resolved"] is True
        assert resolved_alert["status"] == "resolved"
        assert resolved_alert["resolved_at"] is not None

        # Mark as unread again
        unread_alert = alert_repo.mark_as_read(alert_id, user_id="user-state", is_read=False)
        assert unread_alert["is_read"] is False

    def test_list_alerts_with_filters(self):
        """Test alert listing with severity, read, and resolved filters."""
        alert_repo.create_alert(
            title="Critical Alert 1",
            severity="critical",
            category="URL",
            target="target1.com",
            risk_score=90,
            explanation="Critical risk explanation",
            recommended_actions=[],
            user_id="user-filter",
            event_key="crit-1",
        )
        alert_repo.create_alert(
            title="High Alert 2",
            severity="high",
            category="SMS",
            target="target2.com",
            risk_score=60,
            explanation="High risk explanation",
            recommended_actions=[],
            user_id="user-filter",
            event_key="high-2",
        )
        alert3 = alert_repo.create_alert(
            title="Medium Alert 3",
            severity="medium",
            category="QR",
            target="target3.com",
            risk_score=45,
            explanation="Medium risk explanation",
            recommended_actions=[],
            user_id="user-filter",
            event_key="med-3",
        )
        alert_repo.mark_as_resolved(alert3["id"], user_id="user-filter", is_resolved=True)

        # Filter by severity
        crit_only = alert_repo.list_alerts(user_id="user-filter", severity="critical")
        assert len(crit_only) == 1
        assert crit_only[0]["severity"] == "critical"

        # Filter by resolved
        resolved_only = alert_repo.list_alerts(user_id="user-filter", is_resolved=True)
        assert len(resolved_only) == 1
        assert resolved_only[0]["id"] == alert3["id"]

        # Filter by unread
        unread_only = alert_repo.list_alerts(user_id="user-filter", is_read=False)
        assert len(unread_only) == 3

    def test_alert_stats(self):
        """Test aggregate stats calculation."""
        alert_repo.create_alert(
            title="Critical 1",
            severity="critical",
            category="URL",
            target="crit.com",
            risk_score=90,
            explanation="exp",
            recommended_actions=[],
            user_id="user-stats",
            event_key="k1",
        )
        a2 = alert_repo.create_alert(
            title="High 2",
            severity="high",
            category="APK",
            target="app.apk",
            risk_score=65,
            explanation="exp",
            recommended_actions=[],
            user_id="user-stats",
            event_key="k2",
        )
        alert_repo.mark_as_read(a2["id"], user_id="user-stats", is_read=True)

        stats = alert_repo.get_alert_stats(user_id="user-stats")
        assert stats["total"] == 2
        assert stats["unread"] == 1
        assert stats["critical"] == 1
        assert stats["high"] == 1
        assert stats["resolved"] == 0

    def test_api_endpoints_workflow(self):
        """Test full HTTP API lifecycle for security alerts."""
        # 1. Create alert via POST /api/v1/alerts
        create_payload = {
            "title": "Malicious Banking Phish",
            "severity": "critical",
            "category": "URL",
            "target": "https://secure-chase-update.net",
            "risk_score": 92,
            "explanation": "Detected fake login form intercepting credentials.",
            "recommended_actions": ["Block domain", "Do not open"],
        }
        res_create = client.post("/api/v1/alerts", json=create_payload)
        assert res_create.status_code == 201
        alert = res_create.json()
        alert_id = alert["id"]
        assert alert["title"] == "Malicious Banking Phish"
        assert alert["severity"] == "critical"
        assert alert["is_read"] is False

        # 2. Get alert stats via GET /api/v1/alerts/stats
        res_stats = client.get("/api/v1/alerts/stats")
        assert res_stats.status_code == 200
        stats = res_stats.json()
        assert stats["total"] >= 1
        assert stats["unread"] >= 1
        assert stats["critical"] >= 1

        # 3. List alerts via GET /api/v1/alerts
        res_list = client.get("/api/v1/alerts?severity=critical")
        assert res_list.status_code == 200
        data = res_list.json()
        assert data["status"] == "success"
        assert len(data["alerts"]) >= 1

        # 4. Get alert details via GET /api/v1/alerts/{id}
        res_detail = client.get(f"/api/v1/alerts/{alert_id}")
        assert res_detail.status_code == 200
        assert res_detail.json()["id"] == alert_id

        # 5. Mark as read via PATCH /api/v1/alerts/{id}/read
        res_read = client.patch(f"/api/v1/alerts/{alert_id}/read?is_read=true")
        assert res_read.status_code == 200
        assert res_read.json()["is_read"] is True

        # 6. Mark as resolved via PATCH /api/v1/alerts/{id}/resolve
        res_resolve = client.patch(f"/api/v1/alerts/{alert_id}/resolve?is_resolved=true")
        assert res_resolve.status_code == 200
        assert res_resolve.json()["is_resolved"] is True
        assert res_resolve.json()["status"] == "resolved"

        # 7. Non-existent alert returns 404
        res_404 = client.get("/api/v1/alerts/alert-nonexistent-999")
        assert res_404.status_code == 404


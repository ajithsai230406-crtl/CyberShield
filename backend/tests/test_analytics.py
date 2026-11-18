"""Unit and integration tests for CyberShield Security Dashboard & Analytics module."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app, analytics_service, history_repo, community_repo
from app.services.analytics_service import AnalyticsService

client = TestClient(app)


class TestAnalyticsServiceUnit:
    """Unit tests for AnalyticsService metrics, trends, and transparent score formula."""

    def setup_method(self):
        history_repo.clear()
        community_repo.clear_all()

    def test_baseline_score_when_no_scans(self):
        """Empty scan database yields neutral baseline score 70 with non-absolute disclaimer."""
        res = analytics_service.get_dashboard_analytics(user_id="user-empty", days=30)
        assert res["total_scans"] == 0
        assert res["safe_scans"] == 0
        assert res["threat_detection_rate"] == 0.0
        score_data = res["security_score"]
        assert score_data["score"] == 70
        assert score_data["tier"] == "Neutral"
        assert "no security system can guarantee 100%" in score_data["disclaimer"].lower()

    def test_score_calculation_with_clean_scans(self):
        """Safe scans reward hygiene, increasing the security score up to the capped threshold."""
        for i in range(5):
            history_repo.record_scan(
                scan_id=f"clean-{i}",
                scan_type="URL",
                target=f"https://trusted-site-{i}.org",
                risk_score=10,
                classification="Safe",
                summary="Clean URL",
                status_badge="safe",
                details={"user_id": "test-user-clean"},
            )

        res = analytics_service.get_dashboard_analytics(user_id="test-user-clean", days=30)
        assert res["total_scans"] == 5
        assert res["safe_scans"] == 5
        assert res["suspicious_scans"] == 0
        assert res["threat_detection_rate"] == 0.0
        assert res["scanner_breakdown"]["URL"]["safe"] == 5
        score_data = res["security_score"]
        assert score_data["score"] >= 85
        assert score_data["tier"] == "Optimal"
        assert score_data["score"] < 100  # Never 100% to reflect realistic zero-day boundaries
        assert "zero-day" in score_data["disclaimer"].lower()

    def test_score_deductions_for_critical_threats(self):
        """Critical and High Risk threats penalize score and elevate threat detection rate."""
        # 1 Critical scan
        history_repo.record_scan(
            scan_id="crit-1",
            scan_type="FILE",
            target="invoice.pdf.exe",
            risk_score=85,
            classification="Critical",
            summary="Disguised PE Executable",
            status_badge="danger",
            details={"user_id": "test-user-threat"},
        )
        # 1 High Risk scan
        history_repo.record_scan(
            scan_id="high-1",
            scan_type="SMS",
            target="Bank lock within 24h",
            risk_score=65,
            classification="High Risk",
            summary="Smishing alert",
            status_badge="danger",
            details={"user_id": "test-user-threat"},
        )
        # 1 Safe scan
        history_repo.record_scan(
            scan_id="safe-1",
            scan_type="URL",
            target="https://google.com",
            risk_score=5,
            classification="Safe",
            summary="Clean URL",
            status_badge="safe",
            details={"user_id": "test-user-threat"},
        )

        res = analytics_service.get_dashboard_analytics(user_id="test-user-threat", days=30)
        assert res["total_scans"] == 3
        assert res["critical_scans"] == 1
        assert res["high_risk_scans"] == 1
        assert res["safe_scans"] == 1
        assert res["threat_detection_rate"] == pytest.approx(66.7, 0.1)

        score_data = res["security_score"]
        assert score_data["score"] <= 75
        assert "minus threat penalties" in score_data["calculation_explanation"].lower()


class TestDashboardAnalyticsEndpoints:
    """Integration tests for GET /api/v1/analytics/dashboard."""

    def setup_method(self):
        history_repo.clear()
        community_repo.clear_all()

    def test_get_dashboard_analytics_success(self):
        """GET /api/v1/analytics/dashboard returns full structured analytics model."""
        resp = client.get("/api/v1/analytics/dashboard?days=30")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_scans" in data
        assert "threat_detection_rate" in data
        assert "security_score" in data
        assert "scanner_breakdown" in data
        assert "risk_distribution" in data
        assert "activity_trends" in data
        assert "community_stats" in data
        assert "recent_scans" in data

        # Check scanner breakdown coverage
        for sc in ["URL", "SMS", "QR", "SCREENSHOT", "APK", "PERMISSIONS", "EMAIL", "FILE"]:
            assert sc in data["scanner_breakdown"]

        # Check transparent disclaimer presence
        disclaimer = data["security_score"]["disclaimer"]
        assert "100%" in disclaimer
        assert "zero-day" in disclaimer.lower()

    def test_time_window_filtering(self):
        """Querying with days=7 or days=0 succeeds with appropriate timeframe metadata."""
        resp7 = client.get("/api/v1/analytics/dashboard?days=7")
        assert resp7.status_code == 200
        assert resp7.json()["time_range_days"] == 7

        resp_all = client.get("/api/v1/analytics/dashboard?days=0")
        assert resp_all.status_code == 200
        assert resp_all.json()["time_range_days"] == 0


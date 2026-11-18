"""Unit and integration tests for CyberShield Permission Analyzer module."""

from __future__ import annotations

import io
import zipfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.permission_detector import (
    PermissionAnalyzer,
    KNOWN_PERMISSIONS,
    DANGEROUS_COMBOS,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _create_minimal_apk_bytes(manifest_content: str = "") -> bytes:
    """Create a minimal in-memory ZIP simulating an APK with AndroidManifest.xml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_content.encode("utf-8"))
        zf.writestr("classes.dex", b"dex\n035\x00")
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Unit Tests for PermissionAnalyzer Engine
# ---------------------------------------------------------------------------

class TestPermissionAnalyzerUnit:
    """Core unit tests for permission extraction, scoring, and classification."""

    def setup_method(self):
        self.analyzer = PermissionAnalyzer()

    def test_safe_permissions_classified_safe(self):
        """Normal utility permissions should have low risk score and Safe classification."""
        perms = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.VIBRATE",
            "android.permission.WAKE_LOCK",
        ]
        result = self.analyzer.analyze_permissions_list(
            permissions=perms,
            app_name="Calculator Utility",
            package_name="com.example.calculator",
        )
        assert result.risk_score < 30
        assert result.classification == "Safe"
        assert result.dangerous_permissions_count == 0
        assert "normal" in result.explanation.lower()
        assert len(result.recommendations) > 0

    def test_suspicious_permissions_classification(self):
        """Single or moderate sensitive permissions should produce Suspicious tier."""
        perms = [
            "android.permission.INTERNET",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_SETTINGS",
            "android.permission.ACCESS_FINE_LOCATION",
        ]
        result = self.analyzer.analyze_permissions_list(
            permissions=perms,
            app_name="Media Gallery",
            package_name="com.example.gallery",
        )
        assert 30 <= result.risk_score < 60
        assert result.classification == "Suspicious"
        assert result.dangerous_permissions_count >= 1

    def test_high_risk_permissions_classification(self):
        """Accumulation of sensitive permissions should escalate to High Risk."""
        perms = [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CAMERA",
        ]
        result = self.analyzer.analyze_permissions_list(
            permissions=perms,
            app_name="Social Network",
            package_name="com.example.social",
        )
        assert 60 <= result.risk_score < 80
        assert result.classification == "High Risk"
        assert result.dangerous_permissions_count == 4

    def test_critical_banking_trojan_combo(self):
        """SMS interception + Accessibility service combo must trigger Critical tier."""
        perms = [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ]
        result = self.analyzer.analyze_permissions_list(
            permissions=perms,
            app_name="Fake Flash Player",
            package_name="com.trojan.flash",
        )
        assert result.risk_score >= 80
        assert result.classification == "Critical"
        assert any("banking trojan" in combo.lower() for combo in result.combo_findings)
        assert any("accessibility" in f.lower() for f in result.findings)

    def test_critical_silent_dropper_combo(self):
        """Dropper + Accessibility combo must escalate to Critical tier."""
        perms = [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ]
        result = self.analyzer.analyze_permissions_list(
            permissions=perms,
            app_name="App Updater Helper",
            package_name="com.dropper.helper",
        )
        assert result.classification == "Critical"
        assert any("dropper" in combo.lower() for combo in result.combo_findings)

    def test_stalkerware_surveillance_combo(self):
        """Microphone + Fine location surveillance combo triggers bonus and high risk."""
        perms = [
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
        ]
        result = self.analyzer.analyze_permissions_list(perms)
        assert any("surveillance" in combo.lower() or "wiretapping" in combo.lower() for combo in result.combo_findings)

    def test_explanation_exoneration_disclaimer(self):
        """Explanations must clearly state that dangerous permissions alone do not prove malware."""
        perms = ["android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA"]
        result = self.analyzer.analyze_permissions_list(perms)
        # Should not falsely claim confirmed malware
        assert "confirmed malware" not in result.explanation.lower() or "does not" in result.explanation.lower()

    def test_permission_shorthand_normalization(self):
        """Input without 'android.permission.' prefix should be normalized automatically."""
        perms = ["READ_SMS", "CAMERA", "ACCESS_FINE_LOCATION"]
        result = self.analyzer.analyze_permissions_list(perms)
        assert "android.permission.READ_SMS" in result.permissions
        assert "android.permission.CAMERA" in result.permissions

    def test_analyze_apk_bytes_valid_manifest(self):
        """Extracts permissions from an in-memory simulated APK file."""
        manifest_text = (
            "android.permission.READ_SMS "
            "android.permission.RECEIVE_SMS "
            "android.permission.INTERNET "
            "android.permission.ACCESS_FINE_LOCATION"
        )
        apk_bytes = _create_minimal_apk_bytes(manifest_text)
        result = self.analyzer.analyze_apk_bytes(apk_bytes, filename="sample_app.apk")
        assert result.total_permissions_count >= 3
        assert "android.permission.READ_SMS" in result.permissions
        assert "android.permission.ACCESS_FINE_LOCATION" in result.permissions

    def test_reject_corrupted_zip_archive(self):
        """Corrupted/non-ZIP data must raise ValueError."""
        corrupted = b"NOT_A_ZIP_HEADER_123456789"
        with pytest.raises(ValueError, match="not a valid APK"):
            self.analyzer.analyze_apk_bytes(corrupted, filename="bad.apk")

    def test_reject_missing_android_manifest(self):
        """ZIP file without AndroidManifest.xml must raise ValueError."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("some_other_file.txt", b"hello world")
        missing_manifest_bytes = buf.getvalue()

        with pytest.raises(ValueError, match="does not contain AndroidManifest.xml"):
            self.analyzer.analyze_apk_bytes(missing_manifest_bytes, filename="no_manifest.apk")

    def test_reject_empty_bytes(self):
        """Empty byte payload must raise ValueError."""
        with pytest.raises(ValueError, match="empty"):
            self.analyzer.analyze_apk_bytes(b"", filename="empty.apk")


# ---------------------------------------------------------------------------
# API Endpoint Integration Tests
# ---------------------------------------------------------------------------

class TestPermissionAnalyzerEndpoints:
    """Integration tests for POST /api/v1/permissions/analyze and analyze-list."""

    def test_analyze_list_safe_app(self):
        """POST /api/v1/permissions/analyze-list with safe permissions returns 200."""
        payload = {
            "app_name": "Simple Clock",
            "package_name": "com.clock.app",
            "permissions": ["android.permission.WAKE_LOCK", "android.permission.VIBRATE"],
        }
        resp = client.post("/api/v1/permissions/analyze-list", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "analyzed"
        assert data["scan_type"] == "permissions"
        assert data["classification"] == "Safe"
        assert data["risk_score"] < 30
        assert data["dangerous_permissions_count"] == 0
        assert len(data["recommendations"]) > 0

    def test_analyze_list_critical_trojan(self):
        """POST /api/v1/permissions/analyze-list with banking trojan combo returns 200 Critical."""
        payload = {
            "app_name": "Update Bank Security",
            "package_name": "com.trojan.bankhack",
            "permissions": [
                "android.permission.READ_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
            ],
        }
        resp = client.post("/api/v1/permissions/analyze-list", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["classification"] == "Critical"
        assert data["risk_score"] >= 80
        assert len(data["combo_findings"]) > 0

    def test_scan_permissions_alias_endpoint(self):
        """POST /api/v1/scan/permissions alias returns identical response."""
        payload = {
            "app_name": "Photo Editor",
            "package_name": "com.photo.editor",
            "permissions": ["android.permission.CAMERA", "android.permission.READ_EXTERNAL_STORAGE"],
        }
        resp = client.post("/api/v1/scan/permissions", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_type"] == "permissions"
        assert data["total_permissions_count"] == 2

    def test_analyze_apk_upload_success(self):
        """POST /api/v1/permissions/analyze with valid simulated APK returns 200."""
        manifest_data = (
            "android.permission.READ_SMS "
            "android.permission.SYSTEM_ALERT_WINDOW "
            "android.permission.ACCESS_FINE_LOCATION"
        )
        apk_bytes = _create_minimal_apk_bytes(manifest_data)
        files = {"file": ("test_package.apk", apk_bytes, "application/vnd.android.package-archive")}

        resp = client.post("/api/v1/permissions/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_type"] == "permissions"
        assert data["dangerous_permissions_count"] >= 2
        assert "android.permission.READ_SMS" in data["permissions"]

    def test_analyze_apk_rejects_non_apk_extension(self):
        """Uploading a file with .png or .zip extension must return 400 Bad Request."""
        files = {"file": ("not_an_apk.png", b"fake_png_data", "image/png")}
        resp = client.post("/api/v1/permissions/analyze", files=files)
        assert resp.status_code == 400
        assert "Only .apk files are accepted" in resp.json()["detail"]

    def test_analyze_apk_rejects_empty_file(self):
        """Uploading a 0-byte APK must return 400 Bad Request."""
        files = {"file": ("empty.apk", b"", "application/vnd.android.package-archive")}
        resp = client.post("/api/v1/permissions/analyze", files=files)
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()

    def test_analyze_apk_rejects_corrupted_archive(self):
        """Uploading corrupted bytes with .apk extension must return 400."""
        files = {"file": ("corrupted.apk", b"PK_NOT_A_REAL_ZIP_CONTENT", "application/vnd.android.package-archive")}
        resp = client.post("/api/v1/permissions/analyze", files=files)
        assert resp.status_code == 400
        assert "not a valid APK" in resp.json()["detail"]

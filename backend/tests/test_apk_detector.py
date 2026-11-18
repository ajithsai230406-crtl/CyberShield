"""Unit and integration tests for CyberShield APK Security Analysis."""

import io
import zipfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.apk_detector import APKSecurityAnalyzer, APKAnalysisResult

client = TestClient(app)


def make_test_apk_bytes(
    permissions: list[str] | None = None,
    include_manifest: bool = True,
    dex_count: int = 1,
    include_native_lib: bool = False,
) -> bytes:
    """Helper to generate in-memory synthetic APK archives for testing."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if include_manifest:
            manifest_content = " ".join(permissions or [])
            z.writestr("AndroidManifest.xml", manifest_content.encode("utf-8"))
        for i in range(dex_count):
            name = "classes.dex" if i == 0 else f"classes{i+1}.dex"
            z.writestr(name, b"dex\n035\x00")
        if include_native_lib:
            z.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF")
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Direct Service Unit Tests
# ---------------------------------------------------------------------------


def test_apk_analyzer_direct_safe_package():
    """APK with standard permissions should have low risk and Safe classification."""
    analyzer = APKSecurityAnalyzer()
    apk_data = make_test_apk_bytes(permissions=["android.permission.INTERNET"])
    result = analyzer.analyze_bytes(apk_data, "safe_utility.apk")

    assert isinstance(result, APKAnalysisResult)
    assert result.classification == "Safe"
    assert result.risk_score < 30
    assert len(result.dangerous_permissions) == 0
    assert "safe_utility" in result.app_name


def test_apk_analyzer_direct_dangerous_permissions():
    """APK with SMS and contact access should flag dangerous permissions."""
    analyzer = APKSecurityAnalyzer()
    apk_data = make_test_apk_bytes(
        permissions=[
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
        ]
    )
    result = analyzer.analyze_bytes(apk_data, "sus_contacts.apk")

    assert result.risk_score >= 30
    assert result.classification in ("Suspicious", "High Risk")
    assert "android.permission.READ_SMS" in result.dangerous_permissions
    assert "android.permission.READ_CONTACTS" in result.dangerous_permissions
    assert any("READ_SMS" in f for f in result.findings)


def test_apk_analyzer_combo_detection():
    """SMS + Accessibility combination triggers combo bonus and High Risk."""
    analyzer = APKSecurityAnalyzer()
    apk_data = make_test_apk_bytes(
        permissions=[
            "android.permission.READ_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ]
    )
    result = analyzer.analyze_bytes(apk_data, "bank_overlay_trojan.apk")

    assert result.risk_score >= 60
    assert result.classification == "High Risk"
    assert "SMS + Accessibility Combo" in result.combo_findings
    assert any("SMS + Accessibility Combo" in f for f in result.findings)


def test_apk_analyzer_rejects_corrupted_zip():
    """Invalid ZIP archive raises ValueError."""
    analyzer = APKSecurityAnalyzer()
    with pytest.raises(ValueError, match="not a valid APK"):
        analyzer.analyze_bytes(b"corrupted_non_zip_bytes", "broken.apk")


def test_apk_analyzer_rejects_missing_manifest():
    """Archive missing AndroidManifest.xml raises ValueError."""
    analyzer = APKSecurityAnalyzer()
    apk_data = make_test_apk_bytes(include_manifest=False)
    with pytest.raises(ValueError, match="AndroidManifest.xml"):
        analyzer.analyze_bytes(apk_data, "no_manifest.apk")


# ---------------------------------------------------------------------------
# API Integration Tests (POST /api/v1/apk/analyze)
# ---------------------------------------------------------------------------


def test_api_apk_rejects_non_apk_extension():
    """Endpoint should return 400 if file extension is not .apk."""
    response = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("test.png", b"fake png data", "image/png")},
    )
    assert response.status_code == 400
    assert "Invalid file extension" in response.json()["detail"]


def test_api_apk_rejects_empty_file():
    """Endpoint should return 400 if uploaded file is empty."""
    response = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("empty.apk", b"", "application/vnd.android.package-archive")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_api_apk_rejects_corrupted_archive():
    """Endpoint should return 400 if APK is not a valid zip archive."""
    response = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("corrupted.apk", b"random junk data", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "valid APK" in response.json()["detail"]


def test_api_apk_rejects_missing_manifest():
    """Endpoint should return 400 if APK lacks AndroidManifest.xml."""
    apk_data = make_test_apk_bytes(include_manifest=False)
    response = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("nomanifest.apk", apk_data, "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "AndroidManifest.xml" in response.json()["detail"]


def test_api_apk_analyze_safe():
    """Valid safe APK returns HTTP 200 with Safe classification."""
    apk_data = make_test_apk_bytes(
        permissions=["android.permission.INTERNET", "android.permission.VIBRATE"]
    )
    response = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("calculator.apk", apk_data, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "inspected"
    assert data["scan_type"] == "apk"
    assert data["filename"] == "calculator.apk"
    assert data["classification"] == "Safe"
    assert data["risk_score"] < 30
    assert isinstance(data["permissions"], list)
    assert isinstance(data["dangerous_permissions"], list)
    assert len(data["dangerous_permissions"]) == 0
    assert "recommendation" in data
    assert "explanation" in data
    assert "metadata" in data
    assert data["engine_status"] == "apk_security_inspector_active"


def test_api_apk_analyze_suspicious():
    """APK with location and contacts returns Suspicious classification."""
    apk_data = make_test_apk_bytes(
        permissions=[
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
        ]
    )
    response = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("tracker.apk", apk_data, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] in ("Suspicious", "High Risk")
    assert data["risk_score"] >= 30
    assert "android.permission.ACCESS_FINE_LOCATION" in data["dangerous_permissions"]
    assert "android.permission.READ_CONTACTS" in data["dangerous_permissions"]
    assert len(data["findings"]) >= 2
    assert len(data["finding_explanations"]) >= 2


def test_api_apk_analyze_high_risk_dropper_combo():
    """APK with REQUEST_INSTALL_PACKAGES and BIND_ACCESSIBILITY_SERVICE returns High Risk."""
    apk_data = make_test_apk_bytes(
        permissions=[
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ]
    )
    response = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("dropper_payload.apk", apk_data, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "High Risk"
    assert data["risk_score"] >= 60
    assert "Dropper + Accessibility Combo" in data["combo_findings"]


def test_api_apk_does_not_claim_confirmed_malware():
    """High-risk APK explanation explicitly clarifies it does NOT claim confirmed malware."""
    apk_data = make_test_apk_bytes(
        permissions=[
            "android.permission.READ_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ]
    )
    response = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("banking_trojan_test.apk", apk_data, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200
    explanation = response.json()["explanation"]
    assert "does NOT constitute a confirmed malware detection" in explanation


def test_api_apk_records_audit_history():
    """Successful APK scan records an entry in the audit history."""
    # Use the API to get initial count (accounts for SQLite persistence)
    initial_resp = client.get("/api/v1/history")
    initial_count = initial_resp.json()["total_count"] if initial_resp.status_code == 200 else 0

    apk_data = make_test_apk_bytes(permissions=["android.permission.INTERNET"])
    response = client.post(
        "/api/v1/apk/analyze",
        files={"file": ("audit_sample.apk", apk_data, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200

    history_resp = client.get("/api/v1/history")
    assert history_resp.status_code == 200
    history_data = history_resp.json()
    assert history_data["total_count"] == initial_count + 1
    assert history_data["scans"][0]["scan_type"] == "APK"
    assert "audit_sample.apk" in history_data["scans"][0]["target"]


def test_api_legacy_scan_apk_preserved():
    """Backwards-compatible POST /api/v1/scan/apk remains intact and returns 200."""
    response = client.post(
        "/api/v1/scan/apk",
        files={"file": ("legacy.apk", b"dummy content", "application/octet-stream")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "apk"
    assert data["status"] == "received"
    assert data["engine_status"] == "apk_pipeline_ready"


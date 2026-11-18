"""Comprehensive Unit and Integration Tests for CyberShield URL Threat Detection."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.url_detector import URLThreatDetector

client = TestClient(app)
detector = URLThreatDetector()


# ---------------------------------------------------------------------------
# Unit Tests for URLThreatDetector Heuristic Rules
# ---------------------------------------------------------------------------

class TestURLThreatDetectorUnit:
    """Direct unit tests for the heuristic detector class."""

    def test_required_url_google_safe(self):
        """https://google.com should be classified as Safe with score <= 29."""
        result = detector.analyze("https://google.com")
        assert result.scanned_url == "https://google.com"
        assert result.risk_score <= 29
        assert result.classification == "Safe"
        assert len(result.detected_indicators) == 0
        assert "Safe to browse" in result.recommendation
        assert len(result.explanation) > 0

    def test_required_url_ip_malicious(self):
        """http://192.168.1.1/login/verify-account combines IP + HTTP + keywords -> Malicious."""
        result = detector.analyze("http://192.168.1.1/login/verify-account")
        assert result.risk_score >= 70
        assert result.classification == "Malicious"
        assert result.classification != "Safe"
        assert any("IPv4 address" in ind for ind in result.detected_indicators)
        assert any("Insecure plain HTTP" in ind for ind in result.detected_indicators)
        assert any("phishing keyword" in ind for ind in result.detected_indicators)
        assert len(result.finding_explanations) >= 3
        assert "Do not open" in result.recommendation

    def test_required_url_keyword_subdomain_suspicious(self):
        """https://secure-login-verify.example.com has deceptive keywords on untrusted domain -> Suspicious."""
        result = detector.analyze("https://secure-login-verify.example.com")
        assert result.risk_score >= 30
        assert result.classification == "Suspicious"
        assert result.classification != "Safe"
        assert any("phishing keyword" in ind for ind in result.detected_indicators)
        assert len(result.finding_explanations) >= 1
        assert "Do not enter passwords" in result.recommendation

    def test_significant_threat_never_classified_safe(self):
        """Ensure URLs with significant indicators never get classified as Safe."""
        suspicious_samples = [
            "http://192.168.1.1/login/verify-account",
            "https://secure-login-verify.example.com",
            "https://tinyurl.com/account-verify",
            "http://my-blog.top",
            "https://paypal.com@attacker-site.com/auth",
            "https://login.verify.account.update.example.com",
        ]
        for url in suspicious_samples:
            result = detector.analyze(url)
            assert result.classification in ["Suspicious", "Malicious"], (
                f"URL '{url}' with significant indicators was incorrectly classified as '{result.classification}'"
            )
            assert result.risk_score >= 30

    def test_heuristic_raw_ip_address(self):
        """Raw IPv4 address should be flagged as suspicious indicator."""
        result = detector.analyze("https://192.168.1.1/dashboard")
        assert any("IPv4 address" in ind for ind in result.detected_indicators)
        assert result.risk_score >= 30
        assert result.classification in ["Suspicious", "Malicious"]

    def test_heuristic_url_shortener(self):
        """Known URL shorteners should be detected."""
        for shortener in ["https://tinyurl.com/report-doc-2026", "https://bit.ly/3xY9z01"]:
            result = detector.analyze(shortener)
            assert any("shortening service" in ind for ind in result.detected_indicators)
            assert result.risk_score >= 20

    def test_heuristic_userinfo_at_symbol(self):
        """URL with '@' symbol should be flagged for credential/host spoofing."""
        result = detector.analyze("https://paypal.com@attacker-site.com/login")
        assert any("'@' symbol" in ind for ind in result.detected_indicators)
        assert result.risk_score >= 25

    def test_heuristic_insecure_http(self):
        """Plain HTTP URL should trigger insecure transport warning."""
        result = detector.analyze("http://standard-blog.com")
        assert any("Insecure plain HTTP" in ind for ind in result.detected_indicators)
        assert result.risk_score >= 15

    def test_heuristic_suspicious_tld(self):
        """High-risk TLDs (.xyz, .top, .icu) should be detected."""
        result = detector.analyze("https://promo-deals.xyz")
        assert any("top-level domain" in ind for ind in result.detected_indicators)
        assert result.risk_score >= 20

    def test_heuristic_excessive_subdomains(self):
        """Excessive subdomain nesting should be flagged."""
        result = detector.analyze("https://login.verify.account.update.example.com")
        assert any("Excessive subdomains" in ind for ind in result.detected_indicators)
        assert result.risk_score >= 20

    def test_finding_explanations_structure(self):
        """Each finding must have a corresponding structured explanation."""
        result = detector.analyze("http://192.168.1.1/login/verify-account")
        assert len(result.finding_explanations) == len(result.detected_indicators)
        for detail in result.finding_explanations:
            assert "indicator" in detail
            assert "title" in detail
            assert "risk_level" in detail
            assert "explanation" in detail
            assert len(detail["explanation"]) > 20


# ---------------------------------------------------------------------------
# API Integration Tests for POST /api/v1/scan/url and POST /api/v1/url/scan
# ---------------------------------------------------------------------------

class TestURLScanEndpoints:
    """Integration tests verifying both POST /api/v1/scan/url and POST /api/v1/url/scan."""

    @pytest.mark.parametrize("endpoint", ["/api/v1/scan/url", "/api/v1/url/scan"])
    def test_required_google_safe_endpoint(self, endpoint):
        """https://google.com should return HTTP 200 with Safe classification and risk_score <= 29."""
        payload = {"url": "https://google.com"}
        response = client.post(endpoint, json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] <= 29
        assert data["classification"] == "Safe"
        assert "explanation" in data
        assert "recommendation" in data
        assert "Safe to browse" in data["recommendation"]
        assert "scanned_url" in data
        assert "target" in data
        assert "findings" in data
        assert "status" in data
        assert data["status"] == "inspected"

    @pytest.mark.parametrize("endpoint", ["/api/v1/scan/url", "/api/v1/url/scan"])
    def test_required_ip_malicious_endpoint(self, endpoint):
        """http://192.168.1.1/login/verify-account should return Malicious classification with risk_score >= 70."""
        payload = {"url": "http://192.168.1.1/login/verify-account"}
        response = client.post(endpoint, json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] >= 70
        assert data["classification"] == "Malicious"
        assert data["classification"] != "Safe"
        assert any("IPv4 address" in f for f in data["findings"])
        assert any("Insecure plain HTTP" in f for f in data["findings"])
        assert "Do not open" in data["recommendation"]
        assert len(data["finding_explanations"]) >= 3

    @pytest.mark.parametrize("endpoint", ["/api/v1/scan/url", "/api/v1/url/scan"])
    def test_required_keyword_subdomain_suspicious_endpoint(self, endpoint):
        """https://secure-login-verify.example.com should return Suspicious classification with risk_score between 30 and 69."""
        payload = {"url": "https://secure-login-verify.example.com"}
        response = client.post(endpoint, json=payload)
        assert response.status_code == 200
        data = response.json()
        assert 30 <= data["risk_score"] <= 69
        assert data["classification"] == "Suspicious"
        assert data["classification"] != "Safe"
        assert any("phishing keyword" in f for f in data["findings"])
        assert "Do not enter passwords" in data["recommendation"]

    @pytest.mark.parametrize("endpoint", ["/api/v1/scan/url", "/api/v1/url/scan"])
    def test_consistent_structured_json_schema(self, endpoint):
        """Verify all required fields exist consistently in response."""
        payload = {"url": "https://github.com/flutter/flutter"}
        response = client.post(endpoint, json=payload)
        assert response.status_code == 200
        data = response.json()
        
        required_keys = [
            "status",
            "scan_type",
            "target",
            "scanned_url",
            "timestamp",
            "risk_score",
            "classification",
            "findings",
            "detected_indicators",
            "explanation",
            "finding_explanations",
            "recommendation",
            "metadata",
            "engine_status",
        ]
        for key in required_keys:
            assert key in data, f"Key '{key}' missing from response of {endpoint}"

    @pytest.mark.parametrize("endpoint", ["/api/v1/scan/url", "/api/v1/url/scan"])
    def test_input_validation_empty_url(self, endpoint):
        """Empty URL should be rejected with HTTP 422."""
        response = client.post(endpoint, json={"url": ""})
        assert response.status_code == 422

    @pytest.mark.parametrize("endpoint", ["/api/v1/scan/url", "/api/v1/url/scan"])
    def test_input_validation_whitespace(self, endpoint):
        """Whitespace-only URL should be rejected with HTTP 422."""
        response = client.post(endpoint, json={"url": "   "})
        assert response.status_code == 422

    @pytest.mark.parametrize("endpoint", ["/api/v1/scan/url", "/api/v1/url/scan"])
    def test_input_validation_dangerous_scheme(self, endpoint):
        """Disallowed scheme should be rejected with HTTP 422."""
        response = client.post(endpoint, json={"url": "javascript:alert(1)"})
        assert response.status_code == 422

    def test_scan_registers_in_history(self):
        """Scans performed via URL endpoints must be logged into session audit history."""
        test_url = "https://tinyurl.com/session-history-check-unique"
        response = client.post("/api/v1/scan/url", json={"url": test_url})
        assert response.status_code == 200
        
        hist_resp = client.get("/api/v1/history")
        assert hist_resp.status_code == 200
        hist_data = hist_resp.json()
        targets = [s["target"] for s in hist_data["scans"]]
        assert test_url in targets

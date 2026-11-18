"""Tests for CyberShield Audit History Module (SQLite persistence, filtering, get by ID, delete)."""

import pytest
from fastapi.testclient import TestClient

from app.main import app, history_repo, record_scan_event, SCAN_HISTORY
from app.services.history_service import HistoryRepository

client = TestClient(app)


# ---------------------------------------------------------------------------
# Direct Repository Unit Tests
# ---------------------------------------------------------------------------


def test_history_repository_direct_crud(tmp_path):
    """Direct unit tests for SQLite HistoryRepository operations."""
    db_file = str(tmp_path / "test_audit.db")
    repo = HistoryRepository(db_path=db_file)

    # 1. Initially empty
    assert repo.count() == 0
    assert len(repo.get_all()) == 0

    # 2. Record items
    rec1 = repo.record_scan(
        scan_id="test-scan-001",
        scan_type="URL",
        target="https://example.com",
        risk_score=0,
        classification="Safe",
        summary="Risk Score: 0/100 (Safe)",
        status_badge="safe",
        details={"scanned_url": "https://example.com"},
    )
    rec2 = repo.record_scan(
        scan_id="test-scan-002",
        scan_type="SMS",
        target="Win Rs.50000 lottery now!",
        risk_score=85,
        classification="Malicious",
        summary="Risk Score: 85/100 (Malicious)",
        status_badge="danger",
        details={"threat_categories": ["LotteryScam"]},
    )
    rec3 = repo.record_scan(
        scan_id="test-scan-003",
        scan_type="APK",
        target="banking_malware.apk",
        risk_score=70,
        classification="High Risk",
        summary="Risk Score: 70/100 (High Risk)",
        status_badge="danger",
        details={"package_name": "com.fraud.bank"},
    )

    # 3. Counts & Retrieval
    assert repo.count() == 3
    all_scans = repo.get_all()
    assert len(all_scans) == 3

    # 4. Filter by scan_type
    url_scans = repo.get_all(scan_type="URL")
    assert len(url_scans) == 1
    assert url_scans[0]["id"] == "test-scan-001"

    # 5. Filter by classification
    malicious_scans = repo.get_all(classification="Malicious")
    assert len(malicious_scans) == 1
    assert malicious_scans[0]["id"] == "test-scan-002"

    # 6. Get by ID
    found = repo.get_by_id("test-scan-002")
    assert found is not None
    assert found["scan_type"] == "SMS"
    assert found["risk_score"] == 85
    assert found["details"]["threat_categories"] == ["LotteryScam"]

    not_found = repo.get_by_id("non-existent-id")
    assert not_found is None

    # 7. Delete by ID
    deleted = repo.delete_by_id("test-scan-001")
    assert deleted is True
    assert repo.count() == 2
    assert repo.get_by_id("test-scan-001") is None

    delete_again = repo.delete_by_id("test-scan-001")
    assert delete_again is False


# ---------------------------------------------------------------------------
# API Integration Tests
# ---------------------------------------------------------------------------


def test_api_history_get_all():
    """GET /api/v1/history returns 200 with required schema fields."""
    response = client.get("/api/v1/history")
    assert response.status_code == 200
    data = response.json()

    assert "total_count" in data
    assert "filtered_count" in data
    assert "scans" in data
    assert isinstance(data["scans"], list)


def test_api_history_records_url_scan_details():
    """Scanning a URL should create an audit log with risk_score and classification."""
    scan_resp = client.post("/api/v1/url/scan", json={"url": "https://secure-login.test-bank.com"})
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()

    history_resp = client.get("/api/v1/history?limit=1")
    assert history_resp.status_code == 200
    data = history_resp.json()

    assert data["total_count"] >= 1
    latest = data["scans"][0]
    assert latest["scan_type"] == "URL"
    assert "secure-login.test-bank.com" in latest["target"]
    assert latest["risk_score"] == scan_data["risk_score"]
    assert latest["classification"] == scan_data["classification"]


def test_api_history_filtering_by_scan_type():
    """Filtering by scan_type returns only matching records."""
    # Ensure there's at least an SMS scan
    client.post("/api/v1/sms/scan", json={"message": "Urgent! Account blocked. Call 9876543210"})

    resp = client.get("/api/v1/history?scan_type=SMS")
    assert resp.status_code == 200
    data = resp.json()

    for item in data["scans"]:
        assert item["scan_type"] == "SMS"


def test_api_history_filtering_by_classification():
    """Filtering by classification returns only matching records."""
    resp = client.get("/api/v1/history?classification=Safe")
    assert resp.status_code == 200
    data = resp.json()

    for item in data["scans"]:
        assert item["classification"].lower() == "safe"


def test_api_history_get_detail_success():
    """GET /api/v1/history/{scan_id} returns full record for an existing scan."""
    # First get latest scan ID from history
    list_resp = client.get("/api/v1/history?limit=1")
    assert list_resp.status_code == 200
    scans = list_resp.json()["scans"]
    assert len(scans) > 0
    target_id = scans[0]["id"]

    detail_resp = client.get(f"/api/v1/history/{target_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()

    assert detail["id"] == target_id
    assert detail["scan_id"] == target_id
    assert "scan_type" in detail
    assert "target" in detail
    assert "risk_score" in detail
    assert "classification" in detail
    assert "timestamp" in detail
    assert "details" in detail


def test_api_history_get_detail_not_found():
    """GET /api/v1/history/{scan_id} with invalid ID returns 404."""
    response = client.get("/api/v1/history/invalid-non-existent-scan-id")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_history_delete_success():
    """DELETE /api/v1/history/{scan_id} deletes the record from database and cache."""
    # Create an event to delete
    event = record_scan_event(
        scan_type="URL",
        target="https://temporary-delete-test.example.com",
        summary="Risk Score: 0/100 (Safe)",
        status_badge="safe",
        risk_score=0,
        classification="Safe",
    )
    scan_id = event["id"]

    # Verify exists
    assert client.get(f"/api/v1/history/{scan_id}").status_code == 200

    # Delete
    del_resp = client.delete(f"/api/v1/history/{scan_id}")
    assert del_resp.status_code == 200
    del_data = del_resp.json()
    assert del_data["status"] == "deleted"
    assert del_data["scan_id"] == scan_id

    # Verify no longer exists
    assert client.get(f"/api/v1/history/{scan_id}").status_code == 404


def test_api_history_delete_not_found():
    """DELETE /api/v1/history/{scan_id} with non-existent ID returns 404."""
    response = client.delete("/api/v1/history/unknown-missing-id")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


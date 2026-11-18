"""Cloud deployment readiness tests for CyberShield FastAPI backend."""

import os
from fastapi.testclient import TestClient

from app.main import app
from app.services.history_service import HistoryRepository


def test_root_and_health_endpoints_return_security_headers():
    client = TestClient(app)

    root_resp = client.get("/")
    assert root_resp.status_code == 200
    body = root_resp.json()
    assert body["service"] == "CyberShield API"
    assert body["status"] == "online"
    assert body["health"] == "/health"

    # Verify defensive HTTP security headers attached by middleware
    assert root_resp.headers.get("x-content-type-options") == "nosniff"
    assert root_resp.headers.get("x-frame-options") == "DENY"
    assert "max-age=" in (root_resp.headers.get("strict-transport-security") or "")

    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"


def test_history_repository_honors_cybershield_data_dir(tmp_path, monkeypatch):
    cloud_data_dir = tmp_path / "cloud_volume"
    monkeypatch.setenv("CYBERSHIELD_DATA_DIR", str(cloud_data_dir))
    monkeypatch.delenv("CYBERSHIELD_DB_PATH", raising=False)

    repo = HistoryRepository()
    assert os.path.dirname(repo.db_path) == str(cloud_data_dir)
    assert os.path.exists(repo.db_path)


def test_deployment_artifacts_exist_without_hardcoded_secrets():
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_root = os.path.dirname(backend_dir)

    required_files = [
        os.path.join(backend_dir, "Dockerfile"),
        os.path.join(backend_dir, ".dockerignore"),
        os.path.join(backend_dir, "railway.json"),
        os.path.join(backend_dir, "Procfile"),
        os.path.join(backend_dir, "runtime.txt"),
        os.path.join(backend_dir, ".env.example"),
        os.path.join(backend_dir, "requirements.txt"),
        os.path.join(repo_root, "render.yaml"),
    ]
    for path in required_files:
        assert os.path.exists(path), f"Missing cloud deployment file: {path}"
        content = open(path, encoding="utf-8").read()
        assert "sk-or-v1-" not in content, f"Secret leaked in {path}!"
        assert "AIzaSy" not in content, f"API key leaked in {path}!"

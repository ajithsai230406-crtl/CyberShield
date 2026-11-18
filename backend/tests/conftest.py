"""Pytest fixtures for CyberShield test suite."""

import pytest
from app.main import app
from app.auth import get_current_user, AuthenticatedUser


@pytest.fixture(autouse=True)
def default_auth_override():
    """
    By default, authenticate requests in scanner & detection unit tests with a test user.
    Dedicated auth tests in test_firebase_auth.py explicitly override or clear this.
    """
    mock_user = AuthenticatedUser(
        uid="test-suite-user-001",
        email="tester@cybershield.dev",
        email_verified=True,
        claims={"role": "tester", "aud": "cybersheild-30cc7"},
    )
    app.dependency_overrides[get_current_user] = lambda: mock_user
    yield mock_user
    app.dependency_overrides.pop(get_current_user, None)


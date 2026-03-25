"""
Shared pytest fixtures for FTL API integration tests.
"""

import pytest
import requests


FTL_URL = "http://127.0.0.1"


@pytest.fixture(scope="session")
def ftl_url():
    """Base URL for the FTL API."""
    return FTL_URL


@pytest.fixture(scope="session")
def api_session():
    """Shared requests session for the entire test run.

    Verifies FTL is reachable (accepts both 200 and 401 — the latter
    means a password is set, which is fine for read-only stats tests).
    """
    session = requests.Session()
    session.headers["Accept"] = "application/json"
    # Verify FTL is running
    try:
        r = session.get(f"{FTL_URL}/api/auth", timeout=5)
        if r.status_code not in (200, 401):
            r.raise_for_status()
    except requests.ConnectionError:
        pytest.skip("FTL is not running at " + FTL_URL)
    return session

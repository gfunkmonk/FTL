"""
Pi-hole FTL API integration tests -- authentication workflow.

These tests are ORDER-DEPENDENT: the application password must be created
and set before the regular password tests can run.  Method names are
numbered (test_01_ ... test_07_) to guarantee deterministic ordering
inside the single class.

Usage:
    pytest test/api/test_auth.py -v
"""

import base64
import json
import os
import re
import subprocess
import stat

import pytest
import requests

FTL_URL = "http://127.0.0.1"


class TestAuthWorkflow:
    """Order-dependent authentication tests.

    01-04: Application password creation and usage
    05: Setting a regular password via API
    06: Incorrect password is rejected
    07: Correct password is accepted
    """

    # ---- shared state across ordered tests ----
    _app_password = None
    _app_pwhash = None

    # -- 01: no password set => session valid without login --

    def test_01_no_password_means_session_valid(self):
        """API authorization (without password): No login required."""
        r = requests.get(f"{FTL_URL}/api/auth", timeout=5)
        assert r.status_code == 200
        data = r.json()
        session = data["session"]
        assert session["valid"] is True
        assert session["totp"] is False
        assert session["sid"] is None
        assert session["validity"] == -1
        assert session["message"] == "no password set"

    # -- 02: create application password --

    def test_02_create_app_password(self):
        """Create application password and extract password + hash."""
        r = requests.get(f"{FTL_URL}/api/auth/app", timeout=5)
        assert r.status_code == 200
        data = r.json()

        assert "app" in data
        assert "password" in data["app"]
        assert "hash" in data["app"]

        # Store for subsequent tests
        TestAuthWorkflow._app_password = data["app"]["password"]
        TestAuthWorkflow._app_pwhash = data["app"]["hash"]

        assert len(TestAuthWorkflow._app_password) > 0
        assert len(TestAuthWorkflow._app_pwhash) > 0

    # -- 03: set application password hash via API --

    def test_03_set_app_password_hash(self):
        """Set app password hash via PATCH /api/config."""
        assert TestAuthWorkflow._app_pwhash is not None, \
            "test_02 must run first to generate the hash"

        pwhash = TestAuthWorkflow._app_pwhash
        payload = {
            "config": {
                "webserver": {
                    "api": {
                        "app_pwhash": pwhash
                    }
                }
            }
        }
        r = requests.patch(
            f"{FTL_URL}/api/config/webserver/api/app_pwhash",
            json=payload,
            timeout=20,
        )
        assert r.status_code == 200
        data = r.json()

        assert "config" in data
        assert data["config"]["webserver"]["api"]["app_pwhash"] == pwhash

    # -- 04: login with application password succeeds --

    def test_04_login_with_app_password(self):
        """Login using the application password is successful."""
        assert TestAuthWorkflow._app_password is not None, \
            "test_02 must run first to generate the password"

        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": TestAuthWorkflow._app_password},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["session"]["valid"] is True

    # -- 04b: CLI password file is correct --

    def test_04b_cli_password_file(self):
        """CLI password file (/etc/pihole/cli_pw) is well-formed."""
        cli_pw_path = "/etc/pihole/cli_pw"

        # File must exist
        assert os.path.isfile(cli_pw_path), f"{cli_pw_path} does not exist"

        # Read raw bytes to check for trailing newline
        with open(cli_pw_path, "rb") as f:
            raw = f.read()

        # Must be non-empty
        assert len(raw) > 0, "cli_pw file is empty"

        # Content as string (strip only trailing newline for line-check)
        content = raw.decode("utf-8")
        lines = content.splitlines()

        # Exactly one line
        assert len(lines) == 1, \
            f"Expected 1 line, got {len(lines)}"

        # The line must be valid base64
        try:
            base64.b64decode(lines[0], validate=True)
        except Exception as exc:
            pytest.fail(f"cli_pw content is not valid base64: {exc}")

        # Permission should be 640
        mode = stat.S_IMODE(os.stat(cli_pw_path).st_mode)
        assert mode == 0o640, \
            f"Expected permissions 0640, got {oct(mode)}"

    # -- 05: set a regular password --

    def test_05_set_password(self):
        """API authorization: Setting password via API (password: ABC)."""
        payload = {
            "config": {
                "webserver": {
                    "api": {
                        "password": "ABC"
                    }
                }
            }
        }
        r = requests.patch(
            f"{FTL_URL}/api/config/webserver/api/password",
            json=payload,
            timeout=20,
        )
        assert r.status_code == 200
        data = r.json()

        # Password should be masked in the response
        assert data["config"]["webserver"]["api"]["password"] == "********"

    # -- 06: incorrect password is rejected --

    def test_06_incorrect_password_rejected(self):
        """API authorization (with password): Incorrect password is rejected."""
        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": "XXX"},
            timeout=5,
        )
        assert r.status_code == 401
        data = r.json()
        session = data["session"]
        assert session["valid"] is False
        assert session["totp"] is False
        assert session["sid"] is None
        assert session["validity"] == -1
        assert session["message"] == "password incorrect"

    # -- 07: correct password is accepted --

    def test_07_correct_password_accepted(self):
        """API authorization (with password): Correct password is accepted."""
        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": "ABC"},
            timeout=5,
        )
        assert r.status_code == 200
        data = r.json()
        session = data["session"]
        assert session["valid"] is True
        assert session["totp"] is False
        assert session["validity"] == 300
        assert session["message"] == "password correct"
        # SID and CSRF should be non-empty strings
        assert isinstance(session["sid"], str) and len(session["sid"]) > 0
        assert isinstance(session["csrf"], str) and len(session["csrf"]) > 0

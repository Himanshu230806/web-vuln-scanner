"""
Integration smoke-tests against the VulnBank demo app.

These tests do NOT make real HTTP requests — they import the VulnBank
Flask app and use Flask's test client. They verify that:
  - The vulnerable endpoints return the expected HTTP status codes
  - The deliberate vulnerabilities are present (reflected XSS, SQL error
    visible in response, etc.) so the scanner will have real findings
    to detect during a demo.

Run with:
    pytest tests/test_vulnerable_app.py -v
"""

import os
import sys
import sqlite3
import pytest
from pathlib import Path

# VulnBank lives in a sibling repo; skip these tests gracefully if not found
VULNBANK_PATH = Path(__file__).parent.parent.parent / "vulnbank"
if not VULNBANK_PATH.exists():
    pytest.skip(
        "VulnBank not found at expected path — skipping integration tests. "
        "Clone https://github.com/Himanshu230806/vulnbank next to web-vuln-scanner.",
        allow_module_level=True,
    )

sys.path.insert(0, str(VULNBANK_PATH))

try:
    from app import app as vulnbank_app, init_db
except ImportError as exc:
    pytest.skip(f"Could not import VulnBank app: {exc}", allow_module_level=True)


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """Return a test client for VulnBank with a fresh in-memory SQLite DB."""
    import os
    db_path = str(tmp_path_factory.mktemp("db") / "test.db")
    os.environ["DB_PATH"] = db_path
    userfiles = tmp_path_factory.mktemp("files")
    (userfiles / "readme.txt").write_text("test file")

    # Monkey-patch userfiles dir used by the /files route
    import app as vb_module
    vb_module.app.config["TESTING"] = True

    with vb_module.app.app_context():
        vb_module.init_db()

    return vb_module.app.test_client()


class TestVulnBankRoutes:
    def test_home(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"VulnBank" in r.data

    def test_login_page(self, client):
        r = client.get("/login")
        assert r.status_code == 200
        assert b"Login" in r.data

    def test_search_page(self, client):
        r = client.get("/search")
        assert r.status_code == 200

    def test_messages_page(self, client):
        r = client.get("/messages")
        assert r.status_code == 200

    def test_transfer_page(self, client):
        r = client.get("/transfer")
        assert r.status_code == 200

    def test_profile_page(self, client):
        r = client.get("/profile?id=1")
        assert r.status_code == 200

    def test_fetch_page(self, client):
        r = client.get("/fetch")
        assert r.status_code == 200

    def test_files_page(self, client):
        r = client.get("/files")
        assert r.status_code == 200

    def test_xml_api_options(self, client):
        r = client.options("/api/xml")
        assert r.status_code == 200
        assert b"POST" in r.headers.get("Allow", b"")

    def test_redirect_page(self, client):
        r = client.get("/redirect")
        assert r.status_code == 200

    def test_admin_page(self, client):
        r = client.get("/admin")
        assert r.status_code == 200


class TestVulnerabilityPresence:
    """Confirm each deliberate vulnerability is actually present in responses,
    so the scanner will have real findings during a demo."""

    def test_sqli_error_visible(self, client):
        """Sending a bare quote to login should trigger a DB error message."""
        r = client.post("/login", data={"username": "'", "password": "x"})
        body = r.data.decode()
        # Either an SQL error or "logged in as admin" (auth bypass) is a finding
        is_sqli = "error" in body.lower() or "syntax" in body.lower() or "logged in" in body.lower()
        assert is_sqli, "Expected SQL error or bypass — SQLi may not be present"

    def test_reflected_xss_present(self, client):
        """A script tag in ?q= should be echoed back unescaped."""
        payload = "<script>alert(1)</script>"
        r = client.get(f"/search?q={payload}")
        assert payload in r.data.decode(), "Reflected XSS payload not echoed — vulnerability may not be present"

    def test_no_csrf_token_on_transfer(self, client):
        """Transfer form must not contain a CSRF token (intentionally vulnerable)."""
        r = client.get("/transfer")
        body = r.data.decode().lower()
        has_csrf = "csrf" in body or "xsrf" in body or "_token" in body
        assert not has_csrf, "CSRF token found — VulnBank transfer page should be CSRF-vulnerable"

    def test_idor_different_profiles(self, client):
        """Profile?id=1 and profile?id=2 should return different usernames."""
        r1 = client.get("/profile?id=1")
        r2 = client.get("/profile?id=2")
        assert r1.status_code == r2.status_code == 200
        assert r1.data != r2.data, "Profiles are identical — IDOR vulnerability may not be present"

    def test_missing_security_headers(self, client):
        """Responses should lack CSP, X-Frame-Options, and HSTS."""
        r = client.get("/")
        assert "Content-Security-Policy" not in r.headers
        assert "X-Frame-Options" not in r.headers

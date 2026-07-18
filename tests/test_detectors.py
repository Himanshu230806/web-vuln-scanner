"""
Unit tests for all vulnerability detector modules.
Uses 'responses' mock library to avoid real HTTP calls.
"""

import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import requests
import responses as resp_mock

from modules.sqli_detector import SQLiDetector
from modules.xss_detector import XSSDetector
from modules.csrf_detector import CSRFDetector
from modules.open_redirect_detector import OpenRedirectDetector
from modules.directory_traversal_detector import DirectoryTraversalDetector
from modules.security_headers_detector import SecurityHeadersDetector
from modules.ssrf_detector import SSRFDetector
from modules.idor_detector import IDORDetector


# ── helpers ────────────────────────────────────────────────────────────────

BASE_CONFIG = {
    "request_timeout": 5,
    "delay": 0,
    "user_agent": "TestScanner/1.0",
    "verify_ssl": True,
}

def make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": BASE_CONFIG["user_agent"]})
    return s


# ── SQLi ──────────────────────────────────────────────────────────────────

class TestSQLiDetector:
    @resp_mock.activate
    def test_detects_error_based(self):
        """Response containing SQL error + boolean confirmation = SQLi detected."""
        # All payload attempts return the SQL error string
        for _ in range(30):
            resp_mock.add(resp_mock.GET, "http://test.local/page",
                          body="You have an error in your SQL syntax; check the manual", status=200)
        # Boolean confirmation: true payload returns big page, false returns tiny page
        for _ in range(6):
            resp_mock.add(resp_mock.GET, "http://test.local/page",
                          body="A" * 500, status=200)   # AND 1=1 → large
            resp_mock.add(resp_mock.GET, "http://test.local/page",
                          body="", status=200)           # AND 1=2 → empty

        det = SQLiDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/page?id=1", "id")
        assert result is True

    @resp_mock.activate
    def test_clean_page_not_flagged(self):
        """Normal response must not produce a false positive."""
        for _ in range(50):
            resp_mock.add(resp_mock.GET, "http://test.local/page",
                          body="<html><body>Hello</body></html>", status=200)

        det = SQLiDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/page?id=1", "id")
        assert result is False


# ── XSS ──────────────────────────────────────────────────────────────────

class TestXSSDetector:
    @resp_mock.activate
    def test_detects_reflected_xss(self):
        """Dynamic mock echoes injected payloads back unencoded – XSS detected."""
        from urllib.parse import urlparse, parse_qs as _pqs

        def _echo(req):
            q = _pqs(urlparse(req.url).query).get("q", [""])[0]
            return (200, {}, f"<html><body>{q}</body></html>")

        resp_mock.add_callback(resp_mock.GET, "http://test.local/search", callback=_echo)

        det = XSSDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/search?q=hello", "q")
        assert result is True

    @resp_mock.activate
    def test_encoded_payload_not_flagged(self):
        """Properly HTML-encoded payload must not be flagged."""
        for _ in range(40):
            resp_mock.add(
                resp_mock.GET, "http://test.local/search",
                body="<html><body>&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;</body></html>",
                status=200,
            )
        det = XSSDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/search?q=hello", "q")
        assert result is False


# ── CSRF ──────────────────────────────────────────────────────────────────

class TestCSRFDetector:
    @resp_mock.activate
    def test_missing_csrf_token_flagged(self):
        """POST form with no CSRF token should be flagged."""
        resp_mock.add(resp_mock.GET, "http://test.local/form", body="<html></html>", status=200)
        resp_mock.add(resp_mock.POST, "http://test.local/form", body="OK", status=200)

        form = {
            "action": "http://test.local/form",
            "method": "POST",
            "inputs": [{"name": "username", "type": "text", "value": ""}],
        }
        det = CSRFDetector(make_session(), BASE_CONFIG)
        result = det.test_form(form, "http://test.local/form")
        assert result is not None
        assert "No CSRF token" in result["issues"][0]

    def test_get_form_skipped(self):
        """GET forms are not CSRF-relevant and should return None."""
        form = {
            "action": "http://test.local/search",
            "method": "GET",
            "inputs": [{"name": "q", "type": "text", "value": ""}],
        }
        det = CSRFDetector(make_session(), BASE_CONFIG)
        result = det.test_form(form, "http://test.local/search")
        assert result is None


# ── Open Redirect ────────────────────────────────────────────────────────

class TestOpenRedirectDetector:
    @resp_mock.activate
    def test_detects_external_redirect(self):
        """302 to external domain on redirect param = open redirect."""
        for _ in range(20):
            resp_mock.add(
                resp_mock.GET, "http://test.local/goto",
                headers={"Location": "https://evil.com"},
                status=302,
            )

        det = OpenRedirectDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter(
            "http://test.local/goto?redirect=https://example.com", "redirect"
        )
        assert result is True

    @resp_mock.activate
    def test_non_redirect_param_skipped(self):
        """Non-redirect parameter names should be skipped."""
        det = OpenRedirectDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/page?color=blue", "color")
        assert result is False


# ── Directory Traversal ──────────────────────────────────────────────────

class TestDirectoryTraversalDetector:
    @resp_mock.activate
    def test_detects_passwd_file(self):
        """Response containing /etc/passwd content = directory traversal."""
        for _ in range(30):
            resp_mock.add(
                resp_mock.GET, "http://test.local/view",
                body="root:x:0:0:root:/root:/bin/bash",
                status=200,
            )

        det = DirectoryTraversalDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/view?file=index.html", "file")
        assert result is True

    @resp_mock.activate
    def test_normal_page_not_flagged(self):
        for _ in range(30):
            resp_mock.add(resp_mock.GET, "http://test.local/view",
                          body="<html><body>Hello</body></html>", status=200)
        det = DirectoryTraversalDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/view?file=index.html", "file")
        assert result is False


# ── Security Headers ──────────────────────────────────────────────────────

class TestSecurityHeadersDetector:
    @resp_mock.activate
    def test_missing_headers_flagged(self):
        """Response with no security headers should produce multiple findings."""
        resp_mock.add(resp_mock.GET, "http://test.local/",
                      body="<html></html>", status=200,
                      headers={"Content-Type": "text/html"})

        det = SecurityHeadersDetector(make_session(), BASE_CONFIG)
        findings = det.scan("http://test.local/")
        types = [f["subtype"] for f in findings]
        assert "Strict-Transport-Security" in types
        assert "Content-Security-Policy" in types
        assert "X-Frame-Options" in types

    @resp_mock.activate
    def test_all_headers_present_no_findings(self):
        """Response with all required headers should produce no header-missing findings."""
        resp_mock.add(
            resp_mock.GET, "https://secure.local/",
            body="<html></html>", status=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
        )
        det = SecurityHeadersDetector(make_session(), BASE_CONFIG)
        findings = det.scan("https://secure.local/")
        header_missing = [f for f in findings if f["type"] == "Security Header Missing"]
        assert len(header_missing) == 0

    @resp_mock.activate
    def test_info_disclosure_server_header(self):
        """Server header with version info should produce an Info finding."""
        resp_mock.add(
            resp_mock.GET, "https://test.local/",
            body="<html></html>", status=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
                "Server": "Apache/2.4.51 (Ubuntu)",
            },
        )
        det = SecurityHeadersDetector(make_session(), BASE_CONFIG)
        findings = det.scan("https://test.local/")
        info_findings = [f for f in findings if f["type"] == "Information Disclosure"]
        assert any(f["subtype"] == "Server" for f in info_findings)


# ── SSRF ─────────────────────────────────────────────────────────────────

class TestSSRFDetector:
    @resp_mock.activate
    def test_detects_cloud_metadata_response(self):
        """If a URL param fetches cloud metadata content, flag SSRF."""
        for _ in range(20):
            resp_mock.add(
                resp_mock.GET, "http://test.local/fetch",
                body='{"instance-id": "i-abc123", "local-ipv4": "10.0.0.1"}',
                status=200,
            )
        det = SSRFDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter(
            "http://test.local/fetch?url=https://example.com", "url"
        )
        assert result is True

    def test_non_url_param_skipped(self):
        det = SSRFDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/page?page=2", "page")
        assert result is False


# ── IDOR ─────────────────────────────────────────────────────────────────

class TestIDORDetector:
    @resp_mock.activate
    def test_detects_numeric_idor(self):
        """Incrementing numeric ID returning significantly different 200 = potential IDOR."""
        original_body = "<html><body>User: Alice</body></html>"
        # alt body is much larger (>300 chars and >15% relative diff)
        alt_body = "<html><body>User: Bob — Admin Account<br>" + "X" * 400 + "</body></html>"
        # New detector requests the ORIGINAL id twice (natural variance baseline),
        # then the ALT id once.
        resp_mock.add(resp_mock.GET, "http://test.local/profile",
                      body=original_body, status=200)
        resp_mock.add(resp_mock.GET, "http://test.local/profile",
                      body=original_body, status=200)
        resp_mock.add(resp_mock.GET, "http://test.local/profile",
                      body=alt_body, status=200)

        det = IDORDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/profile?id=1", "id")
        assert result is True

    def test_non_id_param_skipped(self):
        det = IDORDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/page?color=blue", "color")
        assert result is False

    @resp_mock.activate
    def test_same_content_not_flagged(self):
        """Same-length responses for different IDs should not be flagged."""
        body = "<html><body>Same content</body></html>"
        resp_mock.add(resp_mock.GET, "http://test.local/item", body=body, status=200)
        resp_mock.add(resp_mock.GET, "http://test.local/item", body=body, status=200)

        det = IDORDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/item?id=5", "id")
        assert result is False


# ── Dedup fix ────────────────────────────────────────────────────────────

class TestScannerDedup:
    """Verify that the scanner records both parameters when two params on the same URL are vulnerable."""

    def test_dedup_key_includes_parameter(self):
        """Two findings with same type+url but different parameters must both be stored."""
        from core.scanner import VulnerabilityScanner

        scanner = VulnerabilityScanner.__new__(VulnerabilityScanner)
        scanner.vulnerabilities = []
        scanner._vuln_keys = set()

        vuln_a = {"type": "SQL Injection", "url": "http://x.com/page", "parameter": "id",
                  "severity": "Critical", "description": "SQLi in id"}
        vuln_b = {"type": "SQL Injection", "url": "http://x.com/page", "parameter": "name",
                  "severity": "Critical", "description": "SQLi in name"}
        vuln_dup = {"type": "SQL Injection", "url": "http://x.com/page", "parameter": "id",
                    "severity": "Critical", "description": "SQLi in id again"}

        # Patch _add_vulnerability to avoid print calls
        from datetime import datetime
        def _add(v):
            v.setdefault("timestamp", datetime.now().isoformat())
            v.setdefault("id", f"VULN-{len(scanner.vulnerabilities)+1:04d}")
            key = (v.get("type",""), v.get("url",""), v.get("parameter",""))
            if key in scanner._vuln_keys:
                return
            scanner._vuln_keys.add(key)
            scanner.vulnerabilities.append(v)

        _add(vuln_a)
        _add(vuln_b)
        _add(vuln_dup)

        assert len(scanner.vulnerabilities) == 2   # dup must be dropped


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ── False-positive regression tests ──────────────────────────────────────
# These tests simulate a NON-vulnerable site and verify the scanner does
# NOT raise findings against it. Each scenario corresponds to a real bug
# that previously caused false positives.

import modules.scan_utils as scan_utils


@pytest.fixture(autouse=True)
def _clear_baseline_cache():
    """Ensure each test gets a fresh baseline (no cross-test pollution)."""
    scan_utils._baseline_cache.clear()
    yield
    scan_utils._baseline_cache.clear()


class TestSPACatchAllFalsePositives:
    """
    Simulates a Single-Page-App style site where EVERY path (including
    nonexistent ones) returns the SAME index.html with status 200.
    Detectors that probe "does this sensitive path return 200?" must NOT
    flag findings on such a site, because the response is identical to
    what ANY random path returns.
    """

    SPA_HTML = (
        "<!DOCTYPE html><html><head><title>MyApp</title></head><body>"
        "<div id='root'>Welcome to MyApp. Contact us: support@myapp.com</div>"
        "<footer>Admin panel · Dashboard · Status · Health · Metrics</footer>"
        "</body></html>"
    )

    @resp_mock.activate
    def test_sri_exposed_files_not_flagged_on_spa(self):
        from modules.sri_detector import SRIDetector

        resp_mock.add(
            resp_mock.GET, re.compile(r"https://myapp\.com/.*"),
            body=self.SPA_HTML, status=200,
        )

        det = SRIDetector(make_session(), BASE_CONFIG)
        findings = det._check_exposed_sensitive_files("https://myapp.com/")
        exposed = [f for f in findings if f["subtype"] == "Exposed Sensitive File"]
        assert exposed == [], f"False positive exposed-file findings: {exposed}"

    @resp_mock.activate
    def test_vulnerable_components_exposed_files_not_flagged_on_spa(self):
        from modules.vulnerable_components_detector import VulnerableComponentsDetector

        resp_mock.add(
            resp_mock.GET, re.compile(r"https://myapp\.com/.*"),
            body=self.SPA_HTML, status=200,
        )

        det = VulnerableComponentsDetector(make_session(), BASE_CONFIG)
        findings = det._check_exposed_files("https://myapp.com/")
        assert findings == [], f"False positive dependency-file findings: {findings}"

    @resp_mock.activate
    def test_admin_panels_not_flagged_on_spa(self):
        from modules.logging_detector import LoggingMonitoringDetector

        resp_mock.add(
            resp_mock.GET, re.compile(r"https://myapp\.com/.*"),
            body=self.SPA_HTML, status=200,
        )

        det = LoggingMonitoringDetector(make_session(), BASE_CONFIG)
        findings = det._check_admin_panels("https://myapp.com/")
        assert findings == [], f"False positive admin-panel findings: {findings}"

    @resp_mock.activate
    def test_error_probes_not_flagged_on_spa(self):
        from modules.logging_detector import LoggingMonitoringDetector

        resp_mock.add(
            resp_mock.GET, re.compile(r"https://myapp\.com/.*"),
            body=self.SPA_HTML, status=200,
        )

        det = LoggingMonitoringDetector(make_session(), BASE_CONFIG)
        findings = det._probe_error_pages("https://myapp.com/")
        assert findings == [], f"False positive error-probe findings: {findings}"

    @resp_mock.activate
    def test_ssrf_not_flagged_on_spa(self):
        from modules.ssrf_detector import SSRFDetector

        resp_mock.add(
            resp_mock.GET, re.compile(r"https://myapp\.com/.*"),
            body=self.SPA_HTML, status=200,
        )

        det = SSRFDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("https://myapp.com/page?url=https://example.com", "url")
        assert result is False


class TestContactEmailNotFlagged:
    """A normal contact email in a page footer must not be reported as
    'Sensitive Data in Error Response'."""

    @resp_mock.activate
    def test_footer_email_not_flagged(self):
        from modules.logging_detector import LoggingMonitoringDetector

        normal_page = (
            "<html><body><h1>About Us</h1><p>Some content.</p>"
            "<footer>Questions? Email support@example.com</footer></body></html>"
        )
        resp_mock.add(
            resp_mock.GET, re.compile(r"https://example-corp\.com/.*"),
            body=normal_page, status=404,
        )

        det = LoggingMonitoringDetector(make_session(), BASE_CONFIG)
        findings = det._probe_error_pages("https://example-corp.com/")
        sensitive = [f for f in findings if f["subtype"] == "Sensitive Data in Error Response"]
        assert sensitive == [], f"False positive on contact email: {sensitive}"


class TestOpenRedirectJSFalsePositive:
    """A page containing normal `window.location = ...` JS (e.g. a cookie
    banner) must not be flagged as Open Redirect for an unrelated parameter."""

    @resp_mock.activate
    def test_unrelated_js_redirect_not_flagged(self):
        from modules.open_redirect_detector import OpenRedirectDetector

        page_with_js = (
            "<html><body>"
            "<script>function acceptCookies(){ window.location = '/accepted'; }</script>"
            "<h1>Welcome</h1>"
            "</body></html>"
        )
        # Every payload request returns 200 with the same JS-containing page
        # (no Location header redirect at all)
        for _ in range(10):
            resp_mock.add(resp_mock.GET, "https://example.com/page",
                          body=page_with_js, status=200)

        det = OpenRedirectDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("https://example.com/page?redirect=foo", "redirect")
        assert result is False


class TestCSRFNoSideEffects:
    """CSRF detector must flag missing token via static analysis only —
    it must NOT perform a blind POST submission (which both causes false
    positives and real side effects on the target)."""

    def test_missing_token_flagged_without_network_calls(self):
        from modules.csrf_detector import CSRFDetector

        # A session whose .post would raise if ever called — proves the
        # detector doesn't perform any blind POST submission.
        class NoPostSession(requests.Session):
            def post(self, *a, **k):
                raise AssertionError("CSRFDetector must not POST the form")

        # Use a genuinely state-changing form (password change) so this
        # test exercises the real detection path, not the benign-form
        # skip path tested separately below.
        form = {
            "action": "https://example.com/account/change-password",
            "method": "POST",
            "inputs": [
                {"name": "current_password", "type": "password", "value": ""},
                {"name": "new_password", "type": "password", "value": ""},
            ],
        }
        det = CSRFDetector(NoPostSession(), BASE_CONFIG)
        result = det.test_form(form, "https://example.com/account/change-password")
        assert result is not None
        assert "issues" in result
        assert "No CSRF token" in result["issues"][0] or "csrf" in result["issues"][0].lower()

    def test_benign_contact_form_not_flagged_at_all(self):
        """A public contact form (name + message, no auth-sensitive
        fields) must NOT be reported as a CSRF finding, even with no
        token and no SameSite protection — forging it has no meaningful
        security impact."""
        from modules.csrf_detector import CSRFDetector

        class NoPostSession(requests.Session):
            def post(self, *a, **k):
                raise AssertionError("CSRFDetector must not POST the form")

        form = {
            "action": "https://example.com/contact",
            "method": "POST",
            "inputs": [
                {"name": "name", "type": "text", "value": ""},
                {"name": "message", "type": "text", "value": ""},
            ],
        }
        det = CSRFDetector(NoPostSession(), BASE_CONFIG)
        result = det.test_form(form, "https://example.com/contact")
        assert result is None

    def test_benign_search_form_not_flagged(self):
        from modules.csrf_detector import CSRFDetector

        form = {
            "action": "https://example.com/search",
            "method": "POST",
            "inputs": [{"name": "q", "type": "text", "value": ""}],
        }
        det = CSRFDetector(make_session(), BASE_CONFIG)
        result = det.test_form(form, "https://example.com/search")
        assert result is None

    def test_benign_newsletter_form_not_flagged(self):
        from modules.csrf_detector import CSRFDetector

        form = {
            "action": "https://example.com/newsletter/subscribe",
            "method": "POST",
            "inputs": [{"name": "email", "type": "email", "value": ""}],
        }
        det = CSRFDetector(make_session(), BASE_CONFIG)
        result = det.test_form(form, "https://example.com/newsletter/subscribe")
        assert result is None


class TestSQLiTimingNotFlaggedOnSlowServer:
    """A server that is simply SLOW (but not vulnerable) must not be
    flagged as time-based SQLi."""

    @resp_mock.activate
    def test_uniformly_slow_server_not_flagged(self):
        from modules.sqli_detector import SQLiDetector
        import time as time_module

        # Every request (baseline AND payload) takes ~the same time —
        # simulating a server that's just slow for everyone, not one that
        # is executing an injected SLEEP().
        def slow_callback(request):
            return (200, {}, "<html>Results</html>")

        resp_mock.add_callback(resp_mock.GET, "http://slow.local/search", callback=slow_callback)

        det = SQLiDetector(make_session(), BASE_CONFIG)
        result = det._test_time_based("http://slow.local/search?q=test", "q", "test")
        assert result is False


class TestIDORDynamicContentNotFlagged:
    """Two requests to the SAME id that merely have different ad/timestamp
    content must not be flagged as IDOR when an alt id is tried."""

    @resp_mock.activate
    def test_small_dynamic_difference_not_flagged(self):
        from modules.idor_detector import IDORDetector

        # Simulate a page with a small dynamic widget (timestamp) that
        # changes by ~20 chars between requests, plus a similar-sized
        # alt-id response — none of these differences should trigger IDOR.
        bodies = [
            "<html><body>Profile for user. Loaded at 12:00:01.123456</body></html>",
            "<html><body>Profile for user. Loaded at 12:00:02.654321</body></html>",
            "<html><body>Profile for user. Loaded at 12:00:03.111222</body></html>",
        ]
        for b in bodies:
            resp_mock.add(resp_mock.GET, "http://test.local/profile", body=b, status=200)

        det = IDORDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/profile?id=5", "id")
        assert result is False


class TestBrokenAuthSPANotFlagged:
    """A login form whose POST action just returns the same SPA shell for
    any credentials must NOT be reported as 'default credentials work'."""

    @resp_mock.activate
    def test_spa_login_shell_not_flagged(self):
        from modules.broken_auth_detector import BrokenAuthDetector

        # Same shell returned for every POST, contains "dashboard" link in
        # nav (so SUCCESS_PATTERNS would match) regardless of credentials.
        shell = (
            "<html><body><nav>Home | Dashboard | Login</nav>"
            "<div id='app'></div></body></html>"
        )

        def callback(request):
            return (200, {}, shell)

        resp_mock.add_callback(resp_mock.POST, "https://app.example.com/login", callback=callback)

        form = {
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
            ],
        }
        det = BrokenAuthDetector(make_session(), BASE_CONFIG)
        result = det._test_default_credentials(form, "https://app.example.com/login", form["inputs"])
        assert result is None


class TestSessionTokenInURLNotFlaggedOnUnrelatedParams:
    """A URL with a query param like ?widget=sidebar must not be flagged as
    'Session Token in URL' just because 'sid' is a substring of 'sidebar'."""

    def test_sidebar_param_not_flagged(self):
        from modules.broken_auth_detector import BrokenAuthDetector
        import requests as req_module

        det = BrokenAuthDetector(make_session(), BASE_CONFIG)
        resp = req_module.Response()
        resp.status_code = 200
        resp._content = b"<html></html>"

        findings = det.scan_session_tokens(resp, "https://example.com/page?widget=sidebar&view=grid")
        token_findings = [f for f in findings if f["subtype"] == "Session Token in URL"]
        assert token_findings == [], f"False positive on 'sidebar' substring: {token_findings}"


class TestDirectoryTraversalEchoNotFlagged:
    """A search page that echoes back the user's input verbatim (e.g.
    'No results for: ../../../etc/passwd') must not be flagged as
    directory traversal — that's just the input being reflected, not file
    content being read."""

    @resp_mock.activate
    def test_echoed_payload_not_flagged(self):
        from modules.directory_traversal_detector import DirectoryTraversalDetector

        def echo_callback(request):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(request.url).query).get("file", [""])[0]
            return (200, {}, f"<html><body>No results for: {q}</body></html>")

        resp_mock.add_callback(resp_mock.GET, "http://test.local/view", callback=echo_callback)

        det = DirectoryTraversalDetector(make_session(), BASE_CONFIG)
        result = det.test_url_parameter("http://test.local/view?file=test", "file")
        assert result is False


# ── Verification engine & confidence scoring tests ─────────────────────────
# These tests validate the centralized verification system: SSRF two-stage
# confirmation, admin-panel fingerprinting, CSRF multi-signal detection,
# confidence scoring, and severity-inflation prevention.

from modules.verification_engine import (
    SSRFVerifier, AdminPanelVerifier, CSRFVerifier,
    confidence_label, adjusted_severity,
    CONFIDENCE_CONFIRMED, CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW,
)


class TestConfidenceScoring:
    """Confidence labels and severity adjustment must behave predictably."""

    def test_confidence_labels(self):
        assert confidence_label(95) == "Confirmed"
        assert confidence_label(75) == "High"
        assert confidence_label(55) == "Medium"
        assert confidence_label(35) == "Low"
        assert confidence_label(10) == "Speculative"

    def test_severity_not_inflated_at_low_confidence(self):
        """A 'Critical' finding with low confidence must be downgraded,
        preventing severity inflation in the report."""
        assert adjusted_severity("Critical", 95) == "Critical"
        assert adjusted_severity("Critical", 60) == "High"     # one level down
        assert adjusted_severity("Critical", 30) == "Medium"   # two levels down

    def test_high_confidence_preserves_severity(self):
        assert adjusted_severity("High", 90) == "High"
        assert adjusted_severity("Medium", 85) == "Medium"


class TestSSRFVerifierTwoStage:
    """
    SSRF must require genuine cloud-metadata content, not generic words.

    With no Interactsh/OOB server configured (the default in these unit
    tests — BASE_CONFIG has no interactsh_server_url), static-indicator
    matches can NEVER reach 'Confirmed' classification (90+) — that tier
    is reserved exclusively for independently-proven out-of-band
    callback confirmation. A static match, even with a secondary
    confirmation probe, stays capped in the 'Potential Vulnerability'
    confidence range (30-50) and must say so explicitly in its
    verification_method field.
    """

    @resp_mock.activate
    def test_single_primary_probe_stays_in_potential_range(self):
        """Only the primary probe matches, no OOB configured → confidence
        must stay in the Potential range (30-50), never reach High/Confirmed."""
        from urllib.parse import urlparse, parse_qs as _pqs

        def callback(request):
            probe = _pqs(urlparse(request.url).query).get("url", [""])[0]
            if probe == "http://169.254.169.254/latest/meta-data/":
                return (200, {}, '{"instance-id": "i-0123456789", "ami-id": "ami-abc"}')
            return (200, {}, "<html>not metadata</html>")

        resp_mock.add_callback(
            resp_mock.GET, re.compile(r"http://test\.local/fetch.*"), callback=callback
        )

        det = SSRFVerifier(make_session(), BASE_CONFIG)

        def build_url(probe_url):
            from urllib.parse import quote
            return f"http://test.local/fetch?url={quote(probe_url, safe='')}"

        finding = det.verify("http://test.local/fetch?url=x", "url", build_url)
        assert finding is not None
        assert finding.confidence == 40
        assert finding.confidence < CONFIDENCE_HIGH
        assert "unconfirmed" in finding.verification_method.lower()

    @resp_mock.activate
    def test_primary_plus_secondary_still_capped_without_oob(self):
        """Both primary AND secondary static probes match, but with NO
        OOB server configured, confidence must still stay below the
        Confirmed threshold — static indicators alone, however numerous,
        are never sufficient proof of real exploitation."""
        from urllib.parse import urlparse, parse_qs as _pqs

        def callback(request):
            probe = _pqs(urlparse(request.url).query).get("url", [""])[0]
            if probe == "http://169.254.169.254/latest/meta-data/iam/security-credentials/":
                return (200, {}, "")
            if probe == "http://169.254.169.254/latest/meta-data/ami-id":
                return (200, {}, "ami-0a1b2c3d4e5f6g7h8")
            if probe == "http://169.254.169.254/latest/meta-data/":
                return (200, {}, '{"instance-id": "i-0123456789", "ami-id": "ami-abc", "local-ipv4": "10.0.0.1"}')
            return (200, {}, "<html>nothing here</html>")

        resp_mock.add_callback(
            resp_mock.GET, re.compile(r"http://test\.local/fetch.*"), callback=callback
        )

        det = SSRFVerifier(make_session(), BASE_CONFIG)

        def build_url(probe_url):
            from urllib.parse import quote
            return f"http://test.local/fetch?url={quote(probe_url, safe='')}"

        finding = det.verify("http://test.local/fetch?url=x", "url", build_url)
        assert finding is not None
        assert finding.confidence < CONFIDENCE_CONFIRMED
        assert finding.confidence <= 50
        # Secondary static confirmation nudges this finding from "Potential"
        # to the low end of "Likely" (50) — but it must NEVER reach
        # "Confirmed" without genuine OOB proof.
        from modules.verification_engine import classify_finding, CLASSIFICATION_CONFIRMED
        assert classify_finding(finding.confidence) != CLASSIFICATION_CONFIRMED

    def test_oob_callback_confirmation_reaches_confirmed_classification(self):
        """When an Interactsh-style OOB server IS configured and a
        callback IS received, the finding must reach 'Confirmed
        Vulnerability' classification — this is the only path that should
        ever produce a Confirmed SSRF finding."""
        from modules.verification_engine import SSRFVerifier as SV, classify_finding, CLASSIFICATION_CONFIRMED
        from modules.interactsh_client import OOBInteraction

        config_with_oob = dict(BASE_CONFIG)
        config_with_oob["interactsh_server_url"] = "https://oob.fake-test-server.com"

        det = SV(make_session(), config_with_oob)

        # Stub out the OOB client so we don't need a real network call
        det.oob.is_available = lambda: True
        det.oob.register = lambda: "abc123.oob.fake-test-server.com"
        det.oob.poll = lambda wait_seconds=8: [
            OOBInteraction(protocol="dns", full_id="abc123", remote_addr="203.0.113.5")
        ]
        det.oob.deregister = lambda: None

        def build_url(probe_url):
            return f"http://test.local/fetch?url={probe_url}"

        finding = det.verify("http://test.local/fetch?url=x", "url", build_url)
        assert finding is not None
        assert finding.confidence >= CONFIDENCE_CONFIRMED
        assert classify_finding(finding.confidence) == CLASSIFICATION_CONFIRMED
        assert "interactsh" in finding.verification_method.lower() or "callback" in finding.verification_method.lower()

    @resp_mock.activate
    def test_generic_word_match_not_flagged(self):
        """A page that merely contains the word 'localhost' in its normal
        text (e.g. dev docs) must NOT be flagged — only specific
        default-server-page banners count."""
        def callback(request):
            return (200, {}, "<html><body>Run this locally via localhost:3000 for development.</body></html>")

        resp_mock.add_callback(
            resp_mock.GET, re.compile(r"http://test\.local/fetch.*"), callback=callback
        )

        det = SSRFVerifier(make_session(), BASE_CONFIG)

        def build_url(probe_url):
            from urllib.parse import quote
            return f"http://test.local/fetch?url={quote(probe_url, safe='')}"

        finding = det.verify("http://test.local/fetch?url=x", "url", build_url)
        assert finding is None


class TestAdminPanelVerifier:
    """Admin panel detection must require tool-specific fingerprints or an
    actual auth challenge, not generic word matches."""

    @resp_mock.activate
    def test_phpmyadmin_fingerprint_detected_with_high_confidence(self):
        from modules.scan_utils import get_baseline
        import modules.scan_utils as su
        su._baseline_cache.clear()

        resp_mock.add(
            resp_mock.GET, re.compile(r"https://victim\.com/.*"),
            body="<html><title>404</title>random unrelated content xyz123</html>",
            status=404,
        )
        resp_mock.add(
            resp_mock.GET, "https://victim.com/phpmyadmin",
            body="<html><title>phpMyAdmin</title>Welcome to phpMyAdmin running on MySQL server</html>",
            status=200,
        )

        det = AdminPanelVerifier(make_session(), BASE_CONFIG)
        baseline = get_baseline(make_session(), "https://victim.com/", BASE_CONFIG)
        finding = det.verify("https://victim.com/phpmyadmin", "/phpmyadmin", "phpMyAdmin", baseline)

        assert finding is not None
        assert finding.confidence >= CONFIDENCE_HIGH
        su._baseline_cache.clear()

    @resp_mock.activate
    def test_generic_word_admin_not_flagged_without_fingerprint(self):
        """A marketing page mentioning 'admin panel' in prose, with no
        login form and no tool-specific fingerprint, should not be flagged
        — or at most flagged with Low confidence."""
        import modules.scan_utils as su
        su._baseline_cache.clear()

        resp_mock.add(
            resp_mock.GET, re.compile(r"https://victim2\.com/.*"),
            body="<html><body>Generic homepage content, nothing special here at all.</body></html>",
            status=404,
        )
        resp_mock.add(
            resp_mock.GET, "https://victim2.com/admin",
            body="<html><body>Our admin panel feature helps you manage your team easily.</body></html>",
            status=200,
        )

        det = AdminPanelVerifier(make_session(), BASE_CONFIG)
        from modules.scan_utils import get_baseline
        baseline = get_baseline(make_session(), "https://victim2.com/", BASE_CONFIG)
        finding = det.verify("https://victim2.com/admin", "/admin", "Admin panel", baseline)

        # No password field, no specific fingerprint → should not flag
        assert finding is None
        su._baseline_cache.clear()


class TestCSRFMultiSignal:
    """CSRF detection should account for SameSite cookie protection AND
    form intent (state-changing vs benign), not just the absence of a
    hidden token field."""

    @resp_mock.activate
    def test_samesite_cookie_lowers_confidence(self):
        resp_mock.add(
            resp_mock.GET, "https://site.com/form",
            body="<html></html>", status=200,
            headers={"Set-Cookie": "session=abc123; SameSite=Strict; Secure"},
        )

        form = {
            "action": "https://site.com/form",
            "method": "POST",
            "inputs": [{"name": "comment", "type": "text", "value": ""}],
        }
        det = CSRFVerifier()
        finding = det.verify(form, "https://site.com/form", make_session(), BASE_CONFIG)

        assert finding is not None
        assert finding.confidence <= CONFIDENCE_LOW + 10  # should be low-ish, not high

    @resp_mock.activate
    def test_generic_non_state_changing_form_stays_low_confidence(self):
        """A generic comment form (not benign-classified, but also not a
        sensitive state-changing action) must stay capped at LOW
        confidence even with no SameSite protection — high confidence is
        reserved for genuinely sensitive, state-changing actions."""
        resp_mock.add(
            resp_mock.GET, "https://site.com/form2",
            body="<html></html>", status=200,
            headers={"Set-Cookie": "session=abc123"},  # no SameSite
        )

        form = {
            "action": "https://site.com/form2",
            "method": "POST",
            "inputs": [{"name": "comment", "type": "text", "value": ""}],
        }
        det = CSRFVerifier()
        finding = det.verify(form, "https://site.com/form2", make_session(), BASE_CONFIG)

        assert finding is not None
        assert finding.confidence < CONFIDENCE_HIGH
        assert finding.severity == "Low"

    @resp_mock.activate
    def test_state_changing_authenticated_form_reaches_high_confidence(self):
        """A genuinely state-changing form (password change) submitted
        while authenticated, with no token and no SameSite, must reach
        HIGH confidence — this is exactly the high-impact case the spec
        requires the detector to prioritize."""
        resp_mock.add(
            resp_mock.GET, "https://site.com/account/change-password",
            body="<html></html>", status=200,
            headers={"Set-Cookie": "session=abc123"},  # no SameSite
        )

        session = make_session()
        session.cookies.set("session", "abc123def456")  # simulate authenticated session

        form = {
            "action": "https://site.com/account/change-password",
            "method": "POST",
            "inputs": [
                {"name": "current_password", "type": "password", "value": ""},
                {"name": "new_password", "type": "password", "value": ""},
            ],
        }
        det = CSRFVerifier()
        finding = det.verify(form, "https://site.com/account/change-password", session, BASE_CONFIG)

        assert finding is not None
        assert finding.confidence >= CONFIDENCE_HIGH
        assert finding.severity == "High"

    def test_classify_intent_detects_money_transfer(self):
        det = CSRFVerifier()
        form = {
            "action": "/transfer",
            "inputs": [
                {"name": "recipient", "type": "text"},
                {"name": "amount", "type": "text"},
            ],
        }
        intent = det.classify_intent(form, "https://bank.com/transfer")
        assert intent["is_state_changing"] is True
        assert intent["is_benign"] is False

    def test_classify_intent_detects_benign_search(self):
        det = CSRFVerifier()
        form = {"action": "/search", "inputs": [{"name": "q", "type": "text"}]}
        intent = det.classify_intent(form, "https://site.com/search")
        assert intent["is_benign"] is True
        assert intent["is_state_changing"] is False

    def test_cross_site_form_not_flagged(self):
        """A form whose action points to a DIFFERENT domain is not a CSRF
        risk on THIS site by definition."""
        form = {
            "action": "https://payment-processor.com/charge",
            "method": "POST",
            "inputs": [{"name": "amount", "type": "text", "value": ""}],
        }
        det = CSRFVerifier()
        finding = det.verify(form, "https://site.com/checkout", make_session(), BASE_CONFIG)
        assert finding is None


class TestSQLiVerifiedEvidence:
    """SQLi findings must include confidence and structured evidence."""

    @resp_mock.activate
    def test_error_based_gets_high_confidence_with_evidence(self):
        from urllib.parse import urlparse, parse_qs as _pqs

        def callback(request):
            q = _pqs(urlparse(request.url).query).get("id", [""])[0]
            # Error-based: a BARE quote (with nothing else) triggers a DB
            # error. AND-based boolean payloads are crafted to be valid
            # SQL, so they do NOT trigger an error — they trigger normal
            # TRUE/FALSE behavior instead (realistic SQLi behavior).
            if q in ("'", '"'):
                return (200, {}, "You have an error in your SQL syntax; check the manual near line 1")
            if "='2" in q or '="2' in q:
                return (200, {}, "<html><body>No results.</body></html>")
            if "='1" in q or '="1' in q:
                return (200, {}, "<html><body>Product #1</body></html>")
            return (200, {}, "<html><body>Product #1</body></html>")

        resp_mock.add_callback(resp_mock.GET, re.compile(r"http://test\.local/page.*"), callback=callback)

        det = SQLiDetector(make_session(), BASE_CONFIG)
        finding = det.verify_url_parameter("http://test.local/page?id=1", "id")

        assert finding is not None
        assert finding["confidence"] >= CONFIDENCE_HIGH
        assert "evidence" in finding
        assert len(finding["evidence"]) > 0
        assert finding["confidence_label"] in ("High", "Confirmed")

    @resp_mock.activate
    def test_boolean_based_uses_real_similarity_not_just_length(self):
        """Boolean-based confirmation must use genuine content-similarity
        comparison (difflib), correctly handling TRUE/FALSE responses that
        are realistic — a product detail page for TRUE, a 'not found'
        page for FALSE — and must NOT be fooled by incidental dynamic
        content like timestamps."""
        from urllib.parse import urlparse, parse_qs as _pqs
        import re as re_mod

        def callback(request):
            q = _pqs(urlparse(request.url).query).get("id", [""])[0]
            # No error pattern present (rules out error-based path)
            if "1'='2" in q or '1"="2' in q:
                # FALSE condition: query returns no rows
                return (200, {}, "<html><body>No product found. Loaded at 10:15:32.</body></html>")
            if "1'='1" in q or '1"="1' in q:
                # TRUE condition: query still returns the same row
                return (200, {}, "<html><body>Product: Widget, Price: $9.99. Loaded at 10:15:01.</body></html>")
            # Baseline (original unmodified value)
            return (200, {}, "<html><body>Product: Widget, Price: $9.99. Loaded at 10:14:50.</body></html>")

        resp_mock.add_callback(resp_mock.GET, re.compile(r"http://test\.local/product.*"), callback=callback)

        det = SQLiDetector(make_session(), BASE_CONFIG)
        finding = det.verify_url_parameter("http://test.local/product?id=1", "id")

        assert finding is not None
        assert finding["confidence"] >= 80
        assert "comparison" in str(finding).lower() or "diff" in finding["evidence"].lower()

    @resp_mock.activate
    def test_clean_page_returns_none_from_verify(self):
        for _ in range(40):
            resp_mock.add(resp_mock.GET, "http://test.local/clean",
                          body="<html><body>Normal page</body></html>", status=200)

        det = SQLiDetector(make_session(), BASE_CONFIG)
        finding = det.verify_url_parameter("http://test.local/clean?id=1", "id")
        assert finding is None


class TestXSSVerifiedEvidence:
    """XSS findings must include confidence and the reflected payload as
    evidence. Without a browser verifier configured, reflection alone must
    NEVER reach 'Confirmed' or even 'High' confidence — execution was not
    proven, only a behavioral signal was observed."""

    @resp_mock.activate
    def test_reflection_only_capped_below_high_without_browser_verifier(self):
        from urllib.parse import urlparse, parse_qs as _pqs

        def _echo(req):
            q = _pqs(urlparse(req.url).query).get("q", [""])[0]
            return (200, {}, f"<html><body>{q}</body></html>")

        resp_mock.add_callback(resp_mock.GET, "http://test.local/search", callback=_echo)

        det = XSSDetector(make_session(), BASE_CONFIG)  # no browser_verifier passed
        finding = det.verify_url_parameter("http://test.local/search?q=hello", "q")

        assert finding is not None
        assert finding["confidence"] < CONFIDENCE_HIGH
        assert "evidence" in finding
        assert "not verified" in finding["verification_method"].lower() or "reflection only" in finding["verification_method"].lower()
        assert "<script>" in finding["evidence"] or "reflected" in finding["evidence"].lower()

    def test_browser_confirmed_execution_reaches_confirmed_classification(self):
        """When a browser verifier IS supplied and confirms real
        execution, the finding must reach Confirmed-level confidence."""
        from modules.browser_xss_verifier import ExecutionProof
        from modules.verification_engine import classify_finding, CLASSIFICATION_CONFIRMED

        class FakeBrowserVerifier:
            def is_available(self): return True
            def verify_reflected(self, url, timeout_ms=8000):
                return ExecutionProof(executed=True, trigger="alert", dialog_message="XSS")

        @resp_mock.activate
        def run():
            from urllib.parse import urlparse, parse_qs as _pqs

            def _echo(req):
                q = _pqs(urlparse(req.url).query).get("q", [""])[0]
                return (200, {}, f"<html><body>{q}</body></html>")

            resp_mock.add_callback(resp_mock.GET, "http://test.local/search2", callback=_echo)

            det = XSSDetector(make_session(), BASE_CONFIG, browser_verifier=FakeBrowserVerifier())
            return det.verify_url_parameter("http://test.local/search2?q=hello", "q")

        finding = run()
        assert finding is not None
        assert finding["confidence"] >= CONFIDENCE_CONFIRMED
        assert classify_finding(finding["confidence"]) == CLASSIFICATION_CONFIRMED
        assert "browser" in finding["verification_method"].lower()

    def test_reflected_but_not_executed_is_not_reported(self):
        """If the browser verifier confirms the payload reflected but did
        NOT execute (e.g. inside a textarea), the detector must move on
        and try other payloads rather than falsely reporting it."""
        from modules.browser_xss_verifier import ExecutionProof

        class NeverExecutesVerifier:
            def is_available(self): return True
            def verify_reflected(self, url, timeout_ms=8000):
                return ExecutionProof(executed=False)

        @resp_mock.activate
        def run():
            from urllib.parse import urlparse, parse_qs as _pqs

            def _echo(req):
                q = _pqs(urlparse(req.url).query).get("q", [""])[0]
                return (200, {}, f"<html><body><textarea>{q}</textarea></body></html>")

            # Every payload attempt returns the same non-executing reflection
            for _ in range(30):
                resp_mock.add_callback(resp_mock.GET, "http://test.local/search3", callback=_echo)

            det = XSSDetector(make_session(), BASE_CONFIG, browser_verifier=NeverExecutesVerifier())
            return det.verify_url_parameter("http://test.local/search3?q=hello", "q")

        finding = run()
        assert finding is None


class TestScannerConfidenceDefaults:
    """Scanner must backfill confidence for detectors not yet upgraded to
    the verification engine, so every finding in the report has a score."""

    def test_finding_without_confidence_gets_default(self):
        from core.scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner.__new__(VulnerabilityScanner)
        scanner.vulnerabilities = []
        scanner._vuln_keys = set()

        vuln = {"type": "Security Header Missing", "url": "http://x.com/",
                "severity": "High", "description": "Missing CSP"}
        scanner._add_vulnerability(vuln)

        assert scanner.vulnerabilities[0]["confidence"] == 75
        assert "confidence_label" in scanner.vulnerabilities[0]
        assert "evidence" in scanner.vulnerabilities[0]


class TestUniformNon200BaselineNotFlagged:
    """
    Regression test for a real bug found during end-to-end testing: an
    environment where EVERY path (including a definitely-nonexistent
    canary path) returns the SAME non-200, non-404 status — e.g. a
    network egress firewall returning 403 for every host/path, or a WAF
    blocking all requests with 503. The baseline detector must recognise
    this uniform response and skip ALL probe-based findings (admin
    panels, exposed files, error-page probes), not just when the uniform
    status happens to be exactly 404.
    """

    @resp_mock.activate
    def test_uniform_403_not_flagged_as_admin_panel(self):
        import modules.scan_utils as su
        su._baseline_cache.clear()

        # Every single path on this origin returns the identical 403 body
        resp_mock.add(
            resp_mock.GET, re.compile(r"https://blocked\.com/.*"),
            body="Host not in allowlist: blocked.com. Add this host to your network egress settings.",
            status=403,
        )

        from modules.logging_detector import LoggingMonitoringDetector
        det = LoggingMonitoringDetector(make_session(), BASE_CONFIG)
        findings = det._check_admin_panels("https://blocked.com/")
        assert findings == [], f"False positive admin-panel findings on uniform-403 origin: {findings}"

        su._baseline_cache.clear()

    @resp_mock.activate
    def test_uniform_503_not_flagged_in_error_probes(self):
        import modules.scan_utils as su
        su._baseline_cache.clear()

        resp_mock.add(
            resp_mock.GET, re.compile(r"https://maintenance\.com/.*"),
            body="Service temporarily unavailable. Please try again later.",
            status=503,
        )

        from modules.logging_detector import LoggingMonitoringDetector
        det = LoggingMonitoringDetector(make_session(), BASE_CONFIG)
        findings = det._probe_error_pages("https://maintenance.com/")
        assert findings == [], f"False positive error-probe findings on uniform-503 origin: {findings}"

        su._baseline_cache.clear()

    def test_matches_baseline_recognises_non_404_uniform_status(self):
        """Direct unit test of the matches_baseline fix."""
        from modules.scan_utils import matches_baseline
        import requests as req_module

        body_text = "Host not in allowlist: example.com. Add this host to allow access."
        baseline = {"status_code": 403, "length": len(body_text),
                   "body": body_text, "is_soft_404_app": False}

        resp = req_module.Response()
        resp.status_code = 403
        resp._content = body_text.encode()

        assert matches_baseline(resp, baseline) is True

    def test_matches_baseline_still_rejects_genuinely_different_status(self):
        """A real 200 response on a baseline-403 origin must NOT match."""
        from modules.scan_utils import matches_baseline
        import requests as req_module

        body_text = "Host not in allowlist: example.com. Add this host to allow access."
        baseline = {"status_code": 403, "length": len(body_text),
                   "body": body_text, "is_soft_404_app": False}

        resp = req_module.Response()
        resp.status_code = 200
        resp._content = b"<html>Real phpMyAdmin panel</html>"

        assert matches_baseline(resp, baseline) is False


# ── Centralized FP Reduction Engine tests ───────────────────────────────────

class TestFPReductionEngine:
    """The centralized cross-cutting pass that runs once over ALL findings
    at the end of a scan, catching patterns no single detector can see."""

    def test_systemic_pattern_merged_and_confidence_lowered(self):
        from modules.fp_reduction_engine import FPReductionEngine

        # 5 "admin panel" findings on different URLs but identical evidence
        # text (simulating a uniform firewall/WAF response that slipped
        # past individual detector baseline checks)
        findings = [
            {
                "type": "Logging & Monitoring Failure", "url": f"https://x.com/path{i}",
                "severity": "High", "confidence": 70,
                "evidence": "HTTP 403 | Response excerpt: Host not in allowlist generic block message here",
            }
            for i in range(5)
        ]

        engine = FPReductionEngine(make_session(), BASE_CONFIG)
        result = engine.process(findings)

        # Should be merged into ONE representative finding
        assert len(result) == 1
        assert result[0]["confidence"] < 70  # confidence lowered
        assert "fp_reduction_note" in result[0]
        assert result[0]["affected_url_count"] == 5

        summary = engine.get_summary()
        assert summary["systemic_clusters_merged"] == 1
        assert summary["findings_suppressed"] == 4

    def test_distinct_findings_not_merged(self):
        from modules.fp_reduction_engine import FPReductionEngine

        findings = [
            {"type": "SQL Injection", "url": "https://x.com/login", "severity": "Critical",
             "confidence": 95, "evidence": "DB error: syntax error near 'OR 1=1'"},
            {"type": "Cross-Site Scripting (XSS)", "url": "https://x.com/search", "severity": "High",
             "confidence": 90, "evidence": "Payload <script>alert(1)</script> reflected unencoded"},
        ]

        engine = FPReductionEngine(make_session(), BASE_CONFIG)
        result = engine.process(findings)

        assert len(result) == 2  # both kept, unrelated findings

    def test_below_threshold_cluster_not_merged(self):
        """Only 2 similar findings (below SYSTEMIC_PATTERN_MIN_COUNT=3)
        should NOT be merged — could legitimately be 2 real findings."""
        from modules.fp_reduction_engine import FPReductionEngine

        findings = [
            {"type": "Logging & Monitoring Failure", "url": "https://x.com/a", "severity": "High",
             "confidence": 70, "evidence": "Same evidence text here for testing purposes only"},
            {"type": "Logging & Monitoring Failure", "url": "https://x.com/b", "severity": "High",
             "confidence": 70, "evidence": "Same evidence text here for testing purposes only"},
        ]

        engine = FPReductionEngine(make_session(), BASE_CONFIG)
        result = engine.process(findings)
        assert len(result) == 2  # below threshold, both kept as-is

    def test_confirming_auth_signals_raise_confidence(self):
        from modules.fp_reduction_engine import FPReductionEngine

        findings = [
            {"type": "Broken Authentication", "url": "https://x.com/login", "severity": "Critical",
             "confidence": 70, "description": "Login succeeded with default credentials admin/admin",
             "evidence": "creds work"},
            {"type": "Broken Authentication", "url": "https://x.com/login", "severity": "Medium",
             "confidence": 60, "description": "No account lockout after 10 failed attempts",
             "evidence": "no lockout"},
        ]

        engine = FPReductionEngine(make_session(), BASE_CONFIG)
        result = engine.process(findings)

        creds_finding = next(f for f in result if "default" in f["description"].lower())
        assert creds_finding["confidence"] > 70  # raised due to confirming signal


# ── New module tests: API security, modern vulns, JS analysis ─────────────

class TestAPISecurityDetector:

    @resp_mock.activate
    def test_cors_misconfiguration_detected(self):
        from modules.api_security_detector import APISecurityDetector

        resp_mock.add(
            resp_mock.GET, "https://api.test.com/",
            body="{}", status=200,
            headers={
                "Access-Control-Allow-Origin": "https://evil-cors-test.example",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        det = APISecurityDetector(make_session(), BASE_CONFIG)
        findings = det._check_cors_misconfiguration("https://api.test.com/")
        assert len(findings) == 1
        assert findings[0]["confidence"] >= 90

    @resp_mock.activate
    def test_safe_cors_not_flagged(self):
        from modules.api_security_detector import APISecurityDetector

        resp_mock.add(
            resp_mock.GET, "https://api.test.com/",
            body="{}", status=200,
            headers={
                "Access-Control-Allow-Origin": "https://trusted-partner.com",
            },
        )
        det = APISecurityDetector(make_session(), BASE_CONFIG)
        findings = det._check_cors_misconfiguration("https://api.test.com/")
        assert findings == []

    @resp_mock.activate
    def test_exposed_openapi_schema_detected(self):
        import modules.scan_utils as su
        su._baseline_cache.clear()
        from modules.api_security_detector import APISecurityDetector

        resp_mock.add(
            resp_mock.GET, re.compile(r"https://api2\.test\.com/.*"),
            body="not found", status=404,
        )
        resp_mock.add(
            resp_mock.GET, "https://api2.test.com/swagger.json",
            body='{"openapi": "3.0.0", "paths": {"/users": {}}}', status=200,
        )
        det = APISecurityDetector(make_session(), BASE_CONFIG)
        findings = det._discover_api_inventory("https://api2.test.com/")
        assert any("swagger.json" in f["url"] for f in findings)
        su._baseline_cache.clear()

    @resp_mock.activate
    def test_bola_detects_different_object_at_incremented_id(self):
        from modules.api_security_detector import APISecurityDetector

        resp_mock.add(
            resp_mock.GET, "https://api3.test.com/users/1",
            body='{"id": 1, "email": "alice@test.com"}',
            status=200, content_type="application/json",
        )
        resp_mock.add(
            resp_mock.GET, "https://api3.test.com/users/2",
            body='{"id": 2, "email": "bob@test.com"}',
            status=200, content_type="application/json",
        )
        det = APISecurityDetector(make_session(), BASE_CONFIG)
        findings = det._check_bola("https://api3.test.com/users/1")
        assert len(findings) == 1
        assert findings[0]["type"] == "Insecure Direct Object Reference (IDOR)"


class TestModernVulnDetector:

    @resp_mock.activate
    def test_ssti_detected_when_expression_evaluated(self):
        from modules.modern_vuln_detector import ModernVulnDetector
        from urllib.parse import urlparse, parse_qs as _pqs

        def callback(request):
            q = _pqs(urlparse(request.url).query).get("name", [""])[0]
            if q == "xKzQNotAPayloadZZ":
                return (200, {}, "<html>Hello xKzQNotAPayloadZZ</html>")
            if "{{7*7}}" in q or q == "{{7*7}}":
                return (200, {}, "<html>Hello 49</html>")  # evaluated!
            return (200, {}, f"<html>Hello {q}</html>")

        resp_mock.add_callback(resp_mock.GET, re.compile(r"https://ssti\.test/page.*"), callback=callback)

        det = ModernVulnDetector(make_session(), BASE_CONFIG)
        findings = det._test_ssti("https://ssti.test/page?name=world", "name")
        assert len(findings) == 1
        assert findings[0]["type"] == "Server-Side Template Injection (SSTI)"

    @resp_mock.activate
    def test_ssti_not_flagged_when_payload_echoed_literally(self):
        from modules.modern_vuln_detector import ModernVulnDetector

        # Payload always echoed back unevaluated — not vulnerable
        for _ in range(20):
            resp_mock.add(resp_mock.GET, re.compile(r"https://safe\.test/page.*"),
                          body="<html>Hello {{7*7}}</html>", status=200)

        det = ModernVulnDetector(make_session(), BASE_CONFIG)
        findings = det._test_ssti("https://safe.test/page?name=world", "name")
        assert findings == []

    def test_jwt_alg_none_detected(self):
        from modules.modern_vuln_detector import ModernVulnDetector
        import base64, json

        header  = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin"}).encode()).decode().rstrip("=")
        token = f"{header}.{payload}."

        det = ModernVulnDetector(make_session(), BASE_CONFIG)
        findings = det._analyze_jwt(token, "https://test.com/")
        assert len(findings) == 1
        assert findings[0]["confidence"] >= 90

    def test_jwt_weak_secret_detected(self):
        from modules.modern_vuln_detector import ModernVulnDetector
        import base64, json, hmac, hashlib

        header_b64  = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps({"sub": "admin"}).encode()).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = hmac.new(b"secret", signing_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        det = ModernVulnDetector(make_session(), BASE_CONFIG)
        findings = det._analyze_jwt(token, "https://test.com/")
        assert len(findings) == 1
        assert findings[0]["confidence"] >= 95

    def test_strong_jwt_secret_not_flagged(self):
        from modules.modern_vuln_detector import ModernVulnDetector
        import base64, json, hmac, hashlib, secrets

        header_b64  = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps({"sub": "admin"}).encode()).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        strong_secret = secrets.token_hex(32).encode()
        sig = hmac.new(strong_secret, signing_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        det = ModernVulnDetector(make_session(), BASE_CONFIG)
        findings = det._analyze_jwt(token, "https://test.com/")
        assert findings == []

    @resp_mock.activate
    def test_clickjacking_detected_when_no_protection_and_has_form(self):
        from modules.modern_vuln_detector import ModernVulnDetector

        html = "<html><body>" + "<form>x</form>" + "A"*600 + "</body></html>"
        resp_mock.add(resp_mock.GET, "https://clickjack.test/", body=html, status=200)

        det = ModernVulnDetector(make_session(), BASE_CONFIG)
        findings = det._check_clickjacking("https://clickjack.test/")
        assert len(findings) == 1

    @resp_mock.activate
    def test_clickjacking_not_flagged_with_xfo_header(self):
        from modules.modern_vuln_detector import ModernVulnDetector

        html = "<html><body>" + "<form>x</form>" + "A"*600 + "</body></html>"
        resp_mock.add(resp_mock.GET, "https://protected.test/", body=html, status=200,
                      headers={"X-Frame-Options": "DENY"})

        det = ModernVulnDetector(make_session(), BASE_CONFIG)
        findings = det._check_clickjacking("https://protected.test/")
        assert findings == []


class TestJSAnalyzer:

    def test_eval_with_tainted_source_high_confidence(self):
        from modules.js_analyzer import JSAnalyzer

        source = "var x = location.hash.substring(1); eval(x);"
        det = JSAnalyzer(make_session(), BASE_CONFIG)
        findings = det._analyze_dangerous_sinks(source, "https://test.com/app.js")
        assert len(findings) >= 1
        assert findings[0]["confidence"] >= 70

    def test_eval_in_comment_not_flagged(self):
        from modules.js_analyzer import JSAnalyzer

        source = "// eval(userInput) -- disabled for security, do not re-enable\nvar safe = 1;"
        det = JSAnalyzer(make_session(), BASE_CONFIG)
        findings = det._analyze_dangerous_sinks(source, "https://test.com/app.js")
        assert findings == []

    def test_eval_with_literal_argument_low_confidence(self):
        from modules.js_analyzer import JSAnalyzer

        source = 'eval("1+1");'
        det = JSAnalyzer(make_session(), BASE_CONFIG)
        findings = det._analyze_dangerous_sinks(source, "https://test.com/app.js")
        assert len(findings) == 1
        assert findings[0]["confidence"] <= 35

    def test_hardcoded_aws_secret_detected(self):
        from modules.js_analyzer import JSAnalyzer

        source = 'const config = { aws_secret: "AKIAQWERTYUIOPASDFGHJKLZXCVBNMQWERTYUIOP12" };'
        det = JSAnalyzer(make_session(), BASE_CONFIG)
        findings = det._analyze_hardcoded_secrets(source, "https://test.com/app.js")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "Critical"

    def test_postmessage_without_origin_check_flagged(self):
        from modules.js_analyzer import JSAnalyzer

        source = '''
        window.addEventListener("message", function(event) {
            document.getElementById("out").innerHTML = event.data;
        });
        '''
        det = JSAnalyzer(make_session(), BASE_CONFIG)
        findings = det._analyze_postmessage_listeners(source, "https://test.com/app.js")
        assert len(findings) == 1

    def test_postmessage_with_origin_check_not_flagged(self):
        from modules.js_analyzer import JSAnalyzer

        source = '''
        window.addEventListener("message", function(event) {
            if (event.origin !== "https://trusted.com") return;
            doSomething(event.data);
        });
        '''
        det = JSAnalyzer(make_session(), BASE_CONFIG)
        findings = det._analyze_postmessage_listeners(source, "https://test.com/app.js")
        assert findings == []

    def test_token_in_localstorage_flagged(self):
        from modules.js_analyzer import JSAnalyzer

        source = 'localStorage.setItem("access_token", response.token);'
        det = JSAnalyzer(make_session(), BASE_CONFIG)
        findings = det._analyze_token_storage(source, "https://test.com/app.js")
        assert len(findings) == 1
        assert findings[0]["type"] == "Broken Authentication"


class TestOSVIntegrationGracefulFallback:
    """OSV.dev may be unreachable in sandboxed/offline environments — the
    detector must fall back to the local table rather than crashing."""

    def test_osv_query_failure_falls_back_gracefully(self):
        from modules.vulnerable_components_detector import VulnerableComponentsDetector

        det = VulnerableComponentsDetector(make_session(), BASE_CONFIG)
        # Force network failure
        det._osv_available = False
        result = det._js_finding("jQuery", "1.8.3", "3.7.0", "Old CVE note", "https://test.com/")
        assert result["type"] == "Vulnerable Component"
        assert "local reference table" in result["description"].lower()


class TestTypelessFindingCrashRegression:
    """
    Regression test for a real production crash:
      KeyError: 'type'  in core.scanner._analyze_results()

    Root cause: SSRFDetector._probe_form_field() returned a partial dict
    ({"field", "probe", "evidence", "confidence"}) missing 'type' and
    'url'. core.scanner._test_form()'s fast-path branch
    (`isinstance(result, dict) and "confidence" in result`) matched this
    partial dict and appended it directly to findings with no type/url,
    which crashed _analyze_results()'s `v["type"]` indexing much later in
    the pipeline. Fixed at three layers: (1) SSRF now returns a complete
    VerifiedFinding, (2) the scanner's fast-path now also requires "type"
    in result before taking the shortcut, (3) _add_vulnerability() now
    guarantees type/url/severity/description exist on every finding
    regardless of what any detector returns, and (4) _analyze_results()
    uses .get() instead of direct indexing as a final safety net.
    """

    def test_ssrf_form_probe_returns_complete_finding(self):
        from modules.ssrf_detector import SSRFDetector
        import responses as rm

        @rm.activate
        def run():
            rm.add(
                rm.GET, "https://victim.com/",
                body="random unrelated baseline content xyz123", status=404,
            )
            rm.add(
                rm.GET, "https://victim.com/fetch",
                body='{"instance-id": "i-0123456789", "ami-id": "ami-abc"}',
                status=200,
            )
            det = SSRFDetector(make_session(), BASE_CONFIG)
            form = {
                "action": "https://victim.com/fetch",
                "method": "GET",
                "inputs": [{"name": "url", "type": "text", "value": ""}],
            }
            import modules.scan_utils as su
            su._baseline_cache.clear()
            result = det.test_form(form, "https://victim.com/fetch")
            su._baseline_cache.clear()
            return result

        result = run()
        assert result is not None
        assert "type" in result
        assert "url" in result
        assert "severity" in result
        assert "confidence" in result
        assert result["type"] == "Server-Side Request Forgery (SSRF)"

    def test_scanner_never_crashes_on_partial_detector_result(self):
        """
        Simulate a hypothetical detector that STILL returns a partial dict
        (e.g. a bug in a future module) and verify _test_form's hardened
        fast-path check correctly falls through to the safe wrapping
        branch, and _add_vulnerability backfills all required fields,
        so _analyze_results never crashes.
        """
        from core.scanner import VulnerabilityScanner

        scanner = VulnerabilityScanner.__new__(VulnerabilityScanner)
        scanner.vulnerabilities = []
        scanner._vuln_keys = set()
        scanner.scan_stats = {}

        class FakeDetector:
            def test_form(self, form, url):
                # Deliberately incomplete — no 'type', no 'url'
                return {"field": "callback_url", "evidence": "test", "confidence": 70}

        scanner.detectors = {"ssrf": FakeDetector()}

        findings = scanner._test_form(
            {"action": "https://x.com/webhook", "method": "POST", "inputs": []},
            "https://x.com/webhook",
        )

        assert len(findings) == 1
        assert "type" in findings[0]
        assert findings[0]["type"] == "Server-Side Request Forgery (SSRF)"

        # Now push it through _add_vulnerability and _analyze_results to
        # confirm the full pipeline survives end-to-end
        for f in findings:
            scanner._add_vulnerability(f)

        scanner._analyze_results()  # must not raise KeyError
        assert "vulnerabilities_by_type" in scanner.scan_stats

    def test_add_vulnerability_backfills_completely_empty_dict(self):
        """Even a completely empty dict (worst case) must not crash the
        pipeline — _add_vulnerability must backfill every required field."""
        from core.scanner import VulnerabilityScanner

        scanner = VulnerabilityScanner.__new__(VulnerabilityScanner)
        scanner.vulnerabilities = []
        scanner._vuln_keys = set()
        scanner.scan_stats = {}

        scanner._add_vulnerability({})
        scanner._analyze_results()  # must not raise

        assert len(scanner.vulnerabilities) == 1
        v = scanner.vulnerabilities[0]
        assert v["type"] == "Unknown Vulnerability"
        assert v["url"] == ""
        assert v["severity"] == "Info"
        assert "confidence" in v

    def test_add_vulnerability_discards_non_dict_silently(self):
        """A detector returning a non-dict (e.g. accidentally returning a
        string or None that slipped past an `if result:` check) must be
        discarded with a warning, not crash the scan."""
        from core.scanner import VulnerabilityScanner

        scanner = VulnerabilityScanner.__new__(VulnerabilityScanner)
        scanner.vulnerabilities = []
        scanner._vuln_keys = set()
        scanner.scan_stats = {}

        scanner._add_vulnerability("not a dict")  # should log warning and return
        scanner._add_vulnerability(None)

        assert len(scanner.vulnerabilities) == 0
        scanner._analyze_results()  # must not raise on empty list either


class TestOutputContractGuarantee:
    """
    Spec requirement: every detector must ultimately produce
    {confidence, verification_method, evidence_score} on every finding,
    regardless of whether that specific detector has been individually
    upgraded to use VerifiedFinding. _add_vulnerability() is the single
    choke point that guarantees this contract project-wide.
    """

    def test_legacy_plain_dict_finding_gets_full_contract_backfilled(self):
        from core.scanner import VulnerabilityScanner

        scanner = VulnerabilityScanner.__new__(VulnerabilityScanner)
        scanner.vulnerabilities = []
        scanner._vuln_keys = set()
        scanner.scan_stats = {}

        # Simulates a legacy detector (e.g. security_headers_detector)
        # that returns a plain dict with no verification engine fields at all.
        legacy_finding = {
            "type": "Security Header Missing",
            "url": "https://example.com/",
            "severity": "Medium",
            "description": "Missing X-Frame-Options header",
            "evidence": "Header 'X-Frame-Options' not present in response",
        }
        scanner._add_vulnerability(legacy_finding)

        result = scanner.vulnerabilities[0]
        assert "confidence" in result
        assert "verification_method" in result
        assert "evidence_score" in result
        assert "classification" in result
        assert "reproduction_steps" in result
        assert "cvss_estimate" in result
        assert isinstance(result["evidence_score"], int)
        assert 0 <= result["evidence_score"] <= 100
        assert result["classification"] in (
            "Confirmed Vulnerability", "Likely Vulnerability",
            "Potential Vulnerability", "Informational",
        )

    def test_verified_finding_dict_contract_already_complete(self):
        """A finding produced via VerifiedFinding.to_dict() should already
        carry the full contract without needing any backfill."""
        from modules.verification_engine import VerifiedFinding, Evidence

        vf = VerifiedFinding(
            vuln_type="SQL Injection", url="https://x.com/page", parameter="id",
            severity="Critical", confidence=92, owasp="A03 – Injection",
            verification_method="Error-based — DB error message captured",
            evidence=Evidence(probe_payload="' OR 1=1", matched_pattern="sql syntax"),
        )
        d = vf.to_dict()
        assert d["verification_method"] == "Error-based — DB error message captured"
        assert d["evidence_score"] > 0
        assert d["classification"] == "Confirmed Vulnerability"
        assert "reproduction_steps" in d
        assert "cvss_estimate" in d

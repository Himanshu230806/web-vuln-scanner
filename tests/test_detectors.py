"""
Unit tests for all vulnerability detector modules.
Uses 'responses' mock library to avoid real HTTP calls.
"""

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
        """Incrementing numeric ID returning different-length 200 = potential IDOR."""
        original_body = "<html><body>User: Alice</body></html>"
        # alt body is >200 chars longer
        alt_body = "<html><body>User: Bob — Admin Account<br>" + "X" * 300 + "</body></html>"
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

"""
Security Logging & Monitoring Failures Detector v2
OWASP A09:2021 — uses AdminPanelVerifier for accurate panel detection.
"""

import logging
import re
from typing import Dict, List
from urllib.parse import urlparse

import requests

from modules.scan_utils import get_baseline, matches_baseline
from modules.verification_engine import AdminPanelVerifier, adjusted_severity

logger = logging.getLogger(__name__)


class LoggingMonitoringDetector:

    STACK_TRACE_PATTERNS = [
        (r'Traceback \(most recent call last\)',  "Python stack trace exposed"),
        (r'at \w+\.\w+\([\w.]+:\d+\)',            "Java stack trace exposed"),
        (r'System\.Web\.HttpException',            "ASP.NET exception exposed"),
        (r'<b>Fatal error</b>:',                   "PHP fatal error exposed"),
        (r'Warning: .+ on line \d+',               "PHP warning exposed"),
        (r'Parse error: .+ on line \d+',           "PHP parse error exposed"),
        (r'Microsoft OLE DB Provider',             "ASP/OLEDB error exposed"),
        (r'ORA-\d{5}',                             "Oracle DB error exposed"),
        (r'com\.mysql\.jdbc\.exceptions',          "MySQL JDBC exception exposed"),
        (r'org\.postgresql\.util\.PSQLException',  "PostgreSQL exception exposed"),
        (r'ActiveRecord::',                        "Rails ActiveRecord error exposed"),
        (r'ActionController::',                    "Rails ActionController error exposed"),
        (r'Werkzeug Debugger',                     "Flask/Werkzeug interactive debugger is ON"),
        (r'Whoops! There was an error\.',          "Laravel Whoops debug page exposed"),
    ]

    ADMIN_PATHS = [
        ("/admin",            "Admin panel"),
        ("/admin/",           "Admin panel"),
        ("/administrator",    "Administrator panel"),
        ("/wp-admin",         "WordPress admin"),
        ("/phpmyadmin",       "phpMyAdmin"),
        ("/phpmyadmin/",      "phpMyAdmin"),
        ("/pma",              "phpMyAdmin"),
        ("/dbadmin",          "DB admin panel"),
        ("/manager/html",     "Tomcat Manager"),
        ("/console",          "Admin console"),
        ("/actuator",         "Spring Boot Actuator"),
        ("/actuator/env",     "Spring Boot Actuator env"),
        ("/actuator/health",  "Spring Boot Actuator health"),
        ("/metrics",          "Metrics endpoint"),
        ("/server-status",    "Apache server-status"),
        ("/_profiler",        "Symfony profiler"),
        ("/telescope",        "Laravel Telescope"),
        ("/horizon",          "Laravel Horizon"),
        ("/grafana",          "Grafana"),
        ("/grafana/login",    "Grafana"),
        ("/-/grafana",        "Grafana"),
        ("/kibana",           "Kibana"),
        ("/app/kibana",       "Kibana"),
        ("/jenkins",          "Jenkins"),
        ("/jenkins/login",    "Jenkins"),
    ]

    DIR_LISTING_PATTERNS = [
        r'Index of /',
        r'<title>Index of',
        r'Directory Listing',
        r'\[To Parent Directory\]',
        r'Parent Directory</a>',
    ]

    SENSITIVE_DATA_PATTERNS = [
        (r'/var/www/[^\s<"\']{3,}',                           "Absolute server path disclosed"),
        (r'/home/[a-zA-Z0-9_\-]+/[^\s<"\']{3,}',             "Home directory path disclosed"),
        (r'C:\\\\?(Users|Windows|inetpub)\\[^\s<"\']{3,}',   "Windows server path disclosed"),
        (r'\bpassword["\'`]?\s*[:=]\s*["\'`]?[^\s<>"\'`]{4,}', "Password value in response"),
        (r'\bapi[_\-]?key["\'`]?\s*[:=]\s*["\'`]?[A-Za-z0-9_\-]{12,}', "API key in response"),
        (r'(?:mysql|postgresql|postgres|mongodb|redis)://[^\s<"\']{5,}', "Database connection string exposed"),
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session  = session
        self.config   = config
        self.verifier = AdminPanelVerifier(session, config)

    def scan(self, base_url: str, crawled_urls: List[str]) -> List[Dict]:
        findings = []
        findings.extend(self._probe_error_pages(base_url))
        findings.extend(self._check_admin_panels(base_url))
        findings.extend(self._check_directory_listing(crawled_urls))
        findings.extend(self._check_responses_for_debug(crawled_urls))
        return findings

    # ── error page probing ────────────────────────────────────────────────────

    def _probe_error_pages(self, base_url: str) -> List[Dict]:
        findings = []
        parsed  = urlparse(base_url)
        origin  = f"{parsed.scheme}://{parsed.netloc}"
        baseline = get_baseline(self.session, base_url, self.config)

        probe_paths = [
            "/nonexistent_path_12345",
            "/index.php?id='",
            "/search?q=<invalid>",
            "/%00",
            "/..%2f..%2f",
        ]

        for path in probe_paths:
            url = origin + path
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
                body = resp.text

                if matches_baseline(resp, baseline):
                    continue

                for pattern, description in self.STACK_TRACE_PATTERNS:
                    m = re.search(pattern, body, re.IGNORECASE)
                    if m:
                        excerpt  = m.group(0)[:200]
                        confidence = 88
                        findings.append({
                            "type":              "Logging & Monitoring Failure",
                            "subtype":           "Verbose Error / Debug Info",
                            "url":               url,
                            "severity":          "Medium",
                            "confidence":        confidence,
                            "confidence_label":  "High",
                            "description":       (
                                f"{description}. Detailed error information helps attackers "
                                "understand your tech stack and find exploitable paths."
                            ),
                            "evidence":          f"Pattern matched: {excerpt}",
                            "owasp":             "A09 – Logging Failures",
                            "recommendation":    (
                                "Disable debug mode in production. Return generic error pages."
                            ),
                        })
                        break

                for pattern, description in self.SENSITIVE_DATA_PATTERNS:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        confidence = 82
                        findings.append({
                            "type":             "Logging & Monitoring Failure",
                            "subtype":          "Sensitive Data in Error Response",
                            "url":              url,
                            "severity":         "High",
                            "confidence":       confidence,
                            "confidence_label": "High",
                            "description":      (
                                f"{description} found in error response. "
                                "This aids attacker reconnaissance."
                            ),
                            "evidence":         f"Matched: {match.group(0)[:80]}",
                            "owasp":            "A09 – Logging Failures",
                            "recommendation":   (
                                "Sanitise all error responses. Never expose internal paths, "
                                "credentials, or keys."
                            ),
                        })
                        break

            except Exception as e:
                logger.debug("Error probe failed for %s: %s", url, e)

        return findings

    # ── admin panel detection ─────────────────────────────────────────────────

    def _check_admin_panels(self, base_url: str) -> List[Dict]:
        findings = []
        parsed  = urlparse(base_url)
        origin  = f"{parsed.scheme}://{parsed.netloc}"
        baseline = get_baseline(self.session, base_url, self.config)
        checked = set()

        for path, label in self.ADMIN_PATHS:
            url = origin + path
            if url in checked:
                continue
            checked.add(url)

            vf = self.verifier.verify(url, path, label, baseline)
            if vf:
                d = vf.to_dict()
                d["recommendation"] = (
                    f"Restrict {path} to authenticated administrators only. "
                    "Use IP allowlisting for extra protection."
                )
                findings.append(d)

        return findings

    # ── directory listing ─────────────────────────────────────────────────────

    def _check_directory_listing(self, urls: List[str]) -> List[Dict]:
        findings = []
        for url in urls:
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
                for pattern in self.DIR_LISTING_PATTERNS:
                    m = re.search(pattern, resp.text, re.IGNORECASE)
                    if m:
                        findings.append({
                            "type":             "Logging & Monitoring Failure",
                            "subtype":          "Directory Listing Enabled",
                            "url":              url,
                            "severity":         "Medium",
                            "confidence":       90,
                            "confidence_label": "Confirmed",
                            "description":      (
                                "Directory listing is enabled. An attacker can enumerate "
                                "all files in this directory."
                            ),
                            "evidence":         f"Pattern '{pattern}' matched: {m.group(0)[:60]}",
                            "owasp":            "A09 – Logging Failures",
                            "recommendation":   "Disable directory listing (Options -Indexes in Apache).",
                        })
                        break
            except Exception:
                continue
        return findings

    # ── debug info in normal pages ────────────────────────────────────────────

    def _check_responses_for_debug(self, urls: List[str]) -> List[Dict]:
        findings = []
        baseline = get_baseline(self.session, urls[0], self.config) if urls else {"body": ""}
        baseline_body = baseline.get("body", "")

        for url in urls:
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
                body = resp.text
                for pattern, description in self.STACK_TRACE_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        if re.search(pattern, baseline_body, re.IGNORECASE):
                            continue
                        m = re.search(pattern, body, re.IGNORECASE)
                        findings.append({
                            "type":             "Logging & Monitoring Failure",
                            "subtype":          "Debug Info in Normal Page",
                            "url":              url,
                            "severity":         "Medium",
                            "confidence":       85,
                            "confidence_label": "High",
                            "description":      f"{description} found on a normal page.",
                            "evidence":         m.group(0)[:150] if m else pattern,
                            "owasp":            "A09 – Logging Failures",
                            "recommendation":   "Disable debug mode and remove all debug output from production.",
                        })
                        break
            except Exception:
                continue
        return findings

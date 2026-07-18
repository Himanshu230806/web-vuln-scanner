"""
Software & Data Integrity Failures Detector
OWASP A08:2021 – Software and Data Integrity Failures

Checks:
  - Missing Subresource Integrity (SRI) on external <script> and <link> tags
  - Dangerous use of eval() / innerHTML / document.write in JS
  - Deserialisation indicators in request/response
  - Exposed .git / .svn / .env files (supply-chain risk)
"""

import logging
import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import requests

from modules.scan_utils import get_baseline, matches_baseline

logger = logging.getLogger(__name__)


class SRIDetector:

    DANGEROUS_JS_PATTERNS = [
        (r'\beval\s*\(',           "eval()",           "Dynamic code execution via eval() can allow code injection."),
        (r'\.innerHTML\s*=',       "innerHTML =",      "Direct innerHTML assignment can introduce XSS if user data is used."),
        (r'document\.write\s*\(',  "document.write()", "document.write() can be used for XSS; prefer safe DOM APIs."),
        (r'setTimeout\s*\(\s*["\']', "setTimeout(string)", "setTimeout with a string argument executes arbitrary code."),
        (r'setInterval\s*\(\s*["\']', "setInterval(string)", "setInterval with a string argument executes arbitrary code."),
        (r'new\s+Function\s*\(',   "new Function()",   "Dynamic function construction can allow code injection."),
    ]

    EXPOSED_SENSITIVE_PATHS = [
        ("/.env",            "Critical", "Environment file with secrets (.env) is publicly accessible."),
        ("/.env.production", "Critical", ".env.production with production secrets is exposed."),
        ("/.env.local",      "Critical", ".env.local with secrets is exposed."),
        ("/.git/HEAD",       "High",     "Git repository metadata is publicly accessible — source code may be downloadable."),
        ("/.git/config",     "High",     ".git/config is accessible — repository origin and credentials may be exposed."),
        ("/.svn/entries",    "High",     "SVN repository metadata is accessible."),
        ("/backup.zip",      "High",     "Backup archive is publicly downloadable."),
        ("/backup.tar.gz",   "High",     "Backup archive is publicly downloadable."),
        ("/db_backup.sql",   "High",     "Database backup file is publicly accessible."),
        ("/config.php.bak",  "High",     "PHP config backup is publicly accessible."),
        ("/web.config.bak",  "High",     "web.config backup is publicly accessible."),
        ("/.DS_Store",       "Medium",   ".DS_Store file exposes directory structure (macOS artefact)."),
        ("/phpinfo.php",     "Medium",   "phpinfo() page exposes full PHP configuration."),
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config  = config

    # ── public API ────────────────────────────────────────────────────────────

    def scan(self, base_url: str, crawled_urls: List[str]) -> List[Dict]:
        findings = []
        findings.extend(self._check_exposed_sensitive_files(base_url))
        findings.extend(self._check_missing_sri(crawled_urls))
        findings.extend(self._check_dangerous_js(crawled_urls))
        return findings

    # ── SRI checks ────────────────────────────────────────────────────────────

    def _check_missing_sri(self, urls: List[str]) -> List[Dict]:
        findings = []
        checked_pages: set = set()

        for url in urls:
            if url in checked_pages:
                continue
            checked_pages.add(url)
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
                html = resp.text
                page_origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

                # External <script src="..."> without integrity=""
                for match in re.finditer(
                    r'<script([^>]+)>',
                    html, re.IGNORECASE
                ):
                    attrs = match.group(1)
                    src_match = re.search(r'src=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                    if not src_match:
                        continue
                    src = src_match.group(1)
                    # Only flag cross-origin scripts
                    if src.startswith("//") or (src.startswith("http") and not src.startswith(page_origin)):
                        if "integrity=" not in attrs.lower():
                            findings.append({
                                "type": "Software Integrity Failure",
                                "subtype": "Missing SRI on Script",
                                "url": url,
                                "severity": "Medium",
                                "description": (
                                    f"External script '{src[:80]}' loaded without a "
                                    "Subresource Integrity (SRI) hash. If the CDN is compromised, "
                                    "malicious code runs on every visitor's browser."
                                ),
                                "recommendation": (
                                    "Add integrity and crossorigin attributes: "
                                    '<script src="..." integrity="sha384-..." crossorigin="anonymous">'
                                ),
                                "evidence": f"<script src=\"{src[:80]}\" [no integrity]>",
                            })

                # External <link rel="stylesheet"> without integrity=""
                for match in re.finditer(
                    r'<link([^>]+)>',
                    html, re.IGNORECASE
                ):
                    attrs = match.group(1)
                    if 'stylesheet' not in attrs.lower():
                        continue
                    href_match = re.search(r'href=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                    if not href_match:
                        continue
                    href = href_match.group(1)
                    if href.startswith("//") or (href.startswith("http") and not href.startswith(page_origin)):
                        if "integrity=" not in attrs.lower():
                            findings.append({
                                "type": "Software Integrity Failure",
                                "subtype": "Missing SRI on Stylesheet",
                                "url": url,
                                "severity": "Low",
                                "description": (
                                    f"External stylesheet '{href[:80]}' loaded without SRI hash."
                                ),
                                "recommendation": "Add integrity attribute to all external CSS links.",
                                "evidence": f"<link href=\"{href[:80]}\" [no integrity]>",
                            })

            except Exception as e:
                logger.debug(f"SRI check error for {url}: {e}")

        return findings

    # ── dangerous JS patterns ─────────────────────────────────────────────────

    def _check_dangerous_js(self, urls: List[str]) -> List[Dict]:
        findings = []
        checked: set = set()

        for url in urls:
            if not url.endswith(".js") or url in checked:
                continue
            checked.add(url)
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
                js_content = resp.text

                for pattern, name, description in self.DANGEROUS_JS_PATTERNS:
                    if re.search(pattern, js_content):
                        findings.append({
                            "type": "Software Integrity Failure",
                            "subtype": f"Dangerous JS Pattern: {name}",
                            "url": url,
                            "severity": "Low",
                            "description": description,
                            "recommendation": "Review all uses of this pattern; replace with safe alternatives.",
                            "evidence": f"Pattern '{name}' found in {url}",
                        })
            except Exception:
                continue

        return findings

    # ── exposed sensitive files ───────────────────────────────────────────────

    def _check_exposed_sensitive_files(self, base_url: str) -> List[Dict]:
        """
        Probe for exposed secrets/backup files.

        Same accuracy fix as vulnerable_components_detector.py: compare
        against this origin's baseline "soft 404" / SPA-catch-all response
        before trusting an HTTP 200. Without this, a single-page-app that
        returns its index.html shell for every path (a very common SPA
        routing pattern) gets flagged for EVERY sensitive path in the list
        — .env, .git/config, backup.zip, etc. — since they all "return
        200", even though none of them actually exist.
        """
        findings = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        baseline = get_baseline(self.session, base_url, self.config)

        for path, severity, description in self.EXPOSED_SENSITIVE_PATHS:
            test_url = origin + path
            try:
                resp = self.session.get(
                    test_url,
                    timeout=self.config.get("request_timeout", 10),
                    allow_redirects=False,
                )
                if resp.status_code != 200 or len(resp.text) <= 10:
                    continue

                if matches_baseline(resp, baseline):
                    continue

                # Defense in depth: none of these files are ever legitimately
                # an HTML page. A catch-all route that the baseline probe
                # happened to miss (e.g. a cached baseline from an earlier,
                # differently-behaving path) would still get caught here.
                stripped = resp.text.lstrip().lower()
                if stripped.startswith(("<!doctype html", "<html")):
                    continue

                findings.append({
                    "type": "Software Integrity Failure",
                    "subtype": "Exposed Sensitive File",
                    "url": test_url,
                    "severity": severity,
                    "description": description,
                    "recommendation": f"Block public access to {path} in your web server configuration.",
                    "evidence": f"HTTP 200 on {test_url} ({len(resp.text)} bytes returned)",
                })
            except Exception:
                continue

        return findings

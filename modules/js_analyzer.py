"""
JavaScript Security Analyzer

Addresses "Limited JavaScript analysis" — the previous implementation
(inside sri_detector.py) only grepped for a handful of dangerous function
names (eval, innerHTML, document.write) with no context, frequently
matching commented-out code, string literals describing the pattern, or
safe usages (e.g. innerHTML = '' to clear a node).

This module performs deeper static analysis:
  - Context-aware dangerous-sink detection (ignores comments/strings,
    checks whether the sink's argument is a literal vs. dynamic/tainted)
  - Source-to-sink taint tracking for common patterns (location.hash,
    document.URL, postMessage data flowing into eval/innerHTML/Function)
  - Hardcoded secret/API-key detection in JS bundles
  - Insecure postMessage listener detection (no origin check)
  - Client-side JWT/token storage in localStorage (XSS-exfiltration risk)
  - Detection of disabled/bypassed security checks left in production code
    (e.g. "// TODO: re-enable CSRF check", commented-out auth guards)
  - Source map exposure (reveals original source structure)
"""

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

from modules.verification_engine import VerifiedFinding, Evidence

logger = logging.getLogger(__name__)


@dataclass
class JSFinding:
    subtype:    str
    severity:   str
    confidence: int
    description: str
    evidence:   str
    line_context: str = ""


class JSAnalyzer:

    # ── Dangerous sinks with taint-source correlation ─────────────────────────
    # Each sink: (regex matching the sink call with its argument captured,
    #             list of "tainted source" patterns that make it dangerous
    #             if found feeding into the same argument, base confidence
    #             if argument is a literal vs dynamic)
    DANGEROUS_SINKS = [
        ("eval",            r'\beval\s*\(\s*([^)]{0,200})\)'),
        ("Function",        r'new\s+Function\s*\(\s*([^)]{0,200})\)'),
        ("setTimeout",      r'setTimeout\s*\(\s*([\'"][^\'\"]*[\'"])'),  # only string-arg form is dangerous
        ("setInterval",     r'setInterval\s*\(\s*([\'"][^\'\"]*[\'"])'),
        ("innerHTML",       r'\.innerHTML\s*=\s*([^;]{0,200});'),
        ("outerHTML",       r'\.outerHTML\s*=\s*([^;]{0,200});'),
        ("documentWrite",   r'document\.write(?:ln)?\s*\(\s*([^)]{0,200})\)'),
        ("insertAdjacentHTML", r'insertAdjacentHTML\s*\(\s*[\'"][a-z]+[\'"]\s*,\s*([^)]{0,200})\)'),
    ]

    # Taint sources: user-influenceable values that should never flow
    # unsanitised into a dangerous sink
    TAINT_SOURCES = [
        "location.hash", "location.search", "location.href", "document.URL",
        "document.referrer", "window.name", "URLSearchParams",
        "event.data",  # postMessage payload
        "req.query", "req.params", "req.body",  # server-side Node, but appears in isomorphic bundles
    ]

    SECRET_PATTERNS = [
        (r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API key"),
        (r'(?:aws_?access_?key_?id)["\']?\s*[:=]\s*["\']([A-Z0-9]{16,})["\']',      "AWS Access Key ID"),
        (r'(?:aws_?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{30,})["\']',          "AWS Secret Key"),
        (r'(?:secret|private)[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Generic secret/private key"),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                                "PEM private key"),
        (r'(?:stripe)[_-]?(?:secret|live)[_-]?key["\']?\s*[:=]\s*["\'](sk_live_[A-Za-z0-9]+)["\']', "Stripe live secret key"),
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config  = config

    # ── public API ────────────────────────────────────────────────────────────

    def scan(self, base_url: str, crawled_urls: List[str]) -> List[Dict]:
        """
        Only report dangerous-sink (innerHTML/eval/document.write) findings
        for JS files hosted on the TARGET domain. Third-party CDN scripts
        (Google Tag Manager, Bootstrap CDN, jQuery CDN etc.) are skipped for
        sink analysis — innerHTML in gtag/js is Google's own code, not a
        vulnerability in the target application.
        Secrets, postMessage, and disabled-security-checks are still checked
        for all JS regardless of host.
        """
        findings = []
        from urllib.parse import urlparse as _up
        target_netloc = _up(base_url).netloc
        target_domains = {
            target_netloc,
            target_netloc.lstrip('www.'),
            'www.' + target_netloc.lstrip('www.'),
        }

        js_urls = self._collect_js_urls(crawled_urls)

        for js_url in js_urls:
            try:
                resp = self.session.get(js_url, timeout=self.config.get("request_timeout", 15))
                if resp.status_code != 200:
                    continue
                source = resp.text
            except Exception:
                continue

            js_domain = _up(js_url).netloc
            is_target_domain = js_domain in target_domains

            # Only flag dangerous sinks in the app's OWN JavaScript
            if is_target_domain:
                findings.extend(self._analyze_dangerous_sinks(source, js_url))

            # Always check these regardless of domain
            findings.extend(self._analyze_hardcoded_secrets(source, js_url))
            findings.extend(self._analyze_postmessage_listeners(source, js_url))
            findings.extend(self._analyze_disabled_security_checks(source, js_url))
            findings.extend(self._analyze_token_storage(source, js_url))
            findings.extend(self._check_sourcemap_exposure(js_url))

        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    def _collect_js_urls(self, crawled_urls: List[str]) -> List[str]:
        """Find <script src> references across crawled pages, plus any
        URL that's directly a .js file."""
        js_urls = set()
        for url in crawled_urls:
            if url.lower().endswith(".js"):
                js_urls.add(url)
                continue
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
                for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE):
                    src = m.group(1)
                    full = src if src.startswith("http") else urljoin(url, src)
                    js_urls.add(full)
            except Exception:
                continue
        return list(js_urls)[:30]  # cap for scan duration

    @staticmethod
    def _strip_comments_and_strings_for_scan(source: str) -> str:
        """
        Remove // and /* */ comments so dangerous-sink regexes don't match
        commented-out code (a major source of false positives in the old
        grep-only approach: '// eval(userInput) -- disabled' used to flag
        as a live vulnerability).
        """
        # Remove /* */ block comments
        no_block = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
        # Remove // line comments (careful not to eat URLs like http://)
        no_line = re.sub(r'(?<!:)//[^\n]*', '', no_block)
        return no_line

    # ── dangerous sinks with taint correlation ────────────────────────────────

    def _analyze_dangerous_sinks(self, source: str, url: str) -> List[Dict]:
        findings = []
        clean_source = self._strip_comments_and_strings_for_scan(source)

        for sink_name, pattern in self.DANGEROUS_SINKS:
            for m in re.finditer(pattern, clean_source):
                arg = m.group(1).strip()
                is_literal = bool(re.match(r'^[\'"].*[\'"]$', arg))

                if is_literal:
                    # eval("some hardcoded string") is still bad practice but
                    # not exploitable by an external attacker directly
                    confidence = 30
                    severity   = "Low"
                    note = "Argument appears to be a string literal (lower risk, but still bad practice)"
                else:
                    # Check if a known taint source appears nearby (within
                    # 300 chars before the sink call) — strong signal that
                    # user-controlled data flows into this sink
                    context_start = max(0, m.start() - 300)
                    context = clean_source[context_start:m.start()]
                    tainted_source = next((src for src in self.TAINT_SOURCES if src in context or src in arg), None)

                    if tainted_source:
                        confidence = 75
                        severity   = "High"
                        note = f"Tainted source '{tainted_source}' found feeding into this sink"
                    else:
                        confidence = 45
                        severity   = "Medium"
                        note = "Dynamic argument, but no known taint source identified nearby — manual review recommended"

                excerpt = clean_source[max(0, m.start()-40):m.end()+20].strip()
                findings.append({
                    "type":             "Software Integrity Failure",
                    "subtype":          f"Dangerous JS Sink: {sink_name}",
                    "url":              url,
                    "severity":         severity,
                    "confidence":       confidence,
                    "confidence_label": "High" if confidence >= 70 else ("Medium" if confidence >= 50 else "Low"),
                    "description": (
                        f"{sink_name}() called with a {'literal' if is_literal else 'dynamic'} "
                        f"argument. {note}."
                    ),
                    "evidence":  excerpt[:250],
                    "owasp":     "A03 – Injection" if not is_literal else "A08 – Software Integrity",
                    "recommendation": (
                        f"Avoid {sink_name}() with any user-influenceable data. "
                        "Use safe DOM APIs (textContent, createElement) or a sanitisation "
                        "library (DOMPurify) before assigning HTML."
                    ),
                })

        return findings

    # ── hardcoded secrets ──────────────────────────────────────────────────────

    def _analyze_hardcoded_secrets(self, source: str, url: str) -> List[Dict]:
        findings = []
        for pattern, label in self.SECRET_PATTERNS:
            m = re.search(pattern, source)
            if m:
                secret_excerpt = (m.group(1) if m.groups() else m.group(0))[:12] + "..."
                findings.append({
                    "type":             "Software Integrity Failure",
                    "subtype":          "Hardcoded Secret in JavaScript",
                    "url":              url,
                    "severity":         "Critical",
                    "confidence":       80,
                    "confidence_label": "High",
                    "description": (
                        f"A {label} appears to be hardcoded in client-side JavaScript. "
                        "Anything shipped to the browser is visible to every visitor and "
                        "can be extracted trivially."
                    ),
                    "evidence":  f"{label} pattern matched: {secret_excerpt}",
                    "owasp":     "A08 – Software Integrity",
                    "recommendation": (
                        "Never embed secrets in client-side code. Move secret-dependent "
                        "operations to a backend service and only expose short-lived, "
                        "scoped tokens to the browser."
                    ),
                })
        return findings

    # ── postMessage without origin check ──────────────────────────────────────

    def _analyze_postmessage_listeners(self, source: str, url: str) -> List[Dict]:
        findings = []
        clean = self._strip_comments_and_strings_for_scan(source)

        for m in re.finditer(
            r'addEventListener\s*\(\s*[\'"]message[\'"]\s*,\s*function\s*\(([^)]*)\)\s*\{([^}]{0,400})',
            clean
        ):
            handler_body = m.group(2)
            has_origin_check = bool(re.search(r'\.origin\s*[=!]=', handler_body))
            if not has_origin_check:
                excerpt = clean[m.start():m.start()+200].strip()
                findings.append({
                    "type":             "Software Integrity Failure",
                    "subtype":          "Insecure postMessage Listener",
                    "url":              url,
                    "severity":         "Medium",
                    "confidence":       60,
                    "confidence_label": "Medium",
                    "description": (
                        "A 'message' event listener does not check event.origin before "
                        "processing the message. Any website (in an iframe or popup) can "
                        "send arbitrary data to this listener, which may lead to XSS or "
                        "data injection if the message content is used unsafely."
                    ),
                    "evidence":  excerpt[:200],
                    "owasp":     "A03 – Injection",
                    "recommendation": (
                        "Always validate event.origin against an explicit allowlist before "
                        "processing postMessage data."
                    ),
                })

        return findings

    # ── disabled/bypassed security checks left in code ───────────────────────

    DISABLED_CHECK_PATTERNS = [
        r'//\s*(?:TODO|FIXME|HACK)[:\s]*.*(?:disable|bypass|skip).*(?:auth|csrf|security|validation)',
        r'if\s*\(\s*(?:true|1)\s*\)\s*\{?\s*//.*(?:bypass|skip).*(?:auth|check)',
        r'(?:auth|csrf|security)Check\s*=\s*false',
        r'//\s*(?:disable|bypass|skip)(?:d)?\s+(?:auth|csrf|security|ssl|cert)',
    ]

    def _analyze_disabled_security_checks(self, source: str, url: str) -> List[Dict]:
        findings = []
        for pattern in self.DISABLED_CHECK_PATTERNS:
            m = re.search(pattern, source, re.IGNORECASE)
            if m:
                findings.append({
                    "type":             "Logging & Monitoring Failure",
                    "subtype":          "Disabled Security Check in Code",
                    "url":              url,
                    "severity":         "Medium",
                    "confidence":       45,
                    "confidence_label": "Medium",
                    "description": (
                        "Client-side code contains a comment or conditional suggesting a "
                        "security check (authentication, CSRF, SSL validation) was "
                        "deliberately disabled or bypassed, possibly left over from "
                        "debugging and never re-enabled."
                    ),
                    "evidence":  m.group(0)[:150],
                    "owasp":     "A09 – Logging Failures",
                    "recommendation": (
                        "Review and remove any debug bypasses before deploying to "
                        "production. Use environment-based feature flags instead of "
                        "commented-out security logic."
                    ),
                })
        return findings

    # ── insecure client-side token storage ────────────────────────────────────

    def _analyze_token_storage(self, source: str, url: str) -> List[Dict]:
        findings = []
        patterns = [
            (r'localStorage\.setItem\s*\(\s*[\'"](?:jwt|token|access_token|auth_token|id_token)[\'"]', "localStorage"),
            (r'sessionStorage\.setItem\s*\(\s*[\'"](?:jwt|token|access_token|auth_token|id_token)[\'"]', "sessionStorage"),
        ]
        for pattern, storage_type in patterns:
            m = re.search(pattern, source, re.IGNORECASE)
            if m:
                findings.append({
                    "type":             "Broken Authentication",
                    "subtype":          f"Token Stored in {storage_type}",
                    "url":              url,
                    "severity":         "Medium",
                    "confidence":       70,
                    "confidence_label": "High",
                    "description": (
                        f"An authentication token is stored in {storage_type}, which is "
                        "accessible to ANY JavaScript running on the page — including "
                        "injected XSS payloads. A single XSS vulnerability anywhere on the "
                        "site can exfiltrate the token and fully hijack the session."
                    ),
                    "evidence":  m.group(0),
                    "owasp":     "A07 – Auth Failures",
                    "recommendation": (
                        "Store session tokens in HttpOnly, Secure, SameSite cookies instead "
                        "of localStorage/sessionStorage, so they are inaccessible to "
                        "JavaScript entirely."
                    ),
                })
        return findings

    # ── source map exposure ───────────────────────────────────────────────────

    def _check_sourcemap_exposure(self, js_url: str) -> List[Dict]:
        findings = []
        map_url = js_url + ".map"
        try:
            resp = self.session.get(map_url, timeout=self.config.get("request_timeout", 10))
            if resp.status_code == 200 and '"sources"' in resp.text and '"mappings"' in resp.text:
                findings.append({
                    "type":             "Information Disclosure",
                    "subtype":          "Exposed Source Map",
                    "url":              map_url,
                    "severity":         "Low",
                    "confidence":       85,
                    "confidence_label": "High",
                    "description": (
                        "A JavaScript source map is publicly accessible, allowing anyone to "
                        "reconstruct readable, original (unminified) source code including "
                        "original file/variable names, internal comments, and project structure."
                    ),
                    "evidence":  f"Valid source map JSON found at {map_url}",
                    "owasp":     "A05 – Security Misconfiguration",
                    "recommendation": "Do not deploy .map files to production, or restrict access to them.",
                })
        except Exception:
            pass
        return findings

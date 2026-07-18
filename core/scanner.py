"""
Main Scanner Engine  (v4.0 – Full OWASP Top 10)
Covers all 10 OWASP categories:
  A01 Broken Access Control     → IDOR detector
  A02 Cryptographic Failures    → Security Headers (HSTS, HTTPS check)
  A03 Injection                 → SQLi, XSS, XXE, Directory Traversal
  A04 Insecure Design           → CSRF, Open Redirect (logic flaws)
  A05 Security Misconfiguration → Security Headers (CSP, X-Frame, cookies)
  A06 Vulnerable Components     → VulnerableComponents detector
  A07 Auth Failures             → BrokenAuth detector
  A08 Software Integrity        → SRI detector
  A09 Logging Failures          → LoggingMonitoring detector
  A10 SSRF                      → SSRF detector
"""

import logging
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from colorama import Fore, Style, init
from requests.auth import HTTPBasicAuth

from config import SCANNER_CONFIG, LOGGING_CONFIG
from core.crawler import make_crawler
from modules.auth_handler import AuthHandler
from modules.waf_detector import WAFDetector, WAFBypassEngine, JSONErrorExtractor
from modules.blind_cmdi_detector import BlindCommandInjectionDetector
from modules.spa_detector import SPADetector
from modules.rate_limit_detector import RateLimitDetector
from modules.business_logic_detector import BusinessLogicDetector
from modules.passive_scanner import PassiveScanner
from modules.smart_targeter import SmartTargeter
from modules.sqli_detector import SQLiDetector
from modules.xss_detector import XSSDetector
from modules.csrf_detector import CSRFDetector
from modules.open_redirect_detector import OpenRedirectDetector
from modules.directory_traversal_detector import DirectoryTraversalDetector
from modules.zap_integration import ZAPIntegration
from modules.security_headers_detector import SecurityHeadersDetector
from modules.ssrf_detector import SSRFDetector
from modules.xxe_detector import XXEDetector
from modules.idor_detector import IDORDetector
from modules.broken_auth_detector import BrokenAuthDetector
from modules.vulnerable_components_detector import VulnerableComponentsDetector
from modules.sri_detector import SRIDetector
from modules.logging_detector import LoggingMonitoringDetector
from modules.verification_engine import adjusted_severity, confidence_label, classify_finding, estimate_cvss
from modules.fp_reduction_engine import FPReductionEngine
from modules.api_security_detector import APISecurityDetector
from modules.modern_vuln_detector import ModernVulnDetector
from modules.js_analyzer import JSAnalyzer

init(autoreset=True)

logging.basicConfig(
    level=LOGGING_CONFIG["level"],
    format=LOGGING_CONFIG["format"],
    handlers=[
        logging.FileHandler(LOGGING_CONFIG["file"]),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

OWASP_MAP = {
    "SQL Injection":                          "A03 – Injection",
    "Cross-Site Scripting (XSS)":             "A03 – Injection",
    "XML External Entity (XXE)":              "A03 – Injection",
    "Directory Traversal / LFI":              "A03 – Injection",
    "Cross-Site Request Forgery (CSRF)":      "A04 – Insecure Design",
    "Open Redirect":                          "A04 – Insecure Design",
    "Insecure Direct Object Reference (IDOR)":"A01 – Broken Access Control",
    "Broken Authentication":                  "A07 – Auth Failures",
    "Server-Side Request Forgery (SSRF)":     "A10 – SSRF",
    "Security Header Missing":                "A05 – Security Misconfiguration",
    "Insecure Cookie":                        "A05 – Security Misconfiguration",
    "Insecure Transport":                     "A02 – Cryptographic Failures",
    "Information Disclosure":                 "A05 – Security Misconfiguration",
    "Vulnerable Component":                   "A06 – Vulnerable Components",
    "Software Integrity Failure":             "A08 – Software Integrity",
    "Logging & Monitoring Failure":           "A09 – Logging Failures",
}


class VulnerabilityScanner:
    """
    Full OWASP Top 10 scanner.

    Auth options (pass via scan_config):
      auth_cookies  : dict  – {'session': 'abc123'}
      auth_headers  : dict  – {'Authorization': 'Bearer <token>'}
      auth_basic    : tuple – ('username', 'password')
    """

    def __init__(self, target_url: str, scan_config: Optional[Dict] = None):
        self.target_url = target_url.rstrip("/")
        self.domain     = urlparse(target_url).netloc
        self.config     = {**SCANNER_CONFIG, **(scan_config or {})}

        if not self.config.get("verify_ssl", True):
            warnings.warn(
                "[SECURITY] verify_ssl is False – TLS certificate validation DISABLED.",
                stacklevel=2,
            )
            requests.packages.urllib3.disable_warnings()

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config["user_agent"]})
        self.session.verify = self.config.get("verify_ssl", True)

        if self.config.get("auth_cookies"):
            self.session.cookies.update(self.config["auth_cookies"])
            logger.info("Auth: cookies applied")
        if self.config.get("auth_headers"):
            self.session.headers.update(self.config["auth_headers"])
            logger.info("Auth: custom headers applied")
        if self.config.get("auth_basic"):
            u, p = self.config["auth_basic"]
            self.session.auth = HTTPBasicAuth(u, p)
            logger.info("Auth: basic auth applied")

        # Auth handler: form-based login BEFORE crawling so the session
        # is authenticated for all subsequent requests — fixes Problem 2.
        self._auth = AuthHandler(self.session, self.config)
        if self._auth.has_credentials():
            if not self._auth.login():
                logger.warning(
                    "Form-based login failed — scan will be limited to public pages. "
                    "Check --auth-user/--auth-pass, or supply --auth-cookie instead."
                )

        # Crawler: PlaywrightCrawler when --browser-crawl is set, otherwise
        # standard HTML crawler — fixes Problem 1.
        self.crawler = make_crawler(self.target_url, self.session, self.config)

        # WAF detector + bypass engine + JSON error extractor — fixes Problem 7.
        self.waf        = WAFDetector(self.session, self.config)
        self.waf_bypass = WAFBypassEngine(self.waf)
        self.json_ex    = JSONErrorExtractor()

        # SPA detector — auto-selects browser crawler when JS framework is detected
        self._spa_detector = SPADetector(self.session, self.config)

        # Rate-limit and business-logic detectors
        self._rate_limit_detector     = RateLimitDetector(self.session, self.config)
        self._business_logic_detector = BusinessLogicDetector(self.session, self.config)

        # Level 1 enhancements
        self._passive    = PassiveScanner(self.config)
        self._targeter   = SmartTargeter()

        # OWASP ZAP integration is opt-in per scan (via --zap CLI flag or
        # the web UI checkbox), not via the hardcoded ZAP_CONFIG['enabled']
        # default — that flag is only a fallback for any other future
        # caller that constructs ZAPIntegration() with no arguments.
        self.zap = None
        if self.config.get("use_zap", False):
            try:
                self.zap = ZAPIntegration(
                    enabled=True,
                    proxy=self.config.get("zap_proxy"),
                    api_key=self.config.get("zap_api_key"),
                )
                if not self.zap.is_available():
                    logger.warning(
                        "ZAP was requested (--zap) but a connection could not be "
                        "established — continuing scan without it."
                    )
            except Exception as e:
                logger.warning(f"ZAP integration failed to initialize: {e}")
                self.zap = None

        # Browser-based XSS execution verifier (Playwright). Created lazily
        # — is_available() launches Chromium on first use and caches the
        # result, so if Chromium isn't installed in this environment, XSS
        # detection automatically and silently falls back to reflection-
        # only mode (capped confidence) rather than crashing the scan.
        self.browser_verifier = None
        if self.config.get("browser_verify_xss", True):
            try:
                from modules.browser_xss_verifier import BrowserXSSVerifier
                self.browser_verifier = BrowserXSSVerifier(self.config)
            except ImportError:
                logger.warning(
                    "Playwright not installed — XSS findings will be capped at "
                    "'Likely Vulnerability' confidence (reflection-only, execution unverified)."
                )

        # All available detector modules, keyed by canonical name.
        # `enabled_modules` (list/set) restricts which run; default = all.
        all_detector_classes = {
            "idor":                  IDORDetector,
            "sqli":                  SQLiDetector,
            "xss":                   XSSDetector,
            "xxe":                   XXEDetector,
            "directory_traversal":   DirectoryTraversalDetector,
            "csrf":                  CSRFDetector,
            "open_redirect":         OpenRedirectDetector,
            "security_headers":      SecurityHeadersDetector,
            "vulnerable_components": VulnerableComponentsDetector,
            "broken_auth":           BrokenAuthDetector,
            "sri":                   SRIDetector,
            "logging_monitoring":    LoggingMonitoringDetector,
            "ssrf":                  SSRFDetector,
            "api_security":          APISecurityDetector,
            "modern_vulns":          ModernVulnDetector,
            "js_analysis":           JSAnalyzer,
            # Problem 5: blind command injection via time-based + OOB probes
            "blind_cmdi":            BlindCommandInjectionDetector,
        }

        enabled = self.config.get("enabled_modules")
        if enabled:
            enabled_set = set(m.strip().lower() for m in enabled)
            active = {k: v for k, v in all_detector_classes.items() if k in enabled_set}
            if not active:
                logger.warning("enabled_modules matched no known module names; running all modules")
                active = all_detector_classes
        else:
            active = all_detector_classes

        self.detectors = {}
        for key, cls in active.items():
            if key == "xss":
                self.detectors[key] = cls(self.session, self.config, browser_verifier=self.browser_verifier)
            else:
                self.detectors[key] = cls(self.session, self.config)
        logger.info("Active detector modules (%d): %s", len(self.detectors), ", ".join(sorted(self.detectors)))

        self.vulnerabilities: List[Dict] = []
        self._vuln_keys: set = set()

        self.scan_stats = {
            "start_time":        None,
            "end_time":          None,
            "urls_crawled":       0,
            "forms_tested":       0,
            "form_fields_tested": 0,
            "parameters_tested":  0,
        }
        self.fp_reduction_summary: Dict = {}

    # ── banner ────────────────────────────────────────────────────────────────

    def print_banner(self):
        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║       Web Application Vulnerability Scanner v4.0             ║
║          Full OWASP Top 10 Coverage Edition                   ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
Target : {Fore.YELLOW}{self.target_url}{Style.RESET_ALL}
Started: {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}
Modules: {Fore.GREEN}{len(self.detectors)} active detectors — OWASP A01–A10{Style.RESET_ALL}
""")

    # ── main scan ─────────────────────────────────────────────────────────────

    def run_scan(self) -> List[Dict]:
        self.print_banner()
        self.scan_stats["start_time"] = datetime.now()

        try:
            # Phase 1 – Smart Crawl (HTML first, then Playwright if SPA detected)
            print(f"\n{Fore.CYAN}[*] Phase 1: Crawling target…{Style.RESET_ALL}")

            if self._auth.has_credentials():
                self._auth.ensure_auth()

            crawled_urls = self._smart_crawl()
            self.scan_stats["urls_crawled"] = len(crawled_urls)
            print(f"{Fore.GREEN}[+] Discovered {len(crawled_urls)} URLs{Style.RESET_ALL}")

            # Phase 1b — WAF fingerprinting.
            waf_name = self.waf.detect(self.target_url)
            if waf_name:
                print(
                    f"{Fore.YELLOW}[!] WAF detected: {waf_name} — some payloads may "
                    f"be blocked. Findings may be incomplete; manual testing with "
                    f"bypass techniques recommended.{Style.RESET_ALL}"
                )
                # Add WAF as an Informational finding in the report
                waf_finding = self.waf.as_finding(self.target_url)
                if waf_finding:
                    self._add_vulnerability(waf_finding)

            # Phase 2 – ZAP (optional)
            if self.zap and self.zap.is_available():
                print(f"\n{Fore.CYAN}[*] Phase 2: OWASP ZAP active scan…{Style.RESET_ALL}")
                for v in self.zap.active_scan(self.target_url):
                    self._add_vulnerability(v)

            # Phase 3 – Security headers & crypto (A02, A05)
            if "security_headers" in self.detectors:
                print(f"\n{Fore.CYAN}[*] Phase 3: Security headers / TLS (A02, A05)…{Style.RESET_ALL}")
                self._run_header_checks(crawled_urls)

            # Phase 4 – Vulnerable components (A06)
            if "vulnerable_components" in self.detectors:
                print(f"\n{Fore.CYAN}[*] Phase 4: Vulnerable components (A06)…{Style.RESET_ALL}")
                for v in self.detectors["vulnerable_components"].scan(self.target_url, crawled_urls):
                    self._add_vulnerability(v)

            # Phase 5 – Software integrity / SRI (A08)
            if "sri" in self.detectors:
                print(f"\n{Fore.CYAN}[*] Phase 5: Software integrity / SRI (A08)…{Style.RESET_ALL}")
                for v in self.detectors["sri"].scan(self.target_url, crawled_urls):
                    self._add_vulnerability(v)

            # Phase 6 – Logging & monitoring (A09)
            if "logging_monitoring" in self.detectors:
                print(f"\n{Fore.CYAN}[*] Phase 6: Logging & monitoring failures (A09)…{Style.RESET_ALL}")
                for v in self.detectors["logging_monitoring"].scan(self.target_url, crawled_urls):
                    self._add_vulnerability(v)

            # Phase 7 – XXE on XML endpoints (A03)
            if "xxe" in self.detectors:
                print(f"\n{Fore.CYAN}[*] Phase 7: XXE injection (A03)…{Style.RESET_ALL}")
                for v in self.detectors["xxe"].scan_crawled_urls(crawled_urls):
                    self._add_vulnerability(v)

            # Phase 7b – API security (REST/JSON, BOLA, CORS, JWT-adjacent)
            if "api_security" in self.detectors:
                print(f"\n{Fore.CYAN}[*] Phase 7b: API security testing (OWASP API Top 10)…{Style.RESET_ALL}")
                for v in self.detectors["api_security"].scan(self.target_url, crawled_urls):
                    self._add_vulnerability(v)

            # Phase 7c – Modern vulnerability categories (SSTI, NoSQLi, JWT, clickjacking, etc.)
            if "modern_vulns" in self.detectors:
                print(f"\n{Fore.CYAN}[*] Phase 7c: Modern vulnerability categories…{Style.RESET_ALL}")
                for v in self.detectors["modern_vulns"].scan_site(self.target_url, crawled_urls):
                    self._add_vulnerability(v)

            # Phase 7d – Deep JavaScript analysis (taint-aware sinks, secrets, postMessage)
            if "js_analysis" in self.detectors:
                print(f"\n{Fore.CYAN}[*] Phase 7d: JavaScript security analysis…{Style.RESET_ALL}")
                for v in self.detectors["js_analysis"].scan(self.target_url, crawled_urls):
                    self._add_vulnerability(v)

            # Phase 8 – Concurrent per-URL / per-param detection
            print(f"\n{Fore.CYAN}[*] Phase 8: Injection, IDOR, SSRF, traversal, auth (A01/A03/A04/A07/A10)…{Style.RESET_ALL}")
            self._run_detection_concurrent(crawled_urls)

            # Phase 8c – Rate limiting & auth blind checks (R1–R5)
            print(f"\n{Fore.CYAN}[*] Phase 8c: Rate limiting & auth enumeration checks (A07)…{Style.RESET_ALL}")
            for v in self._rate_limit_detector.scan(self.target_url):
                self._add_vulnerability(v)

            # Phase 8d – Business logic checks (BL1/BL3/BL4/BL5)
            print(f"\n{Fore.CYAN}[*] Phase 8d: Business logic vulnerabilities (A04)…{Style.RESET_ALL}")
            all_forms_by_url = self.crawler.get_all_forms()
            for url, forms in all_forms_by_url.items():
                for v in self._business_logic_detector.scan_forms(url, forms):
                    self._add_vulnerability(v)
            for v in self._business_logic_detector.scan_urls(crawled_urls):
                self._add_vulnerability(v)
            # BL5 mass assignment: pass API endpoints if available (Playwright crawl)
            if hasattr(self.crawler, "api_endpoints") and self.crawler.api_endpoints:
                for v in self._business_logic_detector.scan_api_endpoints(
                    self.crawler.api_endpoints
                ):
                    self._add_vulnerability(v)

            # Phase 9 – Centralized false-positive reduction pass
            print(f"\n{Fore.CYAN}[*] Phase 9: Cross-validating findings (centralized FP reduction)…{Style.RESET_ALL}")
            self._run_fp_reduction()

            self._analyze_results()

        except Exception as exc:
            logger.error(f"Scan error: {exc}")
            print(f"{Fore.RED}[!] Scan error: {exc}{Style.RESET_ALL}")
        finally:
            if self.browser_verifier is not None:
                try:
                    self.browser_verifier.stop()
                except Exception:
                    pass
            self.scan_stats["end_time"] = datetime.now()
            self._print_summary()

        return self.vulnerabilities

    # ── header checks ────────────────────────────────────────────────────────

    def _run_header_checks(self, urls: List[str]):
        checked = set()
        for url in urls:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin in checked:
                continue
            checked.add(origin)
            for v in self.detectors["security_headers"].scan(url):
                self._add_vulnerability(v)

    # ── concurrent detection ─────────────────────────────────────────────────

    def _run_detection_concurrent(self, urls: List[str]):
        max_workers = min(self.config.get("threads", 10), max(len(urls), 1))

        # Passive scan every URL's response before injection testing.
        # This finds secrets/versions/PII with zero extra requests.
        passive_finding_count = 0
        for url in urls:
            try:
                resp = self.session.get(
                    url,
                    timeout=self.config.get("request_timeout", 15),
                    allow_redirects=True,
                )
                for v in self._passive.scan_response(resp, url):
                    self._add_vulnerability(v)
                    passive_finding_count += 1
            except Exception:
                pass
        if passive_finding_count:
            print(
                f"{Fore.GREEN}[+] Passive scan: "
                f"{passive_finding_count} secret/version finding(s){Style.RESET_ALL}"
            )
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._test_single_url, url): url for url in urls}
            for future in as_completed(futures):
                try:
                    for v in future.result():
                        self._add_vulnerability(v)
                except Exception as exc:
                    logger.debug(f"Worker error: {exc}")

    def _test_single_url(self, url: str) -> List[Dict]:
        findings = []
        parsed   = urlparse(url)

        # URL-parameter tests — with smart targeting
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, param_values in params.items():
                self.scan_stats["parameters_tested"] += 1
                param_value = param_values[0] if param_values else ""

                # Smart targeting: log plan in verbose mode
                if self.config.get("verbose"):
                    plan = self._targeter.plan_url(url)
                    if param_name in plan:
                        p = plan[param_name]
                        logger.debug(
                            "Smart target %s: type=%s skip=%s",
                            param_name, p["type"], p["skip"]
                        )

                findings.extend(
                    self._test_param(url, param_name,
                                     skip_vulns=self._targeter.get_skip_tests(
                                         param_name, param_value
                                     ))
                )

                if "modern_vulns" in self.detectors:
                    findings.extend(
                        self.detectors["modern_vulns"].scan_url_parameter(url, param_name)
                    )

        # Path-based IDOR (A01)
        if "idor" in self.detectors:
            path_idor = self.detectors["idor"].test_path_ids(url)
            if path_idor:
                findings.append({
                    "type": "Insecure Direct Object Reference (IDOR)",
                    "url": url,
                    "severity": "High",
                    "description": (
                        f"Path segment '{path_idor['original_segment']}' is a direct object "
                        "reference. Incrementing it returned a different 200 response — "
                        "broken access control."
                    ),
                    "details": path_idor,
                    "owasp": "A01 – Broken Access Control",
                })

        # Form tests
        for form in self.crawler.get_forms(url):
            self.scan_stats["forms_tested"] += 1
            # Count testable fields (not hidden/submit/button)
            testable_fields = [
                i for i in form.get("inputs", [])
                if i.get("type") not in ("hidden", "submit", "button", "file")
            ]
            self.scan_stats["form_fields_tested"] += len(testable_fields)
            findings.extend(self._test_form(form, url))

            # Broken auth on login forms (A07)
            if "broken_auth" in self.detectors:
                for v in self.detectors["broken_auth"].scan_login_form(form, url):
                    findings.append(v)

        # Directory traversal on URL path + query parameters (A03)
        # Fix: test_url() now returns a complete finding dict (with confidence,
        # evidence, remediation) — use it directly instead of wrapping it in a
        # bare-bones dict that discards all that structured data.
        if "directory_traversal" in self.detectors:
            dt = self.detectors["directory_traversal"].test_url(url)
            if dt:
                if isinstance(dt, dict) and "type" in dt:
                    # New format: complete finding dict from _build_finding()
                    findings.append(dt)
                else:
                    # Legacy format fallback (should not occur after fix)
                    findings.append({
                        "type":        "Directory Traversal / LFI",
                        "url":         url,
                        "severity":    "Critical",
                        "description": "Directory traversal vulnerability detected.",
                        "owasp":       "A03 – Injection",
                    })

        # Blind command injection on URL query parameters (A03) — Problem 5
        if "blind_cmdi" in self.detectors:
            for v in self.detectors["blind_cmdi"].test_url(url):
                findings.append(v)

        # JSON error extraction: check the page's own response for SQL/injection
        # errors buried inside JSON API bodies — invisible to plain-text scanners
        # (Problem 7). This runs once per URL to catch errors the page already
        # returns, before any injection probes are fired.
        try:
            _page_resp = self.session.get(
                url, timeout=self.config.get("request_timeout", 15)
            )
            _json_err = self.json_ex.check_response(_page_resp, url, "")
            if _json_err:
                findings.append({
                    "type":        "Information Disclosure (JSON Error)",
                    "url":         url,
                    "severity":    "Medium",
                    "owasp":       "A05 – Security Misconfiguration",
                    "confidence":  85,
                    "confidence_label": "Confirmed",
                    "classification": "Confirmed Vulnerability",
                    "description": (
                        "The application returns internal error details inside a "
                        "JSON response body, which may assist an attacker in "
                        "crafting targeted exploits."
                    ),
                    "evidence":    _json_err["evidence_note"],
                    "remediation": (
                        "Return generic error messages to clients. Log details "
                        "server-side only. Never expose stack traces, SQL errors, "
                        "or framework internals in API responses."
                    ),
                })
        except Exception:
            pass

        # WAF annotation: if a WAF was detected, attach a note to every
        # finding from this URL so the analyst knows results may be incomplete
        # (Problem 7). Findings are not suppressed — just annotated.
        waf_note = self.waf.waf_annotation()
        if waf_note:
            for f in findings:
                existing_desc = f.get("description", "")
                if waf_note not in existing_desc:
                    f["description"] = f"{existing_desc}\n\n{waf_note}".strip()

        # Session token checks on responses (A07)
        if "broken_auth" in self.detectors:
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
                for v in self.detectors["broken_auth"].scan_session_tokens(resp, url):
                    findings.append(v)
            except Exception:
                pass

        time.sleep(self.config.get("delay", 0.5))
        return findings

    # ── param tests ──────────────────────────────────────────────────────────

    def _test_param(self, url: str, param_name: str,
                    skip_vulns: set = None) -> List[Dict]:
        """
        Test one URL parameter against all applicable detectors.
        skip_vulns: set of detector keys to skip (from SmartTargeter).
        """
        findings   = []
        skip_vulns = skip_vulns or set()

        checks = [
            ("sqli",                "SQL Injection",                          "Critical", "A03 – Injection"),
            ("xss",                 "Cross-Site Scripting (XSS)",             "High",     "A03 – Injection"),
            ("open_redirect",       "Open Redirect",                          "Medium",   "A04 – Insecure Design"),
            ("ssrf",                "Server-Side Request Forgery (SSRF)",     "Critical", "A10 – SSRF"),
            ("idor",                "Insecure Direct Object Reference (IDOR)","High",     "A01 – Broken Access Control"),
            ("directory_traversal", "Directory Traversal / LFI",              "Critical", "A03 – Injection"),
        ]

        for det_key, vuln_type, severity, owasp in checks:
            # Smart targeting: skip tests not relevant for this parameter type
            if det_key in skip_vulns:
                logger.debug("Smart target: skipping %s for %s", det_key, param_name)
                continue
            if det_key not in self.detectors:
                continue
            detector = self.detectors[det_key]
            try:
                if hasattr(detector, "verify_url_parameter"):
                    finding = detector.verify_url_parameter(url, param_name)
                    if finding:
                        findings.append(finding)
                    elif self.waf.is_waf_present():
                        # WAF may have blocked the probe — try bypass variants
                        bypass = self._try_waf_bypass(
                            url, param_name, det_key, detector, vuln_type, severity, owasp
                        )
                        if bypass:
                            findings.append(bypass)
                elif detector.test_url_parameter(url, param_name):
                    findings.append({
                        "type":              vuln_type,
                        "url":               url,
                        "parameter":         param_name,
                        "severity":          adjusted_severity(severity, 50),
                        "original_severity": severity,
                        "confidence":        50,
                        "confidence_label":  "Medium",
                        "description":       f"{vuln_type} detected in parameter '{param_name}' (pattern match, not independently verified).",
                        "evidence":          "Pattern-based detection — no structured evidence captured",
                        "owasp":             owasp,
                    })
            except Exception as exc:
                logger.debug(f"{det_key} param test error: {exc}")

        return findings

    def _try_waf_bypass(self, url, param_name, det_key, detector,
                         vuln_type, severity, owasp) -> Optional[Dict]:
        """
        When a WAF is present and the standard probe didn't find anything,
        try WAFBypassEngine variants. Returns a finding with waf_bypass_used=True
        if any variant succeeds, else None.
        """
        from urllib.parse import parse_qs, urlparse, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original_value = params.get(param_name, [""])[0]

        # Get a representative payload for the detector type
        SAMPLE_PAYLOADS = {
            "sqli":                "' OR 1=1--",
            "xss":                 "<script>alert(1)</script>",
            "directory_traversal": "../../../etc/passwd",
            "ssrf":                "http://169.254.169.254/",
            "open_redirect":       "https://evil.example.com",
        }
        payload = SAMPLE_PAYLOADS.get(det_key, original_value)
        variants = self.waf_bypass.generate_variants(payload)

        for label, variant in variants:
            test_params = params.copy()
            test_params[param_name] = [variant]
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                urlencode(test_params, doseq=True), ""
            ))
            try:
                if hasattr(detector, "verify_url_parameter"):
                    finding = detector.verify_url_parameter(test_url, param_name)
                    if finding:
                        finding["waf_bypass_used"]    = True
                        finding["bypass_variant"]     = label
                        finding["bypass_payload"]     = variant
                        finding["verification_method"] = (
                            f"WAF bypass ({label}) + {finding.get('verification_method','')}"
                        )
                        logger.info(
                            "WAF bypass succeeded for %s on %s using variant '%s'",
                            det_key, url, label
                        )
                        return finding
            except Exception:
                continue
        return None

    # ── smart crawl ───────────────────────────────────────────────────────────

    def _smart_crawl(self) -> List[str]:
        """
        1. HTML crawl first (fast, no dependencies).
        2. Run SPA detection on the start URL.
        3. If SPA confirmed AND --browser-crawl not already set, automatically
           launch Playwright crawler and merge its URLs on top.
        4. Return deduplicated union of all discovered URLs.
        """
        from core.crawler import PlaywrightCrawler, PLAYWRIGHT_AVAILABLE

        # Step 1: HTML crawl
        html_urls = self.crawler.crawl()

        # Step 2: SPA detection (skip if browser-crawl already active)
        if not self.config.get("browser_crawl"):
            spa_result = self._spa_detector.detect(self.target_url)
            if spa_result["is_spa"]:
                print(
                    f"{Fore.YELLOW}[!] {spa_result['confidence']} detected "
                    f"({spa_result['signal_count']} signals: "
                    f"{', '.join(spa_result['signals'][:3])}…). "
                    f"{spa_result['recommendation']}{Style.RESET_ALL}"
                )
                # Step 3: auto-launch Playwright crawler if available
                if PLAYWRIGHT_AVAILABLE:
                    print(f"{Fore.CYAN}[*] Auto-switching to Playwright crawler for SPA…{Style.RESET_ALL}")
                    pw_crawler = PlaywrightCrawler(
                        self.target_url, self.session, self.config
                    )
                    spa_urls = pw_crawler.crawl()
                    # Merge + deduplicate
                    all_urls = list(set(html_urls) | set(spa_urls))
                    print(
                        f"{Fore.GREEN}[+] HTML crawl: {len(html_urls)} URLs, "
                        f"Playwright: {len(spa_urls)} URLs → "
                        f"{len(all_urls)} total after merge{Style.RESET_ALL}"
                    )
                    # Also register any crawler API endpoints for injection testing
                    if hasattr(pw_crawler, "api_endpoints"):
                        for ep in pw_crawler.api_endpoints:
                            if ep not in all_urls:
                                all_urls.append(ep)
                    return all_urls
                else:
                    print(
                        f"{Fore.YELLOW}[!] Playwright not installed — SPA routes "
                        f"may be missed. Install with: pip install playwright && "
                        f"playwright install chromium{Style.RESET_ALL}"
                    )

        return html_urls

    # ── form tests ────────────────────────────────────────────────────────────

    def _test_form(self, form: Dict, url: str) -> List[Dict]:
        findings = []

        form_checks = [
            ("sqli",                "test_form", "SQL Injection",                     "Critical", "A03 – Injection"),
            ("xss",                 "test_form", "Cross-Site Scripting (XSS)",        "High",     "A03 – Injection"),
            ("csrf",                "test_form", "Cross-Site Request Forgery (CSRF)", "Medium",   "A04 – Insecure Design"),
            ("ssrf",                "test_form", "Server-Side Request Forgery (SSRF)","Critical", "A10 – SSRF"),
            # Bug fix: DirectoryTraversalDetector.test_form() was fully
            # implemented but never wired into form_checks, so any
            # file-path/include-style form field (e.g. a "file"/"path"/
            # "page" text input) was never actually tested for traversal —
            # only URL query parameters were.
            ("directory_traversal", "test_form", "Directory Traversal / LFI",         "Critical", "A03 – Injection"),
            # Problem 5: blind command injection (time-based + OOB)
            ("blind_cmdi",          "test_form", "Command Injection (Blind)",          "Critical", "A03 – Injection"),
        ]

        for det_key, method_name, vuln_type, severity, owasp in form_checks:
            if det_key not in self.detectors:
                continue
            try:
                result = getattr(self.detectors[det_key], method_name)(form, url)
                if not result:
                    continue

                # CSRF and verified detectors return a full dict with its
                # own confidence/severity/evidence already computed.
                if isinstance(result, dict) and "confidence" in result and "type" in result:
                    findings.append(result)
                    continue

                # Legacy / partial result (e.g. SSRF form probe) — wrap with
                # a conservative default confidence. Also catches any
                # detector result that has 'confidence' but is missing
                # required keys like 'type' or 'url' (defense in depth —
                # every finding appended below is guaranteed complete).
                confidence = result.get("confidence", 55) if isinstance(result, dict) else 55
                param_guess = (
                    result.get("field") or result.get("parameter")
                    or (str(list(result.keys())[:1]) if isinstance(result, dict) else "")
                )
                findings.append({
                    "type":              vuln_type,
                    "url":               url,
                    "parameter":         param_guess,
                    "form_action":       form.get("action"),
                    "severity":          adjusted_severity(severity, confidence),
                    "original_severity": severity,
                    "confidence":        confidence,
                    "confidence_label":  "Medium",
                    "description":       f"{vuln_type} detected in form at {url}",
                    "evidence":          str(result.get("evidence", result))[:300] if isinstance(result, dict) else str(result)[:300],
                    "owasp":             owasp,
                })
            except Exception as exc:
                logger.debug(f"{det_key} form test error: {exc}")

        return findings

    # ── dedup & record ────────────────────────────────────────────────────────

    def _add_vulnerability(self, vuln: Dict):
        # Defense in depth: this is the single choke point every finding
        # passes through before being added to self.vulnerabilities. Some
        # detector paths (e.g. a form-field probe returning a partial
        # result dict) have previously produced findings missing required
        # keys like 'type' or 'url', which crashed _analyze_results() and
        # the PDF report generator much later in the pipeline — far from
        # where the actual bug was. We guarantee every mandatory field
        # exists here, once, so no detector bug can ever propagate that far.
        if not isinstance(vuln, dict):
            logger.warning(f"Discarding non-dict finding from a detector: {vuln!r}")
            return

        vuln.setdefault("type",        "Unknown Vulnerability")
        vuln.setdefault("url",         "")
        vuln.setdefault("severity",    "Info")
        vuln.setdefault("description", "No description provided by detector.")

        if vuln["type"] == "Unknown Vulnerability":
            logger.warning(f"Finding reached _add_vulnerability without a 'type' key: {vuln}")

        vuln.setdefault("timestamp", datetime.now().isoformat())
        vuln.setdefault("id", f"VULN-{len(self.vulnerabilities)+1:04d}")
        vuln.setdefault("owasp", OWASP_MAP.get(vuln.get("type",""), ""))

        # Confidence scoring: any detector that hasn't been upgraded to the
        # verification engine yet (security_headers, directory_traversal,
        # vulnerable_components, sri) still produces plain findings. We
        # backfill a default confidence so EVERY finding in the report has
        # a confidence score, and apply severity adjustment consistently.
        if "confidence" not in vuln:
            vuln["confidence"]        = 75   # static/structural checks are generally reliable
            vuln["confidence_label"]  = confidence_label(75)
            vuln["original_severity"] = vuln.get("severity", "Info")
            vuln["severity"]          = adjusted_severity(vuln.get("severity", "Info"), 75)
        else:
            vuln.setdefault("confidence_label", confidence_label(vuln["confidence"]))
            vuln.setdefault("original_severity", vuln.get("severity", "Info"))

        vuln.setdefault("evidence", "No structured evidence captured for this finding type.")

        # Spec-mandated output contract: every detector must ultimately
        # produce {confidence, verification_method, evidence_score}.
        # Detectors built on VerifiedFinding.to_dict() already include
        # these; for any detector still returning a plain dict (legacy
        # static checks), backfill sensible defaults here so the contract
        # holds project-wide, not just for upgraded detectors.
        vuln.setdefault("verification_method", "Pattern match (unverified)")
        if "evidence_score" not in vuln:
            # Heuristic evidence_score for legacy findings: based on how
            # much structured detail is actually present.
            score = 0
            if vuln.get("url"):                       score += 20
            if isinstance(vuln.get("evidence"), str) and len(vuln.get("evidence", "")) > 20:
                score += 40
            if vuln.get("parameter"):                  score += 15
            if vuln.get("recommendation"):             score += 15
            if vuln.get("owasp"):                       score += 10
            vuln["evidence_score"] = min(100, score)

        vuln.setdefault(
            "classification",
            classify_finding(vuln.get("confidence", 75), vuln.get("is_informational", False)),
        )
        vuln.setdefault("reproduction_steps", [
            f"1. Re-request {vuln.get('url','the affected URL')} and inspect the response "
            f"for: {str(vuln.get('evidence',''))[:150]}",
        ])
        vuln.setdefault(
            "cvss_estimate",
            estimate_cvss(vuln.get("severity", "Info"), vuln.get("confidence", 75)),
        )
        vuln.setdefault("remediation", vuln.get("recommendation", "Review and remediate per OWASP guidance for this vulnerability class."))

        key = (vuln.get("type",""), vuln.get("url",""), vuln.get("parameter",""))
        if key in self._vuln_keys:
            return
        self._vuln_keys.add(key)
        self.vulnerabilities.append(vuln)

        color = {
            "Critical": Fore.RED,
            "High":     Fore.LIGHTRED_EX,
            "Medium":   Fore.YELLOW,
            "Low":      Fore.GREEN,
            "Info":     Fore.CYAN,
        }.get(vuln.get("severity","Info"), Fore.WHITE)

        owasp_tag  = f" [{vuln['owasp']}]" if vuln.get("owasp") else ""
        conf_tag   = f" ({vuln.get('confidence_label','?')} {vuln.get('confidence','?')}%)" if vuln.get("confidence") is not None else ""
        print(
            f"{color}[!] {vuln.get('severity','?')}: {vuln.get('type','?')}"
            f"{owasp_tag}{conf_tag} — {vuln.get('url','')}"
            f"{' [param: '+vuln['parameter']+']' if vuln.get('parameter') else ''}"
            f"{Style.RESET_ALL}"
        )

    # ── centralized false-positive reduction ──────────────────────────────────

    def _run_fp_reduction(self):
        """
        Final cross-cutting pass over ALL collected findings, run once at
        the end of the scan (not per-detector). This catches false-positive
        patterns that no single detector can see in isolation — e.g. 15
        different URLs all producing the exact same 'admin panel' evidence
        text, which individually each passed their own baseline check but
        collectively indicate a systemic response rather than 15 real bugs.
        """
        engine = FPReductionEngine(self.session, self.config)
        self.vulnerabilities = engine.process(self.vulnerabilities)
        self.fp_reduction_summary = engine.get_summary()
        # Attach to scan_stats so generate_report() (which only receives
        # scan_stats, not the scanner instance) can render the transparency
        # summary — previously computed but never reached the PDF at all.
        self.scan_stats["fp_reduction_summary"] = self.fp_reduction_summary

        summary = self.fp_reduction_summary
        if summary["systemic_clusters_merged"] or summary["findings_suppressed"]:
            print(
                f"{Fore.YELLOW}[*] FP reduction: merged "
                f"{summary['systemic_clusters_merged']} systemic pattern(s), "
                f"suppressed {summary['findings_suppressed']} duplicate finding(s)"
                f"{Style.RESET_ALL}"
            )

    # ── summary ───────────────────────────────────────────────────────────────

    def _analyze_results(self):
        # Use .get() rather than direct indexing here as a second defense
        # layer: _add_vulnerability() already guarantees every finding has
        # a 'type' key before it's appended to self.vulnerabilities, but
        # this method should never crash the whole scan even if some
        # future code path slips a malformed dict through.
        by_type: Dict[str, List] = {}
        for v in self.vulnerabilities:
            by_type.setdefault(v.get("type", "Unknown Vulnerability"), []).append(v)
        self.scan_stats["vulnerabilities_by_type"]  = {k: len(v) for k, v in by_type.items()}

        by_owasp: Dict[str, int] = {}
        for v in self.vulnerabilities:
            cat = v.get("owasp","Unknown")
            by_owasp[cat] = by_owasp.get(cat, 0) + 1
        self.scan_stats["vulnerabilities_by_owasp"] = by_owasp

    def _print_summary(self):
        duration = self.scan_stats["end_time"] - self.scan_stats["start_time"]
        counts = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        for v in self.vulnerabilities:
            s = v.get("severity","Info")
            counts[s] = counts.get(s,0) + 1

        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                     SCAN SUMMARY                             ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
Target     : {self.target_url}
Duration   : {duration}
URLs       : {self.scan_stats['urls_crawled']}
Forms      : {self.scan_stats['forms_tested']}
Parameters : {self.scan_stats['parameters_tested']}

{Fore.CYAN}FINDINGS: {len(self.vulnerabilities)}{Style.RESET_ALL}
{Fore.RED}  Critical : {counts['Critical']}{Style.RESET_ALL}
{Fore.LIGHTRED_EX}  High     : {counts['High']}{Style.RESET_ALL}
{Fore.YELLOW}  Medium   : {counts['Medium']}{Style.RESET_ALL}
{Fore.GREEN}  Low      : {counts['Low']}{Style.RESET_ALL}
{Fore.CYAN}  Info     : {counts['Info']}{Style.RESET_ALL}
""")
        owasp = self.scan_stats.get("vulnerabilities_by_owasp", {})
        if owasp:
            print(f"{Fore.CYAN}OWASP Top 10 breakdown:{Style.RESET_ALL}")
            for cat, cnt in sorted(owasp.items()):
                print(f"  {cat}: {cnt}")
            print()

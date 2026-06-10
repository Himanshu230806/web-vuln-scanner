"""
Main Scanner Engine  (v3.0 – upgraded)
Coordinates all vulnerability detection modules.

Upgrades in this version:
  - ThreadPoolExecutor for concurrent URL testing (replaces sequential loop)
  - Authenticated scanning: cookie / Bearer-token / basic-auth support
  - Fixed deduplication: keyed on (type, url, parameter) not just (type, url)
  - New detectors: SecurityHeaders, SSRF, XXE, IDOR
  - verify_ssl=False emits a visible warning instead of silently ignoring it
"""

import logging
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from colorama import Fore, Style, init
from requests.auth import HTTPBasicAuth

from config import SCANNER_CONFIG, LOGGING_CONFIG
from core.crawler import WebCrawler
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


class VulnerabilityScanner:
    """
    Orchestrates crawling and all detection modules.

    Authentication options (pass via scan_config):
      auth_cookies  : dict  – {'session': 'abc123', ...}
      auth_headers  : dict  – {'Authorization': 'Bearer <token>'}
      auth_basic    : tuple – ('username', 'password')
    """

    def __init__(self, target_url: str, scan_config: Optional[Dict] = None):
        self.target_url = target_url.rstrip("/")
        self.domain = urlparse(target_url).netloc
        self.config = {**SCANNER_CONFIG, **(scan_config or {})}

        # ── SSL warning ────────────────────────────────────────────────
        if not self.config.get("verify_ssl", True):
            warnings.warn(
                "[SECURITY] verify_ssl is False – TLS certificate validation is DISABLED. "
                "Only use this for trusted internal targets.",
                stacklevel=2,
            )
            requests.packages.urllib3.disable_warnings()

        # ── Session setup ──────────────────────────────────────────────
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config["user_agent"]})
        self.session.verify = self.config.get("verify_ssl", True)

        # Authenticated scanning support
        if self.config.get("auth_cookies"):
            self.session.cookies.update(self.config["auth_cookies"])
            logger.info("Auth: session cookies applied")
        if self.config.get("auth_headers"):
            self.session.headers.update(self.config["auth_headers"])
            logger.info("Auth: custom headers applied")
        if self.config.get("auth_basic"):
            user, passwd = self.config["auth_basic"]
            self.session.auth = HTTPBasicAuth(user, passwd)
            logger.info("Auth: HTTP basic auth applied")

        # ── Component setup ────────────────────────────────────────────
        self.crawler = WebCrawler(self.target_url, self.session, self.config)
        self.zap = ZAPIntegration() if self.config.get("use_zap", False) else None

        self.detectors = {
            "sqli": SQLiDetector(self.session, self.config),
            "xss": XSSDetector(self.session, self.config),
            "csrf": CSRFDetector(self.session, self.config),
            "open_redirect": OpenRedirectDetector(self.session, self.config),
            "directory_traversal": DirectoryTraversalDetector(self.session, self.config),
            "security_headers": SecurityHeadersDetector(self.session, self.config),
            "ssrf": SSRFDetector(self.session, self.config),
            "xxe": XXEDetector(self.session, self.config),
            "idor": IDORDetector(self.session, self.config),
        }

        self.vulnerabilities: List[Dict] = []
        self._vuln_keys: set = set()   # for O(1) dedup

        self.scan_stats = {
            "start_time": None,
            "end_time": None,
            "urls_crawled": 0,
            "forms_tested": 0,
            "parameters_tested": 0,
        }

    # ──────────────────────────────────────────────────────────────────
    def print_banner(self):
        print(f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║         Web Application Vulnerability Scanner v3.0           ║
║              Professional Edition – Upgraded                  ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
Target : {Fore.YELLOW}{self.target_url}{Style.RESET_ALL}
Started: {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}
""")

    # ──────────────────────────────────────────────────────────────────
    def run_scan(self) -> List[Dict]:
        self.print_banner()
        self.scan_stats["start_time"] = datetime.now()

        try:
            # Phase 1 – Crawl
            print(f"\n{Fore.CYAN}[*] Phase 1: Crawling target…{Style.RESET_ALL}")
            crawled_urls = self.crawler.crawl()
            self.scan_stats["urls_crawled"] = len(crawled_urls)
            print(f"{Fore.GREEN}[+] Discovered {len(crawled_urls)} URLs{Style.RESET_ALL}")

            # Phase 2 – OWASP ZAP (optional)
            if self.zap and self.zap.is_available():
                print(f"\n{Fore.CYAN}[*] Phase 2: Running OWASP ZAP scan…{Style.RESET_ALL}")
                self.vulnerabilities.extend(self.zap.active_scan(self.target_url))

            # Phase 3 – Security headers (one request per unique host)
            print(f"\n{Fore.CYAN}[*] Phase 3: Checking security headers…{Style.RESET_ALL}")
            self._run_header_checks(crawled_urls)

            # Phase 4 – Concurrent vulnerability detection
            print(f"\n{Fore.CYAN}[*] Phase 4: Running vulnerability detection…{Style.RESET_ALL}")
            self._run_detection_concurrent(crawled_urls)

            # Phase 5 – XXE scan (XML endpoints)
            print(f"\n{Fore.CYAN}[*] Phase 5: Checking for XXE…{Style.RESET_ALL}")
            for vuln in self.detectors["xxe"].scan_crawled_urls(crawled_urls):
                self._add_vulnerability(vuln)

            self._analyze_results()

        except Exception as exc:
            logger.error(f"Scan error: {exc}")
            print(f"{Fore.RED}[!] Error during scan: {exc}{Style.RESET_ALL}")
        finally:
            self.scan_stats["end_time"] = datetime.now()
            self._print_summary()

        return self.vulnerabilities

    # ──────────────────────────────────────────────────────────────────
    def _run_header_checks(self, urls: List[str]):
        """Run security-header checks – one check per unique origin."""
        checked_origins = set()
        for url in urls:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin in checked_origins:
                continue
            checked_origins.add(origin)
            for finding in self.detectors["security_headers"].scan(url):
                self._add_vulnerability(finding)

    # ──────────────────────────────────────────────────────────────────
    def _run_detection_concurrent(self, urls: List[str]):
        """Test all URLs concurrently using a thread pool."""
        max_workers = min(self.config.get("threads", 10), len(urls) or 1)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._test_single_url, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    vulns = future.result()
                    for v in vulns:
                        self._add_vulnerability(v)
                except Exception as exc:
                    logger.debug(f"Worker error for {url}: {exc}")

    def _test_single_url(self, url: str) -> List[Dict]:
        """Test one URL for all vulnerability types. Runs in a thread."""
        findings = []
        parsed = urlparse(url)

        # URL-parameter tests
        if parsed.query:
            from urllib.parse import parse_qs
            for param_name in parse_qs(parsed.query):
                self.scan_stats["parameters_tested"] += 1
                findings.extend(self._test_param(url, param_name))

        # Path-based IDOR
        path_idor = self.detectors["idor"].test_path_ids(url)
        if path_idor:
            findings.append({
                "type": "Insecure Direct Object Reference (IDOR)",
                "url": url,
                "severity": "High",
                "description": (
                    f"Path segment '{path_idor['original_segment']}' appears to be a direct "
                    "object reference. Incrementing it returned a different 200 response, "
                    "suggesting broken access control."
                ),
                "details": path_idor,
            })

        # Form tests
        for form in self.crawler.get_forms(url):
            self.scan_stats["forms_tested"] += 1
            findings.extend(self._test_form(form, url))

        # Directory traversal on path
        dt_result = self.detectors["directory_traversal"].test_url(url)
        if dt_result:
            findings.append({
                "type": "Directory Traversal / LFI",
                "url": url,
                "severity": "Critical",
                "description": "Directory traversal vulnerability detected in URL path.",
                "details": dt_result,
            })

        time.sleep(self.config.get("delay", 0.5))
        return findings

    # ──────────────────────────────────────────────────────────────────
    def _test_param(self, url: str, param_name: str) -> List[Dict]:
        findings = []

        if self.detectors["sqli"].test_url_parameter(url, param_name):
            findings.append({
                "type": "SQL Injection",
                "url": url,
                "parameter": param_name,
                "severity": "Critical",
                "description": f"SQL Injection in parameter '{param_name}'",
            })

        if self.detectors["xss"].test_url_parameter(url, param_name):
            findings.append({
                "type": "Cross-Site Scripting (XSS)",
                "url": url,
                "parameter": param_name,
                "severity": "High",
                "description": f"Reflected XSS in parameter '{param_name}'",
            })

        if self.detectors["open_redirect"].test_url_parameter(url, param_name):
            findings.append({
                "type": "Open Redirect",
                "url": url,
                "parameter": param_name,
                "severity": "Medium",
                "description": f"Open Redirect in parameter '{param_name}'",
            })

        if self.detectors["ssrf"].test_url_parameter(url, param_name):
            findings.append({
                "type": "Server-Side Request Forgery (SSRF)",
                "url": url,
                "parameter": param_name,
                "severity": "Critical",
                "description": f"SSRF in parameter '{param_name}'",
            })

        if self.detectors["idor"].test_url_parameter(url, param_name):
            findings.append({
                "type": "Insecure Direct Object Reference (IDOR)",
                "url": url,
                "parameter": param_name,
                "severity": "High",
                "description": f"Potential IDOR in parameter '{param_name}'",
            })

        return findings

    def _test_form(self, form: Dict, url: str) -> List[Dict]:
        findings = []

        sqli_result = self.detectors["sqli"].test_form(form, url)
        if sqli_result:
            findings.append({
                "type": "SQL Injection",
                "url": url,
                "parameter": str(list(sqli_result.keys())[:1]),
                "form_action": form.get("action"),
                "severity": "Critical",
                "description": "SQL Injection in form submission",
                "details": sqli_result,
            })

        xss_result = self.detectors["xss"].test_form(form, url)
        if xss_result:
            findings.append({
                "type": "Cross-Site Scripting (XSS)",
                "url": url,
                "parameter": str(list(xss_result.keys())[:1]),
                "form_action": form.get("action"),
                "severity": "High",
                "description": "XSS in form submission",
                "details": xss_result,
            })

        csrf_result = self.detectors["csrf"].test_form(form, url)
        if csrf_result:
            findings.append({
                "type": "Cross-Site Request Forgery (CSRF)",
                "url": url,
                "parameter": "",
                "form_action": form.get("action"),
                "severity": "Medium",
                "description": "CSRF protection missing or inadequate",
                "details": csrf_result,
            })

        ssrf_result = self.detectors["ssrf"].test_form(form, url)
        if ssrf_result:
            findings.append({
                "type": "Server-Side Request Forgery (SSRF)",
                "url": url,
                "parameter": ssrf_result.get("field", ""),
                "form_action": form.get("action"),
                "severity": "Critical",
                "description": "SSRF in form field",
                "details": ssrf_result,
            })

        return findings

    # ──────────────────────────────────────────────────────────────────
    def _add_vulnerability(self, vuln: Dict):
        """
        Add a vulnerability record.
        Dedup key = (type, url, parameter) – fixes the original bug where
        two different parameters on the same URL collapsed to one finding.
        """
        vuln.setdefault("timestamp", datetime.now().isoformat())
        vuln.setdefault("id", f"VULN-{len(self.vulnerabilities) + 1:04d}")

        dedup_key = (
            vuln.get("type", ""),
            vuln.get("url", ""),
            vuln.get("parameter", ""),
        )
        if dedup_key in self._vuln_keys:
            return
        self._vuln_keys.add(dedup_key)

        self.vulnerabilities.append(vuln)

        color = {
            "Critical": Fore.RED,
            "High": Fore.LIGHTRED_EX,
            "Medium": Fore.YELLOW,
            "Low": Fore.GREEN,
            "Info": Fore.CYAN,
        }.get(vuln.get("severity", "Info"), Fore.WHITE)

        print(
            f"{color}[!] {vuln.get('severity','?')}: "
            f"{vuln.get('type','?')} – {vuln.get('url','')}"
            f"{' [param: ' + vuln['parameter'] + ']' if vuln.get('parameter') else ''}"
            f"{Style.RESET_ALL}"
        )

    # ──────────────────────────────────────────────────────────────────
    def _analyze_results(self):
        by_type: Dict[str, List] = {}
        for v in self.vulnerabilities:
            by_type.setdefault(v["type"], []).append(v)
        self.scan_stats["vulnerabilities_by_type"] = {k: len(v) for k, v in by_type.items()}

    def _print_summary(self):
        duration = self.scan_stats["end_time"] - self.scan_stats["start_time"]
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in self.vulnerabilities:
            sev = v.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                        SCAN SUMMARY                          ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
Target    : {self.target_url}
Duration  : {duration}
URLs      : {self.scan_stats['urls_crawled']}
Forms     : {self.scan_stats['forms_tested']}
Parameters: {self.scan_stats['parameters_tested']}

{Fore.CYAN}VULNERABILITIES: {len(self.vulnerabilities)}{Style.RESET_ALL}
{Fore.RED}  Critical : {counts['Critical']}{Style.RESET_ALL}
{Fore.LIGHTRED_EX}  High     : {counts['High']}{Style.RESET_ALL}
{Fore.YELLOW}  Medium   : {counts['Medium']}{Style.RESET_ALL}
{Fore.GREEN}  Low      : {counts['Low']}{Style.RESET_ALL}
{Fore.CYAN}  Info     : {counts['Info']}{Style.RESET_ALL}
""")

"""
Configuration settings for Web Vulnerability Scanner v5.0
"""

import os
from pathlib import Path

# ── Base paths ─────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.parent
LOGS_DIR   = Path(os.environ.get("LOGS_DIR",   str(BASE_DIR / "logs")))
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", str(BASE_DIR / "output")))

LOGS_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# ── Scanner defaults ────────────────────────────────────────────────────────
SCANNER_CONFIG = {
    "max_depth":       3,
    "max_urls":        500,
    "request_timeout": 30,
    "threads":         10,
    "delay":           0.5,
    # Coverage: seed the crawl frontier from robots.txt (Sitemap: lines and
    # Disallow/Allow paths) and sitemap.xml (recursively, for sitemap-index
    # files). Finds pages that exist but aren't linked from anywhere the
    # crawler visits — set False to restrict the scan strictly to
    # link-reachable pages.
    "crawl_robots_sitemap": True,
    # Realistic browser UA so targets don't block the scanner
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    # SECURITY: verify_ssl defaults TRUE.
    # Override with --no-verify-ssl CLI flag or verify_ssl=False in scan_config
    # only for self-signed-cert targets in controlled environments.
    "verify_ssl":        True,
    "follow_redirects":  True,
}

# ── OWASP ZAP ──────────────────────────────────────────────────────────────
ZAP_CONFIG = {
    "enabled":          False,
    "proxy":            os.environ.get("ZAP_PROXY", "http://localhost:8080"),
    "api_key":          os.environ.get("ZAP_API_KEY", ""),
    "spider_max_depth": 5,
    "active_scan":      True,
}

# ── Vulnerability detection ─────────────────────────────────────────────────
DETECTION_CONFIG = {
    "sql_injection": {
        "enabled": True,
        "error_patterns": [
            # MySQL
            "sql syntax",
            "mysql_fetch",
            "warning: mysql",
            "you have an error in your sql syntax",
            "supplied argument is not a valid mysql",
            "unknown column",
            "column count doesn't match",
            "table doesn't exist",
            "mysql_num_rows",
            "mysql_query",
            # PostgreSQL
            "pg_query",
            "psql:",
            "unterminated string literal",
            "pg::error",
            "pgerror",
            # MSSQL
            "microsoft ole db provider",
            "odbc sql server driver",
            "unclosed quotation mark",
            "incorrect syntax near",
            "sqlstate",
            "conversion failed when converting",
            "arithmetic overflow error",
            # Oracle
            # (bare "ora-" removed — Oracle errors matched via
            # ORA-##### regex in sqli_detector._matches_error_pattern())
            "quoted string not properly terminated",
            "ora-00907",
            # SQLite
            "sqlite_query",
            "sqlite3",
            "near \".\": syntax error",
            # Generic
            "error in your sql",
            "division by zero",
            "invalid query",
            "sql error",
            "database error",
            "query failed",
        ],
        "time_based_delay": 5,
    },
    "xss": {
        "enabled": True,
        "payloads": [
            # Use numeric alert(1) — shorter, WAF-bypass friendly,
            # unambiguous (won't match alert('string') already on page)
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            # Attribute injection context
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            # WAF bypass variants
            "<ScRiPt>alert(1)</sCrIpT>",
            "<img src=x onerror=\"alert(1)\">",
            "<svg/onload=alert(1)>",
            # Template literal / JS context
            "${alert(1)}",
            "{{constructor.constructor('alert(1)')()}}",
            # DOM-based (hash fragment — many apps put hash value into DOM)
            "javascript:alert(1)",
        ],
        "confirmatory_payloads": [
            "<script>confirm(1)</script>",
            "<script>prompt(1)</script>",
        ],
    },
    "csrf": {
        "enabled": True,
        "check_token_patterns": [
            "csrf",
            "xsrf",
            "_token",
            "authenticity_token",
            "__requestverificationtoken",
            "csrfmiddlewaretoken",
            "_csrf_token",
            "nonce",
        ],
    },
    "open_redirect": {
        "enabled": True,
        "payloads": [
            "//evil.com",
            "https://evil.com",
            "http://evil.com",
            "/\\evil.com",
            "///evil.com",
        ],
        # Parameters that are likely redirect targets
        "param_names": [
            "redirect", "redirect_to", "redirect_url", "redirecturl",
            "return", "return_to", "returnto", "returnurl",
            "next", "goto", "url", "link", "target", "dest",
            "destination", "continue", "forward", "location",
            "callback", "back", "ref", "referer",
        ],
    },
    "directory_traversal": {
        "enabled": True,
        "payloads": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%5c..%5c..%5cwindows%5cwin.ini",
        ],
        "indicators": [
            "root:x:",
            "root:*:",
            "[boot loader]",
            "for 16-bit app support",
        ],
    },
}

# ── Report ──────────────────────────────────────────────────────────────────
REPORT_CONFIG = {
    "company_name": os.environ.get("SCANNER_COMPANY", "Security Assessment Team"),
    "logo_path":    None,
}

# ── Logging ─────────────────────────────────────────────────────────────────
LOGGING_CONFIG = {
    "level":  os.environ.get("LOG_LEVEL", "INFO"),
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file":   LOGS_DIR / "scanner.log",
}

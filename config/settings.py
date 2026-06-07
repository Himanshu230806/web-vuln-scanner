"""
Configuration settings for Web Vulnerability Scanner
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / "logs"
OUTPUT_DIR = BASE_DIR / "output"

# Create directories if they don't exist
LOGS_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# Scanner Configuration
SCANNER_CONFIG = {
    "max_depth": 3,
    "max_urls": 500,
    "request_timeout": 30,
    "threads": 10,
    "delay": 0.5,  # Delay between requests (seconds)
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "verify_ssl": False,
    "follow_redirects": True,
}

# OWASP ZAP Configuration
ZAP_CONFIG = {
    "enabled": True,
    "proxy": "http://localhost:8080",
    "api_key": os.getenv("ZAP_API_KEY", ""),
    "spider_max_depth": 5,
    "active_scan": True,
}

# Selenium Configuration
SELENIUM_CONFIG = {
    "headless": True,
    "window_size": "1920,1080",
    "page_load_timeout": 30,
    "implicit_wait": 10,
}

# Vulnerability Detection Thresholds
DETECTION_CONFIG = {
    "sql_injection": {
        "enabled": True,
        "error_patterns": [
            "sql syntax",
            "mysql_fetch",
            "pg_query",
            "ora-",
            "microsoft ole db provider",
            "odbc sql server driver",
            "sqlite_query",
            "supplied argument is not a valid mysql",
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
        ],
        "time_based_delay": 5,
    },
    "xss": {
        "enabled": True,
        "payloads": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'-alert(1)-'",
            "\"><img src=x onerror=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
        ],
        "confirmatory_payloads": [
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>",
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
            "https:evil.com",
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
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
        ],
        "indicators": [
            "root:x:",
            "[boot loader]",
            "for 16-bit app support",
            "etc/passwd",
            "windows\\system32",
        ],
    },
}

# Report Configuration
REPORT_CONFIG = {
    "company_name": "Security Assessment Team",
    "logo_path": None,
    "include_screenshots": True,
    "severity_colors": {
        "Critical": "#FF0000",
        "High": "#FF6600",
        "Medium": "#FFCC00",
        "Low": "#0066FF",
        "Info": "#00CC00",
    },
}

# Logging Configuration
LOGGING_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": LOGS_DIR / "scanner.log",
}

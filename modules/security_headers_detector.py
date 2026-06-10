"""
Security Headers Detection Module
Checks for missing or misconfigured HTTP security headers
"""

import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


class SecurityHeadersDetector:
    """
    Checks HTTP response headers for security misconfigurations.
    Covers OWASP A05:2021 – Security Misconfiguration.
    """

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "High",
            "description": "HTTP Strict Transport Security (HSTS) is missing. Browsers may allow "
                           "insecure HTTP connections to this host.",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "Content-Security-Policy": {
            "severity": "High",
            "description": "Content-Security-Policy header is absent. Without CSP, the browser "
                           "permits inline scripts and arbitrary resource loading, enabling XSS attacks.",
            "recommendation": "Define a strict CSP. Minimum: Content-Security-Policy: default-src 'self'",
        },
        "X-Frame-Options": {
            "severity": "Medium",
            "description": "X-Frame-Options header is missing. The page may be embedded in iframes "
                           "on other domains, enabling clickjacking attacks.",
            "recommendation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing from the same origin is needed)",
        },
        "X-Content-Type-Options": {
            "severity": "Medium",
            "description": "X-Content-Type-Options header is absent. Browsers may MIME-sniff "
                           "responses and execute scripts from non-script content types.",
            "recommendation": "Add: X-Content-Type-Options: nosniff",
        },
        "Referrer-Policy": {
            "severity": "Low",
            "description": "Referrer-Policy header is missing. Sensitive URL parameters may be "
                           "leaked to third-party sites via the Referer header.",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "severity": "Low",
            "description": "Permissions-Policy (formerly Feature-Policy) header is absent. "
                           "Browser features such as camera, microphone, and geolocation are unrestricted.",
            "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        },
    }

    DANGEROUS_HEADER_VALUES = {
        "X-Powered-By": {
            "severity": "Info",
            "description": "X-Powered-By header exposes server technology ({value}), "
                           "aiding attacker reconnaissance.",
            "recommendation": "Remove X-Powered-By from responses (e.g., unset it in Nginx/Apache config).",
        },
        "Server": {
            "severity": "Info",
            "description": "Server header reveals version information ({value}). "
                           "This helps attackers identify known CVEs for your stack.",
            "recommendation": "Configure your server to return a generic Server value or omit it entirely.",
        },
    }

    COOKIE_CHECKS = {
        "secure_flag": {
            "severity": "High",
            "description": "Session cookie '{name}' is missing the Secure flag and may be "
                           "transmitted over unencrypted HTTP connections.",
            "recommendation": "Set the Secure attribute on all sensitive cookies.",
        },
        "httponly_flag": {
            "severity": "High",
            "description": "Cookie '{name}' is missing the HttpOnly flag, making it accessible "
                           "via JavaScript and vulnerable to cookie theft through XSS.",
            "recommendation": "Set the HttpOnly attribute on all sensitive cookies.",
        },
        "samesite_flag": {
            "severity": "Medium",
            "description": "Cookie '{name}' does not have a SameSite attribute, leaving it "
                           "vulnerable to cross-site request forgery.",
            "recommendation": "Set SameSite=Strict or SameSite=Lax on session cookies.",
        },
    }

    SENSITIVE_COOKIE_PATTERNS = ["session", "auth", "token", "user", "login", "jwt", "id"]

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config

    def scan(self, url: str) -> List[Dict]:
        """
        Run all header and cookie checks against the given URL.
        Returns a list of vulnerability dicts compatible with the scanner engine.
        """
        findings = []
        try:
            response = self.session.get(
                url,
                timeout=self.config.get("request_timeout", 15),
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug(f"SecurityHeadersDetector: request failed for {url}: {exc}")
            return findings

        findings.extend(self._check_missing_headers(response, url))
        findings.extend(self._check_dangerous_headers(response, url))
        findings.extend(self._check_cookies(response, url))
        findings.extend(self._check_https(url, response))

        return findings

    # ------------------------------------------------------------------
    def _check_missing_headers(self, response: requests.Response, url: str) -> List[Dict]:
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        for header_name, meta in self.REQUIRED_HEADERS.items():
            if header_name.lower() not in headers_lower:
                findings.append({
                    "type": "Security Header Missing",
                    "subtype": header_name,
                    "url": url,
                    "severity": meta["severity"],
                    "description": f"Missing header: {header_name}. {meta['description']}",
                    "recommendation": meta["recommendation"],
                    "evidence": f"Header '{header_name}' not present in response",
                })
        return findings

    def _check_dangerous_headers(self, response: requests.Response, url: str) -> List[Dict]:
        findings = []
        for header_name, meta in self.DANGEROUS_HEADER_VALUES.items():
            value = response.headers.get(header_name)
            if value:
                findings.append({
                    "type": "Information Disclosure",
                    "subtype": header_name,
                    "url": url,
                    "severity": meta["severity"],
                    "description": meta["description"].format(value=value),
                    "recommendation": meta["recommendation"],
                    "evidence": f"{header_name}: {value}",
                })
        return findings

    def _check_cookies(self, response: requests.Response, url: str) -> List[Dict]:
        findings = []
        for cookie in response.cookies:
            name_lower = cookie.name.lower()
            is_sensitive = any(p in name_lower for p in self.SENSITIVE_COOKIE_PATTERNS)
            if not is_sensitive:
                continue

            if not cookie.secure:
                findings.append(self._cookie_finding(
                    "secure_flag", cookie.name, url
                ))
            # python-requests does not expose HttpOnly/SameSite directly;
            # check raw Set-Cookie headers instead
            raw_set_cookie = self._get_raw_set_cookie(response, cookie.name)
            if raw_set_cookie:
                if "httponly" not in raw_set_cookie.lower():
                    findings.append(self._cookie_finding(
                        "httponly_flag", cookie.name, url
                    ))
                if "samesite" not in raw_set_cookie.lower():
                    findings.append(self._cookie_finding(
                        "samesite_flag", cookie.name, url
                    ))
        return findings

    def _check_https(self, url: str, response: requests.Response) -> List[Dict]:
        findings = []
        if url.startswith("http://") and not url.startswith("https://"):
            findings.append({
                "type": "Insecure Transport",
                "subtype": "HTTP",
                "url": url,
                "severity": "High",
                "description": "The target is served over plain HTTP without TLS encryption. "
                               "All traffic including credentials is transmitted in cleartext.",
                "recommendation": "Redirect all HTTP traffic to HTTPS and obtain a valid TLS certificate.",
                "evidence": f"URL scheme is http://",
            })
        return findings

    # ------------------------------------------------------------------
    def _cookie_finding(self, check_key: str, cookie_name: str, url: str) -> Dict:
        meta = self.COOKIE_CHECKS[check_key]
        return {
            "type": "Insecure Cookie",
            "subtype": check_key,
            "url": url,
            "severity": meta["severity"],
            "description": meta["description"].format(name=cookie_name),
            "recommendation": meta["recommendation"],
            "evidence": f"Cookie name: {cookie_name}",
        }

    @staticmethod
    def _get_raw_set_cookie(response: requests.Response, cookie_name: str) -> Optional[str]:
        """Return the raw Set-Cookie header string for a given cookie name."""
        for header_value in response.raw.headers.getlist("Set-Cookie"):
            if header_value.split("=")[0].strip().lower() == cookie_name.lower():
                return header_value
        return None

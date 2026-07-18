"""
SSRF Detector v2 — uses SSRFVerifier for two-stage confirmation.
"""

import logging
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

from modules.scan_utils import get_baseline, matches_baseline
from modules.verification_engine import SSRFVerifier, VerifiedFinding

logger = logging.getLogger(__name__)


class SSRFDetector:

    URL_PARAM_PATTERNS = [
        "url", "uri", "src", "source", "href", "link", "redirect",
        "callback", "fetch", "load", "file", "path", "resource",
        "endpoint", "host", "server", "proxy", "request", "data",
        "img", "image", "avatar", "icon", "feed", "api",
        # Additional patterns commonly found in real apps
        "target", "webhook", "notify", "ping", "import", "export",
        "download", "upload", "remote", "extern", "outbound",
        "thumb", "thumbnail", "preview", "logo", "photo",
        "img_url", "image_url", "file_url", "avatar_url",
        "return_url", "next_url", "redirect_url", "forward_url",
        "service", "wsdl", "dtd", "xml", "rss", "atom",
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session  = session
        self.config   = config
        self.verifier = SSRFVerifier(session, config)

    def test_url_parameter(self, url: str, param_name: str) -> bool:
        """Returns True if SSRF confirmed (for scanner compatibility)."""
        finding = self.verify_url_parameter(url, param_name)
        return finding is not None

    def verify_url_parameter(self, url: str, param_name: str) -> Optional[Dict]:
        """Returns a full verified finding dict or None."""
        if not self._is_url_param(param_name):
            return None

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if param_name not in params:
            return None

        baseline = get_baseline(self.session, url, self.config)

        def build_url(probe_url: str) -> str:
            p = params.copy()
            p[param_name] = probe_url
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(p, doseq=True), parsed.fragment
            ))

        finding = self.verifier.verify(url, param_name, build_url)
        if finding:
            return finding.to_dict()
        return None

    def test_form(self, form: Dict, url: str) -> Optional[Dict]:
        action  = form.get("action", url)
        method  = form.get("method", "GET").upper()
        inputs  = form.get("inputs", [])

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

        baseline = get_baseline(self.session, action, self.config)

        for inp in url_inputs:
            def build_url_form(probe_url: str) -> str:
                return action  # POST — just signal the field name

            # Build a request-based probe for form fields
            finding = self._probe_form_field(
                action, method, base_data, inp["name"], baseline
            )
            if finding:
                return finding

        return None

    def _probe_form_field(self, action, method, base_data, field_name, baseline):
        from modules.verification_engine import Evidence, VerifiedFinding, CONFIDENCE_HIGH

        verifier = self.verifier

        for probe_url, indicators in verifier.PRIMARY_PROBES:
            data = {**base_data, field_name: probe_url}
            try:
                if method == "POST":
                    resp = self.session.post(action, data=data,
                                             timeout=self.config.get("request_timeout", 15))
                else:
                    resp = self.session.get(action, params=data,
                                            timeout=self.config.get("request_timeout", 15))

                if matches_baseline(resp, baseline):
                    continue

                body = resp.text.lower()
                for ind in indicators:
                    if ind.lower() in body:
                        pos     = body.find(ind.lower())
                        excerpt = resp.text[max(0, pos-30):pos+120].strip()

                        finding = VerifiedFinding(
                            vuln_type   = "Server-Side Request Forgery (SSRF)",
                            url         = action,
                            parameter   = field_name,
                            severity    = "Critical",
                            confidence  = 70,
                            owasp       = "A10 – SSRF",
                            description = (
                                f"Form field '{field_name}' fetches arbitrary URLs server-side. "
                                f"Probing with '{probe_url}' returned a matching indicator."
                            ),
                            evidence = Evidence(
                                probe_url        = action,
                                probe_payload    = probe_url,
                                response_status  = resp.status_code,
                                response_excerpt = excerpt,
                                matched_pattern  = ind,
                                verification_note= "Form-field SSRF probe — single-stage confirmation",
                            ),
                        )
                        return finding.to_dict()
            except Exception as exc:
                logger.debug("SSRF form probe error: %s", exc)

        return None

    def _is_url_param(self, name: str) -> bool:
        name_lower = name.lower()
        return any(p in name_lower for p in self.URL_PARAM_PATTERNS)

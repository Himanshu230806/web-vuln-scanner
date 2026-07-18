"""
CSRF Detector v2 — uses CSRFVerifier for multi-signal detection.
"""

import logging
from typing import Dict, Optional
from urllib.parse import urlparse

import requests

from modules.verification_engine import CSRFVerifier, VerifiedFinding

logger = logging.getLogger(__name__)


class CSRFDetector:

    def __init__(self, session: requests.Session, config: Dict):
        self.session  = session
        self.config   = config
        self.verifier = CSRFVerifier()

    def test_form(self, form: Dict, url: str) -> Optional[Dict]:
        finding = self.verifier.verify(form, url, self.session, self.config)
        if finding:
            # Return compatible dict for scanner engine
            result = finding.to_dict()
            # Also return legacy 'issues' key for backward compat
            result["issues"] = [finding.description]
            result["recommendation"] = (
                "Add a synchronizer CSRF token to all state-changing forms. "
                "Additionally set SameSite=Strict on session cookies."
            )
            return result
        return None

    def check_cookie_protection(self, url: str) -> Dict:
        """Check cookie security attributes."""
        try:
            resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
            issues = []
            for cookie in resp.cookies:
                if "session" in cookie.name.lower():
                    if not cookie.secure:
                        issues.append(f"Cookie '{cookie.name}' missing Secure flag")
            return {"issues": issues, "cookies_found": [c.name for c in resp.cookies]}
        except Exception:
            return {}

"""
Insecure Direct Object Reference (IDOR) Detection Module
OWASP A01:2021 – Broken Access Control
"""

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)


class IDORDetector:
    """
    Detects potential IDOR vulnerabilities by identifying numeric / UUID
    parameters and testing whether responses change meaningfully when the
    ID is incremented/decremented or replaced with a different UUID.

    A significant content difference between the original and modified
    response — while both return 200 — is flagged as a potential IDOR.
    """

    # Parameters that commonly hold object IDs
    ID_PARAM_PATTERNS = [
        "id", "user_id", "account", "profile", "order", "invoice",
        "doc", "document", "file", "item", "record", "entry", "post",
        "comment", "ticket", "report", "customer", "client", "uid",
        "pid", "oid", "rid", "num", "number", "ref", "key",
    ]

    UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    NUMERIC_RE = re.compile(r"^\d+$")

    # Minimum response body difference (chars) to consider as "different content"
    DIFF_THRESHOLD = 200

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config

    def test_url_parameter(self, url: str, param_name: str) -> bool:
        if not self._is_id_param(param_name):
            return False

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if param_name not in params:
            return False

        original_value = params[param_name][0]
        alt_value = self._generate_alternative(original_value)

        if alt_value is None:
            return False

        try:
            original_resp = self.session.get(
                url, timeout=self.config.get("request_timeout", 15)
            )
            if original_resp.status_code != 200:
                return False

            params[param_name] = alt_value
            alt_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), parsed.fragment
            ))
            alt_resp = self.session.get(
                alt_url, timeout=self.config.get("request_timeout", 15)
            )

            if alt_resp.status_code == 200:
                diff = abs(len(original_resp.text) - len(alt_resp.text))
                if diff > self.DIFF_THRESHOLD and len(alt_resp.text) > 100:
                    logger.warning(
                        f"Potential IDOR in '{param_name}' at {url} "
                        f"(content diff {diff} chars)"
                    )
                    return True

        except Exception as exc:
            logger.debug(f"IDOR test error: {exc}")

        return False

    def test_path_ids(self, url: str) -> Optional[Dict]:
        """
        Detect numeric / UUID path segments and test by incrementing them.
        e.g. /users/42/profile → /users/43/profile
        """
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        for idx, seg in enumerate(segments):
            alt = self._generate_alternative(seg)
            if alt is None:
                continue

            new_segments = segments.copy()
            new_segments[idx] = alt
            new_path = "/".join(new_segments)
            alt_url = urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, parsed.fragment
            ))
            try:
                orig_resp = self.session.get(
                    url, timeout=self.config.get("request_timeout", 15)
                )
                alt_resp = self.session.get(
                    alt_url, timeout=self.config.get("request_timeout", 15)
                )
                if (orig_resp.status_code == 200
                        and alt_resp.status_code == 200
                        and abs(len(orig_resp.text) - len(alt_resp.text)) > self.DIFF_THRESHOLD
                        and len(alt_resp.text) > 100):
                    return {"original_segment": seg, "alt_segment": alt, "alt_url": alt_url}
            except Exception as exc:
                logger.debug(f"Path IDOR test error: {exc}")

        return None

    # ------------------------------------------------------------------
    def _is_id_param(self, name: str) -> bool:
        name_lower = name.lower()
        return any(p in name_lower for p in self.ID_PARAM_PATTERNS)

    def _generate_alternative(self, value: str) -> Optional[str]:
        """Return a plausible alternative ID value, or None if not applicable."""
        if self.NUMERIC_RE.match(value):
            num = int(value)
            # Avoid testing 0 or negative IDs
            return str(num + 1) if num > 0 else str(num + 2)
        if self.UUID_RE.match(value):
            # Flip one character to produce a different UUID
            chars = list(value)
            # Change last hex digit
            last_hex_pos = len(chars) - 1
            chars[last_hex_pos] = "f" if chars[last_hex_pos] != "f" else "0"
            return "".join(chars)
        return None

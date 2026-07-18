"""
Insecure Direct Object Reference (IDOR) Detection Module
OWASP A01:2021 – Broken Access Control
"""

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

from modules.scan_utils import is_significant_difference

logger = logging.getLogger(__name__)


class IDORDetector:
    """
    Detects potential IDOR vulnerabilities by identifying numeric / UUID
    parameters and testing whether responses change meaningfully when the
    ID is incremented/decremented or replaced with a different UUID.

    Accuracy notes:
      - A "content differs between IDs" heuristic alone is extremely
        noisy: dynamic content (CSRF tokens, timestamps, ad slots,
        "N users online" widgets, randomly-ordered recommendations) makes
        almost ANY two requests to the same endpoint differ somewhat —
        even for the EXACT SAME id. The old 200-character absolute
        threshold flagged this constantly.
      - We now first measure the page's NATURAL VARIANCE by requesting
        the ORIGINAL id twice and comparing those two responses. The
        difference between the original id and the alternate id must
        be SIGNIFICANTLY LARGER than this natural variance (not just
        larger than a fixed constant) before we flag it.
      - We also require both an absolute AND a relative size difference
        (via is_significant_difference) so large pages with small dynamic
        deltas aren't flagged, and tiny pages with big relative changes
        still are.
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

    # A 200-status response that's clearly an "access denied" / "not
    # authorized" page is the app working CORRECTLY (many apps return 200
    # with a friendly denial message instead of a proper 403/404) — not
    # evidence of IDOR. Without this check, that denial page's different
    # content/length from the original resource would itself trigger a
    # false "IDOR" finding, which is backwards: it's evidence access
    # control IS working.
    ACCESS_DENIED_PATTERNS = [
        "access denied", "access is denied", "permission denied",
        "you don't have permission", "you do not have permission",
        "not authorized", "unauthorized access", "you are not authorized",
        "forbidden", "you don't have access", "no permission to view",
        "this resource is private", "you cannot view this",
    ]

    # Known, persistent limitation (documented, not silently hidden): this
    # detector can only prove a parameter is enumerable and that content
    # differs — it CANNOT know whether the alternate resource was meant to
    # be private (e.g. another user's invoice) vs. equally public by design
    # (e.g. a different product/article in a public catalog). Confirming
    # genuine cross-tenant access requires testing with a SECOND
    # authenticated identity and comparing — which this single-session
    # scanner does not do. Treat "Potential"/"Likely" classified IDOR
    # findings as leads to manually verify, not confirmed vulnerabilities.

    # Multiplier applied to a page's measured natural variance before the
    # alt-id difference is considered meaningful. e.g. if requesting the
    # SAME id twice naturally varies by 50 chars, the alt-id response must
    # differ by at least 50 * NATURAL_VARIANCE_MULTIPLIER chars.
    NATURAL_VARIANCE_MULTIPLIER = 4
    # Hard floor — even on a page with zero natural variance, require at
    # least this many characters of difference.
    MIN_ABS_DIFF = 300

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config

    def test_url_parameter(self, url: str, param_name: str) -> bool:
        return self.verify_url_parameter(url, param_name) is not None

    def verify_url_parameter(self, url: str, param_name: str) -> Optional[Dict]:
        """
        Full verification with structured evidence and confidence score.

        Confidence scales with how far the diff exceeds the natural
        variance threshold — a diff that's 10x the natural noise floor is
        much more convincing than one that's barely over the line.
        """
        from modules.verification_engine import VerifiedFinding, Evidence

        if not self._is_id_param(param_name):
            return None

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if param_name not in params:
            return None

        original_value = params[param_name][0]
        alt_value = self._generate_alternative(original_value)

        if alt_value is None:
            return None

        timeout = self.config.get("request_timeout", 15)

        try:
            orig_resp_1 = self.session.get(url, timeout=timeout)
            if orig_resp_1.status_code != 200:
                return None
            orig_resp_2 = self.session.get(url, timeout=timeout)
            if orig_resp_2.status_code != 200:
                return None

            natural_variance = abs(len(orig_resp_1.text) - len(orig_resp_2.text))

            params[param_name] = alt_value
            alt_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), parsed.fragment
            ))
            alt_resp = self.session.get(alt_url, timeout=timeout)

            if alt_resp.status_code != 200 or len(alt_resp.text) <= 100:
                return None

            # The "different content" here might just be the app correctly
            # denying access with a 200-status friendly error page rather
            # than a 403/404 — that's secure behavior, not IDOR.
            if self._looks_like_access_denied(alt_resp.text):
                return None

            diff = abs(len(orig_resp_1.text) - len(alt_resp.text))
            required_diff = max(self.MIN_ABS_DIFF,
                                natural_variance * self.NATURAL_VARIANCE_MULTIPLIER)

            if diff <= required_diff or not is_significant_difference(len(orig_resp_1.text), len(alt_resp.text)):
                return None

            logger.warning(
                f"Potential IDOR in '{param_name}' at {url} "
                f"(diff={diff} chars, natural variance={natural_variance}, required>{required_diff})"
            )

            # Scale confidence with how far past the threshold we are
            ratio = diff / max(required_diff, 1)
            if ratio >= 3:
                confidence = 85
            elif ratio >= 1.5:
                confidence = 70
            else:
                confidence = 55

            excerpt = alt_resp.text[:200].strip()

            finding = VerifiedFinding(
                vuln_type   = "Insecure Direct Object Reference (IDOR)",
                url         = url,
                parameter   = param_name,
                severity    = "High",
                confidence  = confidence,
                owasp       = "A01 – Broken Access Control",
                description = (
                    f"Parameter '{param_name}' returns substantially different content "
                    f"when changed from '{original_value}' to '{alt_value}', with no "
                    "authentication required to access the alternate resource."
                ),
                evidence = Evidence(
                    probe_url        = alt_url,
                    probe_payload    = f"{param_name}={alt_value} (original: {original_value})",
                    response_status  = alt_resp.status_code,
                    response_excerpt = excerpt,
                    matched_pattern  = f"Response length diff: {diff} chars (baseline noise: {natural_variance})",
                    verification_note= (
                        f"Diff is {ratio:.1f}x the page's natural variance threshold"
                    ),
                ),
            )
            return finding.to_dict()

        except Exception as exc:
            logger.debug(f"IDOR test error: {exc}")

        return None

    def test_path_ids(self, url: str) -> Optional[Dict]:
        """
        Detect numeric / UUID path segments and test by incrementing them.
        e.g. /users/42/profile → /users/43/profile

        Same natural-variance approach as test_url_parameter, applied to
        path segments.
        """
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        timeout = self.config.get("request_timeout", 15)

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
                orig_resp_1 = self.session.get(url, timeout=timeout)
                if orig_resp_1.status_code != 200:
                    continue
                orig_resp_2 = self.session.get(url, timeout=timeout)
                if orig_resp_2.status_code != 200:
                    continue

                natural_variance = abs(len(orig_resp_1.text) - len(orig_resp_2.text))

                alt_resp = self.session.get(alt_url, timeout=timeout)
                if alt_resp.status_code != 200 or len(alt_resp.text) <= 100:
                    continue
                if self._looks_like_access_denied(alt_resp.text):
                    continue

                diff = abs(len(orig_resp_1.text) - len(alt_resp.text))
                required_diff = max(self.MIN_ABS_DIFF,
                                    natural_variance * self.NATURAL_VARIANCE_MULTIPLIER)

                if diff > required_diff and is_significant_difference(len(orig_resp_1.text), len(alt_resp.text)):
                    return {"original_segment": seg, "alt_segment": alt, "alt_url": alt_url}
            except Exception as exc:
                logger.debug(f"Path IDOR test error: {exc}")

        return None

    # ------------------------------------------------------------------
    def _is_id_param(self, name: str) -> bool:
        name_lower = name.lower()
        return any(p in name_lower for p in self.ID_PARAM_PATTERNS)

    def _looks_like_access_denied(self, text: str) -> bool:
        excerpt = text[:2000].lower()
        return any(p in excerpt for p in self.ACCESS_DENIED_PATTERNS)

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

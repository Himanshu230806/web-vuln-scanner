"""
WAF Detector & Bypass Engine
==============================
Solves Problem 7: production apps that hide errors inside JSON bodies,
WAFs that return identical 403s for every payload, and WAF fingerprinting.

Three classes:

WAFDetector
───────────
Probes with a classic SQLi payload and fingerprints 9 WAFs via
headers/status/body. Reports detection as an Informational finding.

WAFBypassEngine
───────────────
Generates 10–13 bypass variants per payload (URL encoding, double
encoding, comment insertion SEL/**/ECT, case variation, tab/CR/LF
whitespace substitution, encoded space variants %09/%0a/%0d).
In _test_param(), if a payload returns 403/406/412/429 AND a WAF was
detected, bypass variants are automatically tried and the successful
variant is recorded with waf_bypass_used=True in the finding.

JSONErrorExtractor
──────────────────
Recursively walks JSON response trees to find SQL errors, stack traces,
and injection signals buried inside {"success":false,"message":"SQL error"}.
"""

import json
import logging
import re
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# ── 9 WAF fingerprints ─────────────────────────────────────────────────────────

WAF_HEADER_FINGERPRINTS: List[Tuple[str, str, str]] = [
    # (header_name, value_regex, waf_name)
    ("server",              r"cloudflare",                      "Cloudflare"),
    ("cf-ray",              r".*",                              "Cloudflare"),
    ("set-cookie",          r"__cfduid|cf_clearance",           "Cloudflare"),
    ("x-amzn-requestid",    r".*",                              "AWS WAF"),
    ("x-amz-cf-id",         r".*",                              "AWS WAF"),
    ("x-sucuri-id",         r".*",                              "Sucuri"),
    ("x-sucuri-cache",      r".*",                              "Sucuri"),
    ("set-cookie",          r"incap_ses|nlbi_|visid_incap",     "Imperva Incapsula"),
    ("x-iinfo",             r".*",                              "Imperva Incapsula"),
    ("x-cdn",               r"imperva",                         "Imperva Incapsula"),
    ("x-fw-hash",           r".*",                              "Wordfence"),
    ("x-protected-by",      r".*",                              "Generic WAF"),
    ("x-waf",               r".*",                              "Generic WAF"),
    ("x-powered-by",        r"akamai",                          "Akamai"),
    ("x-akamai-transformed",r".*",                              "Akamai"),
    ("server",              r"big-?ip",                         "F5 BIG-IP"),
    ("x-wa-info",           r".*",                              "F5 BIG-IP"),
    ("set-cookie",          r"barra_counter_session|BNI__BARRACUDA", "Barracuda"),
    ("x-datadome",          r".*",                              "DataDome"),
]

WAF_BODY_PATTERNS: List[Tuple[str, str]] = [
    (r"access denied.*cloudflare|ray id:",               "Cloudflare"),
    (r"mod_security|modsecurity",                        "ModSecurity"),
    (r"not acceptable.*server",                          "ModSecurity"),
    (r"sucuri websit(e|eprotection)",                    "Sucuri"),
    (r"akamai reference",                                "Akamai"),
    (r"the page (cannot|can't) be (displayed|found).*big.?ip",  "F5 BIG-IP"),
    (r"barracuda networks",                              "Barracuda"),
    (r"wordfence",                                       "Wordfence"),
    (r"imperva",                                         "Imperva Incapsula"),
    (r"aws.*waf|request blocked.*aws",                   "AWS WAF"),
    (r"this request has been blocked",                   "Generic WAF"),
    (r"request rejected.*security",                      "Generic WAF"),
]

WAF_STATUS_CODES = {403, 406, 412, 429, 501, 503}

# The probe payload sent to fingerprint a WAF
WAF_PROBE_PAYLOAD = "' OR 1=1--"


class WAFDetector:
    """
    Detect and fingerprint WAFs. Reports detection as an Informational
    finding so it appears in the PDF report's finding list.
    """

    def __init__(self, session: requests.Session, config: Dict):
        self.session        = session
        self.config         = config
        self._waf_name:     Optional[str] = None
        self._waf_confirmed = False
        self._checked       = False

    def detect(self, url: str) -> Optional[str]:
        """
        Probe with a SQLi payload and fingerprint any WAF.
        Returns WAF name or None. Caches result.
        """
        if self._checked:
            return self._waf_name
        self._checked = True

        try:
            # Probe with a classic SQLi payload in the URL
            probe_url = url + ("&" if "?" in url else "?") + f"q={WAF_PROBE_PAYLOAD}"
            resp = self.session.get(
                probe_url,
                timeout=self.config.get("request_timeout", 10),
                allow_redirects=True,
            )
            self._waf_name = self._fingerprint(resp)
            if self._waf_name:
                self._waf_confirmed = True
                logger.info("WAF detected: %s at %s", self._waf_name, url)
        except Exception as exc:
            logger.debug("WAF probe error: %s", exc)

        return self._waf_name

    def is_waf_present(self) -> bool:
        return self._waf_confirmed

    def is_blocked(self, response: requests.Response) -> bool:
        """True if this specific response looks like a WAF block."""
        if response.status_code in WAF_STATUS_CODES:
            return bool(self._fingerprint(response))
        body_lower = response.text[:3000].lower()
        return any(re.search(p, body_lower) for p, _ in WAF_BODY_PATTERNS)

    def as_finding(self, url: str) -> Optional[Dict]:
        """Return an Informational finding dict for the PDF report, or None."""
        if not self._waf_name:
            return None
        return {
            "type":             "WAF Detected",
            "url":              url,
            "severity":         "Info",
            "owasp":            "A05 – Security Misconfiguration",
            "confidence":       90,
            "confidence_label": "Confirmed",
            "classification":   "Informational",
            "cvss_estimate":    0.0,
            "evidence_score":   90,
            "description": (
                f"A Web Application Firewall ({self._waf_name}) was detected. "
                f"Some vulnerability probes may have been blocked before reaching "
                f"the application backend. Findings may be incomplete — manual "
                f"testing with WAF-bypass techniques is recommended."
            ),
            "evidence": (
                f"WAF fingerprinted as {self._waf_name} via response headers/body "
                f"when probing with a SQLi test payload."
            ),
            "remediation": (
                "WAF presence is not a vulnerability, but note that WAFs are "
                "not a substitute for fixing underlying vulnerabilities. "
                "This is an informational finding."
            ),
        }

    def waf_annotation(self) -> str:
        if self._waf_name:
            return (
                f"⚠️ WAF DETECTED ({self._waf_name}): some payloads may have been "
                f"blocked before reaching the application. Findings may be incomplete."
            )
        return ""

    def _fingerprint(self, response: requests.Response) -> Optional[str]:
        for header_name, pattern, waf_name in WAF_HEADER_FINGERPRINTS:
            val = response.headers.get(header_name, "")
            if val and re.search(pattern, val, re.IGNORECASE):
                return waf_name
        body_lower = response.text[:3000].lower()
        for pattern, waf_name in WAF_BODY_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                return waf_name
        return None


class WAFBypassEngine:
    """
    Generates WAF-bypass variants for a given payload and auto-retries
    blocked probes.

    Usage (inside a detector's _test_param method):

        bypass = WAFBypassEngine(waf_detector)
        result = bypass.try_with_bypass(
            session, "GET", test_url, None,
            payload, original_test_fn
        )
        if result:
            finding["waf_bypass_used"] = result["bypass_used"]
    """

    def __init__(self, waf_detector: WAFDetector):
        self.waf = waf_detector

    def generate_variants(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generate 10–13 bypass variants of the payload.
        Returns list of (variant_label, variant_payload).
        """
        variants: List[Tuple[str, str]] = []

        # 1. URL encoding (single)
        variants.append(("url_encoded", _url_encode(payload)))

        # 2. Double URL encoding
        variants.append(("double_url_encoded", _url_encode(_url_encode(payload))))

        # 3. SQL comment insertion (SEL/**/ECT style)
        if re.search(r"\bselect\b", payload, re.IGNORECASE):
            variants.append(("sql_comment", re.sub(
                r"(?i)\bSELECT\b", "SEL/**/ECT",
                re.sub(r"(?i)\bFROM\b", "FR/**/OM",
                re.sub(r"(?i)\bWHERE\b", "WHE/**/RE", payload))
            )))
        elif "'" in payload or "--" in payload:
            # Inject inline comment between words
            variants.append(("inline_comment", payload.replace(" ", "/**/")))

        # 4. Case variation
        variants.append(("case_variation", _case_vary(payload)))

        # 5. Tab substitution (space → tab)
        variants.append(("tab_space", payload.replace(" ", "\t")))

        # 6. CR substitution (space → \r)
        variants.append(("cr_space", payload.replace(" ", "\r")))

        # 7. LF substitution (space → \n)
        variants.append(("lf_space", payload.replace(" ", "\n")))

        # 8. %09 encoded space
        variants.append(("pct09_space", payload.replace(" ", "%09")))

        # 9. %0a encoded space (newline)
        variants.append(("pct0a_space", payload.replace(" ", "%0a")))

        # 10. %0d encoded space (carriage return)
        variants.append(("pct0d_space", payload.replace(" ", "%0d")))

        # 11. Mixed case + encoded space
        variants.append(("mixed_case_enc", _case_vary(payload).replace(" ", "%20")))

        # 12. Unicode normalization trick (some WAFs don't normalise before matching)
        try:
            variants.append(("unicode_fullwidth", _unicode_fullwidth(payload)))
        except Exception:
            pass

        # 13. HTML entity encoding (for XSS payloads)
        if "<" in payload or ">" in payload:
            variants.append(("html_entity", payload.replace("<", "&lt;").replace(">", "&gt;")))

        return variants[:13]

    def try_with_bypass(
        self,
        session: requests.Session,
        method: str,
        url: str,
        data: Optional[Dict],
        payload: str,
        test_fn,
        timeout: float = 15,
    ) -> Optional[Dict]:
        """
        If a probe is blocked (WAF status code), automatically try bypass
        variants. Returns dict with bypass_used and variant_payload if
        any variant succeeds (test_fn returns truthy), else None.

        test_fn signature: (response) -> bool
        """
        if not self.waf.is_waf_present():
            return None

        for label, variant in self.generate_variants(payload):
            try:
                if method.upper() == "POST" and data is not None:
                    probe_data = {k: v.replace(payload, variant)
                                  if v == payload else v
                                  for k, v in data.items()}
                    resp = session.post(url, data=probe_data, timeout=timeout,
                                        allow_redirects=True)
                else:
                    probe_url = url.replace(
                        requests.utils.quote(payload, safe=""),
                        requests.utils.quote(variant, safe="")
                    ) if requests.utils.quote(payload, safe="") in url else url
                    resp = session.get(probe_url, timeout=timeout,
                                       allow_redirects=True)

                # Skip variants that are also blocked
                if resp.status_code in WAF_STATUS_CODES:
                    continue

                if test_fn(resp):
                    return {
                        "bypass_used":    True,
                        "bypass_variant": label,
                        "bypass_payload": variant,
                    }
            except Exception:
                continue

        return None


# ── JSON error extraction ─────────────────────────────────────────────────────

JSON_ERROR_PATTERNS: List[Tuple[str, str]] = [
    (r"you have an error in your sql syntax",      "SQL Injection (MySQL error)"),
    (r"unclosed quotation mark",                   "SQL Injection (MSSQL error)"),
    (r"quoted string not properly terminated",     "SQL Injection (Oracle error)"),
    (r"pg_query\(\).*error",                       "SQL Injection (PostgreSQL error)"),
    (r"syntax error.*sql|sql syntax.*error",       "SQL Injection (generic)"),
    (r"mysql_fetch",                               "SQL Injection (MySQL leak)"),
    (r"ora-\d{4,5}",                               "SQL Injection (Oracle error)"),
    (r"invalid query",                             "SQL Injection (generic)"),
    (r"supplied argument is not a valid mysql",    "SQL Injection (MySQL error)"),
    (r"<script[^>]*>.*?</script>",                "XSS reflection"),
    (r"root:x:\d+:\d+:",                          "LFI/Path Traversal"),
    (r"bin:x:\d+:",                               "LFI/Path Traversal"),
    (r'"ami-id"|"instance-id"',                   "SSRF (AWS metadata)"),
    (r"stack trace|traceback \(most recent",       "Internal error exposure"),
    (r"at \w+\.\w+\(.*\.java:\d+\)",              "Java stack trace"),
    (r"exception in thread",                       "Java exception"),
    (r"system\.web\.httpexception",                "ASP.NET exception"),
]


class JSONErrorExtractor:

    def extract(self, response: requests.Response) -> Optional[Tuple[str, str, str]]:
        body = response.text.strip()
        if not body:
            return None
        content_type = response.headers.get("content-type", "").lower()
        is_json = "application/json" in content_type or body[:1] in ("{", "[")
        if not is_json:
            return None
        try:
            data = json.loads(body)
        except Exception:
            return None
        return self._walk(data, "$")

    def _walk(self, node, path: str) -> Optional[Tuple[str, str, str]]:
        if isinstance(node, str):
            text_lower = node.lower()
            for pattern, label in JSON_ERROR_PATTERNS:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    excerpt = node[:200] if len(node) > 200 else node
                    return (label, path, excerpt)
        elif isinstance(node, dict):
            for key, val in node.items():
                r = self._walk(val, f"{path}.{key}")
                if r:
                    return r
        elif isinstance(node, list):
            for i, item in enumerate(node[:20]):
                r = self._walk(item, f"{path}[{i}]")
                if r:
                    return r
        return None

    def check_response(self, response: requests.Response,
                       url: str, param: str) -> Optional[Dict]:
        result = self.extract(response)
        if not result:
            return None
        label, json_path, excerpt = result
        return {
            "json_error_label": label,
            "json_path":        json_path,
            "json_excerpt":     excerpt,
            "evidence_note": (
                f"Error pattern '{label}' found in JSON response "
                f"at path {json_path}: \"{excerpt}\""
            ),
        }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _url_encode(s: str) -> str:
    return "".join(f"%{ord(c):02X}" if not c.isalnum() else c for c in s)


def _case_vary(s: str) -> str:
    result = []
    toggle = True
    for c in s:
        if c.isalpha():
            result.append(c.upper() if toggle else c.lower())
            toggle = not toggle
        else:
            result.append(c)
    return "".join(result)


def _unicode_fullwidth(s: str) -> str:
    """Map ASCII printable chars to Unicode fullwidth equivalents."""
    result = []
    for c in s:
        code = ord(c)
        if 0x21 <= code <= 0x7E:
            result.append(chr(code + 0xFEE0))
        else:
            result.append(c)
    return "".join(result)

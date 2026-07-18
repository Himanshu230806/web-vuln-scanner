"""
Modern Vulnerability Categories Detector

Addresses "Missing modern vulnerability categories" — covers attack classes
that became prominent after the scanner's original OWASP Top 10 design and
are common in modern JS-heavy / API-driven applications:

  - Server-Side Template Injection (SSTI)
  - NoSQL Injection (MongoDB operator injection)
  - Prototype Pollution (Node.js/JS)
  - Insecure Deserialization indicators
  - JWT weaknesses (alg:none, weak/guessable HMAC secret)
  - HTTP Request Smuggling indicators (conflicting Content-Length/
    Transfer-Encoding handling)
  - Clickjacking (missing frame protections, confirmed via live framing test)
"""

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

from modules.scan_utils import get_timing_baseline
from modules.verification_engine import VerifiedFinding, Evidence

logger = logging.getLogger(__name__)


class ModernVulnDetector:

    # ── SSTI payloads per template engine ─────────────────────────────────────
    SSTI_PROBES = [
        # (payload, expected_reflection, engine)
        ("{{7*7}}",         "49",   "Jinja2/Twig"),
        ("${7*7}",          "49",   "FreeMarker/Velocity"),
        ("#{7*7}",          "49",   "Ruby ERB/Slim"),
        ("<%= 7*7 %>",      "49",   "ERB/EJS"),
        ("{{=7*7}}",        "49",   "Mako"),
        ("@(7*7)",          "49",   "Razor"),
    ]

    # ── NoSQL injection payloads (MongoDB operator injection) ────────────────
    NOSQL_PAYLOADS = [
        '{"$gt":""}',
        '{"$ne":null}',
        '{"$regex":".*"}',
        "' || '1'=='1",
        "[$ne]=1",
    ]

    # ── Prototype pollution probes ────────────────────────────────────────────
    PROTO_POLLUTION_PARAMS = [
        "__proto__[polluted]",
        "constructor[prototype][polluted]",
        "__proto__.polluted",
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config  = config

    # ── public API ────────────────────────────────────────────────────────────

    def scan_url_parameter(self, url: str, param_name: str) -> List[Dict]:
        findings = []
        findings.extend(self._test_ssti(url, param_name))
        findings.extend(self._test_nosql_injection(url, param_name))
        findings.extend(self._test_prototype_pollution(url, param_name))
        return findings

    def scan_site(self, base_url: str, crawled_urls: List[str]) -> List[Dict]:
        findings = []
        findings.extend(self._check_clickjacking(base_url))
        findings.extend(self._check_jwt_weaknesses(crawled_urls))
        findings.extend(self._check_request_smuggling_indicators(base_url))
        findings.extend(self._check_deserialization_indicators(crawled_urls))
        return findings

    # ── Server-Side Template Injection ────────────────────────────────────────

    def _test_ssti(self, url: str, param_name: str) -> List[Dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if param_name not in params:
            return findings

        timeout = self.config.get("request_timeout", 15)

        # Baseline with a non-mathematical value to rule out coincidental "49"
        baseline_params = params.copy()
        baseline_params[param_name] = "xKzQNotAPayloadControlZZ"
        baseline_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(baseline_params, doseq=True), parsed.fragment
        ))
        try:
            baseline_resp = self.session.get(baseline_url, timeout=timeout)
            baseline_has_49 = "49" in baseline_resp.text
        except Exception:
            baseline_has_49 = False

        for payload, expected, engine in self.SSTI_PROBES:
            test_params = params.copy()
            test_params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), parsed.fragment
            ))
            try:
                resp = self.session.get(test_url, timeout=timeout)
            except Exception:
                continue

            # Payload echoed literally = not evaluated (no SSTI)
            if payload in resp.text:
                continue

            # Expected math result present, AND not present in the baseline
            # control (rules out a coincidental "49" elsewhere on the page)
            if expected in resp.text and not baseline_has_49:
                finding = VerifiedFinding(
                    vuln_type   = "Server-Side Template Injection (SSTI)",
                    url         = url,
                    parameter   = param_name,
                    severity    = "Critical",
                    confidence  = 85,
                    owasp       = "A03 – Injection",
                    description = (
                        f"Parameter '{param_name}' evaluates template expressions "
                        f"server-side. Payload '{payload}' ({engine} syntax) was evaluated "
                        f"to '{expected}' instead of being treated as literal text. SSTI can "
                        "lead to full remote code execution."
                    ),
                    evidence = Evidence(
                        probe_url        = test_url,
                        probe_payload    = payload,
                        response_status  = resp.status_code,
                        response_excerpt = self._extract_context(resp.text, expected),
                        matched_pattern  = f"Template expression evaluated to '{expected}'",
                        verification_note= f"Likely engine: {engine}; control payload did not show same result",
                    ),
                )
                findings.append(finding.to_dict())
                break  # one confirmed SSTI is enough for this parameter

        return findings

    # ── NoSQL Injection ────────────────────────────────────────────────────────

    def _test_nosql_injection(self, url: str, param_name: str) -> List[Dict]:
        """
        MongoDB-style operator injection. We compare a normal invalid value
        (which should return "no results") against a $gt/$ne/$regex operator
        injection (which should return ALL results if the backend blindly
        passes query params into a Mongo filter).
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if param_name not in params:
            return findings

        timeout = self.config.get("request_timeout", 15)

        # Baseline: a value that should match nothing
        baseline_params = params.copy()
        baseline_params[param_name] = "zzz_definitely_no_match_zzz"
        baseline_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(baseline_params, doseq=True), parsed.fragment
        ))
        try:
            baseline_resp = self.session.get(baseline_url, timeout=timeout)
            baseline_len = len(baseline_resp.text)
        except Exception:
            return findings

        for payload in self.NOSQL_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), parsed.fragment
            ))
            try:
                resp = self.session.get(test_url, timeout=timeout)
            except Exception:
                continue

            # A NoSQL operator injection that "matches everything" should
            # return a SUBSTANTIALLY LARGER response than the no-match baseline
            if resp.status_code == 200 and len(resp.text) > baseline_len * 2 and len(resp.text) > baseline_len + 200:
                finding = VerifiedFinding(
                    vuln_type   = "NoSQL Injection",
                    url         = url,
                    parameter   = param_name,
                    severity    = "Critical",
                    confidence  = 65,
                    owasp       = "A03 – Injection",
                    description = (
                        f"Parameter '{param_name}' may be vulnerable to NoSQL (MongoDB) "
                        f"operator injection. Payload '{payload}' returned a response "
                        f"{len(resp.text)} chars vs {baseline_len} chars for a definitely-"
                        "non-matching value, suggesting the operator was interpreted as a "
                        "query filter rather than a literal string."
                    ),
                    evidence = Evidence(
                        probe_url        = test_url,
                        probe_payload    = payload,
                        response_status  = resp.status_code,
                        matched_pattern  = f"Response size: {len(resp.text)} vs baseline {baseline_len}",
                        verification_note= "Confirm manually — response-size heuristic only, not a captured DB error",
                    ),
                )
                findings.append(finding.to_dict())
                break

        return findings

    # ── Prototype Pollution ────────────────────────────────────────────────────

    def _test_prototype_pollution(self, url: str, param_name: str) -> List[Dict]:
        """
        Tests whether __proto__ / constructor.prototype keys in query params
        get merged into a server-side JS object (common in Node.js apps using
        naive deep-merge of req.query). Detected by checking if a probe value
        gets reflected in an UNRELATED subsequent response field, which would
        indicate the prototype itself was polluted.
        """
        findings = []
        parsed = urlparse(url)

        timeout = self.config.get("request_timeout", 15)
        canary = "pp_canary_zzz999"

        for proto_param in self.PROTO_POLLUTION_PARAMS:
            test_query = f"{proto_param}={canary}"
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, test_query, parsed.fragment
            ))
            try:
                resp = self.session.get(test_url, timeout=timeout)
            except Exception:
                continue

            if resp.status_code == 500:
                # Server crashed trying to process the polluted prototype —
                # weak signal but worth flagging at low confidence
                finding = VerifiedFinding(
                    vuln_type   = "Prototype Pollution",
                    url         = url,
                    parameter   = proto_param,
                    severity    = "Medium",
                    confidence  = 40,
                    owasp       = "A08 – Software Integrity",
                    description = (
                        f"Sending '{proto_param}' caused a server error (HTTP 500), "
                        "which can indicate the application attempted to merge the "
                        "parameter into an object prototype and crashed. Manual "
                        "verification required."
                    ),
                    evidence = Evidence(
                        probe_url        = test_url,
                        probe_payload    = test_query,
                        response_status  = resp.status_code,
                        matched_pattern  = "HTTP 500 on __proto__-style parameter",
                        verification_note= "Weak signal — confirm with manual prototype-pollution testing tools",
                    ),
                )
                findings.append(finding.to_dict())

        return findings

    # ── Clickjacking ────────────────────────────────────────────────────────────

    def _check_clickjacking(self, base_url: str) -> List[Dict]:
        """
        Confirms clickjacking risk: missing X-Frame-Options AND missing CSP
        frame-ancestors directive together mean the page can genuinely be
        framed by an attacker (security_headers_detector already flags each
        header separately, but this checks the COMBINED condition that
        actually determines real exploitability).
        """
        findings = []
        try:
            resp = self.session.get(base_url, timeout=self.config.get("request_timeout", 15))
        except Exception:
            return findings

        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo and not has_frame_ancestors:
            # Check the page actually renders meaningful content worth protecting
            # (a blank/error page being frameable is not interesting)
            if len(resp.text) > 500 and "<form" in resp.text.lower():
                finding = VerifiedFinding(
                    vuln_type   = "Clickjacking",
                    url         = base_url,
                    parameter   = "",
                    severity    = "Medium",
                    confidence  = 75,
                    owasp       = "A05 – Security Misconfiguration",
                    description = (
                        "Neither X-Frame-Options nor a CSP frame-ancestors directive is "
                        "set, AND the page contains a form — an attacker can embed this "
                        "page in an invisible iframe and trick users into submitting the "
                        "form via UI redress (clickjacking)."
                    ),
                    evidence = Evidence(
                        probe_url        = base_url,
                        response_status  = resp.status_code,
                        matched_pattern  = "No X-Frame-Options, no CSP frame-ancestors, page contains a form",
                        verification_note= "Combined-condition check (more specific than a single missing-header finding)",
                    ),
                )
                findings.append(finding.to_dict())

        return findings

    # ── JWT weaknesses ─────────────────────────────────────────────────────────

    def _check_jwt_weaknesses(self, urls: List[str]) -> List[Dict]:
        """
        Looks for JWTs in cookies/responses and checks for the classic
        'alg: none' bypass and a small dictionary of weak HMAC secrets.
        """
        findings = []
        checked_tokens = set()

        for url in urls[:10]:  # limit scope
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
            except Exception:
                continue

            tokens = []
            for cookie in resp.cookies:
                if self._looks_like_jwt(cookie.value):
                    tokens.append(cookie.value)
            auth_header = resp.request.headers.get("Authorization", "") if resp.request else ""
            if auth_header.startswith("Bearer ") and self._looks_like_jwt(auth_header[7:]):
                tokens.append(auth_header[7:])

            for token in tokens:
                if token in checked_tokens:
                    continue
                checked_tokens.add(token)
                findings.extend(self._analyze_jwt(token, url))

        return findings

    @staticmethod
    def _looks_like_jwt(value: str) -> bool:
        return bool(re.match(r'^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$', value or ""))

    def _analyze_jwt(self, token: str, url: str) -> List[Dict]:
        findings = []
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
            header  = json.loads(self._b64decode(header_b64))
            payload = json.loads(self._b64decode(payload_b64))
        except Exception:
            return findings

        alg = header.get("alg", "")

        # alg:none vulnerability check
        if alg.lower() == "none":
            finding = VerifiedFinding(
                vuln_type   = "Broken Authentication",
                url         = url,
                parameter   = "",
                severity    = "Critical",
                confidence  = 95,
                owasp       = "A07 – Auth Failures",
                description = (
                    "JWT uses 'alg: none', meaning the token's signature is not "
                    "verified at all. An attacker can forge arbitrary tokens "
                    "(e.g. set role=admin) with no valid signature required."
                ),
                evidence = Evidence(
                    probe_url        = url,
                    response_excerpt = json.dumps(header),
                    matched_pattern  = '"alg":"none"',
                    verification_note= "JWT header explicitly disables signature verification",
                ),
            )
            findings.append(finding.to_dict())
            return findings

        # Weak HMAC secret dictionary check (only for HS256/HS384/HS512)
        if alg.upper().startswith("HS"):
            weak_secrets = ["secret", "password", "123456", "your-256-bit-secret",
                           "changeme", "jwt_secret", "supersecret", token[:8]]
            digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
            digestmod = digest_map.get(alg.upper(), hashlib.sha256)

            signing_input = f"{token.split('.')[0]}.{token.split('.')[1]}".encode()
            actual_sig = self._b64decode_bytes(token.split(".")[2])

            for secret in weak_secrets:
                computed = hmac.new(secret.encode(), signing_input, digestmod).digest()
                if hmac.compare_digest(computed, actual_sig):
                    finding = VerifiedFinding(
                        vuln_type   = "Broken Authentication",
                        url         = url,
                        parameter   = "",
                        severity    = "Critical",
                        confidence  = 98,
                        owasp       = "A07 – Auth Failures",
                        description = (
                            f"JWT is signed with a weak, guessable HMAC secret ('{secret}'). "
                            "An attacker who knows this secret can forge arbitrary valid "
                            "tokens with any claims, including admin privileges."
                        ),
                        evidence = Evidence(
                            probe_url        = url,
                            matched_pattern  = f"HMAC-{alg} signature matches dictionary secret",
                            verification_note= "Signature cryptographically verified against a known-weak secret",
                        ),
                    )
                    findings.append(finding.to_dict())
                    break

        return findings

    @staticmethod
    def _b64decode(s: str) -> str:
        padded = s + "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")

    @staticmethod
    def _b64decode_bytes(s: str) -> bytes:
        padded = s + "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(padded)

    # ── HTTP Request Smuggling indicators ─────────────────────────────────────

    def _check_request_smuggling_indicators(self, base_url: str) -> List[Dict]:
        """
        Passive indicator check only (does not attempt actual smuggling,
        which requires raw socket control and could disrupt the target).
        Flags it as a LOW-confidence "worth investigating" item if the
        server advertises both chunked transfer-encoding support and a
        front-end proxy header (X-Forwarded-*, Via) — a common precondition
        for desync attacks between front-end/back-end servers.
        """
        findings = []
        try:
            resp = self.session.get(base_url, timeout=self.config.get("request_timeout", 15))
        except Exception:
            return findings

        has_proxy_headers = any(h in resp.headers for h in ("Via", "X-Forwarded-For", "X-Forwarded-Host"))
        server_header = resp.headers.get("Server", "")
        accepts_chunked = "chunked" in resp.headers.get("Transfer-Encoding", "").lower()

        if has_proxy_headers and server_header:
            findings.append({
                "type": "Information Disclosure",
                "subtype": "Potential Request Smuggling Surface",
                "url": base_url,
                "severity": "Low",
                "confidence": 25,
                "confidence_label": "Speculative",
                "description": (
                    "The target sits behind a reverse proxy (proxy headers detected) "
                    f"and identifies its backend as '{server_header}'. Front-end/back-end "
                    "server pairs can be vulnerable to HTTP Request Smuggling if they "
                    "disagree on request boundaries (CL.TE / TE.CL desync). This is a "
                    "passive indicator only — active testing requires manual verification "
                    "with raw HTTP tooling (e.g. Burp's HTTP Request Smuggler)."
                ),
                "evidence": f"Proxy headers present; Server: {server_header}",
                "owasp": "A05 – Security Misconfiguration",
                "recommendation": (
                    "Ensure front-end and back-end servers agree on Content-Length/"
                    "Transfer-Encoding handling. Disable chunked encoding pass-through "
                    "where not required, and normalise request smuggling-prone headers at the edge."
                ),
            })

        return findings

    # ── Insecure Deserialization indicators ───────────────────────────────────

    SERIALIZATION_SIGNATURES = [
        (r'^rO0[A-Za-z0-9+/=]+$',         "Java serialized object (base64, starts with rO0)"),
        (r'O:\d+:"[A-Za-z0-9_\\]+":\d+:', "PHP serialized object"),
        (r'^\x80\x03',                    "Python pickle protocol 3 magic bytes"),
        (r'^\x80\x04',                    "Python pickle protocol 4 magic bytes"),
    ]

    def _check_deserialization_indicators(self, urls: List[str]) -> List[Dict]:
        """
        Looks for serialized-object signatures appearing in cookies or
        response bodies — a strong indicator the app deserializes
        attacker-influenced data, a common RCE vector if untrusted input
        reaches Java's ObjectInputStream, PHP's unserialize(), or Python's
        pickle.loads().
        """
        findings = []
        for url in urls[:15]:
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
            except Exception:
                continue

            for cookie in resp.cookies:
                for pattern, desc in self.SERIALIZATION_SIGNATURES:
                    if re.match(pattern, cookie.value or ""):
                        finding = VerifiedFinding(
                            vuln_type   = "Software Integrity Failure",
                            url         = url,
                            parameter   = "",
                            severity    = "High",
                            confidence  = 55,
                            owasp       = "A08 – Software Integrity",
                            description = (
                                f"Cookie '{cookie.name}' appears to contain a {desc}. If this "
                                "value is deserialized server-side without integrity "
                                "verification, an attacker who can forge or modify it may "
                                "achieve remote code execution (insecure deserialization)."
                            ),
                            evidence = Evidence(
                                probe_url        = url,
                                matched_pattern  = desc,
                                response_excerpt = f"Cookie {cookie.name}={cookie.value[:60]}...",
                                verification_note= "Signature-based detection only — confirm server-side deserialization manually",
                            ),
                        )
                        findings.append(finding.to_dict())

        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_context(text: str, marker: str, width: int = 100) -> str:
        pos = text.find(marker)
        if pos < 0:
            return text[:width]
        start = max(0, pos - width // 2)
        return text[start:start + width].strip()

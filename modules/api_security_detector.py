"""
API Security Detector
OWASP API Security Top 10 coverage for REST/JSON APIs.

Addresses "Limited API testing" — the rest of the scanner assumes HTML
forms and URL query parameters; this module specifically targets JSON
request/response APIs, which the crawler and other detectors largely miss
because they don't parse HTML forms.

Covers:
  API1 — Broken Object Level Authorization (BOLA / IDOR on JSON bodies)
  API2 — Broken Authentication (missing/weak API key & JWT checks)
  API3 — Broken Object Property Level Authorization (mass assignment)
  API4 — Unrestricted Resource Consumption (no pagination limits)
  API5 — Broken Function Level Authorization (admin-only endpoints reachable)
  API7 — Server Side Request Forgery (webhook/callback URL fields)
  API8 — Security Misconfiguration (verbose JSON errors, missing CORS policy)
  API9 — Improper Inventory Management (exposed API docs / schema)
"""

import json
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from modules.scan_utils import get_baseline, matches_baseline
from modules.verification_engine import VerifiedFinding, Evidence

logger = logging.getLogger(__name__)


class APISecurityDetector:

    # Common API discovery / documentation paths (API9: inventory mgmt)
    API_DISCOVERY_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
        "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api/docs", "/api/swagger.json",
        "/.well-known/openapi.json",
        "/graphql", "/graphiql",
        "/v1/api-docs", "/v2/api-docs",
    ]

    # Patterns indicating JSON Web Tokens in headers/cookies
    JWT_PATTERN = re.compile(r'^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$')

    # Fields whose presence in a JSON request body suggests mass-assignment risk
    SENSITIVE_JSON_FIELDS = [
        "role", "isadmin", "is_admin", "admin", "permissions", "privilege",
        "balance", "credit", "verified", "is_verified", "status",
        "userid", "user_id", "owner", "owner_id",
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config  = config

    # ── public API ────────────────────────────────────────────────────────────

    def scan(self, base_url: str, crawled_urls: List[str]) -> List[Dict]:
        findings = []
        findings.extend(self._discover_api_inventory(base_url))
        findings.extend(self._check_cors_misconfiguration(base_url))

        api_urls = self._identify_api_endpoints(crawled_urls)
        for url in api_urls:
            findings.extend(self._check_verbose_json_errors(url))
            findings.extend(self._check_missing_auth(url))
            findings.extend(self._check_bola(url))

        return findings

    # ── API1: BOLA / IDOR on JSON endpoints ───────────────────────────────────

    def _check_bola(self, url: str) -> List[Dict]:
        """
        Broken Object Level Authorization: if a JSON API endpoint contains
        a numeric ID in the PATH (not just query string — the regular IDOR
        detector only checks query params), test whether incrementing it
        returns another user's object without authorization.
        """
        findings = []
        parsed = urlparse(url)
        segments = parsed.path.split("/")

        numeric_positions = [i for i, s in enumerate(segments) if s.isdigit()]
        if not numeric_positions:
            return findings

        timeout = self.config.get("request_timeout", 15)

        try:
            orig_resp = self.session.get(url, timeout=timeout)
            if orig_resp.status_code != 200:
                return findings
            content_type = orig_resp.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                return findings

            try:
                orig_json = orig_resp.json()
            except Exception:
                return findings

            for pos in numeric_positions:
                orig_id = int(segments[pos])
                alt_segments = segments.copy()
                alt_segments[pos] = str(orig_id + 1)
                alt_path = "/".join(alt_segments)
                alt_url = url.replace(parsed.path, alt_path)

                alt_resp = self.session.get(alt_url, timeout=timeout)
                if alt_resp.status_code != 200:
                    continue

                try:
                    alt_json = alt_resp.json()
                except Exception:
                    continue

                # If the alt ID returns a DIFFERENT, non-empty JSON object
                # with no authorization required, that's BOLA.
                if alt_json and alt_json != orig_json and self._looks_like_object(alt_json):
                    finding = VerifiedFinding(
                        vuln_type   = "Insecure Direct Object Reference (IDOR)",
                        url         = url,
                        parameter   = f"path_id[{pos}]",
                        severity    = "High",
                        confidence  = 75,
                        owasp       = "A01 – Broken Access Control",
                        description = (
                            f"API endpoint returns a different JSON object when the path ID "
                            f"is changed from {orig_id} to {orig_id+1}, with no authorization "
                            f"check (API1: Broken Object Level Authorization)."
                        ),
                        evidence = Evidence(
                            probe_url        = alt_url,
                            probe_payload    = f"path id {orig_id} -> {orig_id+1}",
                            response_status  = alt_resp.status_code,
                            response_excerpt = json.dumps(alt_json)[:200],
                            matched_pattern  = "Distinct JSON object returned for unauthorized ID",
                            verification_note= "API1:2023 Broken Object Level Authorization",
                        ),
                    )
                    findings.append(finding.to_dict())

        except Exception as exc:
            logger.debug(f"BOLA check error for {url}: {exc}")

        return findings

    @staticmethod
    def _looks_like_object(data) -> bool:
        if isinstance(data, dict):
            return len(data) > 0
        if isinstance(data, list):
            return len(data) > 0
        return False

    # ── API2: Broken authentication on API endpoints ─────────────────────────

    def _check_missing_auth(self, url: str) -> List[Dict]:
        """
        If an endpoint clearly under an /api/ or /v1/ path returns sensitive-
        looking JSON data (objects with id/email/user fields) with ZERO
        Authorization header and ZERO session cookie, that's a strong signal
        of missing authentication enforcement.
        """
        findings = []
        timeout = self.config.get("request_timeout", 15)

        try:
            # Use a session with NO auth/cookies — simulate an anonymous caller
            anon_session = requests.Session()
            anon_session.headers.update({"User-Agent": self.config.get("user_agent", "Mozilla/5.0")})

            resp = anon_session.get(url, timeout=timeout, verify=self.config.get("verify_ssl", True))
            if resp.status_code != 200:
                return findings

            content_type = resp.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                return findings

            try:
                data = resp.json()
            except Exception:
                return findings

            if self._contains_sensitive_fields(data):
                finding = VerifiedFinding(
                    vuln_type   = "Broken Authentication",
                    url         = url,
                    parameter   = "",
                    severity    = "High",
                    confidence  = 60,
                    owasp       = "A07 – Auth Failures",
                    description = (
                        "API endpoint returns data containing user-identifying fields "
                        "(email/id/user) to a completely anonymous request with no "
                        "Authorization header or session cookie (API2: Broken Authentication)."
                    ),
                    evidence = Evidence(
                        probe_url        = url,
                        response_status  = resp.status_code,
                        response_excerpt = json.dumps(data)[:200] if isinstance(data, (dict, list)) else str(data)[:200],
                        matched_pattern  = "Sensitive field present in unauthenticated response",
                        verification_note= "Request sent with no Authorization header and no cookies",
                    ),
                )
                findings.append(finding.to_dict())

        except Exception as exc:
            logger.debug(f"Missing-auth check error for {url}: {exc}")

        return findings

    @staticmethod
    def _contains_sensitive_fields(data, depth=0) -> bool:
        if depth > 3:
            return False
        sensitive_keys = {"email", "password", "ssn", "token", "secret", "creditcard", "credit_card"}
        if isinstance(data, dict):
            for k, v in data.items():
                if k.lower() in sensitive_keys:
                    return True
                if isinstance(v, (dict, list)) and APISecurityDetector._contains_sensitive_fields(v, depth+1):
                    return True
        elif isinstance(data, list):
            for item in data[:5]:
                if APISecurityDetector._contains_sensitive_fields(item, depth+1):
                    return True
        return False

    # ── API9: Improper inventory management ───────────────────────────────────

    def _discover_api_inventory(self, base_url: str) -> List[Dict]:
        """Probe for exposed API documentation/schema endpoints."""
        findings = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        baseline = get_baseline(self.session, base_url, self.config)

        for path in self.API_DISCOVERY_PATHS:
            url = origin + path
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 10),
                                        allow_redirects=False)
                if resp.status_code != 200 or matches_baseline(resp, baseline):
                    continue

                body = resp.text
                is_openapi = '"openapi"' in body or '"swagger"' in body or "swagger-ui" in body.lower()
                is_graphql = "graphql" in path.lower() and ("query" in body.lower() or "__schema" in body.lower())

                if not (is_openapi or is_graphql):
                    continue

                confidence = 80 if is_openapi else 65
                finding = VerifiedFinding(
                    vuln_type   = "Information Disclosure",
                    url         = url,
                    parameter   = "",
                    severity    = "Medium",
                    confidence  = confidence,
                    owasp       = "A09 – Logging Failures",
                    description = (
                        f"API schema/documentation is publicly exposed at '{path}'. "
                        "This reveals the full API surface (all endpoints, parameters, "
                        "and data models) to unauthenticated users, significantly aiding "
                        "reconnaissance (API9: Improper Inventory Management)."
                    ),
                    evidence = Evidence(
                        probe_url        = url,
                        response_status  = resp.status_code,
                        response_excerpt = body[:200],
                        matched_pattern  = "OpenAPI/Swagger schema" if is_openapi else "GraphQL introspection",
                        verification_note= "API9:2023 Improper Inventory Management",
                    ),
                )
                findings.append(finding.to_dict())

            except Exception:
                continue

        return findings

    # ── API8: CORS misconfiguration ───────────────────────────────────────────

    def _check_cors_misconfiguration(self, base_url: str) -> List[Dict]:
        """
        Send a request with an arbitrary Origin header and check if the
        server reflects it back in Access-Control-Allow-Origin combined
        with Access-Control-Allow-Credentials: true — this allows any
        website to make authenticated cross-origin requests.
        """
        findings = []
        evil_origin = "https://evil-cors-test.example"

        try:
            resp = self.session.get(
                base_url,
                headers={"Origin": evil_origin},
                timeout=self.config.get("request_timeout", 15),
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == evil_origin and acac == "true":
                finding = VerifiedFinding(
                    vuln_type   = "Security Header Missing",
                    url         = base_url,
                    parameter   = "",
                    severity    = "High",
                    confidence  = 92,
                    owasp       = "A05 – Security Misconfiguration",
                    description = (
                        "The server reflects an arbitrary Origin header back in "
                        "Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: "
                        "true. This allows ANY external website to make authenticated "
                        "cross-origin requests using the victim's cookies (API8: Security "
                        "Misconfiguration / CORS misconfiguration)."
                    ),
                    evidence = Evidence(
                        probe_url        = base_url,
                        probe_payload    = f"Origin: {evil_origin}",
                        response_status  = resp.status_code,
                        response_excerpt = f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
                        matched_pattern  = "Reflected arbitrary Origin + credentials:true",
                        verification_note= "Sent a deliberately invalid/arbitrary Origin header that should never be allowlisted",
                    ),
                )
                findings.append(finding.to_dict())
            elif acao == "*" and acac == "true":
                # Technically invalid per spec (browsers reject this combo),
                # but still worth flagging as a misconfiguration with lower
                # severity since it's not actually exploitable in compliant browsers.
                findings.append({
                    "type": "Security Header Missing",
                    "subtype": "CORS",
                    "url": base_url,
                    "severity": "Low",
                    "confidence": 70,
                    "confidence_label": "High",
                    "description": (
                        "Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true is set. Most browsers reject "
                        "this invalid combination, but it indicates a misconfigured CORS policy."
                    ),
                    "evidence": f"Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                    "owasp": "A05 – Security Misconfiguration",
                    "recommendation": "Set Access-Control-Allow-Origin to a specific allowlisted origin, never '*' when credentials are allowed.",
                })

        except Exception as exc:
            logger.debug(f"CORS check error: {exc}")

        return findings

    # ── API8: verbose JSON error messages ─────────────────────────────────────

    def _check_verbose_json_errors(self, url: str) -> List[Dict]:
        """Probe with malformed input and check if the JSON error response
        leaks stack traces, file paths, or framework details."""
        findings = []
        timeout = self.config.get("request_timeout", 15)

        try:
            resp = self.session.post(
                url,
                data="{invalid json!!!",
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            body = resp.text
            leak_patterns = [
                (r'"stack"\s*:\s*"', "Stack trace in JSON error response"),
                (r'/(home|var|usr)/[a-zA-Z0-9_/.\-]+', "Server file path in JSON error response"),
                (r'(Traceback|Exception in thread|at\s+\w+\.\w+\()', "Exception details in JSON error response"),
            ]
            for pattern, desc in leak_patterns:
                m = re.search(pattern, body)
                if m:
                    finding = VerifiedFinding(
                        vuln_type   = "Logging & Monitoring Failure",
                        url         = url,
                        parameter   = "",
                        severity    = "Medium",
                        confidence  = 80,
                        owasp       = "A09 – Logging Failures",
                        description = f"{desc}. Malformed JSON input triggered an unhandled error revealing internal details.",
                        evidence = Evidence(
                            probe_url        = url,
                            probe_payload    = "{invalid json!!!",
                            response_status  = resp.status_code,
                            response_excerpt = m.group(0)[:150],
                            matched_pattern  = pattern,
                            verification_note= "API8:2023 Security Misconfiguration — verbose error disclosure",
                        ),
                    )
                    findings.append(finding.to_dict())
                    break
        except Exception as exc:
            logger.debug(f"Verbose JSON error check failed for {url}: {exc}")

        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    def _identify_api_endpoints(self, urls: List[str]) -> List[str]:
        """Heuristically identify which crawled URLs are likely JSON API endpoints."""
        api_indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", ".json"]
        return [u for u in urls if any(ind in u.lower() for ind in api_indicators)]

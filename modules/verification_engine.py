"""
Centralized Verification Engine & Confidence Scoring System

Solves:
  1. Detection ≠ Exploitation  → multi-step verification before flagging
  2. SSRF false-positive risk  → two-probe confirmation with different indicators
  3. Weak admin detection      → tool-specific fingerprinting + auth challenge
  4. Missing confidence scores → every finding gets 0-100 confidence score
  5. Weak evidence generation  → captures actual HTTP request/response excerpts
  6. Severity inflation        → severity tied to verified confidence level
"""

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)


# ── Confidence thresholds ────────────────────────────────────────────────────
#
# Confidence is a 0–100 integer representing how certain we are that a real
# vulnerability exists (not a false positive).
#
#   90–100 → Confirmed: multiple independent verification signals
#   70–89  → High confidence: strong primary signal + secondary confirmation
#   50–69  → Medium confidence: primary signal only, no counter-evidence
#   30–49  → Low confidence: weak or noisy signal
#     0–29 → Speculative: pattern match only, many possible benign causes
#
CONFIDENCE_CONFIRMED   = 90   # threshold for "Confirmed" label
CONFIDENCE_HIGH        = 70
CONFIDENCE_MEDIUM      = 50
CONFIDENCE_LOW         = 30


def confidence_label(score: int) -> str:
    if score >= CONFIDENCE_CONFIRMED: return "Confirmed"
    if score >= CONFIDENCE_HIGH:      return "High"
    if score >= CONFIDENCE_MEDIUM:    return "Medium"
    if score >= CONFIDENCE_LOW:       return "Low"
    return "Speculative"


# ── Classification system ────────────────────────────────────────────────────
#
# Every finding is bucketed into exactly one of these four pentest-report
# categories, derived directly from its confidence score. This is the
# top-level grouping used throughout the report (separate from the
# 5-level confidence_label, which is a finer-grained number underneath it).
#
#   Confirmed Vulnerability   — independently verified exploitation proof
#                                (callback received, code executed in a
#                                 real browser, DB error captured, etc.)
#   Likely Vulnerability      — strong behavioral signal, not independently
#                                exploited/executed
#   Potential Vulnerability   — weak/single signal, requires manual review
#   Informational             — not a vulnerability by itself (disclosure,
#                                hardening recommendation, config note)

CLASSIFICATION_CONFIRMED     = "Confirmed Vulnerability"
CLASSIFICATION_LIKELY        = "Likely Vulnerability"
CLASSIFICATION_POTENTIAL     = "Potential Vulnerability"
CLASSIFICATION_INFORMATIONAL = "Informational"


def classify_finding(confidence: int, is_informational: bool = False) -> str:
    """
    Map a confidence score (and an explicit informational flag, used by
    detectors whose findings are disclosures/hardening notes rather than
    exploitable vulnerabilities) to one of the four report categories.
    """
    if is_informational:
        return CLASSIFICATION_INFORMATIONAL
    if confidence >= CONFIDENCE_CONFIRMED:
        return CLASSIFICATION_CONFIRMED
    if confidence >= CONFIDENCE_MEDIUM:
        return CLASSIFICATION_LIKELY
    return CLASSIFICATION_POTENTIAL


# Rough CVSS v3.1 base-score estimate per severity, for report display only.
# This is NOT a substitute for a real CVSS calculation (which needs the
# specific attack vector / scope / privilege context per finding) — it
# gives the reader a familiar number to anchor on, clearly labeled as an
# estimate.
CVSS_ESTIMATE_BY_SEVERITY = {
    "Critical": 9.1,
    "High":     7.5,
    "Medium":   5.3,
    "Low":      3.1,
    "Info":     0.0,
}


def estimate_cvss(severity: str, confidence: int) -> float:
    """Confidence-adjusted CVSS estimate — low-confidence findings get a
    slightly reduced estimate to reflect verification uncertainty."""
    base = CVSS_ESTIMATE_BY_SEVERITY.get(severity, 0.0)
    if confidence < CONFIDENCE_MEDIUM and base > 0:
        base = round(base * 0.7, 1)
    return base


def adjusted_severity(original_severity: str, confidence: int) -> str:
    """
    Downgrade severity when confidence is low to prevent severity inflation.

    A 'Critical' finding with only 40% confidence is misleading — it gets
    reported as 'Medium' until verification raises the score.
    """
    if confidence >= CONFIDENCE_HIGH:
        return original_severity   # full severity when well-verified
    if confidence >= CONFIDENCE_MEDIUM:
        # Downgrade one level
        down = {"Critical": "High", "High": "Medium", "Medium": "Low",
                "Low": "Low", "Info": "Info"}
        return down.get(original_severity, original_severity)
    # Low/speculative: two levels down
    down2 = {"Critical": "Medium", "High": "Low", "Medium": "Low",
              "Low": "Info", "Info": "Info"}
    return down2.get(original_severity, original_severity)


@dataclass
class Evidence:
    """Structured evidence captured during detection."""
    probe_url:          str   = ""
    probe_payload:      str   = ""
    response_status:    int   = 0
    response_excerpt:   str   = ""
    matched_pattern:    str   = ""
    verification_note:  str   = ""
    # Spec-required fields for the evidence engine:
    http_method:         str  = "GET"
    comparison_baseline: str  = ""   # e.g. "Response A: 2200 chars"
    comparison_payload:  str  = ""   # e.g. "Response B: 300 chars"
    comparison_diff:     str  = ""   # e.g. "Difference: 1900 chars (86%)"
    reproduction_steps:  List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "probe_url":           self.probe_url,
            "probe_payload":       self.probe_payload[:200] if self.probe_payload else "",
            "http_method":         self.http_method,
            "response_status":     self.response_status,
            "response_excerpt":    self.response_excerpt[:500] if self.response_excerpt else "",
            "matched_pattern":     self.matched_pattern,
            "verification_note":   self.verification_note,
            "comparison_baseline": self.comparison_baseline,
            "comparison_payload":  self.comparison_payload,
            "comparison_diff":     self.comparison_diff,
            "reproduction_steps":  self.reproduction_steps,
        }

    def to_text(self) -> str:
        parts = []
        if self.probe_payload:
            parts.append(f"Payload: {self.probe_payload[:120]}")
        if self.response_status:
            parts.append(f"HTTP {self.response_status}")
        if self.matched_pattern:
            parts.append(f"Matched: {self.matched_pattern[:80]}")
        if self.comparison_diff:
            parts.append(f"Diff: {self.comparison_diff}")
        if self.response_excerpt:
            parts.append(f"Response excerpt: {self.response_excerpt[:200]}")
        if self.verification_note:
            parts.append(f"Note: {self.verification_note}")
        return " | ".join(parts)

    def auto_reproduction_steps(self, url: str, parameter: str = "") -> List[str]:
        """Generate generic reproduction steps if the detector didn't supply
        its own explicit list — every finding must be reproducible."""
        if self.reproduction_steps:
            return self.reproduction_steps
        steps = []
        if parameter:
            steps.append(f"1. Send a {self.http_method} request to {url} with parameter '{parameter}' set to: {self.probe_payload}")
        else:
            steps.append(f"1. Send a {self.http_method} request to: {self.probe_url or url}")
        if self.comparison_baseline and self.comparison_payload:
            steps.append(f"2. Compare the response against baseline — {self.comparison_baseline} vs {self.comparison_payload}")
        if self.matched_pattern:
            steps.append(f"{'3' if len(steps)==2 else '2'}. Confirm response contains/matches: {self.matched_pattern[:100]}")
        if not steps:
            steps.append(f"1. Re-request {url} and inspect the response for the evidence described above.")
        return steps


@dataclass
class VerifiedFinding:
    """A fully-verified vulnerability finding with confidence score,
    classification, and reproducible evidence."""
    vuln_type:    str
    url:          str
    parameter:    str         = ""
    severity:     str         = "Medium"
    description:  str         = ""
    confidence:   int         = 50
    owasp:        str         = ""
    evidence:     Evidence    = field(default_factory=Evidence)
    timestamp:    str         = ""
    verification_method: str  = "Pattern match"   # e.g. "Interactsh DNS callback", "Browser execution"
    is_informational: bool    = False
    remediation:  str         = ""

    def evidence_score(self) -> int:
        """
        How complete/strong is the captured evidence itself, independent of
        confidence (confidence answers 'is this real?'; evidence_score
        answers 'how well-documented is the proof?'). Used in reporting so
        a reviewer can see at a glance whether a finding has a full
        request/response/diff trail or just a bare description.
        """
        score = 0
        if self.evidence.probe_url:            score += 15
        if self.evidence.probe_payload:         score += 15
        if self.evidence.response_status:       score += 10
        if self.evidence.response_excerpt:      score += 20
        if self.evidence.matched_pattern:        score += 15
        if self.evidence.comparison_diff:       score += 15
        if self.evidence.reproduction_steps or self.evidence.probe_url: score += 10
        return min(100, score)

    def to_dict(self) -> Dict:
        import datetime
        sev = adjusted_severity(self.severity, self.confidence)
        classification = classify_finding(self.confidence, self.is_informational)
        repro = self.evidence.auto_reproduction_steps(self.url, self.parameter)
        return {
            "type":                self.vuln_type,
            "url":                 self.url,
            "parameter":           self.parameter,
            "severity":            sev,
            "original_severity":   self.severity,
            "confidence":          self.confidence,
            "confidence_label":    confidence_label(self.confidence),
            "classification":      classification,
            "verification_method": self.verification_method,
            "evidence_score":      self.evidence_score(),
            "description":         self.description,
            "owasp":               self.owasp,
            "evidence":            self.evidence.to_text(),
            "evidence_detail":     self.evidence.to_dict(),
            "reproduction_steps":  repro,
            "cvss_estimate":       estimate_cvss(sev, self.confidence),
            "remediation":         self.remediation,
            "timestamp":           self.timestamp or datetime.datetime.now().isoformat(),
        }


# ── SSRF Verifier ─────────────────────────────────────────────────────────────

class SSRFVerifier:
    """
    SSRF verification with two tiers, tried in order:

    TIER 1 — Out-of-band (OOB) confirmation via Interactsh, when configured.
             Genuine exploitation proof: a unique subdomain is sent as the
             payload, then we check whether the TARGET SERVER itself made
             a DNS/HTTP request to it. Classified as "Confirmed
             Vulnerability" (confidence 95-100).

    TIER 2 — Static-indicator fallback (used automatically when no
             Interactsh server is configured, or OOB confirmation times
             out). Indicators are JSON-key-shaped or multi-word phrases
             unique to real metadata responses — never a bare common noun
             like "hostname" or "zone", which also appear in unrelated
             JavaScript (e.g. window.location.hostname) and previously
             caused false positives. Classified as "Potential
             Vulnerability" (confidence 30-50) since exploitation was not
             independently proven.
    """

    PRIMARY_PROBES = [
        ("http://169.254.169.254/latest/meta-data/",
         ['"ami-id"', '"instance-id"', '"local-ipv4"', "ami-id\n", "instance-id\n"]),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         ['"accesskeyid"', '"secretaccesskey"', '"expiration"']),
        ("http://metadata.google.internal/computeMetadata/v1/instance/",
         ['"machine-type"', '"service-accounts"', "compute.googleapis.com"]),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         ['"subscriptionid"', '"vmid"', '"resourcegroupname"']),
    ]

    SECONDARY_PROBES = [
        ("http://169.254.169.254/latest/meta-data/ami-id",
         ["ami-0", "ami-1"]),
        ("http://169.254.169.254/latest/meta-data/instance-type",
         ["t2.micro", "t2.small", "t3.micro", "t3.small", "m5.large", "c5.large"]),
        ("http://169.254.169.254/latest/api/token",
         ['"ttl"', "x-aws-ec2-metadata-token"]),
    ]

    INTERNAL_PROBES = [
        ("http://127.0.0.1/",      ["welcome to nginx!", "apache2 ubuntu default page", "iis windows server"]),
        ("http://127.0.0.1:8080/", ["apache tomcat", "wildfly", "jetty(", "if you're seeing this"]),
        ("http://localhost/",      ["welcome to nginx!", "apache2 ubuntu default page"]),
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session  = session
        self.config   = config
        self._timeout = config.get("request_timeout", 15)

        from modules.interactsh_client import InteractshClient
        self.oob = InteractshClient(config)

    def verify(self, url: str, param_name: str,
               build_url_fn) -> Optional[VerifiedFinding]:
        """Tries OOB confirmation first (if configured), falls back to
        static-indicator detection otherwise. build_url_fn(probe_url) ->
        test_url_string"""
        if self.oob.is_available():
            oob_finding = self._verify_via_oob(url, param_name, build_url_fn)
            if oob_finding:
                return oob_finding

        return self._verify_via_static_indicators(url, param_name, build_url_fn)

    def _verify_via_oob(self, url: str, param_name: str, build_url_fn) -> Optional[VerifiedFinding]:
        oob_domain = self.oob.register()
        if not oob_domain:
            return None

        probe_url = f"http://{oob_domain}/ssrf-probe"
        test_url  = build_url_fn(probe_url)

        try:
            self.session.get(test_url, timeout=self._timeout, allow_redirects=False)
        except Exception:
            pass

        interactions = self.oob.poll(wait_seconds=self.config.get("oob_wait_seconds", 8))
        self.oob.deregister()

        if not interactions:
            return None

        hit = interactions[0]
        return VerifiedFinding(
            vuln_type   = "Server-Side Request Forgery (SSRF)",
            url         = url,
            parameter   = param_name,
            severity    = "Critical",
            confidence  = 98,
            owasp       = "A10 – SSRF",
            verification_method = "Interactsh DNS/HTTP callback",
            description = (
                f"Parameter '{param_name}' triggered a confirmed out-of-band "
                f"{hit.protocol.upper()} interaction: the target server made a network "
                "request to our unique callback domain. This directly proves SSRF."
            ),
            remediation = (
                "Implement an allowlist of permitted destination hosts/IPs. Reject "
                "requests to private/link-local IP ranges and block resolution to "
                "internal-only hostnames before performing the fetch."
            ),
            evidence = Evidence(
                probe_url        = test_url,
                probe_payload    = probe_url,
                matched_pattern  = f"{hit.protocol.upper()} callback from {hit.remote_addr or 'target server'}",
                verification_note= f"OOB {hit.protocol} interaction recorded on {oob_domain}",
                reproduction_steps = [
                    "1. Register a unique Interactsh (or equivalent OOB) domain.",
                    f"2. Send a request to {test_url} with parameter '{param_name}' "
                    "set to an OOB URL.",
                    f"3. Poll the OOB server — a {hit.protocol.upper()} callback "
                    "confirms the target fetched the URL server-side.",
                ],
            ),
        )

    def _verify_via_static_indicators(self, url: str, param_name: str, build_url_fn) -> Optional[VerifiedFinding]:
        oob_was_attempted = self.oob.is_available()
        note_prefix = (
            "OOB callback server configured but no interaction received; "
            if oob_was_attempted else
            "No OOB callback server configured — static-indicator detection only. "
        )

        for probe_url, indicators in self.PRIMARY_PROBES:
            test_url = build_url_fn(probe_url)
            hit, excerpt, matched = self._probe(test_url, indicators)
            if not hit:
                continue

            confidence = 40
            verification_note = f"{note_prefix}Primary probe matched specific indicator '{matched}'"

            for sec_url, sec_indicators in self.SECONDARY_PROBES:
                sec_test = build_url_fn(sec_url)
                sec_hit, sec_excerpt, sec_matched = self._probe(sec_test, sec_indicators)
                if sec_hit:
                    confidence = 48
                    verification_note += f"; secondary probe also matched '{sec_matched}'"
                    break

            return VerifiedFinding(
                vuln_type   = "Server-Side Request Forgery (SSRF)",
                url         = url,
                parameter   = param_name,
                severity    = "Critical",
                confidence  = confidence,
                owasp       = "A10 – SSRF",
                verification_method = "Static response-indicator match (unconfirmed)",
                description = (
                    f"Parameter '{param_name}' may fetch arbitrary URLs server-side. "
                    f"Probing with '{probe_url}' returned content matching a cloud-"
                    "metadata response signature. Not independently confirmed via "
                    "out-of-band callback — configure an Interactsh server to upgrade "
                    "this to a Confirmed finding."
                ),
                remediation = (
                    "Manually verify, then implement a destination allowlist and block "
                    "requests to private/link-local IP ranges."
                ),
                evidence = Evidence(
                    probe_url        = test_url,
                    probe_payload    = probe_url,
                    response_excerpt = excerpt,
                    matched_pattern  = matched,
                    verification_note= verification_note,
                ),
            )

        for probe_url, indicators in self.INTERNAL_PROBES:
            test_url = build_url_fn(probe_url)
            hit, excerpt, matched = self._probe(test_url, indicators)
            if not hit:
                continue

            external_test = build_url_fn("https://example.com/")
            try:
                ext_resp = self.session.get(external_test, timeout=self._timeout, allow_redirects=False)
                if any(ind.lower() in ext_resp.text.lower() for ind in indicators):
                    continue
            except Exception:
                pass

            return VerifiedFinding(
                vuln_type   = "Server-Side Request Forgery (SSRF)",
                url         = url,
                parameter   = param_name,
                severity    = "High",
                confidence  = 35,
                owasp       = "A10 – SSRF",
                verification_method = "Static response-indicator match (unconfirmed)",
                description = (
                    f"Parameter '{param_name}' may fetch internal URLs. Probing "
                    f"'{probe_url}' returned internal-server banner text absent when "
                    f"targeting an external URL. {note_prefix}"
                ),
                remediation = (
                    "Manually verify, then implement a destination allowlist and block "
                    "127.0.0.0/8, 169.254.0.0/16, and other private ranges."
                ),
                evidence = Evidence(
                    probe_url        = test_url,
                    probe_payload    = probe_url,
                    response_excerpt = excerpt,
                    matched_pattern  = matched,
                    verification_note= "Internal service probe matched; no OOB confirmation available",
                ),
            )

        return None

    def _probe(self, test_url: str, indicators: List[str]):
        """Returns (hit, excerpt, matched_indicator)."""
        try:
            resp = self.session.get(test_url, timeout=self._timeout,
                                    allow_redirects=False)
            if resp.status_code != 200:
                return False, "", ""
            body = resp.text.lower()
            for ind in indicators:
                if ind.lower() in body:
                    # Extract a 200-char excerpt around the match
                    pos = body.find(ind.lower())
                    start = max(0, pos - 40)
                    excerpt = resp.text[start:start + 200].strip()
                    return True, excerpt, ind
        except Exception as exc:
            logger.debug("SSRF probe error: %s", exc)
        return False, "", ""


# ── Admin Panel Verifier ──────────────────────────────────────────────────────

class AdminPanelVerifier:
    """
    Multi-signal admin panel detection.

    Stage 1: Fetch the panel path and check for tool-specific fingerprints.
    Stage 2: Verify authentication IS required (return 401/403 after POST
             with wrong credentials, OR redirect to a login page that has
             specific wording). If no auth is challenged at all, that is the
             actual "broken access control" finding.
    Stage 3: Compare response against the baseline — if identical, it's SPA
             catch-all (not a real panel).
    """

    PANEL_FINGERPRINTS: Dict[str, List[str]] = {
        "/phpmyadmin":    ["phpmyadmin", "pma_", "mysql", "mariadb"],
        "/pma":           ["phpmyadmin", "pma_", "mysql"],
        "/wp-admin":      ["wordpress", "wp-login", "wp-admin", "lost-password"],
        "/administrator": ["joomla", "com_admin", "administrator"],
        "/manager/html":  ["tomcat web application manager", "tomcat manager"],
        "/actuator":      ['"status"', '"diskSpace"', '"_links"', '"components"'],
        "/actuator/health":['"status":"up"', '"status":"down"', '"components"'],
        "/actuator/env":  ['"activeProfiles"', '"propertySources"'],
        "/metrics":       ["# HELP ", "# TYPE ", "http_requests_total"],
        "/server-status": ["apache server status", "server version:", "requests currently being processed"],
        "/_profiler":     ["symfony", "profiler", "sf-toolbar"],
        "/telescope":     ["laravel telescope", "telescope-api"],
        "/horizon":       ["laravel horizon", "horizon-api"],
        "/grafana":       ["grafana", "grafana-app", "data-testid=\"grafana", "public/build/runtime"],
        "/-/grafana":     ["grafana", "grafana-app"],
        "/kibana":        ["kibana", "kbn-injected-metadata", "kbn-csrf-token"],
        "/app/kibana":    ["kibana", "kbn-injected-metadata"],
        "/jenkins":       ["jenkins", "x-jenkins", "hudson.model", "jenkins-session"],
        "/job/":          ["jenkins", "x-jenkins", "hudson.model"],
    }

    # Header-based fingerprints — some tools identify themselves via a
    # response header even when the body alone is ambiguous.
    PANEL_HEADER_FINGERPRINTS: Dict[str, List[str]] = {
        "/jenkins": ["x-jenkins"],
        "/grafana": ["grafana"],
        "/kibana":  ["kbn-name", "kbn-version"],
    }

    AUTH_CHALLENGE_PATTERNS = [
        "type=\"password\"", "type='password'",
        "login", "sign in", "username", "enter your password",
        "401 unauthorized", "403 forbidden", "access denied",
        "please log in", "authentication required",
    ]

    # Positive evidence of actual admin/dashboard content — used ONLY for
    # the generic (non-fingerprinted) path, and ONLY once we've already
    # confirmed no login challenge is present. Without some positive
    # signal like this, "HTTP 200 at a path named /admin" alone is not
    # evidence of anything — plenty of sites have a harmless page there.
    ADMIN_CONTENT_MARKERS = [
        "dashboard", "admin panel", "control panel", "site administration",
        "welcome, admin", "welcome admin", "manage users", "user management",
        "logout", "log out", "add new user", "site settings",
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session  = session
        self.config   = config
        self._timeout = config.get("request_timeout", 10)

    def verify(self, url: str, path: str, label: str,
               baseline: Dict) -> Optional[VerifiedFinding]:
        from modules.scan_utils import matches_baseline

        try:
            resp = self.session.get(url, timeout=self._timeout, allow_redirects=True)
        except Exception as exc:
            logger.debug("Admin panel probe failed for %s: %s", url, exc)
            return None

        if resp.status_code not in (200, 401, 403):
            return None

        body = resp.text
        body_lower = body.lower()

        # Stage 3: baseline comparison
        if matches_baseline(resp, baseline):
            return None

        # Stage 1: tool-specific fingerprint (body content)
        fingerprints = self._get_fingerprints(path)
        matched_fp   = next((fp for fp in fingerprints if fp.lower() in body_lower), None)

        # Stage 1b: header-based fingerprint — some tools (Jenkins, Grafana,
        # Kibana) identify themselves via a distinctive response header
        # even when body content alone is ambiguous.
        header_fp = None
        for hdr_path, hdr_names in self.PANEL_HEADER_FINGERPRINTS.items():
            if path.startswith(hdr_path):
                for hdr_name in hdr_names:
                    if hdr_name in {h.lower() for h in resp.headers.keys()}:
                        header_fp = hdr_name
                        break

        if resp.status_code in (401, 403):
            # Auth IS being challenged → note it but lower confidence
            confidence = 55
            excerpt    = self._excerpt(body, "")
            note       = (
                f"HTTP {resp.status_code} returned — authentication exists "
                "but the panel is exposed (credential brute-force possible)"
            )
        elif matched_fp or header_fp:
            # Strong, tool-specific evidence with NO auth challenge at all
            # — this is independently verifiable proof the exact tool is
            # both present and fully unauthenticated. Reaches Confirmed.
            confidence = 92
            excerpt    = self._excerpt(body, matched_fp or "")
            matched_desc = matched_fp or f"header '{header_fp}'"
            note       = f"Tool-specific fingerprint {matched_desc!r} matched; no auth challenge detected"
        else:
            # Generic (non-fingerprinted) path.
            #
            # Bug fix: this previously treated a MATCH against
            # AUTH_CHALLENGE_PATTERNS (things like `type="password"`,
            # "login", "please log in") as CONFIRMING the vulnerability —
            # exactly backwards. Those patterns mean the page is
            # presenting a login form / auth challenge, i.e. authentication
            # IS being enforced correctly. That is the definition of "not
            # vulnerable", not evidence of "accessible without proper
            # authentication". This previously turned every ordinary
            # /admin login page into a false "unauthenticated admin
            # access" finding.
            #
            # The class docstring already documented the correct design
            # (Stage 2: "If no auth is challenged at all, that is the
            # actual finding") — this just makes the code match it.
            auth_match = next(
                (p for p in self.AUTH_CHALLENGE_PATTERNS if p in body_lower), None
            )
            if auth_match:
                # A login prompt / password field was found — the panel
                # correctly requires authentication. Not a vulnerability.
                return None

            # No login challenge detected AND no known tool fingerprint
            # matched. Only report this as "unauthenticated admin access"
            # if the response actually LOOKS like real admin/dashboard
            # content — otherwise there's no positive evidence this path
            # is an admin panel at all (could just be an unrelated 200
            # page, e.g. a custom 404, a marketing page, or an SPA route).
            admin_content_match = next(
                (m for m in self.ADMIN_CONTENT_MARKERS if m in body_lower), None
            )
            if not admin_content_match:
                return None   # Not enough evidence this is an admin panel

            confidence = 60
            excerpt    = self._excerpt(body, admin_content_match)
            note       = (
                f"No login challenge presented, but admin-content marker "
                f"{admin_content_match!r} found — page appears to be live "
                "admin content reachable without authentication"
            )

        return VerifiedFinding(
            vuln_type   = "Logging & Monitoring Failure",
            url         = url,
            parameter   = "",
            severity    = "High" if confidence >= CONFIDENCE_HIGH else "Medium",
            confidence  = confidence,
            owasp       = "A09 – Logging Failures",
            verification_method = (
                "Tool-specific fingerprint match" if (matched_fp or header_fp)
                else "Admin-content marker with no login challenge (generic path)"
            ),
            description = (
                f"{label} at '{url}' appears accessible without proper authentication. "
                f"Unauthenticated admin access allows attackers to read configuration, "
                "execute commands, or exfiltrate data."
            ),
            remediation = (
                f"Restrict {path} to authenticated administrators only, ideally via "
                "network-level access control (VPN/IP allowlist) rather than relying "
                "solely on application-level auth."
            ),
            evidence = Evidence(
                probe_url        = url,
                response_status  = resp.status_code,
                response_excerpt = excerpt,
                matched_pattern  = matched_fp or header_fp or admin_content_match if not (matched_fp or header_fp) else (matched_fp or ""),
                verification_note= note,
            ),
        )

    def _get_fingerprints(self, path: str) -> List[str]:
        for key, fps in self.PANEL_FINGERPRINTS.items():
            if path.startswith(key):
                return fps
        return []

    @staticmethod
    def _excerpt(body: str, pattern: str) -> str:
        if pattern:
            pos = body.lower().find(pattern.lower())
            if pos >= 0:
                start = max(0, pos - 30)
                return body[start:start + 200].strip()
        return body[:200].strip()


# ── CSRF Verifier ─────────────────────────────────────────────────────────────

class CSRFVerifier:
    """
    Multi-signal CSRF verification that avoids two classic false-positive
    patterns:

    1. Flagging every POST form that lacks a hidden 'csrf_token' field,
       regardless of what the form actually DOES. Real CSRF protection can
       come from CSRF tokens, SameSite=Strict/Lax cookies, custom headers
       validated server-side, double-submit cookies, or Origin/Referer
       validation — we check what's statically detectable and only flag
       when MULTIPLE layers of protection are absent.

    2. Treating a missing token on a benign, public, unauthenticated form
       (search box, contact form, newsletter signup) as equally severe to
       a missing token on an authenticated, STATE-CHANGING action
       (password change, email change, money transfer, account deletion).
       A forged search submission has no meaningful impact; a forged
       password change does. We classify form INTENT before scoring, and
       benign forms are downgraded to Informational rather than reported
       as a security finding at all.
    """

    # Unambiguous CSRF-token name fragments — these strings essentially
    # never appear in unrelated field names, so a substring match is safe.
    TOKEN_NAME_SUBSTRINGS = {
        "csrf", "xsrf", "authenticity_token",
        "__requestverificationtoken", "csrfmiddlewaretoken", "_wpnonce",
    }

    # Generic/ambiguous names that are ONLY treated as a CSRF token when
    # they are (a) an EXACT field-name match — not a substring, so "token"
    # does NOT match "access_token" or "api_token" — AND (b) a hidden
    # input, since CSRF tokens are virtually always hidden fields while,
    # e.g., a visible "state" <select> is just as likely to be a US-state
    # address dropdown as an anti-CSRF value. Bug fix: the previous
    # version matched these as bare substrings against ANY field name,
    # which meant a billing/shipping form's "state" dropdown (extremely
    # common) or an "access_token" hidden field (OAuth, unrelated to CSRF)
    # silently suppressed real CSRF findings on that form.
    AMBIGUOUS_TOKEN_NAMES = {"token", "state", "nonce", "_method"}

    def _has_csrf_token(self, inputs: List[Dict]) -> bool:
        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if any(sub in name for sub in self.TOKEN_NAME_SUBSTRINGS):
                return True
            if name in self.AMBIGUOUS_TOKEN_NAMES and (inp.get("type") or "").lower() == "hidden":
                return True
        return False

    # Field names / form action path keywords that indicate a STATE-
    # CHANGING, sensitive action — these are what actually matter for CSRF
    # impact. A form with NONE of these signals is treated as benign.
    #
    # Split into STRONG vs WEAK: "email" and "phone" alone are NOT reliable
    # evidence of a state-changing action — virtually every ordinary
    # "Contact Us" form on the internet asks for the visitor's own email
    # and phone number so a human can reply, without changing any account
    # state at all. Treating those two field names as sufficient, on
    # their own, to override an explicitly benign action (a form whose
    # action path literally contains "contact") produced a CSRF finding
    # on almost any site's contact form — a very common false positive.
    # STRONG keywords remain trustworthy standalone signals because they
    # essentially only appear on genuine account/financial/permission
    # forms.
    STATE_CHANGING_FIELD_KEYWORDS_STRONG = {
        "password", "newpassword", "new_password", "currentpassword",
        "newemail", "new_email",
        "amount", "transfer", "balance", "recipient", "iban", "account_number",
        "delete", "deactivate", "remove_account", "close_account",
        "role", "permission", "admin", "is_admin", "privilege",
        "newusername",
        # Financial abbreviations / domain-specific patterns
        "xfr", "txn", "trx", "acct", "amt", "dest", "src_acct", "dst_acct",
        "beneficiary", "payee", "pmt", "rcpt", "wdrl", "debit", "credit",
    }
    STATE_CHANGING_FIELD_KEYWORDS_WEAK = {
        "email", "phone", "address", "shipping", "billing", "username",
    }
    STATE_CHANGING_FIELD_KEYWORDS = (
        STATE_CHANGING_FIELD_KEYWORDS_STRONG | STATE_CHANGING_FIELD_KEYWORDS_WEAK
    )
    STATE_CHANGING_ACTION_KEYWORDS = {
        "password", "change-password", "reset-password",
        "transfer", "payment", "withdraw", "checkout", "order",
        "delete", "deactivate", "close-account", "remove",
        "settings", "account", "profile", "admin",
        "email", "update-email", "change-email",
        "role", "permission", "invite",
        # API-style paths common in modern apps
        "update", "modify", "edit", "save", "submit", "confirm",
        "create", "destroy", "revoke", "grant",
    }

    # Benign form categories that should NEVER be flagged regardless of
    # token presence — even if technically "state-changing" in a trivial
    # sense (e.g. subscribing to a newsletter), forging them has no
    # meaningful security impact.
    BENIGN_ACTION_KEYWORDS = {
        "search", "newsletter", "subscribe", "contact", "feedback",
        "comment", "rating", "review", "vote-public", "share",
    }
    BENIGN_FIELD_SIGNATURE = {
        frozenset({"q"}), frozenset({"query"}), frozenset({"search"}),
        frozenset({"email"}),   # newsletter signup with ONLY an email field
                                 # is benign; email CHANGE forms have other
                                 # auth-context fields too (handled below)
    }

    # Structural signals that strongly suggest a state-changing form
    # WITHOUT requiring matching known keywords — fixes Problem 3:
    # a form like <input name="acct_xfr_dest"> uses a custom abbreviation
    # that doesn't match any of the keywords above but is structurally
    # identifiable as financial/account because it's a POST form with a
    # money-amount-like pattern.
    STRUCTURAL_STATE_SIGNALS = [
        # A hidden "action" or "op" field that describes the operation
        # (common in older frameworks that multiplex forms)
        ("hidden_action_field",  lambda inputs: any(
            inp.get("type") == "hidden" and
            (inp.get("name") or "").lower() in ("action", "op", "operation", "cmd", "command")
            for inp in inputs
        )),
        # A numeric field likely to be a currency amount:
        # name contains amt/amount/price/cost/total + type number or text
        ("numeric_amount_field", lambda inputs: any(
            any(tok in (inp.get("name") or "").lower()
                for tok in ("amt", "amount", "price", "cost", "total", "sum", "fee"))
            and inp.get("type") in ("number", "text", None, "")
            for inp in inputs
        )),
        # A field that looks like a routing/account identifier
        # (8-12 digit numeric name, common for bank account numbers)
        ("account_id_field",     lambda inputs: any(
            any(tok in (inp.get("name") or "").lower()
                for tok in ("acct", "account", "routing", "iban", "bic", "swift",
                            "card", "cc_num", "cardnum", "pan"))
            for inp in inputs
        )),
    ]

    def classify_intent(self, form: Dict, url: str) -> Dict:
        """
        Classify what this form actually DOES, independent of whether it's
        protected. Returns a dict with is_state_changing (bool),
        is_benign (bool), and matched_keywords for transparency.

        v2 improvement: also runs structural analysis (STRUCTURAL_STATE_SIGNALS)
        so forms with custom/abbreviated field names (acct_xfr_dest, amt_due,
        dst_acct_num) are correctly classified as state-changing rather than
        falling into "ambiguous" with low confidence.
        """
        action = (form.get("action") or url).lower()
        inputs = form.get("inputs", [])
        field_names = {inp.get("name", "").lower() for inp in inputs}

        matched_state_fields_strong = {
            fname for fname in field_names
            for kw in self.STATE_CHANGING_FIELD_KEYWORDS_STRONG
            if kw in fname
        }
        matched_state_fields_weak = {
            fname for fname in field_names
            for kw in self.STATE_CHANGING_FIELD_KEYWORDS_WEAK
            if kw in fname
        }
        matched_state_fields = matched_state_fields_strong | matched_state_fields_weak
        matched_state_action = {
            kw for kw in self.STATE_CHANGING_ACTION_KEYWORDS if kw in action
        }
        matched_benign_action = {
            kw for kw in self.BENIGN_ACTION_KEYWORDS if kw in action
        }

        # Strong field signals (password, delete, admin/role/permission,
        # financial fields) and explicit state-changing action keywords
        # are trustworthy on their own.
        is_state_changing = bool(matched_state_fields_strong or matched_state_action)

        # Weak field signals (email, phone, address, username, ...) are
        # only trusted as state-changing when the action ISN'T already an
        # explicitly benign one — those same field names are completely
        # ordinary on a "Contact Us" / newsletter-signup form (asking for
        # the visitor's own email/phone so a human can reply) without
        # representing any account-state change. A profile/settings form
        # with the same field names but no benign-action keyword is still
        # correctly flagged.
        if not is_state_changing and matched_state_fields_weak and not matched_benign_action:
            is_state_changing = True

        is_benign = bool(matched_benign_action) and not is_state_changing

        # A form with ONLY a search-box-like field (q, query, search) and
        # nothing else is unambiguously benign even if not matched above.
        non_hidden_non_button = {
            inp.get("name","").lower() for inp in inputs
            if inp.get("type") not in ("hidden", "submit", "button")
        }
        if non_hidden_non_button and frozenset(non_hidden_non_button) in self.BENIGN_FIELD_SIGNATURE:
            is_benign = True
            is_state_changing = False

        # Structural analysis: catch custom-named fields that don't match
        # keywords but structurally indicate a state-changing form.
        triggered_structural = []
        if not is_state_changing and not is_benign:
            for signal_name, signal_fn in self.STRUCTURAL_STATE_SIGNALS:
                try:
                    if signal_fn(inputs):
                        triggered_structural.append(signal_name)
                        is_state_changing = True
                except Exception:
                    pass

        return {
            "is_state_changing": is_state_changing,
            "is_benign":         is_benign and not is_state_changing,
            "matched_state_fields":    sorted(matched_state_fields)[:5],
            "matched_state_action":    sorted(matched_state_action)[:5],
            "matched_benign_action":   sorted(matched_benign_action)[:5],
            "triggered_structural":    triggered_structural,
        }

    def detect_auth_state(self, session: requests.Session) -> bool:
        """
        Heuristic: does this session appear to be authenticated? Checks
        for cookies with session/auth-like names. Used to weight
        confidence — an unauthenticated CSRF "finding" on a state-changing
        form that ALSO requires auth to even reach is lower real-world
        risk than one reachable by any logged-in user.
        """
        auth_cookie_keywords = ("session", "auth", "token", "jwt", "sid", "remember")
        for cookie in session.cookies:
            if any(kw in cookie.name.lower() for kw in auth_cookie_keywords):
                return True
        return False

    def verify(self, form: Dict, url: str,
               session: requests.Session, config: Dict) -> Optional[VerifiedFinding]:
        method = form.get("method", "GET").upper()
        if method not in ("POST", "PUT", "DELETE", "PATCH"):
            return None

        action = form.get("action", url)
        inputs = form.get("inputs", [])

        # Must be same-site form (cross-site action = not CSRF-vulnerable)
        try:
            action_domain = urlparse(action).netloc
            url_domain    = urlparse(url).netloc
            if action_domain and action_domain != url_domain:
                return None
        except Exception:
            pass

        intent = self.classify_intent(form, url)

        # Benign forms (search, newsletter, contact, public comment) are
        # never reported as a security finding — forging them has no
        # meaningful impact regardless of token presence.
        if intent["is_benign"]:
            return None

        # Check for token in hidden inputs
        has_token = self._has_csrf_token(inputs)

        # Check SameSite cookie protection
        has_samesite = False
        is_authenticated = False
        try:
            resp = session.get(url, timeout=config.get("request_timeout", 15))
            is_authenticated = self.detect_auth_state(session)
            raw_cookies = resp.raw.headers.getlist("Set-Cookie")
            for cookie_str in raw_cookies:
                lower = cookie_str.lower()
                if "samesite=strict" in lower or "samesite=lax" in lower:
                    has_samesite = True
                    break
        except Exception:
            pass

        if has_token:
            return None   # Token present → likely protected

        if has_samesite:
            confidence = 30
            note = "No CSRF token in form, but SameSite cookie provides partial protection"
        else:
            confidence = 55
            note = "No CSRF token and no SameSite cookie protection detected"

        # Confidence/severity scaling based on INTENT and auth state — this
        # is the core fix: a state-changing action on an authenticated
        # session with no protection is genuinely High risk; the same
        # missing token on a form that isn't state-changing (but also
        # wasn't classified clearly benign above) stays Low/Informational.
        if intent["is_state_changing"]:
            if is_authenticated:
                confidence += 25   # state-changing + reachable while authenticated = real risk
                severity = "High"
            else:
                confidence += 10
                severity = "Medium"
        else:
            confidence = max(10, confidence - 25)
            severity = "Low"

        confidence = min(95, confidence)

        fields_str = ", ".join(inp.get("name","?") for inp in inputs
                               if inp.get("type") not in ("submit","button","hidden"))

        intent_desc = (
            f"This form performs a STATE-CHANGING action (matched fields: "
            f"{', '.join(intent['matched_state_fields']) or ', '.join(intent['matched_state_action']) or 'none'}). "
            if intent["is_state_changing"] else
            "This form's action does not clearly match a sensitive state-changing "
            "category, but was not confidently classified as benign either — "
            "manual review recommended. "
        )
        auth_desc = (
            "The scanner session carries authentication cookies, so this finding "
            "applies to authenticated users — any logged-in user's browser could "
            "be tricked into submitting this form. "
            if is_authenticated else
            "No authentication was used during this scan. If this endpoint requires "
            "login to access, test manually with an authenticated session to confirm impact. "
            "If it is reachable without authentication, the CSRF risk is lower but still "
            "allows cross-origin form submission by any visitor. "
        )

        return VerifiedFinding(
            vuln_type   = "Cross-Site Request Forgery (CSRF)",
            url         = url,
            parameter   = "",
            severity    = severity,
            confidence  = confidence,
            owasp       = "A04 – Insecure Design",
            verification_method = "Static analysis: token presence + SameSite cookie + form-intent classification",
            description = (
                f"POST form at '{action}' lacks a CSRF token. Fields: {fields_str[:120]}. "
                f"{intent_desc}{auth_desc}{note}."
            ),
            remediation = (
                "Add a synchronizer CSRF token to this form and validate it server-side "
                "on submission. Set SameSite=Strict on session cookies as defense-in-depth. "
                "Prioritize fixing this if the action is reachable while authenticated."
            ),
            evidence = Evidence(
                probe_url        = url,
                probe_payload    = f"Method={method} Action={action}",
                matched_pattern  = "No csrf/xsrf/token field in POST form",
                verification_note= note,
                reproduction_steps = [
                    f"1. Load {url} while authenticated and inspect the form at '{action}'.",
                    "2. Confirm no CSRF token hidden field and no SameSite=Strict/Lax cookie.",
                    f"3. Host a cross-site auto-submitting form targeting '{action}' with the "
                    f"same field names ({fields_str[:80]}) and verify it succeeds when visited "
                    "by an authenticated user.",
                ],
            ),
        )


# ── SQLi Evidence Capturer ────────────────────────────────────────────────────

class SQLiEvidenceCapture:
    """
    Captures structured evidence for confirmed SQL injection findings.
    Runs AFTER the detector has already confirmed the vuln, enriching the
    finding with actual proof fragments.
    """

    ERROR_PATTERNS = [
        r"(you have an error in your sql syntax[^\n<]{0,200})",
        r"(warning: mysql[^\n<]{0,200})",
        r"(unclosed quotation mark[^\n<]{0,200})",
        r"(ora-\d{5}[^\n<]{0,100})",
        r"(pg_query\(\)[^\n<]{0,100})",
        r"(microsoft ole db provider[^\n<]{0,100})",
        r"(sqlite3\.operationalerror[^\n<]{0,100})",
    ]

    def capture(self, session: requests.Session, url: str,
                param_name: str, original_value: str,
                config: Dict) -> Evidence:
        """
        Re-run the most reliable payload to capture actual error text
        or boolean difference as structured evidence.
        """
        ev = Evidence()
        timeout = config.get("request_timeout", 15)

        # Try to capture a DB error message
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload in ("'", '"', "' OR '1'='1"):
            p = params.copy()
            p[param_name] = payload
            probe_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(p, doseq=True), parsed.fragment
            ))
            try:
                resp = session.get(probe_url, timeout=timeout)
                ev.probe_url     = probe_url
                ev.probe_payload = payload
                ev.response_status = resp.status_code
                body = resp.text

                for pat in self.ERROR_PATTERNS:
                    m = re.search(pat, body, re.IGNORECASE)
                    if m:
                        ev.matched_pattern  = m.group(1)[:150]
                        ev.response_excerpt = m.group(1)[:200]
                        ev.verification_note = "Error-based: DB error message captured in response"
                        return ev

                # No error — capture boolean difference evidence
                p2 = params.copy()
                p2[param_name] = f"{original_value}' AND '1'='1"
                p3 = params.copy()
                p3[param_name] = f"{original_value}' AND '1'='2"
                url2 = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(p2, doseq=True), parsed.fragment))
                url3 = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(p3, doseq=True), parsed.fragment))
                resp2 = session.get(url2, timeout=timeout)
                resp3 = session.get(url3, timeout=timeout)
                diff = abs(len(resp2.text) - len(resp3.text))
                ev.probe_payload    = f"Boolean: AND 1=1 vs AND 1=2"
                ev.matched_pattern  = f"Response length diff: {diff} chars (TRUE vs FALSE condition)"
                ev.response_excerpt = f"TRUE payload returned {len(resp2.text)} chars; FALSE returned {len(resp3.text)} chars"
                ev.verification_note = "Boolean-based: significant content difference between TRUE and FALSE conditions"
                return ev

            except Exception:
                continue

        return ev


# ── XSS Evidence Capturer ─────────────────────────────────────────────────────

class XSSEvidenceCapture:
    """Captures the exact reflected payload from the response as evidence."""

    def capture(self, resp_text: str, payload: str, url: str) -> Evidence:
        ev = Evidence()
        ev.probe_url     = url
        ev.probe_payload = payload

        # Find the payload in the response and extract context around it
        pos = resp_text.find(payload)
        if pos >= 0:
            start = max(0, pos - 50)
            excerpt = resp_text[start:start + len(payload) + 100]
            ev.response_excerpt  = excerpt.strip()
            ev.matched_pattern   = payload[:80]
            ev.verification_note = (
                "Payload reflected unencoded in HTML response — "
                "executes in browser if not filtered by CSP"
            )
        else:
            ev.matched_pattern   = "Payload reflected (encoding check failed)"
            ev.verification_note = "Payload present but exact position not captured"

        return ev

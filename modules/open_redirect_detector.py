"""
Open Redirect Detection Module
Tests for unvalidated redirect vulnerabilities
"""

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

from config import DETECTION_CONFIG

logger = logging.getLogger(__name__)


class OpenRedirectDetector:
    """
    Open Redirect vulnerability detector
    """
    
    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config
        self.redirect_config = DETECTION_CONFIG['open_redirect']
        self.payloads = self.redirect_config['payloads']
        
        # Common redirect parameter names
        self.redirect_params = [
            'redirect',
            'redirect_to',
            'return',
            'return_url',
            'return_to',
            'url',
            'next',
            'goto',
            'redir',
            'r',
            'return_path',
            'continue',
            'dest',
            'destination',
            'link',
            'out',
            'view',
            'path',
            'dir',
            'show',
            'open',
            'file',
            'location',
            'returnUrl',
            'returnTo',
            'redirectUrl',
            'redirectUri',
            'redirect_url',
            'redirect_uri',
        ]
    
    def test_url_parameter(self, url: str, param_name: str) -> bool:
        """
        Test URL parameter for open redirect
        """
        return self.verify_url_parameter(url, param_name) is not None

    def verify_url_parameter(self, url: str, param_name: str) -> Optional[Dict]:
        """
        Full verification with structured evidence and confidence score.

        Confidence levels:
          88 — Server-side redirect (Location header) confirmed twice with
               independent payloads pointing to external domains
          65 — Single confirmation only
        """
        from modules.verification_engine import VerifiedFinding, Evidence

        try:
            is_redirect_param = any(
                pattern in param_name.lower()
                for pattern in self.redirect_params
            )
            if not is_redirect_param:
                return None

            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if param_name not in params:
                return None

            for payload in self.payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    response = self.session.get(
                        test_url, timeout=self.config['request_timeout'], allow_redirects=False
                    )
                except Exception as e:
                    logger.debug(f"Redirect test error: {e}")
                    continue

                if response.status_code not in [301, 302, 303, 307, 308]:
                    continue

                location = response.headers.get('Location', '')
                if not self._is_external_redirect(location, parsed.netloc):
                    continue

                confirmed = self._confirm_redirect(url, param_name)
                confidence = 88 if confirmed else 65

                logger.warning(f"Open Redirect confirmed in {param_name} at {url}")

                finding = VerifiedFinding(
                    vuln_type   = "Open Redirect",
                    url         = url,
                    parameter   = param_name,
                    severity    = "Medium",
                    confidence  = confidence,
                    owasp       = "A04 – Insecure Design",
                    description = (
                        f"Parameter '{param_name}' controls a server-side redirect to an "
                        f"external domain with no destination validation."
                    ),
                    evidence = Evidence(
                        probe_url        = test_url,
                        probe_payload    = payload,
                        response_status  = response.status_code,
                        response_excerpt = f"Location: {location}",
                        matched_pattern  = f"HTTP {response.status_code} redirect to external domain",
                        verification_note= (
                            "Confirmed with a second independent payload" if confirmed
                            else "Single confirmation only — re-test manually before reporting as Critical"
                        ),
                    ),
                )
                return finding.to_dict()

            return None

        except Exception as e:
            logger.error(f"Open Redirect test error: {e}")
            return None

    def _is_external_redirect(self, location: str, original_domain: str) -> bool:
        """
        Return True only if the redirect destination is a DIFFERENT domain.

        Bug fix: the old code returned True for any URL starting with 'https:'
        or 'http:' — this flagged redirects to https://same-domain.com/login
        as open redirects because they start with 'https:'. The check now
        correctly compares the destination netloc against the origin domain.
        """
        if not location:
            return False

        # Protocol-relative URLs (//evil.com/...) — always external
        if location.startswith('//'):
            destination = urlparse('https:' + location).netloc
            return destination != original_domain

        # Absolute URLs — compare netloc to origin
        if location.startswith(('http://', 'https://')):
            destination = urlparse(location).netloc
            if not destination:
                return False
            # Strip www. for comparison so www.evil.com != example.com
            # but www.example.com == example.com is NOT flagged
            def strip_www(d: str) -> str:
                return d.lstrip('www.') if d.startswith('www.') else d
            return strip_www(destination) != strip_www(original_domain)

        # Relative URLs — never external
        return False
    
    def _confirm_redirect(self, url: str, param_name: str) -> bool:
        """Confirm open redirect with additional test"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Try with a different payload
            test_payload = "https://evil.com"
            params[param_name] = test_payload
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            response = self.session.get(
                test_url,
                timeout=10,
                allow_redirects=False
            )
            
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if 'evil.com' in location or location.startswith('//'):
                    return True
            
            return False
            
        except:
            return False
    
    def _check_js_redirect(self, html: str) -> bool:
        """Check for JavaScript-based redirects"""
        patterns = [
            r'location\.href\s*=\s*[\'"][^\'"]*[\'"]',
            r'location\.replace\s*\([\'"][^\'"]*[\'"]',
            r'window\.location\s*=\s*[\'"][^\'"]*[\'"]',
        ]
        
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        return False
    
    def scan_for_redirect_params(self, url: str) -> List[str]:
        """
        Scan URL for potential redirect parameters
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        found_params = []
        for param_name in params:
            if any(pattern in param_name.lower() for pattern in self.redirect_params):
                found_params.append(param_name)
        
        return found_params

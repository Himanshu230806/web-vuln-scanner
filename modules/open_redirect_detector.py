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
        try:
            # Check if parameter is a known redirect parameter
            is_redirect_param = any(
                pattern in param_name.lower() 
                for pattern in self.redirect_params
            )
            
            if not is_redirect_param:
                return False
            
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if param_name not in params:
                return False
            
            original_value = params[param_name][0]
            
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
                        timeout=self.config['request_timeout'],
                        allow_redirects=False
                    )
                    
                    # Check for redirect response
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        
                        # Check if redirecting to external domain
                        if self._is_external_redirect(location, parsed.netloc):
                            # Confirm vulnerability
                            if self._confirm_redirect(url, param_name):
                                logger.warning(f"Open Redirect confirmed in {param_name} at {url}")
                                return True
                    
                    # Check for JavaScript redirect in body
                    if self._check_js_redirect(response.text):
                        return True
                
                except Exception as e:
                    logger.debug(f"Redirect test error: {e}")
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"Open Redirect test error: {e}")
            return False
    
    def _is_external_redirect(self, location: str, original_domain: str) -> bool:
        """Check if redirect goes to external domain"""
        if not location:
            return False
        
        # Check for protocol-relative URLs
        if location.startswith('//'):
            return True
        
        # Check for absolute URLs
        if location.startswith('http'):
            parsed = urlparse(location)
            return parsed.netloc != original_domain
        
        # Check for protocol-switching URLs
        if location.startswith('https:') or location.startswith('http:'):
            return True
        
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

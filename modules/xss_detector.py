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

logger = logging.getLogger(__name__)


class XSSDetector:
    """
    XSS vulnerability detector
    """
    
    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config
        self.xss_config = DETECTION_CONFIG['xss']
        self.payloads = self.xss_config['payloads']
        self.confirmatory = self.xss_config['confirmatory_payloads']
        
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
        """Check if payload is properly HTML encoded"""
        # Check for common encodings
        encoded_variants = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '&LT;').replace('>', '&GT;'),
            payload.replace('"', '&quot;'),
            payload.replace("'", '&#x27;').replace("'", '&#39;'),
            payload.replace('<', '&#60;').replace('>', '&#62;'),
        ]
        
        for encoded in encoded_variants:
            if encoded in response_text:
                return True
        
        return False

"""
Cross-Site Request Forgery (CSRF) Detection Module
Tests for missing or inadequate CSRF protection
"""

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from config import DETECTION_CONFIG

logger = logging.getLogger(__name__)


class CSRFDetector:
    """
    CSRF vulnerability detector
    """
    
    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config
        self.csrf_config = DETECTION_CONFIG['csrf']
        self.token_patterns = self.csrf_config['check_token_patterns']
        
        # Common CSRF token names
        self.csrf_names = [
            'csrf_token',
            'csrfmiddlewaretoken',
            '_token',
            'authenticity_token',
            '__requestverificationtoken',
            '_csrf_token',
            'xsrf_token',
            '_wpnonce',
            'nonce',
            'token',
            'csrf',
        ]
    
    def test_form(self, form: Dict, url: str) -> Optional[Dict]:
        """
        Test form for CSRF protection
        """
        try:
            method = form.get('method', 'GET')
            inputs = form.get('inputs', [])
            
            # CSRF only relevant for state-changing methods
            if method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
                return None
            
            issues = []
            
            # Check for CSRF token in form
            has_token = False
            token_field = None
            
            for inp in inputs:
                inp_name = inp.get('name', '').lower()
                
                for pattern in self.csrf_names:
                    if pattern in inp_name:
                        has_token = True
                        token_field = inp
                        break
            
            if not has_token:
                issues.append("No CSRF token found in form")
            
            # Check for SameSite cookie attribute by making a request
            try:
                response = self.session.get(url, timeout=10)
                cookies = response.cookies
                
                for cookie in cookies:
                    # Check for session cookies without SameSite
                    if any(x in cookie.name.lower() for x in ['session', 'auth', 'token', 'id']):
                        # This is a simplified check - real check would need more context
                        pass
            
            except Exception as e:
                logger.debug(f"Cookie check error: {e}")
            
            # Check if form submission accepts requests without Referer header
            action = form.get('action', url)
            test_data = {}
            
            for inp in inputs:
                if inp.get('type') not in ['submit', 'button', 'image', 'file']:
                    test_data[inp['name']] = inp.get('value') or 'test'
            
            # Try submission without proper headers
            try:
                headers = {
                    'Referer': '',  # Empty referer
                    'Origin': None,
                }
                
                response = self.session.post(
                    action,
                    data=test_data,
                    headers=headers,
                    timeout=10,
                    allow_redirects=False
                )
                
                # If successful (2xx or 3xx), CSRF protection might be missing
                if response.status_code in [200, 201, 302, 303, 307, 308]:
                    issues.append("Form accepted submission without proper origin validation")
            
            except Exception as e:
                logger.debug(f"CSRF header test error: {e}")
            
            if issues:
                return {
                    'issues': issues,
                    'recommendation': 'Implement CSRF tokens and validate Origin/Referer headers',
                }
            
            return None
            
        except Exception as e:
            logger.error(f"CSRF test error: {e}")
            return None
    
    def check_cookie_protection(self, url: str) -> Dict:
        """
        Check cookie security attributes relevant to CSRF
        """
        try:
            response = self.session.get(url, timeout=10)
            cookie_issues = []
            
            for cookie in response.cookies:
                # Check SameSite attribute
                # Note: python-requests doesn't expose SameSite directly
                # This is a simplified check
                
                if 'session' in cookie.name.lower():
                    if not cookie.secure:
                        cookie_issues.append(f"Cookie '{cookie.name}' missing Secure flag")
                    
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        cookie_issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")
            
            return {
                'issues': cookie_issues,
                'cookies_found': [c.name for c in response.cookies],
            }
            
        except Exception as e:
            logger.error(f"Cookie check error: {e}")
            return {}

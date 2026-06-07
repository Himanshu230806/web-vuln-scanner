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
        
        # File inclusion indicators
        self.lfi_indicators = [
            "root:x:",
            "bin:x:",
            "daemon:x:",
            "[boot loader]",
            "mult(0)disk(0)rdisk(0)",
            "; for 16-bit app support",
            "[fonts]",
            "[extensions]",
            "[mci extensions]",
            "[files]",
            "[Mail]",
            "MAPI=1",
        ]
    
    def test_url(self, url: str) -> Optional[Dict]:
        """
        Test URL for directory traversal in path
        """
        try:
            parsed = urlparse(url)
            path = parsed.path
            
            # Check if path has file extension that might be vulnerable
            vulnerable_extensions = ['.php', '.jsp', '.asp', '.aspx', '.cgi', '.pl']
            
            if not any(path.endswith(ext) for ext in vulnerable_extensions):
                return None
            
            results = {}
            
            # Test path-based traversal
            for payload in self.payloads[:3]:
                # Modify URL path
                test_path = path + payload
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, test_path,
                    parsed.params, parsed.query, parsed.fragment
                ))
                
                try:
                    response = self.session.get(
                        test_url,
                        timeout=self.config['request_timeout']
                    )
                    
                    if self._check_indicators(response.text):
                        results['path_based'] = {
                            'payload': payload,
                            'url': test_url,
                        }
                        return results
                
                except Exception as e:
                    logger.debug(f"DT path test error: {e}")
            
            return None if not results else results
            
        except Exception as e:
            logger.error(f"DT URL test error: {e}")
            return None
    
    def test_url_parameter(self, url: str, param_name: str) -> bool:
        """
        Test URL parameter for directory traversal
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if param_name not in params:
                return False
            
            original_value = params[param_name][0]
            
            all_payloads = self.payloads + self.additional_payloads
            
            for payload in all_payloads:
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
                    
                    if self._check_indicators(response.text):
                        logger.warning(f"Directory Traversal confirmed in {param_name} at {url}")
                        return True
                
                except Exception as e:
                    logger.debug(f"DT param test error: {e}")
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"DT param test error: {e}")
            return False
    
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
                        
                        if self._check_indicators(response.text):
                            results[field_name] = {
                                'payload': payload,
                                'indicators_found': self._get_found_indicators(response.text),
                            }
                            return results
                    
                    except Exception as e:
                        logger.debug(f"DT form test error: {e}")
                        continue
            
            return None if not results else results
            
        except Exception as e:
            logger.error(f"DT form test error: {e}")
            return None
    
    def _check_indicators(self, response_text: str) -> bool:
        """Check if response contains file content indicators"""
        text_lower = response_text.lower()
        
        for indicator in self.indicators:
            if indicator.lower() in text_lower:
                return True
        
        # Check for common file patterns
        patterns = [
            r'root:x:\d+:\d+:',  # /etc/passwd pattern
            r'\[boot loader\]',   # Windows boot.ini
            r'<\?php',           # PHP source code
            r'\[font\]',         # Windows INI files
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def _get_found_indicators(self, response_text: str) -> List[str]:
        """Get list of indicators found in response"""
        found = []
        text_lower = response_text.lower()
        
        for indicator in self.indicators:
            if indicator.lower() in text_lower:
                found.append(indicator)
        
        return found

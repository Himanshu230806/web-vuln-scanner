"""
OWASP ZAP Integration Module
Integrates with OWASP ZAP API for enhanced scanning
"""

import logging
import time
from typing import Dict, List, Optional

from zapv2 import ZAPv2

from config import ZAP_CONFIG

logger = logging.getLogger(__name__)


class ZAPIntegration:
    """
    OWASP ZAP Scanner Integration
    """
    
    def __init__(self):
        self.config = ZAP_CONFIG
        self.zap = None
        self.connected = False
        
        if self.config['enabled']:
            self._connect()
    
    def _connect(self):
        """Establish connection to ZAP API"""
        try:
            self.zap = ZAPv2(
                proxies={'http': self.config['proxy'], 'https': self.config['proxy']},
                apikey=self.config['api_key'] if self.config['api_key'] else None
            )
            
            # Test connection
            version = self.zap.core.version
            print(f"[+] Connected to OWASP ZAP v{version}")
            self.connected = True
            
        except Exception as e:
            logger.warning(f"Could not connect to ZAP: {e}")
            self.connected = False
    
    def is_available(self) -> bool:
        """Check if ZAP is available"""
        return self.connected and self.zap is not None
    
    def spider_scan(self, target: str, max_depth: int = None) -> List[str]:
        """
        Run ZAP spider to discover URLs
        """
        if not self.is_available():
            return []
        
        try:
            max_depth = max_depth or self.config['spider_max_depth']
            
            print(f"[*] Starting ZAP spider on {target}")
            
            # Start spider
            scan_id = self.zap.spider.scan(target, maxDepth=max_depth)
            
            # Wait for completion
            while int(self.zap.spider.status(scan_id)) < 100:
                time.sleep(1)
            
            print(f"[+] ZAP spider complete")
            
            # Get discovered URLs
            urls = self.zap.spider.results(scan_id)
            return urls
            
        except Exception as e:
            logger.error(f"ZAP spider error: {e}")
            return []
    
    def active_scan(self, target: str) -> List[Dict]:
        """
        Run ZAP active scan and return vulnerabilities
        """
        if not self.is_available():
            return []
        
        vulnerabilities = []
        
        try:
            print(f"[*] Starting ZAP active scan on {target}")
            
            # Spider first
            self.spider_scan(target)
            
            # Run active scan if enabled
            if self.config['active_scan']:
                scan_id = self.zap.ascan.scan(target)
                
                # Wait for completion
                while int(self.zap.ascan.status(scan_id)) < 100:
                    progress = self.zap.ascan.status(scan_id)
                    print(f"[*] ZAP Active Scan progress: {progress}%", end='\r')
                    time.sleep(5)
                
                print(f"\n[+] ZAP active scan complete")
            
            # Get alerts
            alerts = self.zap.core.alerts()
            
            for alert in alerts:
                vuln = {
                    'type': alert.get('alert', 'Unknown'),
                    'url': alert.get('url', ''),
                    'severity': alert.get('riskdesc', 'Informational').split()[0],
                    'description': alert.get('description', ''),
                    'solution': alert.get('solution', ''),
                    'reference': alert.get('reference', ''),
                    'param': alert.get('param', ''),
                    'attack': alert.get('attack', ''),
                    'evidence': alert.get('evidence', ''),
                    'source': 'OWASP ZAP',
                }
                vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"ZAP active scan error: {e}")
            return []
    
    def get_scan_status(self) -> Dict:
        """Get current scan status"""
        if not self.is_available():
            return {'error': 'ZAP not connected'}
        
        try:
            return {
                'version': self.zap.core.version,
                'urls': len(self.zap.core.urls()),
                'alerts': len(self.zap.core.alerts()),
            }
        except Exception as e:
            return {'error': str(e)}
    
    def generate_report(self, report_type: str = 'html') -> str:
        """
        Generate report using ZAP
        """
        if not self.is_available():
            return ""
        
        try:
            if report_type == 'html':
                return self.zap.core.htmlreport()
            elif report_type == 'xml':
                return self.zap.core.xmlreport()
            elif report_type == 'json':
                return self.zap.core.jsonreport()
            else:
                return self.zap.core.htmlreport()
        except Exception as e:
            logger.error(f"ZAP report error: {e}")
            return ""

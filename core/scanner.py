"""
Main Scanner Engine
Coordinates all vulnerability detection modules
"""

import logging
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from colorama import Fore, Style, init

from config import SCANNER_CONFIG, LOGGING_CONFIG
from core.crawler import WebCrawler
from modules.sqli_detector import SQLiDetector
from modules.xss_detector import XSSDetector
from modules.csrf_detector import CSRFDetector
from modules.open_redirect_detector import OpenRedirectDetector
from modules.directory_traversal_detector import DirectoryTraversalDetector
from modules.zap_integration import ZAPIntegration

init(autoreset=True)

# Setup logging
logging.basicConfig(
    level=LOGGING_CONFIG["level"],
    format=LOGGING_CONFIG["format"],
    handlers=[
        logging.FileHandler(LOGGING_CONFIG["file"]),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """
    Main vulnerability scanner class that orchestrates all detection modules
    """
    
    def __init__(self, target_url: str, scan_config: Optional[Dict] = None):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.config = {**SCANNER_CONFIG, **(scan_config or {})}
        
        # Initialize session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config['user_agent']
        })
        self.session.verify = self.config['verify_ssl']
        
        # Initialize components
        self.crawler = WebCrawler(self.target_url, self.session, self.config)
        self.zap = ZAPIntegration() if self.config.get('use_zap', False) else None
        
        # Initialize detectors
        self.detectors = {
            'sqli': SQLiDetector(self.session, self.config),
            'xss': XSSDetector(self.session, self.config),
            'csrf': CSRFDetector(self.session, self.config),
            'open_redirect': OpenRedirectDetector(self.session, self.config),
            'directory_traversal': DirectoryTraversalDetector(self.session, self.config),
        }
        
        # Results storage
        self.vulnerabilities = []
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'urls_crawled': 0,
            'forms_tested': 0,
            'parameters_tested': 0,
        }
        
    def print_banner(self):
        """Display scanner banner"""
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║          Web Application Vulnerability Scanner v2.0           ║
║                    Professional Edition                       ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
Target: {Fore.YELLOW}{self.target_url}{Style.RESET_ALL}
Started: {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}
"""
        print(banner)
        
    def run_scan(self) -> List[Dict]:
        """
        Execute full vulnerability scan
        """
        self.print_banner()
        self.scan_stats['start_time'] = datetime.now()
        
        try:
            # Phase 1: Crawling
            print(f"\n{Fore.CYAN}[*] Phase 1: Crawling target...{Style.RESET_ALL}")
            crawled_urls = self.crawler.crawl()
            self.scan_stats['urls_crawled'] = len(crawled_urls)
            print(f"{Fore.GREEN}[+] Discovered {len(crawled_urls)} URLs{Style.RESET_ALL}")
            
            # Phase 2: ZAP Scan (if enabled)
            if self.zap and self.zap.is_available():
                print(f"\n{Fore.CYAN}[*] Phase 2: Running OWASP ZAP scan...{Style.RESET_ALL}")
                zap_results = self.zap.active_scan(self.target_url)
                self.vulnerabilities.extend(zap_results)
            
            # Phase 3: Custom Detection
            print(f"\n{Fore.CYAN}[*] Phase 3: Running vulnerability detection...{Style.RESET_ALL}")
            self._run_detection(crawled_urls)
            
            # Phase 4: Analyze results
            self._analyze_results()
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            print(f"{Fore.RED}[!] Error during scan: {str(e)}{Style.RESET_ALL}")
            
        finally:
            self.scan_stats['end_time'] = datetime.now()
            self._print_summary()
            
        return self.vulnerabilities
    
    def _run_detection(self, urls: List[str]):
        """Run all vulnerability detectors on discovered URLs"""
        
        for url in urls:
            print(f"\n{Fore.BLUE}[*] Testing: {url}{Style.RESET_ALL}")
            
            # Test URL parameters
            parsed = urlparse(url)
            if parsed.query:
                self._test_url_parameters(url)
            
            # Test forms
            self._test_forms(url)
            
            # Test specific paths for directory traversal
            self.detectors['directory_traversal'].test_url(url)
            
            time.sleep(self.config['delay'])
    
    def _test_url_parameters(self, url: str):
        """Test URL parameters for vulnerabilities"""
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in params:
            self.scan_stats['parameters_tested'] += 1
            
            # Test for SQL Injection
            if self.detectors['sqli'].test_url_parameter(url, param_name):
                self._add_vulnerability({
                    'type': 'SQL Injection',
                    'url': url,
                    'parameter': param_name,
                    'severity': 'Critical',
                    'description': f"SQL Injection vulnerability detected in parameter '{param_name}'",
                })
            
            # Test for XSS
            if self.detectors['xss'].test_url_parameter(url, param_name):
                self._add_vulnerability({
                    'type': 'Cross-Site Scripting (XSS)',
                    'url': url,
                    'parameter': param_name,
                    'severity': 'High',
                    'description': f"Reflected XSS vulnerability detected in parameter '{param_name}'",
                })
            
            # Test for Open Redirect
            if self.detectors['open_redirect'].test_url_parameter(url, param_name):
                self._add_vulnerability({
                    'type': 'Open Redirect',
                    'url': url,
                    'parameter': param_name,
                    'severity': 'Medium',
                    'description': f"Open Redirect vulnerability detected in parameter '{param_name}'",
                })
    
    def _test_forms(self, url: str):
        """Test forms on the page"""
        forms = self.crawler.get_forms(url)
        
        for form in forms:
            self.scan_stats['forms_tested'] += 1
            
            # Test for SQL Injection
            sqli_result = self.detectors['sqli'].test_form(form, url)
            if sqli_result:
                self._add_vulnerability({
                    'type': 'SQL Injection',
                    'url': url,
                    'form_action': form.get('action'),
                    'severity': 'Critical',
                    'description': "SQL Injection vulnerability detected in form submission",
                    'details': sqli_result
                })
            
            # Test for XSS
            xss_result = self.detectors['xss'].test_form(form, url)
            if xss_result:
                self._add_vulnerability({
                    'type': 'Cross-Site Scripting (XSS)',
                    'url': url,
                    'form_action': form.get('action'),
                    'severity': 'High',
                    'description': "Stored/Reflected XSS vulnerability detected in form",
                    'details': xss_result
                })
            
            # Test for CSRF
            csrf_result = self.detectors['csrf'].test_form(form, url)
            if csrf_result:
                self._add_vulnerability({
                    'type': 'Cross-Site Request Forgery (CSRF)',
                    'url': url,
                    'form_action': form.get('action'),
                    'severity': 'Medium',
                    'description': "CSRF protection missing or inadequate",
                    'details': csrf_result
                })
    
    def _add_vulnerability(self, vuln: Dict):
        """Add vulnerability to results with timestamp"""
        vuln['timestamp'] = datetime.now().isoformat()
        vuln['id'] = f"VULN-{len(self.vulnerabilities) + 1:04d}"
        
        # Check for duplicates
        for existing in self.vulnerabilities:
            if (existing['type'] == vuln['type'] and 
                existing['url'] == vuln['url']):
                return
        
        self.vulnerabilities.append(vuln)
        
        severity_color = {
            'Critical': Fore.RED,
            'High': Fore.LIGHTRED_EX,
            'Medium': Fore.YELLOW,
            'Low': Fore.GREEN,
            'Info': Fore.CYAN,
        }.get(vuln['severity'], Fore.WHITE)
        
        print(f"{severity_color}[!] {vuln['severity']}: {vuln['type']} - {vuln['url']}{Style.RESET_ALL}")
    
    def _analyze_results(self):
        """Perform additional analysis on findings"""
        # Group vulnerabilities by type
        by_type = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(vuln)
        
        # Add summary
        self.scan_stats['vulnerabilities_by_type'] = {
            k: len(v) for k, v in by_type.items()
        }
    
    def _print_summary(self):
        """Print scan summary"""
        duration = self.scan_stats['end_time'] - self.scan_stats['start_time']
        
        summary = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                        SCAN SUMMARY                          ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

Target: {self.target_url}
Duration: {duration}
URLs Crawled: {self.scan_stats['urls_crawled']}
Forms Tested: {self.scan_stats['forms_tested']}
Parameters Tested: {self.scan_stats['parameters_tested']}

{Fore.CYAN}VULNERABILITIES FOUND: {len(self.vulnerabilities)}{Style.RESET_ALL}
"""
        # Count by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        summary += f"""
{Fore.RED}Critical: {severity_counts['Critical']}{Style.RESET_ALL}
{Fore.LIGHTRED_EX}High: {severity_counts['High']}{Style.RESET_ALL}
{Fore.YELLOW}Medium: {severity_counts['Medium']}{Style.RESET_ALL}
{Fore.GREEN}Low: {severity_counts['Low']}{Style.RESET_ALL}
{Fore.CYAN}Info: {severity_counts['Info']}{Style.RESET_ALL}
"""
        print(summary)

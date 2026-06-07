"""
Web Crawler Module
Discovers all URLs and forms in the target application
"""

import logging
import re
import time
from typing import List, Set, Dict
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style

from config import SCANNER_CONFIG

logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Web crawler that discovers URLs and extracts forms
    """
    
    def __init__(self, base_url: str, session: requests.Session, config: Dict):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.config = config
        
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.forms_data: Dict[str, List[Dict]] = {}
        
        # File extensions to skip
        self.skip_extensions = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.css', '.js', '.xml', '.json', '.txt', '.log',
        }
        
    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to target domain"""
        try:
            return urlparse(url).netloc == self.domain
        except:
            return False
    
    def is_valid_url(self, url: str) -> bool:
        """Check if URL should be crawled"""
        try:
            parsed = urlparse(url)
            
            # Must be HTTP/HTTPS
            if parsed.scheme not in ('http', 'https'):
                return False
            
            # Skip fragments
            if '#' in url:
                url = url.split('#')[0]
            
            # Skip file extensions
            path = parsed.path.lower()
            for ext in self.skip_extensions:
                if path.endswith(ext):
                    return False
            
            # Must be same domain
            if not self.is_same_domain(url):
                return False
            
            return True
        except:
            return False
    
    def extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find all anchor tags
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            full_url = urljoin(base_url, href)
            if self.is_valid_url(full_url):
                links.append(full_url.split('#')[0])  # Remove fragments
        
        # Find JavaScript redirects
        js_patterns = [
            r'location\.href\s*=\s*["\'](.*?)["\']',
            r'location\.replace\s*\(\s*["\'](.*?)["\']',
            r'window\.location\s*=\s*["\'](.*?)["\']',
        ]
        for pattern in js_patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                full_url = urljoin(base_url, match)
                if self.is_valid_url(full_url):
                    links.append(full_url)
        
        return list(set(links))
    
    def extract_forms(self, html: str, url: str) -> List[Dict]:
        """Extract all forms from HTML"""
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
            }
            
            # Extract all input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                
                if input_name:
                    form_data['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_tag.get('value', ''),
                    })
            
            forms.append(form_data)
        
        self.forms_data[url] = forms
        return forms
    
    def crawl(self, start_url: str = None, max_depth: int = None) -> List[str]:
        """
        Crawl the website starting from base_url
        """
        start = start_url or self.base_url
        max_depth = max_depth or self.config.get('max_depth', 3)
        max_urls = self.config.get('max_urls', 500)
        
        urls_to_visit = [(start, 0)]  # (url, depth)
        
        print(f"{Fore.CYAN}[*] Starting crawl from: {start}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Max depth: {max_depth}, Max URLs: {max_urls}{Style.RESET_ALL}")
        
        while urls_to_visit and len(self.visited_urls) < max_urls:
            current_url, depth = urls_to_visit.pop(0)
            
            if current_url in self.visited_urls or depth > max_depth:
                continue
            
            try:
                print(f"{Fore.BLUE}[*] Crawling: {current_url}{Style.RESET_ALL}", end='\r')
                
                response = self.session.get(
                    current_url,
                    timeout=self.config['request_timeout'],
                    allow_redirects=self.config['follow_redirects']
                )
                
                self.visited_urls.add(current_url)
                
                if 'text/html' in response.headers.get('content-type', ''):
                    # Extract links
                    links = self.extract_links(response.text, current_url)
                    for link in links:
                        if link not in self.visited_urls:
                            self.discovered_urls.add(link)
                            urls_to_visit.append((link, depth + 1))
                    
                    # Extract forms
                    self.extract_forms(response.text, current_url)
                
                time.sleep(self.config.get('delay', 0.5))
                
            except Exception as e:
                logger.debug(f"Error crawling {current_url}: {e}")
                continue
        
        print(f"\n{Fore.GREEN}[+] Crawl complete. Visited {len(self.visited_urls)} URLs{Style.RESET_ALL}")
        return list(self.discovered_urls.union(self.visited_urls))
    
    def get_forms(self, url: str) -> List[Dict]:
        """Get forms for a specific URL"""
        return self.forms_data.get(url, [])
    
    def get_all_forms(self) -> Dict[str, List[Dict]]:
        """Get all discovered forms"""
        return self.forms_data

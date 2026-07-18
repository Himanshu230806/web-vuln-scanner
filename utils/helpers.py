"""
Utility helper functions
"""

import hashlib
import logging
import random
import re
import string
import time
from typing import Dict, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)


def generate_random_string(length: int = 8) -> str:
    """Generate random string for testing"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def normalize_url(url: str) -> str:
    """Normalize URL for comparison"""
    parsed = urlparse(url)
    # Sort query parameters
    query = parse_qs(parsed.query)
    sorted_query = urlencode(sorted(query.items()), doseq=True)
    
    return urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        parsed.params,
        sorted_query,
        ''  # Remove fragment
    ))


def get_domain(url: str) -> str:
    """Extract domain from URL"""
    return urlparse(url).netloc


def is_valid_url(url: str) -> bool:
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def calculate_hash(data: str) -> str:
    """Calculate MD5 hash"""
    return hashlib.md5(data.encode()).hexdigest()


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    return re.sub(r'[^\w\-_\. ]', '_', filename)


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"


def chunk_list(lst: List, chunk_size: int) -> List:
    """Split list into chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def retry_on_exception(max_retries: int = 3, delay: float = 1.0):
    """Decorator to retry function on exception"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    logger.warning(f"Attempt {attempt + 1} failed: {e}")
                    time.sleep(delay * (attempt + 1))
            return None
        return wrapper
    return decorator


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string with ellipsis"""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def encode_html_entities(text: str) -> str:
    """Encode special HTML characters"""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))


def decode_html_entities(text: str) -> str:
    """Decode HTML entities"""
    import html
    return html.unescape(text)


def get_content_type(response) -> str:
    """Get content type from response"""
    content_type = response.headers.get('Content-Type', '')
    return content_type.split(';')[0].strip()


def is_json_response(response) -> bool:
    """Check if response is JSON"""
    return 'application/json' in response.headers.get('Content-Type', '')


def is_html_response(response) -> bool:
    """Check if response is HTML"""
    return 'text/html' in response.headers.get('Content-Type', '')


def extract_csrf_token(html: str, patterns: List[str] = None) -> str:
    """Extract CSRF token from HTML"""
    import re
    
    default_patterns = [
        r'name=["\']csrf[^"\']*["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf[^"\']*["\']',
        r'"csrfToken":\s*"([^"]+)"',
        r'csrf:\s*["\']([^"\']+)["\']',
    ]
    
    patterns = patterns or default_patterns
    
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None


def build_url(base: str, path: str, params: Dict = None) -> str:
    """Build URL with parameters"""
    from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
    
    full_url = urljoin(base, path)
    
    if params:
        parsed = urlparse(full_url)
        query = parse_qs(parsed.query)
        query.update(params)
        new_query = urlencode(query, doseq=True)
        full_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
    
    return full_url

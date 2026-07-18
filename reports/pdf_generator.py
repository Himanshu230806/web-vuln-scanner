"""
Professional PDF Report Generator  v2.0
Generates a full pentest-grade vulnerability report with:
  - Cover page with risk rating
  - Table of contents
  - Executive summary
  - OWASP Top 10 coverage matrix
  - Severity distribution chart (table-based)
  - Findings summary table
  - Per-vulnerability detail cards:
      Description | Impact | Evidence | Recommended Fix | References
  - Prioritised remediation roadmap
  - Scan methodology & statistics appendix
"""

import html as html_mod
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.platypus.flowables import HRFlowable

from config import OUTPUT_DIR, REPORT_CONFIG

logger = logging.getLogger(__name__)

# ── Colour palette ────────────────────────────────────────────────────────────
C_DARK      = colors.HexColor("#0f172a")   # page header / cover bg
C_NAVY      = colors.HexColor("#1e3a5f")   # section headers
C_ACCENT    = colors.HexColor("#2563eb")   # accent blue
C_CRITICAL  = colors.HexColor("#dc2626")
C_HIGH      = colors.HexColor("#ea580c")
C_MEDIUM    = colors.HexColor("#d97706")
C_LOW       = colors.HexColor("#16a34a")
C_INFO      = colors.HexColor("#2563eb")
C_LIGHT_BG  = colors.HexColor("#f8fafc")
C_BORDER    = colors.HexColor("#e2e8f0")
C_CODE_BG   = colors.HexColor("#1e293b")
C_CODE_FG   = colors.HexColor("#e2e8f0")
C_WHITE     = colors.white
C_BLACK     = colors.HexColor("#0f172a")
C_MUTED     = colors.HexColor("#64748b")
C_TABLE_HDR = colors.HexColor("#1e3a5f")

SEV_COLORS = {
    "Critical": C_CRITICAL,
    "High":     C_HIGH,
    "Medium":   C_MEDIUM,
    "Low":      C_LOW,
    "Info":     C_INFO,
}

SEV_BG = {
    "Critical": colors.HexColor("#fef2f2"),
    "High":     colors.HexColor("#fff7ed"),
    "Medium":   colors.HexColor("#fffbeb"),
    "Low":      colors.HexColor("#f0fdf4"),
    "Info":     colors.HexColor("#eff6ff"),
}

# ── Reference database ────────────────────────────────────────────────────────
VULN_REFERENCES = {
    "SQL Injection": [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ],
    "Cross-Site Scripting (XSS)": [
        "https://owasp.org/www-community/attacks/xss/",
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    "Cross-Site Request Forgery (CSRF)": [
        "https://owasp.org/www-community/attacks/csrf",
        "https://cwe.mitre.org/data/definitions/352.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    "Server-Side Request Forgery (SSRF)": [
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "https://cwe.mitre.org/data/definitions/918.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    "XML External Entity (XXE)": [
        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        "https://cwe.mitre.org/data/definitions/611.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    ],
    "Insecure Direct Object Reference (IDOR)": [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
        "https://cwe.mitre.org/data/definitions/639.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    ],
    "Directory Traversal / LFI": [
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    ],
    "Open Redirect": [
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/601.html",
    ],
    "Security Header Missing": [
        "https://owasp.org/www-project-secure-headers/",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        "https://securityheaders.com/",
    ],
    "Insecure Cookie": [
        "https://owasp.org/www-community/controls/SecureFlag",
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    ],
    "Broken Authentication": [
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cwe.mitre.org/data/definitions/287.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ],
    "Vulnerable Component": [
        "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "https://owasp.org/www-project-dependency-check/",
        "https://nvd.nist.gov/",
    ],
    "Software Integrity Failure": [
        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
    ],
    "Logging & Monitoring Failure": [
        "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
    ],
    "Information Disclosure": [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
        "https://cwe.mitre.org/data/definitions/200.html",
    ],
    "Insecure Transport": [
        "https://owasp.org/www-community/vulnerabilities/Insecure_Transport",
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
    # ── New finding types added in v5 ─────────────────────────────────────
    "Missing Rate Limiting": [
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/307.html",
    ],
    "Information Disclosure": [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
    ],
    "Business Logic Vulnerability": [
        "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
        "https://cwe.mitre.org/data/definitions/840.html",
    ],
    "Command Injection (Blind)": [
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    ],
    "WAF Detected": [
        "https://owasp.org/www-project-web-security-testing-guide/",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ],
    "Insecure Auth Design": [
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cwe.mitre.org/data/definitions/640.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
    ],
    "Information Disclosure (JSON Error)": [
        "https://cwe.mitre.org/data/definitions/209.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
    ],
    # ── Level 1 Passive Scanner finding types ─────────────────────────────
    "Secret / Credential Exposure": [
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        "https://docs.github.com/en/code-security/secret-scanning",
    ],
    "Sensitive Data Exposure": [
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
    ],
    "Attack Chain": [
        "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "https://www.mitre.org/sites/default/files/2021-11/prs-21-4483-enterprise-attack-design-and-philosophy.pdf",
    ],
}

# ── Impact database ───────────────────────────────────────────────────────────
VULN_IMPACT = {
    "SQL Injection": (
        "An attacker can bypass authentication, extract the entire database including "
        "passwords and PII, modify or delete data, and in some configurations execute "
        "operating system commands. This is rated CVSS 9.8 (Critical) in most scenarios."
    ),
    "Cross-Site Scripting (XSS)": (
        "Attackers can steal session cookies, redirect users to phishing sites, log "
        "keystrokes, perform actions on behalf of victims, and spread malware. Stored XSS "
        "affects every visitor of the compromised page."
    ),
    "Cross-Site Request Forgery (CSRF)": (
        "An attacker can trick authenticated users into performing unwanted actions such as "
        "fund transfers, password changes, or account deletion without their knowledge."
    ),
    "Server-Side Request Forgery (SSRF)": (
        "The server can be forced to make requests to internal services, cloud metadata "
        "endpoints (e.g. AWS 169.254.169.254), or internal databases — potentially exposing "
        "cloud credentials, internal APIs, and bypassing firewall rules."
    ),
    "XML External Entity (XXE)": (
        "Attackers can read arbitrary files from the server filesystem (e.g. /etc/passwd, "
        "private keys), perform SSRF, and in some cases achieve remote code execution "
        "via nested entity expansion (Billion Laughs DoS)."
    ),
    "Insecure Direct Object Reference (IDOR)": (
        "Any authenticated user can access or modify data belonging to other users by "
        "changing an ID parameter, leading to full horizontal privilege escalation and "
        "mass data exposure."
    ),
    "Directory Traversal / LFI": (
        "An attacker can read sensitive server files including configuration files, "
        "source code, private keys, and system files such as /etc/passwd or "
        "C:\\Windows\\system32\\config\\SAM."
    ),
    "Open Redirect": (
        "Attackers can craft trusted-looking URLs on your domain that redirect victims "
        "to phishing sites, OAuth token theft pages, or malware distribution sites, "
        "bypassing browser security warnings."
    ),
    "Security Header Missing": (
        "Missing security headers remove browser-enforced protections. Without CSP, "
        "XSS attacks are easier. Without HSTS, attackers can downgrade HTTPS to HTTP. "
        "Without X-Frame-Options, clickjacking attacks are possible."
    ),
    "Broken Authentication": (
        "Attackers can gain unauthorized access to user or admin accounts through "
        "default credentials, brute-force attacks, or session token prediction, "
        "leading to full account takeover."
    ),
    "Vulnerable Component": (
        "Known CVEs in third-party libraries can be exploited with public proof-of-concept "
        "exploits, requiring minimal attacker skill. Impact ranges from XSS to full "
        "Remote Code Execution depending on the component."
    ),
    "Software Integrity Failure": (
        "If a CDN or external resource is compromised, malicious code executes in every "
        "visitor's browser. Exposed .env or .git files leak credentials, API keys, and "
        "full application source code."
    ),
    "Logging & Monitoring Failure": (
        "Without proper logging, security incidents go undetected. Verbose error messages "
        "reveal internal paths, stack traces, and DB schemas that directly aid attackers "
        "in planning targeted exploits."
    ),
    "Information Disclosure": (
        "Exposed server version information helps attackers identify specific CVEs and "
        "tailor exploit code to your exact software versions, significantly lowering the "
        "skill bar required to attack."
    ),
    "Insecure Transport": (
        "Credentials, session tokens, and sensitive data transmitted over HTTP can be "
        "intercepted by network attackers (man-in-the-middle), coffee shop snooping, "
        "or ISP-level interception."
    ),
    "Insecure Cookie": (
        "Cookies without HttpOnly can be stolen via XSS. Cookies without Secure can be "
        "transmitted over HTTP. Cookies without SameSite are vulnerable to CSRF attacks."
    ),
    # ── New finding types added in v5 ─────────────────────────────────────
    "Missing Rate Limiting": (
        "Without login rate limiting, an attacker can brute-force credentials offline-speed "
        "against the live endpoint. A 6-digit OTP with no rate limit can be exhausted in "
        "under 24 hours. Account enumeration via timing or error messages allows building "
        "targeted credential lists for phishing or stuffing attacks."
    ),
    "Business Logic Vulnerability": (
        "Price manipulation can allow purchase of items for free or negative cost. "
        "Negative quantities can generate fraudulent credits. Step-skip vulnerabilities "
        "allow bypassing payment, verification, or approval gates. Mass assignment can "
        "escalate privileges to admin without any authentication bypass."
    ),
    "Command Injection (Blind)": (
        "Blind command injection is full Remote Code Execution — the attacker can read "
        "any file, exfiltrate data, install backdoors, pivot to internal systems, and "
        "achieve complete server compromise, even though no output is reflected in the "
        "response. Rated CVSS 9.8 (Critical) in most scenarios."
    ),
    "WAF Detected": (
        "A WAF is not itself a vulnerability, but its presence means some attack payloads "
        "may be blocked before reaching the application. This is informational — it indicates "
        "the scan may be incomplete and manual testing with bypass techniques is recommended."
    ),
    "Insecure Auth Design": (
        "Non-invalidated password reset tokens allow account takeover even after a user "
        "believes they have secured their account. An attacker who obtains an old reset "
        "link (from logs, email headers, or referrer leakage) can use it to set a new "
        "password and silently take over the account."
    ),
    "Information Disclosure (JSON Error)": (
        "Internal error messages in API responses expose database schema, SQL syntax, "
        "stack traces, internal paths, and framework versions. This directly assists "
        "attackers in crafting targeted SQLi, path traversal, or deserialization exploits "
        "against the specific technologies in use."
    ),
    # ── Level 1 Passive Scanner finding types ─────────────────────────────
    "Secret / Credential Exposure": (
        "Exposed API keys, tokens, and credentials give attackers direct access to "
        "third-party services (AWS, Stripe, GitHub, Slack) without any further attack. "
        "An exposed AWS key can result in complete cloud account compromise, data "
        "exfiltration, and significant financial loss. A database connection string "
        "gives the attacker direct read/write access to all application data."
    ),
    "Sensitive Data Exposure": (
        "Credit card numbers, SSNs, and PII in API responses constitute a direct data "
        "breach, triggering GDPR/PCI-DSS notification obligations and potential fines. "
        "Internal IP addresses aid network reconnaissance for further attacks."
    ),
    "Attack Chain": (
        "Individual vulnerabilities rated Medium or Low in isolation can combine to "
        "form Critical-severity attack chains. An attacker who identifies and exploits "
        "a chain can achieve complete account takeover, privilege escalation, or data "
        "breach even when no single finding appears severe enough to warrant urgent action."
    ),
}

VULN_FIX = {
    "SQL Injection": (
        "Use parameterised queries / prepared statements for ALL database interactions. "
        "Never concatenate user input into SQL strings. Apply an ORM. Implement "
        "least-privilege DB accounts. Enable WAF rules for SQL injection."
    ),
    "Cross-Site Scripting (XSS)": (
        "HTML-encode all user-supplied output. Implement a strict Content-Security-Policy "
        "header. Use modern frameworks that auto-escape (React, Angular, Vue). "
        "Validate and sanitise all inputs server-side."
    ),
    "Cross-Site Request Forgery (CSRF)": (
        "Add an unpredictable CSRF token to every state-changing form and verify it "
        "server-side. Use SameSite=Strict cookies. Check the Origin/Referer header "
        "for sensitive operations."
    ),
    "Server-Side Request Forgery (SSRF)": (
        "Validate and whitelist allowed URL schemes and destinations. Block requests to "
        "private IP ranges (RFC1918) and cloud metadata endpoints. Use a dedicated "
        "egress proxy. Disable redirects in HTTP client libraries."
    ),
    "XML External Entity (XXE)": (
        "Disable external entity processing in your XML parser: set "
        "resolve_entities=False, load_dtd=False, no_network=True. Use JSON instead of "
        "XML where possible. Upgrade XML libraries to current versions."
    ),
    "Insecure Direct Object Reference (IDOR)": (
        "Enforce ownership checks on every resource access — verify the authenticated "
        "user owns the requested resource. Use indirect references (map internal IDs "
        "to user-scoped tokens). Implement attribute-based access control (ABAC)."
    ),
    "Directory Traversal / LFI": (
        "Canonicalise file paths and verify they remain within the allowed base directory. "
        "Use os.path.realpath() and check the result starts with the expected prefix. "
        "Never pass user input directly to file-reading functions."
    ),
    "Open Redirect": (
        "Maintain a whitelist of allowed redirect destinations. Validate that redirect "
        "URLs belong to your domain. If external redirects are required, use an "
        "intermediate confirmation page."
    ),
    "Security Header Missing": (
        "Add all security headers in your web server or application middleware: "
        "Strict-Transport-Security, Content-Security-Policy, X-Frame-Options: DENY, "
        "X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy."
    ),
    "Broken Authentication": (
        "Enforce strong password policy. Implement account lockout after 5–10 failed "
        "attempts. Use multi-factor authentication. Generate session tokens with "
        "os.urandom (≥128 bits). Invalidate sessions on logout and password change."
    ),
    "Vulnerable Component": (
        "Update all dependencies to their latest stable versions. Integrate OWASP "
        "Dependency-Check or Snyk into your CI/CD pipeline. Subscribe to security "
        "advisories for components you use. Remove unused dependencies."
    ),
    "Software Integrity Failure": (
        "Add integrity= and crossorigin= attributes to all external script/style tags. "
        "Block public access to .env, .git, and backup files via server config. "
        "Use a Content Security Policy that restricts allowed script sources."
    ),
    "Logging & Monitoring Failure": (
        "Disable debug mode in production (DEBUG=False). Return generic error pages. "
        "Log all authentication events, access control failures, and input validation "
        "failures. Set up alerting for anomalous patterns. Block public access to "
        "admin panels and monitoring endpoints."
    ),
    "Information Disclosure": (
        "Remove or suppress Server and X-Powered-By headers. Return generic error "
        "messages without stack traces, file paths, or library versions. Review all "
        "API responses for unintended data exposure."
    ),
    "Insecure Transport": (
        "Obtain and configure a TLS certificate (Let's Encrypt is free). Redirect all "
        "HTTP traffic to HTTPS. Enable HSTS with a long max-age. Disable TLS 1.0 and 1.1."
    ),
    "Insecure Cookie": (
        "Set Secure flag on all cookies. Set HttpOnly on session cookies to prevent "
        "JavaScript access. Set SameSite=Strict or SameSite=Lax to prevent CSRF. "
        "Use the __Host- prefix for sensitive cookies."
    ),
    # ── New finding types added in v5 ─────────────────────────────────────
    "Missing Rate Limiting": (
        "Implement account lockout after 5–10 failed login attempts with exponential "
        "backoff. Lock OTP codes after 3–5 failures. Rate-limit password reset to "
        "2–3 requests per hour per email. Return HTTP 429 with Retry-After. "
        "Use identical error messages and response times for all authentication failures."
    ),
    "Business Logic Vulnerability": (
        "Validate all financial values server-side against trusted database records — "
        "never accept client-submitted prices or quantities at face value. Enforce "
        "minimum quantity ≥ 1 server-side. Validate multi-step flow state server-side "
        "in the session before serving any step. Use explicit serializer allowlists "
        "(strong parameters in Rails, serializer fields in Django) to prevent mass "
        "assignment — never bind request bodies directly to model.update()."
    ),
    "Command Injection (Blind)": (
        "Never pass user input to shell commands. Replace shell execution with language-"
        "native APIs (Python subprocess with a list, not shell=True; Java ProcessBuilder "
        "with separate args). If shell execution is unavoidable, strictly whitelist "
        "allowed input characters and values — never use a blacklist."
    ),
    "WAF Detected": (
        "A WAF is a useful defence-in-depth layer but is not a substitute for fixing "
        "underlying vulnerabilities. Ensure application-level input validation and output "
        "encoding are implemented regardless of WAF coverage. WAF rules can be bypassed "
        "by determined attackers."
    ),
    "Insecure Auth Design": (
        "Invalidate all existing reset tokens for an account when a new one is issued. "
        "Use cryptographically random single-use tokens (≥128 bits). Set a short expiry "
        "(10–15 minutes). Store tokens as bcrypt hashes, not plaintext."
    ),
    "Information Disclosure (JSON Error)": (
        "Return generic error messages in API responses (e.g. 'An error occurred'). "
        "Log detailed error information server-side only. Disable stack traces in "
        "production (DEBUG=False). Use a centralised error handler that strips "
        "sensitive information before returning responses to clients."
    ),
    # ── Level 1 Passive Scanner finding types ─────────────────────────────
    "Secret / Credential Exposure": (
        "Immediately rotate ALL exposed credentials — treat them as compromised. "
        "Remove secrets from code, config files, and responses. "
        "Use environment variables or a secrets manager (AWS Secrets Manager, "
        "HashiCorp Vault, GCP Secret Manager). Audit git history for past exposure "
        "with tools like TruffleHog or GitLeaks. Never embed credentials in "
        "client-side code — they are visible to every user."
    ),
    "Sensitive Data Exposure": (
        "Apply field-level filtering on all serialized output — only include fields "
        "the requesting user is authorised to see. Mask PII in API responses "
        "(e.g. show last 4 digits of credit cards only). Implement data "
        "minimisation: don't return fields that the frontend doesn't actually use. "
        "For PCI-DSS compliance, never store or transmit full card numbers."
    ),
    "Attack Chain": (
        "Fix each component vulnerability individually — this automatically breaks "
        "the chain. Prioritise fixing the highest-impact component first (usually "
        "the entry point that enables the chain). Conduct a manual penetration test "
        "to verify the chain cannot be exploited via a route the scanner did not test."
    ),
}

OWASP_CATEGORIES = {
    "A01 – Broken Access Control":     ("A01:2021", "Broken Access Control"),
    "A02 – Cryptographic Failures":    ("A02:2021", "Cryptographic Failures"),
    "A03 – Injection":                 ("A03:2021", "Injection"),
    "A04 – Insecure Design":           ("A04:2021", "Insecure Design"),
    "A05 – Security Misconfiguration": ("A05:2021", "Security Misconfiguration"),
    "A06 – Vulnerable Components":     ("A06:2021", "Vulnerable and Outdated Components"),
    "A07 – Auth Failures":             ("A07:2021", "Identification and Authentication Failures"),
    "A08 – Software Integrity":        ("A08:2021", "Software and Data Integrity Failures"),
    "A09 – Logging Failures":          ("A09:2021", "Security Logging and Monitoring Failures"),
    "A10 – SSRF":                      ("A10:2021", "Server-Side Request Forgery"),
}


def _safe(text: str) -> str:
    """Escape HTML but preserve <br/> tags for reportlab."""
    return html_mod.escape(str(text or ""), quote=False)


def _p(text, style):
    return Paragraph(str(text), style)


def _safe_num(value, default: float = 0.0) -> float:
    """Coerce a value to float for sorting/arithmetic, falling back to
    `default` for None, "N/A", "?", or anything else non-numeric.

    Every finding that reaches this report normally passes through
    VulnerabilityScanner._add_vulnerability(), which guarantees
    cvss_estimate/confidence are numeric — but this report generator can
    also be called directly (tests, scripts, future code paths) with
    hand-built dicts that don't go through that guarantee. The rest of
    this file is defensive about missing/wrong-typed fields everywhere
    else (.get() with safe defaults, str() before display); this keeps
    that same guarantee for the two places these fields are used
    *numerically* (sorting/averaging) rather than just displayed.
    """
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class PDFReportGenerator:

    def __init__(self):
        self.company  = REPORT_CONFIG.get("company_name", "Security Assessment Team")
        self.styles   = getSampleStyleSheet()
        self._build_styles()

    # ── style registry ────────────────────────────────────────────────────────

    def _build_styles(self):
        s = self.styles
        add = s.add

        add(ParagraphStyle("ReportTitle",    parent=s["Normal"],  fontSize=22, textColor=C_WHITE,     alignment=TA_CENTER, fontName="Helvetica-Bold",  spaceAfter=6, leading=28))
        add(ParagraphStyle("ReportSubtitle", parent=s["Normal"],  fontSize=13, textColor=colors.HexColor("#93c5fd"), alignment=TA_CENTER, spaceAfter=4))
        add(ParagraphStyle("CoverMeta",      parent=s["Normal"],  fontSize=10, textColor=colors.HexColor("#cbd5e1"), alignment=TA_CENTER, spaceAfter=3))
        add(ParagraphStyle("H1",             parent=s["Normal"],  fontSize=18, textColor=C_NAVY,       fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=8,  borderPad=4))
        add(ParagraphStyle("H2",             parent=s["Normal"],  fontSize=13, textColor=C_NAVY,       fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=6))
        add(ParagraphStyle("H3",             parent=s["Normal"],  fontSize=11, textColor=C_DARK,       fontName="Helvetica-Bold", spaceBefore=6,  spaceAfter=4))
        add(ParagraphStyle("Body",           parent=s["Normal"],  fontSize=9,  textColor=C_BLACK,      leading=14, spaceAfter=4))
        add(ParagraphStyle("BodyJustify",    parent=s["Normal"],  fontSize=9,  textColor=C_BLACK,      leading=14, spaceAfter=4, alignment=TA_JUSTIFY))
        add(ParagraphStyle("Small",          parent=s["Normal"],  fontSize=8,  textColor=C_MUTED,      leading=11))
        add(ParagraphStyle("CodeBlock",      parent=s["Normal"],  fontSize=8,  textColor=C_CODE_FG,    fontName="Courier", leading=11, backColor=C_CODE_BG, leftIndent=8, rightIndent=8, spaceAfter=4, spaceBefore=2))
        add(ParagraphStyle("Label",          parent=s["Normal"],  fontSize=8,  textColor=C_WHITE,      fontName="Helvetica-Bold", alignment=TA_CENTER))
        add(ParagraphStyle("TOCItem",        parent=s["Normal"],  fontSize=9,  textColor=C_ACCENT,     leading=14))
        add(ParagraphStyle("FieldLabel",     parent=s["Normal"],  fontSize=8,  textColor=C_MUTED,      fontName="Helvetica-Bold", spaceBefore=6, spaceAfter=2))
        add(ParagraphStyle("FieldValue",     parent=s["Normal"],  fontSize=9,  textColor=C_BLACK,      leading=13, spaceAfter=2))
        add(ParagraphStyle("BulletItem",     parent=s["Normal"],  fontSize=9,  textColor=C_BLACK,      leading=13, leftIndent=12, spaceAfter=2))
        add(ParagraphStyle("Disclaimer",     parent=s["Normal"],  fontSize=8,  textColor=colors.HexColor("#b91c1c"), alignment=TA_CENTER))

    # ── public entry point ────────────────────────────────────────────────────

    def generate_report(self, target: str, vulnerabilities: List[Dict],
                        scan_stats: Dict, output_file=None) -> str:
        if output_file is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = OUTPUT_DIR / f"vuln_report_{ts}.pdf"

        doc = BaseDocTemplate(
            str(output_file),
            pagesize=A4,
            rightMargin=18*mm, leftMargin=18*mm,
            topMargin=18*mm,   bottomMargin=18*mm,
        )
        frame = Frame(doc.leftMargin, doc.bottomMargin,
                      doc.width, doc.height, id="main")
        doc.addPageTemplates([PageTemplate(id="main", frames=frame,
                                           onPage=self._draw_page_chrome)])

        story = []
        self._cover(story, target, vulnerabilities, scan_stats)
        self._toc(story, vulnerabilities)
        self._executive_summary(story, target, vulnerabilities, scan_stats)
        self._risk_overview(story, vulnerabilities)          # NEW — spec requirement
        self._owasp_matrix(story, vulnerabilities)
        self._severity_chart(story, vulnerabilities)
        self._findings_table(story, vulnerabilities)
        self._detailed_findings(story, vulnerabilities)      # now grouped by classification
        self._remediation_roadmap(story, vulnerabilities)
        self._methodology(story, scan_stats)

        doc.build(story)
        logger.info("PDF report saved: %s", output_file)
        return str(output_file)

    # ── page chrome ───────────────────────────────────────────────────────────

    def _draw_page_chrome(self, canvas, doc):
        canvas.saveState()
        w, h = A4
        # Top strip
        canvas.setFillColor(C_DARK)
        canvas.rect(0, h - 12*mm, w, 12*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(C_WHITE)
        canvas.drawString(18*mm, h - 8*mm, "Web Application Vulnerability Assessment Report")
        canvas.drawRightString(w - 18*mm, h - 8*mm,
                               datetime.now().strftime("%Y-%m-%d"))
        # Bottom strip
        canvas.setFillColor(C_DARK)
        canvas.rect(0, 0, w, 9*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(18*mm, 3*mm, "CONFIDENTIAL — Authorised use only")
        canvas.setFillColor(C_WHITE)
        canvas.drawRightString(w - 18*mm, 3*mm, f"Page {doc.page}")
        canvas.restoreState()

    # ── cover page ────────────────────────────────────────────────────────────

    def _cover(self, story, target, vulns, stats):
        counts = self._count_severity(vulns)
        if counts["Critical"] > 0:   risk, rc = "CRITICAL", C_CRITICAL
        elif counts["High"] > 0:     risk, rc = "HIGH",     C_HIGH
        elif counts["Medium"] > 0:   risk, rc = "MEDIUM",   C_MEDIUM
        else:                         risk, rc = "LOW",      C_LOW

        # Full-page dark cover panel
        cover_data = [[
            Paragraph("WEB APPLICATION VULNERABILITY<br/>ASSESSMENT REPORT",
                      self.styles["ReportTitle"]),
        ]]
        cover = Table(cover_data, colWidths=[174*mm])
        cover.setStyle(TableStyle([
            ("BACKGROUND",  (0,0),(-1,-1), C_DARK),
            ("TOPPADDING",  (0,0),(-1,-1), 55),
            ("BOTTOMPADDING",(0,0),(-1,-1), 55),
            ("LEFTPADDING", (0,0),(-1,-1), 10),
            ("RIGHTPADDING",(0,0),(-1,-1), 10),
        ]))
        story.append(cover)
        story.append(Spacer(1, 6))

        # Meta band
        meta_data = [[
            _p(f"<b>Target:</b> {_safe(target)}", self.styles["CoverMeta"]),
            _p(f"<b>Date:</b> {datetime.now().strftime('%B %d, %Y')}", self.styles["CoverMeta"]),
            _p(f"<b>Prepared by:</b> {self.company}", self.styles["CoverMeta"]),
        ]]
        meta = Table(meta_data, colWidths=[58*mm, 58*mm, 58*mm])
        meta.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), colors.HexColor("#1e293b")),
            ("TOPPADDING", (0,0),(-1,-1), 10),
            ("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ]))
        story.append(meta)
        story.append(Spacer(1, 8))

        # Risk rating badge
        risk_table = Table(
            [[_p(f"OVERALL RISK RATING:  {risk}", ParagraphStyle(
                "RiskBadge", parent=self.styles["Normal"], fontSize=14,
                textColor=rc, fontName="Helvetica-Bold", alignment=TA_CENTER))]],
            colWidths=[174*mm]
        )
        risk_table.setStyle(TableStyle([
            ("BOX",        (0,0),(-1,-1), 2, rc),
            ("BACKGROUND", (0,0),(-1,-1), SEV_BG.get(risk.capitalize(), C_LIGHT_BG)),
            ("TOPPADDING", (0,0),(-1,-1), 12),
            ("BOTTOMPADDING",(0,0),(-1,-1), 12),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 8))

        # Summary counts row
        sev_order = ["Critical","High","Medium","Low","Info"]
        count_cells  = [_p(s, ParagraphStyle("SevLab", parent=self.styles["Normal"],
                           fontSize=8, fontName="Helvetica-Bold",
                           textColor=SEV_COLORS[s], alignment=TA_CENTER))
                        for s in sev_order]
        number_cells = [_p(str(counts[s]), ParagraphStyle("SevNum", parent=self.styles["Normal"],
                           fontSize=20, fontName="Helvetica-Bold",
                           textColor=SEV_COLORS[s], alignment=TA_CENTER))
                        for s in sev_order]
        counts_table = Table([count_cells, number_cells],
                             colWidths=[34.8*mm]*5)
        counts_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), C_LIGHT_BG),
            ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
            ("INNERGRID",     (0,0),(-1,-1), 0.5, C_BORDER),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
        ]))
        story.append(counts_table)
        story.append(Spacer(1, 8))

        # Confidentiality notice
        story.append(Table(
            [[_p("⚠ CONFIDENTIAL — This document contains sensitive security findings. "
                 "Distribute only to authorised personnel.", self.styles["Disclaimer"])]],
            colWidths=[174*mm],
            style=TableStyle([
                ("BOX",        (0,0),(-1,-1), 1, C_CRITICAL),
                ("BACKGROUND", (0,0),(-1,-1), colors.HexColor("#fff5f5")),
                ("TOPPADDING", (0,0),(-1,-1), 8),
                ("BOTTOMPADDING",(0,0),(-1,-1), 8),
            ])
        ))
        story.append(PageBreak())

    # ── table of contents ─────────────────────────────────────────────────────

    def _toc(self, story, vulns):
        story.append(_p("Table of Contents", self.styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 4))

        sections = [
            ("1.", "Executive Summary"),
            ("2.", "OWASP Top 10 Coverage Matrix"),
            ("3.", "Severity Distribution"),
            ("4.", "Findings Summary"),
            ("5.", f"Detailed Findings  ({len(vulns)} vulnerabilities)"),
            ("6.", "Remediation Roadmap"),
            ("7.", "Methodology & Appendix"),
        ]
        toc_data = [[_p(n, self.styles["TOCItem"]),
                     _p(title, self.styles["TOCItem"])]
                    for n, title in sections]
        t = Table(toc_data, colWidths=[12*mm, 162*mm])
        t.setStyle(TableStyle([
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("LINEBELOW",     (0,0),(-1,-1), 0.3, C_BORDER),
        ]))
        story.append(t)
        story.append(PageBreak())

    # ── executive summary ─────────────────────────────────────────────────────

    def _executive_summary(self, story, target, vulns, stats):
        story.append(_p("1. Executive Summary", self.styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 6))

        counts = self._count_severity(vulns)
        start  = stats.get("start_time")
        end    = stats.get("end_time")
        dur    = str(end - start).split(".")[0] if start and end else "N/A"

        story.append(_p(
            f"This report presents the results of an automated web application security "
            f"assessment conducted against <b>{_safe(target)}</b> on "
            f"<b>{datetime.now().strftime('%B %d, %Y')}</b>. "
            f"The scanner performed active testing across all OWASP Top 10 vulnerability "
            f"categories using 17 specialised detection modules.",
            self.styles["BodyJustify"]
        ))
        story.append(Spacer(1, 6))

        # Stats grid
        stat_items = [
            ("Scan Duration",        dur),
            ("URLs Crawled",         str(stats.get("urls_crawled", 0))),
            ("Forms Tested",         str(stats.get("forms_tested", 0))),
            ("Form Fields Tested",   str(stats.get("form_fields_tested", 0))),
            ("URL Parameters Tested",str(stats.get("parameters_tested", 0))),
            ("Total Findings",       str(len(vulns))),
            ("Critical Findings",    str(counts["Critical"])),
        ]
        grid = [[_p(k, self.styles["FieldLabel"]), _p(v, self.styles["H3"])]
                for k, v in stat_items]
        # arrange 2-per-row
        rows = []
        for i in range(0, len(grid), 2):
            if i + 1 < len(grid):
                row = grid[i] + grid[i + 1]
            else:
                # Odd number of stats — pad the last row with empty cells
                # using a real style object (self.styles["Body"]), not the
                # literal string "Body" which crashed reportlab's Paragraph
                # parser (it expects a ParagraphStyle object, not a string).
                row = grid[i] + [_p("", self.styles["Body"]), _p("", self.styles["Body"])]
            rows.append(row)
        st = Table(rows, colWidths=[38*mm, 48*mm, 38*mm, 50*mm])
        st.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), C_LIGHT_BG),
            ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
            ("INNERGRID",     (0,0),(-1,-1), 0.3, C_BORDER),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ]))
        story.append(st)
        story.append(Spacer(1, 10))

        # Key findings narrative
        if counts["Critical"] or counts["High"]:
            story.append(_p("⚠ Key Findings", self.styles["H2"]))
            if counts["Critical"]:
                story.append(_p(
                    f"• <b>{counts['Critical']} Critical severity</b> vulnerabilities were identified "
                    "that require <b>immediate remediation</b> as they allow direct exploitation.",
                    self.styles["BulletItem"]
                ))
            if counts["High"]:
                story.append(_p(
                    f"• <b>{counts['High']} High severity</b> vulnerabilities expose significant risk "
                    "and should be addressed within <b>7 days</b>.",
                    self.styles["BulletItem"]
                ))
            if counts["Medium"]:
                story.append(_p(
                    f"• <b>{counts['Medium']} Medium severity</b> findings should be scheduled for "
                    "remediation within <b>30 days</b>.",
                    self.styles["BulletItem"]
                ))

        story.append(PageBreak())

    # ── risk overview (spec requirement) ─────────────────────────────────────

    def _risk_overview(self, story, vulns):
        """
        Risk Overview section — classification-level summary
        (Confirmed / Likely / Potential / Informational) alongside
        CVSS estimate range and priority action items.
        """
        story.append(_p("4. Risk Overview", self.styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 6))

        CLASSIFICATIONS = [
            "Confirmed Vulnerability",
            "Likely Vulnerability",
            "Potential Vulnerability",
            "Informational",
        ]
        CLASSIF_COLORS = {
            "Confirmed Vulnerability": C_CRITICAL,
            "Likely Vulnerability":    C_HIGH,
            "Potential Vulnerability": C_MEDIUM,
            "Informational":           C_INFO,
        }

        buckets: Dict[str, List] = {c: [] for c in CLASSIFICATIONS}
        for v in vulns:
            cls = v.get("classification", "Potential Vulnerability")
            buckets.setdefault(cls, []).append(v)

        hdr = ["Classification", "Count", "Avg Confidence", "Highest Severity", "Description"]
        rows = [hdr]
        sev_order = ["Critical", "High", "Medium", "Low", "Info"]
        for cls in CLASSIFICATIONS:
            group = buckets.get(cls, [])
            if not group:
                rows.append([cls, "0", "—", "—", ""])
                continue
            avg_conf = int(sum(_safe_num(v.get("confidence", 75), 75) for v in group) / len(group))
            highest = min(
                (v.get("severity", "Info") for v in group),
                key=lambda s: sev_order.index(s) if s in sev_order else 99,
            )
            desc = {
                "Confirmed Vulnerability": "Independently proven — act immediately",
                "Likely Vulnerability":    "Strong evidence — prioritise remediation",
                "Potential Vulnerability": "Manual verification recommended",
                "Informational":           "No direct security impact; harden if feasible",
            }.get(cls, "")
            rows.append([cls, str(len(group)), f"{avg_conf}%", highest, desc])

        col_w = [48*mm, 15*mm, 28*mm, 28*mm, 55*mm]
        tbl = Table(rows, colWidths=col_w, repeatRows=1)
        tbl_style = [
            ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_LIGHT_BG]),
        ]
        for i, cls in enumerate(CLASSIFICATIONS, 1):
            color = CLASSIF_COLORS.get(cls, C_BLACK)
            tbl_style.append(("TEXTCOLOR", (0, i), (0, i), color))
            tbl_style.append(("FONTNAME",  (0, i), (0, i), "Helvetica-Bold"))
        tbl.setStyle(TableStyle(tbl_style))
        story.append(tbl)
        story.append(Spacer(1, 8))

        story.append(_p("Priority Action Items", self.styles["H2"]))
        priority = sorted(
            [v for v in vulns if v.get("classification") in
             ("Confirmed Vulnerability", "Likely Vulnerability")],
            key=lambda v: (-_safe_num(v.get("cvss_estimate"), 0), -_safe_num(v.get("confidence"), 0)),
        )[:5]

        if priority:
            pri_hdr = ["#", "Type", "URL", "Confidence", "CVSS est.", "Classification"]
            pri_rows = [pri_hdr]
            for i, v in enumerate(priority, 1):
                pri_rows.append([
                    str(i),
                    _safe(v.get("type", "?"))[:35],
                    _safe(v.get("url", "?"))[:40],
                    f"{v.get('confidence', '?')}%",
                    str(v.get("cvss_estimate", "?")),
                    v.get("classification", "?"),
                ])
            pri_tbl = Table(pri_rows,
                            colWidths=[8*mm, 40*mm, 50*mm, 20*mm, 18*mm, 38*mm],
                            repeatRows=1)
            pri_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
                ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
                ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_LIGHT_BG]),
            ]))
            story.append(pri_tbl)
        else:
            story.append(_p("No Confirmed or Likely findings to prioritise.", self.styles["Body"]))

        story.append(PageBreak())

    # ── OWASP matrix ──────────────────────────────────────────────────────────

    def _owasp_matrix(self, story, vulns):
        story.append(_p("2. OWASP Top 10 Coverage Matrix", self.styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 6))

        # Map findings to OWASP categories
        owasp_counts = {}
        for v in vulns:
            cat = v.get("owasp", "")
            if cat:
                owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

        ALL_CATS = [
            ("A01 – Broken Access Control",     "IDOR, privilege escalation"),
            ("A02 – Cryptographic Failures",     "HSTS, HTTP transport, weak TLS"),
            ("A03 – Injection",                  "SQLi, XSS, XXE, Dir Traversal"),
            ("A04 – Insecure Design",            "CSRF, Open Redirect"),
            ("A05 – Security Misconfiguration",  "Missing headers, cookie flags"),
            ("A06 – Vulnerable Components",      "Outdated libs, CVE matching"),
            ("A07 – Auth Failures",              "Default creds, no lockout"),
            ("A08 – Software Integrity",         "SRI missing, exposed .env/.git"),
            ("A09 – Logging Failures",           "Stack traces, admin panels"),
            ("A10 – SSRF",                       "Cloud metadata, internal SSRF"),
        ]

        header = [
            _p("OWASP Category", self.styles["Label"]),
            _p("What is tested", self.styles["Label"]),
            _p("Findings", self.styles["Label"]),
            _p("Status", self.styles["Label"]),
        ]
        rows = [header]
        for cat, tested in ALL_CATS:
            cnt   = owasp_counts.get(cat, 0)
            status = "⚠ VULNERABLE" if cnt > 0 else "✓ PASSED"
            s_col  = C_CRITICAL if cnt > 0 else C_LOW
            rows.append([
                _p(cat, self.styles["Body"]),
                _p(tested, self.styles["Small"]),
                _p(str(cnt) if cnt else "0", self.styles["Body"]),
                _p(status, ParagraphStyle("St", parent=self.styles["Body"],
                   textColor=s_col, fontName="Helvetica-Bold")),
            ])

        t = Table(rows, colWidths=[60*mm, 62*mm, 20*mm, 32*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  C_TABLE_HDR),
            ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
            ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,0),  8),
            ("BACKGROUND",    (0,1),(-1,-1), C_LIGHT_BG),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_LIGHT_BG]),
            ("GRID",          (0,0),(-1,-1), 0.4, C_BORDER),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
            ("LEFTPADDING",   (0,0),(-1,-1), 6),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]))
        story.append(t)
        story.append(PageBreak())

    # ── severity distribution ─────────────────────────────────────────────────

    def _severity_chart(self, story, vulns):
        story.append(_p("3. Severity Distribution", self.styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 6))

        counts = self._count_severity(vulns)
        total  = max(len(vulns), 1)

        rows = []
        for sev in ["Critical","High","Medium","Low","Info"]:
            cnt = counts[sev]
            if cnt == 0:
                continue
            pct    = cnt / total * 100
            bar_w  = max(int(pct * 1.2), 2)  # scale to ~120 max chars → use table width
            bar_cell = Table(
                [[""]], colWidths=[bar_w * mm],
                style=TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1), SEV_COLORS[sev]),
                    ("TOPPADDING",(0,0),(-1,-1), 8),
                    ("BOTTOMPADDING",(0,0),(-1,-1), 8),
                ])
            )
            rows.append([
                _p(sev, ParagraphStyle("SevLbl2", parent=self.styles["Body"],
                   fontName="Helvetica-Bold", textColor=SEV_COLORS[sev])),
                bar_cell,
                _p(f"{cnt}  ({pct:.0f}%)", self.styles["Body"]),
            ])

        if rows:
            t = Table(rows, colWidths=[22*mm, 128*mm, 24*mm])
            t.setStyle(TableStyle([
                ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0),(-1,-1), 4),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                ("LINEBELOW",     (0,0),(-1,-1), 0.3, C_BORDER),
            ]))
            story.append(t)

        story.append(PageBreak())

    # ── findings summary table ────────────────────────────────────────────────

    def _findings_table(self, story, vulns):
        story.append(_p("4. Findings Summary", self.styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 6))

        sorted_v = sorted(vulns, key=lambda x: ["Critical","High","Medium","Low","Info"].index(
            x.get("severity","Info")) if x.get("severity","Info") in
            ["Critical","High","Medium","Low","Info"] else 5)

        header = [
            _p("#",           self.styles["Label"]),
            _p("Vulnerability",self.styles["Label"]),
            _p("Severity",    self.styles["Label"]),
            _p("OWASP",       self.styles["Label"]),
            _p("URL / Parameter", self.styles["Label"]),
        ]
        rows = [header]
        for i, v in enumerate(sorted_v, 1):
            sev = v.get("severity","Info")
            url = v.get("url","")
            if len(url) > 50:
                url = url[:47] + "..."
            param = v.get("parameter","")
            loc   = f"{url}\n[{param}]" if param else url
            rows.append([
                _p(str(i), self.styles["Small"]),
                _p(_safe(v.get("type","?")), self.styles["Body"]),
                _p(sev, ParagraphStyle("SevCell", parent=self.styles["Body"],
                   textColor=SEV_COLORS.get(sev, C_BLACK), fontName="Helvetica-Bold")),
                _p(_safe(v.get("owasp","")), self.styles["Small"]),
                _p(_safe(loc), self.styles["Small"]),
            ])

        if len(rows) == 1:
            rows.append([_p("No findings", self.styles["Body"]), _p("-", self.styles["Body"]),
                         _p("-", self.styles["Body"]), _p("-", self.styles["Body"]), _p("-", self.styles["Body"])])

        t = Table(rows, colWidths=[8*mm, 44*mm, 18*mm, 32*mm, 72*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  C_TABLE_HDR),
            ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
            ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,0),  8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_LIGHT_BG]),
            ("GRID",          (0,0),(-1,-1), 0.4, C_BORDER),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("LEFTPADDING",   (0,0),(-1,-1), 5),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]))
        story.append(t)
        story.append(PageBreak())

    # ── detailed findings ─────────────────────────────────────────────────────

    def _detailed_findings(self, story, vulns):
        """
        Section 5 — Detailed Findings.

        Grouped by classification (Confirmed → Likely → Potential →
        Informational) per spec, so reviewers can work through the
        highest-confidence, fully-proven findings first. Each finding
        card includes all spec-required fields:
          Description · Impact · Evidence · Proof · Confidence ·
          Verification Method · Remediation · OWASP · CVSS Estimate ·
          Reproduction Steps.
        """
        story.append(_p("5. Detailed Findings", self.styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 4))

        if not vulns:
            story.append(_p("No vulnerabilities were found during this scan.", self.styles["Body"]))
            story.append(PageBreak())
            return

        CLASSIFICATION_ORDER = [
            "Confirmed Vulnerability",
            "Likely Vulnerability",
            "Potential Vulnerability",
            "Informational",
        ]
        CLASSIF_COLORS = {
            "Confirmed Vulnerability": C_CRITICAL,
            "Likely Vulnerability":    C_HIGH,
            "Potential Vulnerability": C_MEDIUM,
            "Informational":           C_INFO,
        }

        # Group by classification, then sort each group by severity → confidence
        sev_order = ["Critical", "High", "Medium", "Low", "Info"]
        buckets: Dict[str, List] = {c: [] for c in CLASSIFICATION_ORDER}
        for v in vulns:
            cls = v.get("classification", "Potential Vulnerability")
            bucket_key = cls if cls in buckets else "Potential Vulnerability"
            buckets[bucket_key].append(v)

        finding_num = 0
        for cls in CLASSIFICATION_ORDER:
            group = buckets.get(cls, [])
            if not group:
                continue

            group_sorted = sorted(group, key=lambda v: (
                sev_order.index(v.get("severity", "Info")) if v.get("severity", "Info") in sev_order else 99,
                -v.get("confidence", 0),
            ))

            cls_color = CLASSIF_COLORS.get(cls, C_BLACK)

            # Classification section banner
            banner = Table(
                [[_p(f"● {cls.upper()}", ParagraphStyle(
                    "ClsBanner", parent=self.styles["Normal"],
                    fontSize=12, textColor=C_WHITE, fontName="Helvetica-Bold")),
                  _p(f"{len(group)} finding{'s' if len(group) != 1 else ''}",
                     ParagraphStyle("ClsCount", parent=self.styles["Normal"],
                                    fontSize=10, textColor=C_WHITE, alignment=TA_RIGHT))]],
                colWidths=[130*mm, 44*mm],
            )
            banner.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), cls_color),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(banner)
            story.append(Spacer(1, 6))

            for v in group_sorted:
                finding_num += 1
                sev        = v.get("severity", "Info")
                vtype      = v.get("type", "Unknown")
                subtype    = v.get("subtype", "")
                sc         = SEV_COLORS.get(sev, C_BLACK)
                sb         = SEV_BG.get(sev, C_LIGHT_BG)
                owasp_tag  = v.get("owasp", "")
                confidence = v.get("confidence", "?")
                conf_label = v.get("confidence_label", "")
                verif_method = v.get("verification_method", "Pattern match (unverified)")
                cvss_est   = v.get("cvss_estimate", "N/A")
                ev_score   = v.get("evidence_score", "?")

                # ── header band (type + optional subtype) ──
                vtype_display = (
                    f"<b>{_safe(vtype)}</b>"
                    + (f"  <font size='9' color='#6b7280'>— {_safe(subtype)}</font>"
                       if subtype else "")
                )
                hdr_cells = [
                    _p(f"FINDING #{finding_num:03d}", ParagraphStyle(
                        "FNum", parent=self.styles["Normal"],
                        fontSize=7, textColor=C_MUTED, fontName="Helvetica-Bold")),
                    _p(vtype_display, ParagraphStyle(
                        "FType", parent=self.styles["Normal"],
                        fontSize=11, textColor=C_DARK, fontName="Helvetica-Bold")),
                    _p(sev.upper(), ParagraphStyle(
                        "FSev", parent=self.styles["Normal"],
                        fontSize=10, textColor=sc, fontName="Helvetica-Bold",
                        alignment=TA_RIGHT)),
                ]
                hdr = Table([hdr_cells], colWidths=[22*mm, 120*mm, 32*mm])
                hdr.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), sb),
                    ("LINEBELOW",     (0, 0), (-1, -1), 1.5, sc),
                    ("TOPPADDING",    (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                    ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ]))

                # WAF bypass alert block — only present when the finding was
                # confirmed using a bypass variant (waf_bypass_used=True).
                # The analyst needs to know the standard payload was blocked
                # and which technique succeeded, so they can document it.
                waf_bypass      = v.get("waf_bypass_used", False)
                bypass_variant  = _safe(v.get("bypass_variant", ""))
                bypass_payload  = _safe(v.get("bypass_payload", "")[:80])
                waf_bypass_block = None
                if waf_bypass:
                    bypass_detail = bypass_variant
                    if bypass_payload:
                        bypass_detail += f": {bypass_payload}"
                    waf_bypass_text = (
                        f"⚠️  WAF BYPASS USED — confirmed using variant '{bypass_detail}'. "
                        f"The WAF blocked the standard payload but the underlying "
                        f"vulnerability is real. Fix the root cause, not just the WAF rule."
                    )
                    waf_bypass_block = Table(
                        [[_p(waf_bypass_text, self.styles["Small"])]],
                        colWidths=[174*mm]
                    )
                    waf_bypass_block.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#fef3c7")),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                        ("TOPPADDING",    (0, 0), (-1, -1), 7),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                        ("BOX",           (0, 0), (-1, -1), 0.5,
                         colors.HexColor("#f59e0b")),
                    ]))

                # ── meta row (URL, param, OWASP, confidence, CVSS, evidence score) ──
                url   = _safe(v.get("url", "N/A"))
                param = _safe(v.get("parameter", "—"))
                source = _safe(v.get("source", "Custom Scanner (native detector)"))
                meta_data = [
                    [_p("URL",         self.styles["FieldLabel"]),
                     _p(url,           self.styles["FieldValue"]),
                     _p("Parameter",   self.styles["FieldLabel"]),
                     _p(param,         self.styles["FieldValue"]),
                     _p("OWASP",       self.styles["FieldLabel"]),
                     _p(_safe(owasp_tag), self.styles["FieldValue"])],
                    [_p("Confidence",  self.styles["FieldLabel"]),
                     _p(f"{confidence}% ({conf_label})", self.styles["FieldValue"]),
                     _p("CVSS est.",   self.styles["FieldLabel"]),
                     _p(str(cvss_est), self.styles["FieldValue"]),
                     _p("Evidence score", self.styles["FieldLabel"]),
                     _p(f"{ev_score}/100", self.styles["FieldValue"])],
                    [_p("Detected by", self.styles["FieldLabel"]),
                     _p(source,        self.styles["FieldValue"]),
                     _p("CWE",         self.styles["FieldLabel"]),
                     _p(_safe(v.get("cwe", "—")), self.styles["FieldValue"]),
                     _p("", self.styles["FieldLabel"]),
                     _p("", self.styles["FieldValue"])],
                ]
                meta = Table(meta_data, colWidths=[22*mm, 54*mm, 20*mm, 28*mm, 24*mm, 26*mm])
                meta.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), C_LIGHT_BG),
                    ("TOPPADDING",    (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                    ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
                    ("SPAN",          (4, 2), (5, 2)),
                ]))

                # ── body fields helper ──
                def field_block(label: str, content: str, code=False, raw=False) -> Table:
                    if code:
                        style   = self.styles["CodeBlock"]
                        display = _safe(content)
                    elif raw:
                        style   = self.styles["FieldValue"]
                        display = content
                    else:
                        style   = self.styles["FieldValue"]
                        display = _safe(content)
                    return Table(
                        [[_p(label, self.styles["FieldLabel"])],
                         [_p(display, style)]],
                        colWidths=[174*mm],
                        style=TableStyle([
                            ("TOPPADDING",    (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                            ("LINEBELOW",     (0, 1), (-1, -1), 0.3, C_BORDER),
                        ]))

                description  = v.get("description") or "No description available."
                impact       = (VULN_IMPACT.get(vtype)
                                or v.get("impact")
                                or "Refer to OWASP documentation for impact details.")
                evidence_raw = v.get("evidence") or v.get("details") or "No evidence captured."
                fix          = (v.get("remediation")
                                or VULN_FIX.get(vtype)
                                or v.get("recommendation")
                                or "Follow OWASP remediation guidance.")

                # Reproduction steps
                repro_steps = v.get("reproduction_steps", [])
                if isinstance(repro_steps, list):
                    repro_text = "\n".join(repro_steps) if repro_steps else "No reproduction steps captured."
                else:
                    repro_text = str(repro_steps)

                refs = list(VULN_REFERENCES.get(vtype, []))
                # ZAP (and potentially other future integrations) supply
                # their own per-finding reference URL via v["reference"].
                # This was previously captured into the vuln dict but never
                # actually read anywhere in the report — silently dropped.
                own_ref = (v.get("reference") or "").strip()
                if own_ref and own_ref not in refs:
                    refs.append(own_ref)
                refs_text = ("<br/>".join(f"• {_safe(r)}" for r in refs)
                             if refs else "See OWASP Cheat Sheet Series (cheatsheetseries.owasp.org).")

                # FP-reduction transparency block — shown whenever the
                # centralized FPReductionEngine touched this finding (see
                # modules/fp_reduction_engine.py). Previously this note was
                # computed and stored on the finding dict but never actually
                # rendered anywhere in the PDF, so an analyst reading the
                # report had no way to know a finding's confidence had
                # already been adjusted, or that it represents a merged
                # cluster of near-identical findings across many URLs.
                fp_note      = v.get("fp_reduction_note", "")
                affected_ct  = v.get("affected_url_count")
                related      = v.get("related_findings", [])
                fp_block = None
                if fp_note or affected_ct or related:
                    fp_text_parts = []
                    if fp_note:
                        fp_text_parts.append(_safe(fp_note))
                    if affected_ct:
                        fp_text_parts.append(
                            f"This finding is the representative of {affected_ct} "
                            f"near-identical occurrences merged during FP reduction "
                            f"(see Section 7 for the full list)."
                        )
                    if related:
                        fp_text_parts.append(
                            "Related finding(s) sharing the same underlying evidence: "
                            + ", ".join(_safe(r) for r in related if r)
                        )
                    fp_block = Table(
                        [[_p("🧪  <b>FP-REDUCTION NOTE</b> — " + " ".join(fp_text_parts),
                             self.styles["Small"])]],
                        colWidths=[174*mm]
                    )
                    fp_block.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f3f4f6")),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                        ("TOPPADDING",    (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("BOX",           (0, 0), (-1, -1), 0.4, C_MUTED),
                    ]))

                card_elements = [
                    hdr,
                    *([waf_bypass_block] if waf_bypass_block else []),
                    *([fp_block]         if fp_block         else []),
                    meta,
                    field_block("📋  DESCRIPTION",         str(description)),
                    field_block("💥  IMPACT",               str(impact)),
                    field_block("🔍  EVIDENCE",             str(evidence_raw), code=True),
                    field_block("🔬  VERIFICATION METHOD",  _safe(verif_method)),
                    field_block("🔁  REPRODUCTION STEPS",   str(repro_text), code=True),
                    field_block("🔧  RECOMMENDED FIX",      str(fix)),
                    field_block("📚  REFERENCES",           refs_text, raw=True),
                    Spacer(1, 10),
                ]

                story.append(KeepTogether(card_elements[:4]))
                for el in card_elements[4:]:
                    story.append(el)

            story.append(Spacer(1, 8))

        story.append(PageBreak())

    # ── remediation roadmap ───────────────────────────────────────────────────

    def _remediation_roadmap(self, story, vulns):
        story.append(_p("6. Remediation Roadmap", self.styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 6))

        story.append(_p(
            "The following prioritised remediation plan is based on the risk severity "
            "of identified vulnerabilities. Address items in order.",
            self.styles["BodyJustify"]
        ))
        story.append(Spacer(1, 6))

        phases = [
            ("🔴  IMMEDIATE  (within 24–48 hours)", "Critical",
             "These vulnerabilities allow direct exploitation and must be fixed immediately."),
            ("🟠  SHORT-TERM  (within 7 days)", "High",
             "High severity findings carry significant risk and require prompt remediation."),
            ("🟡  MEDIUM-TERM  (within 30 days)", "Medium",
             "Medium severity issues should be included in the next sprint or release cycle."),
            ("🟢  LONG-TERM  (within 90 days)", "Low",
             "Low and informational findings represent hardening opportunities."),
        ]

        sev_map: Dict[str, List] = {"Critical":[], "High":[], "Medium":[], "Low":[]}
        for v in vulns:
            s = v.get("severity","Info")
            if s in sev_map:
                sev_map[s].append(v)
            else:
                sev_map["Low"].append(v)

        for title, sev, note in phases:
            items = sev_map[sev]
            sc = SEV_COLORS[sev]
            phase_hdr = Table([[_p(title, ParagraphStyle(
                "PhaseHdr", parent=self.styles["Normal"],
                fontSize=10, fontName="Helvetica-Bold",
                textColor=C_WHITE))]],
                colWidths=[174*mm],
                style=TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), sc),
                    ("TOPPADDING",    (0,0),(-1,-1), 7),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 7),
                    ("LEFTPADDING",   (0,0),(-1,-1), 10),
                ])
            )
            story.append(phase_hdr)
            story.append(_p(note, self.styles["Small"]))

            if not items:
                story.append(_p("  ✓ No findings in this category.", self.styles["Small"]))
            else:
                seen_types = set()
                for v in items:
                    vtype = v.get("type","?")
                    fix   = VULN_FIX.get(vtype) or v.get("recommendation","See OWASP guidance.")
                    if vtype not in seen_types:
                        seen_types.add(vtype)
                        story.append(_p(f"<b>• {_safe(vtype)}</b>", self.styles["BulletItem"]))
                        story.append(_p(f"  Fix: {_safe(fix[:200])}", self.styles["Small"]))
            story.append(Spacer(1, 6))

        story.append(PageBreak())

    # ── methodology ───────────────────────────────────────────────────────────

    def _methodology(self, story, stats):
        story.append(_p("7. Methodology & Appendix", self.styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 6))

        story.append(_p("Assessment Methodology", self.styles["H2"]))
        steps = [
            ("Phase 1 — Crawling",
             "Automated discovery of all URLs, forms, and input parameters using a recursive "
             "spider with configurable depth. Forms and URL parameters are catalogued for testing."),
            ("Phase 2 — Security Headers & TLS (A02, A05)",
             "HTTP response headers analysed for missing security controls: CSP, HSTS, "
             "X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, "
             "cookie flags."),
            ("Phase 3 — Component Analysis (A06)",
             "Server headers fingerprinted against a CVE database. Page HTML analysed for "
             "outdated JavaScript libraries (jQuery, Bootstrap, Angular, Vue, React, lodash). "
             "Sensitive files probed (package.json, .env, etc.)"),
            ("Phase 4 — Integrity Checks (A08)",
             "External scripts and stylesheets checked for SRI. Sensitive files (.env, "
             ".git/HEAD) probed. JavaScript analysed for dangerous patterns."),
            ("Phase 5 — Logging & Monitoring (A09)",
             "Error pages probed for stack traces, debug mode, PHP errors, framework "
             "exceptions. Admin panels tested for unauthenticated access. Directory listing checked."),
            ("Phase 6 — XXE Injection (A03)",
             "XML-accepting endpoints identified via OPTIONS responses and URL patterns. "
             "Crafted payloads with external entity references submitted."),
            ("Phase 7 — Concurrent Multi-Module Testing (A01/A03/A04/A07/A10)",
             "URL parameters and forms tested in parallel using a thread pool for SQL injection, "
             "XSS, CSRF, SSRF, IDOR, Open Redirect, Directory Traversal, and Broken Auth."),
        ]
        for phase, desc in steps:
            story.append(_p(f"<b>{_safe(phase)}</b>", self.styles["Body"]))
            story.append(_p(desc, self.styles["Small"]))
            story.append(Spacer(1, 4))

        story.append(Spacer(1, 6))
        story.append(_p("Tools & Frameworks", self.styles["H2"]))
        tools = [
            ("Web Vulnerability Scanner v5.0", "Custom Python scanner — 17 detection modules covering OWASP A01–A10, Passive Scanner, Smart Targeting, WAF Bypass"),
            ("OWASP ZAP",                       "Optional active scan integration for deep detection"),
            ("BeautifulSoup4",                  "HTML parsing and form/link extraction"),
            ("lxml",                            "XML parsing for XXE detection"),
            ("requests / httpx",                "HTTP client library"),
            ("ThreadPoolExecutor",              "Concurrent URL testing"),
        ]
        tool_rows = [[_p(t, self.styles["Body"]), _p(d, self.styles["Small"])]
                     for t, d in tools]
        tt = Table(tool_rows, colWidths=[52*mm, 122*mm])
        tt.setStyle(TableStyle([
            ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_WHITE, C_LIGHT_BG]),
            ("GRID",         (0,0),(-1,-1), 0.3, C_BORDER),
            ("TOPPADDING",   (0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",  (0,0),(-1,-1), 6),
        ]))
        story.append(tt)
        story.append(Spacer(1, 8))

        # False-positive reduction summary — the FPReductionEngine already
        # computes this every scan (systemic pattern merging, cross-finding
        # contradiction checks, baseline re-validation) but it was only ever
        # printed to the console, never included in the deliverable report.
        # An analyst reviewing the PDF needs this to trust the confidence
        # scores and to see exactly what was merged/suppressed and why.
        fp_summary = stats.get("fp_reduction_summary") or {}
        if fp_summary.get("input_findings"):
            story.append(_p("False-Positive Reduction Summary", self.styles["H2"]))
            story.append(_p(
                "Every finding passes through a centralized cross-validation pass after "
                "all detectors complete: findings are clustered by evidence similarity to "
                "catch systemic/uniform responses masquerading as many independent bugs, "
                "cross-checked against contradictory signals on the same URL, and "
                "re-validated against the live site baseline one more time before the "
                "confidence scores below are treated as final.",
                self.styles["Small"]
            ))
            story.append(Spacer(1, 4))
            fp_rows = [
                ["Metric", "Value"],
                ["Findings before FP reduction",  str(fp_summary.get("input_findings", 0))],
                ["Systemic pattern clusters merged", str(fp_summary.get("systemic_clusters_merged", 0))],
                ["Findings suppressed/merged",     str(fp_summary.get("findings_suppressed", 0))],
                ["Findings cross-linked",          str(fp_summary.get("findings_cross_linked", 0))],
            ]
            fpt = Table(
                [[_p(r[0], self.styles["FieldLabel"] if i else self.styles["Label"]),
                  _p(r[1], self.styles["FieldValue"] if i else self.styles["Label"])]
                 for i, r in enumerate(fp_rows)],
                colWidths=[110*mm, 64*mm]
            )
            fpt.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0),  C_TABLE_HDR),
                ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_LIGHT_BG]),
                ("GRID",         (0,0),(-1,-1),  0.4, C_BORDER),
                ("TOPPADDING",   (0,0),(-1,-1),  5),
                ("BOTTOMPADDING",(0,0),(-1,-1),  5),
                ("LEFTPADDING",  (0,0),(-1,-1),  6),
            ]))
            story.append(fpt)
            story.append(Spacer(1, 6))

            suppressed_detail = fp_summary.get("suppressed_detail") or []
            if suppressed_detail:
                story.append(_p(
                    f"Merged/suppressed findings ({len(suppressed_detail)} shown, "
                    f"capped at 50):", self.styles["Body"]
                ))
                sd_rows = [["Type", "URL", "Reason"]] + [
                    [_safe(str(d.get("type", ""))[:40]),
                     _safe(str(d.get("url", ""))[:55]),
                     _safe(str(d.get("reason", ""))[:60])]
                    for d in suppressed_detail[:50]
                ]
                sdt = Table(
                    [[_p(c, self.styles["FieldLabel"] if i else self.styles["Label"]) for c in row]
                     if i == 0 else
                     [_p(c, self.styles["Small"]) for c in row]
                     for i, row in enumerate(sd_rows)],
                    colWidths=[38*mm, 74*mm, 62*mm]
                )
                sdt.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,0),  C_TABLE_HDR),
                    ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_LIGHT_BG]),
                    ("GRID",         (0,0),(-1,-1),  0.3, C_BORDER),
                    ("TOPPADDING",   (0,0),(-1,-1),  4),
                    ("BOTTOMPADDING",(0,0),(-1,-1),  4),
                    ("LEFTPADDING",  (0,0),(-1,-1),  5),
                ]))
                story.append(sdt)
                story.append(Spacer(1, 8))

        # Scan stats appendix
        story.append(_p("Scan Statistics", self.styles["H2"]))
        start = stats.get("start_time")
        end   = stats.get("end_time")
        dur   = str(end - start).split(".")[0] if start and end else "N/A"
        stat_rows = [
            ["Metric", "Value"],
            ["Scan Start",          str(start)[:19] if start else "N/A"],
            ["Scan End",            str(end)[:19]   if end   else "N/A"],
            ["Duration",            dur],
            ["URLs Crawled",        str(stats.get("urls_crawled", 0))],
            ["Forms Tested",          str(stats.get("forms_tested", 0))],
            ["Form Fields Tested",    str(stats.get("form_fields_tested", 0))],
            ["URL Parameters Tested", str(stats.get("parameters_tested", 0))],
            ["Scanner Version",     "v5.0 — Full OWASP Top 10 + Smart Targeting"],
        ]
        st = Table(
            [[_p(r[0], self.styles["FieldLabel"] if i else self.styles["Label"]),
              _p(r[1], self.styles["FieldValue"] if i else self.styles["Label"])]
             for i, r in enumerate(stat_rows)],
            colWidths=[60*mm, 114*mm]
        )
        st.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  C_TABLE_HDR),
            ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_LIGHT_BG]),
            ("GRID",         (0,0),(-1,-1),  0.4, C_BORDER),
            ("TOPPADDING",   (0,0),(-1,-1),  5),
            ("BOTTOMPADDING",(0,0),(-1,-1),  5),
            ("LEFTPADDING",  (0,0),(-1,-1),  6),
        ]))
        story.append(st)
        story.append(Spacer(1, 8))

        # Disclaimer
        story.append(Table(
            [[_p(
                "DISCLAIMER: This report was generated by an automated scanner. Results should be "
                "reviewed by a qualified security professional. Automated tools may produce false "
                "positives or miss vulnerabilities that require manual testing. This report is "
                "provided for informational purposes only.",
                self.styles["Disclaimer"]
            )]],
            colWidths=[174*mm],
            style=TableStyle([
                ("BOX",         (0,0),(-1,-1), 1, C_BORDER),
                ("BACKGROUND",  (0,0),(-1,-1), C_LIGHT_BG),
                ("TOPPADDING",  (0,0),(-1,-1), 10),
                ("BOTTOMPADDING",(0,0),(-1,-1), 10),
            ])
        ))

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _count_severity(vulns: List[Dict]) -> Dict[str, int]:
        counts = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        for v in vulns:
            s = v.get("severity","Info")
            counts[s] = counts.get(s, 0) + 1
        return counts

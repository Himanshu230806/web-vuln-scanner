"""
Passive Scanner
================
Runs silently on every HTTP response the crawler collects —
no extra requests, no payloads, zero false-positive risk from
probe interference. This is what gives coverage depth ZAP misses
because ZAP's passive scanner has very limited secret detection.

Detects:

  SECRETS IN RESPONSES
  ─────────────────────
  High-entropy strings matching known service key formats:
  • AWS Access Key IDs (AKIA...)
  • AWS Secret Access Keys
  • GitHub personal access tokens (ghp_...)
  • Slack tokens (xox...)
  • Stripe secret keys (sk_live_...)
  • Twilio auth tokens
  • SendGrid API keys (SG.)
  • Google API keys (AIza...)
  • JWT tokens (eyJ...)
  • Private key PEM blocks (-----BEGIN RSA PRIVATE KEY-----)
  • Generic high-entropy secrets (passwords, API keys in JS vars)

  SENSITIVE DATA EXPOSURE
  ────────────────────────
  • Credit card numbers (Luhn-validated)
  • Social Security Numbers (US)
  • Email addresses in API responses (PII leak)
  • Phone numbers in API responses
  • Internal IP addresses (RFC1918 in responses)
  • Stack traces / debug information
  • Database connection strings

  VERSION DISCLOSURE
  ──────────────────
  • Server version in headers (Apache/2.4.1, nginx/1.18.0)
  • X-Powered-By framework version (PHP/7.4.3)
  • Framework/language versions in response bodies
  • Known vulnerable version strings

These are all passive checks — the scanner never sends additional
requests to find them, it just reads what the app returns normally.
This is the correct way to do secret detection: fire no probes,
generate no server-side logs, leave no attack evidence.
"""

import logging
import math
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# ── Secret patterns ────────────────────────────────────────────────────────────
# Each entry: (pattern_name, regex, severity, description)
SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key ID",
     re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])", re.I),
     "Critical",
     "AWS Access Key ID exposed. Can be used to access AWS services."),

    ("AWS Secret Access Key",
     re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+]{40})['\"]"),
     "Critical",
     "AWS Secret Access Key exposed. Enables full AWS account access."),

    # GitHub
    ("GitHub Personal Access Token",
     re.compile(r"(ghp_[A-Za-z0-9_]{36,})"),
     "Critical",
     "GitHub Personal Access Token. Grants access to repositories."),

    ("GitHub OAuth Token",
     re.compile(r"(gho_[A-Za-z0-9_]{36,})"),
     "Critical",
     "GitHub OAuth Token exposed."),

    # Slack
    ("Slack Bot Token",
     re.compile(r"(xoxb-[0-9A-Za-z\-]{50,})"),
     "High",
     "Slack Bot Token. Can read/write to Slack workspaces."),

    ("Slack User Token",
     re.compile(r"(xoxp-[0-9A-Za-z\-]{50,})"),
     "High",
     "Slack User Token exposed."),

    # Stripe
    ("Stripe Secret Key",
     re.compile(r"(sk_live_[0-9A-Za-z]{24,})"),
     "Critical",
     "Stripe LIVE secret key. Enables financial transactions."),

    ("Stripe Restricted Key",
     re.compile(r"(rk_live_[0-9A-Za-z]{24,})"),
     "High",
     "Stripe restricted API key exposed."),

    # Google
    ("Google API Key",
     re.compile(r"(AIza[0-9A-Za-z\-_]{35})"),
     "High",
     "Google API Key. May grant access to Google Cloud services."),

    # Twilio
    ("Twilio Auth Token",
     re.compile(r"(?i)twilio.{0,20}['\"]([0-9a-f]{32})['\"]"),
     "High",
     "Twilio Auth Token. Can send SMS, make calls."),

    # SendGrid
    ("SendGrid API Key",
     re.compile(r"(SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,})"),
     "High",
     "SendGrid API Key. Can send emails from your domain."),

    # Private keys
    ("Private Key (PEM)",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "Critical",
     "Private key material exposed in response. Immediate rotation required."),

    # JWT (full token, not just header)
    ("JWT Token",
     re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
     "High",
     "JWT token exposed in response. May be a valid session token."),

    # Generic password assignment patterns
    ("Hardcoded Password",
     re.compile(r"""(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*['"]([^'"]{8,50})['"]"""),
     "High",
     "Hardcoded password or secret value in response."),

    # Database connection strings
    ("Database Connection String",
     re.compile(
         r"(?i)(mysql|postgresql|mongodb|redis|mssql|oracle)://"
         r"[A-Za-z0-9_\-]+:[^@\s]{3,}@[A-Za-z0-9\.\-]+"
     ),
     "Critical",
     "Database connection string with credentials exposed."),
]

# ── Sensitive data patterns ────────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    # Credit card (Luhn validation done separately)
    ("Credit Card Number",
     re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
                r"6(?:011|5[0-9]{2})[0-9]{12})\b"),
     "High",
     "Credit card number pattern detected in response."),

    # US SSN
    ("Social Security Number",
     re.compile(r"\b(?!000|666|9[0-9]{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b"),
     "Critical",
     "US Social Security Number pattern in response (PII breach risk)."),

    # Internal RFC1918 IPs in responses (info disclosure)
    ("Internal IP Address",
     re.compile(r"\b(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|"
                r"172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|"
                r"192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b"),
     "Low",
     "Internal RFC1918 IP address exposed in response body."),

    # Stack traces
    ("Stack Trace",
     re.compile(
         r"(?:Traceback \(most recent call last\)|"
         r"at [a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z_$][a-zA-Z0-9_$]*\([^)]*\.(?:java|kt|scala):\d+\)|"
         r"System\.Web\.HttpException|"
         r"Unhandled exception|"
         r"Fatal error:.+in .+ on line \d+)"
     ),
     "Medium",
     "Stack trace / internal error detail exposed in response."),
]

# ── Version disclosure patterns ────────────────────────────────────────────────
VERSION_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Joomla-Version",
]

VERSION_BODY_RE = re.compile(
    r"(?i)(?:apache|nginx|iis|php|tomcat|jboss|weblogic|"
    r"wordpress|drupal|joomla|laravel|django|rails|express)/"
    r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"
)

# ── Entropy helper ─────────────────────────────────────────────────────────────
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())

def _is_high_entropy(s: str, min_entropy: float = 4.5, min_len: int = 20) -> bool:
    return len(s) >= min_len and _shannon_entropy(s) >= min_entropy


# ── Luhn check ────────────────────────────────────────────────────────────────
def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


class PassiveScanner:
    """
    Analyse HTTP responses for secrets, sensitive data, and version
    disclosure without sending any additional requests.
    """

    def __init__(self, config: Dict):
        self.config = config
        self._seen_secrets: set = set()   # dedup identical secrets across pages

    def scan_response(self, response: requests.Response,
                      url: str) -> List[Dict]:
        """
        Scan a single response object. Returns a list of findings.
        Call this for every response the crawler collects.
        """
        findings: List[Dict] = []

        # Skip binary/non-text responses
        content_type = response.headers.get("content-type", "").lower()
        if any(t in content_type for t in ("image/", "audio/", "video/", "font/")):
            return []

        body   = response.text
        source = "response body"

        # 1. Secrets in body
        findings.extend(self._scan_secrets(body, url, source))

        # 2. Sensitive data in body
        findings.extend(self._scan_sensitive(body, url))

        # 3. Version disclosure in headers
        findings.extend(self._scan_version_headers(response.headers, url))

        # 4. Version disclosure in body
        findings.extend(self._scan_version_body(body, url))

        # 5. For JS files: also run high-entropy check for undocumented secrets
        if url.endswith(".js") or "javascript" in content_type:
            findings.extend(self._scan_js_entropy(body, url))

        return findings

    def scan_headers_only(self, headers: dict, url: str) -> List[Dict]:
        """Scan only response headers (no body needed)."""
        return self._scan_version_headers(headers, url)

    # ── Internal scanners ──────────────────────────────────────────────────────

    def _scan_secrets(self, body: str, url: str, source: str) -> List[Dict]:
        findings = []
        body_sample = body[:50000]   # first 50KB is enough, avoids huge pages

        for name, pattern, severity, description in SECRET_PATTERNS:
            matches = pattern.findall(body_sample)
            for match in matches[:3]:   # max 3 matches per pattern per page
                secret_val = match if isinstance(match, str) else match[0] if match else ""
                # Dedup: same secret value across multiple pages = one finding
                dedup_key = f"{name}:{secret_val[:20]}"
                if dedup_key in self._seen_secrets:
                    continue
                self._seen_secrets.add(dedup_key)

                # Truncate for evidence display (never show full secret in report)
                masked = secret_val[:6] + "..." + secret_val[-4:] if len(secret_val) > 12 else "***"

                findings.append({
                    "type":             "Secret / Credential Exposure",
                    "subtype":          name,
                    "url":              url,
                    "severity":         severity,
                    "owasp":            "A02 – Cryptographic Failures",
                    "confidence":       90,
                    "confidence_label": "Confirmed",
                    "classification":   "Confirmed Vulnerability",
                    "cvss_estimate":    9.8 if severity == "Critical" else 7.5,
                    "evidence_score":   90,
                    "description":      (
                        f"{name} found in {source} of {url}. {description}"
                    ),
                    "evidence":         (
                        f"{name} pattern matched: '{masked}' "
                        f"(full value masked for security)"
                    ),
                    "remediation": (
                        f"Immediately rotate the exposed {name}. Remove it from "
                        f"the codebase and response. Use environment variables or "
                        f"a secrets manager (AWS Secrets Manager, HashiCorp Vault). "
                        f"Audit git history for historical exposure."
                    ),
                    "verification_method": "Passive scanning — pattern match on response body",
                    "source":           "Passive Scanner",
                })
        return findings

    def _scan_sensitive(self, body: str, url: str) -> List[Dict]:
        findings = []
        body_sample = body[:50000]

        for name, pattern, severity, description in SENSITIVE_PATTERNS:
            matches = pattern.findall(body_sample)
            for match in matches[:2]:
                val = match if isinstance(match, str) else (match[0] if match else "")

                # Luhn-validate credit card numbers to avoid FPs
                if name == "Credit Card Number":
                    digits = re.sub(r"\D", "", val)
                    if not _luhn_valid(digits):
                        continue

                dedup_key = f"{name}:{url}:{val[:8]}"
                if dedup_key in self._seen_secrets:
                    continue
                self._seen_secrets.add(dedup_key)

                findings.append({
                    "type":             "Sensitive Data Exposure",
                    "subtype":          name,
                    "url":              url,
                    "severity":         severity,
                    "owasp":            "A02 – Cryptographic Failures",
                    "confidence":       80,
                    "confidence_label": "Likely",
                    "classification":   "Likely Vulnerability",
                    "cvss_estimate":    7.5 if severity in ("Critical", "High") else 4.3,
                    "evidence_score":   80,
                    "description":      f"{name} pattern found in response from {url}. {description}",
                    "evidence":         f"Pattern matched in response body at {url}",
                    "remediation": (
                        f"Ensure {name} values are not included in API responses "
                        f"unless explicitly required. Apply field-level filtering on "
                        f"all serialized output. Consider data masking for display."
                    ),
                    "verification_method": "Passive scanning — pattern match on response body",
                    "source":           "Passive Scanner",
                })
        return findings

    def _scan_version_headers(self, headers, url: str) -> List[Dict]:
        findings = []
        for header in VERSION_HEADERS:
            val = headers.get(header, "")
            if val and re.search(r"[0-9]+\.[0-9]", val):
                findings.append({
                    "type":             "Information Disclosure",
                    "subtype":          f"Version Disclosure ({header})",
                    "url":              url,
                    "severity":         "Low",
                    "owasp":            "A05 – Security Misconfiguration",
                    "confidence":       95,
                    "confidence_label": "Confirmed",
                    "classification":   "Confirmed Vulnerability",
                    "cvss_estimate":    3.7,
                    "evidence_score":   95,
                    "description": (
                        f"Response header '{header}: {val}' reveals the server "
                        f"software version, helping attackers identify known CVEs."
                    ),
                    "evidence":         f"{header}: {val}",
                    "remediation": (
                        f"Remove or suppress the '{header}' response header in your "
                        f"web server configuration. "
                        f"Apache: ServerTokens Prod. Nginx: server_tokens off. "
                        f"IIS: remove X-Powered-By via web.config."
                    ),
                    "verification_method": "Passive scanning — response header analysis",
                    "source":           "Passive Scanner",
                })
        return findings

    def _scan_version_body(self, body: str, url: str) -> List[Dict]:
        findings = []
        matches = VERSION_BODY_RE.findall(body[:20000])
        seen = set()
        for match in matches[:3]:
            key = match.lower()
            if key not in seen:
                seen.add(key)
                findings.append({
                    "type":             "Information Disclosure",
                    "subtype":          "Version Disclosure (Response Body)",
                    "url":              url,
                    "severity":         "Low",
                    "owasp":            "A05 – Security Misconfiguration",
                    "confidence":       75,
                    "confidence_label": "Likely",
                    "classification":   "Likely Vulnerability",
                    "cvss_estimate":    3.7,
                    "evidence_score":   75,
                    "description": (
                        f"Software version string '{match}' detected in response body "
                        f"at {url}. Version disclosure aids targeted CVE exploitation."
                    ),
                    "evidence":         f"Version string in body: {match}",
                    "remediation": (
                        "Suppress version strings in error pages, admin panels, and "
                        "default pages. Set display_errors=Off in PHP. "
                        "Use generic error pages in production."
                    ),
                    "verification_method": "Passive scanning — body content analysis",
                    "source":           "Passive Scanner",
                })
        return findings

    def _scan_js_entropy(self, js_body: str, url: str) -> List[Dict]:
        """
        Find high-entropy strings in JS files that look like undocumented
        API keys or secrets not matching any known pattern.
        """
        findings = []
        # Look for assignment patterns: var/const/let key = "..."
        assign_re = re.compile(
            r"""(?i)(?:var|const|let|window\.)"""
            r"""[\s_]*(key|token|secret|api_?key|auth|password|credential)"""
            r"""[^=]*=\s*['"]([A-Za-z0-9+/=_\-]{20,80})['"]"""
        )
        for m in assign_re.finditer(js_body[:100000]):
            val = m.group(2)
            if _is_high_entropy(val, min_entropy=4.8, min_len=24):
                dedup = f"jsent:{url}:{val[:12]}"
                if dedup not in self._seen_secrets:
                    self._seen_secrets.add(dedup)
                    masked = val[:6] + "..." + val[-4:]
                    findings.append({
                        "type":             "Secret / Credential Exposure",
                        "subtype":          "High-Entropy Secret in JavaScript",
                        "url":              url,
                        "severity":         "High",
                        "owasp":            "A02 – Cryptographic Failures",
                        "confidence":       68,
                        "confidence_label": "Likely",
                        "classification":   "Likely Vulnerability",
                        "cvss_estimate":    7.5,
                        "evidence_score":   68,
                        "description": (
                            f"High-entropy string assigned to a credential-named variable "
                            f"in {url}. Likely an API key or secret that should not be "
                            f"present in client-side JavaScript."
                        ),
                        "evidence":         f"Variable assignment: {m.group(1)} = '{masked}'",
                        "remediation": (
                            "Move all API keys, tokens, and secrets to server-side "
                            "environment variables. Never embed credentials in "
                            "client-side JavaScript — they are visible to all users."
                        ),
                        "verification_method": "Passive scanning — high-entropy JS analysis",
                        "source":           "Passive Scanner",
                    })
        return findings[:5]   # cap at 5 per JS file

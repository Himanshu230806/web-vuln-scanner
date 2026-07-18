"""
OWASP ZAP Integration Module
Integrates with OWASP ZAP API for enhanced scanning

Findings returned by active_scan() are shaped to match this project's
internal vulnerability dict format (type/url/severity/confidence/
classification/...) so they can be passed straight into
VulnerabilityScanner._add_vulnerability() and flow through the same
confidence scoring, FP reduction, DB storage, and PDF report as every
other detector's findings — instead of being a bolted-on second format.
"""

import logging
import time
from typing import Dict, List, Optional

try:
    from zapv2 import ZAPv2
    ZAP_LIBRARY_AVAILABLE = True
except ImportError:
    # The python-owasp-zap-v2.4 package is an optional dependency — only
    # needed if the person actually wants ZAP integration. Importing this
    # module (which core/scanner.py does unconditionally) must not crash
    # the whole scanner for everyone else if it isn't installed.
    ZAPv2 = None
    ZAP_LIBRARY_AVAILABLE = False

from config import ZAP_CONFIG
from modules.verification_engine import (
    adjusted_severity, confidence_label, classify_finding, estimate_cvss,
)

logger = logging.getLogger(__name__)

# ZAP's own "confidence" string (separate from its "risk" string) reflects
# how sure ZAP itself is about a given alert. We translate that into our
# 0-100 numeric scale so ZAP findings get the same severity-downgrade
# treatment as every other detector's findings, rather than being reported
# at face value.
ZAP_CONFIDENCE_TO_SCORE = {
    "confirmed": 95,
    "high":      80,
    "medium":    60,
    "low":       35,
}

# ZAP risk strings line up with ours except "Informational" → "Info".
ZAP_RISK_TO_SEVERITY = {
    "high":          "High",
    "medium":        "Medium",
    "low":           "Low",
    "informational": "Info",
}


# ZAP alerts identify themselves by CWE ID, not by this project's own
# canonical vulnerability-type strings (e.g. ZAP says "Cross Site
# Scripting (Reflected)" where this project says "Cross-Site Scripting
# (XSS)"). Mapping by CWE is far more robust than trying to string-match
# ZAP's many alert-name variants. These category labels are copied
# verbatim from core/scanner.py's OWASP_MAP so a ZAP finding lands in
# exactly the same coverage-matrix bucket a native finding of the same
# type would — this matters because the PDF report's "OWASP Top 10
# Coverage Matrix" does an exact string match against these labels; a
# mismatched label silently makes that category look untested.
CWE_TO_OWASP_CATEGORY = {
    "89":  "A03 – Injection",                  # SQL Injection
    "79":  "A03 – Injection",                  # XSS
    "611": "A03 – Injection",                  # XXE
    "776": "A03 – Injection",                  # XML entity expansion
    "22":  "A03 – Injection",                  # Path Traversal
    "78":  "A03 – Injection",                  # OS Command Injection
    "94":  "A03 – Injection",                  # Code Injection
    "352": "A04 – Insecure Design",            # CSRF
    "601": "A04 – Insecure Design",            # Open Redirect
    "639": "A01 – Broken Access Control",      # IDOR / authorization bypass
    "284": "A01 – Broken Access Control",
    "285": "A01 – Broken Access Control",
    "862": "A01 – Broken Access Control",
    "863": "A01 – Broken Access Control",
    "287": "A07 – Auth Failures",
    "384": "A07 – Auth Failures",              # Session Fixation
    "613": "A07 – Auth Failures",              # Insufficient Session Expiration
    "798": "A07 – Auth Failures",              # Hardcoded credentials
    "521": "A07 – Auth Failures",              # Weak password requirements
  "918": "A10 – SSRF",
    "16":  "A05 – Security Misconfiguration",
    "693": "A05 – Security Misconfiguration",  # Missing protection mechanism (CSP/clickjacking)
    "1021": "A05 – Security Misconfiguration", # Clickjacking
    "614": "A05 – Security Misconfiguration",  # Cookie missing Secure flag
    "1004": "A05 – Security Misconfiguration", # Cookie missing HttpOnly flag
    "200": "A05 – Security Misconfiguration",  # Information Exposure
    "209": "A05 – Security Misconfiguration",  # Error message info leak
    "538": "A05 – Security Misconfiguration",
    "327": "A02 – Cryptographic Failures",
    "326": "A02 – Cryptographic Failures",
    "295": "A02 – Cryptographic Failures",
    "311": "A02 – Cryptographic Failures",
    "319": "A02 – Cryptographic Failures",     # Cleartext transmission
    "937": "A06 – Vulnerable Components",
    "1104": "A06 – Vulnerable Components",
    "345": "A08 – Software Integrity",         # Insufficient verification of data authenticity
    "494": "A08 – Software Integrity",         # Download of code without integrity check
    "829": "A08 – Software Integrity",
    "117": "A09 – Logging Failures",
    "223": "A09 – Logging Failures",
    "532": "A09 – Logging Failures",           # Sensitive info in log file
    "778": "A09 – Logging Failures",           # Insufficient logging
}


class ZAPIntegration:
    """
    OWASP ZAP Scanner Integration

    Decoupled from the global ZAP_CONFIG['enabled'] flag — pass `enabled`
    explicitly (e.g. from the --zap CLI flag or the web UI checkbox) so the
    caller controls activation per-scan rather than via a hardcoded default.
    """

    def __init__(self, enabled: Optional[bool] = None,
                 proxy: Optional[str] = None, api_key: Optional[str] = None):
        self.config = ZAP_CONFIG
        self.zap = None
        self.connected = False

        self.enabled  = self.config["enabled"] if enabled is None else enabled
        self.proxy    = proxy or self.config["proxy"]
        self.api_key  = api_key if api_key is not None else self.config["api_key"]

        if not ZAP_LIBRARY_AVAILABLE:
            if self.enabled:
                logger.warning(
                    "ZAP integration requested but the 'python-owasp-zap-v2.4' "
                    "package isn't installed. Run: pip install python-owasp-zap-v2.4"
                )
            return

        if self.enabled:
            self._connect()

    def _connect(self):
        """Establish connection to ZAP API"""
        try:
            self.zap = ZAPv2(
                proxies={'http': self.proxy, 'https': self.proxy},
                apikey=self.api_key if self.api_key else None
            )

            # Test connection
            version = self.zap.core.version
            print(f"[+] Connected to OWASP ZAP v{version}")
            self.connected = True

        except Exception as e:
            logger.warning(
                f"Could not connect to ZAP at {self.proxy}: {e}. "
                f"Is ZAP running in daemon mode (zap.sh -daemon -port 8080)?"
            )
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
        Run ZAP spider + active scan and return findings already shaped to
        match this project's internal vulnerability dict format, ready to
        pass directly to VulnerabilityScanner._add_vulnerability().
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

            # Get alerts and translate each into our internal vuln shape
            alerts = self.zap.core.alerts(baseurl=target)

            for alert in alerts:
                vulnerabilities.append(self._alert_to_vuln(alert))

            return vulnerabilities

        except Exception as e:
            logger.error(f"ZAP active scan error: {e}")
            return []

    def _alert_to_vuln(self, alert: Dict) -> Dict:
        """
        Translate one ZAP alert dict into this project's internal
        vulnerability dict format (type/url/severity/confidence/
        classification/...), reusing the same confidence-scoring and
        severity-adjustment logic every other detector goes through —
        so a ZAP finding and a SQLiDetector finding read identically in
        the report instead of looking like two different tools bolted
        together.
        """
        zap_risk       = (alert.get("risk") or "Informational").strip().lower()
        zap_confidence = (alert.get("confidence") or "Medium").strip().lower()

        base_severity = ZAP_RISK_TO_SEVERITY.get(zap_risk, "Info")
        score         = ZAP_CONFIDENCE_TO_SCORE.get(zap_confidence, 50)
        severity      = adjusted_severity(base_severity, score)

        cwe = alert.get("cweid", "")
        owasp_category = CWE_TO_OWASP_CATEGORY.get(str(cwe), "")
        owasp_tag = owasp_category if owasp_category else "Uncategorized (see CWE)"
        cwe_label = f"CWE-{cwe}" if cwe and cwe != "-1" else "CWE not provided by ZAP"

        attack = alert.get("attack", "")

        return {
            "type":                alert.get("alert", "ZAP Finding"),
            "url":                 alert.get("url", ""),
            "parameter":           alert.get("param", ""),
            "severity":            severity,
            "original_severity":   base_severity,
            "description":         (alert.get("description") or "").strip()
                                    or "No description provided by ZAP for this alert.",
            "evidence":            alert.get("evidence") or
                                    "No specific evidence string captured by ZAP for this alert.",
            "remediation":         (alert.get("solution") or "").strip(),
            "reference":           alert.get("reference", ""),
            "confidence":          score,
            "confidence_label":    confidence_label(score),
            "evidence_score":      score,
            "classification":      classify_finding(score),
            "cvss_estimate":       estimate_cvss(severity, score),
            "verification_method": f"OWASP ZAP active scan (ZAP confidence: {zap_confidence.title()})",
            "reproduction_steps":  [f"ZAP attack vector: {attack}"] if attack else [],
            "owasp":               owasp_tag,
            "cwe":                 cwe_label,
            "source":              "OWASP ZAP",
        }
    
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

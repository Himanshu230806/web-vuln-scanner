"""
Broken Authentication & Session Management Detector
OWASP A07:2021 – Identification and Authentication Failures

Checks:
  - Default / weak credentials on login forms
  - No account lockout (brute-force possible)
  - Session token in URL
  - Weak / short session cookie values
  - Missing HttpOnly / Secure / SameSite flags (delegated to security_headers)
  - Password transmitted over HTTP
"""

import logging
import re
import string
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import requests

logger = logging.getLogger(__name__)


class BrokenAuthDetector:

    # Top weak credential pairs to try
    DEFAULT_CREDENTIALS = [
        ("admin",     "admin"),
        ("admin",     "password"),
        ("admin",     "admin123"),
        ("admin",     "1234"),
        ("admin",     ""),
        ("root",      "root"),
        ("root",      "toor"),
        ("test",      "test"),
        ("guest",     "guest"),
        ("user",      "user"),
        ("demo",      "demo"),
        ("admin",     "letmein"),
        ("administrator", "administrator"),
    ]

    # Patterns that indicate a successful login in the response
    SUCCESS_PATTERNS = [
        "dashboard", "welcome back", "logout", "sign out", "log out",
        "my account", "logged in", "authenticated",
        "account settings", "your account",
        "/logout", "/signout", "/sign-out",
        # Removed: "welcome" (homepage text), "profile" (public profile pages)
    ]

    # Patterns that indicate a failed login — expanded to catch more
    # natural-language failure messages that real apps use
    FAILURE_PATTERNS = [
        "invalid", "incorrect", "wrong", "failed", "error",
        "unauthorized", "denied", "bad credentials",
        "unsuccessful", "couldn't sign you in", "we didn't recognize",
        "hmm, that didn't work", "login failed", "authentication failed",
        "invalid username or password", "user not found",
        "no account found", "please check your",
    ]

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config  = config

    # ── public API ────────────────────────────────────────────────────────────

    def scan_login_form(self, form: Dict, page_url: str) -> List[Dict]:
        """Run all auth checks against a login form."""
        findings = []

        # Only care about POST forms with password fields
        if form.get("method", "GET").upper() != "POST":
            return findings
        inputs = form.get("inputs", [])
        if not any(i.get("type") == "password" for i in inputs):
            return findings

        action = form.get("action", page_url)

        # 1 – default credentials
        cred_result = self._test_default_credentials(form, action, inputs)
        if cred_result:
            findings.append({
                "type": "Broken Authentication",
                "subtype": "Default Credentials",
                "url": action,
                "severity": "Critical",
                "description": (
                    f"Login succeeded with default credentials "
                    f"'{cred_result[0]}' / '{cred_result[1]}'. "
                    "Default passwords must be changed before deployment."
                ),
                "recommendation": "Enforce strong password policy; remove all default accounts.",
                "evidence": f"username={cred_result[0]}, password={cred_result[1]}",
            })

        # 2 – no account lockout (brute-force)
        if self._test_no_lockout(form, action, inputs):
            findings.append({
                "type": "Broken Authentication",
                "subtype": "No Account Lockout",
                "url": action,
                "severity": "High",
                "description": (
                    "The login endpoint did not lock or rate-limit after "
                    "10 consecutive failed attempts, enabling brute-force attacks."
                ),
                "recommendation": (
                    "Implement account lockout (e.g. lock after 5 failures) "
                    "or CAPTCHA / rate limiting on the login endpoint."
                ),
                "evidence": "10 rapid failed logins returned identical responses with no lockout indication.",
            })

        # 3 – password over HTTP
        if action.startswith("http://"):
            findings.append({
                "type": "Broken Authentication",
                "subtype": "Credentials Over HTTP",
                "url": action,
                "severity": "Critical",
                "description": (
                    "Login form submits credentials over plain HTTP. "
                    "Passwords are transmitted in cleartext and can be intercepted."
                ),
                "recommendation": "Serve the login form and its action over HTTPS only.",
                "evidence": f"Form action: {action}",
            })

        return findings

    # Recognized session-identifier names. Matched as a whole, delimiter-
    # separated segment of a parameter/cookie name — not a bare substring —
    # so e.g. a "widget=sidebar" query param doesn't trip "sid" just
    # because "sid" happens to be a substring of "sidebar".
    SESSION_TOKEN_NAMES = {"sessionid", "session", "token", "jsessionid", "phpsessid", "sid", "auth", "jwt"}

    def _is_session_token_name(self, name: str) -> Optional[str]:
        """Return the matched token name if `name` IS (or contains, as a
        delimited segment) a recognized session-identifier name; else None."""
        name_lower = name.lower()
        if name_lower in self.SESSION_TOKEN_NAMES:
            return name_lower
        for segment in re.split(r"[_\-.]", name_lower):
            if segment in self.SESSION_TOKEN_NAMES:
                return segment
        return None

    def scan_session_tokens(self, response: requests.Response, url: str) -> List[Dict]:
        """Check session cookie strength and URL token exposure."""
        findings = []

        # Session token in URL — check actual query PARAMETER NAMES, not
        # a substring search across the whole URL string (which would
        # match "sid" inside "?widget=sidebar" even though that has
        # nothing to do with a session token).
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for param_name in query_params:
            matched = self._is_session_token_name(param_name)
            if matched:
                findings.append({
                    "type": "Broken Authentication",
                    "subtype": "Session Token in URL",
                    "url": url,
                    "severity": "High",
                    "description": (
                        f"Session token '{matched}' appears in the URL query string (parameter "
                        f"'{param_name}'). Tokens in URLs are logged by proxies and servers and "
                        "leak via Referer headers."
                    ),
                    "recommendation": "Store session tokens in HttpOnly cookies only, never in URLs.",
                    "evidence": f"URL contains: {param_name}=...",
                })

        # Weak / short session cookies
        for cookie in response.cookies:
            if self._is_session_token_name(cookie.name):
                val = cookie.value or ""
                if len(val) < 16:
                    findings.append({
                        "type": "Broken Authentication",
                        "subtype": "Weak Session Token",
                        "url": url,
                        "severity": "High",
                        "description": (
                            f"Session cookie '{cookie.name}' has a very short value "
                            f"({len(val)} chars). Short tokens are trivially brute-forced."
                        ),
                        "recommendation": "Use cryptographically random tokens of at least 128 bits (32 hex chars).",
                        "evidence": f"Cookie {cookie.name} length: {len(val)}",
                    })
                if self._is_low_entropy(val):
                    findings.append({
                        "type": "Broken Authentication",
                        "subtype": "Low-Entropy Session Token",
                        "url": url,
                        "severity": "Medium",
                        "description": (
                            f"Session cookie '{cookie.name}' appears to have low entropy "
                            "(sequential or predictable value)."
                        ),
                        "recommendation": "Use a CSPRNG (e.g. os.urandom) to generate session tokens.",
                        "evidence": f"Cookie value: {val[:20]}...",
                    })
        return findings

    # ── internals ─────────────────────────────────────────────────────────────

    def _test_default_credentials(self, form, action, inputs):
        user_field = next((i["name"] for i in inputs if i.get("type") not in ("password","submit","hidden")), None)
        pass_field = next((i["name"] for i in inputs if i.get("type") == "password"), None)
        if not user_field or not pass_field:
            return None

        # Get a baseline failure response
        try:
            baseline = self.session.post(
                action,
                data={user_field: "zzzinvaliduser999", pass_field: "zzzinvalidpass999"},
                timeout=self.config.get("request_timeout", 15),
                allow_redirects=True,
            )
            baseline_text    = baseline.text.lower()
            baseline_cookies = {c.name: c.value for c in baseline.cookies}
            baseline_url     = baseline.url
        except Exception:
            return None

        for username, password in self.DEFAULT_CREDENTIALS:
            try:
                resp = self.session.post(
                    action,
                    data={user_field: username, pass_field: password},
                    timeout=self.config.get("request_timeout", 15),
                    allow_redirects=True,
                )
                resp_lower = resp.text.lower()

                # Differential success match: a success word must appear
                # in THIS response but be ABSENT from the baseline failure
                # response. A static word present on every page regardless
                # of auth state (e.g. a nav bar "Dashboard" link rendered
                # by a single-page-app shell that returns identical markup
                # for every request) appears in BOTH responses and is
                # correctly ignored — this is what previously caused a
                # false "default credentials work" report on SPA login
                # forms whose POST just returns the same shell every time.
                new_success_words = {
                    p for p in self.SUCCESS_PATTERNS
                    if p in resp_lower and p not in baseline_text
                }
                has_failure_word = any(p in resp_lower for p in self.FAILURE_PATTERNS)

                # Structural confirmation: a genuine login almost always
                # changes session state (new/changed cookie) or destination
                # (redirect to a different URL than the failure case). This
                # replaces the old standalone "different content length"
                # check, which could be satisfied by any two DIFFERENT
                # failure messages (e.g. "user not found" vs "wrong
                # password") even when neither credential pair actually
                # worked.
                cookie_changed = any(
                    c.name not in baseline_cookies or c.value != baseline_cookies[c.name]
                    for c in resp.cookies
                )
                url_changed = resp.url != baseline_url

                if new_success_words and not has_failure_word and (cookie_changed or url_changed):
                    logger.warning(f"Default creds work: {username}/{password} at {action}")
                    return (username, password)
            except Exception:
                continue
        return None

    def _test_no_lockout(self, form, action, inputs) -> bool:
        user_field = next((i["name"] for i in inputs if i.get("type") not in ("password","submit","hidden")), None)
        pass_field = next((i["name"] for i in inputs if i.get("type") == "password"), None)
        if not user_field or not pass_field:
            return False

        blocked_indicators = ["locked", "blocked", "too many", "captcha", "429", "forbidden", "rate limit"]
        try:
            for attempt in range(10):
                resp = self.session.post(
                    action,
                    data={user_field: "brute_test_user", pass_field: f"wrongpass{attempt}"},
                    timeout=self.config.get("request_timeout", 15),
                    allow_redirects=True,
                )
                if resp.status_code == 429:
                    return False
                if any(ind in resp.text.lower() for ind in blocked_indicators):
                    return False
            return True  # 10 failures with no lockout → vulnerable
        except Exception:
            return False

    @staticmethod
    def _is_low_entropy(val: str) -> bool:
        if not val or len(val) < 8:
            return False
        # Sequential digits or letters → low entropy
        if val.isdigit() and (val == val[::-1] or int(val) < 10000):
            return True
        unique_chars = len(set(val))
        return unique_chars < max(4, len(val) // 4)

"""
Authentication Handler
======================
Solves Problem 2: scanners that can only test public pages because
everything behind /dashboard or /admin requires a logged-in session.

4 strategies tried in order via setup():
  1. Cookie injection  — --auth-cookie "name=value; name2=value2"
  2. Header injection  — --auth-header "Authorization: Bearer TOKEN"
  3. HTTP Basic auth   — --auth-basic "user:pass"
  4. Form-based login  — --auth-login-url + --auth-username + --auth-password
     Substrategy: if no <form> found, tries blind POST with 5 common
     field name combinations before giving up.

Session expiry mid-scan triggers automatic re-login via ensure_auth().
"""

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

SUCCESS_SIGNALS = [
    "dashboard", "welcome", "logout", "log out", "sign out",
    "my account", "my profile", "profile", "logged in", "authenticated",
    "account settings", "overview",
]
FAILURE_SIGNALS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "unauthorized", "denied", "bad credentials", "login failed",
    "authentication failed", "couldn't sign you in", "unsuccessful",
    "we didn't recognize", "hmm, that didn't work",
]

# 5 common field-name combos tried when form auto-detection fails
BLIND_POST_COMBOS = [
    ("username", "password"),
    ("email",    "password"),
    ("user",     "pass"),
    ("login",    "password"),
    ("email",    "passwd"),
]


class AuthHandler:
    """
    Manages authentication state for a scanning session.

    Usage:
        auth = AuthHandler(session, config)
        ok   = auth.setup()   # tries all 4 strategies in order
    """

    def __init__(self, session: requests.Session, config: Dict):
        self.session   = session
        self.config    = config
        self._logged_in           = False
        self._login_page_url: Optional[str] = None
        self._strategy_used: Optional[str]  = None

    # ── Public API ─────────────────────────────────────────────────────────

    def has_credentials(self) -> bool:
        """True if any auth method is configured."""
        c = self.config
        return bool(
            c.get("auth_cookie") or
            c.get("auth_header") or
            c.get("auth_basic") or
            (c.get("auth_url") and c.get("auth_user") and c.get("auth_pass"))
        )

    def setup(self) -> bool:
        """
        Try all 4 auth strategies in order.
        Returns True as soon as one succeeds.
        """
        # Strategy 1 — Cookie injection
        if self.config.get("auth_cookie"):
            ok = self._inject_cookies(self.config["auth_cookie"])
            if ok:
                self._strategy_used = "cookie"
                self._logged_in = True
                print("[+] Auth: session cookies injected")
                return True

        # Strategy 2 — Header injection
        if self.config.get("auth_header"):
            ok = self._inject_header(self.config["auth_header"])
            if ok:
                self._strategy_used = "header"
                self._logged_in = True
                print("[+] Auth: request header injected")
                return True

        # Strategy 3 — HTTP Basic auth
        if self.config.get("auth_basic"):
            ok = self._set_basic_auth(self.config["auth_basic"])
            if ok:
                self._strategy_used = "basic"
                self._logged_in = True
                print("[+] Auth: HTTP Basic auth configured")
                return True

        # Strategy 4 — Form-based login
        if self.config.get("auth_url") and self.config.get("auth_user") and self.config.get("auth_pass"):
            return self.login()

        return False

    # backward-compat alias used by scanner.py
    def login(self) -> bool:
        """Form-based login. Falls back to blind POST if no form found."""
        if not (self.config.get("auth_url") and
                self.config.get("auth_user") and
                self.config.get("auth_pass")):
            return False

        try:
            form, action = self._find_login_form(self.config["auth_url"])
            if form:
                success = self._submit_login(form, action)
            else:
                # Blind POST fallback — try 5 common field combos
                logger.info(
                    "Auth: no login form found at %s — trying blind POST combos",
                    self.config["auth_url"],
                )
                success = self._blind_post(self.config["auth_url"])

            if success:
                self._logged_in = True
                self._strategy_used = "form"
                self._login_page_url = self.config["auth_url"]
                print(f"[+] Auth: logged in successfully at {self.config['auth_url']}")
            else:
                logger.warning(
                    "Auth: login failed at %s — scan limited to public pages.",
                    self.config["auth_url"],
                )
            return success

        except Exception as exc:
            logger.warning("Auth: login exception: %s", exc)
            return False

    def is_authenticated(self) -> bool:
        if not self._logged_in:
            return False
        if not self._login_page_url:
            return True
        try:
            resp = self.session.get(
                self._login_page_url,
                timeout=self.config.get("request_timeout", 10),
                allow_redirects=True,
            )
            if resp.status_code in (401, 403):
                return False
            final_url = resp.url.lower()
            if any(kw in final_url for kw in ("login", "signin", "sign-in", "auth")):
                return False
            return True
        except Exception:
            return True

    def ensure_auth(self) -> bool:
        """Re-authenticate if session has expired."""
        if not self.has_credentials():
            return False
        if not self.is_authenticated():
            logger.info("Auth: session expired — re-authenticating via %s", self._strategy_used)
            self._logged_in = False
            return self.setup()
        return True

    # ── Strategy implementations ────────────────────────────────────────────

    def _inject_cookies(self, cookie_str: str) -> bool:
        """Parse 'name=value; name2=value2' and add to session."""
        try:
            for pair in cookie_str.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name, _, value = pair.partition("=")
                    self.session.cookies.set(name.strip(), value.strip())
            return True
        except Exception as exc:
            logger.debug("Auth cookie injection failed: %s", exc)
            return False

    def _inject_header(self, header_str: str) -> bool:
        """Parse 'HeaderName: value' and add to session headers."""
        try:
            name, _, value = header_str.partition(":")
            self.session.headers[name.strip()] = value.strip()
            return True
        except Exception as exc:
            logger.debug("Auth header injection failed: %s", exc)
            return False

    def _set_basic_auth(self, basic_str: str) -> bool:
        """Parse 'user:pass' and configure session basic auth."""
        try:
            user, _, passwd = basic_str.partition(":")
            self.session.auth = (user.strip(), passwd)
            return True
        except Exception as exc:
            logger.debug("Auth basic auth setup failed: %s", exc)
            return False

    def _blind_post(self, url: str) -> bool:
        """
        Try 5 common field-name combos when no <form> tag was found.
        Some apps use JS-only forms or non-standard markup.
        """
        user = self.config["auth_user"]
        pwd  = self.config["auth_pass"]
        timeout = self.config.get("request_timeout", 15)

        for user_field, pass_field in BLIND_POST_COMBOS:
            try:
                resp = self.session.post(
                    url,
                    data={user_field: user, pass_field: pwd},
                    timeout=timeout,
                    allow_redirects=True,
                )
                if self._looks_like_success(resp):
                    logger.info(
                        "Auth: blind POST succeeded with fields %s/%s",
                        user_field, pass_field,
                    )
                    return True
            except Exception:
                continue
        return False

    # ── Form helpers (unchanged from v1) ────────────────────────────────────

    def _find_login_form(self, url: str) -> Tuple[Optional[Dict], str]:
        try:
            resp = self.session.get(
                url,
                timeout=self.config.get("request_timeout", 15),
                allow_redirects=True,
            )
            resp.raise_for_status()
        except Exception as exc:
            logger.debug("Auth: could not fetch login page %s: %s", url, exc)
            return None, url

        soup  = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return None, url

        best_form   = None
        best_action = url

        for form in forms:
            action   = urljoin(resp.url, form.get("action", "") or resp.url)
            inputs   = form.find_all(["input", "textarea"])
            has_pwd  = any(i.get("type", "").lower() == "password" for i in inputs)
            has_text = any(i.get("type", "").lower() in ("text", "email", "") for i in inputs)

            if has_pwd and has_text:
                best_form   = form
                best_action = action
                break

            if any(kw in action.lower() for kw in ("login", "signin", "sign-in", "auth", "session")):
                if best_form is None:
                    best_form   = form
                    best_action = action

        if best_form is None:
            for form in forms:
                if form.get("method", "GET").upper() == "POST":
                    best_form   = form
                    best_action = urljoin(resp.url, form.get("action", "") or resp.url)
                    break

        if best_form is None:
            return None, url

        return self._parse_form(best_form, resp.url), best_action

    def _parse_form(self, soup_form, page_url: str) -> Dict:
        action = urljoin(page_url, soup_form.get("action", "") or page_url)
        inputs = []
        for tag in soup_form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                inputs.append({
                    "name":  name,
                    "type":  tag.get("type", "text").lower(),
                    "value": tag.get("value", ""),
                })
        return {
            "action": action,
            "method": soup_form.get("method", "GET").upper(),
            "inputs": inputs,
        }

    def _submit_login(self, form: Dict, action: str) -> bool:
        inputs     = form.get("inputs", [])
        method     = form.get("method", "POST").upper()
        user_field = None
        pass_field = None

        for inp in inputs:
            t    = (inp.get("type") or "text").lower()
            name = (inp.get("name") or "").lower()
            if t in ("email",) or any(kw in name for kw in ("user", "email", "login", "name")):
                if user_field is None:
                    user_field = inp["name"]
            elif t == "password":
                if pass_field is None:
                    pass_field = inp["name"]

        if user_field is None or pass_field is None:
            for inp in inputs:
                t = (inp.get("type") or "text").lower()
                if t in ("text", "email") and user_field is None:
                    user_field = inp["name"]
                elif t == "password" and pass_field is None:
                    pass_field = inp["name"]

        if not user_field or not pass_field:
            return False

        data = {
            inp["name"]: inp.get("value", "")
            for inp in inputs
            if inp.get("name") and inp.get("type") not in ("submit", "button", "image")
        }
        data[user_field] = self.config["auth_user"]
        data[pass_field] = self.config["auth_pass"]

        try:
            if method == "POST":
                resp = self.session.post(
                    action, data=data,
                    timeout=self.config.get("request_timeout", 15),
                    allow_redirects=True,
                )
            else:
                resp = self.session.get(
                    action, params=data,
                    timeout=self.config.get("request_timeout", 15),
                    allow_redirects=True,
                )
        except Exception as exc:
            logger.debug("Auth: form submit error: %s", exc)
            return False

        return self._looks_like_success(resp)

    def _looks_like_success(self, resp: requests.Response) -> bool:
        resp_lower  = resp.text.lower()
        final_url   = resp.url.lower()
        has_failure = any(p in resp_lower for p in FAILURE_SIGNALS)
        still_login = any(kw in final_url for kw in ("login", "signin", "sign-in"))
        if has_failure or (still_login and not any(p in resp_lower for p in SUCCESS_SIGNALS)):
            return False
        new_cookies = list(resp.cookies)
        if not new_cookies and still_login:
            return False
        return True

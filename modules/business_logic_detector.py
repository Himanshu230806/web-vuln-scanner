"""
Business Logic Vulnerability Detector
=======================================
Solves Problem 6: automatable business-logic flaws. True business logic
bugs require human understanding of the app, but 4 classes have clear
enough structural signatures to test automatically:

  BL1 – Price manipulation
        Submits price=0, price=-1, price=0.01 to forms containing a
        price/cost/amount field. If the form accepts the submission
        without an error response, the app may be processing the
        manipulated price.

  BL3 – Negative quantity
        Submits quantity=-1 to forms containing a quantity/qty/count
        field. A negative quantity accepted by a cart/order endpoint
        can result in a "refund" credit being applied.

  BL4 – Multi-step flow skipping
        Detects multi-step flows (?step=N, ?stage=N, /step/N/) and
        attempts to jump directly to the final step with a fresh session
        (no cookies). If the final step returns 200 with no redirect to
        step 1, the flow can be bypassed.

  BL5 – Mass assignment (REST API)
        Sends PUT/PATCH requests to JSON API endpoints with injected
        privilege-escalation fields (role=admin, isAdmin=true,
        verified=true, credit=9999). If any injected field appears in
        the response body, the API may have a mass assignment flaw.

Honest limitations (documented in each finding):
  - BL1/BL3: detecting "acceptance" from an HTTP 200 is heuristic —
    the app may show an error in the page body even on 200. Findings
    are capped at "Potential Vulnerability" (55% confidence).
  - BL4: fresh-session step-skip only detects missing server-side state
    validation. Apps that validate state server-side but accept the
    request are not detectable.
  - BL5: the injected field appearing in the response is a strong signal
    but not proof of exploitation — the app may echo but not apply it.
"""

import json
import logging
import re
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse, urlencode

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ── Field name heuristics ───────────────────────────────────────────────────────

PRICE_FIELD_NAMES = {
    "price", "cost", "amount", "total", "subtotal", "fee",
    "unit_price", "unitprice", "item_price", "itemprice",
    "product_price", "sale_price", "rate",
}
QTY_FIELD_NAMES = {
    "quantity", "qty", "count", "num", "number",
    "amount",  # reused in some cart forms
    "units", "copies",
}

# Fields to inject in mass-assignment probes (BL5)
MASS_ASSIGN_FIELDS = {
    "role":         "admin",
    "isAdmin":      "true",
    "is_admin":     "true",
    "admin":        "true",
    "verified":     "true",
    "email_verified": "true",
    "active":       "true",
    "status":       "active",
    "credit":       "9999",
    "balance":      "9999",
    "points":       "9999",
    "plan":         "enterprise",
    "subscription": "premium",
}

# Response error signals — if present, the manipulation was likely REJECTED
REJECTION_SIGNALS = [
    "invalid", "error", "invalid price", "price must be", "minimum",
    "cannot be negative", "must be greater", "not allowed", "rejected",
    "forbidden", "out of range",
]

# Step-param patterns
STEP_PARAM_RE = re.compile(
    r"[?&](step|stage|page|phase|wizard)=(\d+)", re.IGNORECASE
)
STEP_PATH_RE = re.compile(
    r"/(step|stage|phase)/(\d+)(/|$)", re.IGNORECASE
)


class BusinessLogicDetector:

    def __init__(self, session: requests.Session, config: Dict):
        self.session  = session
        self.config   = config
        self._timeout = config.get("request_timeout", 15)

    # ── Public API ─────────────────────────────────────────────────────────

    def scan_forms(self, url: str, forms: List[Dict]) -> List[Dict]:
        """Run BL1 and BL3 against all forms discovered for this URL."""
        findings = []
        for form in forms:
            findings.extend(self._bl1_price_manipulation(url, form))
            findings.extend(self._bl3_negative_quantity(url, form))
        return findings

    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """Run BL4 (step skipping) across all discovered URLs."""
        findings  = []
        seen_flows: Set[str] = set()

        for url in urls:
            flow_key, last_step = self._detect_step_flow(url)
            if flow_key and flow_key not in seen_flows and last_step:
                seen_flows.add(flow_key)
                finding = self._bl4_step_skip(url, flow_key, last_step)
                if finding:
                    findings.append(finding)

        return findings

    def scan_api_endpoints(self, api_urls: List[str]) -> List[Dict]:
        """Run BL5 (mass assignment) against JSON API endpoints."""
        findings = []
        for url in api_urls:
            finding = self._bl5_mass_assignment(url)
            if finding:
                findings.append(finding)
        return findings

    # ── BL1: Price manipulation ─────────────────────────────────────────────

    def _bl1_price_manipulation(self, page_url: str, form: Dict) -> List[Dict]:
        findings = []
        action   = form.get("action", page_url)
        inputs   = form.get("inputs", [])
        method   = form.get("method", "POST").upper()

        price_fields = [
            inp for inp in inputs
            if any(kw in (inp.get("name") or "").lower() for kw in PRICE_FIELD_NAMES)
        ]
        if not price_fields:
            return []

        base_data = {
            inp["name"]: inp.get("value") or "1"
            for inp in inputs
            if inp.get("name") and inp.get("type") not in ("submit", "button", "file")
        }

        for pf in price_fields:
            for bad_price in ("0", "-1", "0.001"):
                data = {**base_data, pf["name"]: bad_price}
                try:
                    resp = self._submit(method, action, data)
                    if resp is None:
                        continue
                    if self._was_accepted(resp):
                        findings.append({
                            "type":             "Business Logic Vulnerability",
                            "subtype":          "BL1 – Price Manipulation",
                            "url":              action,
                            "parameter":        pf["name"],
                            "severity":         "High",
                            "owasp":            "A04 – Insecure Design",
                            "confidence":       55,
                            "confidence_label": "Potential",
                            "classification":   "Potential Vulnerability",
                            "cvss_estimate":    7.5,
                            "evidence_score":   55,
                            "description": (
                                f"The form field '{pf['name']}' accepted a price "
                                f"value of '{bad_price}' without returning a visible "
                                f"error response. If the server processes this value "
                                f"as the actual price, items could be purchased for "
                                f"free or at near-zero cost."
                            ),
                            "evidence": (
                                f"POST {action} with {pf['name']}={bad_price} "
                                f"→ HTTP {resp.status_code}, no error detected in body."
                            ),
                            "remediation": (
                                "Validate and enforce price values server-side. "
                                "Never trust client-submitted prices — look up the "
                                "price from your database using the product ID."
                            ),
                            "reproduction_steps": [
                                f"Submit the form at {page_url}",
                                f"Intercept and change {pf['name']}={bad_price}",
                                "Observe: submission succeeds without error",
                            ],
                        })
                        break  # one finding per field is enough
                except Exception:
                    continue

        return findings

    # ── BL3: Negative quantity ──────────────────────────────────────────────

    def _bl3_negative_quantity(self, page_url: str, form: Dict) -> List[Dict]:
        findings = []
        action   = form.get("action", page_url)
        inputs   = form.get("inputs", [])
        method   = form.get("method", "POST").upper()

        qty_fields = [
            inp for inp in inputs
            if any(kw in (inp.get("name") or "").lower() for kw in QTY_FIELD_NAMES)
        ]
        if not qty_fields:
            return []

        base_data = {
            inp["name"]: inp.get("value") or "1"
            for inp in inputs
            if inp.get("name") and inp.get("type") not in ("submit", "button", "file")
        }

        for qf in qty_fields:
            data = {**base_data, qf["name"]: "-1"}
            try:
                resp = self._submit(method, action, data)
                if resp is None:
                    continue
                if self._was_accepted(resp):
                    findings.append({
                        "type":             "Business Logic Vulnerability",
                        "subtype":          "BL3 – Negative Quantity Accepted",
                        "url":              action,
                        "parameter":        qf["name"],
                        "severity":         "Medium",
                        "owasp":            "A04 – Insecure Design",
                        "confidence":       55,
                        "confidence_label": "Potential",
                        "classification":   "Potential Vulnerability",
                        "cvss_estimate":    5.4,
                        "evidence_score":   55,
                        "description": (
                            f"The quantity field '{qf['name']}' accepted a value "
                            f"of -1 without returning an error. In cart/order "
                            f"flows, a negative quantity can result in a credit "
                            f"being applied to the account."
                        ),
                        "evidence": (
                            f"POST {action} with {qf['name']}=-1 "
                            f"→ HTTP {resp.status_code}, no rejection detected."
                        ),
                        "remediation": (
                            "Enforce server-side minimum quantity validation "
                            "(qty >= 1). Reject or clamp negative values."
                        ),
                        "reproduction_steps": [
                            f"Open the form at {page_url}",
                            f"Set {qf['name']}=-1",
                            "Submit and observe: no error returned",
                        ],
                    })
            except Exception:
                continue

        return findings

    # ── BL4: Multi-step flow skipping ──────────────────────────────────────

    def _detect_step_flow(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect if a URL is part of a multi-step flow.
        Returns (flow_key, last_step_url) or (None, None).
        """
        # Query-param style: ?step=2
        m = STEP_PARAM_RE.search(url)
        if m:
            param_name = m.group(1)
            step_num   = int(m.group(2))
            if step_num >= 2:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                # Build the "last step" URL: try step_num + 1 and step_num + 2
                last_step = step_num + 2
                params[param_name] = [str(last_step)]
                last_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), ""
                ))
                # flow key is the base URL without step param
                params.pop(param_name)
                flow_key = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), ""
                ))
                return flow_key, last_url

        # Path style: /step/2/
        m = STEP_PATH_RE.search(url)
        if m:
            step_num = int(m.group(2))
            if step_num >= 2:
                last_step = step_num + 2
                last_url  = STEP_PATH_RE.sub(
                    lambda x: x.group(0).replace(
                        f"/{x.group(2)}", f"/{last_step}"
                    ), url, count=1
                )
                flow_key = STEP_PATH_RE.sub("", url)
                return flow_key, last_url

        return None, None

    def _bl4_step_skip(self, url: str, flow_key: str,
                       last_step_url: str) -> Optional[Dict]:
        # Use a fresh session (no cookies) to test step-skip
        fresh_session = requests.Session()
        fresh_session.headers.update(self.session.headers)
        try:
            resp = fresh_session.get(
                last_step_url,
                timeout=self._timeout,
                allow_redirects=False,   # don't follow — we want to see if it redirects
            )
        except Exception:
            return None

        # A properly-implemented multi-step flow MUST redirect to step 1
        # when the session has no valid state. If we get 200 directly,
        # the step-skip worked.
        if resp.status_code != 200:
            return None

        body_lower = resp.text.lower()
        # Sanity check: 200 but the body looks like a login/access-denied page
        if any(kw in body_lower for kw in ("login", "sign in", "access denied", "unauthorized")):
            return None

        return {
            "type":             "Business Logic Vulnerability",
            "subtype":          "BL4 – Multi-Step Flow Step Skipping",
            "url":              last_step_url,
            "severity":         "High",
            "owasp":            "A04 – Insecure Design",
            "confidence":       65,
            "confidence_label": "Likely",
            "classification":   "Likely Vulnerability",
            "cvss_estimate":    7.5,
            "evidence_score":   65,
            "description": (
                f"Directly accessing the final step of a multi-step flow "
                f"({last_step_url}) with a fresh session (no cookies/state) "
                f"returned HTTP 200 instead of redirecting to the beginning. "
                f"This may allow bypassing earlier steps (e.g. payment, "
                f"email verification, identity check)."
            ),
            "evidence": (
                f"GET {last_step_url} with no session cookies → HTTP 200 "
                f"(expected: redirect to step 1)"
            ),
            "remediation": (
                "Validate server-side that all preceding steps have been "
                "completed before serving any step. Store completion state "
                "in the server-side session, never in URL params."
            ),
            "reproduction_steps": [
                "Open the flow from the beginning to observe step URLs",
                "Copy the final step URL",
                "Open a private/incognito browser (fresh session)",
                f"Navigate directly to: {last_step_url}",
                "Observe: page loads without redirect to step 1",
            ],
        }

    # ── BL5: Mass assignment ────────────────────────────────────────────────

    def _bl5_mass_assignment(self, url: str) -> Optional[Dict]:
        """
        Send PUT then PATCH with privilege-escalation fields to a JSON
        API endpoint. If any injected field appears in the response,
        flag as potential mass assignment.
        """
        parsed = urlparse(url)
        # Only test endpoints that look like a REST resource
        # (path ends with an ID segment or /users/me etc.)
        path = parsed.path
        if not re.search(r"/(\d+|me|self|profile|account|user)/?$", path, re.IGNORECASE):
            return None

        injected: Dict = {}
        for method in ("PUT", "PATCH"):
            try:
                resp = self.session.request(
                    method, url,
                    json=MASS_ASSIGN_FIELDS,
                    headers={"Content-Type": "application/json"},
                    timeout=self._timeout,
                    allow_redirects=True,
                )
            except Exception:
                continue

            if resp.status_code not in (200, 201, 204):
                continue

            try:
                body = resp.json()
            except Exception:
                body = {}

            # Check if any injected field appears in the response
            for field, value in MASS_ASSIGN_FIELDS.items():
                resp_val = self._find_in_json(body, field)
                if resp_val is not None:
                    injected[field] = str(resp_val)

            if injected:
                break

        if not injected:
            return None

        return {
            "type":             "Business Logic Vulnerability",
            "subtype":          "BL5 – Mass Assignment",
            "url":              url,
            "severity":         "High",
            "owasp":            "A04 – Insecure Design",
            "confidence":       70,
            "confidence_label": "Likely",
            "classification":   "Likely Vulnerability",
            "cvss_estimate":    8.1,
            "evidence_score":   70,
            "description": (
                f"The API endpoint {url} accepted PUT/PATCH requests "
                f"containing privilege-escalation fields and returned those "
                f"fields in the response. This suggests the API may bind "
                f"request body fields directly to model attributes without "
                f"allowlisting (mass assignment)."
            ),
            "evidence": (
                f"Injected fields found in response: "
                + ", ".join(f"{k}={v}" for k, v in injected.items())
            ),
            "remediation": (
                "Use an explicit allowlist of fields that users are permitted "
                "to update. Never bind request body directly to model.update(). "
                "In Rails: use strong parameters. In Django: use explicit "
                "serializer fields. In Node: explicitly pick allowed fields."
            ),
            "reproduction_steps": [
                f"PATCH {url} with Content-Type: application/json",
                f"Body: {json.dumps({k: v for k, v in list(MASS_ASSIGN_FIELDS.items())[:3]})}",
                "Observe: response contains injected field values",
            ],
        }

    # ── Utilities ───────────────────────────────────────────────────────────

    def _submit(self, method: str, action: str,
                data: Dict) -> Optional[requests.Response]:
        try:
            if method == "POST":
                return self.session.post(action, data=data,
                                          timeout=self._timeout,
                                          allow_redirects=True)
            return self.session.get(action, params=data,
                                     timeout=self._timeout,
                                     allow_redirects=True)
        except Exception:
            return None

    def _was_accepted(self, resp: requests.Response) -> bool:
        """Heuristic: was the manipulated value accepted (not rejected)?"""
        if resp.status_code not in (200, 201, 302):
            return False
        body_lower = resp.text.lower()
        return not any(sig in body_lower for sig in REJECTION_SIGNALS)

    def _find_in_json(self, obj, key: str):
        """Recursively search a JSON object for a key."""
        if isinstance(obj, dict):
            if key in obj:
                return obj[key]
            for v in obj.values():
                result = self._find_in_json(v, key)
                if result is not None:
                    return result
        elif isinstance(obj, list):
            for item in obj:
                result = self._find_in_json(item, key)
                if result is not None:
                    return result
        return None

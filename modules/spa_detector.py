"""
SPA Detector
============
Detects whether a target is a Single-Page Application (React, Vue,
Angular, Next.js, Nuxt, etc.) before crawling begins, so the scanner
can automatically switch to the Playwright browser crawler when needed
instead of requiring the user to set --browser-crawl manually.

6 detection signals (any 2+ = SPA confirmed):

  S1 – Framework DOM markers
       id="root", id="app", id="__next", ng-version attribute,
       data-reactroot, __NEXT_DATA__ script tag, __nuxt, data-v-app

  S2 – JS bundle patterns
       <script src="...chunk...js">, vendor.js, app.bundle.js,
       main.[hash].js — the fingerprints of a webpack/vite build

  S3 – Thin body
       < 300 chars of visible text in the raw HTML response — classic
       SPA shell that renders content only after JS executes

  S4 – Hash-router links
       href="#/" or href="#/route" links in the raw HTML

  S5 – All links collapse to one path
       Every <a href> points to the same URL or origin root ("/" only)
       — the SPA shell that JS will take over

  S6 – <noscript> warning
       "Please enable JavaScript" / "You need JavaScript" message —
       the developer's own admission that the page requires JS

Confidence tiers:
  2 signals → "Likely SPA" (recommended: use browser crawler)
  3+ signals → "Confirmed SPA" (strongly recommended)
  0-1 signals → "Server-rendered" (HTML crawler is sufficient)
"""

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# ── Signal patterns ────────────────────────────────────────────────────────────

# S1: DOM marker id/attr patterns
SPA_DOM_MARKERS = [
    'id="root"', "id='root'",
    'id="app"',  "id='app'",
    'id="__next"', "id='__next'",
    "ng-version",
    "data-reactroot",
    "__NEXT_DATA__",
    "__nuxt",
    "data-v-app",
    'id="vue-app"',
    "data-server-rendered",
]

# S2: JS bundle filename patterns
SPA_BUNDLE_RE = re.compile(
    r'<script[^>]+src=["\'][^"\']*'
    r'(chunk\.|vendor\.|bundle\.|app\.|main\.[a-f0-9]{6,}\.|runtime\.)[^"\']*\.js["\']',
    re.IGNORECASE,
)

# S4: Hash-router link pattern
HASH_ROUTER_RE = re.compile(r'href=["\']#/', re.IGNORECASE)

# S6: Noscript warning text
NOSCRIPT_RE = re.compile(
    r"(please enable javascript|you need (to enable )?javascript|"
    r"javascript is (required|disabled|not enabled)|"
    r"this app (works best|requires) with javascript)",
    re.IGNORECASE,
)


class SPADetector:
    """Analyse a URL's raw HTML response for SPA framework signals."""

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config  = config

    def detect(self, url: str) -> Dict:
        """
        Fetch `url` and check all 6 signals.
        Returns a result dict:
          {
            "is_spa": bool,
            "confidence": "Confirmed SPA" | "Likely SPA" | "Server-rendered",
            "signal_count": int,
            "signals": [list of triggered signal names],
            "recommendation": str,
          }
        """
        try:
            resp = self.session.get(
                url,
                timeout=self.config.get("request_timeout", 15),
                allow_redirects=True,
            )
        except Exception:
            return self._result([], url)

        html = resp.text
        signals: List[str] = []

        # S1 — Framework DOM markers
        html_lower = html.lower()
        for marker in SPA_DOM_MARKERS:
            if marker.lower() in html_lower:
                signals.append(f"S1:framework_marker({marker.strip()[:30]})")
                break   # one hit is enough for this signal

        # S2 — JS bundle filename patterns
        if SPA_BUNDLE_RE.search(html):
            signals.append("S2:js_bundle_pattern")

        # S3 — Thin body (< 300 chars of visible text)
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(["script", "style", "head", "meta"]):
                tag.decompose()
            visible_text = soup.get_text(separator=" ", strip=True)
            if len(visible_text) < 300:
                signals.append(f"S3:thin_body({len(visible_text)}_chars)")
        except Exception:
            pass

        # S4 — Hash-router links
        if HASH_ROUTER_RE.search(html):
            signals.append("S4:hash_router_links")

        # S5 — All links collapse to one path
        try:
            soup2 = BeautifulSoup(html, "html.parser")
            hrefs = [
                a.get("href", "").strip()
                for a in soup2.find_all("a", href=True)
                if not a["href"].startswith(("mailto:", "tel:", "javascript:"))
            ]
            parsed_base = urlparse(url)
            base_path = parsed_base.path.rstrip("/") or "/"
            unique_paths = {
                urlparse(h).path.rstrip("/") or "/"
                for h in hrefs
                if h and not h.startswith("#")
            }
            if hrefs and len(unique_paths) <= 1:
                signals.append(f"S5:all_links_same_path({list(unique_paths)[:1]})")
        except Exception:
            pass

        # S6 — <noscript> JavaScript warning
        if NOSCRIPT_RE.search(html):
            signals.append("S6:noscript_warning")

        return self._result(signals, url)

    @staticmethod
    def _result(signals: List[str], url: str) -> Dict:
        count = len(signals)
        if count >= 3:
            confidence   = "Confirmed SPA"
            is_spa       = True
            recommendation = (
                "This appears to be a Single-Page Application. Use --browser-crawl "
                "to enable Playwright-based crawling so JavaScript-rendered routes, "
                "hash-router paths, and XHR/fetch API endpoints are discovered."
            )
        elif count >= 2:
            confidence   = "Likely SPA"
            is_spa       = True
            recommendation = (
                "This may be a Single-Page Application (2 signals detected). "
                "Consider using --browser-crawl for more complete coverage."
            )
        else:
            confidence   = "Server-rendered"
            is_spa       = False
            recommendation = (
                "No SPA signals detected — HTML crawler should provide good coverage."
            )

        return {
            "url":            url,
            "is_spa":         is_spa,
            "confidence":     confidence,
            "signal_count":   count,
            "signals":        signals,
            "recommendation": recommendation,
        }

"""
Shared utilities to reduce false positives across all detector modules.

Core problem this solves:
  Many modern sites (SPAs with client-side routing, servers with catch-all
  404 handlers) return HTTP 200 with IDENTICAL content for almost ANY path —
  including paths that don't really exist (/.env, /admin, /xxxxx12345).
  Without a baseline, every "probe this path and check for 200" detector
  (SRI exposed files, admin panels, vulnerable components, SSRF, IDOR,
  broken auth) produces wall-to-wall false positives on such sites.

  This module establishes a "soft 404" baseline once per scan and lets
  detectors compare probe responses against it.
"""

import logging
import random
import re
import string
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Cache baselines per-origin so we only probe once per host per scan
_baseline_cache: Dict[str, Dict] = {}


def _random_path() -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return f"/__scanner_canary_{suffix}__"


def get_baseline(session: requests.Session, base_url: str, config: Dict) -> Dict:
    """
    Fetch (and cache) the response for a definitely-nonexistent path on this
    origin. Returns a dict with status_code, length, and a normalised body
    used for similarity comparisons.
    """
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    if origin in _baseline_cache:
        return _baseline_cache[origin]

    baseline = {"status_code": 404, "length": 0, "body": "", "is_soft_404_app": False}
    try:
        url = origin + _random_path()
        resp = session.get(url, timeout=config.get("request_timeout", 15), allow_redirects=True)
        baseline["status_code"] = resp.status_code
        baseline["length"] = len(resp.text)
        baseline["body"] = resp.text
        # If a nonexistent path returns 200 with a real-looking page,
        # this origin has a catch-all (SPA router / custom 404-as-200).
        if resp.status_code == 200 and len(resp.text) > 50:
            baseline["is_soft_404_app"] = True
            logger.info(
                "Origin %s returns HTTP 200 for nonexistent paths (soft-404 / SPA catch-all). "
                "Probe-based checks will be compared against this baseline.",
                origin,
            )
    except Exception as exc:
        logger.debug("Baseline probe failed for %s: %s", origin, exc)

    _baseline_cache[origin] = baseline
    return baseline


def matches_baseline(response: requests.Response, baseline: Dict,
                     tolerance: float = None) -> bool:
    """
    Return True if `response` looks like the same "soft 404" / catch-all
    page as the baseline (i.e. probably NOT a real hit).

    Fix: adaptive tolerance — large pages (>20KB) get 10% tolerance since
    they have more dynamic content noise. Small pages (<5KB, e.g. login/
    contact forms) get 5% tolerance so real injection-caused differences
    are not masked by the loose threshold.
    """
    # Adaptive tolerance based on baseline page size
    if tolerance is None:
        base_len = baseline.get("length", 0)
        tolerance = 0.05 if base_len < 5000 else 0.10

    if baseline.get("is_soft_404_app"):
        if response.status_code != baseline["status_code"]:
            return False
        base_len = baseline["length"]
        resp_len = len(response.text)
        if base_len == 0:
            return resp_len == 0
        diff_ratio = abs(resp_len - base_len) / base_len
        return diff_ratio <= tolerance

    if response.status_code == baseline.get("status_code"):
        base_len = baseline.get("length", 0)
        resp_len = len(response.text)
        if base_len == 0:
            return resp_len == 0
        diff_ratio = abs(resp_len - base_len) / base_len
        return diff_ratio <= tolerance

    return False


def is_significant_difference(len_a: int, len_b: int,
                              min_abs: int = 300, min_pct: float = 0.15) -> bool:
    """
    Return True only if two response lengths differ by BOTH an absolute
    amount and a relative percentage. Avoids flagging tiny dynamic content
    (timestamps, CSRF tokens, ad slots) as "different pages".
    """
    diff = abs(len_a - len_b)
    if diff < min_abs:
        return False
    base = max(len_a, len_b, 1)
    return (diff / base) >= min_pct


def strip_reflected_payload(response_text: str, payload: str) -> str:
    """
    Remove literal occurrences of `payload` (and its common URL-encoded
    forms) from response_text before running content-indicator checks.

    Prevents false positives where a page simply *echoes back* the
    submitted value (e.g. "You searched for: ../../../etc/passwd" or
    "No results for: <?php ..."), which would otherwise look like the
    payload succeeded in reading that content.
    """
    if not payload:
        return response_text

    cleaned = response_text.replace(payload, "")

    # Also strip URL-encoded variants of common traversal characters
    variants = [
        payload.replace("/", "%2f").replace("\\", "%5c"),
        payload.replace("/", "%2F").replace("\\", "%5C"),
    ]
    for v in variants:
        if v in cleaned:
            cleaned = cleaned.replace(v, "")

    return cleaned


def get_timing_baseline(session: requests.Session, url: str, config: Dict,
                        samples: int = 3) -> float:
    """
    Measure normal (unmodified) response time for a URL, used to detect
    time-based SQL injection without false-flagging naturally slow servers.
    Returns the average response time in seconds.

    Bug fix: default samples raised from 1 to 3. A single timing sample
    is noisy — one unlucky slow response would make the baseline too high,
    causing every subsequent sleep-payload probe to look like it didn't work
    (false negative). Averaging 3 samples gives a stable baseline.
    """
    import time
    times = []
    for _ in range(max(samples, 1)):
        try:
            start = time.time()
            session.get(url, timeout=config.get("request_timeout", 15))
            times.append(time.time() - start)
        except Exception:
            times.append(0.0)
    return sum(times) / len(times) if times else 0.0


# ── Response similarity comparison ────────────────────────────────────────────
#
# Used to replace length-only comparisons (which false-positive constantly
# on dynamic pages — timestamps, CSRF tokens, ad slots, randomized ordering
# all change response LENGTH without changing the page's actual MEANING)
# with genuine content-similarity analysis.

@dataclass
class ResponseDiff:
    """Structured result of comparing two HTTP responses."""
    similarity_ratio:   float            # 0.0-1.0, SequenceMatcher ratio on normalized text
    length_a:            int
    length_b:            int
    length_diff:          int
    length_diff_pct:     float
    keyword_diff:        List[str] = field(default_factory=list)   # words in A not in B or vice versa
    record_count_a:      int = 0     # heuristic count of repeated row-like structures
    record_count_b:      int = 0

    def is_meaningfully_different(self, similarity_threshold: float = 0.93) -> bool:
        """
        True if the two responses differ enough to suggest a genuinely
        different result set / page state, not just incidental dynamic
        content (timestamps, nonces, ad slots typically keep similarity
        above ~0.97 even though length can shift by hundreds of chars).
        """
        return self.similarity_ratio < similarity_threshold


def normalize_for_comparison(text: str) -> str:
    """
    Strip high-churn dynamic content that would otherwise dominate a diff
    and mask the actual structural difference we care about: timestamps,
    CSRF/nonce tokens, and session-like hex/base64 blobs.
    """
    import re
    text = re.sub(r'\b\d{1,2}:\d{2}(:\d{2})?\s*(AM|PM|am|pm)?\b', '', text)          # times
    text = re.sub(r'\b(19|20)\d{2}-\d{2}-\d{2}\b', '', text)                          # ISO dates
    text = re.sub(r'(?:csrf|token|nonce)["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]{8,}', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\b[A-Fa-f0-9]{32,}\b', '', text)                                  # hex blobs (session ids, hashes)
    return text


def compare_responses(text_a: str, text_b: str) -> ResponseDiff:
    """
    Compare two HTTP response bodies using normalized content similarity
    (difflib SequenceMatcher) rather than raw length — this is the
    "response similarity comparison" required for accurate boolean-based
    SQLi confirmation, replacing a naive `len(a) != len(b)` check that
    false-positives on any page with dynamic content.
    """
    norm_a = normalize_for_comparison(text_a)
    norm_b = normalize_for_comparison(text_b)

    ratio = SequenceMatcher(None, norm_a, norm_b).ratio()

    words_a = set(re.findall(r'\b[a-zA-Z]{3,}\b', norm_a.lower()))
    words_b = set(re.findall(r'\b[a-zA-Z]{3,}\b', norm_b.lower()))
    keyword_diff = sorted((words_a ^ words_b))[:20]   # symmetric difference, capped

    # Heuristic "record count": count of <tr>, <li>, or repeated div/card-like
    # blocks — a SQLi returning extra/fewer rows often changes this even
    # when overall text similarity is otherwise close.
    record_count_a = len(re.findall(r'<tr[\s>]|<li[\s>]', text_a, re.IGNORECASE))
    record_count_b = len(re.findall(r'<tr[\s>]|<li[\s>]', text_b, re.IGNORECASE))

    len_a, len_b = len(text_a), len(text_b)
    diff = abs(len_a - len_b)
    pct = (diff / max(len_a, len_b, 1)) * 100

    return ResponseDiff(
        similarity_ratio  = ratio,
        length_a          = len_a,
        length_b          = len_b,
        length_diff       = diff,
        length_diff_pct   = round(pct, 1),
        keyword_diff      = keyword_diff,
        record_count_a    = record_count_a,
        record_count_b    = record_count_b,
    )

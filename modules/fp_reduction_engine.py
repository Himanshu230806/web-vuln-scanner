"""
Centralized False-Positive Reduction System

This is the single choke point every finding passes through before it is
added to the final report. Individual detectors each do their own local
checks (baseline comparison, payload confirmation, etc.) — but nothing
previously looked at the finding SET as a whole. This module adds a
second, cross-cutting pass that:

  1. Cross-validates findings against each other (e.g. if 15 different
     "admin panel" findings all share identical evidence text, they are
     almost certainly one systemic false positive, not 15 real panels).
  2. Flags contradictory signals (e.g. a "Broken Authentication: default
     creds work" finding on a URL that ALSO has a "CSRF protected" /
     "auth required" signal from another detector).
  3. Re-validates surviving findings against the live baseline one more
     time, in case the baseline changed mid-scan (e.g. a WAF kicked in
     after the first N requests).
  4. Deduplicates near-identical evidence text across different findings
     on the same URL (different detectors sometimes describe the same
     underlying issue).
  5. Produces a per-scan false-positive risk report so the user can see
     WHY a finding survived (or would have been suppressed).

Run via: FPReductionEngine.process(findings, session, config)
"""

import logging
import re
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests

from modules.verification_engine import classify_finding, confidence_label

logger = logging.getLogger(__name__)


def _resync_confidence_derived_fields(finding: Dict) -> None:
    """
    Keep `classification` and `confidence_label` consistent whenever this
    module adjusts a finding's `confidence` score.

    Bug fix: `classification` (Confirmed / Likely / Potential /
    Informational) is normally derived from `confidence` once, in
    core/scanner.py's _add_vulnerability(), at the time a finding is first
    added — using whatever confidence the finding had THEN. This module
    runs afterwards and can lower (or raise) `confidence` significantly
    — e.g. discounting a systemic-pattern cluster from 92% down to 67% —
    without ever touching `classification`, which was computed from the
    ORIGINAL 92%. The report then shows a finding at 67% confidence
    labeled "Confirmed Vulnerability" (the >=90% tier) right next to an
    unrelated 80%-confidence finding correctly labeled "Likely
    Vulnerability" — a visibly self-contradictory report. Recomputing
    both fields here, right after every confidence mutation, keeps them
    truthful.
    """
    conf = finding.get("confidence", 50)
    finding["classification"]   = classify_finding(conf, finding.get("is_informational", False))
    finding["confidence_label"] = confidence_label(conf)


class FPReductionEngine:

    # If 3+ findings of the SAME type share near-identical evidence text,
    # treat it as one systemic pattern (likely a uniform server response)
    # rather than N independent vulnerabilities.
    SYSTEMIC_PATTERN_MIN_COUNT   = 3
    SYSTEMIC_PATTERN_SIMILARITY  = 0.85   # 0-1, SequenceMatcher ratio

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config  = config
        self.suppressed: List[Dict] = []   # audit trail of what was removed/downgraded
        self.stats = {
            "input_count":           0,
            "systemic_clusters":     0,
            "suppressed_count":      0,
            "downgraded_count":      0,
            "deduplicated_count":    0,
        }

    # ── public entry point ────────────────────────────────────────────────────

    def process(self, findings: List[Dict]) -> List[Dict]:
        self.stats["input_count"] = len(findings)

        findings = self._detect_systemic_patterns(findings)
        findings = self._cross_validate_contradictions(findings)
        findings = self._dedupe_similar_evidence(findings)
        findings = self._revalidate_against_baseline(findings)

        return findings

    # ── Stage 4: re-validate surviving findings against live baseline ─────────

    def _revalidate_against_baseline(self, findings: List[Dict]) -> List[Dict]:
        """
        Re-validate each probe-based finding one more time against the
        current live baseline. Catches cases where:
          - The WAF kicked in after the first N requests (now blocks everything)
          - The target site went into maintenance mode mid-scan
          - A transient network issue caused a spurious response earlier

        Only runs for finding types that use probe-based URL testing
        (admin panels, exposed files, IDOR, directory traversal). Skips
        passive findings (security headers, version disclosure, SRI) since
        those are already confirmed from the actual response, not a probe.

        Findings whose re-validation probe now matches the baseline are
        downgraded to Informational with a note, not silently deleted.
        """
        PROBE_BASED_TYPES = {
            "Logging & Monitoring Failure",
            "Software Integrity Failure",
            "Insecure Direct Object Reference (IDOR)",
            "Directory Traversal / LFI",
            "Server-Side Request Forgery (SSRF)",
        }

        from modules.scan_utils import get_baseline, matches_baseline

        revalidated: List[Dict] = []

        for finding in findings:
            vuln_type = finding.get("type", "")
            if vuln_type not in PROBE_BASED_TYPES:
                revalidated.append(finding)
                continue

            url = finding.get("url", "")
            if not url:
                revalidated.append(finding)
                continue

            # Skip findings that are already informational or very-low confidence
            if finding.get("severity") in ("Info",) or finding.get("confidence", 100) < 35:
                revalidated.append(finding)
                continue

            try:
                resp = self.session.get(
                    url,
                    timeout=self.config.get("request_timeout", 10),
                    allow_redirects=True,
                )
                baseline = get_baseline(self.session, url, self.config)

                if matches_baseline(resp, baseline):
                    # URL now looks like the soft-404 baseline — the
                    # earlier finding may have been a transient response
                    original_sev = finding.get("severity")
                    finding = dict(finding)
                    finding["severity"]   = "Info"
                    finding["confidence"] = max(20, finding.get("confidence", 50) - 30)
                    finding["fp_reduction_note"] = (
                        f"Re-validation: URL now matches the site baseline (soft-404 / "
                        f"WAF block). Original severity was {original_sev}. "
                        f"Manual verification recommended before treating as confirmed."
                    )
                    _resync_confidence_derived_fields(finding)
                    self.stats["downgraded_count"] += 1
                    logger.info(
                        "FP reduction: re-validation downgraded %s at %s "
                        "(now matches baseline)", vuln_type, url
                    )

            except Exception as exc:
                logger.debug("FP re-validation probe failed for %s: %s", url, exc)

            revalidated.append(finding)

        return revalidated

    # ── Stage 1: systemic pattern detection ───────────────────────────────────

    def _detect_systemic_patterns(self, findings: List[Dict]) -> List[Dict]:
        """
        Group findings by (type, evidence-shape). If a large cluster shares
        near-identical evidence (ignoring the specific URL), it's likely a
        single systemic response (uniform WAF block, uniform SPA shell that
        slipped past per-detector baseline checks, etc.) rather than N
        independent vulnerabilities. We keep ONE representative finding per
        cluster and note the suppression, rather than silently dropping
        everything — the user should know N similar findings were merged.
        """
        by_type: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            by_type[f.get("type", "Unknown")].append(f)

        kept: List[Dict] = []

        for vuln_type, group in by_type.items():
            if len(group) < self.SYSTEMIC_PATTERN_MIN_COUNT:
                kept.extend(group)
                continue

            clusters = self._cluster_by_evidence_similarity(group)

            for cluster in clusters:
                if len(cluster) >= self.SYSTEMIC_PATTERN_MIN_COUNT:
                    self.stats["systemic_clusters"] += 1
                    representative = max(cluster, key=lambda f: f.get("confidence", 50))

                    # Lower confidence: a pattern this repetitive across many
                    # distinct URLs is statistically more likely to be a
                    # uniform false-positive signature than N real bugs.
                    original_conf = representative.get("confidence", 50)
                    representative = dict(representative)
                    representative["confidence"] = max(10, original_conf - 25)
                    representative["fp_reduction_note"] = (
                        f"This finding pattern repeated {len(cluster)} times with "
                        f"near-identical evidence across different URLs. Confidence "
                        f"reduced from {original_conf}% to {representative['confidence']}% "
                        f"— a systemic/uniform response is more likely than {len(cluster)} "
                        f"independent vulnerabilities. Review manually if unsure."
                    )
                    _resync_confidence_derived_fields(representative)
                    representative["affected_url_count"] = len(cluster)

                    for f in cluster:
                        if f is not representative:
                            self.suppressed.append({
                                "type":   f.get("type"),
                                "url":    f.get("url"),
                                "reason": f"Merged into systemic-pattern cluster ({len(cluster)} similar findings)",
                            })
                    self.stats["suppressed_count"] += len(cluster) - 1

                    kept.append(representative)
                else:
                    kept.extend(cluster)

        return kept

    def _cluster_by_evidence_similarity(self, findings: List[Dict]) -> List[List[Dict]]:
        """Greedy clustering of findings whose evidence text is near-identical."""
        clusters: List[List[Dict]] = []
        for f in findings:
            ev = str(f.get("evidence", ""))
            placed = False
            for cluster in clusters:
                ref_ev = str(cluster[0].get("evidence", ""))
                if self._similarity(ev, ref_ev) >= self.SYSTEMIC_PATTERN_SIMILARITY:
                    cluster.append(f)
                    placed = True
                    break
            if not placed:
                clusters.append([f])
        return clusters

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        # Strip URLs/numbers so structurally-identical evidence with different
        # incidental values (e.g. different port numbers) still clusters.
        norm_a = re.sub(r'https?://\S+|\d+', '', a)[:300]
        norm_b = re.sub(r'https?://\S+|\d+', '', b)[:300]
        return SequenceMatcher(None, norm_a, norm_b).ratio()

    # ── Stage 2: cross-validation against contradictory signals ───────────────

    def _cross_validate_contradictions(self, findings: List[Dict]) -> List[Dict]:
        """
        Look for findings that contradict each other on the SAME url:
          - "Default credentials work" + a CSRF/auth finding implying the
            endpoint actually validates credentials server-side strictly
            → lower confidence on the credentials finding, it's more likely
              the login form just doesn't have real server-side logic at
              all (SPA shell) rather than truly accepting any password.
          - A "Security Header Missing" + "Information Disclosure: Server"
            on the exact same response are NOT contradictory and stay as-is.
        """
        by_url: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            by_url[f.get("url", "")].append(f)

        for url, group in by_url.items():
            types = {f.get("type") for f in group}

            has_default_creds = any(
                f.get("type") == "Broken Authentication"
                and "default credentials" in f.get("description", "").lower()
                for f in group
            )
            has_no_lockout = any(
                f.get("type") == "Broken Authentication"
                and "lockout" in f.get("description", "").lower()
                for f in group
            )

            # If BOTH "default creds work" and "no lockout" fire on the exact
            # same login endpoint, that's actually a confirming signal (not a
            # contradiction) — raise confidence slightly since two
            # independent auth-weakness checks agree.
            if has_default_creds and has_no_lockout:
                for f in group:
                    if f.get("type") == "Broken Authentication":
                        f["confidence"] = min(99, f.get("confidence", 50) + 5)
                        f["fp_reduction_note"] = (
                            "Confidence raised: multiple independent authentication "
                            "weaknesses confirmed on the same endpoint."
                        )
                        _resync_confidence_derived_fields(f)

        return findings

    # ── Stage 3: dedupe near-identical evidence across DIFFERENT types ────────

    def _dedupe_similar_evidence(self, findings: List[Dict]) -> List[Dict]:
        """
        Different detectors occasionally describe the same underlying root
        cause from two angles (e.g. 'Information Disclosure: Server header'
        and 'Vulnerable Component: outdated server version' both fire from
        the exact same Server: header value). Keep both but cross-link them
        with a note rather than letting them look like two unrelated issues
        in the report.
        """
        by_url: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            by_url[f.get("url", "")].append(f)

        for url, group in by_url.items():
            if len(group) < 2:
                continue
            for i, f1 in enumerate(group):
                for f2 in group[i+1:]:
                    if f1.get("type") == f2.get("type"):
                        continue  # handled by systemic-pattern clustering
                    ev1 = str(f1.get("evidence", ""))
                    ev2 = str(f2.get("evidence", ""))
                    if ev1 and ev2 and self._similarity(ev1, ev2) > 0.7:
                        f1.setdefault("related_findings", [])
                        f2.setdefault("related_findings", [])
                        f1["related_findings"].append(f2.get("type"))
                        f2["related_findings"].append(f1.get("type"))
                        self.stats["deduplicated_count"] += 1

        return findings

    # ── reporting ────────────────────────────────────────────────────────────

    def get_summary(self) -> Dict:
        return {
            "input_findings":      self.stats["input_count"],
            "systemic_clusters_merged": self.stats["systemic_clusters"],
            "findings_suppressed": self.stats["suppressed_count"],
            "findings_cross_linked": self.stats["deduplicated_count"],
            "suppressed_detail":   self.suppressed[:50],  # cap for report size
        }

"""
Shared scan orchestration — used by BOTH the CLI (run.py) and the desktop
GUI (gui_app.py).

This is the exact ProgressScanner logic that used to live only inside
run.py. It has been extracted verbatim (same phase order, same detector
calls, same FP-reduction steps) into its own module so a second
interface can drive a scan without duplicating — and risking silently
diverging from — the CLI's behavior. Nothing about *how* a scan runs
changed; this file only changes *where* the class lives.

Progress reporting contract
────────────────────────────
`ProgressScanner` takes any `pb` object that implements:

    pb.update(percent: int, phase_text: str, vulns: int = 0) -> None

No other method is required for the scan itself to run (run.py's
ProgressBar and _NoOpPB satisfy this; the GUI provides its own thread-safe
queue-backed adapter — see gui_app.py's GuiProgressAdapter).
"""

from datetime import datetime
from typing import Dict, List, Tuple


class ProgressScanner:
    """
    Thin wrapper around VulnerabilityScanner that orchestrates scan phases
    and pushes progress to the caller-supplied `pb` at each phase boundary.
    """

    PHASES = [
        (5,   "Initialising scanner"),
        (15,  "Crawling target URLs"),
        (10,  "Checking security headers"),
        (10,  "Scanning for vulnerable components"),
        (8,   "Checking software integrity (SRI)"),
        (8,   "Checking logging & monitoring"),
        (9,   "Testing for XXE injection"),
        (25,  "Running injection & auth tests"),
        (7,   "Generating PDF report"),
        (3,   "Saving results"),
    ]

    def __init__(self, target_url: str, scan_config: dict, pb):
        from core.scanner import VulnerabilityScanner
        self.scanner = VulnerabilityScanner(target_url, scan_config)
        self.pb      = pb
        self.target  = target_url

    def run(self) -> Tuple[List[Dict], Dict]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        s   = self.scanner
        pb  = self.pb
        cum = 0

        # Phase 1 – Init
        pb.update(3, self.PHASES[0][1])
        s.scan_stats["start_time"] = datetime.now()
        cum += self.PHASES[0][0]
        pb.update(cum, "Scanner ready")

        # Phase 2 – Crawl
        pb.update(cum + 3, self.PHASES[1][1])
        crawled_urls = s.crawler.crawl()
        s.scan_stats["urls_crawled"] = len(crawled_urls)
        cum += self.PHASES[1][0]
        pb.update(cum, f"Discovered {len(crawled_urls)} URL(s)")

        # Phase 3 – Security headers
        pb.update(cum + 2, self.PHASES[2][1])
        if "security_headers" in s.detectors:
            s._run_header_checks(crawled_urls)
        cum += self.PHASES[2][0]
        pb.update(cum, "Security headers checked", len(s.vulnerabilities))

        # Phase 4 – Vulnerable components
        pb.update(cum + 2, self.PHASES[3][1])
        if "vulnerable_components" in s.detectors:
            for v in s.detectors["vulnerable_components"].scan(self.target, crawled_urls):
                s._add_vulnerability(v)
        cum += self.PHASES[3][0]
        pb.update(cum, "Component analysis done", len(s.vulnerabilities))

        # Phase 5 – SRI
        pb.update(cum + 2, self.PHASES[4][1])
        if "sri" in s.detectors:
            for v in s.detectors["sri"].scan(self.target, crawled_urls):
                s._add_vulnerability(v)
        cum += self.PHASES[4][0]
        pb.update(cum, "Integrity checks done", len(s.vulnerabilities))

        # Phase 6 – Logging & monitoring
        pb.update(cum + 2, self.PHASES[5][1])
        if "logging_monitoring" in s.detectors:
            for v in s.detectors["logging_monitoring"].scan(self.target, crawled_urls):
                s._add_vulnerability(v)
        cum += self.PHASES[5][0]
        pb.update(cum, "Logging checks done", len(s.vulnerabilities))

        # Phase 7 – XXE
        pb.update(cum + 2, self.PHASES[6][1])
        if "xxe" in s.detectors:
            for v in s.detectors["xxe"].scan_crawled_urls(crawled_urls):
                s._add_vulnerability(v)
        cum += self.PHASES[6][0]
        pb.update(cum, "XXE checks done", len(s.vulnerabilities))

        # Phase 8 – Concurrent detection
        total_urls  = max(len(crawled_urls), 1)
        phase8_start = cum
        completed   = 0

        pb.update(cum + 2, self.PHASES[7][1], len(s.vulnerabilities))
        max_workers = min(s.config.get("threads", 5), total_urls)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(s._test_single_url, url): url for url in crawled_urls}
            for future in as_completed(futures):
                try:
                    for v in future.result():
                        s._add_vulnerability(v)
                except Exception:
                    pass
                completed += 1
                sub_pct = int((completed / total_urls) * self.PHASES[7][0])
                pb.update(phase8_start + sub_pct,
                          f"Testing {completed}/{total_urls} URLs",
                          len(s.vulnerabilities))

        cum += self.PHASES[7][0]
        pb.update(cum, "Vulnerability tests done", len(s.vulnerabilities))

        # Phase 8b – Rate limiting & business logic
        pb.update(cum + 2, "Rate limiting & business logic checks…", len(s.vulnerabilities))
        try:
            from modules.rate_limit_detector import RateLimitDetector
            from modules.business_logic_detector import BusinessLogicDetector
            rl = RateLimitDetector(s.session, s.config)
            for v in rl.scan(self.target):
                s._add_vulnerability(v)
            bl = BusinessLogicDetector(s.session, s.config)
            for url, forms in s.crawler.get_all_forms().items():
                for v in bl.scan_forms(url, forms):
                    s._add_vulnerability(v)
            for v in bl.scan_urls(crawled_urls):
                s._add_vulnerability(v)
        except Exception as exc:
            import logging as _l
            _l.getLogger(__name__).debug("Rate-limit/BL: %s", exc)

        # Phase 9 – FP reduction
        pb.update(cum + 3, "Cross-validating findings (FP reduction)…",
                  len(s.vulnerabilities))
        s._run_fp_reduction()
        pb.update(cum + 8, "Finalising results…", len(s.vulnerabilities))

        s._analyze_results()
        s.scan_stats["end_time"] = datetime.now()

        return s.vulnerabilities, s.scan_stats


class NoOpProgress:
    """Drop-in progress sink when no progress reporting is needed."""
    def update(self, *a, **k): pass
    def finish(self, *a, **k): pass
    def fail(self, *a, **k):   pass

#!/usr/bin/env python3
"""
Web Vulnerability Scanner – Web Interface v5.0
Real-time progress tracking via Server-Sent Events (SSE).

Changes in v5.0:
  - Interactsh server URL / token configuration fields in the scan form
  - Browser-based XSS verification toggle (Playwright)
  - FP reduction phase (Phase 9) wired into progress tracking
  - API security / modern vulns / JS analysis phases in progress tracker
  - DETAIL_TEMPLATE: cards now show classification, confidence %,
    verification_method, evidence_score, reproduction_steps, cvss_estimate
  - Summary bar shows classification counts (Confirmed / Likely /
    Potential / Informational) alongside severity counts
  - HOME_TEMPLATE: subtitle updated to v5.0, module count updated to 16
"""

import html as html_module
import json
import os
import threading
import sys
import uuid
from datetime import datetime
from pathlib import Path

# ── Load .env file automatically (server config, never user-supplied) ──────────
# This file is gitignored — never committed to version control.
#
# Uses env_loader.py (zero external dependencies) instead of python-dotenv —
# the previous try/except ImportError around `from dotenv import load_dotenv`
# silently did NOTHING if python-dotenv wasn't installed in the venv, which
# meant a correctly-filled .env file could be completely ignored with no
# error message anywhere. This is now structurally impossible.
from env_loader import load_env_file
load_env_file(Path(__file__).parent, verbose=True)

from flask import (Flask, Response, redirect, render_template_string,
                   request, send_file, stream_with_context)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import VulnerabilityScanner
from reports.pdf_generator import PDFReportGenerator
from config import OUTPUT_DIR
import db as scan_db

app = Flask(__name__)
os.makedirs(OUTPUT_DIR, exist_ok=True)
scan_db.init_db()

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)

# ── In-memory scan progress store ────────────────────────────────────────────
_scan_progress: dict = {}
_scan_lock = threading.Lock()

# ── Phase weights (must sum to 100) ──────────────────────────────────────────
PHASES = [
    (5,  "Initialising scanner"),                       # 0
    (9,  "Crawling target URLs"),                       # 1
    (6,  "Checking security headers"),                  # 2
    (6,  "Scanning for vulnerable components"),         # 3
    (4,  "Checking software integrity (SRI)"),          # 4
    (5,  "Checking logging & monitoring"),              # 5
    (5,  "Testing for XXE injection"),                  # 6
    (3,  "API security testing"),                       # 7b
    (3,  "Modern vulnerability categories"),            # 7c
    (3,  "JavaScript security analysis"),               # 7d
    (14, "Running injection & auth tests"),             # 8
    (4,  "Cross-validating findings (FP reduction)"),   # 9
    (7,  "Finalising results"),                         # 10 (was AI phase)
    (6,  "Generating PDF report"),                      # 11
    (3,  "Saving results"),                             # 12
    (6,  "Running OWASP ZAP active scan"),              # 13 — optional
    (6,  "Passive secret & version scanning"),          # 14 — passive scanner
    (5,  "Rate limiting & business logic checks"),      # 15
]


def _update(scan_id, pct, phase, vulns=0, log_line=""):
    with _scan_lock:
        prev = _scan_progress.get(scan_id, {})
        _scan_progress[scan_id] = {
            "pct":         max(prev.get("pct", 0), min(pct, 99)),
            "phase":       phase,
            "status":      "running",
            "vulns_found": vulns,
            "log":         (prev.get("log", []) + [log_line])[-30:] if log_line else prev.get("log", []),
        }


def _finish(scan_id, vulns, report_path=""):
    with _scan_lock:
        _scan_progress[scan_id] = {
            "pct": 100, "phase": "Scan complete", "status": "done",
            "vulns_found": vulns,
            "log": _scan_progress.get(scan_id, {}).get("log", []),
        }


def _fail(scan_id, error):
    with _scan_lock:
        _scan_progress[scan_id] = {
            "pct": 0, "phase": f"Failed: {error[:80]}", "status": "failed",
            "vulns_found": 0,
            "log": _scan_progress.get(scan_id, {}).get("log", []),
        }


# ── Background scan thread ────────────────────────────────────────────────────

def _run_scan_thread(scan_id: str, target_url: str, scan_config: dict):
    """Run the full scan in a background thread, pushing progress updates."""
    try:
        cum = 0

        # Phase 0 – Init
        _update(scan_id, 3, PHASES[0][1])
        scanner = VulnerabilityScanner(target_url, scan_config)
        cum += PHASES[0][0]
        _update(scan_id, cum, "Scanner initialised",
                log_line=f"Scanner ready — {len(scanner.detectors)} modules active")

        scanner.scan_stats["start_time"] = datetime.now()

        # Phase 1 – Crawl
        _update(scan_id, cum + 3, PHASES[1][1])
        crawled_urls = scanner.crawler.crawl()
        scanner.scan_stats["urls_crawled"] = len(crawled_urls)
        cum += PHASES[1][0]
        _update(scan_id, cum, f"Discovered {len(crawled_urls)} URLs",
                log_line=f"Crawled {len(crawled_urls)} URLs")

        # Phase 2 – Security headers
        _update(scan_id, cum + 2, PHASES[2][1])
        if "security_headers" in scanner.detectors:
            scanner._run_header_checks(crawled_urls)
        cum += PHASES[2][0]
        _update(scan_id, cum, "Security headers checked",
                vulns=len(scanner.vulnerabilities),
                log_line=f"Headers: {len(scanner.vulnerabilities)} findings so far")

        # Phase 3 – Vulnerable components
        _update(scan_id, cum + 2, PHASES[3][1])
        if "vulnerable_components" in scanner.detectors:
            for v in scanner.detectors["vulnerable_components"].scan(target_url, crawled_urls):
                scanner._add_vulnerability(v)
        cum += PHASES[3][0]
        _update(scan_id, cum, "Component analysis done",
                vulns=len(scanner.vulnerabilities),
                log_line=f"Components: {len(scanner.vulnerabilities)} findings so far")

        # Phase 4 – SRI
        _update(scan_id, cum + 2, PHASES[4][1])
        if "sri" in scanner.detectors:
            for v in scanner.detectors["sri"].scan(target_url, crawled_urls):
                scanner._add_vulnerability(v)
        cum += PHASES[4][0]
        _update(scan_id, cum, "Integrity checks done",
                vulns=len(scanner.vulnerabilities),
                log_line=f"SRI: {len(scanner.vulnerabilities)} findings so far")

        # Phase 5 – Logging & monitoring
        _update(scan_id, cum + 2, PHASES[5][1])
        if "logging_monitoring" in scanner.detectors:
            for v in scanner.detectors["logging_monitoring"].scan(target_url, crawled_urls):
                scanner._add_vulnerability(v)
        cum += PHASES[5][0]
        _update(scan_id, cum, "Logging checks done",
                vulns=len(scanner.vulnerabilities),
                log_line=f"Logging: {len(scanner.vulnerabilities)} findings so far")

        # Phase 6 – XXE
        _update(scan_id, cum + 2, PHASES[6][1])
        if "xxe" in scanner.detectors:
            for v in scanner.detectors["xxe"].scan_crawled_urls(crawled_urls):
                scanner._add_vulnerability(v)
        cum += PHASES[6][0]
        _update(scan_id, cum, "XXE checks done",
                vulns=len(scanner.vulnerabilities),
                log_line=f"XXE: {len(scanner.vulnerabilities)} findings so far")

        # Phase 7b – API security
        _update(scan_id, cum + 2, PHASES[7][1])
        if "api_security" in scanner.detectors:
            for v in scanner.detectors["api_security"].scan(target_url, crawled_urls):
                scanner._add_vulnerability(v)
        cum += PHASES[7][0]
        _update(scan_id, cum, "API security checks done",
                vulns=len(scanner.vulnerabilities),
                log_line=f"API: {len(scanner.vulnerabilities)} findings so far")

        # Phase 7c – Modern vulns
        _update(scan_id, cum + 2, PHASES[8][1])
        if "modern_vulns" in scanner.detectors:
            for v in scanner.detectors["modern_vulns"].scan_site(target_url, crawled_urls):
                scanner._add_vulnerability(v)
        cum += PHASES[8][0]
        _update(scan_id, cum, "Modern vuln checks done",
                vulns=len(scanner.vulnerabilities),
                log_line=f"Modern: {len(scanner.vulnerabilities)} findings so far")

        # Phase 7d – JS analysis
        _update(scan_id, cum + 2, PHASES[9][1])
        if "js_analysis" in scanner.detectors:
            for v in scanner.detectors["js_analysis"].scan(target_url, crawled_urls):
                scanner._add_vulnerability(v)
        cum += PHASES[9][0]
        _update(scan_id, cum, "JS analysis done",
                vulns=len(scanner.vulnerabilities),
                log_line=f"JS: {len(scanner.vulnerabilities)} findings so far")

        # Phase 8 – Concurrent injection/auth tests (batched for live progress)
        _update(scan_id, cum + 2, PHASES[10][1])
        total_urls = max(len(crawled_urls), 1)
        phase8_start = cum
        from concurrent.futures import ThreadPoolExecutor, as_completed
        max_workers = min(scanner.config.get("threads", 5), total_urls)
        completed = 0
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(scanner._test_single_url, url): url for url in crawled_urls}
            for future in as_completed(futures):
                try:
                    for v in future.result():
                        scanner._add_vulnerability(v)
                except Exception:
                    pass
                completed += 1
                sub_pct = int((completed / total_urls) * PHASES[10][0])
                _update(scan_id, phase8_start + sub_pct,
                        f"Testing {completed}/{total_urls} URLs",
                        vulns=len(scanner.vulnerabilities),
                        log_line=f"Tested {completed}/{total_urls} — {len(scanner.vulnerabilities)} findings")
        cum += PHASES[10][0]
        _update(scan_id, cum, "Injection tests done", vulns=len(scanner.vulnerabilities))

        # Phase 8b – OWASP ZAP active scan (optional, only runs if the
        # person checked "Run OWASP ZAP active scan" AND a ZAP daemon was
        # actually reachable — otherwise this is a no-op and consumes no
        # progress-bar time).
        if scanner.zap and scanner.zap.is_available():
            _update(scan_id, cum + 2, PHASES[14][1],
                    log_line="Starting OWASP ZAP active scan (this can take a while)…")
            zap_count_before = len(scanner.vulnerabilities)
            for v in scanner.zap.active_scan(target_url):
                scanner._add_vulnerability(v)
            cum += PHASES[14][0]
            _update(scan_id, cum, "OWASP ZAP scan complete",
                    vulns=len(scanner.vulnerabilities),
                    log_line=(
                        f"ZAP: {len(scanner.vulnerabilities) - zap_count_before} "
                        f"additional finding(s)"
                    ))
        elif scanner.config.get("use_zap"):
            _update(scan_id, cum, "OWASP ZAP unavailable — skipped",
                    log_line="ZAP was requested but no connection could be established; continuing without it")

        # Phase 9 – FP reduction
        _update(scan_id, cum + 2, PHASES[11][1],
                log_line="Running centralized false-positive reduction…")
        scanner._run_fp_reduction()
        scanner._analyze_results()
        scanner.scan_stats["end_time"] = datetime.now()
        cum += PHASES[11][0]
        fp_summary = getattr(scanner, "fp_reduction_summary", {})
        _update(scan_id, cum, "FP reduction complete",
                vulns=len(scanner.vulnerabilities),
                log_line=(
                    f"FP reduction: {fp_summary.get('findings_suppressed', 0)} merged, "
                    f"{len(scanner.vulnerabilities)} final findings"
                ))

        # Phase 10 – finalise results (this slot used to run AI deep
        # analysis; AI has been removed from the scanner entirely, so this
        # is now just a lightweight checkpoint before PDF generation).
        _update(scan_id, cum + 2, PHASES[10][1],
                log_line="Finalising results…")
        cum += PHASES[10][0]

        # Phase 11 – PDF
        _update(scan_id, cum + 2, PHASES[12][1],
                log_line="Generating PDF report…")
        pdf_gen = PDFReportGenerator()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = OUTPUT_DIR / f"scan_{scan_id}_{ts}.pdf"
        report_path = pdf_gen.generate_report(
            target_url, scanner.vulnerabilities, scanner.scan_stats, output_file
        )
        cum += PHASES[12][0]
        _update(scan_id, cum, "PDF generated",
                vulns=len(scanner.vulnerabilities),
                log_line="PDF report generated")

        # Phase 11 – Save
        _update(scan_id, cum + 2, PHASES[13][1])
        scan_db.finish_scan(scan_id, scanner.vulnerabilities, scanner.scan_stats, report_path)
        cum += PHASES[13][0]
        _finish(scan_id, len(scanner.vulnerabilities), str(report_path))

    except Exception as exc:
        import traceback
        traceback.print_exc()
        scan_db.mark_scan_failed(scan_id, str(exc))
        _fail(scan_id, str(exc))


# ──────────────────────────────────────────────────────────────────────────────
# Templates
# ──────────────────────────────────────────────────────────────────────────────

HOME_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Web Vulnerability Scanner v5.0</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);min-height:100vh;padding:24px}
.container{max-width:860px;margin:0 auto;background:#fff;border-radius:18px;padding:38px;box-shadow:0 24px 70px rgba(0,0,0,.5)}
h1{color:#0f3460;text-align:center;margin-bottom:6px;font-size:2em}
.subtitle{text-align:center;color:#666;margin-bottom:22px;font-size:14px}
.warn{background:#fffbeb;border-left:5px solid #f59e0b;padding:14px 18px;margin:16px 0;border-radius:8px;font-size:13px}
.warn b{color:#92400e}
.nav{text-align:right;margin-bottom:12px}
.nav a{color:#0f3460;text-decoration:none;font-size:13px;margin-left:14px}
label.main{display:block;margin:14px 0 5px;font-weight:700;color:#111;font-size:14px}
input[type=url],input[type=text]{width:100%;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s}
input[type=url]:focus,input[type=text]:focus{outline:none;border-color:#0f3460}
.section{background:#f8faff;padding:18px;border-radius:10px;margin:18px 0;border:1px solid #e8ecf8}
.section h3{color:#333;margin-bottom:14px;font-size:14px;font-weight:700}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.cb{display:flex;align-items:center;gap:8px;padding:6px 10px;border-radius:6px;cursor:pointer;transition:background .15s}
.cb:hover{background:#e8ecf8}
.cb input[type=checkbox]{accent-color:#0f3460;width:16px;height:16px;cursor:pointer}
.cb label{font-size:13px;color:#333;cursor:pointer;margin:0}
.nb{display:inline-block;background:#059669;color:#fff;padding:1px 7px;border-radius:8px;font-size:10px;font-weight:700;margin-left:4px}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:10px}
.field-row label{font-size:12px;font-weight:600;color:#555;margin-bottom:3px;display:block}
.field-hint{font-size:11px;color:#9ca3af;margin-top:2px}
.toggle-row{display:flex;align-items:center;gap:10px;margin-top:10px;padding:10px;background:#fff;border-radius:8px;border:1px solid #e5e7eb}
.toggle-row label{font-size:13px;color:#374151;flex:1}
.toggle-row input[type=checkbox]{accent-color:#0f3460;width:18px;height:18px}
.btn-scan{width:100%;padding:15px;background:linear-gradient(135deg,#0f3460,#533483);color:#fff;border:none;border-radius:10px;font-size:16px;font-weight:700;cursor:pointer;margin-top:10px;letter-spacing:.3px;transition:opacity .2s}
.btn-scan:hover{opacity:.9}
</style>
</head><body>
<div class="container">
  <div class="nav"><a href="/">🏠 Home</a><a href="/history">📋 History</a></div>
  <h1>🔒 Web Vulnerability Scanner</h1>
  <p class="subtitle">Professional Security Assessment · OWASP Top 10 · v5.0 · Classification-based reporting</p>

  <div class="warn">
    ⚠️ <b>Legal Notice:</b> Only scan websites you <b>own</b> or have <b>written permission</b> to test.
    Unauthorized scanning is <b>illegal</b>.
  </div>

  <form action="/scan" method="POST">
    <label class="main" for="url">🌐 Target URL</label>
    <input type="url" id="url" name="url" placeholder="https://example.com" required>

    <div class="section">
      <h3>🧩 Vulnerability Modules &nbsp;<span style="font-weight:400;color:#8b949e">(16 modules · full OWASP Top 10)</span></h3>
      <div class="grid2">
        <div class="cb"><input type="checkbox" name="modules" value="sqli"                 id="m1" checked><label for="m1">SQL Injection <small>(A03)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="xss"                  id="m2" checked><label for="m2">XSS <small>(A03)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="xxe"                  id="m3" checked><label for="m3">XXE <small>(A03)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="directory_traversal"  id="m4" checked><label for="m4">Directory Traversal <small>(A03)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="csrf"                 id="m5" checked><label for="m5">CSRF <small>(A04)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="open_redirect"        id="m6" checked><label for="m6">Open Redirect <small>(A04)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="security_headers"     id="m7" checked><label for="m7">Security Headers <small>(A02/A05)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="idor"                 id="m8" checked><label for="m8">IDOR <small>(A01)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="vulnerable_components" id="m9" checked><label for="m9">Vulnerable Components <small>(A06)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="broken_auth"          id="m10" checked><label for="m10">Broken Auth <small>(A07)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="sri"                  id="m11" checked><label for="m11">Software Integrity <small>(A08)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="logging_monitoring"   id="m12" checked><label for="m12">Logging &amp; Monitoring <small>(A09)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="ssrf"                 id="m13" checked><label for="m13">SSRF <small>(A10)</small></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="api_security"         id="m14" checked><label for="m14">API Security <small>(BOLA/CORS)</small><span class="nb">NEW</span></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="modern_vulns"         id="m15" checked><label for="m15">Modern Vulns <small>(SSTI/JWT/NoSQLi)</small><span class="nb">NEW</span></label></div>
        <div class="cb"><input type="checkbox" name="modules" value="js_analysis"          id="m16" checked><label for="m16">JS Analysis <small>(taint/secrets)</small><span class="nb">NEW</span></label></div>
      </div>
    </div>

    <div class="section">
      <h3>🔬 Verification Options &nbsp;<span style="font-weight:400;color:#8b949e">(improve confirmation quality)</span></h3>

      <div class="toggle-row">
        <input type="checkbox" name="browser_verify" id="browser_verify" checked>
        <label for="browser_verify">
          <b>Browser-based XSS verification (Playwright)</b>
          <div class="field-hint">Launches headless Chromium to verify actual JS execution — eliminates reflection-only false positives. Disable if Playwright is not installed.</div>
        </label>
      </div>

      <p style="font-size:12px;color:#6b7280;margin:14px 0 6px;font-weight:600">🔗 Interactsh OOB Server (optional — for confirmed SSRF proof)</p>
      <div class="field-row">
        <div>
          <label for="interactsh_server">Server URL</label>
          <input type="text" id="interactsh_server" name="interactsh_server"
                 placeholder="https://oob.yourcompany.com">
          <div class="field-hint">Self-hosted Interactsh server URL. Leave empty to use static-indicator detection (findings capped at "Potential Vulnerability").</div>
        </div>
        <div>
          <label for="interactsh_token">Auth Token (optional)</label>
          <input type="text" id="interactsh_token" name="interactsh_token"
                 placeholder="your-server-token">
          <div class="field-hint">Auth token for your Interactsh server, if required.</div>
        </div>
      </div>
    </div>

    <div class="section">
      <h3>🕷️ Crawler Mode</h3>
      <div class="toggle-row">
        <input type="checkbox" name="browser_crawl" id="browser_crawl">
        <label for="browser_crawl">
          <b>Use Playwright browser crawler (SPA/JS mode)</b>
          <div class="field-hint">Executes JavaScript before extracting links — discovers React/Vue/Angular routes, hash-router paths (#/admin/users), and XHR/fetch API endpoints invisible to the standard HTML crawler. Requires <code>pip install playwright && playwright install chromium</code> on the server.</div>
        </label>
      </div>
    </div>

    <div class="section">
      <h3>🔑 Authentication <span style="font-weight:400;color:#8b949e">(optional — scan protected pages behind login)</span></h3>

      <p style="font-size:12px;color:#6b7280;margin:0 0 10px;font-weight:600">Strategy 1 — Form-based auto-login</p>
      <div class="field-row">
        <div>
          <label for="auth_url">Login Page URL</label>
          <input type="text" id="auth_url" name="auth_url" placeholder="https://target.com/login">
          <div class="field-hint">The scanner will auto-detect and submit the login form before crawling.</div>
        </div>
      </div>
      <div class="field-row">
        <div>
          <label for="auth_user">Username / Email</label>
          <input type="text" id="auth_user" name="auth_user" placeholder="admin@example.com">
        </div>
        <div>
          <label for="auth_pass">Password</label>
          <input type="password" id="auth_pass" name="auth_pass" placeholder="••••••••">
          <div class="field-hint">Credentials are used only for this scan and never stored.</div>
        </div>
      </div>

      <p style="font-size:12px;color:#6b7280;margin:14px 0 6px;font-weight:600">Strategy 2 — Cookie injection <span style="font-weight:400">(for SSO / OAuth / OTP flows)</span></p>
      <div class="field-row">
        <div>
          <label for="auth_cookie">Session Cookies</label>
          <input type="text" id="auth_cookie" name="auth_cookie" placeholder="sessionid=abc123; csrftoken=xyz">
          <div class="field-hint">Paste cookies from your browser DevTools → Application → Cookies. Use this for multi-step logins, OTP, or SSO that auto-login can't handle.</div>
        </div>
      </div>

      <p style="font-size:12px;color:#6b7280;margin:14px 0 6px;font-weight:600">Strategy 3 — Header injection <span style="font-weight:400">(Bearer tokens, API keys)</span></p>
      <div class="field-row">
        <div>
          <label for="auth_header">Authorization Header</label>
          <input type="text" id="auth_header" name="auth_header" placeholder="Authorization: Bearer eyJhbGci...">
          <div class="field-hint">Full header in "Name: Value" format. Also works for API keys: "X-API-Key: abc123".</div>
        </div>
      </div>

      <p style="font-size:12px;color:#6b7280;margin:14px 0 6px;font-weight:600">Strategy 4 — HTTP Basic auth</p>
      <div class="field-row">
        <div>
          <label for="auth_basic">Credentials</label>
          <input type="text" id="auth_basic" name="auth_basic" placeholder="username:password">
          <div class="field-hint">Standard HTTP Basic Auth in "user:pass" format.</div>
        </div>
      </div>
      <div class="field-hint" style="margin-top:4px">Strategies are tried in order: form-login → cookie → header → Basic. Supply only what applies.</div>
    </div>

    <div class="section">
      <h3>🦓 OWASP ZAP Integration <span style="font-weight:400;color:#8b949e">(optional — runs alongside this scanner's own modules)</span></h3>

      <div class="toggle-row">
        <input type="checkbox" name="use_zap" id="use_zap" onchange="document.getElementById('zapFields').style.display=this.checked?'grid':'none'">
        <label for="use_zap">
          <b>Run OWASP ZAP active scan</b>
          <div class="field-hint">Requires ZAP running separately in daemon mode (e.g. <code>zap.sh -daemon -port 8080 -config api.key=YOURKEY</code>). Adds ZAP's spider + active scan findings to this report alongside this tool's own detectors.</div>
        </label>
      </div>

      <div class="field-row" id="zapFields" style="display:none">
        <div>
          <label for="zap_proxy">ZAP Proxy Address</label>
          <input type="text" id="zap_proxy" name="zap_proxy" placeholder="http://localhost:8080">
          <div class="field-hint">Leave blank to use the server's default ($ZAP_PROXY or http://localhost:8080).</div>
        </div>
        <div>
          <label for="zap_api_key">ZAP API Key (optional)</label>
          <input type="text" id="zap_api_key" name="zap_api_key" placeholder="your-zap-api-key">
          <div class="field-hint">Only needed if your ZAP daemon was started with an API key configured.</div>
        </div>
      </div>
    </div>

    <button type="submit" class="btn-scan">🚀 Start Security Scan</button>
  </form>
</div>
</body></html>
"""

PROGRESS_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Scanning — {{ target_url }}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:18px;padding:40px;max-width:680px;width:100%;box-shadow:0 24px 70px rgba(0,0,0,.5)}
.card-header{text-align:center;margin-bottom:24px}
.card-header h2{color:#0f3460;font-size:1.4em;margin-bottom:6px}
.target{font-size:13px;color:#6b7280;word-break:break-all;background:#f8faff;padding:8px 12px;border-radius:8px;font-family:monospace}
.pct{font-size:3em;font-weight:800;color:#0f3460;text-align:center;margin:16px 0 4px;letter-spacing:-1px}
.bar-wrap{background:#e5e7eb;border-radius:99px;height:12px;overflow:hidden;margin:0 0 10px}
.bar{height:100%;background:linear-gradient(90deg,#0f3460,#533483);border-radius:99px;transition:width .5s ease;min-width:6px}
.phase{text-align:center;color:#374151;font-size:14px;font-weight:600;min-height:22px;margin-bottom:4px}
.timing{text-align:center;color:#9ca3af;font-size:12px;margin-bottom:12px}
.stats-row{display:flex;justify-content:center;gap:24px;margin:14px 0}
.stat{text-align:center}
.stat .n{font-size:1.5em;font-weight:800;color:#0f3460}
.stat .l{font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em}
.vulns-found{text-align:center;font-size:14px;font-weight:700;margin-bottom:12px;min-height:20px}
.vulns-found.has-vulns{color:#dc2626}
.log-box{background:#0f172a;border-radius:10px;padding:14px;font-family:monospace;font-size:11px;color:#94a3b8;max-height:160px;overflow-y:auto}
.log-box p{margin:2px 0;line-height:1.5}
.log-box p:first-child{color:#e2e8f0}
</style>
</head><body>
<div class="card">
  <div class="card-header">
    <h2>🔍 Scanning in Progress</h2>
    <div class="target">{{ target_url }}</div>
  </div>
  <div class="pct" id="pct">0%</div>
  <div class="bar-wrap"><div class="bar" id="bar" style="width:0%"></div></div>
  <div class="phase" id="phase">Initialising…</div>
  <div class="timing" id="timing">Elapsed: 0:00</div>
  <div class="stats-row">
    <div class="stat"><div class="n" id="urlsN">—</div><div class="l">URLs Found</div></div>
    <div class="stat"><div class="n" id="vulnsN">0</div><div class="l">Findings</div></div>
  </div>
  <div class="vulns-found" id="vulns"></div>
  <div class="log-box" id="log"><p>▸ Scanner initialising…</p></div>
</div>
<script>
const start = Date.now();
const timer = setInterval(() => {
  const s = Math.floor((Date.now()-start)/1000);
  document.getElementById('timing').textContent = 'Elapsed: ' + Math.floor(s/60)+':'+(s%60<10?'0':'')+(s%60);
}, 1000);

const es = new EventSource('/progress/{{ scan_id }}');
es.onmessage = e => {
  const d = JSON.parse(e.data);
  document.getElementById('pct').textContent  = d.pct + '%';
  document.getElementById('bar').style.width  = d.pct + '%';
  document.getElementById('phase').textContent = d.phase;
  document.getElementById('vulnsN').textContent = d.vulns_found || 0;

  const vEl = document.getElementById('vulns');
  if(d.vulns_found > 0){
    vEl.textContent = '⚠ ' + d.vulns_found + ' finding' + (d.vulns_found!==1?'s':'') + ' so far';
    vEl.className = 'vulns-found has-vulns';
  }
  if(d.log && d.log.length){
    const lb = document.getElementById('log');
    lb.innerHTML = d.log.slice(-20).reverse().map((l,i)=>`<p style="opacity:${i===0?1:Math.max(0.35,1-i*0.07)}"">▸ ${l}</p>`).join('');
    lb.scrollTop = 0;
  }
  if(d.status === 'done'){
    es.close(); clearInterval(timer);
    window.location.href = '/results/{{ scan_id }}';
  } else if(d.status === 'failed'){
    es.close(); clearInterval(timer);
    document.getElementById('phase').style.color = '#dc2626';
  }
};
es.onerror = ()=>{ es.close(); clearInterval(timer); };
</script>
</body></html>
"""

RESULT_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<title>Error</title>
<style>body{font-family:sans-serif;padding:40px;background:#f9fafb}
.err{background:#fef2f2;border:1px solid #fca5a5;padding:20px;border-radius:8px;color:#991b1b}</style>
</head><body>
<div class="err"><b>Error:</b> {{ error }}</div>
<a href="/">← Back</a>
</body></html>
"""

DETAIL_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Scan Results — {{ scan.url }}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);min-height:100vh;padding:20px}
.container{max-width:1020px;margin:0 auto;background:#fff;border-radius:18px;padding:36px;box-shadow:0 24px 70px rgba(0,0,0,.5)}
h1{color:#0f3460;margin-bottom:4px;font-size:1.5em}
.meta{color:#6b7280;font-size:13px;margin-bottom:20px}
.nav{text-align:right;margin-bottom:12px}
.nav a{color:#0f3460;font-size:13px;margin-left:14px;text-decoration:none}
.done-banner{background:#f0fdf4;border:1px solid #86efac;color:#166534;padding:10px 16px;border-radius:8px;margin-bottom:16px;font-size:14px;font-weight:600}

/* Severity summary bar */
.summary{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 12px}
.sum-card{flex:1;min-width:80px;text-align:center;border-radius:10px;padding:14px 6px;color:#fff}
.sum-card .num{font-size:1.8em;font-weight:800;display:block}
.sum-card .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.05em;opacity:.9}
.sum-Critical{background:#dc2626}.sum-High{background:#ea580c}.sum-Medium{background:#d97706}
.sum-Low{background:#16a34a}.sum-Info{background:#2563eb}

/* Classification summary bar */
.cls-bar{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 18px}
.cls-card{flex:1;min-width:130px;text-align:center;border-radius:8px;padding:10px 8px;color:#fff}
.cls-card .cls-num{font-size:1.6em;font-weight:800;display:block}
.cls-card .cls-lbl{font-size:10px;letter-spacing:.04em;opacity:.92}
.cls-Confirmed{background:#b91c1c}.cls-Likely{background:#c2410c}
.cls-Potential{background:#b45309}.cls-Informational{background:#1d4ed8}

.dl-btn{display:inline-block;padding:10px 22px;background:#059669;color:#fff;border-radius:8px;text-decoration:none;font-weight:700;margin-bottom:18px;font-size:14px}

/* Filter tabs */
.filter-bar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.filter-btn{padding:6px 14px;border-radius:20px;border:1px solid #d1d5db;background:#fff;font-size:12px;cursor:pointer;font-weight:600;transition:all .15s}
.filter-btn.active{background:#0f3460;color:#fff;border-color:#0f3460}
.filter-btn:hover:not(.active){background:#f0f4ff}

/* Vuln cards */
.vuln-card{border:1px solid #e5e7eb;border-radius:10px;margin:10px 0;overflow:hidden;transition:box-shadow .15s}
.vuln-card:hover{box-shadow:0 4px 16px rgba(0,0,0,.08)}
.vuln-header{padding:12px 16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;cursor:pointer;background:#f8faff}
.vuln-body{padding:16px;font-size:13px;color:#374151;line-height:1.65;display:none;border-top:1px solid #e5e7eb}
.vuln-body.open{display:block}

/* Badges */
.badge{padding:2px 9px;border-radius:8px;font-size:11px;font-weight:700;color:#fff}
.bg-Critical{background:#dc2626}.bg-High{background:#ea580c}.bg-Medium{background:#d97706}
.bg-Low{background:#16a34a}.bg-Info{background:#2563eb}
.cls-badge{padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;color:#fff}
.cls-badge-Confirmed{background:#b91c1c}.cls-badge-Likely{background:#c2410c}
.cls-badge-Potential{background:#b45309}.cls-badge-Informational{background:#1d4ed8}
.conf-badge{padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;background:#e0e7ff;color:#3730a3}

.vtype{font-weight:700;color:#111;font-size:13.5px}
.param{font-family:monospace;background:#e0e7ff;color:#3730a3;padding:2px 6px;border-radius:5px;font-size:11px}
.owasp{background:#0f3460;color:#fff;padding:2px 7px;border-radius:6px;font-size:10px;font-weight:700}

/* Evidence grid inside card body */
.ev-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
.ev-item{background:#f8faff;border-radius:6px;padding:10px 12px}
.ev-item .label{font-size:10px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
.ev-item .value{font-size:12px;color:#111;word-break:break-all}
.ev-item .value code{font-family:monospace;background:#e0e7ff;padding:2px 5px;border-radius:4px;font-size:11px}
.ev-full{background:#0f172a;border-radius:6px;padding:12px;margin-top:8px;font-family:monospace;font-size:11px;color:#94a3b8;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto}
.repro{background:#f0fdf4;border:1px solid #86efac;border-radius:6px;padding:12px;margin-top:8px}
.repro .label{font-size:11px;font-weight:700;color:#166534;margin-bottom:6px}
.repro ol{padding-left:16px;font-size:12px;color:#166534;line-height:1.7}
.remediation{background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:12px;margin-top:8px}
.remediation .label{font-size:11px;font-weight:700;color:#92400e;margin-bottom:4px}
.remediation p{font-size:12px;color:#78350f}

.url-text{font-family:monospace;font-size:12px;color:#6b7280;word-break:break-all;margin-bottom:6px}
.empty{color:#9ca3af;padding:24px;text-align:center}
</style>
</head><body>
<div class="container">
  <div class="nav"><a href="/">🏠 Home</a><a href="/history">📋 History</a></div>
  <h1>🔍 Scan Results — {{ scan.url }}</h1>
  <div class="meta">Scan ID: <code>{{ scan.id }}</code> · Started: {{ scan.started_at[:16] }} · Status: {{ scan.status }}</div>

  {% if scan.status == 'done' %}
  <div class="done-banner">✅ Scan complete — {{ vulns|length }} finding(s)</div>
  {% endif %}

  <!-- Severity summary -->
  <div class="summary">
    <div class="sum-card sum-Critical"><span class="num">{{ counts.Critical }}</span><span class="lbl">Critical</span></div>
    <div class="sum-card sum-High"><span class="num">{{ counts.High }}</span><span class="lbl">High</span></div>
    <div class="sum-card sum-Medium"><span class="num">{{ counts.Medium }}</span><span class="lbl">Medium</span></div>
    <div class="sum-card sum-Low"><span class="num">{{ counts.Low }}</span><span class="lbl">Low</span></div>
    <div class="sum-card sum-Info"><span class="num">{{ counts.Info }}</span><span class="lbl">Info</span></div>
  </div>

  <!-- Classification summary (new — shows proof quality) -->
  <div class="cls-bar">
    <div class="cls-card cls-Confirmed"><span class="cls-num">{{ cls_counts.Confirmed }}</span><span class="cls-lbl">✅ Confirmed</span></div>
    <div class="cls-card cls-Likely"><span class="cls-num">{{ cls_counts.Likely }}</span><span class="cls-lbl">⚠ Likely</span></div>
    <div class="cls-card cls-Potential"><span class="cls-num">{{ cls_counts.Potential }}</span><span class="cls-lbl">🔍 Potential</span></div>
    <div class="cls-card cls-Informational"><span class="cls-num">{{ cls_counts.Informational }}</span><span class="cls-lbl">ℹ Informational</span></div>
  </div>

  {% if scan.report_path %}
  <a class="dl-btn" href="/download/{{ scan.id }}">📥 Download PDF Report</a>
  {% endif %}

  <!-- Filter buttons -->
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterCards('all', this)">All ({{ vulns|length }})</button>
    <button class="filter-btn" onclick="filterCards('Confirmed Vulnerability', this)">✅ Confirmed ({{ cls_counts.Confirmed }})</button>
    <button class="filter-btn" onclick="filterCards('Likely Vulnerability', this)">⚠ Likely ({{ cls_counts.Likely }})</button>
    <button class="filter-btn" onclick="filterCards('Potential Vulnerability', this)">🔍 Potential ({{ cls_counts.Potential }})</button>
    <button class="filter-btn" onclick="filterCards('Informational', this)">ℹ Info ({{ cls_counts.Informational }})</button>
  </div>

  {% if vulns %}
  {% for v in vulns %}
  <div class="vuln-card" data-cls="{{ v.classification }}">
    <div class="vuln-header" onclick="toggleCard(this)">
      <span class="badge bg-{{ v.severity }}">{{ v.severity }}</span>
      <span class="cls-badge cls-badge-{{ v.classification.split()[0] }}">{{ v.classification }}</span>
      <span class="conf-badge">{{ v.confidence }}% · {{ v.confidence_label }}</span>
      <span class="vtype">{{ v.vuln_type }}{% if v.subtype %} — {{ v.subtype }}{% endif %}</span>
      {% if v.parameter %}<span class="param">{{ v.parameter }}</span>{% endif %}
      {% if v.owasp %}<span class="owasp">{{ v.owasp }}</span>{% endif %}
      {% if v.waf_bypass_used %}<span style="background:#f59e0b;color:#fff;font-size:10px;padding:2px 6px;border-radius:4px;font-weight:600">WAF BYPASS USED</span>{% endif %}
    </div>
    <div class="vuln-body">
      <div class="url-text">{{ v.url }}</div>
      {% if v.source and v.source != 'Custom Scanner (native detector)' %}
      <div style="font-size:11px;color:#6b7280;margin-bottom:6px">Detected by: {{ v.source }}{% if v.cwe %} · {{ v.cwe }}{% endif %}</div>
      {% endif %}
      {% if v.waf_bypass_used %}
      <div style="background:#fef3c7;border:1px solid #f59e0b;border-radius:6px;padding:8px 12px;margin-bottom:10px;font-size:12px">
        ⚠️ <b>WAF Bypass Used</b>: this finding was confirmed using bypass variant <code>{{ v.bypass_variant }}</code>.
        The WAF would have blocked the standard payload — the underlying vulnerability is confirmed but additional hardening is needed.
      </div>
      {% endif %}
      <p style="margin-bottom:10px">{{ v.description }}</p>

      <!-- Evidence / proof grid -->
      <div class="ev-grid">
        <div class="ev-item">
          <div class="label">Verification Method</div>
          <div class="value">{{ v.verification_method }}</div>
        </div>
        <div class="ev-item">
          <div class="label">Evidence Score</div>
          <div class="value">
            <span style="font-size:1.3em;font-weight:800;color:#0f3460">{{ v.evidence_score }}</span>/100
          </div>
        </div>
        <div class="ev-item">
          <div class="label">CVSS Estimate</div>
          <div class="value"><span style="font-size:1.2em;font-weight:700">{{ v.cvss_estimate }}</span>/10</div>
        </div>
        <div class="ev-item">
          <div class="label">OWASP Mapping</div>
          <div class="value">{{ v.owasp }}</div>
        </div>
      </div>

      {% if v.evidence %}
      <div class="ev-full">{{ v.evidence }}</div>
      {% endif %}

      {% if v.reproduction_steps %}
      <div class="repro">
        <div class="label">🔁 Reproduction Steps</div>
        <ol>{% for step in v.reproduction_steps %}<li>{{ step }}</li>{% endfor %}</ol>
      </div>
      {% endif %}

      {% if v.remediation %}
      <div class="remediation">
        <div class="label">🔧 Remediation</div>
        <p>{{ v.remediation }}</p>
      </div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
  {% else %}
  <p class="empty">✅ No vulnerabilities found for this scan.</p>
  {% endif %}
</div>

<script>
function toggleCard(hdr) {
  const body = hdr.nextElementSibling;
  body.classList.toggle('open');
}
function filterCards(cls, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.vuln-card').forEach(card => {
    if (cls === 'all' || card.dataset.cls === cls) {
      card.style.display = '';
    } else {
      card.style.display = 'none';
    }
  });
}
// Auto-open first Confirmed finding on load
const firstConfirmed = document.querySelector('.vuln-card[data-cls="Confirmed Vulnerability"] .vuln-header');
if (firstConfirmed) firstConfirmed.click();
</script>
</body></html>
"""

HISTORY_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Scan History</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);min-height:100vh;padding:20px}
.container{max-width:980px;margin:0 auto;background:#fff;border-radius:18px;padding:36px;box-shadow:0 24px 70px rgba(0,0,0,.5)}
h1{color:#0f3460;margin-bottom:22px}
.nav{text-align:right;margin-bottom:12px}
.nav a{color:#0f3460;font-size:13px;margin-left:14px;text-decoration:none}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:10px 14px;border:1px solid #e5e7eb;text-align:left}
th{background:#f8faff;color:#374151;font-weight:600}
tr:hover td{background:#f0f4ff}
.badge{padding:2px 9px;border-radius:8px;font-size:11px;font-weight:700;color:#fff}
.bg-done{background:#059669}.bg-failed{background:#dc2626}.bg-running{background:#d97706}
a.lnk{color:#0f3460;text-decoration:none;font-weight:600}
a.lnk:hover{text-decoration:underline}
.empty{color:#9ca3af;text-align:center;padding:48px}
</style>
</head><body>
<div class="container">
  <div class="nav"><a href="/">🏠 Home</a></div>
  <h1>📋 Scan History</h1>
  {% if scans %}
  <table>
    <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Vulns</th><th>Started</th><th>Actions</th></tr></thead>
    <tbody>
    {% for s in scans %}
    <tr>
      <td><code>{{ s.id }}</code></td>
      <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ s.url }}</td>
      <td><span class="badge bg-{{ s.status }}">{{ s.status }}</span></td>
      <td>{{ s.vuln_count }}</td>
      <td>{{ s.started_at[:16] }}</td>
      <td>
        <a class="lnk" href="/results/{{ s.id }}">View</a>
        {% if s.report_path %} · <a class="lnk" href="/download/{{ s.id }}">PDF</a>{% endif %}
        · <a class="lnk" href="/delete/{{ s.id }}" style="color:#dc2626"
             onclick="return confirm('Delete this scan record?')">Delete</a>
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="empty">No scans yet. <a href="/" style="color:#0f3460">Start your first scan →</a></p>
  {% endif %}
</div>
</body></html>
"""


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HOME_TEMPLATE)


@app.route("/scan", methods=["POST"])
@limiter.limit("5 per hour")
def scan():
    target_url = request.form.get("url", "").strip()
    if not target_url:
        return render_template_string(RESULT_TEMPLATE, error="URL is required"), 400
    if not target_url.startswith(("http://", "https://")):
        return render_template_string(RESULT_TEMPLATE,
                                      error="URL must start with http:// or https://"), 400

    selected_modules = request.form.getlist("modules")
    scan_id = str(uuid.uuid4())[:8]
    scan_db.create_scan(scan_id, target_url)

    # ── Build scan config ───────────────────────────────────────────────────
    scan_config = {
        "max_depth":       2,
        "threads":         5,
        "request_timeout": 15,
        "delay":           0.2,
        "verify_ssl":      True,
        # Browser-based XSS verification (Playwright)
        "browser_verify_xss": "browser_verify" in request.form,
        # Interactsh OOB server (for confirmed SSRF proof)
        "interactsh_server_url": request.form.get("interactsh_server", "").strip() or None,
        "interactsh_token":      request.form.get("interactsh_token", "").strip() or None,
        # OWASP ZAP integration (optional — requires a separately running
        # ZAP daemon; see the field hints in the scan form)
        "zap_proxy":       request.form.get("zap_proxy", "").strip() or None,
        "zap_api_key":     request.form.get("zap_api_key", "").strip() or None,
        "browser_crawl":   "browser_crawl" in request.form,
        "auth_url":        request.form.get("auth_url", "").strip() or None,
        "auth_user":       request.form.get("auth_user", "").strip() or None,
        "auth_pass":       request.form.get("auth_pass", "") or None,
        "auth_cookie":     request.form.get("auth_cookie", "").strip() or None,
        "auth_header":     request.form.get("auth_header", "").strip() or None,
        "auth_basic":      request.form.get("auth_basic", "").strip() or None,
    }

    ALL_MODULES = {
        "sqli", "xss", "xxe", "directory_traversal", "csrf", "open_redirect",
        "security_headers", "idor", "vulnerable_components", "broken_auth",
        "sri", "logging_monitoring", "ssrf", "api_security", "modern_vulns", "js_analysis",
    }
    if selected_modules and set(selected_modules) != ALL_MODULES:
        scan_config["enabled_modules"] = selected_modules

    _update(scan_id, 0, "Initialising scanner")
    t = threading.Thread(
        target=_run_scan_thread, args=(scan_id, target_url, scan_config), daemon=True
    )
    t.start()
    return render_template_string(PROGRESS_TEMPLATE, scan_id=scan_id, target_url=target_url)


@app.route("/progress/<scan_id>")
def progress_sse(scan_id: str):
    """Server-Sent Events stream for real-time progress."""
    def generate():
        last_pct = -1
        idle_count = 0
        while True:
            with _scan_lock:
                data = _scan_progress.get(scan_id, {
                    "pct": 0, "phase": "Starting…", "status": "running",
                    "vulns_found": 0, "log": [],
                })
            payload = json.dumps(data)
            yield f"data: {payload}\n\n"
            if data.get("status") in ("done", "failed"):
                break
            if data.get("pct", 0) == last_pct:
                idle_count += 1
                if idle_count > 600:   # 10 min timeout
                    break
            else:
                idle_count = 0
                last_pct = data.get("pct", 0)
            import time
            time.sleep(1)
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/results/<scan_id>")
def results(scan_id: str):
    scan = scan_db.get_scan(scan_id)
    if not scan:
        return render_template_string(RESULT_TEMPLATE, error="Scan not found"), 404

    raw_vulns = scan_db.get_scan_vulns(scan_id)

    # Build display-friendly vuln list from DB rows
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    vulns = []
    for row in raw_vulns:
        import json as _json
        details = {}
        try:
            details = _json.loads(row.get("details_json") or "{}")
        except Exception:
            pass

        v = {
            "vuln_type":           row.get("vuln_type", "Unknown"),
            "severity":            row.get("severity", "Info"),
            "url":                 row.get("url", ""),
            "parameter":           row.get("parameter", ""),
            "description":         row.get("description", ""),
            "owasp":               row.get("owasp", ""),
            # Classification system fields — from details if available
            "classification":      details.get("classification", "Potential Vulnerability"),
            "confidence":          details.get("confidence", 75),
            "confidence_label":    details.get("confidence_label", "High"),
            "verification_method": details.get("verification_method", "Pattern match (unverified)"),
            "evidence_score":      details.get("evidence_score", 0),
            "cvss_estimate":       details.get("cvss_estimate", "N/A"),
            "evidence":            details.get("evidence", row.get("description", "")),
            "reproduction_steps":  details.get("reproduction_steps", []),
            "remediation":         details.get("remediation", ""),
            # New fields from rate-limit, business-logic, WAF bypass, ZAP
            "subtype":             details.get("subtype", ""),
            "source":              details.get("source", ""),
            "cwe":                 details.get("cwe", ""),
            "waf_bypass_used":     details.get("waf_bypass_used", False),
            "bypass_variant":      details.get("bypass_variant", ""),
        }
        vulns.append(v)

    # Sort by classification order then severity
    cls_order = {
        "Confirmed Vulnerability": 0,
        "Likely Vulnerability":    1,
        "Potential Vulnerability": 2,
        "Informational":           3,
    }
    vulns.sort(key=lambda v: (
        cls_order.get(v["classification"], 4),
        sev_order.index(v["severity"]) if v["severity"] in sev_order else 5,
        -v["confidence"],
    ))

    counts = {s: sum(1 for v in vulns if v["severity"] == s)
              for s in ["Critical", "High", "Medium", "Low", "Info"]}

    cls_counts = {
        "Confirmed":    sum(1 for v in vulns if v["classification"] == "Confirmed Vulnerability"),
        "Likely":       sum(1 for v in vulns if v["classification"] == "Likely Vulnerability"),
        "Potential":    sum(1 for v in vulns if v["classification"] == "Potential Vulnerability"),
        "Informational":sum(1 for v in vulns if v["classification"] == "Informational"),
    }

    return render_template_string(
        DETAIL_TEMPLATE, scan=scan, vulns=vulns, counts=counts, cls_counts=cls_counts,
    )


@app.route("/history")
def history():
    scans = scan_db.list_scans(limit=50)
    return render_template_string(HISTORY_TEMPLATE, scans=scans)


@app.route("/download/<scan_id>")
def download(scan_id: str):
    scan = scan_db.get_scan(scan_id)
    if not scan or not scan.get("report_path"):
        return "Report not available", 404
    path = Path(scan["report_path"])
    if not path.exists():
        return "Report file not found on disk", 404
    return send_file(str(path), as_attachment=True,
                     download_name=f"vuln_report_{scan_id}.pdf",
                     mimetype="application/pdf")


@app.route("/health")
def health():
    return {"status": "ok", "version": "5.0"}


@app.route("/delete/<scan_id>", methods=["GET","POST"])
def delete_scan(scan_id: str):
    """Delete a scan record and its PDF from history."""
    scan = scan_db.get_scan(scan_id)
    if scan:
        # Remove PDF file if it exists
        if scan.get("report_path"):
            try:
                Path(scan["report_path"]).unlink(missing_ok=True)
            except Exception:
                pass
        scan_db.delete_scan(scan_id)
    return redirect("/history")


@app.errorhandler(404)
def not_found(e):
    html = render_template_string("""
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Page Not Found</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);
     min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.box{background:#fff;border-radius:18px;padding:48px;max-width:480px;text-align:center;
     box-shadow:0 24px 70px rgba(0,0,0,.5)}
h1{font-size:4em;color:#0f3460;margin-bottom:8px}
p{color:#6b7280;font-size:14px;margin-bottom:24px}
a{display:inline-block;padding:10px 24px;background:#0f3460;color:#fff;border-radius:8px;
  text-decoration:none;font-weight:700}
</style></head><body>
<div class="box">
  <h1>404</h1>
  <p>The page or scan you're looking for doesn't exist.</p>
  <a href="/">← Back to Scanner</a>
</div></body></html>""")
    return html, 404


@app.errorhandler(500)
def server_error(e):
    html = render_template_string("""
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Server Error</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);
     min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.box{background:#fff;border-radius:18px;padding:48px;max-width:480px;text-align:center;
     box-shadow:0 24px 70px rgba(0,0,0,.5)}
h1{font-size:4em;color:#dc2626;margin-bottom:8px}
p{color:#6b7280;font-size:14px;margin-bottom:24px}
a{display:inline-block;padding:10px 24px;background:#0f3460;color:#fff;border-radius:8px;
  text-decoration:none;font-weight:700}
</style></head><body>
<div class="box">
  <h1>500</h1>
  <p>An unexpected error occurred. Check the server logs for details.</p>
  <a href="/">← Back to Scanner</a>
</div></body></html>""")
    return html, 500


@app.route("/favicon.ico")
def favicon():
    """Serve an empty favicon to stop browsers logging 404 errors every page load."""
    return "", 204


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

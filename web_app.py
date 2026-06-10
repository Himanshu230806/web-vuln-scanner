#!/usr/bin/env python3
"""
Web Vulnerability Scanner – Web Interface  (v3.0 – upgraded)

Upgrades:
  - Persistent scan history via SQLite (db.py)
  - /history page listing past scans with vuln counts
  - Per-scan-endpoint rate limit (5/hour) separate from global limits
  - Auth options exposed in the UI (cookies, Bearer token, basic auth)
  - New modules (security headers, SSRF, XXE, IDOR) shown in module list
  - SSL verify_ssl warning shown in UI when disabled
"""

import html as html_module
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request, send_file
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

# ──────────────────────────────────────────────────────────────────────────────
# Templates
# ──────────────────────────────────────────────────────────────────────────────

HOME_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Web Vulnerability Scanner v3</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);min-height:100vh;padding:20px}
.container{max-width:860px;margin:0 auto;background:#fff;border-radius:16px;padding:40px;box-shadow:0 20px 60px rgba(0,0,0,.4)}
h1{color:#c0392b;text-align:center;margin-bottom:8px;font-size:2.2em}
.subtitle{text-align:center;color:#555;margin-bottom:24px}
.warning{background:#fff8e1;border-left:5px solid #f9a825;padding:16px;margin:16px 0;border-radius:6px}
.warning h3{color:#7a5900;margin-bottom:8px}
.warning ul{margin-left:20px;color:#7a5900}
label{display:block;margin:14px 0 4px;font-weight:600;color:#222}
input[type=url],input[type=text],input[type=password]{width:100%;padding:12px;border:2px solid #ddd;border-radius:7px;font-size:15px}
input:focus{outline:none;border-color:#0f3460}
.section{background:#f4f6fb;padding:18px;border-radius:8px;margin:18px 0}
.section h3{color:#333;margin-bottom:14px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.checkbox-item{margin:8px 0;display:flex;align-items:center;gap:8px}
.checkbox-item label{margin:0;font-weight:normal;color:#333}
.collapsible-toggle{background:none;border:none;color:#0f3460;cursor:pointer;font-size:14px;padding:0;text-decoration:underline;width:auto}
.collapsible{display:none;margin-top:12px}
button.submit{width:100%;padding:16px;background:linear-gradient(135deg,#0f3460,#533483);color:#fff;border:none;border-radius:8px;font-size:17px;font-weight:700;cursor:pointer;margin-top:8px}
button.submit:hover{opacity:.92}
.nav{text-align:right;margin-bottom:12px}
.nav a{color:#0f3460;text-decoration:none;font-size:14px;margin-left:16px}
.nav a:hover{text-decoration:underline}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700;color:#fff;margin-left:6px}
.badge-new{background:#27ae60}
</style>
</head><body><div class="container">

<div class="nav">
  <a href="/">🏠 Home</a>
  <a href="/history">📋 Scan History</a>
</div>

<h1>🔒 Web Vulnerability Scanner</h1>
<p class="subtitle">Professional Security Assessment Tool v3.0</p>

<div class="warning">
  <h3>⚠️ Legal Notice</h3>
  <ul>
    <li>Only scan websites you <strong>own</strong> or have <strong>written permission</strong> to test</li>
    <li>Unauthorized scanning is <strong>illegal</strong></li>
    <li>You are solely responsible for any consequences</li>
  </ul>
</div>

<form action="/scan" method="POST">
  <label for="url">🌐 Target URL</label>
  <input type="url" id="url" name="url" placeholder="https://example.com" required>

  <div class="section">
    <h3>🧩 Vulnerability Modules</h3>
    <div class="grid2">
      <div class="checkbox-item"><input type="checkbox" name="modules" value="sqli" id="sqli" checked><label for="sqli">SQL Injection</label></div>
      <div class="checkbox-item"><input type="checkbox" name="modules" value="xss" id="xss" checked><label for="xss">XSS</label></div>
      <div class="checkbox-item"><input type="checkbox" name="modules" value="csrf" id="csrf" checked><label for="csrf">CSRF</label></div>
      <div class="checkbox-item"><input type="checkbox" name="modules" value="redirect" id="redirect" checked><label for="redirect">Open Redirect</label></div>
      <div class="checkbox-item"><input type="checkbox" name="modules" value="traversal" id="traversal" checked><label for="traversal">Directory Traversal</label></div>
      <div class="checkbox-item"><input type="checkbox" name="modules" value="headers" id="headers" checked><label for="headers">Security Headers <span class="badge badge-new">NEW</span></label></div>
      <div class="checkbox-item"><input type="checkbox" name="modules" value="ssrf" id="ssrf" checked><label for="ssrf">SSRF <span class="badge badge-new">NEW</span></label></div>
      <div class="checkbox-item"><input type="checkbox" name="modules" value="xxe" id="xxe" checked><label for="xxe">XXE <span class="badge badge-new">NEW</span></label></div>
      <div class="checkbox-item"><input type="checkbox" name="modules" value="idor" id="idor" checked><label for="idor">IDOR <span class="badge badge-new">NEW</span></label></div>
    </div>
  </div>

  <div class="section">
    <h3>🔐 Authentication (optional)</h3>
    <label for="auth_cookie">Session Cookie (name=value, comma-separated)</label>
    <input type="text" id="auth_cookie" name="auth_cookie" placeholder="session=abc123, csrftoken=xyz">
    <label for="auth_header">Auth Header</label>
    <input type="text" id="auth_header" name="auth_header" placeholder="Authorization: Bearer &lt;token&gt;">
    <div class="grid2">
      <div>
        <label for="auth_user">Basic Auth Username</label>
        <input type="text" id="auth_user" name="auth_user" placeholder="admin">
      </div>
      <div>
        <label for="auth_pass">Basic Auth Password</label>
        <input type="password" id="auth_pass" name="auth_pass" placeholder="password">
      </div>
    </div>
  </div>

  <button type="submit" class="submit">🔍 Start Security Scan</button>
</form>

</div></body></html>
"""


RESULT_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Scan Results</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#0f3460);min-height:100vh;padding:20px}
.container{max-width:860px;margin:0 auto;background:#fff;border-radius:16px;padding:36px;box-shadow:0 20px 60px rgba(0,0,0,.4)}
.header-box{padding:24px;border-radius:12px;margin-bottom:24px;color:#fff}
.header-box.success{background:linear-gradient(135deg,#0f3460,#533483)}
.header-box.error{background:#c0392b}
.vuln-count{font-size:3.5em;font-weight:800;text-align:center;margin:16px 0}
.c-critical{color:#c0392b}.c-high{color:#e67e22}.c-medium{color:#f39c12}.c-clean{color:#27ae60}
.stats{background:#f4f6fb;padding:18px;border-radius:8px;margin:18px 0}
.stat-row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #e0e0e0}
.stat-row:last-child{border-bottom:none}
.btn{display:block;width:100%;padding:16px;text-align:center;border-radius:8px;font-size:1.1em;font-weight:700;text-decoration:none;margin:10px 0;transition:opacity .2s}
.btn:hover{opacity:.88}
.btn-green{background:#27ae60;color:#fff}
.btn-blue{background:#0f3460;color:#fff}
.sev-table{width:100%;border-collapse:collapse;margin:12px 0;font-size:14px}
.sev-table th,.sev-table td{padding:8px 12px;border:1px solid #ddd;text-align:left}
.sev-table th{background:#f4f6fb}
.badge{padding:2px 9px;border-radius:10px;font-size:12px;font-weight:700;color:#fff}
.bg-critical{background:#c0392b}.bg-high{background:#e67e22}.bg-medium{background:#f39c12}.bg-low{background:#27ae60}.bg-info{background:#2980b9}
.nav{text-align:right;margin-bottom:12px}
.nav a{color:#0f3460;font-size:14px;margin-left:14px;text-decoration:none}
</style>
</head><body><div class="container">

<div class="nav"><a href="/">🏠 Home</a><a href="/history">📋 History</a></div>

{% if error %}
<div class="header-box error"><h2>❌ Scan Failed</h2><p>{{ error }}</p></div>
{% else %}
<div class="header-box success">
  <h2>✅ Scan Complete</h2>
  <p><strong>Target:</strong> {{ url }}</p>
  <p><strong>Scan ID:</strong> {{ scan_id }}</p>
</div>

<div class="vuln-count {{ severity_class }}">{{ count }}</div>
<p style="text-align:center;font-size:1.1em;margin-bottom:20px">Vulnerabilities Found</p>

<table class="sev-table">
  <tr><th>Severity</th><th>Count</th></tr>
  <tr><td><span class="badge bg-critical">Critical</span></td><td>{{ counts.Critical }}</td></tr>
  <tr><td><span class="badge bg-high">High</span></td><td>{{ counts.High }}</td></tr>
  <tr><td><span class="badge bg-medium">Medium</span></td><td>{{ counts.Medium }}</td></tr>
  <tr><td><span class="badge bg-low">Low</span></td><td>{{ counts.Low }}</td></tr>
  <tr><td><span class="badge bg-info">Info</span></td><td>{{ counts.Info }}</td></tr>
</table>

<div class="stats">
  <div class="stat-row"><span>URLs Crawled</span><span>{{ stats.urls_crawled }}</span></div>
  <div class="stat-row"><span>Forms Tested</span><span>{{ stats.forms_tested }}</span></div>
  <div class="stat-row"><span>Parameters Tested</span><span>{{ stats.parameters_tested }}</span></div>
</div>

<a href="/download/{{ scan_id }}" class="btn btn-green">📥 Download PDF Report</a>
<a href="/results/{{ scan_id }}" class="btn btn-blue">📊 View Detailed Results</a>
{% endif %}
<a href="/" style="display:block;text-align:center;color:#0f3460;margin-top:14px">← Scan Another Website</a>
</div></body></html>
"""


HISTORY_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Scan History</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#0f3460);min-height:100vh;padding:20px}
.container{max-width:960px;margin:0 auto;background:#fff;border-radius:16px;padding:36px;box-shadow:0 20px 60px rgba(0,0,0,.4)}
h1{color:#0f3460;margin-bottom:24px}
.nav{text-align:right;margin-bottom:12px}
.nav a{color:#0f3460;font-size:14px;margin-left:14px;text-decoration:none}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:10px 14px;border:1px solid #ddd;text-align:left}
th{background:#f4f6fb}
tr:hover{background:#f9f9f9}
.badge{padding:2px 9px;border-radius:10px;font-size:12px;font-weight:700;color:#fff}
.bg-done{background:#27ae60}.bg-failed{background:#c0392b}.bg-running{background:#f39c12}
a.link{color:#0f3460;text-decoration:none}
a.link:hover{text-decoration:underline}
.empty{color:#888;text-align:center;padding:40px}
</style>
</head><body><div class="container">
<div class="nav"><a href="/">🏠 Home</a></div>
<h1>📋 Scan History</h1>
{% if scans %}
<table>
  <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Vulns</th><th>Started</th><th>Actions</th></tr></thead>
  <tbody>
  {% for s in scans %}
  <tr>
    <td><code>{{ s.id }}</code></td>
    <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis">{{ s.url }}</td>
    <td><span class="badge bg-{{ s.status }}">{{ s.status }}</span></td>
    <td>{{ s.vuln_count }}</td>
    <td>{{ s.started_at[:16] }}</td>
    <td>
      <a class="link" href="/results/{{ s.id }}">View</a>
      {% if s.report_path %}&nbsp;·&nbsp;<a class="link" href="/download/{{ s.id }}">PDF</a>{% endif %}
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p class="empty">No scans yet. <a href="/">Start your first scan →</a></p>
{% endif %}
</div></body></html>
"""


DETAIL_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Scan Detail – {{ scan.id }}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#0f3460);min-height:100vh;padding:20px}
.container{max-width:960px;margin:0 auto;background:#fff;border-radius:16px;padding:36px;box-shadow:0 20px 60px rgba(0,0,0,.4)}
h1{color:#0f3460;margin-bottom:4px;font-size:1.5em}
.meta{color:#555;font-size:13px;margin-bottom:24px}
.nav{text-align:right;margin-bottom:12px}
.nav a{color:#0f3460;font-size:14px;margin-left:14px;text-decoration:none}
.vuln-card{border:1px solid #ddd;border-radius:8px;margin:14px 0;overflow:hidden}
.vuln-header{padding:12px 16px;display:flex;align-items:center;gap:12px;background:#f8f8f8}
.vuln-body{padding:14px 16px;font-size:14px;color:#333;line-height:1.6}
.badge{padding:3px 10px;border-radius:10px;font-size:12px;font-weight:700;color:#fff}
.bg-Critical{background:#c0392b}.bg-High{background:#e67e22}.bg-Medium{background:#f39c12}
.bg-Low{background:#27ae60}.bg-Info{background:#2980b9}
.type{font-weight:700;color:#222;font-size:15px}
.param{font-family:monospace;background:#eef;padding:1px 5px;border-radius:3px;font-size:13px}
.url{font-family:monospace;font-size:12px;color:#555;word-break:break-all}
.empty{color:#888;padding:24px;text-align:center}
.dl-btn{display:inline-block;padding:10px 20px;background:#27ae60;color:#fff;border-radius:7px;text-decoration:none;font-weight:700;margin-bottom:16px}
</style>
</head><body><div class="container">
<div class="nav"><a href="/">🏠 Home</a><a href="/history">📋 History</a></div>
<h1>Scan Results – <code>{{ scan.id }}</code></h1>
<div class="meta">Target: {{ scan.url }} · Started: {{ scan.started_at[:16] }} · Status: {{ scan.status }}</div>

{% if scan.report_path %}
<a class="dl-btn" href="/download/{{ scan.id }}">📥 Download PDF</a>
{% endif %}

{% if vulns %}
{% for v in vulns %}
<div class="vuln-card">
  <div class="vuln-header">
    <span class="badge bg-{{ v.severity }}">{{ v.severity }}</span>
    <span class="type">{{ v.vuln_type }}</span>
    {% if v.parameter %}<span class="param">param: {{ v.parameter }}</span>{% endif %}
  </div>
  <div class="vuln-body">
    <div class="url">{{ v.url }}</div>
    <p style="margin-top:8px">{{ v.description }}</p>
  </div>
</div>
{% endfor %}
{% else %}
<p class="empty">No vulnerabilities recorded for this scan.</p>
{% endif %}

</div></body></html>
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
    selected_modules = request.form.getlist("modules")

    if not target_url:
        return render_template_string(RESULT_TEMPLATE, error="URL is required"), 400
    if not target_url.startswith(("http://", "https://")):
        return render_template_string(RESULT_TEMPLATE,
                                      error="URL must start with http:// or https://"), 400

    scan_id = str(uuid.uuid4())[:8]
    scan_db.create_scan(scan_id, target_url)

    try:
        scan_config = {
            "max_depth": 2,
            "threads": 5,
            "request_timeout": 15,
            "delay": 0.2,
            "verify_ssl": True,
        }

        # Parse auth fields from form
        raw_cookie = request.form.get("auth_cookie", "").strip()
        if raw_cookie:
            cookies = {}
            for pair in raw_cookie.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()
            scan_config["auth_cookies"] = cookies

        raw_header = request.form.get("auth_header", "").strip()
        if raw_header and ":" in raw_header:
            k, v = raw_header.split(":", 1)
            scan_config["auth_headers"] = {k.strip(): v.strip()}

        auth_user = request.form.get("auth_user", "").strip()
        auth_pass = request.form.get("auth_pass", "").strip()
        if auth_user and auth_pass:
            scan_config["auth_basic"] = (auth_user, auth_pass)

        scanner = VulnerabilityScanner(target_url, scan_config)
        vulnerabilities = scanner.run_scan()

        # PDF report
        pdf_gen = PDFReportGenerator()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = OUTPUT_DIR / f"scan_{scan_id}_{ts}.pdf"
        report_path = pdf_gen.generate_report(
            target_url, vulnerabilities, scanner.scan_stats, output_file
        )

        scan_db.finish_scan(scan_id, vulnerabilities, scanner.scan_stats, report_path)

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in vulnerabilities:
            sev = v.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        if counts["Critical"] > 0:
            sev_class = "c-critical"
        elif counts["High"] > 0:
            sev_class = "c-high"
        elif counts["Medium"] > 0:
            sev_class = "c-medium"
        else:
            sev_class = "c-clean"

        return render_template_string(
            RESULT_TEMPLATE,
            url=target_url,
            scan_id=scan_id,
            count=len(vulnerabilities),
            severity_class=sev_class,
            counts=counts,
            stats=scanner.scan_stats,
            error=None,
        )

    except Exception as exc:
        scan_db.mark_scan_failed(scan_id, str(exc))
        return render_template_string(RESULT_TEMPLATE, error=str(exc)), 500


@app.route("/history")
def history():
    scans = scan_db.list_scans(50)
    return render_template_string(HISTORY_TEMPLATE, scans=scans)


@app.route("/results/<scan_id>")
def scan_detail(scan_id: str):
    scan = scan_db.get_scan(scan_id)
    if not scan:
        return "Scan not found", 404
    vulns = scan_db.get_scan_vulns(scan_id)
    return render_template_string(DETAIL_TEMPLATE, scan=scan, vulns=vulns)


@app.route("/download/<scan_id>")
def download_report(scan_id: str):
    scan = scan_db.get_scan(scan_id)
    if not scan or not scan.get("report_path"):
        return "Report not found", 404
    report_path = scan["report_path"]
    if not os.path.exists(report_path):
        return "Report file not found", 404
    return send_file(report_path, as_attachment=True,
                     download_name=f"vuln_report_{scan_id}.pdf")


@app.errorhandler(429)
def ratelimit_handler(e):
    return "<h1>⏳ Rate limit exceeded</h1><p>Max 5 scans/hour per IP.</p><a href='/'>Back</a>", 429


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

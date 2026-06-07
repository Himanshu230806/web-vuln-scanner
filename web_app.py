#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Web Interface
Deployed on Render via GitHub
"""

from flask import Flask, render_template_string, request, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import html
import os
import uuid
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import VulnerabilityScanner
from reports.pdf_generator import PDFReportGenerator
from config import OUTPUT_DIR

app = Flask(__name__)

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Rate limiting - 5 scans per hour per IP
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# In-memory storage for scan results
scan_results = {}

# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Vulnerability Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #d32f2f;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }
        .warning {
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        .warning h3 {
            color: #856404;
            margin-bottom: 10px;
        }
        .warning ul {
            margin-left: 20px;
            color: #856404;
        }
        form {
            margin-top: 30px;
        }
        label {
            display: block;
            margin: 15px 0 5px 0;
            font-weight: bold;
            color: #333;
        }
        input[type="url"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input[type="url"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .checkbox-group {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .checkbox-group label {
            display: inline;
            font-weight: normal;
            margin-left: 8px;
        }
        .checkbox-item {
            margin: 10px 0;
        }
        button {
            width: 100%;
            padding: 18px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        .features {
            margin-top: 40px;
            padding-top: 30px;
            border-top: 2px solid #eee;
        }
        .features h3 {
            color: #333;
            margin-bottom: 20px;
        }
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        .feature-item {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .feature-icon {
            font-size: 2em;
            margin-bottom: 10px;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Web Vulnerability Scanner</h1>
        <p class="subtitle">Professional Security Assessment Tool</p>
        
        <div class="warning">
            <h3>⚠️ Legal Notice</h3>
            <ul>
                <li>Only scan websites you <strong>own</strong> or have <strong>written permission</strong> to test</li>
                <li>Unauthorized scanning is <strong>illegal</strong> and may result in criminal charges</li>
                <li>You are solely responsible for any consequences of using this tool</li>
            </ul>
        </div>
        
        <form action="/scan" method="POST">
            <label for="url">🌐 Target URL:</label>
            <input type="url" id="url" name="url" placeholder="https://example.com" required>
            
            <div class="checkbox-group">
                <label><strong>Select Vulnerability Tests:</strong></label>
                <div class="checkbox-item">
                    <input type="checkbox" name="modules" value="sqli" id="sqli" checked>
                    <label for="sqli">SQL Injection</label>
                </div>
                <div class="checkbox-item">
                    <input type="checkbox" name="modules" value="xss" id="xss" checked>
                    <label for="xss">Cross-Site Scripting (XSS)</label>
                </div>
                <div class="checkbox-item">
                    <input type="checkbox" name="modules" value="csrf" id="csrf" checked>
                    <label for="csrf">CSRF</label>
                </div>
                <div class="checkbox-item">
                    <input type="checkbox" name="modules" value="redirect" id="redirect" checked>
                    <label for="redirect">Open Redirect</label>
                </div>
                <div class="checkbox-item">
                    <input type="checkbox" name="modules" value="traversal" id="traversal" checked>
                    <label for="traversal">Directory Traversal</label>
                </div>
            </div>
            
            <button type="submit">🔍 Start Security Scan</button>
        </form>
        
        <div class="features">
            <h3>✨ Features</h3>
            <div class="feature-grid">
                <div class="feature-item">
                    <div class="feature-icon">🕷️</div>
                    <div>Web Crawling</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🛡️</div>
                    <div>OWASP Top 10</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">📊</div>
                    <div>PDF Reports</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">⚡</div>
                    <div>Fast Scanning</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Powered by Python, Flask & ReportLab</p>
        </div>
    </div>
</body>
</html>
'''

RESULT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Results - Web Vulnerability Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .success-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
        }
        .success-box h2 {
            margin-bottom: 15px;
        }
        .success-box p {
            margin: 10px 0;
            font-size: 1.1em;
        }
        .vuln-count {
            font-size: 3em;
            font-weight: bold;
            text-align: center;
            margin: 20px 0;
        }
        .vuln-critical { color: #d32f2f; }
        .vuln-high { color: #f57c00; }
        .vuln-medium { color: #fbc02d; }
        .vuln-low { color: #388e3c; }
        .download-btn {
            display: block;
            width: 100%;
            padding: 20px;
            background: #4caf50;
            color: white;
            text-align: center;
            text-decoration: none;
            border-radius: 10px;
            font-size: 1.2em;
            font-weight: bold;
            margin: 20px 0;
            transition: transform 0.2s;
        }
        .download-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(76, 175, 80, 0.3);
        }
        .back-link {
            display: block;
            text-align: center;
            color: #667eea;
            text-decoration: none;
            margin-top: 20px;
        }
        .back-link:hover {
            text-decoration: underline;
        }
        .stats {
            background: #f5f5f5;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .stats h3 {
            margin-bottom: 15px;
            color: #333;
        }
        .stat-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #ddd;
        }
        .error-box {
            background: #ffebee;
            color: #c62828;
            padding: 30px;
            border-radius: 15px;
            text-align: center;
        }
        .error-box h2 {
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        {% if error %}
        <div class="error-box">
            <h2>❌ Scan Failed</h2>
            <p>{{ error }}</p>
            <a href="/" class="back-link">← Go Back</a>
        </div>
        {% else %}
        <div class="success-box">
            <h2>✅ Scan Complete!</h2>
            <p><strong>Target:</strong> {{ url }}</p>
            <p><strong>Scan ID:</strong> {{ scan_id }}</p>
        </div>
        
        <div class="vuln-count {{ severity_class }}">
            {{ count }}
        </div>
        <p style="text-align: center; font-size: 1.2em; margin-bottom: 30px;">
            Vulnerabilities Found
        </p>
        
        <div class="stats">
            <h3>📊 Scan Statistics</h3>
            <div class="stat-item">
                <span>URLs Crawled:</span>
                <span>{{ stats.urls_crawled }}</span>
            </div>
            <div class="stat-item">
                <span>Forms Tested:</span>
                <span>{{ stats.forms_tested }}</span>
            </div>
            <div class="stat-item">
                <span>Parameters Tested:</span>
                <span>{{ stats.parameters_tested }}</span>
            </div>
        </div>
        
        <a href="/download/{{ scan_id }}" class="download-btn">
            📥 Download PDF Report
        </a>
        
        <a href="/" class="back-link">← Scan Another Website</a>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    """Home page"""
    return render_template_string(HOME_TEMPLATE)

@app.route('/scan', methods=['POST'])
@limiter.limit("5 per hour")
def scan():
    """Run vulnerability scan"""
    target_url = request.form.get('url', '').strip()
    selected_modules = request.form.getlist('modules')
    
    # Validate URL
    if not target_url:
        return render_template_string(RESULT_TEMPLATE, error="URL is required"), 400
    
    if not target_url.startswith(('http://', 'https://')):
        return render_template_string(RESULT_TEMPLATE, error="URL must start with http:// or https://"), 400
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())[:8]
    
    try:
        # Configure scan
        scan_config = {
            'max_depth': 2,
            'threads': 3,
            'request_timeout': 15,
            'delay': 0.2,
        }
        
        # Run scan
        scanner = VulnerabilityScanner(target_url, scan_config)
        vulnerabilities = scanner.run_scan()
        
        # Generate PDF report
        pdf_gen = PDFReportGenerator()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = OUTPUT_DIR / f"scan_{scan_id}_{timestamp}.pdf"
        
        report_path = pdf_gen.generate_report(
            target_url,
            vulnerabilities,
            scanner.scan_stats,
            output_file
        )
        
        # Store result
        scan_results[scan_id] = {
            'url': target_url,
            'vulnerabilities': len(vulnerabilities),
            'report': report_path,
            'timestamp': datetime.now().isoformat()
        }
        
        # Determine severity class
        if len(vulnerabilities) == 0:
            severity_class = 'vuln-low'
        elif any(v.get('severity') == 'Critical' for v in vulnerabilities):
            severity_class = 'vuln-critical'
        elif any(v.get('severity') == 'High' for v in vulnerabilities):
            severity_class = 'vuln-high'
        else:
            severity_class = 'vuln-medium'
        
        return render_template_string(
            RESULT_TEMPLATE,
            url=target_url,
            scan_id=scan_id,
            count=len(vulnerabilities),
            severity_class=severity_class,
            stats=scanner.scan_stats,
            error=None
        )
        
    except Exception as e:
        return render_template_string(RESULT_TEMPLATE, error=str(e)), 500

@app.route('/download/<scan_id>')
def download_report(scan_id):
    """Download PDF report"""
    if scan_id not in scan_results:
        return "Report not found", 404
    
    report_path = scan_results[scan_id]['report']
    
    if not os.path.exists(report_path):
        return "Report file not found", 404
    
    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"vulnerability_report_{scan_id}.pdf"
    )

@app.errorhandler(429)
def ratelimit_handler(e):
    """Rate limit exceeded"""
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>Rate Limited</title></head>
    <body style="text-align: center; padding: 50px; font-family: Arial;">
        <h1>⏳ Rate Limit Exceeded</h1>
        <p>Please wait before scanning again.</p>
        <a href="/">← Go Back</a>
    </body>
    </html>
    '''), 429

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

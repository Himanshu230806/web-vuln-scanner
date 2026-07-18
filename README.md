# 🔒 Web Application Vulnerability Scanner v4.0
### Full OWASP Top 10 Coverage — Professional Security Assessment Tool

> ⚠️ **Legal Notice:** Only scan websites you **own** or have **written permission** to test. Unauthorized scanning is illegal. You are solely responsible for how you use this tool.

---

## 📋 Table of Contents
- [Features](#-features)
- [OWASP Top 10 Coverage](#-owasp-top-10-coverage)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Web UI](#web-ui)
  - [Command Line](#command-line)
  - [Authenticated Scanning](#authenticated-scanning)
- [Scan Modules](#-scan-modules)
- [Output & Reports](#-output--reports)
- [Scan History](#-scan-history)
- [Deployment](#-deployment)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Running Tests](#-running-tests)

---

## ✨ Features

| Feature | Description |
|---|---|
| **Full OWASP Top 10** | All 10 OWASP 2021 categories covered (A01–A10) |
| **13 Detection Modules** | SQLi, XSS, CSRF, SSRF, XXE, IDOR, Dir Traversal, Security Headers, Broken Auth, Vulnerable Components, SRI, Logging Failures, Open Redirect |
| **Concurrent Scanning** | ThreadPoolExecutor for fast multi-URL scanning |
| **Authenticated Scanning** | Cookie, Bearer token, and HTTP Basic auth support |
| **PDF Reports** | Professional reports with severity breakdown and remediation steps |
| **Scan History** | SQLite-persisted history — survives restarts |
| **Web UI + CLI** | Browser-based interface and full command-line tool |
| **OWASP ZAP Integration** | Optional passthrough to OWASP ZAP active scanner |
| **Rate Limiting** | Flask-Limiter (5 scans/hour per IP) |

---

## 🛡️ OWASP Top 10 Coverage

| # | OWASP Category | Scanner Module | Coverage |
|---|---|---|---|
| A01 | Broken Access Control | IDOR Detector | ✅ Full |
| A02 | Cryptographic Failures | Security Headers (HSTS, HTTPS) | ✅ Full |
| A03 | Injection | SQLi, XSS, XXE, Dir Traversal | ✅ Full |
| A04 | Insecure Design | CSRF, Open Redirect | ✅ Full |
| A05 | Security Misconfiguration | Security Headers (CSP, X-Frame, cookies) | ✅ Full |
| A06 | Vulnerable & Outdated Components | Vulnerable Components Detector | ✅ Full |
| A07 | Identification & Auth Failures | Broken Auth Detector | ✅ Full |
| A08 | Software & Data Integrity Failures | SRI Detector | ✅ Full |
| A09 | Security Logging & Monitoring Failures | Logging & Monitoring Detector | ✅ Full |
| A10 | Server-Side Request Forgery | SSRF Detector | ✅ Full |

---

## 🚀 Installation

### Requirements
- Python 3.9+
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/Himanshu230806/web-vuln-scanner.git
cd web-vuln-scanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Install test dependencies
pip install responses pytest
```

### Dependencies

```
flask>=3.0.0
flask-limiter>=3.5.0
requests>=2.31.0
beautifulsoup4>=4.12.0
reportlab>=4.0.0
colorama>=0.4.6
lxml>=4.9.3
gunicorn>=21.2.0
python-owasp-zap-v2.4
```

---

## 📖 Usage

### Web UI

```bash
python web_app.py
```

Open your browser at **http://localhost:5000**

The UI lets you:
- Enter a target URL
- Select which vulnerability modules to run
- Add authentication credentials (cookie / token / basic auth)
- View results instantly after scan completes
- Download the PDF report
- Browse all past scans in the History page

---

### Command Line

**Basic scan:**
```bash
python run.py -u https://target.com
```

**With options:**
```bash
# Deeper crawl with more threads
python run.py -u https://target.com -d 5 -t 20

# Save report to specific file
python run.py -u https://target.com -o /tmp/my_report.pdf

# Run only specific modules
python run.py -u https://target.com --modules sqli,xss,headers,ssrf

# Skip PDF generation
python run.py -u https://target.com --no-pdf

# With OWASP ZAP active scan
python run.py -u https://target.com --zap

# Verbose output
python run.py -u https://target.com -v

# Disable SSL verification (self-signed certs only)
python run.py -u https://target.com --no-verify-ssl
```

**All CLI options:**
```
-u, --url             Target URL (required)
-d, --depth           Crawl depth (default: 3)
-t, --threads         Worker threads (default: 10)
    --timeout         Request timeout in seconds (default: 30)
    --delay           Delay between requests (default: 0.5s)
    --user-agent      Custom User-Agent string
    --modules         Comma-separated module list
    --zap             Enable OWASP ZAP integration
    --no-pdf          Skip PDF report generation
-o, --output          Output PDF file path
-v, --verbose         Verbose output
    --no-verify-ssl   Disable TLS certificate verification
    --auth-cookie     Session cookies (name=value,name=value)
    --auth-header     Auth header (e.g. "Authorization: Bearer token")
    --auth-basic      HTTP Basic auth (username:password)
```

---

### Authenticated Scanning

Many real-world apps require login. Use these options to scan behind authentication:

```bash
# Cookie-based session
python run.py -u https://app.com --auth-cookie "session=abc123xyz"

# Multiple cookies
python run.py -u https://app.com --auth-cookie "session=abc123,csrftoken=xyz789"

# Bearer token (JWT / OAuth)
python run.py -u https://api.com --auth-header "Authorization: Bearer eyJhbGci..."

# HTTP Basic auth
python run.py -u https://staging.com --auth-basic admin:password123
```

---

## 🧩 Scan Modules

### A01 — Broken Access Control
**Module:** `modules/idor_detector.py`
- Tests numeric and UUID parameters by incrementing/substituting values
- Probes path segments for direct object references
- Flags when different IDs return significantly different 200 responses

### A02 — Cryptographic Failures
**Module:** `modules/security_headers_detector.py`
- Detects pages served over HTTP (no TLS)
- Checks for missing HSTS header
- Verifies TLS configuration via header inspection

### A03 — Injection
**Modules:** `sqli_detector.py`, `xss_detector.py`, `xxe_detector.py`, `directory_traversal_detector.py`
- **SQLi:** Error-based, boolean-based, and time-based payloads
- **XSS:** Reflected and stored XSS via URL params and forms
- **XXE:** Tests XML-accepting endpoints with external entity payloads
- **Dir Traversal:** `../` sequences, URL encoding, and double encoding

### A04 — Insecure Design
**Modules:** `csrf_detector.py`, `open_redirect_detector.py`
- **CSRF:** Checks POST forms for missing CSRF tokens
- **Open Redirect:** Tests redirect/url/next parameters for external destinations

### A05 — Security Misconfiguration
**Module:** `modules/security_headers_detector.py`
- Checks for: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- Flags exposed `Server` and `X-Powered-By` version headers
- Checks cookie flags: `Secure`, `HttpOnly`, `SameSite`

### A06 — Vulnerable & Outdated Components
**Module:** `modules/vulnerable_components_detector.py`
- Fingerprints server version from headers vs known CVE database
- Detects outdated JS libraries: jQuery, Bootstrap, Angular, Vue, React, lodash, moment.js
- Probes for exposed `package.json`, `composer.json`, `requirements.txt`
- Detects CMS (WordPress, Drupal, Joomla) and version

### A07 — Identification & Authentication Failures
**Module:** `modules/broken_auth_detector.py`
- Tests default credentials (admin/admin, admin/password, etc.)
- Checks for missing account lockout by sending 10 failed logins
- Detects credentials submitted over HTTP
- Checks session tokens for weak entropy or short length
- Flags session tokens exposed in URLs

### A08 — Software & Data Integrity Failures
**Module:** `modules/sri_detector.py`
- Checks external `<script>` tags for missing `integrity=` attribute (SRI)
- Checks external `<link rel="stylesheet">` for missing SRI
- Probes for exposed `.env`, `.git/HEAD`, `.git/config`, backup files
- Detects dangerous JS patterns: `eval()`, `innerHTML=`, `document.write()`

### A09 — Security Logging & Monitoring Failures
**Module:** `modules/logging_detector.py`
- Probes for stack traces / debug info in error pages
- Checks Flask/Django debug mode, PHP errors, Java exceptions
- Tests admin panels (`/admin`, `/phpmyadmin`, `/actuator`) for unauthenticated access
- Detects directory listing enabled
- Flags sensitive data (paths, DB strings, API keys) in responses

### A10 — Server-Side Request Forgery
**Module:** `modules/ssrf_detector.py`
- Tests URL-accepting parameters with cloud metadata endpoints (`169.254.169.254`)
- Tests loopback addresses (`127.0.0.1`, `0.0.0.0`, `[::1]`)
- Tests both GET parameters and form fields

---

## 📊 Output & Reports

After every scan a PDF report is generated in the `output/` folder containing:

- **Executive Summary** — total findings by severity
- **OWASP Top 10 Breakdown** — findings mapped to OWASP categories
- **Vulnerability Details** — type, severity, URL, parameter, description
- **Remediation Guidance** — specific fix recommendations per finding
- **Scan Statistics** — URLs crawled, forms tested, parameters tested, duration

**Severity levels:**

| Level | Color | Meaning |
|---|---|---|
| Critical 🔴 | Red | Immediate exploitation possible (SQLi, RCE, SSRF to metadata) |
| High 🟠 | Orange | Serious risk, exploit likely (XSS, IDOR, broken auth) |
| Medium 🟡 | Yellow | Significant risk (CSRF, open redirect, missing headers) |
| Low 🟢 | Green | Low risk (info disclosure, SRI missing) |
| Info 🔵 | Blue | Informational (CMS detected, server version) |

---

## 📋 Scan History

All scan results are persisted in a local SQLite database (`scan_history.db`).

- View at **http://localhost:5000/history**
- See full vulnerability list for any past scan
- Re-download PDF reports
- Results survive app restarts

---

## 🌐 Deployment

### Local Development
```bash
python web_app.py
# Runs on http://localhost:5000
```

### Deploy to Render (Free)

1. Push to GitHub:
```bash
git add .
git commit -m "v4.0 Full OWASP Top 10"
git push origin main
```

2. On [render.com](https://render.com):
   - **New → Web Service**
   - Connect your GitHub repo
   - Render reads `render.yaml` automatically
   - Click **Deploy**

Your app will be live at `https://your-app.onrender.com`

> **Note:** Render free tier spins down after 15 min inactivity. First request after sleep takes ~30s.

### Environment Variables (optional)
```
DB_PATH     Path to SQLite DB file (default: project root)
PORT        Port to listen on (default: 5000)
ZAP_API_KEY OWASP ZAP API key if using ZAP integration
```

---

## 🏗️ Architecture

```
web-vuln-scanner/
├── web_app.py              ← Flask web UI (routes, history, auth)
├── run.py                  ← CLI entry point
├── db.py                   ← SQLite persistence layer
├── core/
│   ├── scanner.py          ← Main orchestrator (all 10 phases)
│   └── crawler.py          ← URL + form discovery
├── modules/
│   ├── sqli_detector.py            ← A03 SQL Injection
│   ├── xss_detector.py             ← A03 XSS
│   ├── xxe_detector.py             ← A03 XXE
│   ├── directory_traversal_detector.py ← A03 Dir Traversal
│   ├── csrf_detector.py            ← A04 CSRF
│   ├── open_redirect_detector.py   ← A04 Open Redirect
│   ├── security_headers_detector.py← A02 + A05 Headers
│   ├── idor_detector.py            ← A01 IDOR
│   ├── ssrf_detector.py            ← A10 SSRF
│   ├── broken_auth_detector.py     ← A07 Auth Failures
│   ├── vulnerable_components_detector.py ← A06 Components
│   ├── sri_detector.py             ← A08 Integrity
│   ├── logging_detector.py         ← A09 Logging
│   └── zap_integration.py          ← OWASP ZAP bridge
├── reports/
│   └── pdf_generator.py    ← PDF report generator
├── config/
│   └── settings.py         ← Scanner configuration
├── tests/
│   └── test_detectors.py   ← 19 unit tests
├── output/                 ← Generated PDF reports
├── logs/                   ← Scanner logs
├── requirements.txt
└── render.yaml             ← Render deployment config
```

---

## 🧪 Running Tests

```bash
# Run all 19 unit tests
python -m pytest tests/test_detectors.py -v

# Run a specific test class
python -m pytest tests/test_detectors.py::TestSQLiDetector -v

# Run with coverage
pip install pytest-cov
python -m pytest tests/ --cov=modules --cov-report=term-missing
```

All tests use the `responses` mock library — no real HTTP requests are made during testing.

---

## 🔧 Demo Target

Use **VulnBank** — a deliberately vulnerable demo app built to match all scanner modules:

```bash
# Clone VulnBank
git clone https://github.com/Himanshu230806/vulnbank.git
cd vulnbank
pip install -r requirements.txt
python app.py
# Runs at http://localhost:8080
```

Then scan it:
```bash
python run.py -u http://localhost:8080 -d 3
```

VulnBank contains: SQLi, Reflected XSS, Stored XSS, CSRF, IDOR, SSRF, Directory Traversal, XXE, Open Redirect, missing security headers, verbose error pages, and unauthenticated admin panel.

---

## 👨‍💻 Author

**Himanshu** — Security Scanner Project  
GitHub: [@Himanshu230806](https://github.com/Himanshu230806)

---

## ⚠️ Disclaimer

This tool is intended **strictly for educational purposes** and authorized security testing only. The authors are not responsible for any misuse. Always obtain written permission before scanning any system you do not own.

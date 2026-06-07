# Web Application Vulnerability Scanner

A professional-grade web application security scanner built with Python, featuring automated vulnerability detection and comprehensive PDF reporting.

## Features

- **Automated Crawling**: Discovers all URLs and forms in target applications
- **Vulnerability Detection**:
  - SQL Injection (Error-based, Boolean-based, Time-based, Union-based)
  - Cross-Site Scripting (XSS) - Reflected and Stored
  - Cross-Site Request Forgery (CSRF)
  - Open Redirect
  - Directory Traversal / Local File Inclusion
- **OWASP ZAP Integration**: Enhanced scanning with professional security tool
- **Professional PDF Reports**: Executive summary with risk ratings
- **Multi-threaded Scanning**: Fast and efficient scanning
- **Configurable**: Customizable payloads and detection rules

## Requirements

- Python 3.8+
- Kali Linux (recommended) or any Linux distribution
- Chrome/Chromium (for Selenium)
- OWASP ZAP (optional, for enhanced scanning)

## Installation

### Quick Install (Kali Linux)

```bash
# Clone or extract the project
cd web-vuln-scanner

# Run setup script
chmod +x setup.sh
sudo ./setup.sh

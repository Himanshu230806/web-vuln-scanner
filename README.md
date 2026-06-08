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

# Clone or extract the project
cd web-vuln-scanner

# Run setup script
chmod +x setup.sh
sudo ./setup.sh

### Advanced Options

```bash
# Deep scan with ZAP integration
python run.py -u https://target.com --zap -d 5 -t 20

# Specific modules only
python run.py -u https://target.com --modules sqli,xss

# Custom output file
python run.py -u https://target.com -o custom_report.pdf

# Verbose output
python run.py -u https://target.com -v
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Target URL (required) | - |
| `-d, --depth` | Maximum crawl depth | 3 |
| `-t, --threads` | Number of threads | 10 |
| `--zap` | Enable OWASP ZAP | False |
| `-o, --output` | Output PDF file | auto-generated |
| `--no-pdf` | Skip PDF generation | False |
| `--timeout` | Request timeout (seconds) | 30 |
| `--delay` | Delay between requests | 0.5 |
| `--modules` | Comma-separated modules | all |
| `-v, --verbose` | Verbose output | False |

## OWASP ZAP Integration

1. Start ZAP in daemon mode:
   ```bash
   zaproxy -daemon -config api.key=your-api-key -port 8080
   ```

2. Run scanner with ZAP:
   ```bash
   python run.py -u https://target.com --zap
   ```

## Project Structure

```
web-vuln-scanner/
├── config/              # Configuration files
├── core/                # Core scanner and crawler
├── modules/             # Vulnerability detection modules
├── reports/             # PDF report generation
├── utils/               # Helper functions and payloads
├── logs/                # Log files
├── output/              # Generated reports
├── run.py               # Main entry point
├── setup.sh             # Setup script
└── requirements.txt     # Python dependencies
```

## Detection Capabilities

### SQL Injection
- Error-based detection
- Boolean-based blind injection
- Time-based blind injection
- Union-based injection

### XSS (Cross-Site Scripting)
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Multiple context payloads

### CSRF
- Token absence detection
- Referer/Origin validation
- SameSite cookie analysis

### Open Redirect
- Parameter identification
- External redirect detection
- JavaScript redirect analysis

### Directory Traversal
- Path traversal payloads
- Encoding bypasses
- File inclusion detection

## Report Contents

- Executive Summary with Risk Rating
- Findings Summary Table
- Detailed Vulnerability Descriptions
- Evidence and Proof of Concept
- Remediation Recommendations
- Technical Methodology

## Legal Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning any system you do not own. Unauthorized access to computer systems is illegal.

## License

MIT License - For educational and authorized testing purposes only.

## Contributing

Contributions are welcome. Please ensure all tests pass before submitting pull requests.

## Support

For issues and feature requests, please use the issue tracker.

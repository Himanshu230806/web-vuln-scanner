#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner
Main entry point
"""

import argparse
import sys
import os
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import VulnerabilityScanner
from reports.pdf_generator import PDFReportGenerator
from config import OUTPUT_DIR


def print_banner():
    """Print application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║          Web Application Vulnerability Scanner v2.0          ║
    ║                    Professional Edition                      ║
    ║                                                              ║
    ║  Supports: SQLi, XSS, CSRF, Open Redirect, Dir Traversal   ║
    ║  Integration: OWASP ZAP API, Selenium, BeautifulSoup       ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description='Web Application Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py -u https://example.com
  python run.py -u https://example.com --zap
  python run.py -u https://example.com -o report.pdf
  python run.py -u https://example.com --depth 5 --threads 20
        """
    )
    
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to scan'
    )
    
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=3,
        help='Maximum crawl depth (default: 3)'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of threads (default: 10)'
    )
    
    parser.add_argument(
        '--zap',
        action='store_true',
        help='Enable OWASP ZAP integration'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output PDF report file'
    )
    
    parser.add_argument(
        '--no-pdf',
        action='store_true',
        help='Skip PDF report generation'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=0.5,
        help='Delay between requests in seconds (default: 0.5)'
    )
    
    parser.add_argument(
        '--user-agent',
        default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        help='Custom User-Agent string'
    )
    
    parser.add_argument(
        '--modules',
        help='Comma-separated list of modules to run (sqli,xss,csrf,redirect,traversal)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("[-] Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Build configuration
    scan_config = {
        'max_depth': args.depth,
        'threads': args.threads,
        'request_timeout': args.timeout,
        'delay': args.delay,
        'user_agent': args.user_agent,
        'use_zap': args.zap,
    }
    
    # Disable specific modules if requested
    if args.modules:
        enabled_modules = [m.strip().lower() for m in args.modules.split(',')]
        all_modules = ['sqli', 'xss', 'csrf', 'open_redirect', 'directory_traversal']
        for mod in all_modules:
            if mod not in enabled_modules:
                scan_config[f'enable_{mod}'] = False
    
    try:
        # Initialize scanner
        print(f"[*] Initializing scanner for: {args.url}")
        scanner = VulnerabilityScanner(args.url, scan_config)
        
        # Run scan
        vulnerabilities = scanner.run_scan()
        
        # Generate PDF report
        if not args.no_pdf and vulnerabilities:
            print("\n[*] Generating PDF report...")
            pdf_gen = PDFReportGenerator()
            
            output_file = args.output
            if not output_file:
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = OUTPUT_DIR / f"scan_report_{timestamp}.pdf"
            
            report_path = pdf_gen.generate_report(
                args.url,
                vulnerabilities,
                scanner.scan_stats,
                output_file
            )
            print(f"[+] PDF report saved: {report_path}")
        
        # Summary
        print(f"\n[+] Scan completed!")
        print(f"[+] Total vulnerabilities found: {len(vulnerabilities)}")
        
        if vulnerabilities:
            sys.exit(1)  # Exit with error code if vulnerabilities found
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

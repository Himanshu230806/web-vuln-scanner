#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner  (v3.0)
Main CLI entry point – includes authentication options.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import VulnerabilityScanner
from reports.pdf_generator import PDFReportGenerator
from config import OUTPUT_DIR


BANNER = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║         Web Application Vulnerability Scanner v3.0           ║
    ║                    Professional Edition                      ║
    ║                                                              ║
    ║  Modules: SQLi · XSS · CSRF · Open Redirect · Dir Traversal ║
    ║           Security Headers · SSRF · XXE · IDOR               ║
    ╚══════════════════════════════════════════════════════════════╝
"""


def main():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py -u https://example.com
  python run.py -u https://example.com --zap -d 5 -t 20
  python run.py -u https://app.internal --auth-cookie "session=abc123"
  python run.py -u https://api.example.com --auth-header "Authorization: Bearer token"
  python run.py -u https://example.com --auth-basic admin:password
  python run.py -u https://example.com --modules sqli,xss,headers
        """,
    )

    # Target
    parser.add_argument("-u", "--url", required=True, help="Target URL")

    # Crawl / scan options
    parser.add_argument("-d", "--depth", type=int, default=3, help="Crawl depth (default: 3)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Worker threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout seconds")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests")
    parser.add_argument("--user-agent", default=None, help="Custom User-Agent string")
    parser.add_argument("--modules", help="Comma-separated module list (sqli,xss,csrf,redirect,traversal,headers,ssrf,xxe,idor)")
    parser.add_argument("--zap", action="store_true", help="Enable OWASP ZAP integration")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF generation")
    parser.add_argument("-o", "--output", help="Output PDF file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS certificate verification")

    # Authentication options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--auth-cookie",
        metavar="NAME=VALUE[,NAME=VALUE]",
        help="Session cookies, e.g. session=abc123,csrftoken=xyz",
    )
    auth_group.add_argument(
        "--auth-header",
        metavar="HEADER: VALUE",
        help="Auth header, e.g. 'Authorization: Bearer <token>'",
    )
    auth_group.add_argument(
        "--auth-basic",
        metavar="USER:PASS",
        help="HTTP Basic auth credentials",
    )

    args = parser.parse_args()

    print(BANNER)

    if not args.url.startswith(("http://", "https://")):
        print("[-] Error: URL must start with http:// or https://")
        sys.exit(1)

    # Build scan config
    scan_config: dict = {
        "max_depth": args.depth,
        "threads": args.threads,
        "request_timeout": args.timeout,
        "delay": args.delay,
        "use_zap": args.zap,
        "verify_ssl": not args.no_verify_ssl,
    }
    if args.user_agent:
        scan_config["user_agent"] = args.user_agent

    # Auth config
    if args.auth_cookie:
        cookies = {}
        for pair in args.auth_cookie.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
        scan_config["auth_cookies"] = cookies

    if args.auth_header:
        if ":" in args.auth_header:
            k, v = args.auth_header.split(":", 1)
            scan_config["auth_headers"] = {k.strip(): v.strip()}

    if args.auth_basic:
        if ":" in args.auth_basic:
            u, p = args.auth_basic.split(":", 1)
            scan_config["auth_basic"] = (u, p)

    # Module filter
    if args.modules:
        enabled = [m.strip().lower() for m in args.modules.split(",")]
        for mod in ["sqli", "xss", "csrf", "open_redirect", "directory_traversal",
                    "security_headers", "ssrf", "xxe", "idor"]:
            if mod not in enabled:
                scan_config[f"enable_{mod}"] = False

    try:
        scanner = VulnerabilityScanner(args.url, scan_config)
        vulns = scanner.run_scan()

        if not args.no_pdf:
            print("\n[*] Generating PDF report…")
            pdf_gen = PDFReportGenerator()
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = args.output or str(OUTPUT_DIR / f"scan_report_{ts}.pdf")
            report_path = pdf_gen.generate_report(
                args.url, vulns, scanner.scan_stats, out_file
            )
            print(f"[+] Report saved: {report_path}")

        print(f"\n[+] Done. Total findings: {len(vulns)}")
        sys.exit(1 if vulns else 0)

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)
    except Exception as exc:
        print(f"\n[-] Fatal error: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

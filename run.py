#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner v5.0 — CLI entry point
Includes a live animated progress bar in the terminal.
"""

import argparse
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ── Load .env file automatically (server/admin config, not user input) ─────────
# Uses env_loader.py (zero external dependencies) — see web_app.py for why
# this replaced the previous python-dotenv-dependent loader that could
# silently fail to load a correctly-configured .env file.
from env_loader import load_env_file
load_env_file(Path(__file__).parent, verbose=True)

BANNER = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║       Web Application Vulnerability Scanner v5.0             ║
    ║        Full OWASP Top 10 · Smart Targeting                   ║
    ║                                                              ║
    ║  A01 IDOR · A02 TLS/HSTS · A03 SQLi/XSS/XXE/Traversal       ║
    ║  A04 CSRF/Redirect · A05 Headers · A06 Components            ║
    ║  A07 Auth/RateLimit · A08 SRI · A09 Logging · A10 SSRF       ║
    ║  + Passive Secret Scanner · Business Logic · WAF Bypass      ║
    ╚══════════════════════════════════════════════════════════════╝
"""

# ── Terminal progress bar ─────────────────────────────────────────────────────

class ProgressBar:
    """
    Animated terminal progress bar.

    Usage:
        pb = ProgressBar(total_phases=10)
        pb.start()
        pb.update(3, "Crawling target")
        pb.finish()
    """

    BAR_WIDTH = 40
    SPINNER   = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self):
        self._pct      = 0
        self._phase    = "Starting…"
        self._vulns    = 0
        self._done     = False
        self._failed   = False
        self._spin_idx = 0
        self._lock     = threading.Lock()
        self._thread   = None
        self._use_color = sys.stdout.isatty()

    # ── ANSI helpers ─────────────────────────────────────────────────────────

    def _c(self, code: str, text: str) -> str:
        if not self._use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def _red(self, t):   return self._c("31", t)
    def _green(self, t): return self._c("32", t)
    def _yellow(self, t):return self._c("33", t)
    def _cyan(self, t):  return self._c("36", t)
    def _bold(self, t):  return self._c("1",  t)
    def _dim(self, t):   return self._c("2",  t)

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self):
        self._thread = threading.Thread(target=self._render_loop, daemon=True)
        self._thread.start()

    def update(self, pct: int, phase: str, vulns: int = 0):
        with self._lock:
            self._pct   = max(0, min(int(pct), 99))
            self._phase = phase
            self._vulns = vulns

    def finish(self, total_vulns: int = 0):
        with self._lock:
            self._pct    = 100
            self._phase  = "Scan complete"
            self._vulns  = total_vulns
            self._done   = True
        time.sleep(0.15)   # let render loop paint the final frame

    def fail(self, msg: str = ""):
        with self._lock:
            self._phase  = f"Failed: {msg[:60]}"
            self._failed = True
            self._done   = True
        time.sleep(0.15)

    # ── Render loop (runs in background thread) ───────────────────────────────

    def _render_loop(self):
        # Hide cursor
        if self._use_color:
            sys.stdout.write("\033[?25l")
            sys.stdout.flush()

        try:
            while True:
                with self._lock:
                    pct    = self._pct
                    phase  = self._phase
                    vulns  = self._vulns
                    done   = self._done
                    failed = self._failed
                    spin   = self.SPINNER[self._spin_idx % len(self.SPINNER)]
                    self._spin_idx += 1

                self._draw(pct, phase, vulns, spin, done, failed)

                if done:
                    break
                time.sleep(0.1)
        finally:
            # Show cursor again
            if self._use_color:
                sys.stdout.write("\033[?25h")
                sys.stdout.flush()

    def _draw(self, pct, phase, vulns, spin, done, failed):
        # Build bar
        filled = int(self.BAR_WIDTH * pct / 100)
        empty  = self.BAR_WIDTH - filled

        if failed:
            bar_body = self._red("━" * filled) + self._dim("─" * empty)
            icon = "✗"
        elif done:
            bar_body = self._green("━" * self.BAR_WIDTH)
            icon = "✓"
        else:
            bar_body = self._cyan("━" * filled) + self._dim("─" * empty)
            icon = spin

        bar  = f"[{bar_body}]"
        pct_str = self._bold(f"{pct:3d}%")

        if failed:
            status_icon = self._red("✗")
        elif done:
            status_icon = self._green("✓")
        else:
            status_icon = self._cyan(spin)

        vuln_str = ""
        if vulns > 0:
            vuln_str = self._yellow(f"  ⚠ {vulns} finding{'s' if vulns!=1 else ''}")

        phase_str = self._bold(phase[:55])

        line = f"\r  {status_icon} {bar} {pct_str}  {phase_str}{vuln_str}   "

        sys.stdout.write(line)
        sys.stdout.flush()

        if done:
            sys.stdout.write("\n")
            sys.stdout.flush()


# ── Patched scanner that emits progress ──────────────────────────────────────
# ProgressScanner now lives in core/scan_runner.py so the GUI (gui_app.py)
# can drive the exact same scan orchestration as the CLI — no duplicated
# logic, no risk of the two interfaces silently diverging in behavior.
from core.scan_runner import ProgressScanner  # noqa: E402



# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner v5.0 — Full OWASP Top 10",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py -u https://example.com
  python run.py -u https://example.com --zap -d 5 -t 20
  python run.py -u https://app.internal --auth-cookie "session=abc123"
  python run.py -u https://api.example.com --auth-header "Authorization: Bearer token"
  python run.py -u https://example.com --auth-basic admin:password
  python run.py -u https://example.com --modules sqli,xss,security_headers

Available module names (--modules):
  sqli, xss, xxe, directory_traversal,         A03 Injection
  csrf, open_redirect,                          A04 Insecure Design
  security_headers,                             A02/A05 Headers & TLS
  idor,                                         A01 Broken Access Control
  vulnerable_components,                        A06 Vulnerable Components (live OSV.dev CVE lookup)
  broken_auth,                                  A07 Auth Failures
  sri,                                          A08 Software Integrity
  logging_monitoring,                           A09 Logging Failures
  ssrf,                                         A10 SSRF
  api_security,                                 OWASP API Top 10 (BOLA, CORS, schema exposure)
  modern_vulns,                                 SSTI, NoSQLi, JWT, clickjacking, prototype pollution
  js_analysis                                   Deep JS taint analysis, secrets, postMessage
        """,
    )

    parser.add_argument("-u", "--url",         required=True, help="Target URL")
    parser.add_argument("-d", "--depth",       type=int,   default=3,   help="Crawl depth (default: 3)")
    parser.add_argument("-t", "--threads",     type=int,   default=10,  help="Worker threads (default: 10)")
    parser.add_argument("--timeout",           type=int,   default=30,  help="Request timeout seconds")
    parser.add_argument("--delay",             type=float, default=0.5, help="Delay between requests")
    parser.add_argument("--user-agent",        default=None, help="Custom User-Agent string")
    parser.add_argument("--modules",           help="Comma-separated module list")
    parser.add_argument("--zap",               action="store_true", help="Enable OWASP ZAP integration")
    parser.add_argument("--zap-proxy",          default=None, metavar="URL",
                        help="ZAP daemon proxy address (default: http://localhost:8080, "
                             "or $ZAP_PROXY). ZAP must already be running, e.g. "
                             "'zap.sh -daemon -port 8080 -config api.key=YOURKEY'")
    parser.add_argument("--zap-api-key",        default=None, metavar="KEY",
                        help="ZAP API key, if the daemon was started with one (default: $ZAP_API_KEY)")
    # Problem 1: SPA/JS crawling
    parser.add_argument("--browser-crawl",      action="store_true",
                        help="Use Playwright headless browser for crawling — discovers JS-rendered "
                             "SPA routes, hash-router paths, and XHR/fetch API endpoints invisible "
                             "to the standard HTML crawler. Requires: pip install playwright && "
                             "playwright install chromium")
    # Problem 2: form-based authentication
    parser.add_argument("--auth-url",           default=None, metavar="URL",
                        help="URL of the login page for form-based auto-login.")
    parser.add_argument("--auth-user",          default=None, metavar="USERNAME",
                        help="Username / email for form-based login")
    parser.add_argument("--auth-pass",          default=None, metavar="PASSWORD",
                        help="Password for form-based login")
    parser.add_argument("--auth-cookie",        default=None, metavar="COOKIES",
                        help="Session cookies to inject: 'name=value; name2=value2'")
    parser.add_argument("--auth-header",        default=None, metavar="HEADER",
                        help="Auth header to inject: 'Authorization: Bearer TOKEN'")
    parser.add_argument("--auth-basic",         default=None, metavar="USER:PASS",
                        help="HTTP Basic auth credentials: 'username:password'")
    parser.add_argument("--no-pdf",            action="store_true", help="Skip PDF generation")
    parser.add_argument("-o", "--output",      help="Output PDF file path")
    parser.add_argument("-v", "--verbose",     action="store_true", help="Verbose output")
    parser.add_argument("--no-verify-ssl",     action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--no-progress",       action="store_true", help="Disable animated progress bar")

    verify_group = parser.add_argument_group("Verification (proof-of-exploitation)")
    verify_group.add_argument("--interactsh-server", metavar="URL",
                              help="Self-hosted Interactsh server URL for confirmed SSRF/blind-injection callbacks "
                                   "(e.g. https://oob.yourcompany.com). Without this, SSRF findings are capped at "
                                   "'Potential Vulnerability' since exploitation can't be independently proven.")
    verify_group.add_argument("--interactsh-token", metavar="TOKEN",
                              help="Auth token for the Interactsh server, if required")
    verify_group.add_argument("--no-browser-verify", action="store_true",
                              help="Disable Playwright browser-based XSS execution verification "
                                   "(falls back to reflection-only detection, capped at 'Likely Vulnerability')")

    args = parser.parse_args()

    print(BANNER)

    if not args.url.startswith(("http://", "https://")):
        print("[-] Error: URL must start with http:// or https://")
        sys.exit(1)

    # Build scan config
    scan_config: dict = {
        "max_depth":       args.depth,
        "threads":         args.threads,
        "request_timeout": args.timeout,
        "delay":           args.delay,
        "use_zap":         args.zap,
        "zap_proxy":       args.zap_proxy,
        "zap_api_key":     args.zap_api_key,
        "browser_crawl":   args.browser_crawl,
        "auth_url":        args.auth_url,
        "auth_user":       args.auth_user,
        "auth_pass":       args.auth_pass,
        "auth_cookie":     args.auth_cookie,
        "auth_header":     args.auth_header,
        "auth_basic":      args.auth_basic,
        "verify_ssl":      not args.no_verify_ssl,
    }
    if args.user_agent:
        scan_config["user_agent"] = args.user_agent

    if args.auth_cookie:
        cookies = {}
        for pair in args.auth_cookie.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
        scan_config["auth_cookies"] = cookies

    if args.auth_header and ":" in args.auth_header:
        k, v = args.auth_header.split(":", 1)
        scan_config["auth_headers"] = {k.strip(): v.strip()}

    if args.auth_basic and ":" in args.auth_basic:
        u, p = args.auth_basic.split(":", 1)
        scan_config["auth_basic"] = (u, p)

    if args.interactsh_server:
        scan_config["interactsh_server_url"] = args.interactsh_server
    if args.interactsh_token:
        scan_config["interactsh_token"] = args.interactsh_token
    scan_config["browser_verify_xss"] = not args.no_browser_verify

    if args.modules:
        scan_config["enabled_modules"] = [m.strip().lower() for m in args.modules.split(",") if m.strip()]

    # ── Run with progress bar ─────────────────────────────────────────────────
    use_pb = not args.no_progress
    pb = ProgressBar()

    try:
        if use_pb:
            print(f"  Target  : {args.url}")
            print(f"  Depth   : {args.depth}   Threads: {args.threads}\n")
            pb.start()

        ps = ProgressScanner(args.url, scan_config, pb if use_pb else _NoOpPB())
        vulns, stats = ps.run()

        # PDF
        if not args.no_pdf:
            if use_pb:
                pb.update(93, "Generating PDF report…", len(vulns))
            from reports.pdf_generator import PDFReportGenerator
            from config import OUTPUT_DIR
            pdf_gen = PDFReportGenerator()
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = args.output or str(OUTPUT_DIR / f"scan_report_{ts}.pdf")
            report_path = pdf_gen.generate_report(args.url, vulns, stats, out_file)
            if use_pb:
                pb.update(98, "PDF saved", len(vulns))

        if use_pb:
            pb.finish(len(vulns))
        else:
            print(f"\n[+] Scan complete. {len(vulns)} findings.")

        # ── Summary ───────────────────────────────────────────────────────────
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        cls_counts = {"Confirmed": 0, "Likely": 0, "Potential": 0, "Informational": 0}

        for v in vulns:
            sev = v.get("severity", "Info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            cls = v.get("classification", "Potential Vulnerability")
            for key in cls_counts:
                if key in cls:
                    cls_counts[key] += 1
                    break

        dur = ""
        if stats.get("start_time") and stats.get("end_time"):
            dur = str(stats["end_time"] - stats["start_time"]).split(".")[0]

        print(f"""
┌─────────────────────────────────────────────────────┐
│                  SCAN SUMMARY                        │
├─────────────────────────────────────────────────────┤
│  Target     : {args.url[:48]:<48} │
│  Duration   : {dur:<48} │
│  URLs tested: {str(stats.get('urls_crawled', 0)):<48} │
│  Forms tested: {str(stats.get('forms_tested', 0)):<47} │
│  Form fields : {str(stats.get('form_fields_tested', 0)):<47} │
│  URL params  : {str(stats.get('parameters_tested', 0)):<47} │
│  Total finds: {str(len(vulns)):<48} │
├──────────────── Severity ───────────────────────────┤
│  Critical   : {str(sev_counts['Critical']):<48} │
│  High       : {str(sev_counts['High']):<48} │
│  Medium     : {str(sev_counts['Medium']):<48} │
│  Low        : {str(sev_counts['Low']):<48} │
│  Info       : {str(sev_counts['Info']):<48} │
├──────────────── Confidence ─────────────────────────┤
│  Confirmed  : {str(cls_counts['Confirmed']):<48} │
│  Likely     : {str(cls_counts['Likely']):<48} │
│  Potential  : {str(cls_counts['Potential']):<48} │
│  Info       : {str(cls_counts['Informational']):<48} │
└─────────────────────────────────────────────────────┘""")

        if not args.no_pdf:
            print(f"\n  📄 Report : {report_path}")

        # Print confirmed/high findings inline so user sees them immediately
        critical_confirmed = [
            v for v in vulns
            if v.get("severity") in ("Critical", "High")
            and "Confirmed" in v.get("classification", "")
        ]
        if critical_confirmed:
            print(f"\n  ⚠  {len(critical_confirmed)} Confirmed Critical/High finding(s):")
            for v in critical_confirmed[:8]:   # show max 8 inline
                print(f"     [{v.get('severity','?'):8}] {v.get('type','?')}")
                print(f"              {v.get('url','')[:70]}")

        sys.exit(1 if vulns else 0)

    except KeyboardInterrupt:
        if use_pb:
            pb.fail("Interrupted by user")
        print("\n[!] Interrupted")
        sys.exit(130)
    except Exception as exc:
        if use_pb:
            pb.fail(str(exc))
        print(f"\n[-] Fatal error: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


class _NoOpPB:
    """Drop-in ProgressBar replacement when --no-progress is set."""
    def update(self, *a, **k): pass
    def finish(self, *a, **k): pass
    def fail(self, *a, **k):   pass


if __name__ == "__main__":
    main()

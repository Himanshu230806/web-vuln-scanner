#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner v5.0 — Desktop GUI
══════════════════════════════════════════════════════════

A native desktop front-end for the scanner. This does NOT reimplement any
scanning logic — it drives the exact same `core.scan_runner.ProgressScanner`
used by the CLI (run.py), writes to the exact same SQLite scan-history
database (db.py), and produces the exact same PDF report
(reports/pdf_generator.py). Only the interface changed: no browser, no
Flask server, no HTTP — just a native window.

Run:
    pip install customtkinter          # one-time, if not already installed
    python gui_app.py

Layout:
    Scan tab     — target URL, advanced options (auth, crawl, AI, ZAP),
                   live progress bar + phase text + scrolling log console.
    Results tab  — severity summary strip, filterable findings table,
                   full detail panel per finding, "Open PDF Report" button.
    History tab  — every past scan (from scan_history.db), reopen or
                   delete old reports.
"""

import os
import re
import sys
import time
import queue
import threading
import platform
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

# ── Load .env (ZAP proxy config, Interactsh tokens, etc.) ───────────────────
from env_loader import load_env_file
load_env_file(BASE_DIR, verbose=False)

try:
    import customtkinter as ctk
except ImportError:
    print(
        "\nThis GUI requires customtkinter, which isn't installed.\n\n"
        "    pip install customtkinter\n\n"
        "(Everything else the scanner needs — flask, requests, reportlab, "
        "etc. — you already have from requirements.txt.)\n"
    )
    sys.exit(1)

import tkinter as tk
from tkinter import ttk, messagebox

import db
from config import OUTPUT_DIR
from core.scan_runner import ProgressScanner
from reports.pdf_generator import PDFReportGenerator

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High":     "#ea580c",
    "Medium":   "#d97706",
    "Low":      "#16a34a",
    "Info":     "#2563eb",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def strip_ansi(text: str) -> str:
    """Scanner code prints colorama/ANSI-colored lines to stdout — strip
    the escape codes before showing them in the GUI log console."""
    return ANSI_RE.sub("", text)


def format_duration(seconds: float) -> str:
    """Format elapsed seconds as H:MM:SS (or M:SS under an hour)."""
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def HRule(parent, color: str = "#1e293b"):
    """A thin horizontal divider line — used to separate header/content
    sections without the visual weight of a full bordered frame."""
    return ctk.CTkFrame(parent, height=1, fg_color=color)


def open_with_default_app(path: str) -> None:
    """Open a file (PDF report) with whatever the OS considers the default
    viewer — works cross-platform without any extra dependency."""
    try:
        system = platform.system()
        if system == "Windows":
            os.startfile(path)  # type: ignore[attr-defined]
        elif system == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as exc:
        messagebox.showerror("Couldn't open file", f"{path}\n\n{exc}")


def build_scan_config(
    *,
    max_depth: int,
    threads: int,
    timeout: int,
    delay: float,
    browser_crawl: bool,
    use_zap: bool,
    zap_proxy: str,
    zap_api_key: str,
    verify_ssl: bool,
    cookie_str: str,
    header_str: str,
    basic_user: str,
    basic_pass: str,
    auth_url: str,
    auth_user: str,
    auth_pass: str,
) -> Dict:
    """
    Build the scan_config dict the same way run.py's CLI does, field for
    field, so a scan launched from the GUI produces identical results to
    the same options passed on the command line.
    """
    scan_config: Dict = {
        "max_depth":        max_depth,
        "threads":          threads,
        "request_timeout":  timeout,
        "delay":            delay,
        "use_zap":          use_zap,
        "browser_crawl":    browser_crawl,
        "verify_ssl":       verify_ssl,
        "browser_verify_xss": True,
    }

    # ZAP proxy/key — same as run.py's --zap-proxy/--zap-api-key: only set
    # when the user actually typed something, so a blank field falls back
    # to ZAP_PROXY/ZAP_API_KEY from the environment/.env rather than
    # overriding them with an empty string.
    zap_proxy = (zap_proxy or "").strip()
    if zap_proxy:
        scan_config["zap_proxy"] = zap_proxy
    zap_api_key = (zap_api_key or "").strip()
    if zap_api_key:
        scan_config["zap_api_key"] = zap_api_key

    # Cookie string: "name=value,name2=value2" — same comma-separated
    # convention run.py's --auth-cookie parses.
    cookie_str = (cookie_str or "").strip()
    if cookie_str:
        cookies = {}
        for pair in cookie_str.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
        if cookies:
            scan_config["auth_cookies"] = cookies

    header_str = (header_str or "").strip()
    if header_str and ":" in header_str:
        k, v = header_str.split(":", 1)
        scan_config["auth_headers"] = {k.strip(): v.strip()}

    basic_user = (basic_user or "").strip()
    if basic_user and basic_pass:
        scan_config["auth_basic"] = (basic_user, basic_pass)

    auth_url = (auth_url or "").strip()
    if auth_url:
        scan_config["auth_url"]  = auth_url
        scan_config["auth_user"] = (auth_user or "").strip()
        scan_config["auth_pass"] = auth_pass or ""

    return scan_config


class QueueWriter:
    """
    File-like object that redirects print() output into the GUI's
    thread-safe queue as discrete log lines, so the scanner's existing
    console output (phase banners, warnings) shows up
    in the GUI log console without the scanner code needing to know a
    GUI exists.
    """

    def __init__(self, q: "queue.Queue"):
        self.q = q
        self._buf = ""

    def write(self, s: str) -> None:
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.strip("\r")
            if line.strip():
                self.q.put(("log", strip_ansi(line)))

    def flush(self) -> None:
        pass


class GuiProgressAdapter:
    """
    Implements the same duck-typed progress interface ProgressScanner
    expects from run.py's ProgressBar (`update(pct, phase, vulns=0)`),
    but pushes updates into a thread-safe queue instead of drawing to a
    terminal, since Tkinter widgets may only be touched from the main
    thread.
    """

    def __init__(self, q: "queue.Queue"):
        self.q = q

    def update(self, percent: int, phase_text: str, vulns: int = 0) -> None:
        self.q.put(("progress", percent, phase_text, vulns))

    def finish(self, vulns: int = 0) -> None:
        self.q.put(("progress", 100, "Scan complete", vulns))

    def fail(self, message: str) -> None:
        self.q.put(("log", f"[!] {message}"))


# ─────────────────────────────────────────────────────────────────────────
# Main application
# ─────────────────────────────────────────────────────────────────────────

class ScannerApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Web Application Vulnerability Scanner  ·  v5.0")
        self.geometry("1220x820")
        self.minsize(1000, 660)
        try:
            self.configure(fg_color="#0f172a")
        except Exception:
            pass

        db.init_db()

        self.scan_queue: "queue.Queue" = queue.Queue()
        self.scan_thread: Optional[threading.Thread] = None
        self.current_vulns: List[Dict] = []
        self.current_stats: Dict = {}
        self.current_report_path: Optional[str] = None
        self.current_scan_id: Optional[str] = None

        # Live scan timer state
        self.scan_start_ts: Optional[float] = None
        self.timer_active: bool = False
        self.last_duration_str: str = "—"

        self._build_layout()
        self._refresh_history()
        self.after(150, self._poll_queue)

    # ── layout ───────────────────────────────────────────────────────────

    def _build_layout(self):
        self.tabview = ctk.CTkTabview(self, width=1140, height=740)
        self.tabview.pack(fill="both", expand=True, padx=12, pady=12)

        self.tab_scan    = self.tabview.add("🔍  Scan")
        self.tab_results = self.tabview.add("📋  Results")
        self.tab_history = self.tabview.add("🕘  History")

        self._build_scan_tab(self.tab_scan)
        self._build_results_tab(self.tab_results)
        self._build_history_tab(self.tab_history)

    # ── Scan tab ─────────────────────────────────────────────────────────

    def _build_scan_tab(self, parent):
        header_row = ctk.CTkFrame(parent, fg_color="transparent")
        header_row.pack(fill="x", padx=16, pady=(16, 0))
        ctk.CTkLabel(
            header_row, text="🛡", font=ctk.CTkFont(size=26)
        ).pack(side="left", padx=(0, 8))
        title_col = ctk.CTkFrame(header_row, fg_color="transparent")
        title_col.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(
            title_col, text="Web Application Vulnerability Scanner",
            font=ctk.CTkFont(size=22, weight="bold"), anchor="w"
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_col,
            text="Full OWASP Top 10 coverage · systemic false-positive reduction · "
                 "only scan sites you own or have written permission to test.",
            font=ctk.CTkFont(size=12), text_color="#94a3b8", anchor="w"
        ).pack(anchor="w", pady=(2, 0))
        ctk.CTkLabel(
            header_row, text="v5.0", font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#60a5fa", fg_color="#1e293b", corner_radius=6,
            width=44, height=24
        ).pack(side="right")

        HRule(parent).pack(fill="x", padx=16, pady=(14, 14))

        # Target row
        target_row = ctk.CTkFrame(parent, fg_color="transparent")
        target_row.pack(fill="x", padx=16, pady=(0, 8))
        ctk.CTkLabel(target_row, text="Target URL", width=90, anchor="w",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        self.url_entry = ctk.CTkEntry(
            target_row, placeholder_text="https://example.com", height=38,
            corner_radius=8, border_width=1
        )
        self.url_entry.pack(side="left", fill="x", expand=True, padx=8)
        self.start_btn = ctk.CTkButton(
            target_row, text="▶  Start Scan", width=150, height=38,
            corner_radius=8, font=ctk.CTkFont(size=13, weight="bold"),
            command=self._on_start_clicked
        )
        self.start_btn.pack(side="left")

        # Advanced options (collapsible)
        self.adv_visible = False
        self.adv_toggle = ctk.CTkButton(
            parent, text="▸  Advanced Options", width=190, height=28,
            fg_color="transparent", border_width=1, corner_radius=6,
            font=ctk.CTkFont(size=12),
            command=self._toggle_advanced
        )
        self.adv_toggle.pack(anchor="w", padx=16, pady=(6, 4))

        self.adv_frame = ctk.CTkFrame(parent, corner_radius=10)
        # not packed yet — shown on toggle

        self._build_advanced_options(self.adv_frame)

        # Status card: phase, live timer, findings-so-far, all in one place
        prog_frame = ctk.CTkFrame(parent, corner_radius=10)
        prog_frame.pack(fill="x", padx=16, pady=(12, 8))

        status_row = ctk.CTkFrame(prog_frame, fg_color="transparent")
        status_row.pack(fill="x", padx=14, pady=(12, 4))

        phase_col = ctk.CTkFrame(status_row, fg_color="transparent")
        phase_col.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(phase_col, text="STATUS", font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#64748b", anchor="w").pack(anchor="w")
        self.phase_label = ctk.CTkLabel(
            phase_col, text="Ready.", anchor="w", font=ctk.CTkFont(size=14)
        )
        self.phase_label.pack(anchor="w")

        timer_col = ctk.CTkFrame(status_row, fg_color="transparent")
        timer_col.pack(side="left", padx=(24, 0))
        ctk.CTkLabel(timer_col, text="⏱  ELAPSED TIME",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#64748b", anchor="w").pack(anchor="w")
        self.timer_label = ctk.CTkLabel(
            timer_col, text="00:00", anchor="w",
            font=ctk.CTkFont(size=18, weight="bold", family="Consolas"),
            text_color="#60a5fa"
        )
        self.timer_label.pack(anchor="w")

        findings_col = ctk.CTkFrame(status_row, fg_color="transparent")
        findings_col.pack(side="left", padx=(24, 0))
        ctk.CTkLabel(findings_col, text="FINDINGS SO FAR",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#64748b", anchor="w").pack(anchor="w")
        self.vulns_label = ctk.CTkLabel(
            findings_col, text="0", anchor="w",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.vulns_label.pack(anchor="w")

        self.progress_bar = ctk.CTkProgressBar(prog_frame, height=10, corner_radius=5)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=14, pady=(10, 14))

        # Log console
        ctk.CTkLabel(parent, text="Scan Log", anchor="w").pack(
            anchor="w", padx=16, pady=(4, 2)
        )
        self.log_box = ctk.CTkTextbox(
            parent, height=260, font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.log_box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.log_box.configure(state="disabled")

    def _build_advanced_options(self, frame):
        row1 = ctk.CTkFrame(frame, fg_color="transparent")
        row1.pack(fill="x", padx=12, pady=(12, 4))

        def labeled_entry(container, label, default, width=80):
            ctk.CTkLabel(container, text=label, width=100, anchor="w").pack(side="left")
            e = ctk.CTkEntry(container, width=width)
            e.insert(0, str(default))
            e.pack(side="left", padx=(0, 16))
            return e

        self.depth_entry   = labeled_entry(row1, "Crawl depth",  3)
        self.threads_entry = labeled_entry(row1, "Threads",      10)
        self.timeout_entry = labeled_entry(row1, "Timeout (s)",  30)
        self.delay_entry   = labeled_entry(row1, "Delay (s)",    0.5)

        row2 = ctk.CTkFrame(frame, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=4)

        self.browser_crawl_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(row2, text="Browser crawl (SPA / Playwright)",
                        variable=self.browser_crawl_var).pack(side="left", padx=(0, 16))

        self.use_zap_var = tk.BooleanVar(value=False)
        zap_check = ctk.CTkCheckBox(row2, text="Use OWASP ZAP",
                                     variable=self.use_zap_var,
                                     command=lambda: self._toggle_zap_fields())
        zap_check.pack(side="left", padx=(0, 16))

        self.verify_ssl_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(row2, text="Verify SSL",
                        variable=self.verify_ssl_var).pack(side="left", padx=(0, 16))

        # ZAP proxy/API-key row — hidden until "Use OWASP ZAP" is checked.
        # Previously the GUI could only pick up ZAP_API_KEY from .env /
        # the environment (unlike the web UI, which has input fields for
        # this on the scan form) — there was no way to type a key in here.
        self.zap_row = ctk.CTkFrame(frame, fg_color="transparent")
        ctk.CTkLabel(self.zap_row, text="ZAP Proxy", width=100, anchor="w").pack(side="left")
        self.zap_proxy_entry = ctk.CTkEntry(
            self.zap_row, placeholder_text="http://localhost:8080", width=200
        )
        self.zap_proxy_entry.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(self.zap_row, text="API Key", width=60, anchor="w").pack(side="left")
        self.zap_key_entry = ctk.CTkEntry(
            self.zap_row, placeholder_text="leave blank to use $ZAP_API_KEY", width=220, show="•"
        )
        self.zap_key_entry.pack(side="left", padx=(0, 12))
        self.zap_test_btn = ctk.CTkButton(
            self.zap_row, text="Test Connection", width=130, height=28,
            fg_color="transparent", border_width=1,
            command=self._test_zap_connection
        )
        self.zap_test_btn.pack(side="left")
        self.zap_status_label = ctk.CTkLabel(
            self.zap_row, text="", font=ctk.CTkFont(size=11), text_color="#94a3b8"
        )
        self.zap_status_label.pack(side="left", padx=(10, 0))
        # Not packed yet — _toggle_zap_fields() packs/unpacks it.

        ctk.CTkLabel(frame, text="Authentication (optional)",
                     font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=12, pady=(10, 2))

        row3 = ctk.CTkFrame(frame, fg_color="transparent")
        row3.pack(fill="x", padx=12, pady=4)
        ctk.CTkLabel(row3, text="Cookies", width=100, anchor="w").pack(side="left")
        self.cookie_entry = ctk.CTkEntry(
            row3, placeholder_text="session=abc123,role=admin", width=260
        )
        self.cookie_entry.pack(side="left", padx=(0, 16))
        ctk.CTkLabel(row3, text="Header", width=70, anchor="w").pack(side="left")
        self.header_entry = ctk.CTkEntry(
            row3, placeholder_text="Authorization: Bearer TOKEN", width=260
        )
        self.header_entry.pack(side="left")

        row4 = ctk.CTkFrame(frame, fg_color="transparent")
        row4.pack(fill="x", padx=12, pady=4)
        ctk.CTkLabel(row4, text="Basic auth", width=100, anchor="w").pack(side="left")
        self.basic_user_entry = ctk.CTkEntry(row4, placeholder_text="username", width=140)
        self.basic_user_entry.pack(side="left", padx=(0, 6))
        self.basic_pass_entry = ctk.CTkEntry(row4, placeholder_text="password", width=140, show="•")
        self.basic_pass_entry.pack(side="left", padx=(0, 16))

        row5 = ctk.CTkFrame(frame, fg_color="transparent")
        row5.pack(fill="x", padx=12, pady=(4, 12))
        ctk.CTkLabel(row5, text="Login form", width=100, anchor="w").pack(side="left")
        self.auth_url_entry = ctk.CTkEntry(
            row5, placeholder_text="Login page URL (form-based auto-login)", width=260
        )
        self.auth_url_entry.pack(side="left", padx=(0, 6))
        self.auth_user_entry = ctk.CTkEntry(row5, placeholder_text="username", width=110)
        self.auth_user_entry.pack(side="left", padx=(0, 6))
        self.auth_pass_entry = ctk.CTkEntry(row5, placeholder_text="password", width=110, show="•")
        self.auth_pass_entry.pack(side="left")

    def _toggle_advanced(self):
        self.adv_visible = not self.adv_visible
        if self.adv_visible:
            # `after=` keeps it directly below the toggle button regardless
            # of how many other widgets were packed later in build order.
            self.adv_frame.pack(fill="x", padx=16, pady=(0, 8), after=self.adv_toggle)
            self.adv_toggle.configure(text="▾  Advanced Options")
        else:
            self.adv_frame.pack_forget()
            self.adv_toggle.configure(text="▸  Advanced Options")

    def _toggle_zap_fields(self):
        if self.use_zap_var.get():
            self.zap_row.pack(fill="x", padx=12, pady=(0, 8))
        else:
            self.zap_row.pack_forget()

    def _test_zap_connection(self):
        """Tries a live connection to the ZAP daemon with whatever
        proxy/key is currently in the fields (falling back to
        ZAP_PROXY/ZAP_API_KEY from the environment if left blank), and
        reports success/failure right in the GUI instead of only finding
        out once a full scan is underway."""
        proxy   = self.zap_proxy_entry.get().strip() or None
        api_key = self.zap_key_entry.get().strip() or None

        self.zap_status_label.configure(text="Testing…", text_color="#94a3b8")
        self.zap_test_btn.configure(state="disabled")

        def worker():
            try:
                from modules import zap_integration
                if not zap_integration.ZAP_LIBRARY_AVAILABLE:
                    self.scan_queue.put((
                        "zap_test_result", False,
                        "✗ python-owasp-zap-v2.4 not installed "
                        "(pip install python-owasp-zap-v2.4)"
                    ))
                    return
                zap = zap_integration.ZAPIntegration(enabled=True, proxy=proxy, api_key=api_key)
                ok = zap.is_available()
                version_str = ""
                if ok:
                    try:
                        version_str = f" (v{zap.zap.core.version})"
                    except Exception:
                        pass
                self.scan_queue.put((
                    "zap_test_result", ok,
                    f"✓ Connected{version_str}" if ok else "✗ Could not connect — is ZAP running?"
                ))
            except Exception as exc:
                self.scan_queue.put(("zap_test_result", False, f"✗ {exc}"))

        threading.Thread(target=worker, daemon=True).start()

    # ── Results tab ──────────────────────────────────────────────────────

    def _build_results_tab(self, parent):
        header_row = ctk.CTkFrame(parent, fg_color="transparent")
        header_row.pack(fill="x", padx=16, pady=(16, 4))
        ctk.CTkLabel(
            header_row, text="Scan Results", font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left")
        self.duration_summary_label = ctk.CTkLabel(
            header_row, text="", font=ctk.CTkFont(size=12), text_color="#94a3b8"
        )
        self.duration_summary_label.pack(side="right")

        summary = ctk.CTkFrame(parent, fg_color="transparent")
        summary.pack(fill="x", padx=16, pady=(8, 8))
        self.severity_count_labels: Dict[str, ctk.CTkLabel] = {}
        for sev in SEVERITY_ORDER:
            card = ctk.CTkFrame(summary, fg_color=SEVERITY_COLORS[sev], corner_radius=10)
            card.pack(side="left", fill="x", expand=True, padx=4)
            ctk.CTkLabel(card, text=sev.upper(), text_color="white",
                         font=ctk.CTkFont(size=11, weight="bold")).pack(pady=(10, 0))
            count_lbl = ctk.CTkLabel(card, text="0", text_color="white",
                                      font=ctk.CTkFont(size=26, weight="bold"))
            count_lbl.pack(pady=(0, 10))
            self.severity_count_labels[sev] = count_lbl

        toolbar = ctk.CTkFrame(parent, fg_color="transparent")
        toolbar.pack(fill="x", padx=16, pady=(0, 8))
        ctk.CTkLabel(toolbar, text="Filter:").pack(side="left", padx=(0, 6))
        self.filter_var = tk.StringVar(value="All")
        filter_menu = ctk.CTkOptionMenu(
            toolbar, values=["All"] + SEVERITY_ORDER, variable=self.filter_var,
            command=lambda _v: self._refresh_findings_table()
        )
        filter_menu.pack(side="left", padx=(0, 16))
        ctk.CTkButton(toolbar, text="Open PDF Report", width=150,
                      command=self._open_current_report).pack(side="left", padx=(0, 8))
        ctk.CTkButton(toolbar, text="Reveal in Folder", width=150,
                      command=self._reveal_report_folder).pack(side="left")

        table_frame = ctk.CTkFrame(parent)
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        self._style_ttk_dark()

        columns = ("severity", "type", "url", "confidence", "classification")
        self.findings_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", height=10,
            style="Dark.Treeview"
        )
        headings = {
            "severity": "Severity", "type": "Type", "url": "URL",
            "confidence": "Conf.", "classification": "Classification",
        }
        widths = {"severity": 80, "type": 220, "url": 340, "confidence": 60, "classification": 160}
        for col in columns:
            self.findings_tree.heading(col, text=headings[col],
                                        command=lambda c=col: self._sort_findings(c))
            self.findings_tree.column(col, width=widths[col], anchor="w")
        self.findings_tree.pack(fill="both", expand=True, side="left")

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.findings_tree.yview)
        scroll.pack(side="right", fill="y")
        self.findings_tree.configure(yscrollcommand=scroll.set)
        self.findings_tree.bind("<<TreeviewSelect>>", self._on_finding_selected)

        ctk.CTkLabel(parent, text="Finding Detail", anchor="w").pack(
            anchor="w", padx=16, pady=(4, 2)
        )
        self.detail_box = ctk.CTkTextbox(parent, height=180)
        self.detail_box.pack(fill="both", expand=False, padx=16, pady=(0, 16))
        self.detail_box.configure(state="disabled")

    def _style_ttk_dark(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Dark.Treeview",
                         background="#1e293b", fieldbackground="#1e293b",
                         foreground="#e2e8f0", rowheight=26, borderwidth=0)
        style.configure("Dark.Treeview.Heading",
                         background="#0f172a", foreground="#e2e8f0",
                         relief="flat")
        style.map("Dark.Treeview", background=[("selected", "#2563eb")])

    # ── History tab ──────────────────────────────────────────────────────

    def _build_history_tab(self, parent):
        toolbar = ctk.CTkFrame(parent, fg_color="transparent")
        toolbar.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkButton(toolbar, text="Refresh", width=100,
                      command=self._refresh_history).pack(side="left", padx=(0, 8))
        ctk.CTkButton(toolbar, text="Open Report", width=120,
                      command=self._open_selected_history_report).pack(side="left", padx=(0, 8))
        ctk.CTkButton(toolbar, text="Delete Scan", width=120,
                      fg_color="#dc2626", hover_color="#991b1b",
                      command=self._delete_selected_history_scan).pack(side="left")

        table_frame = ctk.CTkFrame(parent)
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        columns = ("date", "target", "status", "duration", "findings", "report")
        self.history_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", style="Dark.Treeview"
        )
        headings = {"date": "Date", "target": "Target", "status": "Status",
                    "duration": "Duration", "findings": "Findings", "report": "Report"}
        widths = {"date": 150, "target": 300, "status": 90, "duration": 90,
                  "findings": 80, "report": 230}
        for col in columns:
            self.history_tree.heading(col, text=headings[col])
            self.history_tree.column(col, width=widths[col], anchor="w")
        self.history_tree.pack(fill="both", expand=True, side="left")

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.history_tree.yview)
        scroll.pack(side="right", fill="y")
        self.history_tree.configure(yscrollcommand=scroll.set)

    def _refresh_history(self):
        for row in self.history_tree.get_children():
            self.history_tree.delete(row)
        try:
            scans = db.list_scans(limit=100)
        except Exception as exc:
            scans = []
            self._append_log(f"[!] Could not load scan history: {exc}")
        for scan in scans:
            started = (scan.get("started_at") or "")[:19].replace("T", " ")
            duration = "—"
            try:
                if scan.get("started_at") and scan.get("finished_at"):
                    t0 = datetime.fromisoformat(scan["started_at"])
                    t1 = datetime.fromisoformat(scan["finished_at"])
                    duration = format_duration((t1 - t0).total_seconds())
            except Exception:
                pass
            self.history_tree.insert(
                "", "end", iid=scan["id"],
                values=(
                    started,
                    scan.get("url", ""),
                    scan.get("status", ""),
                    duration,
                    scan.get("vuln_count", 0),
                    scan.get("report_path") or "—",
                )
            )

    def _open_selected_history_report(self):
        sel = self.history_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select a scan from the list first.")
            return
        scan = db.get_scan(sel[0])
        report_path = scan.get("report_path") if scan else None
        if not report_path or not Path(report_path).exists():
            messagebox.showwarning("No report", "No PDF report is available for this scan.")
            return
        open_with_default_app(report_path)

    def _delete_selected_history_scan(self):
        sel = self.history_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select a scan from the list first.")
            return
        if not messagebox.askyesno("Delete scan", "Delete this scan's history record? "
                                                    "(The PDF file itself is not deleted.)"):
            return
        db.delete_scan(sel[0])
        self._refresh_history()

    # ── scan lifecycle ───────────────────────────────────────────────────

    def _on_start_clicked(self):
        url = self.url_entry.get().strip()
        if not url.startswith(("http://", "https://")):
            messagebox.showerror("Invalid URL", "Target URL must start with http:// or https://")
            return
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan running", "A scan is already in progress.")
            return

        try:
            scan_config = build_scan_config(
                max_depth=int(self.depth_entry.get() or 3),
                threads=int(self.threads_entry.get() or 10),
                timeout=int(self.timeout_entry.get() or 30),
                delay=float(self.delay_entry.get() or 0.5),
                browser_crawl=self.browser_crawl_var.get(),
                use_zap=self.use_zap_var.get(),
                zap_proxy=self.zap_proxy_entry.get(),
                zap_api_key=self.zap_key_entry.get(),
                verify_ssl=self.verify_ssl_var.get(),
                cookie_str=self.cookie_entry.get(),
                header_str=self.header_entry.get(),
                basic_user=self.basic_user_entry.get(),
                basic_pass=self.basic_pass_entry.get(),
                auth_url=self.auth_url_entry.get(),
                auth_user=self.auth_user_entry.get(),
                auth_pass=self.auth_pass_entry.get(),
            )
        except ValueError as exc:
            messagebox.showerror("Invalid option", f"Check the advanced options: {exc}")
            return

        scan_id = str(uuid.uuid4())[:8]
        self.current_scan_id = scan_id
        try:
            db.create_scan(scan_id, url)
        except Exception as exc:
            self._append_log(f"[!] Could not create scan history record: {exc}")

        self.current_vulns = []
        self.current_stats = {}
        self.current_report_path = None
        self._clear_log()
        self._append_log(f"[*] Starting scan of {url} (scan id {scan_id})")
        self.progress_bar.set(0)
        self.phase_label.configure(text="Starting…")
        self.vulns_label.configure(text="0")
        self.start_btn.configure(state="disabled", text="⏳  Scanning…")
        self.tabview.set("🔍  Scan")

        self.scan_start_ts = time.monotonic()
        self.timer_active = True
        self.timer_label.configure(text="00:00", text_color="#60a5fa")
        self._tick_timer()

        self.scan_thread = threading.Thread(
            target=self._scan_worker, args=(scan_id, url, scan_config), daemon=True
        )
        self.scan_thread.start()

    def _tick_timer(self):
        """Updates the live elapsed-time display once per second while a
        scan is running. Stops rescheduling itself once the scan ends."""
        if self.timer_active and self.scan_start_ts is not None:
            elapsed = time.monotonic() - self.scan_start_ts
            self.timer_label.configure(text=format_duration(elapsed))
            self.after(1000, self._tick_timer)

    def _scan_worker(self, scan_id: str, url: str, scan_config: Dict):
        """Runs on a background thread — must not touch Tk widgets directly."""
        q = self.scan_queue
        adapter = GuiProgressAdapter(q)
        old_stdout = sys.stdout
        sys.stdout = QueueWriter(q)
        try:
            ps = ProgressScanner(url, scan_config, adapter)
            vulns, stats = ps.run()

            q.put(("log", "[*] Generating PDF report…"))
            pdf_gen = PDFReportGenerator()
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = str(OUTPUT_DIR / f"scan_{scan_id}_{ts}.pdf")
            pdf_gen.generate_report(url, vulns, stats, report_path)

            try:
                db.finish_scan(scan_id, vulns, stats, report_path)
            except Exception as exc:
                q.put(("log", f"[!] Could not save scan history: {exc}"))

            q.put(("done", vulns, stats, report_path))
        except Exception as exc:
            try:
                db.mark_scan_failed(scan_id, str(exc))
            except Exception:
                pass
            q.put(("error", str(exc)))
        finally:
            sys.stdout = old_stdout

    def _poll_queue(self):
        try:
            while True:
                msg = self.scan_queue.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, pct, phase, vulns = msg
                    self.progress_bar.set(max(0.0, min(1.0, pct / 100)))
                    self.phase_label.configure(text=phase)
                    self.vulns_label.configure(text=str(vulns))
                elif kind == "log":
                    self._append_log(msg[1])
                elif kind == "done":
                    _, vulns, stats, report_path = msg
                    self._on_scan_done(vulns, stats, report_path)
                elif kind == "error":
                    self._on_scan_error(msg[1])
                elif kind == "zap_test_result":
                    _, ok, message = msg
                    self.zap_status_label.configure(
                        text=message, text_color="#22c55e" if ok else "#ef4444"
                    )
                    self.zap_test_btn.configure(state="normal")
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _stop_timer(self) -> str:
        """Freezes the live timer and returns the final elapsed-time string."""
        self.timer_active = False
        if self.scan_start_ts is not None:
            self.last_duration_str = format_duration(time.monotonic() - self.scan_start_ts)
        return self.last_duration_str

    def _on_scan_done(self, vulns: List[Dict], stats: Dict, report_path: str):
        self.current_vulns = vulns
        self.current_stats = stats
        self.current_report_path = report_path
        duration = self._stop_timer()
        self.timer_label.configure(text=duration, text_color="#22c55e")
        self.start_btn.configure(state="normal", text="▶  Start Scan")
        self.progress_bar.set(1.0)
        self.phase_label.configure(text=f"✓ Scan complete — {len(vulns)} finding(s)")
        self._append_log(
            f"[+] Scan complete in {duration}. {len(vulns)} finding(s). Report: {report_path}"
        )
        self.duration_summary_label.configure(text=f"Scan took {duration}")
        self._refresh_findings_table()
        self._refresh_history()
        self.tabview.set("📋  Results")

    def _on_scan_error(self, message: str):
        duration = self._stop_timer()
        self.timer_label.configure(text=duration, text_color="#ef4444")
        self.start_btn.configure(state="normal", text="▶  Start Scan")
        self.phase_label.configure(text="✗ Scan failed")
        self._append_log(f"[-] Scan failed after {duration}: {message}")
        self._refresh_history()
        messagebox.showerror("Scan failed", message)

    # ── log console ──────────────────────────────────────────────────────

    def _append_log(self, line: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    # ── findings table ───────────────────────────────────────────────────

    def _refresh_findings_table(self):
        for row in self.findings_tree.get_children():
            self.findings_tree.delete(row)

        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for v in self.current_vulns:
            sev = v.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1
        for sev, lbl in self.severity_count_labels.items():
            lbl.configure(text=str(counts.get(sev, 0)))

        filt = self.filter_var.get()
        shown = [
            v for v in self.current_vulns
            if filt == "All" or v.get("severity", "Info") == filt
        ]
        shown.sort(key=lambda v: (
            SEVERITY_ORDER.index(v.get("severity", "Info"))
            if v.get("severity", "Info") in SEVERITY_ORDER else 99,
            -v.get("confidence", 0)
        ))

        for idx, v in enumerate(shown):
            iid = str(idx)
            self.findings_tree.insert(
                "", "end", iid=iid,
                values=(
                    v.get("severity", "Info"),
                    v.get("type", "Unknown"),
                    v.get("url", ""),
                    f"{v.get('confidence', '?')}%",
                    v.get("classification", ""),
                )
            )
        self._filtered_findings = shown

    def _sort_findings(self, column: str):
        if not getattr(self, "_filtered_findings", None):
            return
        reverse = getattr(self, "_last_sort_col", None) == column and not getattr(
            self, "_last_sort_rev", False
        )
        self._filtered_findings.sort(
            key=lambda v: str(v.get(
                {"severity": "severity", "type": "type", "url": "url",
                 "confidence": "confidence", "classification": "classification"}[column],
                ""
            )),
            reverse=reverse,
        )
        self._last_sort_col = column
        self._last_sort_rev = reverse
        for row in self.findings_tree.get_children():
            self.findings_tree.delete(row)
        for idx, v in enumerate(self._filtered_findings):
            self.findings_tree.insert(
                "", "end", iid=str(idx),
                values=(
                    v.get("severity", "Info"), v.get("type", "Unknown"),
                    v.get("url", ""), f"{v.get('confidence', '?')}%",
                    v.get("classification", ""),
                )
            )

    def _on_finding_selected(self, _event):
        sel = self.findings_tree.selection()
        if not sel or not getattr(self, "_filtered_findings", None):
            return
        try:
            v = self._filtered_findings[int(sel[0])]
        except (ValueError, IndexError):
            return

        lines = [
            f"Type: {v.get('type', 'Unknown')}",
            f"Severity: {v.get('severity', 'Info')}   "
            f"Confidence: {v.get('confidence', '?')}%   "
            f"Classification: {v.get('classification', '')}",
            f"URL: {v.get('url', '')}",
        ]
        if v.get("parameter"):
            lines.append(f"Parameter: {v.get('parameter')}")
        if v.get("owasp"):
            lines.append(f"OWASP: {v.get('owasp')}")
        lines.append("")
        lines.append("Description:")
        lines.append(str(v.get("description") or "—"))
        lines.append("")
        lines.append("Evidence:")
        lines.append(str(v.get("evidence") or v.get("details") or "—"))
        lines.append("")
        lines.append("Verification method:")
        lines.append(str(v.get("verification_method") or "Pattern match (unverified)"))
        lines.append("")
        lines.append("Recommended fix:")
        lines.append(str(v.get("remediation") or "—"))
        if v.get("fp_reduction_note"):
            lines.append("")
            lines.append("FP-reduction note:")
            lines.append(str(v.get("fp_reduction_note")))

        self.detail_box.configure(state="normal")
        self.detail_box.delete("1.0", "end")
        self.detail_box.insert("1.0", "\n".join(lines))
        self.detail_box.configure(state="disabled")

    # ── report actions ───────────────────────────────────────────────────

    def _open_current_report(self):
        if not self.current_report_path or not Path(self.current_report_path).exists():
            messagebox.showinfo("No report yet", "Run a scan first, or open one from History.")
            return
        open_with_default_app(self.current_report_path)

    def _reveal_report_folder(self):
        folder = str(OUTPUT_DIR)
        open_with_default_app(folder)


def main():
    app = ScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()

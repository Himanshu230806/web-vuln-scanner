"""
Persistent SQLite database for scan history.
Stores scan metadata and vulnerability records across restarts.
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from config import BASE_DIR

DB_PATH = BASE_DIR / "scan_history.db"
logger = logging.getLogger(__name__)

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Return a thread-local SQLite connection (creates it on first use)."""
    if not hasattr(_local, "conn") or _local.conn is None:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        _local.conn = conn
    return _local.conn


def init_db() -> None:
    """Create tables if they don't already exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          TEXT    PRIMARY KEY,
            url         TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'running',
            started_at  TEXT    NOT NULL,
            finished_at TEXT,
            vuln_count  INTEGER DEFAULT 0,
            report_path TEXT,
            stats_json  TEXT
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     TEXT    NOT NULL REFERENCES scans(id),
            vuln_type   TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            url         TEXT    NOT NULL,
            parameter   TEXT,
            description TEXT,
            details_json TEXT,
            found_at    TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scans_url  ON scans(url);
    """)
    conn.commit()
    logger.debug("Database initialised at %s", DB_PATH)


def create_scan(scan_id: str, url: str) -> None:
    conn = _get_conn()
    conn.execute(
        "INSERT INTO scans (id, url, started_at) VALUES (?, ?, ?)",
        (scan_id, url, datetime.utcnow().isoformat()),
    )
    conn.commit()


def finish_scan(
    scan_id: str,
    vulnerabilities: List[Dict],
    stats: Dict,
    report_path: Optional[str] = None,
) -> None:
    conn = _get_conn()
    # Save each vuln
    for vuln in vulnerabilities:
        details = {k: v for k, v in vuln.items()
                   if k not in ("type", "severity", "url", "parameter", "description")}
        conn.execute(
            """INSERT INTO vulnerabilities
               (scan_id, vuln_type, severity, url, parameter, description, details_json, found_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                vuln.get("type", "Unknown"),
                vuln.get("severity", "Info"),
                vuln.get("url", ""),
                vuln.get("parameter", ""),
                vuln.get("description", ""),
                json.dumps(details),
                vuln.get("timestamp", datetime.utcnow().isoformat()),
            ),
        )
    conn.execute(
        """UPDATE scans
           SET status='done', finished_at=?, vuln_count=?, report_path=?, stats_json=?
           WHERE id=?""",
        (
            datetime.utcnow().isoformat(),
            len(vulnerabilities),
            str(report_path) if report_path else None,
            json.dumps(stats, default=str),
            scan_id,
        ),
    )
    conn.commit()


def get_scan(scan_id: str) -> Optional[Dict]:
    row = _get_conn().execute(
        "SELECT * FROM scans WHERE id=?", (scan_id,)
    ).fetchone()
    return dict(row) if row else None


def get_scan_vulns(scan_id: str) -> List[Dict]:
    rows = _get_conn().execute(
        "SELECT * FROM vulnerabilities WHERE scan_id=? ORDER BY id", (scan_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def list_scans(limit: int = 50) -> List[Dict]:
    rows = _get_conn().execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def mark_scan_failed(scan_id: str, error: str) -> None:
    conn = _get_conn()
    conn.execute(
        "UPDATE scans SET status='failed', finished_at=?, stats_json=? WHERE id=?",
        (datetime.utcnow().isoformat(), json.dumps({"error": error}), scan_id),
    )
    conn.commit()

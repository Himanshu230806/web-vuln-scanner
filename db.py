"""
Persistent SQLite database for scan history.
Stores scan metadata and vulnerability records across restarts.
DB_PATH is read from the DB_PATH environment variable so Render's
persistent disk is used automatically in production.
"""

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from config import BASE_DIR

# Allow the DB path to be overridden via environment variable (used in production)
DB_PATH = Path(os.environ.get("DB_PATH", str(BASE_DIR / "scan_history.db")))
logger  = logging.getLogger(__name__)

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Return a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return _local.conn


def init_db() -> None:
    """Create tables and run lightweight migrations."""
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
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      TEXT    NOT NULL REFERENCES scans(id),
            vuln_type    TEXT    NOT NULL,
            severity     TEXT    NOT NULL DEFAULT 'Info',
            url          TEXT    NOT NULL,
            parameter    TEXT,
            description  TEXT,
            owasp        TEXT,
            details_json TEXT,
            found_at     TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scans_url  ON scans(url);
        CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(started_at DESC);
    """)
    conn.commit()

    # Lightweight migrations — add columns that didn't exist in older schemas
    _migrate(conn, "vulnerabilities", "owasp", "TEXT")
    _migrate(conn, "vulnerabilities", "details_json", "TEXT")
    logger.debug("Database initialised at %s", DB_PATH)


def _migrate(conn: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    """Add a column if it doesn't exist (idempotent ALTER TABLE)."""
    try:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
            conn.commit()
            logger.info("DB migration: added column %s.%s", table, column)
    except Exception as exc:
        logger.warning("DB migration skipped (%s.%s): %s", table, column, exc)


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
    for vuln in vulnerabilities:
        details = {k: v for k, v in vuln.items()
                   if k not in ("type", "severity", "url", "parameter", "description", "owasp")}
        conn.execute(
            """INSERT INTO vulnerabilities
               (scan_id, vuln_type, severity, url, parameter, description, owasp, details_json, found_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                vuln.get("type",        "Unknown"),
                vuln.get("severity",    "Info"),
                vuln.get("url",         ""),
                vuln.get("parameter",   ""),
                vuln.get("description", ""),
                vuln.get("owasp",       ""),
                json.dumps(details, default=str),
                vuln.get("timestamp",   datetime.utcnow().isoformat()),
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
        """SELECT * FROM vulnerabilities WHERE scan_id=?
           ORDER BY
             CASE severity
               WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3
               WHEN 'Low' THEN 4 ELSE 5
             END, id""",
        (scan_id,)
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


def delete_scan(scan_id: str) -> None:
    """Delete a scan and all its vulnerabilities."""
    conn = _get_conn()
    conn.execute("DELETE FROM vulnerabilities WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()


def get_stats() -> Dict:
    """Return aggregate statistics across all scans."""
    conn = _get_conn()
    total_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE status='done'").fetchone()[0]
    total_vulns = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    by_severity = dict(conn.execute(
        "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
    ).fetchall())
    return {
        "total_scans":   total_scans,
        "total_vulns":   total_vulns,
        "by_severity":   by_severity,
    }

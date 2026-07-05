"""
db.py - SQLite database for storing parsed log entries and detected alerts.
"""

import sqlite3
from datetime import datetime, timedelta
from typing import List, Optional

DB_PATH = "log_analyzer.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS log_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    host TEXT,
    process TEXT,
    pid INTEGER,
    message TEXT,
    raw TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    source_ip TEXT,
    username TEXT,
    details TEXT,
    emailed INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
"""


def connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def insert_log_entry(conn: sqlite3.Connection, entry) -> None:
    conn.execute(
        "INSERT INTO log_entries (timestamp, host, process, pid, message, raw) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (entry.timestamp.isoformat(), entry.host, entry.process, entry.pid, entry.message, entry.raw),
    )


def insert_log_entries(conn: sqlite3.Connection, entries) -> None:
    for entry in entries:
        insert_log_entry(conn, entry)
    conn.commit()


def insert_alert(conn: sqlite3.Connection, alert) -> int:
    cursor = conn.execute(
        "INSERT INTO alerts (timestamp, threat_type, severity, score, source_ip, username, details, emailed) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            alert.timestamp.isoformat(),
            alert.threat_type,
            alert.severity,
            alert.score,
            alert.source_ip,
            alert.username,
            alert.details,
            int(alert.emailed),
        ),
    )
    conn.commit()
    return cursor.lastrowid


def insert_alerts(conn: sqlite3.Connection, alerts) -> None:
    for alert in alerts:
        insert_alert(conn, alert)


def mark_emailed(conn: sqlite3.Connection, alert_id: int) -> None:
    conn.execute("UPDATE alerts SET emailed = 1 WHERE id = ?", (alert_id,))
    conn.commit()


def count_recent_alerts_for_ip(conn: sqlite3.Connection, ip: str, hours: int = 24) -> int:
    """Used by the threat-scoring engine: repeat offenders score higher."""
    if not ip:
        return 0
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    row = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE source_ip = ? AND timestamp >= ?",
        (ip, cutoff),
    ).fetchone()
    return row[0] if row else 0


def get_all_alerts(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute("SELECT * FROM alerts ORDER BY score DESC, timestamp DESC").fetchall()


def get_all_log_entries(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute("SELECT * FROM log_entries ORDER BY timestamp DESC").fetchall()


def get_alert_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
    return row[0] if row else 0

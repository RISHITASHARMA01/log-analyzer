import hashlib
import json
import sqlite3


def store_alerts(alerts, db_path="security_alerts.db"):
    conn = sqlite3.connect(db_path)

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                fingerprint TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                platform TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                technique_id TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)

        inserted = 0

        for alert in alerts:
            identity = [
                alert.get(key) for key in (
                    "rule_id", "timestamp", "platform",
                    "host", "username", "source_ip", "evidence"
                )
            ]

            fingerprint = hashlib.sha256(
                json.dumps(identity).encode()
            ).hexdigest()

            cursor = conn.execute("""
                INSERT OR IGNORE INTO security_alerts
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                fingerprint,
                alert["timestamp"],
                alert["platform"],
                alert["severity"],
                alert["score"],
                alert["technique_id"],
                json.dumps(alert)
            ))

            inserted += cursor.rowcount

        conn.commit()
        return inserted

    finally:
        conn.close()

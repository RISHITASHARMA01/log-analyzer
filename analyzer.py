"""
analyzer.py - Main entry point. Ties together parser.py, detector.py, db.py,
alerts.py and report.py.

Usage:
    python3 analyzer.py --sample     # test with a generated sample log
    sudo python3 analyzer.py         # analyze real system logs (needs read
                                      # access to /var/log/auth.log, /var/log/syslog)
    python3 analyzer.py --watch      # live monitoring - tails the log files
"""

import argparse
import os
import time
from datetime import datetime, timedelta

import db
import report
from alerts import send_email_alerts
from detector import run_all_detectors
from parser import parse_line, parse_lines

REAL_LOG_PATHS = ["/var/log/auth.log", "/var/log/syslog"]
WATCH_POLL_SECONDS = 5
WATCH_WINDOW_MINUTES = 30  # how much history to keep in memory for windowed detectors


def generate_sample_log(now: datetime = None) -> list:
    """Build a synthetic set of syslog lines covering all 7 threat types
    plus normal, benign traffic - for testing without real system logs."""
    now = now or datetime.now()

    def fmt(dt: datetime) -> str:
        return f"{dt.strftime('%b')} {dt.day} {dt.strftime('%H:%M:%S')}"

    lines = []
    host = "ubuntu-server"

    # --- benign traffic -----------------------------------------------
    t = now - timedelta(hours=2)
    lines.append(f"{fmt(t)} {host} sshd[1001]: Accepted password for rishita from 10.0.0.5 port 51000 ssh2")
    lines.append(f"{fmt(t + timedelta(seconds=1))} {host} CRON[1002]: (root) CMD (run-parts /etc/cron.hourly)")
    lines.append(f"{fmt(t + timedelta(minutes=5))} {host} systemd[1]: Started Daily apt download activities.")

    # --- 1. Brute Force Attack: 7 failed logins from one IP -----------
    attacker_ip = "203.0.113.10"
    t = now - timedelta(minutes=20)
    for i in range(7):
        lines.append(f"{fmt(t + timedelta(seconds=i * 20))} {host} sshd[2000]: Failed password for admin from {attacker_ip} port {40000+i} ssh2")

    # --- 2. Distributed Attack: 'root' attacked from 6 different IPs --
    t = now - timedelta(minutes=15)
    for i, ip in enumerate(["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5", "198.51.100.6"]):
        lines.append(f"{fmt(t + timedelta(seconds=i * 30))} {host} sshd[2100]: Failed password for root from {ip} port {42000+i} ssh2")

    # --- 3. User Enumeration: 6 invalid usernames from one IP ----------
    enum_ip = "198.51.100.22"
    t = now - timedelta(minutes=10)
    for i, user in enumerate(["administrator", "test", "guest", "oracle", "postgres", "backup"]):
        lines.append(f"{fmt(t + timedelta(seconds=i * 15))} {host} sshd[2200]: Failed password for invalid user {user} from {enum_ip} port {43000+i} ssh2")

    # --- 4. Sudo Abuse: unauthorized sudo attempts ----------------------
    t = now - timedelta(minutes=8)
    lines.append(f"{fmt(t)} {host} sudo: intern : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/intern ; USER=root ; COMMAND=/bin/cat /etc/shadow")
    lines.append(f"{fmt(t + timedelta(seconds=10))} {host} sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1002 euid=0 tty=/dev/pts/1 ruser=intern rhost=  user=intern")

    # --- 5. New User Creation: suspicious privileged account -----------
    t = now - timedelta(minutes=6)
    lines.append(f"{fmt(t)} {host} useradd[2300]: new user: name=eviluser, UID=0, GID=0, home=/home/eviluser, shell=/bin/bash")

    # --- 6. Off-Hours Login: successful login at 2:30 AM ----------------
    off_hours_time = now.replace(hour=2, minute=30, second=0, microsecond=0)
    if off_hours_time > now:
        off_hours_time -= timedelta(days=1)
    lines.append(f"{fmt(off_hours_time)} {host} sshd[2400]: Accepted password for ops from 192.0.2.77 port 50500 ssh2")

    # --- 7. Root Login Attempt: failed + successful direct root login --
    t = now - timedelta(minutes=3)
    lines.append(f"{fmt(t)} {host} sshd[2500]: Failed password for root from 192.0.2.99 port 44000 ssh2")
    lines.append(f"{fmt(t + timedelta(seconds=5))} {host} sshd[2500]: Accepted password for root from 192.0.2.99 port 44001 ssh2")

    lines.sort(key=lambda line: parse_line(line).timestamp if parse_line(line) else now)
    return lines


def _print_alerts(alerts):
    if not alerts:
        print("No threats detected.")
        return
    print(f"\n{len(alerts)} alert(s) detected:\n")
    for alert in alerts:
        print(f"  [{alert.severity:8s}] score={alert.score:3d}  {alert.threat_type:22s}  {alert.details}")


def _process(entries, conn, send_emails=True):
    db.insert_log_entries(conn, entries)
    alerts = run_all_detectors(entries, db_conn=conn)
    db.insert_alerts(conn, alerts)
    if send_emails:
        sent = send_email_alerts([a for a in alerts if a.severity in ("HIGH", "CRITICAL")])
        if sent:
            print(f"  [alerts] {sent} email(s) sent for HIGH/CRITICAL threats")
    return alerts


def run_sample(conn, args):
    print("Generating sample log data covering all 7 threat types...")
    lines = generate_sample_log()
    entries = parse_lines(lines)
    print(f"Parsed {len(entries)} log entries.")
    alerts = _process(entries, conn, send_emails=not args.no_email)
    _print_alerts(alerts)
    path = report.generate_report(alerts, len(entries), output_path=args.report)
    print(f"\nReport written to {path}")


def run_real_logs(conn, args):
    paths = [p for p in REAL_LOG_PATHS if os.path.exists(p)]
    if not paths:
        print("No readable log files found. Try: sudo python3 analyzer.py")
        return
    entries = []
    for path in paths:
        if not os.access(path, os.R_OK):
            print(f"Skipping {path} (permission denied - try running with sudo)")
            continue
        from parser import parse_file
        file_entries = parse_file(path)
        print(f"Parsed {len(file_entries)} entries from {path}")
        entries.extend(file_entries)
    entries.sort(key=lambda e: e.timestamp)
    alerts = _process(entries, conn, send_emails=not args.no_email)
    _print_alerts(alerts)
    path = report.generate_report(alerts, len(entries), output_path=args.report)
    print(f"\nReport written to {path}")


def run_watch(conn, args):
    paths = [p for p in REAL_LOG_PATHS if os.path.exists(p) and os.access(p, os.R_OK)]
    if not paths:
        print("No readable log files found. Try: sudo python3 analyzer.py --watch")
        return

    print(f"Watching {', '.join(paths)} - checking every {WATCH_POLL_SECONDS}s. Press Ctrl+C to stop.\n")
    offsets = {p: os.path.getsize(p) for p in paths}  # start from end of file
    recent_entries = []
    seen_alert_keys = set()

    try:
        while True:
            new_lines = []
            for path in paths:
                with open(path, "r", errors="replace") as f:
                    f.seek(offsets[path])
                    new_lines.extend(f.readlines())
                    offsets[path] = f.tell()

            if new_lines:
                new_entries = parse_lines(new_lines)
                if new_entries:
                    db.insert_log_entries(conn, new_entries)
                    recent_entries.extend(new_entries)
                    cutoff = datetime.now() - timedelta(minutes=WATCH_WINDOW_MINUTES)
                    recent_entries = [e for e in recent_entries if e.timestamp >= cutoff]

                    alerts = run_all_detectors(recent_entries, db_conn=conn)
                    new_alerts = []
                    for alert in alerts:
                        key = (alert.threat_type, alert.source_ip, alert.username, alert.timestamp)
                        if key not in seen_alert_keys:
                            seen_alert_keys.add(key)
                            new_alerts.append(alert)

                    if new_alerts:
                        db.insert_alerts(conn, new_alerts)
                        send_email_alerts([a for a in new_alerts if a.severity in ("HIGH", "CRITICAL")])
                        _print_alerts(new_alerts)

            time.sleep(WATCH_POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nStopped watching.")


def main():
    parser_ = argparse.ArgumentParser(description="Log Analyzer & Anomaly Detector")
    parser_.add_argument("--sample", action="store_true", help="Run against generated sample log data")
    parser_.add_argument("--watch", action="store_true", help="Live-monitor log files for new entries")
    parser_.add_argument("--db", default=db.DB_PATH, help="Path to SQLite database file")
    parser_.add_argument("--report", default="report.md", help="Path to write the Markdown report")
    parser_.add_argument("--no-email", action="store_true", help="Skip sending email alerts")
    args = parser_.parse_args()

    conn = db.connect(args.db)

    if args.watch:
        run_watch(conn, args)
    elif args.sample:
        run_sample(conn, args)
    else:
        run_real_logs(conn, args)

    conn.close()


if __name__ == "__main__":
    main()

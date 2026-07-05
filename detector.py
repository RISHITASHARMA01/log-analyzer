"""
detector.py - Detects 7 threat types in parsed log entries using pattern
matching, and assigns each alert a 0-100 threat score.

Threat types:
1. Brute Force Attack    - 5+ failed logins from the same IP in a time window
2. Distributed Attack    - Same account attacked from many different IPs
3. User Enumeration      - Many invalid usernames tried from the same IP
4. Sudo Abuse             - Unauthorized / failed sudo attempts
5. New User Creation      - Suspicious account creation (useradd)
6. Off-Hours Login        - Successful login between midnight and 5 AM
7. Root Login Attempt     - Direct root login attempt (success or failure)
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional
from collections import defaultdict

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Base score per threat type, before modifiers. Reflects how dangerous the
# threat generally is, independent of any particular instance's severity.
BASE_SCORE = {
    "Brute Force Attack": 50,
    "Distributed Attack": 70,
    "User Enumeration": 30,
    "Sudo Abuse": 50,
    "New User Creation": 70,
    "Off-Hours Login": 10,
    "Root Login Attempt": 70,
}


@dataclass
class Alert:
    timestamp: datetime
    threat_type: str
    severity: str
    score: int
    source_ip: Optional[str]
    username: Optional[str]
    details: str
    emailed: bool = False


def score_to_severity(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def calculate_threat_score(threat_type: str, modifiers: dict, db_conn=None, source_ip: str = None) -> int:
    """Combine a base score for the threat type with situational modifiers.

    modifiers keys used across detectors:
      excess_count   - how far past the trigger threshold this instance is
      involves_root  - root account was targeted or used
      deep_night     - login happened between 2-4am (worse than midnight-5am edges)
      login_succeeded - the attempt actually succeeded, not just probed
    """
    score = BASE_SCORE[threat_type]
    score += min(modifiers.get("excess_count", 0) * 2, 20)
    if modifiers.get("involves_root"):
        score += 15
    if modifiers.get("deep_night"):
        score += 10
    if modifiers.get("login_succeeded"):
        score += 10

    if db_conn is not None and source_ip:
        from db import count_recent_alerts_for_ip
        repeat_offenses = count_recent_alerts_for_ip(db_conn, source_ip, hours=24)
        score += min(repeat_offenses * 3, 15)

    return max(0, min(100, score))


def _make_alert(timestamp, threat_type, source_ip, username, details, modifiers, db_conn=None) -> Alert:
    score = calculate_threat_score(threat_type, modifiers, db_conn=db_conn, source_ip=source_ip)
    return Alert(
        timestamp=timestamp,
        threat_type=threat_type,
        severity=score_to_severity(score),
        score=score,
        source_ip=source_ip,
        username=username,
        details=details,
    )


def _extract_ip(message: str) -> Optional[str]:
    match = IP_PATTERN.search(message)
    return match.group(0) if match else None


def _extract_failed_login_user(message: str) -> Optional[str]:
    match = re.search(r"Failed password for (?:invalid user )?(\S+) from", message)
    return match.group(1) if match else None


def _is_invalid_user_attempt(message: str) -> bool:
    return "Failed password for invalid user" in message


# ---------------------------------------------------------------------------
# 1. Brute Force Attack - 5+ failed logins from the same IP in a window
# ---------------------------------------------------------------------------
def detect_brute_force(entries, threshold=5, window_minutes=10, db_conn=None) -> List[Alert]:
    alerts = []
    by_ip = defaultdict(list)
    for entry in entries:
        if "Failed password" not in entry.message and "authentication failure" not in entry.message:
            continue
        ip = _extract_ip(entry.message)
        if ip:
            by_ip[ip].append(entry)

    for ip, ip_entries in by_ip.items():
        ip_entries.sort(key=lambda e: e.timestamp)
        window = []
        alerted = False
        for entry in ip_entries:
            window.append(entry)
            window = [e for e in window if entry.timestamp - e.timestamp <= timedelta(minutes=window_minutes)]
            if len(window) >= threshold and not alerted:
                usernames = sorted({_extract_failed_login_user(e.message) for e in window if _extract_failed_login_user(e.message)})
                alerts.append(_make_alert(
                    timestamp=entry.timestamp,
                    threat_type="Brute Force Attack",
                    source_ip=ip,
                    username=usernames[0] if len(usernames) == 1 else None,
                    details=f"{len(window)} failed login attempts from {ip} within {window_minutes} min "
                            f"(usernames tried: {', '.join(usernames) if usernames else 'unknown'})",
                    modifiers={"excess_count": len(window) - threshold, "involves_root": "root" in usernames},
                    db_conn=db_conn,
                ))
                alerted = True
    return alerts


# ---------------------------------------------------------------------------
# 2. Distributed Attack - same account attacked from many different IPs
# ---------------------------------------------------------------------------
def detect_distributed_attack(entries, ip_threshold=4, window_minutes=15, db_conn=None) -> List[Alert]:
    alerts = []
    by_user = defaultdict(list)
    for entry in entries:
        if "Failed password" not in entry.message:
            continue
        user = _extract_failed_login_user(entry.message)
        ip = _extract_ip(entry.message)
        if user and ip:
            by_user[user].append((entry, ip))

    for user, attempts in by_user.items():
        attempts.sort(key=lambda pair: pair[0].timestamp)
        window = []
        alerted = False
        for entry, ip in attempts:
            window.append((entry, ip))
            window = [(e, i) for e, i in window if entry.timestamp - e.timestamp <= timedelta(minutes=window_minutes)]
            distinct_ips = {i for _, i in window}
            if len(distinct_ips) >= ip_threshold and not alerted:
                alerts.append(_make_alert(
                    timestamp=entry.timestamp,
                    threat_type="Distributed Attack",
                    source_ip=None,
                    username=user,
                    details=f"Account '{user}' targeted from {len(distinct_ips)} distinct IPs within "
                            f"{window_minutes} min: {', '.join(sorted(distinct_ips))}",
                    modifiers={"excess_count": len(distinct_ips) - ip_threshold, "involves_root": user == "root"},
                    db_conn=db_conn,
                ))
                alerted = True
    return alerts


# ---------------------------------------------------------------------------
# 3. User Enumeration - many invalid usernames tried from the same IP
# ---------------------------------------------------------------------------
def detect_user_enumeration(entries, threshold=5, window_minutes=10, db_conn=None) -> List[Alert]:
    alerts = []
    by_ip = defaultdict(list)
    for entry in entries:
        if not _is_invalid_user_attempt(entry.message):
            continue
        ip = _extract_ip(entry.message)
        user = _extract_failed_login_user(entry.message)
        if ip and user:
            by_ip[ip].append((entry, user))

    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda pair: pair[0].timestamp)
        window = []
        alerted = False
        for entry, user in attempts:
            window.append((entry, user))
            window = [(e, u) for e, u in window if entry.timestamp - e.timestamp <= timedelta(minutes=window_minutes)]
            distinct_users = {u for _, u in window}
            if len(distinct_users) >= threshold and not alerted:
                alerts.append(_make_alert(
                    timestamp=entry.timestamp,
                    threat_type="User Enumeration",
                    source_ip=ip,
                    username=None,
                    details=f"{len(distinct_users)} distinct invalid usernames tried from {ip} within "
                            f"{window_minutes} min: {', '.join(sorted(distinct_users))}",
                    modifiers={"excess_count": len(distinct_users) - threshold},
                    db_conn=db_conn,
                ))
                alerted = True
    return alerts


# ---------------------------------------------------------------------------
# 4. Sudo Abuse - unauthorized or failed sudo attempts
# ---------------------------------------------------------------------------
def detect_sudo_abuse(entries, db_conn=None) -> List[Alert]:
    alerts = []
    for entry in entries:
        if entry.process != "sudo":
            continue
        if "NOT in sudoers" in entry.message or "authentication failure" in entry.message or "incorrect password attempts" in entry.message:
            user_match = re.search(r"user=(\S+)", entry.message)
            username = user_match.group(1).rstrip(",") if user_match else None
            alerts.append(_make_alert(
                timestamp=entry.timestamp,
                threat_type="Sudo Abuse",
                source_ip=None,
                username=username,
                details=f"Unauthorized sudo attempt: {entry.message}",
                modifiers={"involves_root": True},
                db_conn=db_conn,
            ))
    return alerts


# ---------------------------------------------------------------------------
# 5. New User Creation - suspicious account creation
# ---------------------------------------------------------------------------
def detect_new_user_creation(entries, db_conn=None) -> List[Alert]:
    alerts = []
    for entry in entries:
        if entry.process != "useradd" and "new user" not in entry.message.lower():
            continue
        name_match = re.search(r"name=(\S+?),", entry.message)
        uid_match = re.search(r"UID=(\d+)", entry.message)
        username = name_match.group(1) if name_match else None
        is_privileged_uid = uid_match and int(uid_match.group(1)) == 0
        alerts.append(_make_alert(
            timestamp=entry.timestamp,
            threat_type="New User Creation",
            source_ip=None,
            username=username,
            details=f"New account created: {entry.message}",
            modifiers={"involves_root": bool(is_privileged_uid)},
            db_conn=db_conn,
        ))
    return alerts


# ---------------------------------------------------------------------------
# 6. Off-Hours Login - successful login between midnight and 5 AM
# ---------------------------------------------------------------------------
def detect_off_hours_login(entries, start_hour=0, end_hour=5, db_conn=None) -> List[Alert]:
    alerts = []
    for entry in entries:
        if "Accepted password" not in entry.message and "Accepted publickey" not in entry.message:
            continue
        if not (start_hour <= entry.timestamp.hour < end_hour):
            continue
        user_match = re.search(r"Accepted \S+ for (\S+) from", entry.message)
        username = user_match.group(1) if user_match else None
        ip = _extract_ip(entry.message)
        alerts.append(_make_alert(
            timestamp=entry.timestamp,
            threat_type="Off-Hours Login",
            source_ip=ip,
            username=username,
            details=f"Login at {entry.timestamp.strftime('%H:%M:%S')} (outside business hours): {entry.message}",
            modifiers={"involves_root": username == "root", "deep_night": 2 <= entry.timestamp.hour < 4},
            db_conn=db_conn,
        ))
    return alerts


# ---------------------------------------------------------------------------
# 7. Root Login Attempt - direct root login (success or failure)
# ---------------------------------------------------------------------------
def detect_root_login_attempt(entries, db_conn=None) -> List[Alert]:
    alerts = []
    for entry in entries:
        is_root_attempt = re.search(r"(Accepted|Failed) \S+ for root from", entry.message)
        if not is_root_attempt:
            continue
        ip = _extract_ip(entry.message)
        succeeded = is_root_attempt.group(1) == "Accepted"
        outcome = "succeeded" if succeeded else "failed"
        alerts.append(_make_alert(
            timestamp=entry.timestamp,
            threat_type="Root Login Attempt",
            source_ip=ip,
            username="root",
            details=f"Direct root login {outcome} from {ip}: {entry.message}",
            modifiers={"involves_root": True, "login_succeeded": succeeded},
            db_conn=db_conn,
        ))
    return alerts


DETECTORS = [
    detect_brute_force,
    detect_distributed_attack,
    detect_user_enumeration,
    detect_sudo_abuse,
    detect_new_user_creation,
    detect_off_hours_login,
    detect_root_login_attempt,
]


def run_all_detectors(entries, db_conn=None) -> List[Alert]:
    """Run all 7 detectors against a list of LogEntry objects and return a
    single list of Alert objects, sorted by threat score (highest first)."""
    alerts = []
    for detector in DETECTORS:
        alerts.extend(detector(entries, db_conn=db_conn))
    alerts.sort(key=lambda a: a.score, reverse=True)
    return alerts

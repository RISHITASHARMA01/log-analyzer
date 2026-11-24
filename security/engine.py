from collections import defaultdict, deque
from datetime import datetime, timedelta
import re

from security.mitre import get_technique
from security.advanced import detect_advanced

PRIVILEGED = {"root", "administrator", "admin"}

def severity(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"

def analyze(events, threshold=5, window_minutes=10,
            privileged_accounts=None, trusted_admins=None):
    privileged = set(PRIVILEGED if privileged_accounts is None else (u.lower() for u in privileged_accounts))
    trusted = set(u.lower() for u in (trusted_admins or []))
    alerts = []
    failures = defaultdict(deque)
    source_failures = defaultdict(deque)
    seen = set()

    def emit(event, rule, title, score, technique, confidence="medium"):
        key = (
            rule, event["platform"], event["host"],
            event["username"], event["source_ip"],
            event["timestamp"], event["message"]
        )
        if key in seen:
            return

        seen.add(key)
        score = min(100, max(0, score))

        alerts.append({
            "rule_id": rule,
            "threat_type": title,
            "timestamp": event["timestamp"],
            "platform": event["platform"],
            "host": event["host"],
            "username": event["username"],
            "source_ip": event["source_ip"],
            "severity": severity(score),
            "score": score,
            "confidence": confidence,
            "evidence": event["message"],
            "remediation": "Review authorization and correlate with endpoint and authentication telemetry.",
            **get_technique(technique)
        })

    window = timedelta(minutes=window_minutes)

    for event in sorted(events, key=lambda e: e["timestamp"]):
        eid = event["event_id"]
        msg = event["message"]
        lower = msg.lower()
        user = event["username"].lower()
        ip = event["source_ip"]
        platform = event["platform"]
        data = event["data"]
        now = datetime.fromisoformat(event["timestamp"])

        failed = False
        success = False

        if platform == "Windows":
            failed = eid in {4625, 4771}
            success = eid == 4624

            if eid == 4672:
                emit(event, "WIN001", "Special privileges assigned",
                     35, "T1078", "low")

            if eid == 4648:
                emit(event, "WIN002", "Explicit credential usage",
                     40, "T1078", "low")

            if eid in {4728, 4732, 4756}:
                emit(event, "WIN003", "Security group membership changed",
                     65, "T1098")

            if eid == 4670:
                emit(event, "WIN004", "Object permissions changed",
                     60, "T1222.001")

            if eid == 4720:
                emit(event, "WIN005", "New account created",
                     45, "T1136")

            if eid == 1102:
                emit(event, "WIN006", "Security audit log cleared",
                     85, "T1070.001", "high")

            if eid == 4740:
                emit(event, "WIN007", "Account lockout",
                     45, "T1110.001", "low")

            if eid == 4724:
                emit(event, "WIN008", "Password reset attempt",
                     45, "T1098", "low")

        else:
            process = data.get("process", "")
            failed = process == "sshd" and "Failed password" in msg
            success = process == "sshd" and "Accepted " in msg

            if process == "sudo":
                if "not in sudoers" in lower or "authentication failure" in lower:
                    emit(event, "LIN001", "Unauthorized sudo attempt",
                         70, "T1548.003")
                elif "command=" in lower:
                    emit(event, "LIN002", "Privileged command activity",
                         25, "T1548.003", "low")

                command = msg.split("COMMAND=", 1)[-1]

                if "COMMAND=" in msg and re.search(
                    r"\b(chmod|chown|setfacl)\b", command
                ):
                    emit(event, "LIN003", "Permission change command",
                         55, "T1222.002")

                if "COMMAND=" in msg and re.search(
                    r"\b(chmod|chown|setfacl|visudo)\b", command
                ) and any(p in command for p in (
                    "/etc/shadow", "/etc/passwd", "/etc/sudoers"
                )):
                    emit(event, "LIN004", "Sensitive permission modification attempt",
                         80, "T1222.002")

                if "COMMAND=" in msg and "/etc/shadow" in command:
                    emit(event, "LIN005", "Sensitive credential file access indicator",
                         65, "T1003", "low")

            if process == "useradd" and "new user" in lower:
                emit(event, "LIN006", "New Linux account created",
                     45, "T1136")

            if process in {"usermod", "gpasswd", "groupmod"}:
                emit(event, "LIN007", "Account or group modification",
                     60, "T1098")

        if user in privileged and (failed or (success and user not in trusted)):
            emit(event, "AUTH001", "Privileged account authentication",
                 65 if failed else 40, "T1078", "low")

        if not ip or ip in {"-", "::1", "127.0.0.1"} or not user:
            continue

        account_key = (platform, event["host"], ip, user)
        source_key = (platform, event["host"], ip)

        account_queue = failures[account_key]
        source_queue = source_failures[source_key]

        for queue in (account_queue, source_queue):
            while queue and now - queue[0][0] > window:
                queue.popleft()

        if failed:
            account_queue.append((now, user))
            source_queue.append((now, user))

            if len(account_queue) == threshold:
                emit(event, "AUTH002", "Brute force indicator",
                     75, "T1110.001")

            users = {item[1] for item in source_queue}
            if len(users) == threshold and sum(
                item[1] == user for item in source_queue
            ) == 1:
                emit(event, "AUTH003", "Password spraying indicator",
                     80, "T1110.003")

        if success and len(account_queue) >= threshold:
            emit(event, "AUTH004", "Successful login after repeated failures",
                 90, "T1078")
            account_queue.clear()

    detect_advanced(events, emit, threshold, window_minutes)

    return sorted(alerts, key=lambda a: a["score"], reverse=True)

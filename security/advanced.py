from collections import defaultdict, deque
from datetime import datetime, timedelta


def detect_advanced(events, emit, threshold=5, window_minutes=10):
    requests = defaultdict(deque)
    window = timedelta(minutes=window_minutes)

    for event in sorted(events, key=lambda e: e["timestamp"]):
        data = event["data"]
        eid = event["event_id"]
        now = datetime.fromisoformat(event["timestamp"])

        if event["platform"] == "Windows":

            encryption = str(
                data.get("TicketEncryptionType", "")
            ).lower()

            preauth = str(data.get("PreAuthType", ""))
            status = str(data.get("Status", "")).lower()
            service = str(data.get("ServiceName", "")).lower()

            successful = status in ("0", "0x0", "0x00000000")

            if (
                eid == 4769
                and encryption in ("0x17", "23")
                and service
                and not service.endswith("$")
                and service != "krbtgt"
                and successful
            ):
                emit(
                    event, "KER001",
                    "Possible Kerberoasting indicator",
                    65, "T1558.003", "medium"
                )

                key = (
                    event["host"],
                    event["source_ip"],
                    event["username"].lower()
                )

                queue = requests[key]

                while queue and now - queue[0][0] > window:
                    queue.popleft()

                queue.append((now, service))

                if len(set(item[1] for item in queue)) == threshold:
                    emit(
                        event, "KER002",
                        "Multiple RC4 service ticket requests",
                        85, "T1558.003", "medium"
                    )

            if eid == 4768 and preauth == "0" and successful:
                emit(
                    event, "KER003",
                    "Possible AS-REP roasting indicator",
                    70, "T1558.004", "medium"
                )

            if eid == 4771 and str(
                data.get("Status", data.get("FailureCode", ""))
            ).lower() == "0x18":
                emit(
                    event, "KER004",
                    "Kerberos pre-authentication failure",
                    40, "T1110.001", "low"
                )

        elif event["platform"] == "Linux":
            kind = data.get("audit_type", "")
            process = data.get("process", "")

            if kind == "SYSCALL" and process in (
                "chmod", "chown", "fchmod", "setfacl"
            ):
                emit(
                    event, "AUD001",
                    "Audited permission modification",
                    55, "T1222.002", "medium"
                )

            if kind == "PATH" and data.get("name") == "/etc/shadow":
                emit(
                    event, "AUD002",
                    "Sensitive credential file referenced",
                    55, "T1003.008", "low"
                )

            if kind in ("ADD_USER", "ADD_GROUP"):
                emit(
                    event, "AUD003",
                    "Audited account or group creation",
                    45, "T1136", "medium"
                )

            if kind in ("USER_CHAUTHTOK", "USER_MGMT", "GRP_MGMT"):
                emit(
                    event, "AUD004",
                    "Audited account modification",
                    55, "T1098", "medium"
                )

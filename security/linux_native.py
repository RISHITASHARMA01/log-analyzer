import json
import re
from datetime import datetime, timezone


def parse_auditd(path):
    events = []

    with open(path, errors="replace") as file:
        for line in file:
            match = re.search(
                r'type=(\S+).*?audit\(([\d.]+):(\d+)\)',
                line
            )

            if not match:
                continue

            kind, epoch, serial = match.groups()

            fields = dict(re.findall(
                r'(\w+)=("[^"]*"|\S+)', line
            ))

            fields = dict(
                (key, value.strip('"'))
                for key, value in fields.items()
            )

            fields.update(dict(
                process=fields.get("comm", "auditd"),
                audit_type=kind,
                audit_serial=serial
            ))

            events.append(dict(
                platform="Linux",
                timestamp=datetime.fromtimestamp(
                    float(epoch), timezone.utc
                ).isoformat(),
                event_id=0,
                host=fields.get("node", ""),
                username=fields.get("acct", fields.get("auid", "")),
                source_ip=fields.get("addr", ""),
                message=line.strip(),
                data=fields
            ))

    return events


def parse_journal(path):
    events = []

    with open(path, errors="replace") as file:
        for line in file:
            try:
                data = json.loads(line)

                epoch = int(
                    data["__REALTIME_TIMESTAMP"]
                ) / 1000000

                message = data.get("MESSAGE", "")

                if not isinstance(message, str):
                    continue

                process = data.get(
                    "SYSLOG_IDENTIFIER",
                    data.get("_COMM", "")
                )

                match = re.search(
                    r"(?:Failed|Accepted) \S+ for "
                    r"(?:invalid user )?(\S+) from (\S+)",
                    message
                )

                user = match.group(1) if match else ""
                ip = match.group(2) if match else ""

                if process == "sudo" and not user:
                    user = message.split(":", 1)[0].strip()

                data["process"] = process

                events.append(dict(
                    platform="Linux",
                    timestamp=datetime.fromtimestamp(
                        epoch, timezone.utc
                    ).isoformat(),
                    event_id=0,
                    host=data.get("_HOSTNAME", ""),
                    username=user,
                    source_ip=ip,
                    message=message,
                    data=data
                ))

            except (ValueError, KeyError, TypeError, OverflowError):
                continue

    return events

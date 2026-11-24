import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from defusedxml import ElementTree
from parser import parse_line

def timestamp(value):
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def windows_event(data):
    return {
        "platform": "Windows",
        "timestamp": timestamp(data["TimeCreated"]),
        "event_id": int(data["EventID"]),
        "host": data.get("Computer", ""),
        "username": data.get("TargetUserName") or
                    data.get("SubjectUserName", ""),
        "source_ip": data.get("IpAddress", ""),
        "message": json.dumps(data),
        "data": data
    }

def xml_events(content):
    root = ElementTree.fromstring(content)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    nodes = [root] if root.tag.endswith("}Event") else root.findall(".//e:Event", ns)

    for node in nodes:
        system = node.find("e:System", ns)
        if system is None:
            continue

        data = {
            "EventID": system.findtext("e:EventID", namespaces=ns),
            "Computer": system.findtext("e:Computer", namespaces=ns),
            "TimeCreated": system.find("e:TimeCreated", ns).get("SystemTime")
        }

        for item in node.findall("e:EventData/e:Data", ns):
            if item.get("Name"):
                data[item.get("Name")] = item.text or ""

        yield windows_event(data)

def parse_windows(path):
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".xml":
        return list(xml_events(path.read_text(encoding="utf-8-sig")))

    if suffix == ".evtx":
        from Evtx.Evtx import Evtx
        events = []
        with Evtx(str(path)) as log:
            for record in log.records():
                events.extend(xml_events(record.xml()))
        return events

    if suffix == ".json":
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            data = [data]
        return [windows_event(row) for row in data]

    if suffix == ".csv":
        with path.open(encoding="utf-8-sig") as file:
            return [windows_event(row) for row in csv.DictReader(file)]

    raise ValueError("Unsupported Windows log format")

def parse_linux(path, year=None):
    events = []

    with open(path, errors="replace") as file:
        for line in file:
            entry = parse_line(line, year=year)
            if not entry:
                continue

            message = entry.message
            match = re.search(
                r"(?:Failed|Accepted) \S+ for (?:invalid user )?(\S+) from (\S+)",
                message
            )

            user = match.group(1) if match else ""
            ip = match.group(2) if match else ""

            if entry.process == "sudo" and not user:
                user = message.split(":", 1)[0].strip()

            events.append({
                "platform": "Linux",
                "timestamp": timestamp(entry.timestamp),
                "event_id": 0,
                "host": entry.host,
                "username": user,
                "source_ip": ip,
                "message": message,
                "data": {"process": entry.process}
            })

    return events

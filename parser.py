"""
parser.py - Reads and parses Linux log files (auth.log, syslog)

Turns raw syslog-format lines into structured LogEntry objects that
detector.py can run pattern matching against.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

# Standard Linux syslog line format:
#   Jul  5 02:14:33 ubuntu-server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 51678 ssh2
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class LogEntry:
    timestamp: datetime
    host: str
    process: str
    pid: Optional[int]
    message: str
    raw: str

    def source_ip(self) -> Optional[str]:
        match = IP_PATTERN.search(self.message)
        return match.group(0) if match else None


def parse_line(line: str, year: Optional[int] = None) -> Optional[LogEntry]:
    """Parse a single syslog-format line into a LogEntry. Returns None if the
    line doesn't match the expected format (e.g. blank lines, continuations)."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    match = SYSLOG_PATTERN.match(line)
    if not match:
        return None

    year = year or datetime.now().year
    timestamp_str = f"{year} {match.group('month')} {match.group('day')} {match.group('time')}"
    try:
        timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    pid = int(match.group("pid")) if match.group("pid") else None

    return LogEntry(
        timestamp=timestamp,
        host=match.group("host"),
        process=match.group("process"),
        pid=pid,
        message=match.group("message"),
        raw=line,
    )


def parse_file(path: str, year: Optional[int] = None) -> List[LogEntry]:
    """Parse an entire log file into a list of LogEntry objects, skipping
    any lines that don't match the expected syslog format."""
    entries = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            entry = parse_line(line, year=year)
            if entry:
                entries.append(entry)
    return entries


def parse_lines(lines: List[str], year: Optional[int] = None) -> List[LogEntry]:
    """Parse an in-memory list of lines (used by the sample log generator)."""
    entries = []
    for line in lines:
        entry = parse_line(line, year=year)
        if entry:
            entries.append(entry)
    return entries

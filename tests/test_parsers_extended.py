import pytest

from security.parsers import parse_windows, parse_linux
from defusedxml.common import EntitiesForbidden


def test_windows_xml(tmp_path):
    path = tmp_path / "security.xml"

    path.write_text("""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <EventID>4625</EventID>
            <TimeCreated SystemTime="2026-11-24T10:00:00Z"/>
            <Computer>WIN-LAB</Computer>
        </System>
        <EventData>
            <Data Name="TargetUserName">admin</Data>
            <Data Name="IpAddress">192.0.2.10</Data>
        </EventData>
    </Event>
    """)

    events = parse_windows(path)
    assert len(events) == 1
    assert events[0]["event_id"] == 4625
    assert events[0]["username"] == "admin"


def test_windows_csv(tmp_path):
    path = tmp_path / "security.csv"

    path.write_text(
        "EventID,TimeCreated,Computer,TargetUserName,IpAddress\n"
        "4625,2026-11-24T10:00:00Z,WIN-LAB,admin,192.0.2.10\n"
    )

    events = parse_windows(path)
    assert len(events) == 1
    assert events[0]["event_id"] == 4625


def test_unsupported_format(tmp_path):
    path = tmp_path / "unknown.txt"
    path.write_text("test")

    with pytest.raises(ValueError):
        parse_windows(path)


def test_invalid_linux_lines(tmp_path):
    path = tmp_path / "invalid.log"
    path.write_text("Invalid log entry\n\n")

    assert parse_linux(path) == []


def test_xml_entity_protection(tmp_path):
    path = tmp_path / "unsafe.xml"

    path.write_text(
        '<!DOCTYPE Event [<!ENTITY test "blocked">]>'
        '<Event>&test;</Event>'
    )

    with pytest.raises(EntitiesForbidden):
        parse_windows(path)

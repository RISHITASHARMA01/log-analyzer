from security.parsers import parse_windows, parse_linux
from security.engine import analyze, severity
from security.reporting import export_reports
from security.mitre import get_technique

def test_windows_parser():
    events = parse_windows("samples/windows_security.json")
    assert len(events) == 12
    assert events[0]["platform"] == "Windows"

def test_linux_parser():
    events = parse_linux("samples/linux_auth.log", year=2026)
    assert len(events) == 10

def test_brute_force():
    alerts = analyze(parse_windows("samples/windows_security.json"))
    assert any(a["rule_id"] == "AUTH002" for a in alerts)

def test_credential_correlation():
    alerts = analyze(parse_windows("samples/windows_security.json"))
    assert any(a["rule_id"] == "AUTH004" for a in alerts)

def test_privileged_activity():
    alerts = analyze(parse_windows("samples/windows_security.json"))
    assert any(a["rule_id"] == "WIN001" for a in alerts)

def test_permission_changes():
    alerts = analyze(parse_linux("samples/linux_auth.log", year=2026))
    assert any(a["rule_id"] == "LIN004" for a in alerts)

def test_mitre_mapping():
    assert get_technique("T1110.001")["technique_name"] == "Password Guessing"

def test_risk_scoring():
    assert severity(90) == "CRITICAL"
    assert severity(70) == "HIGH"
    assert severity(40) == "MEDIUM"
    assert severity(10) == "LOW"

def test_benign_login():
    events = parse_linux("samples/linux_auth.log", year=2026)
    benign = [e for e in events if e["username"] == "employee"]
    assert analyze(benign) == []

def test_password_spraying():
    events = parse_windows("samples/windows_security.json")[:5]
    for i, event in enumerate(events):
        event["username"] = f"user{i}"
    assert any(a["rule_id"] == "AUTH003" for a in analyze(events))

def test_reports(tmp_path):
    events = parse_windows("samples/windows_security.json")
    export_reports(events, analyze(events), tmp_path)
    for extension in ("json", "csv", "html"):
        assert (tmp_path / f"security_report.{extension}").exists()

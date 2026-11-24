from security.storage import store_alerts
from security.engine import analyze
from security.parsers import parse_windows


def test_persistent_deduplication(tmp_path):
    events = parse_windows("samples/windows_security.json")
    alerts = analyze(events)

    database = tmp_path / "test.db"

    assert store_alerts(alerts, database) == len(alerts)
    assert store_alerts(alerts, database) == 0

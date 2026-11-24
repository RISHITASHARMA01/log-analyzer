import csv
import json
from html import escape
from pathlib import Path
from collections import Counter

def safe_cell(value):
    value = str(value)
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value

def export_reports(events, alerts, directory="reports"):
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=True)

    summary = {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "platforms": dict(Counter(e["platform"] for e in events)),
        "severity": dict(Counter(a["severity"] for a in alerts)),
        "mitre": dict(Counter(a["technique_id"] for a in alerts)),
        "limitations": "Rule-based indicators require analyst validation."
    }

    result = {"summary": summary, "alerts": alerts}

    (output / "security_report.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )

    with (output / "security_report.csv").open("w", newline="", encoding="utf-8") as file:
        fields = list(alerts[0]) if alerts else ["rule_id", "threat_type"]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for alert in alerts:
            writer.writerow({k: safe_cell(v) for k, v in alert.items()})

    rows = "".join(
        "<tr>" + "".join(
            f"<td>{escape(str(alert.get(key, '')))}</td>"
            for key in (
                "timestamp", "platform", "threat_type",
                "severity", "score", "technique_id", "evidence"
            )
        ) + "</tr>"
        for alert in alerts
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Analysis Report</title>
<style>
body {{font-family: Arial; margin: 30px;}}
table {{border-collapse: collapse; width: 100%;}}
td, th {{padding: 10px; border: 1px solid #ccc;}}
th {{background: #172033; color: white;}}
td {{overflow-wrap: anywhere;}}
</style>
</head>
<body>
<h1>Security Log Analysis Report</h1>
<p>Events analyzed: {len(events)}</p>
<p>Alerts generated: {len(alerts)}</p>
<p>Indicators require analyst validation.</p>
<table>
<tr><th>Time</th><th>Platform</th><th>Finding</th>
<th>Severity</th><th>Score</th><th>MITRE</th><th>Evidence</th></tr>
{rows}
</table>
</body>
</html>"""

    (output / "security_report.html").write_text(html, encoding="utf-8")
    return result

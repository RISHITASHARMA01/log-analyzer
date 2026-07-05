"""
report.py - Generates a Markdown security report summarizing detected alerts.
"""

from collections import Counter
from datetime import datetime


def generate_report(alerts, entries_count: int, output_path: str = "report.md") -> str:
    """Write a Markdown report to output_path and return the path."""
    alerts_sorted = sorted(alerts, key=lambda a: a.score, reverse=True)
    severity_counts = Counter(a.severity for a in alerts)
    threat_counts = Counter(a.threat_type for a in alerts)

    lines = []
    lines.append("# Security Log Analysis Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Log entries analyzed: **{entries_count}**")
    lines.append(f"- Total alerts: **{len(alerts)}**")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"- {severity}: **{severity_counts.get(severity, 0)}**")
    lines.append("")

    if threat_counts:
        lines.append("## Alerts by Threat Type")
        lines.append("")
        lines.append("| Threat Type | Count |")
        lines.append("|---|---|")
        for threat_type, count in threat_counts.most_common():
            lines.append(f"| {threat_type} | {count} |")
        lines.append("")

    lines.append("## Alert Details (sorted by threat score)")
    lines.append("")
    if not alerts_sorted:
        lines.append("No threats detected.")
    else:
        lines.append("| Time | Threat Type | Severity | Score | Source IP | Username | Details |")
        lines.append("|---|---|---|---|---|---|---|")
        for alert in alerts_sorted:
            details = alert.details.replace("|", "\\|")
            lines.append(
                f"| {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | {alert.threat_type} | "
                f"{alert.severity} | {alert.score} | {alert.source_ip or '-'} | "
                f"{alert.username or '-'} | {details} |"
            )
    lines.append("")

    content = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(content)
    return output_path

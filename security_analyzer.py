import argparse
from security.parsers import parse_windows, parse_linux
from security.engine import analyze
from security.reporting import export_reports
from security.storage import store_alerts

def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform Security Log Analyzer"
    )

    parser.add_argument("--windows", nargs="+", default=[])
    parser.add_argument("--linux", nargs="+", default=[])
    parser.add_argument("--year", type=int)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--output", default="reports")

    parser.add_argument("--db", default="security_alerts.db")
    args = parser.parse_args()

    if not args.windows and not args.linux:
        parser.error("Provide Windows or Linux log files")

    if args.threshold < 2 or args.window < 1:
        parser.error("Invalid detection threshold or time window")

    events = []

    for path in args.windows:
        events.extend(parse_windows(path))

    for path in args.linux:
        events.extend(parse_linux(path, year=args.year))

    alerts = analyze(events, args.threshold, args.window)
    result = export_reports(events, alerts, args.output)
    print("New alerts stored:", store_alerts(alerts, args.db))

    print("\nSECURITY ANALYSIS COMPLETE")
    print("Events:", len(events))
    print("Alerts:", len(alerts))

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['threat_type']} | "
            f"{alert['technique_id']} | "
            f"Score: {alert['score']}"
        )

    print("\nReports saved in:", args.output)

if __name__ == "__main__":
    main()

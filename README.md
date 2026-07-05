# Log Analyzer & Anomaly Detector

A Python-based security tool that parses Linux system logs (`auth.log`, `syslog`),
detects common attack patterns, scores each alert by severity, and surfaces
everything through a live Streamlit dashboard.

## Features

- **7 threat detectors** using pattern matching over parsed log entries
- **Threat scoring (0-100)** — combines threat-type severity with contextual
  signals (root involvement, attack success, repeat offenders, off-hours timing)
  to prioritize which alerts matter most
- **SQLite storage** for parsed log entries and detected alerts
- **Email alerts** (Gmail SMTP) for HIGH/CRITICAL severity threats
- **Markdown report generation**, sorted by threat score
- **Streamlit + Plotly dashboard** with live charts and filtering
- **Sample log generator** for testing without needing real system logs
- **Live watch mode** that tails log files and alerts on new activity

## Threats detected

| # | Threat | Trigger |
|---|---|---|
| 1 | Brute Force Attack | 5+ failed logins from the same IP in a time window |
| 2 | Distributed Attack | Same account attacked from many different IPs |
| 3 | User Enumeration | Many invalid usernames tried from the same IP |
| 4 | Sudo Abuse | Unauthorized or failed sudo attempts |
| 5 | New User Creation | Suspicious account creation (e.g. privileged UID) |
| 6 | Off-Hours Login | Successful login between midnight and 5 AM |
| 7 | Root Login Attempt | Direct root login, success or failure |

## Tech stack

Python 3, SQLite, Streamlit, Plotly, Pandas, smtplib, regex

## Project structure

```
parser.py      Parses syslog-format lines (auth.log, syslog) into LogEntry objects
detector.py    7 threat detectors + 0-100 threat-scoring engine
db.py          SQLite storage for log entries and alerts
alerts.py      Gmail email alerts for HIGH/CRITICAL threats
report.py      Markdown report generation
analyzer.py    Main CLI - ties everything together, includes sample log generator
dashboard.py   Streamlit dashboard with Plotly charts
```

## Setup

```bash
pip install -r requirements.txt
```

To enable email alerts, set these environment variables (Gmail requires an
[App Password](https://myaccount.google.com/apppasswords), not your normal password):

```bash
export GMAIL_USER="you@gmail.com"
export GMAIL_APP_PASSWORD="16-char-app-password"
export ALERT_RECIPIENT="you@gmail.com"   # optional, defaults to GMAIL_USER
```

## Usage

```bash
# Test with generated sample logs covering all 7 threat types
python3 analyzer.py --sample

# Analyze real system logs (needs read access to /var/log/auth.log, /var/log/syslog)
sudo python3 analyzer.py

# Live monitoring - tails log files and alerts on new activity
python3 analyzer.py --watch

# Skip email alerts for a given run
python3 analyzer.py --sample --no-email

# Open the live dashboard
streamlit run dashboard.py
```

Each run stores results in `log_analyzer.db` and writes a Markdown summary to
`report.md`.

## How detection works

Each detector scans parsed log entries for a specific pattern (e.g. failed SSH
logins grouped by source IP within a sliding time window). When a threshold is
crossed, it raises an `Alert` with a threat type, source IP/username, and a
human-readable description.

Every alert then runs through `calculate_threat_score()`, which starts from a
base score for that threat type and adds points for aggravating factors —
how far over the threshold the activity is, whether root was involved,
whether the attempt succeeded, whether it happened in the middle of the night,
and whether the source IP has triggered alerts before. The final score maps to
a severity: `CRITICAL` (70+), `HIGH` (50+), `MEDIUM` (30+), `LOW` (below 30).
Only `HIGH`/`CRITICAL` alerts trigger an email notification.

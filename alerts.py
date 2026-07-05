"""
alerts.py - Sends email alerts (via Gmail SMTP) for HIGH/CRITICAL severity
threats. Credentials are read from environment variables so they never
end up committed to git:

    export GMAIL_USER="you@gmail.com"
    export GMAIL_APP_PASSWORD="16-char app password"   # NOT your normal password
    export ALERT_RECIPIENT="you@gmail.com"             # optional, defaults to GMAIL_USER

Gmail requires an "app password" (Google Account -> Security -> App Passwords)
since it blocks plain password SMTP login.
"""

import os
import smtplib
from email.mime.text import MIMEText

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
NOTIFY_SEVERITIES = {"HIGH", "CRITICAL"}


def _build_message(alert) -> MIMEText:
    body = (
        f"Threat type : {alert.threat_type}\n"
        f"Severity    : {alert.severity}\n"
        f"Score       : {alert.score}/100\n"
        f"Time        : {alert.timestamp}\n"
        f"Source IP   : {alert.source_ip or 'n/a'}\n"
        f"Username    : {alert.username or 'n/a'}\n\n"
        f"Details: {alert.details}\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = f"[{alert.severity}] {alert.threat_type} detected (score {alert.score})"
    return msg


def send_email_alert(alert) -> bool:
    """Send an email for a single alert. Returns True if sent, False if
    skipped (credentials missing) or failed (network/auth error)."""
    if alert.severity not in NOTIFY_SEVERITIES:
        return False

    gmail_user = os.environ.get("GMAIL_USER")
    gmail_password = os.environ.get("GMAIL_APP_PASSWORD")
    recipient = os.environ.get("ALERT_RECIPIENT", gmail_user)

    if not gmail_user or not gmail_password:
        print(f"  [alerts] Skipping email for '{alert.threat_type}' - GMAIL_USER / GMAIL_APP_PASSWORD not set")
        return False

    msg = _build_message(alert)
    msg["From"] = gmail_user
    msg["To"] = recipient

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.login(gmail_user, gmail_password)
            server.sendmail(gmail_user, [recipient], msg.as_string())
        print(f"  [alerts] Email sent for '{alert.threat_type}' (score {alert.score})")
        return True
    except (smtplib.SMTPException, OSError) as exc:
        print(f"  [alerts] Failed to send email for '{alert.threat_type}': {exc}")
        return False


def send_email_alerts(alerts) -> int:
    """Send emails for every HIGH/CRITICAL alert in the list. Returns count sent."""
    sent = 0
    for alert in alerts:
        if send_email_alert(alert):
            alert.emailed = True
            sent += 1
    return sent

import json

from security.engine import analyze
from security.parsers import windows_event
from security.linux_native import parse_auditd, parse_journal


def make_event(event_id, **fields):
    data = dict(
        EventID=event_id,
        TimeCreated="2026-11-24T10:00:00Z",
        Computer="DC-LAB",
        TargetUserName="testuser",
        IpAddress="192.0.2.10"
    )

    data.update(fields)
    return windows_event(data)


def test_kerberoasting():
    event = make_event(
        4769,
        TicketEncryptionType="0x17",
        ServiceName="sqlservice",
        Status="0x0"
    )

    alerts = analyze([event])

    assert any(
        a["technique_id"] == "T1558.003"
        for a in alerts
    )


def test_asrep_roasting():
    event = make_event(
        4768,
        PreAuthType="0",
        Status="0x0"
    )

    assert any(
        a["technique_id"] == "T1558.004"
        for a in analyze([event])
    )


def test_kerberos_failure():
    event = make_event(4771, Status="0x18")

    assert any(
        a["rule_id"] == "KER004"
        for a in analyze([event])
    )


def test_normal_kerberos():
    event = make_event(
        4769,
        TicketEncryptionType="0x12",
        ServiceName="sqlservice",
        Status="0x0"
    )

    assert analyze([event]) == []


def test_kerberos_ticket_burst():
    events = [
        make_event(
            4769,
            TicketEncryptionType="0x17",
            ServiceName="service" + str(i),
            Status="0x0"
        )
        for i in range(5)
    ]

    assert any(
        a["rule_id"] == "KER002"
        for a in analyze(events)
    )


def test_auditd_parser(tmp_path):
    path = tmp_path / "audit.log"

    path.write_text(
        'type=SYSCALL msg=audit(1795514400.1:123): '
        'comm="chmod" auid=1000 success=yes\n'
    )

    events = parse_auditd(path)

    assert len(events) == 1

    assert any(
        a["rule_id"] == "AUD001"
        for a in analyze(events)
    )


def test_journal_parser(tmp_path):
    path = tmp_path / "journal.json"

    data = dict(
        __REALTIME_TIMESTAMP="1795514400000000",
        _HOSTNAME="linux-lab",
        SYSLOG_IDENTIFIER="sshd",
        MESSAGE="Failed password for root from 192.0.2.10 port 22"
    )

    path.write_text(json.dumps(data) + "\n")

    events = parse_journal(path)

    assert len(events) == 1
    assert events[0]["username"] == "root"

    assert any(
        a["rule_id"] == "AUTH001"
        for a in analyze(events)
    )


def test_trusted_admin():
    event = make_event(
        4624,
        TargetUserName="administrator"
    )

    assert analyze(
        [event],
        trusted_admins=["administrator"]
    ) == []


def test_trusted_admin_failure_not_suppressed():
    event = make_event(
        4625,
        TargetUserName="administrator"
    )

    assert any(
        a["rule_id"] == "AUTH001"
        for a in analyze(
            [event],
            trusted_admins=["administrator"]
        )
    )


def test_custom_privileged_account():
    event = make_event(
        4624,
        TargetUserName="domainadmin"
    )

    assert any(
        a["rule_id"] == "AUTH001"
        for a in analyze(
            [event],
            privileged_accounts=["domainadmin"]
        )
    )

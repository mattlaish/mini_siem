import sqlite3

import ai_soc
from rules import RuleEngine


TRIGGER_IP = "10.20.30.40"


class StorageStub:
    def __init__(self):
        self.alerts = []

    def insert_alert(self, rule_name, severity, source_ip, description, log_ids):
        self.alerts.append({
            "rule_name": rule_name,
            "severity": severity,
            "source_ip": source_ip,
            "description": description,
            "log_ids": list(log_ids),
        })
        return len(self.alerts)


def _nxlog_event(severity, event_id=4625, channel="Security"):
    return {
        "severity": severity,
        "source_ip": TRIGGER_IP,
        "format": "json",
        "app_name": "Microsoft-Windows-Security-Auditing",
        "message": f"NXLog EventID {event_id} {severity}",
        "_json": {"EventID": event_id, "Channel": channel},
    }


def _firewall_event(severity):
    return {
        "severity": severity,
        "source_ip": TRIGGER_IP,
        "format": "rfc3164",
        "app_name": "CEF",
        "message": f"FortiGate {severity} traffic",
    }


def _process(event):
    storage = StorageStub()
    engine = RuleEngine(storage)
    engine.process(101, event)
    return storage.alerts


def _alerts_named(alerts, name):
    return [a for a in alerts if a["rule_name"] == name]




def test_real_nxlog_json_shape_parses_and_triggers():
    import json
    import listener

    raw = json.dumps({
        "EventTime": "2026-09-01 10:00:00",
        "Hostname": "win1.example.local",
        "EventType": "AUDIT_FAILURE",
        "SeverityValue": 2,
        "Severity": "INFO",
        "EventID": 4625,
        "SourceName": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Message": "An account failed to log on.",
    })
    event = listener.parse_syslog(raw, TRIGGER_IP)
    assert event["format"] == "json"
    assert event["severity"] == "warning"
    alerts = _process(event)
    got = _alerts_named(alerts, "nxlog_severity_event")
    assert len(got) == 1
    assert got[0]["severity"] == "warning"


def test_nxlog_warning_is_trigger_with_warning_alert_severity():
    alerts = _process(_nxlog_event("warning", 4625))
    got = _alerts_named(alerts, "nxlog_severity_event")
    assert len(got) == 1
    assert got[0]["severity"] == "warning"
    assert got[0]["source_ip"] == TRIGGER_IP


def test_nxlog_error_is_trigger_with_error_alert_severity():
    alerts = _process(_nxlog_event("error", 1102))
    got = _alerts_named(alerts, "nxlog_severity_event")
    assert len(got) == 1
    assert got[0]["severity"] == "error"


def test_nxlog_notice_and_information_are_context_only_not_triggers():
    assert not _alerts_named(_process(_nxlog_event("notice", 4738)), "nxlog_severity_event")
    assert not _alerts_named(_process(_nxlog_event("informational", 4624)), "nxlog_severity_event")


def test_firewall_warning_and_error_do_not_use_nxlog_trigger():
    for sev in ("warning", "error"):
        alerts = _process(_firewall_event(sev))
        assert not _alerts_named(alerts, "nxlog_severity_event")
        # The pre-existing generic rule remains critical/alert/emergency only.
        assert not _alerts_named(alerts, "high_severity_event")


def test_firewall_critical_preserves_preexisting_generic_trigger():
    alerts = _process(_firewall_event("critical"))
    assert not _alerts_named(alerts, "nxlog_severity_event")
    got = _alerts_named(alerts, "high_severity_event")
    assert len(got) == 1
    assert got[0]["severity"] == "critical"


def _context_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY,
            received_at TEXT,
            source_ip TEXT,
            peer_ip TEXT,
            destination TEXT,
            hostname TEXT,
            app_name TEXT,
            severity TEXT,
            message TEXT
        );
        CREATE TABLE log_fields (
            id INTEGER PRIMARY KEY,
            log_id INTEGER NOT NULL,
            field TEXT NOT NULL,
            value TEXT
        );
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY,
            created_at TEXT,
            rule_name TEXT,
            severity TEXT,
            source_ip TEXT,
            description TEXT,
            log_ids TEXT,
            ai_status TEXT,
            ai_analysis TEXT,
            ai_triaged_at TEXT,
            ai_attempts INTEGER DEFAULT 0
        );
    """)
    return conn


def _seed_cross_source_related(conn):
    events = [
        # NXLog lower-severity history from the trigger host.
        (1, "2026-09-01T01:00:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "informational", "NXLog logon success"),
        (2, "2026-09-01T01:01:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "notice", "NXLog privileged logon"),
        # NXLog trigger.
        (3, "2026-09-01T01:02:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "warning", "NXLog failed logon"),
        # Firewall where trigger IP is the traffic source.
        (4, "2026-09-01T01:02:10+00:00", TRIGGER_IP, "192.168.1.1", "8.8.8.8", "fw1", "CEF", "warning", "FortiGate outbound traffic"),
        # Firewall where trigger IP is the destination.
        (5, "2026-09-01T01:02:20+00:00", "185.10.20.30", "192.168.1.1", TRIGGER_IP, "fw1", "CEF", "error", "FortiGate inbound traffic"),
        # API/Sophos event: connector is source column, endpoint IP is indexed.
        (6, "2026-09-01T01:02:30+00:00", "sophos", "sophos", "", "endpoint-a", "Event::Endpoint", "low", "Sophos endpoint event"),
        # Unrelated noise.
        (7, "2026-09-01T01:02:40+00:00", "10.99.99.99", "10.99.99.99", "1.1.1.1", "other", "CEF", "critical", "unrelated event"),
    ]
    conn.executemany("INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?)", events)
    conn.execute(
        "INSERT INTO log_fields (log_id,field,value) VALUES (6,'endpoint_ip',?)",
        (TRIGGER_IP,),
    )
    conn.execute(
        "INSERT INTO alerts (id,created_at,rule_name,severity,source_ip,description,log_ids,ai_status,ai_attempts) "
        "VALUES (1,?,?,?,?,?,?,?,?)",
        ("2026-09-01T01:02:01+00:00", "nxlog_severity_event", "warning", TRIGGER_IP,
         "NXLog warning trigger", "3", "pending", 0),
    )
    conn.commit()


def test_related_context_crosses_sources_destinations_and_all_severities():
    conn = _context_db()
    _seed_cross_source_related(conn)

    ctx = ai_soc.gather_alert_context(conn, 1)
    assert ctx["entity_ip"] == TRIGGER_IP
    by_id = {r["id"]: r for r in ctx["related_history"]}

    # NXLog informational/notice/warning all remain evidence.
    assert {1, 2, 3}.issubset(by_id)
    # Firewall is related evidence whether IP is source or destination.
    assert {4, 5}.issubset(by_id)
    # API/Sophos endpoint_ip is related evidence too.
    assert 6 in by_id
    # Unrelated traffic stays out.
    assert 7 not in by_id

    assert by_id[1]["severity"] == "informational"
    assert by_id[2]["severity"] == "notice"
    assert by_id[4]["app_name"] == "CEF"
    assert by_id[5]["destination"] == TRIGGER_IP
    assert by_id[6]["source_ip"] == "sophos"

    rendered = "\n".join(m["content"] for m in ai_soc.build_triage_messages(ctx))
    assert "NXLog logon success" in rendered
    assert "NXLog privileged logon" in rendered
    assert "FortiGate outbound traffic" in rendered
    assert "FortiGate inbound traffic" in rendered
    assert "Sophos endpoint event" in rendered
    assert f"dst={TRIGGER_IP}" in rendered


def test_api_alert_can_resolve_related_entity_from_endpoint_ip():
    conn = _context_db()
    conn.executemany(
        "INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (10, "2026-09-01T02:00:00+00:00", "sophos", "sophos", "", "endpoint-a", "Sophos", "warning", "API trigger"),
            (11, "2026-09-01T02:00:01+00:00", "185.1.2.3", "fw", TRIGGER_IP, "fw", "CEF", "notice", "Firewall to endpoint"),
        ],
    )
    conn.execute("INSERT INTO log_fields (log_id,field,value) VALUES (10,'endpoint_ip',?)", (TRIGGER_IP,))
    conn.execute(
        "INSERT INTO alerts (id,created_at,rule_name,severity,source_ip,description,log_ids,ai_status,ai_attempts) "
        "VALUES (2,?,?,?,?,?,?,?,?)",
        ("2026-09-01T02:00:02+00:00", "api_product_alert", "warning", "sophos", "API trigger", "10", "pending", 0),
    )
    conn.commit()

    ctx = ai_soc.gather_alert_context(conn, 2)
    assert ctx["entity_ip"] == TRIGGER_IP
    ids = {r["id"] for r in ctx["related_history"]}
    assert {10, 11}.issubset(ids)


class _LLMStub:
    def __init__(self):
        self.calls = []

    def chat(self, messages, max_tokens=900):
        self.calls.append((messages, max_tokens))
        return "triaged"


def test_error_minimum_does_not_suppress_nxlog_warning_trigger():
    import ai_worker

    conn = _context_db()
    _seed_cross_source_related(conn)
    llm = _LLMStub()

    class NoCloseConn:
        def __getattr__(self, name):
            if name == "close":
                return lambda: None
            return getattr(conn, name)

    worker = ai_worker.TriageWorker(
        get_conn=lambda: NoCloseConn(),
        get_settings=lambda: {
            "enabled": True,
            "auto_triage": True,
            "min_severity": "error",
            "llm": llm,
            "dedup_groups": False,
        },
        batch=5,
    )
    assert worker.run_once() == 1
    row = conn.execute("SELECT ai_status, ai_analysis FROM alerts WHERE id=1").fetchone()
    assert row["ai_status"] == "done"
    assert row["ai_analysis"] == "triaged"
    assert len(llm.calls) == 1
    rendered = "\n".join(m.get("content", "") for m in llm.calls[0][0])
    assert "NXLog logon success" in rendered
    assert "NXLog privileged logon" in rendered
    assert "FortiGate outbound traffic" in rendered
    assert "FortiGate inbound traffic" in rendered
    assert "Sophos endpoint event" in rendered


def test_error_minimum_still_filters_ordinary_firewall_warning_alert():
    import ai_worker

    conn = _context_db()
    conn.execute(
        "INSERT INTO alerts (id,created_at,rule_name,severity,source_ip,description,log_ids,ai_status,ai_attempts) "
        "VALUES (1,?,?,?,?,?,?,?,?)",
        ("2026-09-01T01:02:01+00:00", "firewall_deny_burst", "warning", TRIGGER_IP,
         "ordinary firewall warning", "", "pending", 0),
    )
    conn.commit()
    llm = _LLMStub()

    class NoCloseConn:
        def __getattr__(self, name):
            if name == "close":
                return lambda: None
            return getattr(conn, name)

    worker = ai_worker.TriageWorker(
        get_conn=lambda: NoCloseConn(),
        get_settings=lambda: {
            "enabled": True,
            "auto_triage": True,
            "min_severity": "error",
            "llm": llm,
            "dedup_groups": False,
        },
        batch=5,
    )
    assert worker.run_once() == 0
    row = conn.execute("SELECT ai_status FROM alerts WHERE id=1").fetchone()
    assert row["ai_status"] == "skipped"
    assert not llm.calls

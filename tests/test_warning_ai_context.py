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
            message TEXT,
            format TEXT,
            msg_id TEXT
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
    conn.executemany(
        "INSERT INTO logs (id,received_at,source_ip,peer_ip,destination,hostname,app_name,severity,message) VALUES (?,?,?,?,?,?,?,?,?)",
        events,
    )
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
        "INSERT INTO logs (id,received_at,source_ip,peer_ip,destination,hostname,app_name,severity,message) VALUES (?,?,?,?,?,?,?,?,?)",
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
        return "triaged\nINVESTIGATION_DECISION: SUSPICIOUS"


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
    assert "=== SHORT /" in row["ai_analysis"]
    assert "triaged" in row["ai_analysis"]
    assert "Decision: SUSPICIOUS" in row["ai_analysis"]
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


def test_progressive_auth_profile_expands_time_windows():
    conn = _context_db()
    rows = [
        # Alert anchor is 01:02:01. Short starts ~00:57, Medium ~00:47, Long ~00:02.
        (31, "2026-09-01T00:58:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "informational", "short evidence"),
        (32, "2026-09-01T00:50:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "notice", "medium-only evidence"),
        (33, "2026-09-01T00:10:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "notice", "long-only evidence"),
        (34, "2026-08-31T23:50:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "notice", "outside long"),
        (35, "2026-09-01T01:02:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "warning", "NXLog failed logon"),
    ]
    conn.executemany(
        "INSERT INTO logs (id,received_at,source_ip,peer_ip,destination,hostname,app_name,severity,message) VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.execute("UPDATE logs SET format='json', msg_id='4625' WHERE id=35")
    conn.execute(
        "INSERT INTO alerts (id,created_at,rule_name,severity,source_ip,description,log_ids,ai_status,ai_attempts) "
        "VALUES (3,?,?,?,?,?,?,?,?)",
        ("2026-09-01T01:02:01+00:00", "nxlog_severity_event", "warning", TRIGGER_IP,
         "NXLog failed logon", "35", "pending", 0),
    )
    conn.commit()

    short = ai_soc.gather_alert_context(conn, 3, stage="short")
    medium = ai_soc.gather_alert_context(conn, 3, stage="medium")
    long_ctx = ai_soc.gather_alert_context(conn, 3, stage="long")

    assert short["investigation_profile"] == "auth_anomaly"
    assert {r["id"] for r in short["related_history"]} == {31, 35}
    assert {31, 32, 35}.issubset({r["id"] for r in medium["related_history"]})
    long_ids = {r["id"] for r in long_ctx["related_history"]}
    assert {31, 32, 33, 35}.issubset(long_ids)
    assert 34 not in long_ids


class _SequenceLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def chat(self, messages, max_tokens=900):
        self.calls.append((messages, max_tokens))
        if not self.replies:
            raise AssertionError("unexpected extra LLM call")
        return self.replies.pop(0)


def _run_progressive_worker_with_replies(replies):
    import ai_worker

    conn = _context_db()
    _seed_cross_source_related(conn)
    llm = _SequenceLLM(replies)

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
    return conn, llm, row


def test_progressive_stops_at_short_when_suspicious():
    _, llm, row = _run_progressive_worker_with_replies([
        "short suspicious\\nINVESTIGATION_DECISION: SUSPICIOUS",
    ])
    assert len(llm.calls) == 1
    assert "=== SHORT /" in row["ai_analysis"]
    assert "=== MEDIUM /" not in row["ai_analysis"]
    assert "=== LONG /" not in row["ai_analysis"]


def test_progressive_short_clean_then_medium_suspicious():
    _, llm, row = _run_progressive_worker_with_replies([
        "short clean\\nINVESTIGATION_DECISION: NO_SUSPICIOUS",
        "medium suspicious\\nINVESTIGATION_DECISION: SUSPICIOUS",
    ])
    assert len(llm.calls) == 2
    assert "=== SHORT /" in row["ai_analysis"]
    assert "=== MEDIUM /" in row["ai_analysis"]
    assert "=== LONG /" not in row["ai_analysis"]


def test_progressive_reaches_long_only_after_short_and_medium_do_not_find_suspicion():
    _, llm, row = _run_progressive_worker_with_replies([
        "short clean\\nINVESTIGATION_DECISION: NO_SUSPICIOUS",
        "medium sparse\\nINVESTIGATION_DECISION: INSUFFICIENT",
        "long final\\nINVESTIGATION_DECISION: NO_SUSPICIOUS",
    ])
    assert len(llm.calls) == 3
    assert "=== SHORT /" in row["ai_analysis"]
    assert "=== MEDIUM /" in row["ai_analysis"]
    assert "=== LONG /" in row["ai_analysis"]


def test_missing_decision_marker_fails_open_to_wider_profile():
    _, llm, row = _run_progressive_worker_with_replies([
        "short model forgot marker",
        "medium found it\\nINVESTIGATION_DECISION: SUSPICIOUS",
    ])
    assert len(llm.calls) == 2
    assert "Decision: INSUFFICIENT" in row["ai_analysis"]


def test_long_profile_summarizes_repeated_patterns():
    conn = _context_db()
    conn.execute(
        "INSERT INTO alerts (id,created_at,rule_name,severity,source_ip,description,log_ids,ai_status,ai_attempts) "
        "VALUES (4,?,?,?,?,?,?,?,?)",
        ("2026-09-01T01:10:00+00:00", "high_severity_event", "critical", TRIGGER_IP,
         "beaconing C2 traffic", "", "pending", 0),
    )
    repeated = []
    for i in range(10):
        repeated.append((100+i, f"2026-09-01T01:{i:02d}:00+00:00", TRIGGER_IP, "fw", "185.1.2.3", "fw1", "CEF", "notice", "repeated beacon"))
    conn.executemany(
        "INSERT INTO logs (id,received_at,source_ip,peer_ip,destination,hostname,app_name,severity,message) VALUES (?,?,?,?,?,?,?,?,?)",
        repeated,
    )
    conn.commit()
    ctx = ai_soc.gather_alert_context(conn, 4, stage="long")
    assert ctx["investigation_profile"] == "firewall_c2"
    assert ctx["pattern_summaries"]
    assert ctx["pattern_summaries"][0]["count"] == 10
    # Repeated raw rows are reduced to representative evidence for Long.
    assert len(ctx["related_history"]) <= 3


def test_profile_window_anchors_on_linked_trigger_event_time_not_alert_creation_time():
    conn = _context_db()
    conn.executemany(
        "INSERT INTO logs (id,received_at,source_ip,peer_ip,destination,hostname,app_name,severity,message,format,msg_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [
            (500, "2026-09-01T01:00:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "warning", "failed logon", "json", "4625"),
            (501, "2026-09-01T00:56:00+00:00", TRIGGER_IP, TRIGGER_IP, "", "win1", "Security", "informational", "near trigger", "json", "4624"),
        ],
    )
    # Alert was created much later (e.g. delayed API/queue handling).
    conn.execute(
        "INSERT INTO alerts (id,created_at,rule_name,severity,source_ip,description,log_ids,ai_status,ai_attempts) "
        "VALUES (5,?,?,?,?,?,?,?,?)",
        ("2026-09-01T03:00:00+00:00", "nxlog_severity_event", "warning", TRIGGER_IP,
         "delayed alert", "500", "pending", 0),
    )
    conn.commit()

    ctx = ai_soc.gather_alert_context(conn, 5, stage="short")
    ids = {r["id"] for r in ctx["related_history"]}
    assert {500, 501}.issubset(ids)
    assert ctx["window_start"].startswith("2026-09-01T00:55:00")


def test_long_profile_reduces_repeated_raw_evidence_before_llm():
    conn = _context_db()
    conn.execute(
        "INSERT INTO alerts (id,created_at,rule_name,severity,source_ip,description,log_ids,ai_status,ai_attempts) "
        "VALUES (6,?,?,?,?,?,?,?,?)",
        ("2026-09-01T01:10:00+00:00", "firewall_c2_beacon", "critical", TRIGGER_IP,
         "Repeated beaconing to command and control", "", "pending", 0),
    )
    repeated = []
    for i in range(20):
        repeated.append((600+i, f"2026-09-01T01:{i:02d}:00+00:00", TRIGGER_IP, "fw", "185.1.2.3", "fw1", "CEF", "notice", "same beacon"))
    conn.executemany(
        "INSERT INTO logs (id,received_at,source_ip,peer_ip,destination,hostname,app_name,severity,message) VALUES (?,?,?,?,?,?,?,?,?)",
        repeated,
    )
    conn.commit()

    ctx = ai_soc.gather_alert_context(conn, 6, stage="long")
    assert ctx["candidate_count"] == 20
    assert ctx["pattern_summaries"][0]["count"] == 20
    # Exact repeated shape is represented by first/closest/last, not 20 raw rows.
    assert len(ctx["related_history"]) <= 3


def test_ip_ioc_investigation_prefers_indicator_ip_as_related_entity():
    conn = _context_db()
    internal = "192.168.1.50"
    indicator = "203.0.113.77"
    conn.executemany(
        "INSERT INTO logs (id,received_at,source_ip,peer_ip,destination,hostname,app_name,severity,message) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (700, "2026-09-01T01:00:00+00:00", internal, "fw", indicator, "fw1", "CEF", "warning", "IOC destination hit"),
            (701, "2026-09-01T00:59:00+00:00", "10.0.0.8", "fw", indicator, "fw1", "CEF", "notice", "other host to same IOC"),
        ],
    )
    conn.execute(
        "INSERT INTO alerts (id,created_at,rule_name,severity,source_ip,description,log_ids,ai_status,ai_attempts) "
        "VALUES (7,?,?,?,?,?,?,?,?)",
        ("2026-09-01T01:00:01+00:00", "threat_intel_match", "warning", internal,
         f"IOC match (ip): {indicator} — known C2", "700", "pending", 0),
    )
    conn.commit()
    ctx = ai_soc.gather_alert_context(conn, 7, stage="short")
    assert ctx["investigation_profile"] == "ioc_hit"
    assert ctx["entity_ip"] == indicator
    assert {700, 701}.issubset({r["id"] for r in ctx["related_history"]})

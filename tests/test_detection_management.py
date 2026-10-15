import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

import db
import detection
from detection_runtime import TelemetryMonitor
from listener import Storage, parse_syslog, IngestPipeline
from rules import RuleEngine
from windows_events import normalize_windows, timestamp


def event(**overrides):
    raw = dict(EventID=4688, Channel="Security", SourceName="Microsoft-Windows-Security-Auditing",
               Hostname="HMSWEB1", EventTime="2026-10-15T22:56:35+08:00",
               NewProcessName=r"C:\Windows\System32\cmd.exe", ParentProcessName=r"C:\Tomcat\tomcat7.exe",
               CommandLine="cmd.exe /c whoami", NewProcessId="0x2bc", ProcessId="0xe74",
               SubjectUserName="SYSTEM", SubjectUserSid="S-1-5-18", TargetUserSid="S-1-5-21-123",
               EventRecordID=1234)
    raw.update(overrides)
    return parse_syslog(json.dumps(raw), "10.0.0.10")


def config():
    cfg = detection.defaults()
    cfg["hosts"] = [{"hostname": "HMSWEB1", "timezone": "Asia/Taipei", "groups": ["web"], "roles": ["web_server"]}]
    cfg["schedules"] = [{"id": "office", "name": "Office", "timezone": "Asia/Taipei", "hosts": [], "groups": ["web"],
                         "weekdays": [0, 1, 2, 3, 4], "start": "09:00", "end": "18:00", "dates": [], "exclude_dates": []}]
    return cfg


def fields(**overrides):
    return event(**overrides)["_normalized"]


@pytest.fixture
def store(tmp_path):
    obj = Storage(db_config=db.config_from_path(str(tmp_path / "test.db")))
    yield obj
    obj.close()


def test_source_qualified_4688_mapping_retains_original_evidence():
    e = event()
    f = e["_normalized"]
    assert f["event.kind"] == "process_creation"
    assert f["process.pid"] == "700" and f["process.parent.pid"] == "3700"
    assert f["user.creator.sid"] == "S-1-5-18" and f["user.target.sid"] == "S-1-5-21-123"
    assert f["process.parent.name"] == "tomcat7.exe"
    assert f["event.record_id"] == "1234"
    assert json.loads(e["raw"])["NewProcessId"] == "0x2bc"
    assert timestamp(f["event.time"]).hour == 14


@pytest.mark.parametrize("override", [dict(SourceName="Vendor-Other"), dict(Channel="System"), dict(EventID=1)])
def test_wrong_provider_channel_or_id_does_not_become_process_event(override):
    assert normalize_windows(event(**override)) == {}


def test_nested_eventdata_mapping_and_powershell_script_event():
    e = {"_json": {"Event": {"System": {"Provider": {"Name": "Microsoft-Windows-Sysmon"}, "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
            "Computer": "HMSWEB1", "TimeCreated": {"SystemTime": "2026-10-15T14:56:35Z"}},
            "EventData": {"Data": [{"Name": "Image", "#text": r"C:\Windows\cmd.exe"}, {"Name": "ProcessGuid", "#text": "{guid}"}]}}}, "received_at": "2026-10-15T14:56:45Z"}
    f = normalize_windows(e)
    assert f["process.guid"] == "{guid}" and f["event.ingest_delay_seconds"] == "10.0"
    f = fields(EventID=4104, Channel="Microsoft-Windows-PowerShell/Operational", SourceName="Microsoft-Windows-PowerShell", ScriptBlockText="Get-Process", ScriptBlockId="script-1")
    assert f["event.kind"] == "script_execution" and f["script.text"] == "Get-Process"


@pytest.mark.parametrize("parent,child", [("tomcat7.exe", "cmd.exe"), ("w3wp.exe", "powershell.exe")])
@pytest.mark.parametrize("hour", ["14", "22"])
def test_web_shell_always_critical(parent, child, hour):
    result = detection.evaluate(config(), fields(ParentProcessName=parent, NewProcessName=child, EventTime=f"2026-10-15T{hour}:00:00+08:00"))
    matches = [r for r in result["findings"] if r["rule_id"] == "web_server_shell"]
    assert len(matches) == 1 and matches[0]["severity"] == "critical"


def test_java_requires_host_role_and_normal_admin_shell_is_not_web_shell():
    cfg = config()
    f = fields(ParentProcessName="java.exe")
    assert any(x["rule_id"] == "web_server_shell" for x in detection.evaluate(cfg, f)["findings"])
    cfg["hosts"][0]["roles"] = []
    assert not any(x["rule_id"] == "web_server_shell" for x in detection.evaluate(cfg, f)["findings"])
    assert not detection.evaluate(config(), fields(ParentProcessName="explorer.exe", EventTime="2026-10-15T14:00:00+08:00"))["findings"]


@pytest.mark.parametrize("child", ["cmd.exe", "powershell.exe", "pwsh.exe"])
def test_after_hours_shell_high(child):
    matches = detection.evaluate(config(), fields(NewProcessName=child, ParentProcessName="explorer.exe"))["findings"]
    assert len(matches) == 1 and matches[0]["rule_id"] == "out_of_hours_shell" and matches[0]["severity"] == "error"


def test_schedule_unconfigured_and_bad_time_are_explicitly_unknown():
    assert not detection.evaluate(detection.defaults(), fields(ParentProcessName="explorer.exe"))["findings"]
    result = detection.evaluate(config(), fields(EventTime="invalid", ParentProcessName="explorer.exe"))
    assert result["time_status"].startswith("unknown") and not result["findings"]
    assert detection.evaluate(config(), fields(EventTime="2026-10-15 22:56:35"))["time_status"] == "valid"
    assert timestamp("2026-11-01T01:30:00", "America/New_York") is None
    assert timestamp("2026-03-08T02:30:00", "America/New_York") is None


def test_overnight_boundary_holiday_and_explicit_date():
    s = config()["schedules"][0]
    s.update(weekdays=[4], start="22:00", end="02:00")
    assert detection.in_window(s, timestamp("2026-10-17T01:00:00+08:00"))
    assert not detection.in_window(s, timestamp("2026-10-17T02:00:00+08:00"))
    s["exclude_dates"] = ["2026-10-17"]
    assert not detection.in_window(s, timestamp("2026-10-17T01:00:00+08:00"))
    s["dates"] = ["2026-10-18"]
    assert detection.in_window(s, timestamp("2026-10-18T23:00:00+08:00"))


def exception():
    return {"id": "backup", "rule_id": "out_of_hours_shell", "hosts": ["HMSWEB1"], "groups": [],
            "process_path": r"C:\Windows\System32\powershell.exe", "parent_path": r"C:\Windows\System32\taskeng.exe",
            "command_glob": r"powershell.exe -File C:\Scripts\backup.ps1", "user": "SYSTEM", "schedule_id": "backup-window",
            "expires_at": "2027-01-01T00:00:00+08:00", "approved_by": "admin", "ticket": "CHG-123"}


def test_scoped_backup_exception_and_expiry_preserve_other_rules():
    cfg = config()
    night = copy.deepcopy(cfg["schedules"][0]); night.update(id="backup-window", start="02:00", end="02:30", weekdays=list(range(7)))
    # A backup exception window must not also approve all shell executions.
    night["exception_only"] = True
    cfg["schedules"].append(night)
    cfg["exceptions"] = [exception()]
    f = fields(EventTime="2026-10-16T02:10:00+08:00", NewProcessName=exception()["process_path"], ParentProcessName=exception()["parent_path"], CommandLine=exception()["command_glob"])
    now = timestamp("2026-10-16T02:11:00+08:00")
    result = detection.evaluate(cfg, f, now)
    assert result["suppressed"] == [{"rule_id": "out_of_hours_shell", "exception_id": "backup"}]
    assert not result["findings"]
    cfg["exceptions"][0]["expires_at"] = "2026-10-15T00:00:00+08:00"
    assert detection.evaluate(cfg, f, now)["findings"]
    cfg["exceptions"][0]["rule_id"] = "web_server_shell"
    with pytest.raises(ValueError): detection.validate_config(cfg)


def test_dedup_security_and_sysmon_links_both_raw_events(store):
    cfg = config(); detection.save_config(store.conn, cfg, "analyst-admin")
    engine = RuleEngine(store)
    first = event(); first_id = store.insert_log(first, fields=first["_normalized"]); engine.process(first_id, first)
    second = event(EventID=1, Channel="Microsoft-Windows-Sysmon/Operational", SourceName="Microsoft-Windows-Sysmon",
                   Image=first["_json"]["NewProcessName"], ParentImage=first["_json"]["ParentProcessName"], ProcessId="700", ParentProcessId="3700", ProcessGuid="{guid}")
    second_id = store.insert_log(second, fields=second["_normalized"]); engine.process(second_id, second)
    rows = store.conn.execute("SELECT * FROM alerts WHERE rule_name='web_server_shell'").fetchall()
    assert len(rows) == 1
    assert rows[0]["log_ids"] == f"{first_id},{second_id}"
    assert detection.describe_alert(dict(rows[0]))["detection_evidence"]["occurrences"] == 2
    assert store.conn.execute("SELECT COUNT(*) AS n FROM logs").fetchone()["n"] == 2
    # Restarting the engine does not lose the bounded persisted duplicate key.
    RuleEngine(store).process(second_id, second)
    assert store.conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE rule_name='web_server_shell'").fetchone()["n"] == 1


def test_different_process_or_time_never_deduplicates(store):
    engine = RuleEngine(store)
    for e in [event(), event(NewProcessId="0x2bd"), event(EventTime="2026-10-15T22:57:35+08:00")]:
        engine.process(store.insert_log(e), e)
    assert store.conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE rule_name='web_server_shell'").fetchone()["n"] == 3


def test_config_revision_audit_atomicity_and_live_builtin_toggle(store):
    cfg = config(); saved = detection.save_config(store.conn, cfg, "operator", "127.0.0.1")
    assert saved["revision"] == 1
    with pytest.raises(detection.ConfigConflict): detection.save_config(store.conn, cfg, "operator")
    audit = json.loads(store.conn.execute("SELECT detail FROM audit_log WHERE action='detection_config_changed'").fetchone()["detail"])
    assert audit["before"]["revision"] == 0 and audit["after"]["revision"] == 1
    for r in saved["rules"]:
        if r["id"] == "high_severity_event": r["enabled"] = False
    detection.save_config(store.conn, saved, "operator")
    engine = RuleEngine(store); e = parse_syslog("<130>Oct 15 14:00:00 fw app: critical test", "10.1.1.1")
    engine.process(store.insert_log(e), e)
    assert not store.conn.execute("SELECT id FROM alerts WHERE rule_name='high_severity_event'").fetchone()


def test_custom_script_conditions_and_validation():
    cfg = config(); cfg["rules"].append({"id": "script_test", "name": "Script test", "kind": "match", "severity": "warning", "enabled": True,
        "conditions": [{"field": "event.kind", "op": "equals", "value": "script_execution"}, {"field": "script.text", "op": "contains", "value": "Invoke-WebRequest"}]})
    detection.validate_config(cfg)
    f = fields(EventID=4104, Channel="Microsoft-Windows-PowerShell/Operational", SourceName="Microsoft-Windows-PowerShell", ScriptBlockText="Invoke-WebRequest https://example.invalid")
    assert detection.evaluate(cfg, f)["findings"][0]["rule_id"] == "script_test"
    cfg["rules"][-1]["conditions"][0]["op"] = "eval"
    with pytest.raises(ValueError): detection.validate_config(cfg)


def test_telemetry_silence_is_source_specific_and_survives_monitor_restart(store):
    cfg = config(); cfg["hosts"][0].update(telemetry_enabled=True, max_silence_seconds=60, expected_sources=["security_4688"])
    detection.save_config(store.conn, cfg, "operator")
    monitor = TelemetryMonitor(store)
    now = datetime.now(timezone.utc)
    assert monitor.tick(now)["hmsweb1|security_4688"]["status"] == "waiting"
    monitor.tick(now + timedelta(seconds=61)); monitor.tick(now + timedelta(seconds=62))
    TelemetryMonitor(store).tick(now + timedelta(seconds=63))
    assert store.conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE rule_name='telemetry_silence'").fetchone()["n"] == 1
    monitor.observe(fields())
    assert monitor.tick()["hmsweb1|security_4688"]["status"] == "receiving"


def test_async_pipeline_runs_detection_after_persisting_log(store):
    pipeline = IngestPipeline(store, rules=RuleEngine(store))
    try:
        assert pipeline.submit(event()["raw"], "10.0.0.1", transport="tcp")
        pipeline.queue.join()
        assert pipeline.stats()["failed"] == 0
        assert store.conn.execute("SELECT id FROM alerts WHERE rule_name='web_server_shell'").fetchone()
    finally:
        pipeline.stop(drain=True)


def test_process_alert_uses_existing_notification_worker_once(store, monkeypatch):
    import workers
    engine = RuleEngine(store)
    e = event()
    first_id = store.insert_log(e)
    engine.process(first_id, e)
    engine.process(store.insert_log(e), e)
    cfg = db.config_from_path(store.conn.execute("PRAGMA database_list").fetchone()["file"])
    sent = []
    def fake_http(url, **kwargs):
        sent.append(json.loads(kwargs["body"]))
        return 201, '{"id":"fixture-ticket"}'
    monkeypatch.setattr(workers, "_http", fake_http)
    worker = workers.TicketWorker(lambda: db.connect(cfg), lambda: {"enabled": True, "url": "https://fixture.invalid/tickets", "min_severity": "warning"})
    assert worker.run_once() == 1
    assert worker.run_once() == 0 and len(sent) == 1


def test_host_timezone_enters_index_and_typed_projection(store):
    from normalize import FieldIndexer
    import event_storage_v2
    detection.save_config(store.conn, config(), "operator")
    indexer = object.__new__(FieldIndexer)
    indexer._patterns = []
    indexer._detection_config = config()
    e = event(EventTime="2026-10-15 22:56:35")
    f = indexer.extract(e)
    assert f["event.time"] == "2026-10-15T14:56:35+00:00"
    projection = event_storage_v2.normalized_projection(e, f)
    assert projection["event_time"] == f["event.time"]
    assert projection["event_type"] == "process_creation" and projection["user_name"] == "SYSTEM"
    log_id = store.insert_log(e, fields=f)
    import normalize
    normalize.reindex(store.conn)
    rows = store.conn.execute("SELECT field,value FROM log_fields WHERE log_id=?", (log_id,)).fetchall()
    indexed = {row["field"]: row["value"] for row in rows}
    assert indexed["process.name"] == "cmd.exe" and indexed["event.time"] == f["event.time"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    import dashboard
    cfg = db.config_from_path(str(tmp_path / "dashboard.db"))
    monkeypatch.setattr(dashboard, "DB_CONFIG", cfg)
    dashboard.init_auth(None)
    with dashboard.app.test_client() as c:
        with c.session_transaction() as s:
            s.update(user="admin", role="admin", must_change=False, csrf_token="test-csrf")
        yield c
    if dashboard._HTTP_PIPELINE:
        dashboard._HTTP_PIPELINE[2].stop_monitor()
        dashboard._HTTP_PIPELINE[1].close()
        dashboard._HTTP_PIPELINE = None


HEADERS = {"X-CSRF-Token": "test-csrf"}


def test_management_pages_routes_auth_csrf_and_conflict(client):
    for page in ["/detection-rules", "/execution-windows", "/security-alerts", "/ai"]:
        assert client.get(page).status_code == 200
    cfg = client.get("/api/detection/config").get_json()
    assert client.put("/api/detection/config", json=cfg).status_code == 403
    assert client.put("/api/detection/config", json=cfg, headers=HEADERS).status_code == 200
    assert client.put("/api/detection/config", json=cfg, headers=HEADERS).status_code == 409
    with client.session_transaction() as s: s["role"] = "viewer"
    saved = client.get("/api/detection/config").get_json()
    assert client.put("/api/detection/config", json=saved, headers=HEADERS).status_code == 403
    assert client.get("/api/detection/alerts").status_code == 200


def test_simulation_has_no_side_effects_and_dead_routes_are_removed(client):
    import dashboard
    r = client.post("/api/detection/simulate", json={"event": event()["_json"]}, headers=HEADERS)
    assert r.status_code == 200 and r.get_json()["findings"][0]["severity"] == "critical"
    conn = db.connect(dashboard.DB_CONFIG)
    assert conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"] == 0
    conn.close()
    for route in ["/api/correlate", "/api/normalize"]:
        assert client.post(route, json={}, headers=HEADERS).status_code == 404


def test_standalone_dashboard_http_ingest_and_evidence(client):
    import dashboard
    assert dashboard._ingest_raw(event()["raw"], "10.0.0.1")
    alerts = client.get("/api/detection/alerts").get_json()
    assert alerts[0]["detection_evidence"]["fields"]["process.name"] == "cmd.exe"
    result = client.get(f"/api/detection/alerts/{alerts[0]['id']}/evidence").get_json()
    assert json.loads(result["events"][0]["raw"])["NewProcessName"].endswith("cmd.exe")


def test_api_key_only_ingestion_preserves_windows_json_and_runs_rules(client):
    import dashboard
    response = client.post("/api/ingest/keys", json={"name": "synthetic-source"}, headers=HEADERS)
    assert response.status_code == 200
    key = response.get_json()["api_key"]
    anonymous = dashboard.app.test_client()
    assert anonymous.post("/api/ingest", json=event()["_json"]).status_code == 401
    assert anonymous.post("/api/ingest", json=event()["_json"], headers={"X-API-Key": "invalid"}).status_code == 401
    result = anonymous.post("/api/ingest", json=event()["_json"], headers={"X-API-Key": key})
    assert result.status_code == 200 and result.get_json()["ingested"] == 1
    alerts = client.get("/api/detection/alerts").get_json()
    assert alerts[0]["rule_name"] == "web_server_shell"
    assert anonymous.get("/api/detection/config").status_code == 401


def test_ai_usage_cost_rates_account_for_cached_input_and_unpriced_calls(client):
    import dashboard
    import ai_config_store
    conn = db.connect(dashboard.DB_CONFIG)
    ai_config_store.record_usage(conn, {"provider": "fixture", "model": "test", "input_tokens": 1000, "cached_tokens": 400, "output_tokens": 100, "total_tokens": 1100, "status": "ok"})
    ai_config_store.record_usage(conn, {"provider": "other", "model": "test", "input_tokens": 10, "status": "error"})
    conn.close()
    data = client.get("/api/ai/usage").get_json()
    assert data["cost"]["estimated_usd"] is None and data["cost"]["unpriced_calls"] == 2
    rates = [{"provider": "fixture", "model": "test", "input": 2, "cached": 1, "output": 4}]
    assert client.put("/api/ai/usage/rates", json={"rates": rates}, headers=HEADERS).status_code == 200
    data = client.get("/api/ai/usage").get_json()
    assert data["cost"]["estimated_usd"] == 0.002 and data["cost"]["unpriced_calls"] == 1
    rates[0]["input"] = -1
    assert client.put("/api/ai/usage/rates", json={"rates": rates}, headers=HEADERS).status_code == 400

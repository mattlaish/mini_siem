"""Hardening for detection management: stored-config robustness and engine
isolation, short-name/FQDN host matching, web-shell defaults, and all-events
field-match rules with stream aggregation."""
import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

import db
import detection
import normalize
from detection_runtime import TelemetryMonitor, UNPROFILED_KEY
from listener import Storage, parse_syslog
from rules import RuleEngine
from windows_events import find_host_profile, host_matches


def win_event(**overrides):
    raw = dict(EventID=4688, Channel="Security", SourceName="Microsoft-Windows-Security-Auditing",
               Hostname="HMSWEB1", EventTime="2026-10-15T22:56:35+08:00",
               NewProcessName=r"C:\Windows\System32\cmd.exe", ParentProcessName=r"C:\Tomcat\tomcat7.exe",
               CommandLine="cmd.exe /c whoami", NewProcessId="0x2bc", ProcessId="0xe74", SubjectUserName="SYSTEM")
    raw.update(overrides)
    return parse_syslog(json.dumps(raw), "10.0.0.10")


def config(hostname="HMSWEB1"):
    cfg = detection.defaults()
    cfg["hosts"] = [{"hostname": hostname, "timezone": "Asia/Taipei", "groups": ["web"], "roles": ["web_server"]}]
    cfg["schedules"] = [{"id": "office", "name": "Office", "timezone": "Asia/Taipei", "hosts": [], "groups": ["web"],
                         "weekdays": [0, 1, 2, 3, 4], "start": "09:00", "end": "18:00", "dates": [], "exclude_dates": []}]
    return cfg


def put_raw_config(conn, value):
    conn.execute("INSERT INTO app_config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (detection.CONFIG_KEY, value if isinstance(value, str) else json.dumps(value)))
    conn.commit()


def ingest(store, engine, raw):
    event = parse_syslog(raw, "10.9.9.9")
    fields = normalize.extract_fields(event.get("message"), [], json_obj=event.get("_json"))
    log_id = store.insert_log(event, fields=fields)
    engine.process(log_id, event, fields=fields)
    return log_id


def count(store, rule):
    return store.conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE rule_name=?", (rule,)).fetchone()["n"]


@pytest.fixture
def store(tmp_path):
    obj = Storage(db_config=db.config_from_path(str(tmp_path / "hardening.db")))
    yield obj
    obj.close()


# ---------------------------------------------------------------- 1. robustness

def test_config_saved_by_older_release_is_migrated_not_rejected(store):
    stale = detection.defaults()
    stale["rules"] = [r for r in stale["rules"] if r["id"] != "firewall_deny_burst"]
    del stale["exceptions"]
    put_raw_config(store.conn, stale)
    loaded = detection.load_config(store.conn)
    assert "firewall_deny_burst" in {r["id"] for r in loaded["rules"]} and loaded["exceptions"] == []
    engine = RuleEngine(store)
    engine.process(store.insert_log(win_event()), win_event())
    assert engine.errors == 0 and count(store, "web_server_shell") == 1


def test_unloadable_config_keeps_last_good_and_never_raises(store):
    detection.save_config(store.conn, config(), "admin")
    engine = RuleEngine(store)
    first = win_event()
    engine.process(store.insert_log(first), first)
    assert engine.config["revision"] == 1
    bad = config(); bad["revision"] = 7; bad["hosts"][0]["timezone"] = "Not/AZone"
    put_raw_config(store.conn, bad)
    engine._reload_at = 0
    second = win_event(NewProcessId="0x2bd")
    engine.process(store.insert_log(second), second)          # must not raise
    assert engine.config["revision"] == 1 and engine.errors == 1 and "Not/AZone" in engine.last_error
    assert count(store, "web_server_shell") == 2               # detection kept working on last good config
    fallback, warning = detection.load_config_or_fallback(store.conn)
    assert warning and fallback["revision"] == 7 and fallback["hosts"] == []


def test_corrupt_rows_do_not_wedge_saves_or_alert_writes(store):
    put_raw_config(store.conn, "{not json")
    fallback, warning = detection.load_config_or_fallback(store.conn)
    assert warning and fallback["revision"] == 0
    assert detection.save_config(store.conn, fallback, "admin")["revision"] == 1
    store.conn.execute("INSERT INTO app_config(key,value) VALUES(?,?)", (detection.STATE_KEY, "[]"))
    store.conn.commit()
    engine = RuleEngine(store)
    engine.process(store.insert_log(win_event()), win_event())
    assert engine.errors == 0 and count(store, "web_server_shell") == 1


def test_alert_write_failure_is_isolated_and_connection_stays_usable(store, monkeypatch):
    engine = RuleEngine(store)
    monkeypatch.setattr(detection, "emit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    engine.process(store.insert_log(win_event()), win_event())   # must not raise
    assert engine.errors == 1 and "db down" in engine.last_error
    assert store.insert_log(win_event()) > 0                      # caller's later writes still work


def test_fallback_config_is_editable_through_the_api(tmp_path, monkeypatch):
    import dashboard
    cfg = db.config_from_path(str(tmp_path / "api.db"))
    monkeypatch.setattr(dashboard, "DB_CONFIG", cfg)
    dashboard.init_auth(None)
    conn = db.connect(cfg)
    bad = config(); bad["revision"] = 3; bad["hosts"][0]["timezone"] = "Not/AZone"
    put_raw_config(conn, bad); conn.close()
    with dashboard.app.test_client() as c:
        with c.session_transaction() as s:
            s.update(user="admin", role="admin", must_change=False, csrf_token="t")
        got = c.get("/api/detection/config").get_json()
        assert "rejected" in got["load_warning"] and got["revision"] == 3
        saved = c.put("/api/detection/config", json=got, headers={"X-CSRF-Token": "t"})
        assert saved.status_code == 200 and saved.get_json()["revision"] == 4
        assert "load_warning" not in c.get("/api/detection/config").get_json()


# ---------------------------------------------------------------- 2. hostnames

@pytest.mark.parametrize("configured,observed,expected", [
    ("HMSWEB1", "hmsweb1.corp.example.com", True),
    ("hmsweb1.corp.example.com", "HMSWEB1", True),
    ("HMSWEB1.", "hmsweb1", True),
    ("web1.a.example", "web1.b.example", False),
    ("10.0.0.5", "10", False),
    ("10", "10.0.0.5", False),
    ("web1", "web10.corp", False),
    ("", "web1", False),
])
def test_host_matches(configured, observed, expected):
    assert host_matches(configured, observed) is expected


def test_profile_prefers_exact_and_refuses_ambiguous_short_name():
    hosts = [{"hostname": "web1.a.example"}, {"hostname": "web1.b.example"}, {"hostname": "WEB1"}]
    assert find_host_profile(hosts, "web1")["hostname"] == "WEB1"
    assert find_host_profile(hosts[:2], "web1") == {}
    assert find_host_profile(hosts[:1], "WEB1")["hostname"] == "web1.a.example"


def test_fqdn_events_use_short_name_profile_for_schedule_role_and_timezone():
    cfg = config("HMSWEB1")
    f = win_event(Hostname="HMSWEB1.corp.example.com", ParentProcessName=r"C:\Windows\explorer.exe",
                  EventTime="2026-10-15T03:00:00")["_normalized"]   # naive: needs the profile timezone
    result = detection.evaluate(cfg, f)
    assert result["host_profile"] == "HMSWEB1" and result["time_status"] == "valid"
    assert [x["rule_id"] for x in result["findings"]] == ["out_of_hours_shell"]
    java = win_event(Hostname="HMSWEB1.corp.example.com", ParentProcessName=r"C:\Java\bin\java.exe")["_normalized"]
    assert "web_server_shell" in {x["rule_id"] for x in detection.evaluate(cfg, java)["findings"]}


def test_telemetry_attributes_fqdn_events_and_lists_unprofiled_hosts(store):
    cfg = config("HMSWEB1"); cfg["hosts"][0].update(telemetry_enabled=True, max_silence_seconds=60)
    detection.save_config(store.conn, cfg, "admin")
    monitor = TelemetryMonitor(store)
    monitor.observe(win_event(Hostname="HMSWEB1.corp.example.com")["_normalized"])
    monitor.observe(win_event(Hostname="DB02.corp.example.com")["_normalized"])
    state = monitor.tick()
    assert state["hmsweb1|security_4688"]["status"] == "receiving"
    seen = json.loads(store.conn.execute("SELECT value FROM app_config WHERE key=?", (UNPROFILED_KEY,)).fetchone()["value"])
    assert list(seen) == ["db02.corp.example.com"] and seen["db02.corp.example.com"]["sources"] == ["security_4688"]


def test_telemetry_skips_tick_without_pruning_state_when_config_is_bad(store):
    cfg = config(); cfg["hosts"][0].update(telemetry_enabled=True, max_silence_seconds=60)
    detection.save_config(store.conn, cfg, "admin")
    monitor = TelemetryMonitor(store)
    now = datetime.now(timezone.utc)
    monitor.tick(now)
    before = store.conn.execute("SELECT value FROM app_config WHERE key='detection_telemetry_v1'").fetchone()["value"]
    bad = copy.deepcopy(cfg); bad["revision"] = 1; bad["hosts"][0]["timezone"] = "Not/AZone"
    put_raw_config(store.conn, bad)
    assert monitor.tick(now + timedelta(seconds=120)) == {}
    after = store.conn.execute("SELECT value FROM app_config WHERE key='detection_telemetry_v1'").fetchone()["value"]
    assert after == before and count(store, "telemetry_silence") == 0


# ---------------------------------------------------------------- 3. web-shell defaults

@pytest.mark.parametrize("parent", [r"C:\Program Files\Apache Software Foundation\Tomcat 9.0\bin\Tomcat9.exe",
                                    r"C:\Tomcat10\bin\tomcat10.exe", r"C:\Tomcat11\bin\tomcat11.exe",
                                    r"C:\Tomcat8\bin\tomcat8.exe", r"C:\php\php-cgi.exe"])
def test_modern_tomcat_and_php_parents_are_covered(parent):
    f = win_event(ParentProcessName=parent)["_normalized"]
    assert "web_server_shell" in {x["rule_id"] for x in detection.evaluate(detection.defaults(), f)["findings"]}


@pytest.mark.parametrize("child,fires", [("whoami.exe", True), ("certutil.exe", True), ("rundll32.exe", True),
                                         ("net1.exe", True), ("mshta.exe", True),
                                         ("csc.exe", False), ("conhost.exe", False)])
def test_w3wp_direct_recon_children(child, fires):
    f = win_event(ParentProcessName=r"C:\Windows\System32\inetsrv\w3wp.exe",
                  NewProcessName="C:\\Windows\\System32\\" + child)["_normalized"]
    found = "web_server_shell" in {x["rule_id"] for x in detection.evaluate(detection.defaults(), f)["findings"]}
    assert found is fires


# ---------------------------------------------------------------- 4. all-events rules

def deny_rule(scope="all"):
    return {"id": "fw_admin_deny", "name": "Firewall deny for admin", "kind": "match", "scope": scope,
            "enabled": True, "severity": "warning",
            "conditions": [{"field": "field.action", "op": "equals", "value": "deny"},
                           {"field": "message", "op": "contains", "value": "user=admin"}]}


FW_LINE = "<134>Oct 15 14:00:00 fw01 filterlog: action=deny src=10.9.9.9 dst=10.0.0.5 user=admin"


def test_all_events_rule_matches_syslog_and_aggregates_one_alert(store):
    cfg = config(); cfg["rules"].append(deny_rule())
    detection.save_config(store.conn, cfg, "admin")
    engine = RuleEngine(store)
    ids = [ingest(store, engine, FW_LINE) for _ in range(3)]
    ingest(store, engine, FW_LINE.replace("action=deny", "action=accept"))
    rows = store.conn.execute("SELECT * FROM alerts WHERE rule_name='fw_admin_deny'").fetchall()
    assert len(rows) == 1 and rows[0]["log_ids"] == ",".join(map(str, ids))
    evidence = detection.describe_alert(dict(rows[0]))
    assert evidence["detection_evidence"]["occurrences"] == 3
    assert "fw01" in evidence["description"] and "action=deny" in evidence["description"]
    assert engine.errors == 0


def test_windows_scope_rule_ignores_syslog_and_legacy_rules_default_to_windows(store):
    cfg = config(); rule = deny_rule(scope="windows"); cfg["rules"].append(rule)
    detection.save_config(store.conn, cfg, "admin")
    engine = RuleEngine(store)
    ingest(store, engine, FW_LINE)
    assert count(store, "fw_admin_deny") == 0
    legacy = dict(rule); legacy.pop("scope")
    assert detection.validate_config({**config(), "rules": config()["rules"] + [legacy]})


def test_scope_and_field_name_validation():
    for bad in [dict(scope="everything"),
                dict(conditions=[{"field": "field.bad name", "op": "equals", "value": "x"}]),
                dict(conditions=[{"field": "nonexistent", "op": "equals", "value": "x"}])]:
        cfg = config(); cfg["rules"].append({**deny_rule(), **bad})
        with pytest.raises(ValueError):
            detection.validate_config(cfg)


def test_exceptions_on_rules_they_cannot_apply_to_are_rejected_on_save_only(store):
    cfg = config()
    cfg["schedules"].append({"id": "night", "name": "Night", "timezone": "Asia/Taipei", "hosts": ["HMSWEB1"],
                             "groups": [], "weekdays": [0], "start": "01:00", "end": "02:00", "exception_only": True})
    cfg["exceptions"] = [{"id": "x1", "rule_id": "ssh_bruteforce", "hosts": ["HMSWEB1"], "groups": [],
                          "process_path": r"C:\a.exe", "parent_path": r"C:\b.exe", "command_glob": "a.exe *",
                          "user": "svc", "schedule_id": "night", "expires_at": "2027-01-01T00:00:00+08:00",
                          "approved_by": "admin", "ticket": "CHG-1"}]
    detection.validate_config(cfg)                         # an already-stored copy stays loadable
    with pytest.raises(ValueError, match="cannot apply"):
        detection.save_config(store.conn, cfg, "admin")
    cfg["exceptions"][0]["rule_id"] = "out_of_hours_shell"
    assert detection.save_config(store.conn, cfg, "admin")["revision"] == 1


def test_simulator_accepts_raw_syslog_and_any_json(tmp_path, monkeypatch):
    import dashboard
    cfg = db.config_from_path(str(tmp_path / "sim.db"))
    monkeypatch.setattr(dashboard, "DB_CONFIG", cfg)
    dashboard.init_auth(None)
    draft = config(); draft["rules"].append(deny_rule())
    with dashboard.app.test_client() as c:
        with c.session_transaction() as s:
            s.update(user="viewer", role="viewer", must_change=False, csrf_token="t")
        h = {"X-CSRF-Token": "t"}
        raw = c.post("/api/detection/simulate", json={"raw": FW_LINE, "config": draft}, headers=h).get_json()
        assert raw["windows_event"] is False and raw["findings"][0]["rule_id"] == "fw_admin_deny"
        assert raw["normalized"]["field.action"] == "deny"
        js = c.post("/api/detection/simulate", json={"event": {"message": "user=admin", "action": "deny"}, "config": draft},
                    headers=h).get_json()
        assert [f["rule_id"] for f in js["findings"]] == ["fw_admin_deny"]
        win = c.post("/api/detection/simulate", json={"event": json.loads(win_event()["raw"])}, headers=h).get_json()
        assert win["windows_event"] is True and win["findings"][0]["rule_id"] == "web_server_shell"
        conn = db.connect(cfg)
        assert conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"] == 0
        conn.close()

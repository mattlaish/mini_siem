"""Bulk/group alert triage, background-tab alert check, near-miss replay
("why didn't this rule fire?") and the label/guard fixes."""
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import db
import detection
import rules

ROOT = Path(__file__).resolve().parents[1]
H = {"X-CSRF-Token": "t"}


@pytest.fixture
def app_db(tmp_path, monkeypatch):
    import dashboard
    cfg = db.config_from_path(str(tmp_path / "triage.db"))
    monkeypatch.setattr(dashboard, "DB_CONFIG", cfg)
    dashboard.init_auth(None)
    db.initialize(cfg)
    yield dashboard, cfg
    if dashboard._HTTP_PIPELINE:
        dashboard._HTTP_PIPELINE[2].stop_monitor()
        dashboard._HTTP_PIPELINE[1].close()
        dashboard._HTTP_PIPELINE = None


def client(dashboard, role="analyst", user="alice"):
    c = dashboard.app.test_client()
    with c.session_transaction() as s:
        s.update(user=user, role=role, must_change=False, csrf_token="t")
    return c


def add_alerts(cfg, n, rule="ssh_bruteforce", severity="critical"):
    conn = db.connect(cfg)
    for _ in range(n):
        conn.execute("INSERT INTO alerts(created_at,rule_name,severity,source_ip,description,log_ids) VALUES(?,?,?,?,?,?)",
                     (datetime.now(timezone.utc).isoformat(), rule, severity, "203.0.113.5", "burst", ""))
    conn.commit()
    ids = [r["id"] for r in conn.execute("SELECT id FROM alerts ORDER BY id").fetchall()]
    conn.close()
    return ids


# ---------------------------------------------------------------- bulk / group triage

def test_bulk_workflow_applies_per_alert_rules_and_reports_skips(app_db):
    dashboard, cfg = app_db
    ids = add_alerts(cfg, 4)
    c = client(dashboard)
    for step in ("resolved", "closed"):
        assert c.post(f"/api/alerts/{ids[0]}/workflow", json={"status": step}, headers=H).status_code == 200
    r = c.post("/api/alerts/workflow/bulk", json={"ids": ids, "status": "acknowledged", "note": "triaged together"}, headers=H)
    d = r.get_json()
    assert r.status_code == 200 and sorted(d["updated"]) == ids[1:]
    assert d["skipped"] == [{"id": ids[0], "reason": "is closed; cannot move to acknowledged"}]
    rows = {a["id"]: a for a in c.get("/api/alerts").get_json()}
    assert all(rows[i]["workflow_status"] == "acknowledged" and rows[i]["workflow_resolution_note"] == "triaged together" for i in ids[1:])
    assert rows[ids[0]]["workflow_status"] == "closed"                          # never forced
    hist = c.get(f"/api/alerts/{ids[1]}/workflow").get_json()["events"]
    assert hist[-1]["from_status"] == "new" and hist[-1]["to_status"] == "acknowledged" and hist[-1]["actor"] == "alice"
    again = c.post("/api/alerts/workflow/bulk", json={"ids": ids[1:], "status": "acknowledged"}, headers=H).get_json()
    assert again["unchanged"] == ids[1:] and again["updated"] == []
    assigned = c.post("/api/alerts/workflow/bulk", json={"ids": ids, "assignee": "bob"}, headers=H).get_json()
    assert sorted(assigned["updated"]) == ids                                    # assignment is valid in any state
    conn = db.connect(cfg)
    audit = conn.execute("SELECT detail FROM audit_log WHERE action='alert_workflow_bulk' ORDER BY id").fetchall()
    conn.close()
    assert len(audit) == 3 and "skipped=1" in audit[0]["detail"]


@pytest.mark.parametrize("body,code", [
    ({"ids": [], "status": "acknowledged"}, 400),
    ({"ids": ["x"], "status": "acknowledged"}, 400),
    ({"ids": list(range(1, 502)), "status": "acknowledged"}, 400),
    ({"ids": [1]}, 400),                                       # nothing to change
    ({"ids": [1], "status": "deleted"}, 400),
])
def test_bulk_workflow_validation(app_db, body, code):
    dashboard, cfg = app_db
    add_alerts(cfg, 1)
    assert client(dashboard).post("/api/alerts/workflow/bulk", json=body, headers=H).status_code == code


def test_bulk_workflow_requires_triage_role_and_csrf(app_db):
    dashboard, cfg = app_db
    ids = add_alerts(cfg, 2)
    assert client(dashboard, role="viewer").post("/api/alerts/workflow/bulk", json={"ids": ids, "status": "acknowledged"}, headers=H).status_code == 403
    assert client(dashboard).post("/api/alerts/workflow/bulk", json={"ids": ids, "status": "acknowledged"}).status_code == 403


def test_single_alert_endpoint_unchanged_after_refactor(app_db):
    dashboard, cfg = app_db
    ids = add_alerts(cfg, 1)
    c = client(dashboard)
    bad = c.post(f"/api/alerts/{ids[0]}/workflow", json={"status": "closed"}, headers=H)
    assert bad.status_code == 409 and bad.get_json()["allowed_next"] == ["acknowledged", "investigating", "resolved"]
    ok = c.post(f"/api/alerts/{ids[0]}/workflow", json={"status": "investigating", "assignee": "alice"}, headers=H)
    assert ok.status_code == 200 and ok.get_json()["workflow_status"] == "investigating"
    assert c.post("/api/alerts/999/workflow", json={"status": "resolved"}, headers=H).status_code == 404


def test_after_id_returns_only_newer_alerts(app_db):
    dashboard, cfg = app_db
    ids = add_alerts(cfg, 3)
    add_alerts(cfg, 1, severity="warning")
    c = client(dashboard)
    newer = c.get(f"/api/alerts?after_id={ids[0]}&severity=critical,alert,emergency,error").get_json()
    assert sorted(a["id"] for a in newer) == ids[1:3]                           # warning excluded, older excluded
    assert c.get("/api/alerts?after_id=abc").status_code == 200                 # ignored, not an error


# ---------------------------------------------------------------- near-miss replay

def _rows(lines, start=None):
    start = start or datetime(2026, 10, 19, 9, 0, tzinfo=timezone.utc)
    return [{"received_at": (start + timedelta(seconds=sec)).isoformat(), "source_ip": "10.0.0.5", "message": msg}
            for sec, msg in lines]


def _ssh(ip):
    return f"sshd[1]: Failed password for root from {ip} port 22"


def test_replay_reports_near_misses_fires_and_disabled_rules():
    cfg = detection.defaults()["rules"]
    lines = [(i * 5, _ssh("203.0.113.50")) for i in range(4)]                   # 4 of 5 in 15s
    lines += [(100 + i, _ssh("198.51.100.7")) for i in range(6)]                # fires at the 5th
    lines += [(400 + i * 70, _ssh("192.0.2.9")) for i in range(5)]              # 5 total, never 2 within 60s
    ssh = next(r for r in rules.replay_threshold_rules(_rows(lines), cfg) if r["id"] == "ssh_bruteforce")
    top = {k["key"]: k for k in ssh["top"]}
    assert ssh["fires"] == 1 and top["198.51.100.7"]["fires"] == 1
    assert top["198.51.100.7"]["peak"] == 5                                     # counter clears after firing
    assert top["203.0.113.50"]["peak"] == 4 and top["203.0.113.50"]["fires"] == 0
    assert top["192.0.2.9"]["peak"] == 1 and top["192.0.2.9"]["matches"] == 5   # spread out: window slides
    assert ssh["top"][0]["key"] == "198.51.100.7"                                # fired sources first
    for r in cfg:
        if r["id"] == "ssh_bruteforce":
            r.update(enabled=False, threshold=4)
    off = next(r for r in rules.replay_threshold_rules(_rows(lines), cfg) if r["id"] == "ssh_bruteforce")
    assert off["enabled"] is False and off["fires"] == 2                         # saved threshold honoured


def test_replay_matches_the_live_engine():
    """The replay and the live engine share THRESHOLD_RULE_SPECS; on the same
    burst they must reach the same answer."""
    class Store:
        def __init__(self):
            self.lock = threading.RLock()
            self.alerts = []
        def insert_alert(self, **kw):
            self.alerts.append(kw)
    store = Store()
    engine = rules.RuleEngine(store)
    lines = [(i, _ssh("198.51.100.7")) for i in range(12)] + [(i, "fw: action=deny src=10.1.1.1 dst=10.0.0.2 blocked") for i in range(25)]
    for n, row in enumerate(_rows(lines)):
        engine.process(n + 1, {"message": row["message"], "source_ip": row["source_ip"], "severity": "informational"})
    live = {}
    for a in store.alerts:
        live[a["rule_name"]] = live.get(a["rule_name"], 0) + 1
    replay = {r["id"]: r["fires"] for r in rules.replay_threshold_rules(_rows(lines), detection.defaults()["rules"])}
    assert live == {k: v for k, v in replay.items() if v} == {"ssh_bruteforce": 2, "firewall_deny_burst": 1}
    assert [r.name for r in engine.rules[:3]] == [s["name"] for s in rules.THRESHOLD_RULE_SPECS]


def test_near_miss_endpoint(app_db, monkeypatch):
    dashboard, cfg = app_db
    for i in range(4):
        dashboard._ingest_raw(f"<38>Oct 19 09:0{i}:00 bastion {_ssh('203.0.113.50')}", "10.0.0.5")
    c = client(dashboard, role="viewer")                                         # read-only: any signed-in user
    d = c.get("/api/detection/near-misses?minutes=60").get_json()
    ssh = next(r for r in d["rules"] if r["id"] == "ssh_bruteforce")
    assert d["scanned"] == 4 and not d["truncated"] and ssh["fires"] == 0 and ssh["top"][0]["peak"] == 4
    assert c.get("/api/detection/near-misses?minutes=abc").status_code == 400
    assert c.get("/api/detection/near-misses?minutes=99999").get_json()["window_minutes"] == 1440
    import web_blueprints.detection as bp
    monkeypatch.setattr(bp, "_NEAR_MISS_MAX_EVENTS", 2)
    small = c.get("/api/detection/near-misses?minutes=60").get_json()
    assert small["truncated"] and small["scanned"] == 2


# ---------------------------------------------------------------- UI contracts

def test_ui_contracts_for_labels_groups_guard_and_notifications():
    index = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    alerts_js = (ROOT / "static" / "alerts.js").read_text(encoding="utf-8")
    detection_js = (ROOT / "static" / "detection.js").read_text(encoding="utf-8")
    app_js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
    base = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
    # one alert-severity label everywhere (error -> High)
    assert "MS.label(a.severity)" not in alerts_js and alerts_js.count("MS.alertSeverity(a.severity)") == 2
    assert "${g.severity}</span>" not in index and "MS.alertSeverity(g.severity)" in index
    # collapsed groups act on every member through the bulk endpoint
    # the bulk bar's display:flex must not override [hidden]
    assert ".aq-bulk[hidden]{display:none}" in (ROOT / "templates" / "alerts.html").read_text(encoding="utf-8")
    assert "${multi ? _groupWorkflowControl(g) : _workflowControl(rep)}" in index and "/api/alerts/workflow/bulk" in index
    # unsaved detection drafts are protected on navigation
    assert "addEventListener('beforeunload'" in detection_js and "if(dirty)" in detection_js
    # page title matches the sidebar label
    assert "{% block page_title %}Threat Intelligence{% endblock %}" in (ROOT / "templates" / "threatintel.html").read_text(encoding="utf-8")
    # background-tab check: hidden only, opt-in notifications, background header
    assert "if (!document.hidden || baselineId === null) return;" in app_js and "X-Background-Poll" in app_js
    assert 'id="notifyToggle"' in base and "Notification.requestPermission()" in app_js

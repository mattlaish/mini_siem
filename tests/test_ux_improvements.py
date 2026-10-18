"""UX contracts: readable event summaries, live ingestion status, the unified
alert queue (filters + role-aware triage), grouped navigation, and no native
prompt()/alert() dialogs in the UI."""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import db

ROOT = Path(__file__).resolve().parents[1]

WIN_4688 = json.dumps({
    "EventID": 4688, "Channel": "Security", "SourceName": "Microsoft-Windows-Security-Auditing",
    "Hostname": "HMSWEB1", "EventTime": "2026-10-17T22:56:35+08:00",
    "NewProcessName": r"C:\Users\Public\update.exe", "ParentProcessName": r"C:\Windows\System32\inetsrv\w3wp.exe",
    "NewProcessId": "0x2bc", "ProcessId": "0xe74", "CommandLine": r"C:\Users\Public\update.exe -c 10.66.1.9:443",
    "SubjectUserName": "svc-web"})


@pytest.fixture
def app_db(tmp_path, monkeypatch):
    import dashboard
    cfg = db.config_from_path(str(tmp_path / "ux.db"))
    monkeypatch.setattr(dashboard, "DB_CONFIG", cfg)
    dashboard.init_auth(None)
    db.initialize(cfg)
    yield dashboard, cfg
    if dashboard._HTTP_PIPELINE:
        dashboard._HTTP_PIPELINE[2].stop_monitor()
        dashboard._HTTP_PIPELINE[1].close()
        dashboard._HTTP_PIPELINE = None


def client(dashboard, role="admin", user="alice"):
    c = dashboard.app.test_client()
    with c.session_transaction() as s:
        s.update(user=user, role=role, must_change=False, csrf_token="t")
    return c


H = {"X-CSRF-Token": "t"}


def test_windows_events_get_a_readable_summary_and_syslog_does_not(app_db):
    dashboard, _ = app_db
    dashboard._ingest_raw(WIN_4688, "10.0.0.40")
    dashboard._ingest_raw("<134>Oct 17 09:20:00 app01 nginx: GET /health 200", "10.0.0.30")
    rows = client(dashboard).get("/api/logs?limit=10").get_json()
    by_host = {r["hostname"]: r for r in rows}
    summary = by_host["HMSWEB1"]["summary"]
    assert summary.startswith("w3wp.exe → update.exe") and "10.66.1.9:443" in summary and "as svc-web" in summary
    assert by_host["HMSWEB1"]["message"].startswith("EventID=4688")      # stored message untouched
    assert "summary" not in by_host["app01"]


def test_ingest_status_states(app_db):
    dashboard, cfg = app_db
    c = client(dashboard)
    assert c.get("/api/ingest-status").get_json()["state"] == "no_data"
    dashboard._ingest_raw("<134>Oct 17 09:20:00 app01 nginx: GET /health 200", "10.0.0.30")
    live = c.get("/api/ingest-status").get_json()
    assert live["state"] == "receiving" and live["events_last_5m"] == 1 and live["last_event_age_seconds"] < 60
    conn = db.connect(cfg)
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    conn.execute("UPDATE logs SET received_at=?", (old,)); conn.commit()
    assert c.get("/api/ingest-status").get_json()["state"] == "listener_down"   # no heartbeat, data stale
    db.runtime_stat_upsert(conn, "listener_health", value_text=json.dumps({"listener": "READY"}),
                           updated_at=datetime.now(timezone.utc).isoformat())
    conn.commit(); conn.close()
    quiet = c.get("/api/ingest-status").get_json()
    assert quiet["state"] == "quiet" and quiet["listener"] == "READY"


def _alerts(cfg, *rows):
    conn = db.connect(cfg)
    for rule, sev, src, desc in rows:
        conn.execute("INSERT INTO alerts(created_at,rule_name,severity,source_ip,description,log_ids) VALUES(?,?,?,?,?,?)",
                     (datetime.now(timezone.utc).isoformat(), rule, sev, src, desc, ""))
    conn.commit(); conn.close()


def test_alert_queue_filters(app_db):
    dashboard, cfg = app_db
    _alerts(cfg, ("ssh_bruteforce", "critical", "203.0.113.5", "SSH brute force from 203.0.113.5"),
            ("firewall_deny_burst", "warning", "198.51.100.9", "Deny burst"),
            ("web_server_shell", "critical", "10.0.0.40", "w3wp.exe -> update.exe 100%_done"))
    c = client(dashboard, user="alice")
    ids = {a["rule_name"]: a["id"] for a in c.get("/api/alerts").get_json()}
    assert len(ids) == 3                                                    # no params: unchanged behaviour
    assert c.post(f"/api/alerts/{ids['firewall_deny_burst']}/workflow", json={"status": "resolved"}, headers=H).status_code == 200
    assert c.post(f"/api/alerts/{ids['ssh_bruteforce']}/workflow", json={"assignee": "alice"}, headers=H).status_code == 200
    names = lambda qs: sorted(a["rule_name"] for a in c.get("/api/alerts?" + qs).get_json())
    assert names("status=open") == ["ssh_bruteforce", "web_server_shell"]
    assert names("status=resolved") == ["firewall_deny_burst"]
    assert names("severity=critical") == ["ssh_bruteforce", "web_server_shell"]
    assert names("assignee=me") == ["ssh_bruteforce"]
    assert names("assignee=unassigned") == ["firewall_deny_burst", "web_server_shell"]
    assert names("q=203.0.113") == ["ssh_bruteforce"]
    assert names("q=100%25_") == ["web_server_shell"]                      # LIKE metacharacters are literal
    assert names("q=%25") == ["web_server_shell"]
    assert names("rule=firewall_deny_burst") == ["firewall_deny_burst"]
    assert c.get("/api/alerts/rules").get_json() == ["firewall_deny_burst", "ssh_bruteforce", "web_server_shell"]
    assert isinstance(c.get("/api/alerts?group=1&status=open").get_json()["groups"], list)


@pytest.mark.parametrize("role,editable", [("admin", "yes"), ("analyst", "yes"), ("viewer", "no")])
def test_alert_queue_page_is_role_aware(app_db, role, editable):
    dashboard, _ = app_db
    page = client(dashboard, role=role).get("/security-alerts")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert f'data-can-triage="{editable}"' in html and "alerts.js" in html


def test_navigation_is_grouped_and_status_is_live_on_every_page(app_db):
    dashboard, _ = app_db
    c = client(dashboard)
    for path in ["/", "/security-alerts", "/detection-rules", "/setup", "/health"]:
        html = c.get(path).get_data(as_text=True)
        assert 'id="ingestStatus"' in html and 'id="listenerLine"' not in html
        for group in ("Investigate", "Detection", "Admin"):
            assert f'<div class="nav-group" aria-hidden="true">{group}</div>' in html
        assert '>Alerts\n' in html or '</span>Alerts' in html


def test_no_native_prompt_or_alert_dialogs_in_the_ui():
    """Workflow input uses MS.form and messages use MS.toast; confirm() stays
    for destructive actions only."""
    offenders = []
    for path in list((ROOT / "templates").glob("*.html")) + list((ROOT / "static").glob("*.js")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("//", 1)[0]
            if re.search(r"(?<![.\w])(prompt|alert)\(", code) and "replace alert()" not in line and "replace prompt()" not in line:
                offenders.append(f"{path.name}:{n}: {line.strip()[:80]}")
    assert offenders == []

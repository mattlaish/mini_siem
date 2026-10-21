"""Guided cloud-connection test, role-aware settings and permission checks,
field/time-zone pickers and the shared request-recovery pattern."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import db

ROOT = Path(__file__).resolve().parents[1]
H = {"X-CSRF-Token": "t"}


@pytest.fixture
def app_db(tmp_path, monkeypatch):
    import dashboard
    cfg = db.config_from_path(str(tmp_path / "guided.db"))
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


@pytest.fixture
def provider():
    """A tiny Sophos-shaped provider: token -> whoami -> events."""
    state = {"token_status": 200, "seen": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if state["token_status"] != 200:
                return self._send(state["token_status"], {"error": "invalid_client"})
            self._send(200, {"access_token": "tok"})

        def do_GET(self):
            state["seen"].append((self.path, dict(self.headers)))
            if self.path.startswith("/whoami"):
                return self._send(200, {"id": "tenant-1", "idType": "tenant",
                                        "apiHosts": {"dataRegion": f"http://127.0.0.1:{srv.server_port}"}})
            if self.path.startswith("/siem/v1/events") or self.path.startswith("/events"):
                return self._send(200, {"items": [{"id": "e1", "name": "Malware blocked"}, {"id": "e2"}],
                                        "next_cursor": "NEXT"})
            self._send(404, {"error": "no route"})

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state["base"] = f"http://127.0.0.1:{srv.server_port}"
    yield state
    srv.shutdown()


def _create_sophos(c, base, **extra):
    body = {"name": "sophos-central", "auth_scheme": "oauth2_sophos", "token_url": base + "/token",
            "whoami_url": base + "/whoami/v1", "events_url": "/siem/v1/events", "client_id": "cid",
            "client_secret": "s3cret", "secret_mode": "encrypted", "scope": "token", "enabled": False}
    body.update(extra)
    r = c.post("/api/pollers", json=body, headers=H)
    assert r.status_code == 200, r.get_json()
    return r.get_json()["id"]


# ---------------------------------------------------------------- guided cloud setup

def test_connection_test_walks_each_step_without_storing(app_db, provider):
    dashboard, cfg = app_db
    c = client(dashboard)
    pid = _create_sophos(c, provider["base"])
    d = c.post(f"/api/pollers/{pid}/test", headers=H).get_json()
    assert d["ok"] and [s["step"] for s in d["steps"]] == ["sign_in", "account_discovery", "events"]
    assert all(s["ok"] for s in d["steps"]) and d["events"] == 2
    assert "tenant found" in d["steps"][1]["detail"] and json.loads(d["sample"])["name"] == "Malware blocked"
    path, headers = provider["seen"][-1]
    headers = {k.lower(): v for k, v in headers.items()}                        # urllib title-cases names
    assert path.startswith("/siem/v1/events?from_date=") and headers.get("x-tenant-id") == "tenant-1"
    conn = db.connect(cfg)
    row = conn.execute("SELECT cursor, pulled_count, last_poll_at FROM api_pollers WHERE id=?", (pid,)).fetchone()
    logs = conn.execute("SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
    audit = conn.execute("SELECT detail FROM audit_log WHERE action='poller_tested'").fetchall()
    conn.close()
    assert row["cursor"] is None and not row["pulled_count"] and row["last_poll_at"] is None   # dry run
    assert logs == 0 and audit[-1]["detail"] == "ok; events=2"


def test_connection_test_reports_where_it_stopped(app_db, provider):
    dashboard, cfg = app_db
    c = client(dashboard)
    pid = _create_sophos(c, provider["base"])
    provider["token_status"] = 401
    d = c.post(f"/api/pollers/{pid}/test", headers=H).get_json()
    assert not d["ok"] and len(d["steps"]) == 1
    assert d["steps"][0]["step"] == "sign_in" and "HTTP 401" in d["steps"][0]["detail"]
    assert "invalid_client" in d["steps"][0]["detail"]                            # provider's own reason


def test_connection_test_api_key_scheme(app_db, provider):
    dashboard, cfg = app_db
    c = client(dashboard)
    r = c.post("/api/pollers", json={"name": "vendor", "auth_scheme": "api_key", "events_url": provider["base"] + "/events",
                                     "client_secret": "k3y", "api_key_header": "X-Key", "secret_mode": "encrypted"}, headers=H)
    d = c.post(f"/api/pollers/{r.get_json()['id']}/test", headers=H).get_json()
    assert d["ok"] and [s["step"] for s in d["steps"]] == ["sign_in", "events"]
    assert {k.lower(): v for k, v in provider["seen"][-1][1].items()}.get("x-key") == "k3y"


def test_connection_test_permissions(app_db, provider):
    dashboard, cfg = app_db
    pid = _create_sophos(client(dashboard), provider["base"])
    for role in ("analyst", "viewer"):
        assert client(dashboard, role).post(f"/api/pollers/{pid}/test", headers=H).status_code == 403
    assert client(dashboard).post("/api/pollers/999/test", headers=H).status_code == 404
    assert client(dashboard).post(f"/api/pollers/{pid}/test").status_code == 403    # CSRF


# ---------------------------------------------------------------- permission checks

@pytest.mark.parametrize("method,url,body", [
    ("post", "/api/norm-patterns", {"patterns": []}),
    ("post", "/api/norm-reindex", {}),
    ("post", "/api/forwarders/1/test", {}),
    ("post", "/api/tickets/test", {}),
    ("post", "/api/ioc-feeds", {"name": "x", "url": "https://example.invalid/feed.txt"}),
    ("put", "/api/ioc-feeds/1", {"enabled": False}),
    ("post", "/api/reports/schedule", {"schedule": "weekly"}),
    ("post", "/api/ai/test", {}),
    ("post", "/api/ai/queue/retry", {}),
    ("post", "/api/ai/queue/clear", {}),
])
def test_admin_only_actions(app_db, method, url, body):
    dashboard, _ = app_db
    for role in ("analyst", "viewer"):
        r = getattr(client(dashboard, role), method)(url, json=body, headers=H)
        assert r.status_code == 403, (role, url, r.status_code)


@pytest.mark.parametrize("method,url,body", [
    ("post", "/api/norm-columns", {"columns": ["user"]}),
    ("post", "/api/iocs", {"value": "203.0.113.66"}),
    ("post", "/api/iocs/import", {"text": "198.51.100.23"}),
    ("put", "/api/iocs/1", {"enabled": False}),
    ("post", "/api/ioc-feeds/1/fetch", {}),
    ("post", "/api/reports/run", {"window_days": 1}),
    ("post", "/api/ai/triage", {"alert_id": 1}),
])
def test_triage_actions_need_analyst(app_db, method, url, body):
    dashboard, _ = app_db
    assert getattr(client(dashboard, "viewer"), method)(url, json=body, headers=H).status_code == 403
    assert getattr(client(dashboard, "analyst"), method)(url, json=body, headers=H).status_code != 403


def test_denials_are_audited(app_db):
    dashboard, cfg = app_db
    client(dashboard, "viewer", user="vic").post("/api/iocs", json={"value": "203.0.113.66"}, headers=H)
    conn = db.connect(cfg)
    row = conn.execute("SELECT username, detail FROM audit_log WHERE action='permission_denied'").fetchone()
    conn.close()
    assert row["username"] == "vic" and row["detail"] == "role=viewer"


# ---------------------------------------------------------------- role-aware pages

def test_settings_page_is_grouped_and_role_aware(app_db):
    dashboard, _ = app_db
    admin = client(dashboard).get("/setup").get_data(as_text=True)
    viewer = client(dashboard, "viewer").get("/setup").get_data(as_text=True)
    assert 'data-role="admin"' in admin and 'data-locked="yes"' not in admin
    assert 'data-role="viewer"' in viewer and viewer.count('data-locked="yes"') == 11
    for html in (admin, viewer):
        assert 'id="setupNavSelect"' in html and 'data-section="sec-account"' in html and 'id="pwBtn"' in html
        assert "Log collection" in html and "Administration" in html
    assert "Read-only viewer" in viewer and "(administrators)" in viewer
    # the ticket template hint lists its placeholders instead of rendering them empty
    assert "{{id}} {{rule_name}} {{severity}}" in admin


def test_threat_intel_controls_follow_role(app_db):
    dashboard, _ = app_db
    pages = {role: client(dashboard, role).get("/threatintel").get_data(as_text=True)
             for role in ("admin", "analyst", "viewer")}
    assert 'id="addBtn"' not in pages["viewer"] and "Analysts and administrators add" in pages["viewer"]
    assert 'id="addBtn"' in pages["analyst"] and 'id="clearSrcBtn"' not in pages["analyst"]
    assert 'id="addFeedBtn"' not in pages["analyst"] and 'id="addFeedBtn"' in pages["admin"]
    assert 'id="clearSrcBtn"' in pages["admin"]


def test_dashboard_and_reports_controls_follow_role(app_db):
    dashboard, _ = app_db
    admin = client(dashboard).get("/").get_data(as_text=True)
    analyst = client(dashboard, "analyst").get("/").get_data(as_text=True)
    viewer = client(dashboard, "viewer").get("/").get_data(as_text=True)
    assert 'id="reindexBtn"' in admin and 'id="aiRetryBtn"' in admin
    assert 'id="reindexBtn"' not in analyst and ">Save columns</button>" in analyst and 'id="aiRetryBtn"' not in analyst
    assert 'id="savePatternsBtn"' not in viewer and 'id="normPatterns" readonly' in viewer
    corr = client(dashboard, "analyst").get("/correlate").get_data(as_text=True)
    assert 'id="saveSchedBtn"' not in corr and "Administrators set the report schedule." in corr


# ---------------------------------------------------------------- field picker

def test_extracted_field_list(app_db):
    dashboard, cfg = app_db
    conn = db.connect(cfg)
    for log_id, field in enumerate(["user", "user", "action", "bad field!", "user"]):
        conn.execute("INSERT INTO log_fields(log_id, field, value) VALUES (?,?,?)", (log_id, field, "v"))
    conn.commit(); conn.close()
    d = client(dashboard, "viewer").get("/api/detection/fields").get_json()
    assert d["fields"] == [{"name": "field.user", "count": 3}, {"name": "field.action", "count": 1}]


# ---------------------------------------------------------------- UI contracts

def test_ui_contracts_for_recovery_pickers_and_background_polls():
    app_js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
    detection_js = (ROOT / "static" / "detection.js").read_text(encoding="utf-8")
    pages = {n: (ROOT / "templates" / f"{n}.html").read_text(encoding="utf-8")
             for n in ("index", "health", "audit", "setup", "threatintel", "correlate")}
    # one recovery pattern: friendly message, retry, technical detail
    assert "MS.getJSON = async function" in app_js and "MS.failed = function" in app_js and "'Technical detail'" in app_js
    for name in ("health", "audit", "setup", "threatintel", "correlate"):
        assert "MS.failed(" in pages[name], name
    # failed refreshes are labelled stale, never "updated"
    assert "Refresh failed at" in pages["index"] and "Refresh failed at" in pages["health"]
    # timed refreshes never keep an idle session alive
    assert "MS.background = function" in app_js
    assert "MS.background(load)" in pages["health"] and "MS.background(load)" in pages["audit"]
    assert "MS.background(loadForwarders)" in pages["setup"] and "MS.background(() => { loadMatches(); loadStats(); })" in pages["threatintel"]
    # guided setup
    assert "/test', {method: 'POST'}" in pages["setup"] and "Turn on collection" in pages["setup"]
    # pickers: described fields, browser time zones, host roles
    assert "const FIELD_HELP={" in detection_js and "Intl.supportedValuesOf('timeZone')" in detection_js
    assert "timezone:'Asia/Taipei'" not in detection_js and "knownRoles()" in detection_js

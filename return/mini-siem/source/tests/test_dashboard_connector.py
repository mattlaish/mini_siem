import json
import os
from datetime import datetime, timezone

import dashboard
import dashboard_connector as connector
import jsonschema


def _auth(token):
    return {"Authorization": "Bearer " + token}


def _seed(conn):
    now = datetime.now(timezone.utc).isoformat()
    for index in range(3):
        conn.execute(
            """INSERT INTO alerts
               (created_at,rule_name,severity,source_ip,description,log_ids,
                workflow_status,workflow_updated_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (now, f"test-rule-{index}", "high", f"192.0.2.{index + 1}",
             "synthetic connector test", json.dumps([index + 1]), "new", now))
        conn.execute(
            """INSERT INTO logs
               (received_at,source_ip,hostname,message,raw)
               VALUES(?,?,?,?,?)""",
            (now, f"192.0.2.{index + 1}", f"test-host-{index}", "test", "test"))
    conn.commit()


def test_machine_auth_paging_and_read_only_contract(tmp_path):
    dashboard.DB_CONFIG = dashboard.dbmod.config_from_path(str(tmp_path / "connector.db"))
    dashboard.dbmod.initialize(dashboard.DB_CONFIG)
    conn = dashboard.dbmod.connect(dashboard.DB_CONFIG)
    try:
        token, token_id = connector.create_reader_token(conn, "workspace-reader", "tenant-test")
        _seed(conn)
    finally:
        conn.close()

    guards = dashboard.app.before_request_funcs.get(None, [])
    if not any(fn.__name__ == "_guard" for fn in guards):
        dashboard.init_auth(None)
    client = dashboard.app.test_client()
    base = connector.PREFIX

    unauthenticated = client.get(base + "/alerts")
    assert unauthenticated.status_code == 401
    assert unauthenticated.get_json()["error"]["code"] == "AUTH_REQUIRED"
    assert "no-store" in unauthenticated.headers["Cache-Control"]

    with client.session_transaction() as session:
        session["user"] = "admin"
        session["role"] = "admin"
        session["must_change"] = False
    assert client.get(base + "/alerts").status_code == 401

    capabilities = client.get(base + "/capabilities", headers=_auth(token))
    assert capabilities.status_code == 200
    capability_document = capabilities.get_json()
    assert capability_document["actions"] == []
    disabled_resources = {
        resource["resource_kind"]: resource
        for resource in capability_document["resources"]
        if not resource["enabled"]
    }
    assert disabled_resources["EVENT"]["stream_semantics"] == "HISTORY"
    assert disabled_resources["EVENT"]["bootstrap_retention_days"] == 30
    assert disabled_resources["AUDIT_EVENT"]["stream_semantics"] == "HISTORY"
    assert disabled_resources["AUDIT_EVENT"]["bootstrap_retention_days"] == 30
    assert disabled_resources["ACTION_STATUS"]["stream_semantics"] == "STATE"
    assert disabled_resources["ACTION_STATUS"]["bootstrap_retention_days"] is None
    assert client.get(base + "/events", headers=_auth(token)).status_code == 501
    assert client.post(base + "/alerts", headers=_auth(token), json={}).status_code == 403

    contract_schema_path = os.environ.get("OWI_PAGE_SCHEMA")
    if contract_schema_path:
        with open(contract_schema_path, encoding="utf-8") as handle:
            contract_schema = json.load(handle)
        for lane in ("alerts", "incidents", "assets", "health-observations"):
            response = client.get(base + "/" + lane, headers=_auth(token))
            assert response.status_code == 200
            jsonschema.Draft202012Validator(contract_schema).validate(response.get_json())
    control_schema_path = os.environ.get("OWI_CONTROL_SCHEMA")
    if control_schema_path:
        with open(control_schema_path, encoding="utf-8") as handle:
            control_schema = json.load(handle)
        validator = jsonschema.Draft202012Validator(control_schema)
        validator.validate(capabilities.get_json())
        validator.validate(client.get(base + "/health", headers=_auth(token)).get_json())
        validator.validate(unauthenticated.get_json())

    first = client.get(base + "/alerts?limit=1", headers=_auth(token))
    assert first.status_code == 200
    first_page = first.get_json()
    assert first_page["sync_mode"] == "SNAPSHOT"
    assert first_page["has_more"] is True
    assert len(first_page["records"]) == 1

    second = client.get(base + "/alerts?limit=1&cursor=" + first_page["next_cursor"],
                        headers=_auth(token)).get_json()
    assert second["sync_mode"] == "SNAPSHOT"
    assert second["has_more"] is True

    # A new client represents a dashboard process restart.  The cursor still
    # resumes because snapshots are in the database rather than memory.
    restarted_client = dashboard.app.test_client()
    third_response = restarted_client.get(
        base + "/alerts?limit=1&cursor=" + second["next_cursor"], headers=_auth(token))
    assert third_response.status_code == 200
    third = third_response.get_json()
    assert third["sync_mode"] == "SNAPSHOT"
    assert third["has_more"] is False

    empty_incremental = restarted_client.get(
        base + "/alerts?limit=1&cursor=" + third["next_cursor"], headers=_auth(token))
    assert empty_incremental.status_code == 200
    empty = empty_incremental.get_json()
    assert empty["sync_mode"] == "INCREMENTAL"
    assert empty["records"] == []
    assert empty["next_cursor"]

    conn = dashboard.dbmod.connect(dashboard.DB_CONFIG)
    try:
        connector.revoke_reader_token(conn, token_id)
    finally:
        conn.close()
    assert restarted_client.get(base + "/health", headers=_auth(token)).status_code == 401


def test_scope_and_cursor_binding_are_enforced(tmp_path):
    dashboard.DB_CONFIG = dashboard.dbmod.config_from_path(str(tmp_path / "scope.db"))
    dashboard.dbmod.initialize(dashboard.DB_CONFIG)
    conn = dashboard.dbmod.connect(dashboard.DB_CONFIG)
    try:
        limited, _ = connector.create_reader_token(
            conn, "health-only", "tenant-a", ["dashboard:read:health"])
        reader_a, _ = connector.create_reader_token(conn, "reader-a", "tenant-a")
        reader_b, _ = connector.create_reader_token(conn, "reader-b", "tenant-b")
        _seed(conn)
    finally:
        conn.close()

    client = dashboard.app.test_client()
    assert client.get(connector.PREFIX + "/alerts", headers=_auth(limited)).status_code == 403
    first = client.get(connector.PREFIX + "/alerts?limit=1", headers=_auth(reader_a)).get_json()
    rebound = client.get(connector.PREFIX + "/alerts?cursor=" + first["next_cursor"],
                         headers=_auth(reader_b))
    assert rebound.status_code == 400
    assert rebound.get_json()["error"]["code"] == "INVALID_CURSOR"


def test_token_rotation_digest_storage_and_rate_limit(tmp_path, monkeypatch):
    dashboard.DB_CONFIG = dashboard.dbmod.config_from_path(str(tmp_path / "rotation.db"))
    dashboard.dbmod.initialize(dashboard.DB_CONFIG)
    conn = dashboard.dbmod.connect(dashboard.DB_CONFIG)
    try:
        token, token_id = connector.create_reader_token(
            conn, "rate-reader", "tenant-rate", ["dashboard:read:health"])
        stored = conn.execute(
            "SELECT token_digest,expires_at FROM dashboard_reader_tokens WHERE id=?", (token_id,)).fetchone()
        assert token not in stored["token_digest"]
        replacement, replacement_id = connector.rotate_reader_token(
            conn, token_id, days=90, overlap_hours=24)
        assert replacement != token
        old = conn.execute(
            "SELECT expires_at FROM dashboard_reader_tokens WHERE id=?", (token_id,)).fetchone()
        expiry = datetime.fromisoformat(old["expires_at"].replace("Z", "+00:00"))
        assert (expiry - datetime.now(timezone.utc)).total_seconds() <= 24 * 3600 + 5
        assert replacement_id != token_id
    finally:
        conn.close()

    monkeypatch.setenv("MINISIEM_DASHBOARD_RATE_PER_MINUTE", "1")
    client = dashboard.app.test_client()
    first = client.get(connector.PREFIX + "/health", headers=_auth(replacement))
    second = client.get(connector.PREFIX + "/health", headers=_auth(replacement))
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["Retry-After"] == "1"


def test_visibility_change_requires_cursor_reset(tmp_path):
    dashboard.DB_CONFIG = dashboard.dbmod.config_from_path(str(tmp_path / "visibility.db"))
    dashboard.dbmod.initialize(dashboard.DB_CONFIG)
    conn = dashboard.dbmod.connect(dashboard.DB_CONFIG)
    try:
        original, _ = connector.create_reader_token(conn, "same-reader", "tenant-visibility")
        reduced, _ = connector.create_reader_token(conn, "same-reader", "tenant-visibility",
            ["dashboard:read:health", "dashboard:read:alerts"])
        _seed(conn)
    finally:
        conn.close()
    client = dashboard.app.test_client()
    first = client.get(connector.PREFIX + "/alerts?limit=1", headers=_auth(original)).get_json()
    response = client.get(connector.PREFIX + "/alerts?limit=1&cursor=" + first["next_cursor"], headers=_auth(reduced))
    assert response.status_code == 409
    assert response.get_json()["error"]["code"] == "RESET_REQUIRED"


def test_snapshot_sequence_order_does_not_use_lexical_external_ids(tmp_path):
    dashboard.DB_CONFIG = dashboard.dbmod.config_from_path(str(tmp_path / "sequence.db"))
    dashboard.dbmod.initialize(dashboard.DB_CONFIG)
    conn = dashboard.dbmod.connect(dashboard.DB_CONFIG)
    try:
        token, _ = connector.create_reader_token(conn, "sequence-reader", "tenant-sequence")
        for _ in range(4):
            _seed(conn)
    finally:
        conn.close()
    page = dashboard.app.test_client().get(connector.PREFIX + "/alerts", headers=_auth(token)).get_json()
    sequences = [int(record["stream_sequence"]) for record in page["records"]]
    assert len(sequences) == 12
    assert sequences == sorted(sequences)

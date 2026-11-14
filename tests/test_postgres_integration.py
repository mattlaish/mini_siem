"""Live PostgreSQL integration tests.

These exercise the PostgreSQL backend end to end — schema init, Event Storage v2
projection, index design, and the case-insensitive field search — against a real
server. They are skipped unless the connection env vars are present, so the
default SQLite-only test run is unaffected. CI provides a postgres service and
sets these variables.

Required env (admin/superuser able to CREATE DATABASE):
    MINISIEM_TEST_PG_HOST, MINISIEM_TEST_PG_PORT,
    MINISIEM_TEST_PG_USER, MINISIEM_TEST_PG_PASSWORD
"""

import os
import uuid

import pytest

psycopg2 = pytest.importorskip("psycopg2")

import db
import event_storage_v2
import normalize


def _admin():
    host = os.environ.get("MINISIEM_TEST_PG_HOST")
    if not host:
        return None
    return {
        "host": host,
        "port": int(os.environ.get("MINISIEM_TEST_PG_PORT", "5432")),
        "user": os.environ.get("MINISIEM_TEST_PG_USER", "postgres"),
        "password": os.environ.get("MINISIEM_TEST_PG_PASSWORD", ""),
    }


pytestmark = pytest.mark.skipif(
    _admin() is None,
    reason="set MINISIEM_TEST_PG_HOST to run PostgreSQL integration tests",
)


@pytest.fixture()
def pg_cfg():
    adm = _admin()
    name = "minisiem_test_" + uuid.uuid4().hex[:12]
    admin_conn = psycopg2.connect(dbname="postgres", **adm)
    admin_conn.autocommit = True
    with admin_conn.cursor() as c:
        c.execute(f'CREATE DATABASE "{name}"')
    cfg = {"backend": "postgres",
           "postgres": {**adm, "dbname": name, "connect_timeout": 5}}
    try:
        yield cfg
    finally:
        with admin_conn.cursor() as c:
            c.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname=%s AND pid<>pg_backend_pid()", (name,))
            c.execute(f'DROP DATABASE IF EXISTS "{name}"')
        admin_conn.close()


def _index_names(cfg):
    conn = db.connect(cfg)
    try:
        rows = conn.execute(
            "SELECT indexname FROM pg_indexes WHERE schemaname='public'").fetchall()
        return {(r["indexname"] if isinstance(r, dict) else r[0]) for r in rows}
    finally:
        conn.close()


def test_initialize_is_idempotent_and_creates_core_schema(pg_cfg):
    db.initialize(pg_cfg)
    db.initialize(pg_cfg)  # must not raise on a populated DB
    conn = db.connect(pg_cfg)
    try:
        for table in ("logs", "alerts", "log_fields", "security_events",
                      "schema_migrations", "users"):
            reg = conn.execute("SELECT to_regclass(?)", (f"public.{table}",)).fetchone()
            assert (reg["to_regclass"] if isinstance(reg, dict) else reg[0]) is not None, table
    finally:
        conn.close()


def test_source_summary_upgrade_and_dashboard_timeout(pg_cfg, monkeypatch):
    from datetime import datetime, timedelta, timezone
    import dashboard
    import storage_stats
    from tools.postgres_upgrade_existing import _upgrade_existing_owner_schema

    db.initialize(pg_cfg)
    now = datetime.now(timezone.utc)
    conn = db.connect(pg_cfg)
    try:
        # Simulate the previous schema on this disposable database only.
        conn.execute("DROP TRIGGER minisiem_track_log_sources ON logs")
        conn.execute("DROP TABLE log_source_last_seen")
        conn.execute("DELETE FROM schema_migrations WHERE version=43")
        conn.execute("INSERT INTO logs(received_at,source_ip,message) VALUES (?,?,?)",
                     ((now-timedelta(days=4)).isoformat(), "192.0.2.1", "pre-upgrade"))
        conn.commit()
    finally:
        conn.close()
    assert 43 in _upgrade_existing_owner_schema(pg_cfg)
    assert 43 in _upgrade_existing_owner_schema(pg_cfg)
    db.ensure_runtime_ready(pg_cfg)
    conn = db.connect(pg_cfg)
    try:
        assert storage_stats.silent_sources(conn, (now-timedelta(days=14)).isoformat(),
                                           (now-timedelta(days=3)).isoformat()) == (1, ["192.0.2.1"])
        conn.execute("INSERT INTO logs(received_at,source_ip,message) VALUES (?,?,?),(?,?,?),(?,?,?)",
                     (now.isoformat(), "192.0.2.1", "current",
                      (now-timedelta(days=8)).isoformat(), "192.0.2.1", "late replay",
                      "not a timestamp", "192.0.2.2", "malformed receipt"))
        conn.commit()
        row = conn.execute("SELECT source_ip,last_seen FROM log_source_last_seen").fetchone()
        assert row["source_ip"] == "192.0.2.1"
        assert row["last_seen"] == now.replace(second=0, microsecond=0)
        assert storage_stats.silent_sources(conn, (now-timedelta(days=14)).isoformat(),
                                           (now-timedelta(days=3)).isoformat()) == (0, [])
        assert storage_stats.log_total(conn)[1:] == (True, True)
        conn.execute("INSERT INTO logs(received_at,source_ip) VALUES (?,?)",
                     (now.isoformat(), "192.0.2.3"))
        conn.rollback()
        assert conn.execute("SELECT 1 FROM log_source_last_seen WHERE source_ip=?",
                            ("192.0.2.3",)).fetchone() is None
    finally:
        conn.close()

    cfg = dict(pg_cfg, postgres={**pg_cfg["postgres"], "dashboard_statement_timeout_ms": 1000})
    monkeypatch.setattr(dashboard, "DB_CONFIG", cfg)
    with dashboard.app.test_request_context("/api/stats"):
        stats = dashboard.api_stats().get_json()
        assert stats["has_logs"] and stats["total_logs_estimated"]
        assert stats["silent_sources"]["count"] == 0
        from health import siem_metrics
        assert siem_metrics(dashboard.get_conn(), cfg)["total_logs_estimated"]
    with dashboard.app.test_request_context("/api/logs"):
        with pytest.raises(psycopg2.errors.QueryCanceled) as cancelled:
            dashboard.get_conn().execute("SELECT pg_sleep(2)")
        response, status = dashboard.app.handle_user_exception(cancelled.value)
        assert status == 504 and response.json["code"] == "database_query_timeout"
    with dashboard.app.test_request_context("/api/logs"):
        assert dashboard.get_conn().execute("SELECT 1 AS ok").fetchone()["ok"] == 1
    background = db.connect(cfg)
    try:
        assert background.execute("SHOW statement_timeout").fetchone()["statement_timeout"] == "0"
    finally:
        background.close()


def test_projection_keeps_typed_values_without_writing_entity_tables(pg_cfg):
    import event_storage_v2 as es
    db.initialize(pg_cfg)
    conn = db.connect(pg_cfg)
    try:
        assert es.append_projection(conn, 1, {"source_ip": "192.0.2.1", "peer_ip": "192.0.2.2"},
                                    {"user": "Alice", "dpt": 443}, search_ready=True) == 1
        row = conn.execute("SELECT user_name, dst_port, asset_id, identity_id FROM security_events").fetchone()
        assert dict(row) == {"user_name": "Alice", "dst_port": 443, "asset_id": None, "identity_id": None}
        es.update_projection_fields(conn, 1, {}, {"user": "Bob"}, search_ready=True)
        assert conn.execute("SELECT user_name FROM security_events").fetchone()["user_name"] == "Bob"
        assert conn.execute("SELECT COUNT(*) AS n FROM assets").fetchone()["n"] == 0
        assert conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"] == 0
    finally:
        conn.rollback()
        conn.close()


def test_split_roles_can_append_logs_but_not_write_entities(pg_cfg):
    from psycopg2 import sql
    from tools.postgres_privilege_boundary import _apply_grants

    db.initialize(pg_cfg)
    p = pg_cfg["postgres"]
    raw = psycopg2.connect(dbname=p["dbname"], **_admin())
    roles = {name: name + "_" + p["dbname"].rsplit("_", 1)[-1]
             for name in ("runtime", "ingest", "dashboard", "maintenance")}
    try:
        _apply_grants(raw, **{name + "_role": role for name, role in roles.items()})
        for identity in ("ingest", "dashboard"):
            with raw.cursor() as cur:
                cur.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(roles[identity])))
                cur.execute("INSERT INTO logs(received_at,source_ip) VALUES (%s,%s)",
                            ("2026-11-13T00:00:00+00:00", "192.0.2.3"))
                cur.execute("SELECT source_ip FROM log_source_last_seen")
                assert cur.fetchone()[0] == "192.0.2.3"
                cur.execute("""SELECT has_table_privilege(current_user,'assets','INSERT'),
                                      has_table_privilege(current_user,'identities','UPDATE'),
                                      has_table_privilege(current_user,'log_source_last_seen','DELETE')""")
                assert cur.fetchone() == (False, False, False)
            raw.rollback()
        for identity in ("runtime", "ingest", "dashboard", "maintenance"):
            with raw.cursor() as cur:
                cur.execute("SELECT has_function_privilege(%s,'public.minisiem_prune_log_sources(integer)','EXECUTE')",
                            (roles[identity],))
                assert cur.fetchone()[0] is (identity == "maintenance"), identity
        with raw.cursor() as cur:
            cur.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(roles["maintenance"])))
            cur.execute("SELECT public.minisiem_prune_log_sources(15)")
            assert cur.fetchone()[0] >= 0
        raw.rollback()
    finally:
        raw.close()


def test_index_design_applied(pg_cfg):
    db.initialize(pg_cfg)
    idx = _index_names(pg_cfg)
    # Partial poller indexes and the dedup index are present.
    assert {"idx_alerts_ai_pending", "idx_alerts_ticket_pending",
            "idx_alerts_rule_id"} <= idx
    # Dead indexes are retired.
    assert "idx_se_fields_gin" not in idx
    assert "idx_se_event_time_brin" not in idx
    assert "idx_logs_severity" not in idx
    assert "idx_lf_field_value" not in idx
    assert not (idx & set(event_storage_v2.RETIRED_EVENT_INDEXES))
    assert {"idx_se_message_terms_gin", "idx_lf_exact_digest", "idx_lf_prefix_v2"} <= idx


def test_compact_search_fields_clock_and_literal_filters(pg_cfg, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from urllib.parse import urlencode
    import dashboard
    from listener import Storage, parse_syslog

    db.initialize(pg_cfg)
    monkeypatch.setattr(dashboard, "DB_CONFIG", pg_cfg)
    received = datetime.now(timezone.utc) - timedelta(minutes=5)
    literal = "!value*"
    script = ("測" * 2000) + "\nTAILTEXT"
    event = parse_syslog("event payload uniqueword", "192.0.2.11")
    event["received_at"] = received.isoformat()
    event["device_timestamp"] = (received + timedelta(days=8)).isoformat()
    store = Storage(db_config=pg_cfg)
    try:
        a = store.insert_log(event, {"act": "deny", "tag": literal, "script.text": script})
        b = store.insert_log(event, {"act": "allow", "tag": "value", "zone": "remote"})
        c = store.insert_log(event, {"act": "deny", "tag": "other"})
        legacy = store.insert_log(event, {"act": "deny", "tag": literal})
    finally:
        store.close()
    conn = db.connect(pg_cfg)
    try:
        conn.execute("UPDATE security_events SET search_fields=NULL WHERE legacy_log_id=?", (legacy,))
        conn.commit()
        row = conn.execute(
            "SELECT event_time, device_event_time, message, raw FROM security_event_logs WHERE id=?", (a,),
        ).fetchone()
        assert row["event_time"] == received
        assert row["device_event_time"] == received + timedelta(days=8)
        assert row["message"] == event["message"] and row["raw"] == event["raw"]
    finally:
        conn.close()
    client = dashboard.app.test_client()

    def search(expected, **filters):
        response = client.get("/api/logs?" + urlencode({"page": 1, **filters}))
        assert response.status_code == 200, response.get_json()
        assert {r["id"] for r in response.get_json()["items"]} == expected

    search({a, b, c, legacy}, q="uniqueword")
    search({b, c}, f_act="deny", f_zone="remote", fne_tag=literal, fc_op="or")
    search({a, legacy}, feq_tag=literal)
    search({a}, **{"f_script.text": "*tailtext*"})
    search({a}, **{"feq_script.text": script})
    search({a}, **{"f_script.text": ("測" * 1000) + "*"})
    search({a}, ids=str(a))
    search({a, b, c, legacy}, source_ip="192.0.2.11/31")


def test_owner_upgrade_removes_only_verified_duplicate_evidence(pg_cfg):
    from tools.postgres_upgrade_existing import _upgrade_existing_owner_schema

    db.initialize(pg_cfg)
    conn = db.connect(pg_cfg)
    try:
        conn.execute("DELETE FROM schema_migrations WHERE version=44")
        log_id = conn.insert_returning_id(
            "INSERT INTO logs(received_at,message,raw) VALUES (?,?,?)",
            ("2026-11-13T00:00:00+00:00", "legacy message", "raw original"),
        )
        conn.execute("ALTER TABLE security_events ADD COLUMN message TEXT, ADD COLUMN raw_event TEXT")
        conn.execute("CREATE INDEX idx_se_type_time ON security_events(event_type,event_time DESC)")
        conn.execute(
            """INSERT INTO security_events(legacy_log_id,event_time,ingested_at,message,raw_event)
               VALUES (?,now(),now(),'legacy message','unmatched evidence')""", (log_id,),
        )
        conn.commit()
        with pytest.raises(RuntimeError, match="contains evidence missing from or different from logs"):
            _upgrade_existing_owner_schema(pg_cfg)
        assert conn.execute("SELECT raw_event FROM security_events").fetchone()["raw_event"] == "unmatched evidence"
        conn.execute("UPDATE security_events SET raw_event='raw original'")
        conn.commit()
        assert 44 in _upgrade_existing_owner_schema(pg_cfg)
        assert 44 in _upgrade_existing_owner_schema(pg_cfg)
        assert not db.postgres_schema_has_column(conn.raw, "security_events", "raw_event")
        assert not db.postgres_schema_has_column(conn.raw, "security_events", "message")
        row = conn.execute("SELECT id,raw,message FROM security_event_logs WHERE message_terms @@ to_tsquery('simple','legacy')").fetchone()
        assert dict(row) == {"id": log_id, "raw": "raw original", "message": "legacy message"}
        assert "idx_se_type_time" not in _index_names(pg_cfg)
    finally:
        conn.close()


def test_compact_projection_archive_move_keeps_original_evidence(pg_cfg, tmp_path):
    from datetime import datetime, timedelta, timezone
    import archive
    from listener import Storage, parse_syslog

    db.initialize(pg_cfg)
    cfg = {**pg_cfg, "archive": {"enabled": True, "directory": str(tmp_path),
                                "hot_days": 1, "mode": "move"}}
    now = datetime.now(timezone.utc)
    event = parse_syslog("original message", "192.0.2.8")
    event["received_at"] = (now - timedelta(days=2)).isoformat()
    storage = Storage(db_config=cfg)
    try:
        log_id = storage.insert_log(event, {"script.text": "a" * 4096 + "tail"})
        result = archive.run_archive_cycle(storage, cfg, now=now)
        assert result["hot_evicted"] == 1, result
        assert storage.conn.execute("SELECT id FROM security_event_logs WHERE id=?", (log_id,)).fetchone() is None
        segment = archive.list_segments(storage.conn, ids=[log_id])[0]
        archived = archive.open_archive(segment["path"])
        try:
            row = archived.execute("SELECT message,raw FROM logs WHERE id=?", (log_id,)).fetchone()
            assert (row["message"], row["raw"]) == (event["message"], event["raw"])
            field = archived.execute("SELECT value FROM log_fields WHERE log_id=?", (log_id,)).fetchone()
            assert field["value"].endswith("tail")
        finally:
            archived.close()
    finally:
        storage.close()


def test_bootstrap_object_ownership_verification_runs(pg_cfg):
    """Regression: the fresh-bootstrap SCHEMA_VERIFIED gate must not crash.

    `_verify_object_ownership` passes a params tuple, so its ``LIKE 'pg_%'`` /
    ``'sql_%'`` literals must be doubled (``%%``) or psycopg2 raises
    ``IndexError: tuple index out of range`` and aborts every PostgreSQL
    install before grants are applied.
    """
    from tools import postgres_bootstrap as bs

    db.initialize(pg_cfg)
    pg = pg_cfg["postgres"]
    raw = psycopg2.connect(
        host=pg["host"], port=pg["port"], user=pg["user"],
        password=pg["password"], dbname=pg["dbname"])
    try:
        rows = bs._verify_object_ownership(raw, pg["user"])
        # Owner created every object, so nothing is mis-owned.
        assert rows == [], rows
    finally:
        raw.close()


def test_field_search_is_case_insensitive_via_alias(pg_cfg):
    """Regression: a mixed-case host that lives only in an alias field must
    match. Before the case-fold fix, `DC01` returned zero rows on PostgreSQL."""
    import dashboard
    db.initialize(pg_cfg)
    conn = db.connect(pg_cfg)
    try:
        event = {
            "received_at": "2026-09-20T10:00:00Z", "source_ip": "10.0.0.5",
            "peer_ip": "10.0.0.5", "format": "json", "priority": 134,
            "facility": "local0", "severity": "warning",
            "device_timestamp": "2026-09-20T10:00:00Z", "hostname": "",
            "destination": "", "app_name": "nxlog", "proc_id": "", "msg_id": "",
            "message": "logon", "raw": "{}",
        }
        new_id = conn.insert_returning_id(
            "INSERT INTO logs (received_at,source_ip,peer_ip,format,priority,"
            "facility,severity,device_timestamp,hostname,destination,app_name,"
            "proc_id,msg_id,message,raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event["received_at"], event["source_ip"], event["peer_ip"],
             event["format"], event["priority"], event["facility"],
             event["severity"], event["device_timestamp"], event["hostname"],
             event["destination"], event["app_name"], event["proc_id"],
             event["msg_id"], event["message"], event["raw"]))
        normalize.write_fields(conn, int(new_id), {"computer": "DC01"})
        event_storage_v2.append_projection(conn, int(new_id), event, {"computer": "DC01"})
        conn.commit()

        orig = dashboard.get_search_aliases
        dashboard.get_search_aliases = lambda: {"source": [], "host": ["computer"], "destination": []}
        try:
            for term in ("DC01", "dc01", "Dc01"):
                clause, params = dashboard._concept_clause(
                    "l.hostname", "host", term, False, backend="postgres_v2")
                row = conn.execute(
                    f"SELECT count(*) AS c FROM security_event_logs l WHERE {clause}",
                    params).fetchone()
                count = row["c"] if isinstance(row, dict) else row[0]
                assert count == 1, f"host search {term!r} returned {count}, expected 1"
        finally:
            dashboard.get_search_aliases = orig
    finally:
        conn.close()


def test_detection_config_and_concurrent_duplicate_evidence(pg_cfg):
    """Independent PostgreSQL sessions must link one process to one alert."""
    import json
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timezone
    import detection
    from listener import Storage, parse_syslog
    db.initialize(pg_cfg)
    store = Storage(db_config=pg_cfg)
    try:
        saved = detection.save_config(store.conn, detection.defaults(), "pg-fixture")
        assert saved["revision"] == 1
        raw = json.dumps({"EventID": 4688, "Channel": "Security", "SourceName": "Microsoft-Windows-Security-Auditing",
                          "Hostname": "web-fixture", "EventTime": datetime.now(timezone.utc).isoformat(),
                          "NewProcessName": "cmd.exe", "ParentProcessName": "tomcat7.exe", "NewProcessId": "100", "ProcessId": "50"})
        event = parse_syslog(raw, "192.0.2.10")
        ids = [store.insert_log(event, fields=event["_normalized"]) for _ in range(2)]
        finding = detection.evaluate(saved, event["_normalized"])["findings"][0]
        def emit(log_id):
            conn = db.connect(pg_cfg)
            try:
                return detection.emit(conn, finding, log_id, "192.0.2.10")
            finally:
                conn.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            emitted = list(pool.map(emit, ids))
        assert emitted[0] == emitted[1]
        row = store.conn.execute("SELECT log_ids,description FROM alerts WHERE id=?", (emitted[0],)).fetchone()
        assert set(map(int, row["log_ids"].split(","))) == set(ids)
        assert detection.describe_alert(dict(row))["detection_evidence"]["occurrences"] == 2
    finally:
        store.close()


def test_source_summary_keys_senders_never_deadlocks_and_prunes(pg_cfg):
    import threading
    from datetime import datetime, timedelta, timezone

    db.initialize(pg_cfg)
    p = pg_cfg["postgres"]
    connect = lambda: psycopg2.connect(dbname=p["dbname"], **_admin())  # noqa: E731
    ins = "INSERT INTO logs(received_at, source_ip, peer_ip, message, raw) VALUES (%s,%s,%s,'x','x')"
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    old, new = (now - timedelta(minutes=5)).isoformat(), now.isoformat()

    seed = connect()
    with seed.cursor() as cur:
        # A firewall (peer) reporting two attacker addresses, and an API source.
        cur.execute(ins, (old, "203.0.113.1", "10.0.0.1"))
        cur.execute(ins, (old, "203.0.113.2", "10.0.0.2"))
        cur.execute(ins, (old, "sophos", ""))
        cur.execute("SELECT source_ip FROM log_source_last_seen ORDER BY 1")
        assert [r[0] for r in cur.fetchall()] == ["10.0.0.1", "10.0.0.2", "sophos"]
    seed.commit()

    # Two batched writers touch the same senders in opposite order.
    a, b, outcome = connect(), connect(), {}
    a.cursor().execute(ins, (new, "198.51.100.1", "10.0.0.1"))
    b.cursor().execute(ins, (new, "198.51.100.2", "10.0.0.2"))

    def second_half():
        try:
            a.cursor().execute(ins, (new, "198.51.100.1", "10.0.0.2"))
            a.commit()
            outcome["a"] = "ok"
        except Exception as exc:  # noqa: BLE001
            outcome["a"] = type(exc).__name__

    t = threading.Thread(target=second_half)
    t.start()
    t.join(0.5)
    b.cursor().execute(ins, (new, "198.51.100.2", "10.0.0.1"))
    b.commit()
    t.join(5)
    assert outcome == {"a": "ok"}
    with seed.cursor() as cur:
        cur.execute("SELECT source_ip, last_seen FROM log_source_last_seen WHERE source_ip LIKE '10.%' ORDER BY 1")
        assert [(r[0], r[1]) for r in cur.fetchall()] == [("10.0.0.1", now), ("10.0.0.2", now)]

        # Pruning is bounded and removes only senders older than the window.
        cur.execute("UPDATE log_source_last_seen SET last_seen = now() - interval '20 days' WHERE source_ip='sophos'")
        cur.execute("SELECT public.minisiem_prune_log_sources(15)")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM log_source_last_seen")
        assert cur.fetchone()[0] == 2
    seed.commit()
    with seed.cursor() as cur:
        with pytest.raises(psycopg2.Error):
            cur.execute("SELECT public.minisiem_prune_log_sources(3)")
    seed.rollback()
    for c in (a, b, seed):
        c.close()


def test_source_summary_rekeys_an_older_source_ip_summary(pg_cfg):
    from datetime import datetime, timedelta, timezone
    import storage_stats

    db.initialize(pg_cfg)
    now = datetime.now(timezone.utc)
    conn = db.connect(pg_cfg)
    try:
        conn.execute("INSERT INTO logs(received_at,source_ip,peer_ip,message) VALUES (?,?,?,?)",
                     ((now - timedelta(days=4)).isoformat(), "203.0.113.9", "10.0.0.7", "old"))
        # The previous release keyed rows by source_ip and set no marker.
        conn.execute("DELETE FROM log_source_last_seen")
        conn.execute("INSERT INTO log_source_last_seen VALUES ('203.0.113.9', now() - interval '4 days')")
        conn.execute("COMMENT ON TABLE log_source_last_seen IS NULL")
        conn.commit()
        for statement in storage_stats.postgres_schema_statements():
            conn.execute(statement)
        conn.commit()
        assert storage_stats.silent_sources(conn, (now - timedelta(days=14)).isoformat(),
                                            (now - timedelta(days=3)).isoformat()) == (1, ["10.0.0.7"])
    finally:
        conn.close()


def test_playbook_scan_pages_and_all_history_steps_on_postgres(pg_cfg, monkeypatch):
    from datetime import datetime, timedelta, timezone
    import contextlib
    import io
    from werkzeug.datastructures import MultiDict
    import correlations
    import dashboard
    from listener import Storage, parse_syslog

    db.initialize(pg_cfg)
    now = datetime.now(timezone.utc)
    with contextlib.redirect_stdout(io.StringIO()):
        storage = Storage(db_config=pg_cfg)
        for i, days in enumerate([0, 0, 0, 3, 3, 40, 400]):
            ev = parse_syslog(f"<38>Nov 14 10:00:00 web01 sshd[1]: Failed password for root from 203.0.113.{i} port 22",
                              "10.0.0.5")
            ev["received_at"] = (now - timedelta(days=days, minutes=i)).isoformat()
            ev["device_timestamp"] = ""
            storage.insert_log(ev, fields={"act": "deny"})
        storage.conn.commit()
        storage.close()

    conn = db.connect(pg_cfg)
    try:
        monkeypatch.setattr(correlations, "PAGE_ROWS", 2)
        out = correlations.run_correlation(conn, {"type": "threshold", "pattern": "failed password",
                                                  "group_by": "hostname", "threshold": 1,
                                                  "window_minutes": 5 * 1440})
        assert out["coverage"]["complete"] and out["coverage"]["scanned"] == 5
        assert out["groups"][0]["count"] == 5
        out = correlations.run_correlation(conn, {"type": "threshold", "pattern": "failed password",
                                                  "group_by": "hostname", "threshold": 1,
                                                  "window_minutes": 5 * 1440}, scan_limit=3)
        assert not out["coverage"]["complete"] and out["groups"][0]["count"] == 3
    finally:
        conn.close()

    monkeypatch.setattr(dashboard, "DB_CONFIG", pg_cfg)
    cols = "id, received_at, source_ip, message"
    with dashboard.app.test_request_context("/"):
        stepped = dashboard._query_logs_extracted(MultiDict([("f_act", "deny"), ("scope", "all")]), 4, cols)
        unbounded = dashboard._query_logs_window(MultiDict([("f_act", "deny"), ("scope", "all")]), 4, cols)
        assert [r["id"] for r in stepped] == [r["id"] for r in unbounded] and len(stepped) == 4
        everything = dashboard._query_logs_extracted(MultiDict([("f_act", "deny"), ("scope", "all")]), 50, cols)
        assert len(everything) == 7

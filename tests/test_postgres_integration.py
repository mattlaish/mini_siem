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

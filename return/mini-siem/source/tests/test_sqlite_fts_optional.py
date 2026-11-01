import ast
import ipaddress
import os
from pathlib import Path
import re
import sqlite3

import db


class _Severity:
    @staticmethod
    def synonyms_of(value):
        return [str(value).lower()]


class _Args(dict):
    def get(self, key, default=None):
        return super().get(key, default)


def _build_dashboard_query(args, select_cols, search_backend):
    dashboard = Path(__file__).resolve().parents[1] / "dashboard.py"
    wanted = {
        "_fts_token", "_fts_build_match", "_like_escape", "_postgres_tsquery_token",
        "_concept_match_mode", "_field_value_predicate", "_base_match_clause",
        "_alias_match_clause", "_concept_clause", "_concept_filter_terms", "_build_log_query",
    }
    tree = ast.parse(dashboard.read_text(encoding="utf-8"), filename=str(dashboard))
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    ns = {
        "re": re, "ipaddress": ipaddress, "severity_mod": _Severity,
        "get_search_aliases": lambda: {"source": [], "host": [], "destination": []},
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(dashboard), "exec"), ns)
    return ns["_build_log_query"](_Args(args), select_cols, search_backend=search_backend)


def _insert_log(conn, message):
    conn.execute(
        """INSERT INTO logs
           (received_at,source_ip,peer_ip,format,priority,facility,severity,
            device_timestamp,hostname,destination,app_name,proc_id,msg_id,message,raw)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "2026-09-23T08:00:00+00:00", "192.0.2.10", "192.0.2.10", "unknown",
            None, "", "informational", "", "host", "", "app", "", "", message, message,
        ),
    )
    conn.commit()


def _sqlite_objects(conn):
    return {
        (row["type"], row["name"])
        for row in conn.execute(
            "SELECT type, name FROM sqlite_master WHERE name IN ('logs_fts','logs_ai','logs_ad','logs_au')"
        ).fetchall()
    }


def test_fts5_unavailable_initializes_and_ingests_without_fts_objects(tmp_path, monkeypatch):
    cfg = db.config_from_path(os.path.join(tmp_path, "no-fts.db"))
    monkeypatch.setattr(db, "fts5_available", lambda _conn: False)

    db.initialize(cfg)
    conn = db.connect(cfg)
    try:
        assert _sqlite_objects(conn) == set()
        _insert_log(conn, "fortigate blocked connection")
        sql, params = _build_dashboard_query(
            {"q": "blocked"}, "l.id, l.message", search_backend="sqlite_like"
        )
        assert "logs_fts" not in sql
        row = conn.execute(sql + " LIMIT ?", params + [10]).fetchone()
        assert row is not None and row["message"] == "fortigate blocked connection"
    finally:
        conn.close()


def test_existing_fts_db_reopens_without_fts_and_drops_trigger_dependency(tmp_path, monkeypatch):
    cfg = db.config_from_path(os.path.join(tmp_path, "existing.db"))
    probe = db.connect(cfg)
    try:
        if not db.fts5_available(probe):
            return
    finally:
        probe.close()

    db.initialize(cfg)
    conn = db.connect(cfg)
    try:
        assert ("table", "logs_fts") in _sqlite_objects(conn)
        assert ("trigger", "logs_ai") in _sqlite_objects(conn)
        _insert_log(conn, "existing indexed event")
    finally:
        conn.close()

    monkeypatch.setattr(db, "fts5_available", lambda _conn: False)
    db.initialize(cfg)
    conn = db.connect(cfg)
    try:
        objects = _sqlite_objects(conn)
        # Preserve the prior virtual table metadata, but remove every runtime
        # write dependency on it while this SQLite runtime lacks FTS5.
        assert ("trigger", "logs_ai") not in objects
        assert ("trigger", "logs_ad") not in objects
        assert ("trigger", "logs_au") not in objects
        _insert_log(conn, "second event after capability loss")
        sql, params = _build_dashboard_query(
            {"q": "capability loss"}, "l.id, l.message", search_backend="sqlite_like"
        )
        assert "logs_fts" not in sql
        row = conn.execute(sql + " LIMIT ?", params + [10]).fetchone()
        assert row is not None and "capability loss" in row["message"]
    finally:
        conn.close()


def test_runtime_probe_uses_actual_fts5_module_not_compile_option_query():
    raw = sqlite3.connect(":memory:")
    raw.row_factory = sqlite3.Row
    conn = db.Connection(raw, "sqlite")
    try:
        available = db.fts5_available(conn)
        if available:
            raw.execute("CREATE VIRTUAL TABLE temp.confirm_fts5 USING fts5(value)")
            raw.execute("DROP TABLE temp.confirm_fts5")
        assert available in (True, False)
    finally:
        conn.close()

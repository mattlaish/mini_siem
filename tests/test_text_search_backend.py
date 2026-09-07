import ast
import ipaddress
import os
import re
from pathlib import Path

import db


DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard.py"


class _Severity:
    @staticmethod
    def synonyms_of(value):
        return [str(value).lower()]


class Args(dict):
    def get(self, key, default=None):
        return super().get(key, default)


def _query_helpers():
    """Load only pure query-builder helpers from dashboard.py.

    This keeps the regression runnable in packaging environments where Flask is
    intentionally absent, while still executing the actual current source.
    """
    wanted = {
        "_fts_token", "_postgres_tsquery_token", "_fts_build_match", "_subnet_clause",
        "_like_escape", "_concept_match_mode", "_base_match_clause", "_alias_match_clause",
        "_concept_clause", "_concept_filter_terms", "_build_log_query",
    }
    tree = ast.parse(DASHBOARD.read_text(encoding="utf-8"), filename=str(DASHBOARD))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    module = ast.Module(body=nodes, type_ignores=[])
    ns = {
        "re": re,
        "ipaddress": ipaddress,
        "severity_mod": _Severity,
        "get_search_aliases": lambda: {"source": [], "host": [], "destination": []},
    }
    exec(compile(module, str(DASHBOARD), "exec"), ns)
    return ns


def test_text_search_environment_override(monkeypatch):
    cfg = {"backend": "sqlite", "text_search": "auto"}
    monkeypatch.setenv("MINISIEM_TEXT_SEARCH", "like")
    assert db.text_search_requested(cfg) == "like"
    monkeypatch.setenv("MINISIEM_TEXT_SEARCH", "not-a-mode")
    assert db.text_search_requested(cfg) == "auto"


def test_postgres_auto_prefers_indexed_fts(monkeypatch):
    class Conn:
        backend = "postgres"

    monkeypatch.setattr(
        db,
        "postgres_text_search_capabilities",
        lambda _conn: {"fts_index": True, "trigram_extension": True, "trigram_index": True},
    )
    status = db.text_search_status(Conn(), {"backend": "postgres", "text_search": "auto"}, fresh=True)
    assert status["engine"] == "postgres_fts"
    assert status["accelerated"] is True


def test_postgres_auto_falls_back_to_ilike_without_indexes(monkeypatch):
    class Conn:
        backend = "postgres"

    monkeypatch.setattr(
        db,
        "postgres_text_search_capabilities",
        lambda _conn: {"fts_index": False, "trigram_extension": False, "trigram_index": False},
    )
    status = db.text_search_status(Conn(), {"backend": "postgres", "text_search": "auto"}, fresh=True)
    assert status["engine"] == "postgres_ilike"
    assert status["accelerated"] is False


def test_postgres_fts_sql_keeps_other_filters_conjunctive():
    build = _query_helpers()["_build_log_query"]
    sql, params = build(
        Args({"q": "failed password", "source_ip": "10.0.0.5", "hostname": "DC01"}),
        "id, received_at, source_ip, hostname, destination, severity, message",
        search_backend="postgres_fts",
    )
    assert "to_tsquery" in sql
    assert "LOWER(source_ip) = ?" in sql
    assert "LOWER(hostname) LIKE ?" in sql
    assert " AND " in sql
    assert params[0] == "'failed' <-> 'password'"


def test_postgres_trigram_uses_ilike_contains_semantics():
    build = _query_helpers()["_build_log_query"]
    sql, params = build(
        Args({"q": "PowerShell.exe,!debug"}),
        "id, received_at, source_ip, hostname, destination, severity, message",
        search_backend="postgres_trigram",
    )
    assert "message ILIKE ?" in sql
    assert "message NOT ILIKE ?" in sql
    assert params == ["%PowerShell.exe%", "%debug%"]


def test_postgres_optional_search_ddl_is_once_per_process_and_uses_persisted_mode(monkeypatch):
    calls = []
    monkeypatch.setenv("MINISIEM_TEXT_SEARCH", "like")
    monkeypatch.setattr(
        db, "_ensure_postgres_text_search",
        lambda _conn, mode="auto": calls.append(mode) or {"fts": True},
    )
    db._PG_SEARCH_INIT_DONE.clear()
    cfg = {
        "backend": "postgres",
        "text_search": "fts",
        "postgres": {"host": "db", "port": 5432, "dbname": "siem", "user": "u"},
    }
    conn = object()
    db._ensure_postgres_text_search_once(conn, cfg)
    db._ensure_postgres_text_search_once(conn, cfg)
    assert calls == ["fts"]


class _DDLConn:
    def __init__(self):
        self.sql = []
    def execute(self, sql, params=()):
        self.sql.append(sql)
        return self
    def commit(self):
        pass
    def rollback(self):
        pass


def test_postgres_search_ddl_respects_selected_mode():
    like = _DDLConn()
    assert db._ensure_postgres_text_search(like, "like") == {"skipped": True}
    assert like.sql == []

    fts = _DDLConn()
    db._ensure_postgres_text_search(fts, "fts")
    joined = "\n".join(fts.sql)
    assert "idx_logs_message_fts" in joined
    assert "pg_trgm" not in joined

    trigram = _DDLConn()
    db._ensure_postgres_text_search(trigram, "trigram")
    joined = "\n".join(trigram.sql)
    assert "pg_trgm" in joined
    assert "idx_logs_message_trgm" in joined
    assert "idx_logs_message_fts" not in joined


def test_sqlite_fts_builder_retains_prefix_match_contract():
    build = _query_helpers()["_build_log_query"]
    sql, params = build(
        Args({"q": "fort,!debug"}),
        "id, received_at, source_ip, hostname, destination, severity, message",
        search_backend="sqlite_fts5",
    )
    assert "logs_fts MATCH ?" in sql
    assert params == ['"fort"* NOT "debug"*']

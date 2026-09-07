import ast
import ipaddress
import os
import re
import sqlite3
import tempfile
from pathlib import Path

import db
from listener import IngestPipeline
from normalize import write_fields

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard.py"
INDEX = ROOT / "templates" / "index.html"


class _Severity:
    @staticmethod
    def synonyms_of(value):
        return [str(value).lower()]


class Args(dict):
    def get(self, key, default=None):
        return super().get(key, default)


def _query_helpers():
    wanted = {
        "_subnet_clause", "_like_escape", "_concept_match_mode",
        "_base_match_clause", "_alias_match_clause", "_concept_clause",
        "_concept_filter_terms", "_build_log_query", "_fts_token",
        "_postgres_tsquery_token", "_fts_build_match", "_parse_field_filter",
        "_field_value_predicate",
    }
    tree = ast.parse(DASHBOARD.read_text(encoding="utf-8"), filename=str(DASHBOARD))
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    ns = {
        "re": re,
        "ipaddress": ipaddress,
        "severity_mod": _Severity,
        "get_search_aliases": lambda: {"source": [], "host": [], "destination": []},
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(DASHBOARD), "exec"), ns)
    return ns


def test_sqlite_runtime_tuning_is_applied_and_bounded():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        cfg["sqlite"].update({
            "busy_timeout_ms": 4321,
            "cache_size_kib": 16384,
            "temp_store_memory": True,
            "mmap_size_mb": 64,
            "wal_autocheckpoint_pages": 777,
            "optimize_interval_seconds": 0,
        })
        conn = db.connect(cfg)
        try:
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 4321
            assert conn.execute("PRAGMA cache_size").fetchone()[0] == -16384
            assert conn.execute("PRAGMA temp_store").fetchone()[0] == 2
            assert conn.execute("PRAGMA wal_autocheckpoint").fetchone()[0] == 777
            assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
            assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
            # mmap may be capped by the platform but must be non-negative.
            assert conn.execute("PRAGMA mmap_size").fetchone()[0] >= 0
        finally:
            conn.close()


def test_old_log_fields_schema_is_backfilled_with_normalized_index():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "legacy.db")
        raw = sqlite3.connect(path)
        raw.execute(
            "CREATE TABLE log_fields (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "log_id INTEGER NOT NULL, field TEXT NOT NULL, value TEXT)"
        )
        raw.execute("INSERT INTO log_fields(log_id,field,value) VALUES (1,'user','Alice')")
        raw.commit(); raw.close()

        cfg = db.config_from_path(path)
        db.initialize(cfg)
        conn = db.connect(cfg)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(log_fields)").fetchall()}
            assert "value_norm" in cols
            row = conn.execute("SELECT value_norm FROM log_fields WHERE log_id=1").fetchone()
            assert row["value_norm"] == "alice"
            indexes = {r[1] for r in conn.execute("PRAGMA index_list(log_fields)").fetchall()}
            assert "idx_lf_field_value_norm" in indexes
            plan = " ".join(
                r[3] for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT log_id FROM log_fields "
                    "WHERE field=? AND value_norm=? COLLATE NOCASE",
                    ("user", "alice"),
                ).fetchall()
            )
            assert "idx_lf_field_value_norm" in plan
        finally:
            conn.close()


def test_write_fields_stores_display_and_normalized_values():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        db.initialize(cfg)
        conn = db.connect(cfg)
        try:
            write_fields(conn, 7, {"User": "Alice", "event_id": 4625})
            conn.commit()
            rows = conn.execute(
                "SELECT field,value,value_norm FROM log_fields ORDER BY field"
            ).fetchall()
            assert [(r["field"], r["value"], r["value_norm"]) for r in rows] == [
                ("User", "Alice", "alice"),
                ("event_id", "4625", "4625"),
            ]
        finally:
            conn.close()


def test_field_filter_exact_prefix_and_explicit_contains_contract():
    ns = _query_helpers()
    parse = ns["_parse_field_filter"]
    pred = ns["_field_value_predicate"]

    exact = parse("event_id", "4625", "chip")
    prefix = parse("user", "adm*", "chip")
    contains = parse("command", "*powershell*", "chip")
    assert exact["mode"] == "exact" and exact["needle"] == "4625"
    assert prefix["mode"] == "prefix" and prefix["needle"] == "adm"
    assert contains["mode"] == "contains" and contains["needle"] == "powershell"
    assert "value_norm = ?" in pred("f0", "exact", "4625", backend="sqlite")[0]
    assert pred("f0", "prefix", "adm", backend="sqlite")[1] == ["adm%"]
    assert pred("f0", "contains", "powershell", backend="sqlite")[1] == ["%powershell%"]


def test_source_host_destination_use_index_friendly_modes():
    build = _query_helpers()["_build_log_query"]
    sql, params = build(
        Args({
            "source_ip": "192.0.2.15",      # full IP => exact
            "hostname": "dc01",             # bare text => prefix
            "destination": "*database*",    # explicit contains
        }),
        "id,source_ip,hostname,destination,message",
        search_backend="sqlite_like",
    )
    assert "source_ip = ? COLLATE NOCASE" in sql
    assert "hostname LIKE ? COLLATE NOCASE" in sql
    assert "destination LIKE ? COLLATE NOCASE" in sql
    assert "192.0.2.15" in params
    assert "dc01%" in params
    assert "%database%" in params


def test_sqlite_prefix_plan_uses_composite_identity_index():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        db.initialize(cfg)
        conn = db.connect(cfg)
        try:
            plan = " ".join(
                r[3] for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT id FROM logs "
                    "WHERE hostname LIKE ? COLLATE NOCASE ESCAPE '\\'",
                    ("dc01%",),
                ).fetchall()
            )
            assert "idx_logs_host_time_ci" in plan
            field_plan = " ".join(
                r[3] for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT log_id FROM log_fields "
                    "WHERE field=? AND value_norm LIKE ? COLLATE NOCASE ESCAPE '\\'",
                    ("user", "adm%"),
                ).fetchall()
            )
            assert "idx_lf_field_value_norm" in field_plan
        finally:
            conn.close()


def test_per_event_stdout_is_off_by_default(capsys):
    class Storage:
        def insert_log(self, event, fields=None):
            return 1

    class Fields:
        def extract(self, event):
            return {}
        def capture_unidentified(self, *args, **kwargs):
            pass

    class Noop:
        def process(self, *args, **kwargs):
            pass

    class Forwarders:
        def forward(self, event):
            return True

    pipeline = IngestPipeline(
        Storage(), Noop(), Noop(), Fields(), Forwarders(),
        worker_count=1, queue_size=4, stats_interval_seconds=0,
    )
    pipeline.submit(b"<134>Sep  4 12:00:00 host app: user=alice", "192.0.2.1")
    pipeline.stop(drain=True)
    captured = capsys.readouterr()
    assert "user=alice" not in captured.out


def test_dashboard_log_refresh_uses_incremental_dom_and_event_delegation():
    html = INDEX.read_text(encoding="utf-8")
    assert "function incrementalRenderLogs(rows, ncols, signature)" in html
    assert "body.insertAdjacentHTML('afterbegin'" in html
    assert "const logsBodyEl = document.getElementById('logsBody');" in html
    assert "logsBodyEl.addEventListener('click'" in html
    assert "document.querySelectorAll('.log-row').forEach" not in html
    assert "if (!background) renderXColumns();" in html
    assert "if (nextIds.length === renderedLogIds.length" in html

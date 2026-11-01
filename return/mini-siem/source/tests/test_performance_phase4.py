import ast
import base64
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path

import db
from listener import IngestPipeline, Storage, parse_syslog

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard.py"
INDEX = ROOT / "templates" / "index.html"


class Noop:
    def process(self, *args, **kwargs):
        return None


class Fields:
    def extract(self, event):
        return {"event_id": "4625", "user": "alice"}

    def capture_unidentified(self, *args, **kwargs):
        return None


class Forwarders:
    def forward(self, event):
        return True


def _event(i=0, source="192.0.2.10"):
    ev = parse_syslog(
        f"<132>Sep  4 15:00:00 host app: Event ID 4625 user=alice seq={i}", source
    )
    ev["received_at"] = f"2026-09-04T15:{i % 60:02d}:00+00:00"
    return ev


def _cursor_helpers():
    wanted = {
        "_encode_log_cursor", "_decode_log_cursor", "_cursor_supported",
        "_build_log_query",
    }
    tree = ast.parse(DASHBOARD.read_text(encoding="utf-8"), filename=str(DASHBOARD))
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    ns = {"json": json, "base64": base64}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(DASHBOARD), "exec"), ns)
    return ns


def test_db_writer_microbatches_and_rollups_are_transactional():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        cfg.update({
            "ingest_workers": 4,
            "ingest_queue_size": 1000,
            "db_writer_queue_size": 1000,
            "db_writer_batch_size": 50,
            "db_writer_max_delay_ms": 25,
        })
        storage = Storage(db_config=cfg)
        pipeline = IngestPipeline(
            storage, Noop(), Noop(), Fields(), Forwarders(),
            worker_count=4, queue_size=1000,
            db_writer_queue_size=1000, db_writer_batch_size=50,
            db_writer_max_delay_ms=25, stats_interval_seconds=0,
        )
        try:
            for i in range(200):
                assert pipeline.submit(
                    f"<132>Sep  4 15:00:00 host app: Event ID 4625 user=alice seq={i}",
                    "192.0.2.10", transport="api",
                    received_at=f"2026-09-04T15:{i % 60:02d}:00+00:00",
                )
            pipeline.stop(drain=True)
            st = pipeline.stats()
            assert st["processed"] == 200
            assert st["db_written"] == 200
            assert st["db_failed"] == 0
            assert st["db_batches"] < 200
            assert st["db_batch_avg"] > 1
            assert st["db_commit_ms_p95"] >= 0

            observer = db.connect(cfg)
            try:
                assert observer.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"] == 200
                assert observer.execute("SELECT COUNT(*) c FROM log_fields").fetchone()["c"] >= 400
                rt = db.read_runtime_stats(observer, ["total_logs"])
                assert int(rt["total_logs"]["value_num"]) == 200
                src = observer.execute(
                    "SELECT event_count,last_seen FROM source_last_seen WHERE source_ip=?",
                    ("192.0.2.10",),
                ).fetchone()
                assert src["event_count"] == 200
                assert observer.execute("SELECT SUM(count) c FROM hourly_log_stats").fetchone()["c"] == 200
            finally:
                observer.close()
        finally:
            # stop is idempotence-neutral for this test; storage still needs close.
            storage.close()


def test_post_processing_never_runs_before_log_id_is_persisted():
    class PersistingStorage:
        def __init__(self):
            self.persisted = set()
            self.next_id = 0

        def insert_log_batch(self, batch):
            ids = []
            for _event, _fields in batch:
                self.next_id += 1
                self.persisted.add(self.next_id)
                ids.append(self.next_id)
            return ids, 0.2

    class AssertEngine:
        def __init__(self, storage):
            self.storage = storage
            self.seen = []

        def process(self, log_id, event):
            assert log_id in self.storage.persisted
            self.seen.append(log_id)

    storage = PersistingStorage()
    engine = AssertEngine(storage)
    pipeline = IngestPipeline(
        storage, engine, Noop(), Fields(), Forwarders(),
        worker_count=2, queue_size=20,
        db_writer_queue_size=20, db_writer_batch_size=10,
        db_writer_max_delay_ms=5, stats_interval_seconds=0,
    )
    for i in range(10):
        assert pipeline.submit(f"event seq={i}", "192.0.2.2", transport="api")
    pipeline.stop(drain=True)
    assert len(engine.seen) == 10
    assert pipeline.stats()["processed"] == 10


def test_alert_counter_uses_runtime_rollup():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        storage = Storage(db_config=cfg)
        try:
            storage.insert_alert("test", "warning", "192.0.2.3", "test alert", [1])
            conn = db.connect(cfg)
            try:
                rt = db.read_runtime_stats(conn, ["total_alerts"])
                assert int(rt["total_alerts"]["value_num"]) == 1
            finally:
                conn.close()
        finally:
            storage.close()


def test_received_at_id_cursor_is_stable_across_equal_timestamps():
    ns = _cursor_helpers()
    encode, decode, build = ns["_encode_log_cursor"], ns["_decode_log_cursor"], ns["_build_log_query"]
    cursor = encode("2026-09-04T15:00:00+00:00", 1)
    assert decode(cursor) == ("2026-09-04T15:00:00+00:00", 1)

    class Args(dict):
        def get(self, key, default=None):
            return super().get(key, default)

    args = Args({"after_cursor": cursor, "sort": "received_at", "dir": "asc"})
    sql, params = build(args, "id, received_at", search_backend="sqlite_like")
    assert "l.received_at > ?" in sql
    assert "ORDER BY received_at ASC, id ASC" in sql

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE logs(id INTEGER PRIMARY KEY, received_at TEXT NOT NULL)")
    conn.executemany("INSERT INTO logs VALUES (?,?)", [
        (1, "2026-09-04T15:00:00+00:00"),
        (2, "2026-09-04T15:00:00+00:00"),
        (3, "2026-09-04T15:01:00+00:00"),
    ])
    got = [r["id"] for r in conn.execute(sql, params).fetchall()]
    assert got == [2, 3]

    before = encode("2026-09-04T15:00:00+00:00", 2)
    sql, params = build(Args({"before_cursor": before, "sort": "received_at", "dir": "desc"}),
                        "id, received_at", search_backend="sqlite_like")
    got = [r["id"] for r in conn.execute(sql, params).fetchall()]
    assert got == [1]


def test_dashboard_uses_incremental_cursor_and_timeline_virtualization():
    html = INDEX.read_text(encoding="utf-8")
    assert "params.set('after_cursor', logNewestCursor);" in html
    assert "params.set('envelope', '1');" in html
    assert "function prependIncrementalLogs(rows, ncols)" in html
    assert "timelineNewestCursor" in html
    assert "params.set('after_cursor', timelineNewestCursor);" in html
    assert 'id="timelineVirtualLayer"' in html or 'timelineVirtualLayer' in html
    assert "function renderTimelineWindow()" in html
    assert "timelineLayout.filter(item =>" in html
    assert "timelineScrollEl.addEventListener('scroll', scheduleTimelineVirtualRender" in html
    # Card click is delegated; virtualized cards do not each receive a listener.
    assert "document.getElementById('timelineCanvas').addEventListener('click'" in html


def test_phase4_schema_has_cursor_and_rollup_indexes():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        db.initialize(cfg)
        conn = db.connect(cfg)
        try:
            tables = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            assert {"runtime_stats", "hourly_log_stats", "source_last_seen"} <= tables
            indexes = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()}
            assert "idx_logs_received_id" in indexes
            plan = " ".join(r[3] for r in conn.execute(
                "EXPLAIN QUERY PLAN SELECT id FROM logs "
                "WHERE received_at < ? OR (received_at = ? AND id < ?) "
                "ORDER BY received_at DESC,id DESC LIMIT 200",
                ("2026-09-04T15:00:00+00:00", "2026-09-04T15:00:00+00:00", 10),
            ).fetchall())
            assert "idx_logs_received_id" in plan or "idx_logs_received_at" in plan
        finally:
            conn.close()


def test_db_writer_shutdown_flushes_partial_tail_without_waiting_full_delay():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        storage = Storage(db_config=cfg)
        pipeline = IngestPipeline(
            storage, Noop(), Noop(), Fields(), Forwarders(),
            worker_count=1, queue_size=20,
            db_writer_queue_size=20, db_writer_batch_size=100,
            db_writer_max_delay_ms=10000, stats_interval_seconds=0,
        )
        try:
            for i in range(3):
                assert pipeline.submit(
                    f"<132>Sep  4 15:00:00 host app: tail seq={i}",
                    "192.0.2.55", transport="api",
                    received_at=f"2026-09-04T15:00:0{i}+00:00",
                )
            started = time.monotonic()
            pipeline.stop(drain=True)
            elapsed = time.monotonic() - started
            assert elapsed < 2.0
            assert pipeline.stats()["db_written"] == 3
            observer = db.connect(cfg)
            try:
                assert observer.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"] == 3
            finally:
                observer.close()
        finally:
            storage.close()


def test_recent_rollup_counts_are_exact_across_partial_boundary_hours():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        storage = Storage(db_config=cfg)
        try:
            # In-range leading partial hour, one full interior hour, and trailing
            # partial hour. The two out-of-range rows must not leak in even though
            # their hourly buckets overlap the boundary buckets.
            rows = [
                ("2026-09-03T15:20:00+00:00", "warning"),   # before start
                ("2026-09-03T15:40:00+00:00", "warning"),   # leading partial
                ("2026-09-03T16:10:00+00:00", "error"),     # full hour
                ("2026-09-04T15:10:00+00:00", "critical"),  # trailing partial
                ("2026-09-04T15:40:00+00:00", "critical"),  # after end
            ]
            storage.insert_log_batch([
                ({**_event(i), "received_at": ts, "severity": sev}, {"event_id": "4625"})
                for i, (ts, sev) in enumerate(rows)
            ])
            observer = db.connect(cfg)
            try:
                got = db.recent_log_counts_from_rollups(
                    observer,
                    "2026-09-03T15:30:00+00:00",
                    "2026-09-04T15:30:00+00:00",
                )
                assert got == {"warning": 1, "error": 1, "critical": 1}
                same_hour = db.recent_log_counts_from_rollups(
                    observer,
                    "2026-09-04T15:00:00+00:00",
                    "2026-09-04T15:30:00+00:00",
                )
                assert same_hour == {"critical": 1}
            finally:
                observer.close()
        finally:
            storage.close()

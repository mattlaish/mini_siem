import os
import tempfile
import threading
import time

import db
from forwarder import ForwarderManager
from listener import IngestPipeline, Storage, parse_syslog
from normalize import reindex, write_fields


def _event(message="user=alice action=login"):
    return parse_syslog(
        f"<134>Sep  3 10:00:00 host app: {message}",
        "192.0.2.10",
    )


def test_log_and_fields_share_one_batched_transaction():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        cfg["commit_batch_size"] = 100
        cfg["commit_max_delay_ms"] = 60_000
        storage = Storage(db_config=cfg)
        try:
            log_id = storage.insert_log(_event(), fields={"user": "alice", "action": "login"})

            observer = db.connect(cfg)
            try:
                # A separate connection must not see either row before the
                # configured batch is flushed.
                assert observer.execute("SELECT COUNT(*) AS n FROM logs").fetchone()["n"] == 0
                assert observer.execute("SELECT COUNT(*) AS n FROM log_fields").fetchone()["n"] == 0
            finally:
                observer.close()

            storage.flush()
            observer = db.connect(cfg)
            try:
                assert observer.execute("SELECT COUNT(*) AS n FROM logs").fetchone()["n"] == 1
                rows = observer.execute(
                    "SELECT field, value FROM log_fields WHERE log_id=? ORDER BY field", (log_id,)
                ).fetchall()
                assert [(r["field"], r["value"]) for r in rows] == [
                    ("action", "login"),
                    ("user", "alice"),
                ]
            finally:
                observer.close()
        finally:
            storage.close()


def test_write_fields_uses_one_executemany_call():
    class SpyConn:
        def __init__(self):
            self.calls = []

        def executemany(self, sql, rows):
            self.calls.append((sql, list(rows)))

        def execute(self, *args, **kwargs):
            raise AssertionError("write_fields should not issue per-row execute calls")

    conn = SpyConn()
    count = write_fields(conn, 7, {"user": "alice", "action": "login", "src": "192.0.2.1"})
    assert count == 3
    assert len(conn.calls) == 1
    assert len(conn.calls[0][1]) == 3


def test_reindex_batches_deletes_and_inserts():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        db.initialize(cfg)
        base = db.connect(cfg)
        for i in range(5):
            base.execute(
                """INSERT INTO logs
                   (received_at,source_ip,peer_ip,format,priority,facility,severity,
                    device_timestamp,hostname,destination,app_name,proc_id,msg_id,message,raw)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "2026-09-03T10:00:00+00:00", "192.0.2.1", "192.0.2.1", "unknown", None,
                    "", "informational", "", "host", "", "app", "", "",
                    f"user=user{i} action=login", f"user=user{i} action=login",
                ),
            )
        base.commit()

        class CountingConn:
            def __init__(self, inner):
                self.inner = inner
                self.executemany_calls = 0
                self.commits = 0

            def execute(self, sql, params=()):
                return self.inner.execute(sql, params)

            def executemany(self, sql, rows):
                self.executemany_calls += 1
                return self.inner.executemany(sql, rows)

            def commit(self):
                self.commits += 1
                return self.inner.commit()

        wrapped = CountingConn(base)
        logs, fields = reindex(wrapped, batch_size=5)
        assert logs == 5
        assert fields == 10
        assert wrapped.executemany_calls == 2  # one batched DELETE + one batched INSERT
        assert wrapped.commits == 1
        base.close()


def test_ingest_queue_reports_udp_overflow_and_drains():
    class BlockingStorage:
        def __init__(self):
            self.entered = threading.Event()
            self.release = threading.Event()
            self.events = []
            self._next = 0

        def insert_log(self, event, fields=None):
            self.entered.set()
            assert self.release.wait(2)
            self.events.append((event, dict(fields or {})))
            self._next += 1
            return self._next

    class Fields:
        def extract(self, event):
            return {"worker": "ok"}

        def capture_unidentified(self, *args, **kwargs):
            return None

    class Noop:
        def process(self, *args, **kwargs):
            return None

    class Forwarders:
        def __init__(self):
            self.count = 0

        def forward(self, event):
            self.count += 1
            return True

    storage = BlockingStorage()
    forwarders = Forwarders()
    pipeline = IngestPipeline(
        storage, Noop(), Noop(), Fields(), forwarders,
        worker_count=1, queue_size=1,
    )
    try:
        assert pipeline.submit(b"first", "192.0.2.1", transport="udp", received_at="2026-09-03T01:00:00+00:00")
        assert storage.entered.wait(1)
        assert pipeline.submit(b"second", "192.0.2.2", transport="udp")
        assert not pipeline.submit(b"third", "192.0.2.3", transport="udp")
        stats = pipeline.stats()
        assert stats["dropped"] == 1
        assert stats["dropped_udp"] == 1
        storage.release.set()
        pipeline.stop(drain=True)
        stats = pipeline.stats()
        assert stats["processed"] == 2
        assert stats["failed"] == 0
        assert storage.events[0][0]["received_at"] == "2026-09-03T01:00:00+00:00"
        assert forwarders.count == 2
    finally:
        storage.release.set()


def test_forwarder_enqueue_is_non_blocking_when_sender_is_slow():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        storage = Storage(db_config=cfg)
        manager = ForwarderManager(storage, listen_port=5514, reload_interval=3600, queue_size=4)

        class SlowForwarder:
            def __init__(self):
                self.id = 999999
                self.name = "slow-test"
                self.origin_mode = "off"
                self.pending_count = 0
                self.last_forward_at = None
                self.last_error = None
                self.entered = threading.Event()
                self.release = threading.Event()

            def wants(self, event):
                return True

            def send(self, raw, udp_sock):
                self.entered.set()
                assert self.release.wait(2)
                self.pending_count += 1

            def _close_tcp(self):
                return None

        slow = SlowForwarder()
        with manager._fw_lock:
            manager._forwarders[slow.id] = slow
        try:
            start = time.perf_counter()
            assert manager.forward(_event("hello"))
            elapsed = time.perf_counter() - start
            assert elapsed < 0.05
            assert slow.entered.wait(1)
            slow.release.set()
            manager.stop(drain=True)
            assert manager.stats()["dropped"] == 0
        finally:
            slow.release.set()
            storage.close()


def test_fts5_index_sync_and_availability_probe():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        db.initialize(cfg)
        conn = db.connect(cfg)
        try:
            if not db.fts5_available(conn):
                # Initialization must remain successful even on SQLite builds
                # compiled without FTS5.
                return
            conn.execute(
                """INSERT INTO logs
                   (received_at,source_ip,peer_ip,format,priority,facility,severity,
                    device_timestamp,hostname,destination,app_name,proc_id,msg_id,message,raw)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "2026-09-03T10:00:00+00:00", "192.0.2.1", "192.0.2.1", "unknown", None,
                    "", "informational", "", "host", "", "app", "", "",
                    "fortigate blocked connection", "fortigate blocked connection",
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?", ('"fort"*',)
            ).fetchone()
            assert row is not None
        finally:
            conn.close()

import hashlib
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timedelta, timezone

import archive
import db
from listener import Storage
from maintenance import run_maintenance_cycle
from telemetry import derive_operational_health

ROOT = Path(__file__).resolve().parents[1]


def _event(ts, message="Event ID 4625 failed login", raw="<132>fixed failed login"):
    return {
        "received_at": ts,
        "source_ip": "192.0.2.44",
        "peer_ip": "192.0.2.44",
        "format": "rfc3164",
        "priority": 132,
        "facility": "auth",
        "severity": "warning",
        "device_timestamp": "Sep 01 10:00:00",
        "hostname": "dc01",
        "destination": "auth.local",
        "app_name": "sshd",
        "proc_id": "123",
        "msg_id": "AUTH",
        "message": message,
        "raw": raw,
    }


def _cfg(td, mode="copy"):
    cfg = db.config_from_path(os.path.join(td, "siem.db"))
    cfg["archive"].update({
        "enabled": True,
        "directory": os.path.join(td, "archive"),
        "hot_days": 1,
        "mode": mode,
        "batch_rows": 100,
        "max_batches_per_cycle": 1,
        "run_interval_seconds": 3600,
        "verify_on_create": True,
    })
    cfg["maintenance"]["incremental_vacuum_pages"] = 0
    return cfg


def test_archive_copy_is_lossless_exact_dedup_and_idempotent():
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td, "copy")
        storage = Storage(db_config=cfg)
        now = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        try:
            items = []
            # Three true duplicates differ only in mini-SIEM receive time.
            for i in range(3):
                items.append((_event((now - timedelta(days=10, minutes=-i)).isoformat()),
                              {"event_id": "4625", "user": "alice"}))
            # Similar security event is NOT deduplicated.
            items.append((_event((now - timedelta(days=10, minutes=-4)).isoformat(),
                                 message="Event ID 4625 failed login user=bob",
                                 raw="<132>fixed failed login user=bob"),
                          {"event_id": "4625", "user": "bob"}))
            ids, _ = storage.insert_log_batch(items)

            result = archive.run_archive_cycle(storage, cfg, now=now)
            assert result["error"] == ""
            assert result["archived_events"] == 4
            assert result["unique_payloads"] == 2
            assert result["duplicate_occurrences"] == 2
            assert result["hot_evicted"] == 0
            assert storage.conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"] == 4

            segs = archive.list_segments(storage.conn)
            assert len(segs) == 1
            seg = segs[0]
            assert Path(seg["path"]).is_file()
            assert Path(seg["manifest_path"]).is_file()
            assert hashlib.sha256(Path(seg["path"]).read_bytes()).hexdigest() == seg["sha256"]
            manifest = json.loads(Path(seg["manifest_path"]).read_text())
            assert manifest["format"] == "mini-siem-archive-v1"
            assert manifest["event_count"] == 4

            ac = archive.open_archive(seg["path"])
            try:
                assert ac.execute("SELECT COUNT(*) c FROM archive_occurrences").fetchone()["c"] == 4
                assert ac.execute("SELECT COUNT(*) c FROM archive_payloads").fetchone()["c"] == 2
                row = ac.execute("SELECT raw,message FROM logs WHERE id=?", (ids[0],)).fetchone()
                assert row["raw"] == "<132>fixed failed login"
                assert row["message"] == "Event ID 4625 failed login"
                fields = {r["field"]: r["value"] for r in ac.execute(
                    "SELECT field,value FROM log_fields WHERE log_id=?", (ids[0],)).fetchall()}
                assert fields == {"event_id": "4625", "user": "alice"}
            finally:
                ac.close()

            # Copy mode does not produce endless duplicate archive segments.
            again = archive.run_archive_cycle(storage, cfg, now=now)
            assert again["archived_events"] == 0
            assert len(archive.list_segments(storage.conn)) == 1
        finally:
            storage.close()


def test_archive_move_evicts_only_verified_hot_copy_and_preserves_evidence_rollups():
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td, "copy")
        storage = Storage(db_config=cfg)
        now = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        old = now - timedelta(days=10)
        try:
            ids, _ = storage.insert_log_batch([
                (_event((old + timedelta(minutes=i)).isoformat()),
                 {"event_id": "4625", "user": "alice"})
                for i in range(3)
            ])
            with storage.lock:
                storage.conn.execute(
                    """INSERT INTO ioc_matches
                       (matched_at,ioc_id,ioc_type,ioc_value,threat,log_id,source_ip,hostname,message)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (old.isoformat(), None, "ip", "192.0.2.44", "test", ids[0],
                     "192.0.2.44", "dc01", "failed login"),
                )
                storage.conn.commit()

            copy_result = archive.run_archive_cycle(storage, cfg, now=now)
            assert copy_result["archived_events"] == 3
            runtime_before = db.read_runtime_stats(storage.conn, ["total_logs"])
            hourly_before = storage.conn.execute("SELECT SUM(count) c FROM hourly_log_stats").fetchone()["c"]

            cfg["archive"]["mode"] = "move"
            move_result = archive.run_archive_cycle(storage, cfg, now=now)
            assert move_result["hot_evicted_existing"] == 3
            assert storage.conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"] == 0
            # Detection evidence and global evidence counters survive hot eviction.
            assert storage.conn.execute("SELECT COUNT(*) c FROM ioc_matches").fetchone()["c"] == 1
            assert db.read_runtime_stats(storage.conn, ["total_logs"])["total_logs"]["value_num"] == runtime_before["total_logs"]["value_num"]
            assert storage.conn.execute("SELECT SUM(count) c FROM hourly_log_stats").fetchone()["c"] == hourly_before
            assert storage.conn.execute(
                "SELECT event_count FROM source_last_seen WHERE source_ip='192.0.2.44'"
            ).fetchone()["event_count"] == 3

            # The original global IDs remain present in the archive tier.
            seg = archive.list_segments(storage.conn, ids=[ids[1]])[0]
            ac = archive.open_archive(seg["path"])
            try:
                assert ac.execute("SELECT id FROM logs WHERE id=?", (ids[1],)).fetchone()["id"] == ids[1]
            finally:
                ac.close()
        finally:
            storage.close()


def test_archive_views_support_text_structured_field_and_time_filters_together():
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td, "move")
        storage = Storage(db_config=cfg)
        now = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        try:
            ids, _ = storage.insert_log_batch([
                (_event((now - timedelta(days=8)).isoformat()), {"event_id": "4625", "user": "alice"}),
                (_event((now - timedelta(days=7)).isoformat(), message="Event ID 4624 success",
                        raw="<132>success"), {"event_id": "4624", "user": "alice"}),
            ])
            result = archive.run_archive_cycle(storage, cfg, now=now)
            assert result["hot_evicted"] == 2
            seg = archive.list_segments(storage.conn)[0]
            ac = archive.open_archive(seg["path"])
            try:
                rows = ac.execute(
                    """SELECT l.id FROM logs l
                       JOIN log_fields f ON f.log_id=l.id AND f.field=? AND f.value_norm=?
                       WHERE l.message LIKE ? AND l.source_ip=? AND l.hostname=?
                         AND l.received_at>=? AND l.received_at<=?
                       ORDER BY l.received_at DESC,l.id DESC""",
                    ("event_id", "4625", "%failed login%", "192.0.2.44", "dc01",
                     (now - timedelta(days=9)).isoformat(), (now - timedelta(days=6)).isoformat()),
                ).fetchall()
                assert [r["id"] for r in rows] == [ids[0]]
            finally:
                ac.close()
        finally:
            storage.close()


def test_archive_catalog_checksum_verification_detects_tamper():
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        storage = Storage(db_config=cfg)
        now = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        try:
            storage.insert_log_batch([(_event((now - timedelta(days=5)).isoformat()), {"event_id": "4625"})])
            archive.run_archive_cycle(storage, cfg, now=now)
            assert archive.verify_catalog(storage.conn)[0]["ok"] is True
            seg = archive.list_segments(storage.conn)[0]
            with open(seg["path"], "ab") as fh:
                fh.write(b"tamper")
            checked = archive.verify_catalog(storage.conn)[0]
            assert checked["ok"] is False
            assert "checksum" in checked["error"].lower()
        finally:
            storage.close()


def test_maintenance_is_nondestructive_and_reports_archive_and_quick_check():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        cfg["maintenance"]["incremental_vacuum_pages"] = 0
        storage = Storage(db_config=cfg)
        now = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        try:
            storage.insert_log_batch([(_event((now - timedelta(days=500)).isoformat()), {"event_id": "4625"})])
            status = run_maintenance_cycle(storage, cfg, now=now)
            assert storage.conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"] == 1
            assert status["archive"]["enabled"] is False
            assert status["sqlite"]["quick_check"] in ("ok", "not_due")
            assert "deleted_logs" not in status
        finally:
            storage.close()


def test_operational_health_exposes_queue_signals_without_enforcement():
    cfg = db.config_from_path(":memory:")
    health = derive_operational_health({
        "queue_depth": 85, "queue_capacity": 100,
        "db_queue_depth": 97, "db_queue_capacity": 100,
        "post_queue_depth": 1, "post_queue_capacity": 100,
        "forward_queue_depth": 1, "forward_queue_capacity": 100,
        "interval_dropped": 0, "interval_db_queue_dropped": 0,
        "interval_forward_dropped": 0, "interval_failed": 0,
        "interval_db_write_failed": 0,
    }, {}, cfg)
    assert health["state"] == "OVERLOADED"
    signals = {s["name"]: s for s in health["signals"]}
    assert signals["ingest"]["state"] == "DEGRADED"
    assert signals["DB writer"]["state"] == "OVERLOADED"
    # Health is observation only; there is no throttle/drop action in the result.
    assert "action" not in health


def test_phase6_removes_age_delete_configuration_and_freezes_ioc_architecture():
    assert "retention" not in db.DEFAULT_CONFIG
    assert db.DEFAULT_CONFIG["archive"]["enabled"] is False
    assert db.DEFAULT_CONFIG["archive"]["mode"] == "copy"
    dashboard = (ROOT / "dashboard.py").read_text(encoding="utf-8")
    assert "_record_query_telemetry_safe" in dashboard
    assert "archive search unavailable" in dashboard
    assert "include_archive" in dashboard
    help_html = (ROOT / "templates" / "help.html").read_text(encoding="utf-8")
    assert "does <strong>not</strong> age-delete evidence" in help_html
    assert "new IOC architecture decision" in help_html

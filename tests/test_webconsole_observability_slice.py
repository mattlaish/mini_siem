import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import archive
import db
import runtime_health
from listener import Storage

ROOT = Path(__file__).resolve().parents[1]


def _event(ts):
    return {
        "received_at": ts,
        "source_ip": "192.0.2.10",
        "peer_ip": "192.0.2.10",
        "format": "rfc3164",
        "priority": 13,
        "facility": "user",
        "severity": "notice",
        "device_timestamp": "",
        "hostname": "edge01",
        "destination": "",
        "app_name": "agent",
        "proc_id": "",
        "msg_id": "",
        "message": "health test",
        "raw": "<13>health test",
    }


def test_observability_schema_and_runtime_stats_roundtrip(tmp_path):
    cfg = db.config_from_path(str(tmp_path / "siem.db"))
    db.initialize(cfg)
    conn = db.connect(cfg)
    try:
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert {"runtime_stats", "archive_segments", "archive_occurrence_catalog"} <= tables
        ready = db.migration_readiness(conn)
        assert ready["ready"] is True
        assert ready["current_version"] == ready["expected_version"]
        db.runtime_stat_upsert(conn, "test_status", value_num=7, value_text='{"ok":true}')
        conn.commit()
        row = db.read_runtime_stats(conn, ["test_status"])["test_status"]
        assert row["value_num"] == 7
        assert json.loads(row["value_text"])["ok"] is True
    finally:
        conn.close()


def test_cross_process_runtime_health_marks_stale_heartbeat(tmp_path):
    cfg = db.config_from_path(str(tmp_path / "siem.db"))
    db.initialize(cfg)
    conn = db.connect(cfg)
    try:
        payload = {
            "listener": "READY", "ingest": "RUNNING", "worker": "DIRECT",
            "processed_events": 42, "failed_events": 1, "last_event_at": "2026-09-13T10:00:00+00:00",
        }
        db.runtime_stat_upsert(conn, "listener_health", value_text=json.dumps(payload),
                               updated_at=datetime.now(timezone.utc).isoformat())
        conn.commit()
        snap = runtime_health.listener_snapshot_from_db(conn, stale_after_seconds=10)
        assert snap["listener"] == "READY"
        assert snap["processed_events"] == 42

        old = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
        db.runtime_stat_upsert(conn, "listener_health", value_text=json.dumps(payload), updated_at=old)
        conn.commit()
        stale = runtime_health.listener_snapshot_from_db(conn, stale_after_seconds=10)
        assert stale["listener"] == "STALE"
        assert stale["ingest"] == "STALE"
    finally:
        conn.close()


def test_archive_cycle_records_seal_and_verification_status(tmp_path):
    cfg = db.config_from_path(str(tmp_path / "siem.db"))
    cfg["archive"].update({
        "enabled": True,
        "directory": str(tmp_path / "archive"),
        "hot_days": 1,
        "mode": "copy",
        "verify_on_create": True,
    })
    storage = Storage(db_config=cfg)
    try:
        old = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        ids, _ = storage.insert_log_batch([(_event(old), {"event_id": "1"})])
        assert ids == [1]
        result = archive.run_archive_cycle(storage, cfg)
        assert result["error"] == ""
        assert result["archived_events"] == 1
        stats = db.read_runtime_stats(storage.conn, ["archive_status", "archive_verify_status"])
        verified = json.loads(stats["archive_verify_status"]["value_text"])
        assert verified["ok"] is True
        assert verified["mode"] == "on_create"
        assert archive.archive_summary(storage.conn)["segments"] == 1
    finally:
        storage.close()


def test_web_console_exposes_read_only_observability_and_systemd_restart():
    health = (ROOT / "templates" / "health.html").read_text(encoding="utf-8")
    setup = (ROOT / "templates" / "setup.html").read_text(encoding="utf-8")
    api = (ROOT / "web_blueprints" / "db_health.py").read_text(encoding="utf-8")

    assert "PostgreSQL security &amp; schema readiness" in health
    assert "Archive &amp; maintenance" in health
    assert "/api/postgres/security-status" in health
    assert "/api/archive/status" in health
    assert "Archive execution remains CLI/maintenance-only" in health
    assert "sudo systemctl restart mini-siem-listener" in setup
    assert "pkill -f listener.py" not in setup
    assert "sudo python3 listener.py --db siem.db" not in setup

    assert "has_table_privilege" in api
    assert "guard_triggers" in api
    assert "migration_readiness" in api
    assert "archive_summary" in api
    assert "run_archive_cycle" not in api
    assert "db-maintenance-credentials" not in api
    assert "archive_execution_from_web\": False" in api

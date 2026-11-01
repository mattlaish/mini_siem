import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timedelta, timezone

import db
from listener import Storage
from maintenance import run_retention_cycle
from telemetry import QueryTelemetry, derive_operational_health
from threatintel import MultiPatternMatcher, _domain_suffixes

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "templates" / "index.html"
HEALTH = ROOT / "templates" / "health.html"


def _event(ts, seq, source):
    return {
        "received_at": ts,
        "source_ip": source,
        "peer_ip": source,
        "format": "rfc3164",
        "priority": 132,
        "facility": "auth",
        "severity": "warning" if seq % 2 else "informational",
        "device_timestamp": ts,
        "hostname": f"host-{seq}",
        "destination": "server.local",
        "app_name": "phase5-test",
        "proc_id": "",
        "msg_id": "",
        "message": f"Event ID 4625 user=user{seq} seq={seq}",
        "raw": f"phase5 seq={seq}",
    }


def test_legacy_retention_config_no_longer_age_deletes_evidence():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        # A stale Phase-5 key may remain in an operator file after upgrade. It
        # is intentionally ignored by the Phase-6 maintenance path.
        cfg["retention"] = {"enabled": True, "retention_days": 1}
        storage = Storage(db_config=cfg)
        now = datetime(2026, 9, 4, tzinfo=timezone.utc)
        try:
            storage.insert_log_batch([(
                _event((now - timedelta(days=365)).isoformat(), 1, "198.51.100.1"),
                {"event_id": "4625"},
            )])
            status = run_retention_cycle(storage, cfg, now=now)
            assert storage.conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"] == 1
            assert status["archive"]["enabled"] is False
        finally:
            storage.close()


def test_archive_is_opt_in_and_disabled_by_default():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        assert cfg["archive"]["enabled"] is False
        assert "retention" not in db.DEFAULT_CONFIG


def test_fresh_sqlite_uses_incremental_auto_vacuum_without_full_vacuum():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "fresh.db"))
        db.initialize(cfg)
        conn = db.connect(cfg)
        try:
            row = conn.execute("PRAGMA auto_vacuum").fetchone()
            assert int(row[0]) == 2
        finally:
            conn.close()
    shell = (ROOT / "db-maintenance.sh").read_text(encoding="utf-8")
    assert "wal_checkpoint(PASSIVE)" in shell
    assert "incremental_vacuum" in shell
    assert "PRAGMA optimize" in shell
    assert "VACUUM;" not in shell


def test_url_multi_pattern_matcher_preserves_substring_hits_without_n_scans():
    matcher = MultiPatternMatcher([
        "https://evil.example/path",
        "malware.test/download",
        "needle-token",
    ])
    text = "GET https://evil.example/path?a=1 and later needle-token observed"
    assert set(matcher.find(text)) == {"https://evil.example/path", "needle-token"}
    assert list(matcher.find("nothing relevant")) == []


def test_domain_suffix_lookup_matches_subdomains_but_not_bare_tld():
    assert list(_domain_suffixes("a.b.evil.example")) == [
        "a.b.evil.example", "b.evil.example", "evil.example"
    ]
    assert list(_domain_suffixes("example")) == []


def test_query_telemetry_is_bounded_and_reports_percentiles_without_query_text():
    q = QueryTelemetry(max_samples=32, slow_ms=20)
    for i in range(100):
        q.record("logs.text_field", i)
    snap = q.snapshot()["logs.text_field"]
    assert snap["count"] == 100
    assert snap["samples"] == 32
    assert snap["p95_ms"] >= snap["p50_ms"]
    assert snap["slow_count"] > 0
    assert "query" not in snap


def test_operational_health_uses_recent_deltas_and_queue_pressure():
    cfg = db.config_from_path(":memory:")
    healthy = derive_operational_health({
        "queue_depth": 1, "queue_capacity": 100,
        "db_queue_depth": 1, "db_queue_capacity": 100,
        "post_queue_depth": 1, "post_queue_capacity": 100,
        "forward_queue_depth": 1, "forward_queue_capacity": 100,
        "dropped": 500,  # historical cumulative value must not poison current health
        "interval_dropped": 0, "interval_db_queue_dropped": 0, "interval_forward_dropped": 0,
        "interval_failed": 0, "interval_db_write_failed": 0,
        "db_commit_ms_p95": 5,
    }, {}, cfg)
    assert healthy["state"] == "HEALTHY"

    degraded = derive_operational_health({
        "queue_depth": 85, "queue_capacity": 100,
        "db_queue_depth": 1, "db_queue_capacity": 100,
        "interval_dropped": 0, "interval_db_queue_dropped": 0,
        "interval_failed": 0, "interval_db_write_failed": 0,
    }, {}, cfg)
    assert degraded["state"] == "DEGRADED"

    overloaded = derive_operational_health({
        "queue_depth": 99, "queue_capacity": 100,
        "interval_dropped": 1, "interval_db_queue_dropped": 0,
        "interval_failed": 0, "interval_db_write_failed": 0,
    }, {}, cfg)
    assert overloaded["state"] == "OVERLOADED"


def test_nested_phase5_config_merges_with_defaults():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "db-config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "backend": "sqlite",
                "sqlite": {"path": os.path.join(td, "x.db")},
                "archive": {"enabled": True},
                "query_telemetry": {"slow_ms": 500},
                "postgres": {"host": "db.example"},
            }, fh)
        cfg = db.load_config(path)
        assert cfg["archive"]["enabled"] is True
        assert cfg["archive"]["hot_days"] == 30
        assert cfg["query_telemetry"]["slow_ms"] == 500
        assert cfg["query_telemetry"]["max_samples"] == 512
        assert cfg["postgres"]["host"] == "db.example"
        assert cfg["postgres"]["statement_timeout_ms"] == 15000
        assert cfg["postgres"]["pool_max"] == 10


def test_dashboard_exposes_phase5_health_query_and_archive_status():
    html = INDEX.read_text(encoding="utf-8")
    assert 'id="systemHealthBadge"' in html
    assert 'id="queryTelemetry"' in html
    assert 'id="archiveStatus"' in html
    assert "params.set('purpose', 'timeline')" in html
    assert "params.set('purpose', 'live')" in html
    assert "operational_health" in html
    health = HEALTH.read_text(encoding="utf-8")
    assert "Operational state" in health
    assert "Archive / maintenance" in health
    assert "Query latency" in health


def test_postgres_validation_harness_checks_phase5_session_profile():
    text = (ROOT / "tools" / "postgres_phase4_validation.py").read_text(encoding="utf-8")
    assert "SHOW " in text
    assert "statement_timeout" in text
    assert "lock_timeout" in text
    assert "idle_in_transaction_session_timeout" in text
    assert "pool_checkout_smoke" in text
    assert (ROOT / "tools" / "postgres_phase5_validation.py").exists()

import io
import json
import tarfile
from pathlib import Path

import operational_diagnostics as od

ROOT = Path(__file__).resolve().parents[1]


def _health(**runtime_overrides):
    runtime = {
        "database": "READY", "listener": "READY", "ingest": "RUNNING", "worker": "DIRECT",
        "heartbeat_age_seconds": 1.2, "processed_events": 10, "failed_events": 0,
        "dropped_events": 0, "dropped_udp": 0, "last_event_at": "2026-09-13T10:00:00+00:00",
    }
    runtime.update(runtime_overrides)
    return {"runtime": runtime, "siem": {"total_logs": 100}, "udp": {"available": True, "drops": 0}}


def test_diagnostics_healthy_path():
    pg = {"backend": "postgres", "healthy": True, "status": "HEALTHY"}
    ar = {"status": "HEALTHY"}
    d = od.build_diagnostics(_health(), pg, ar)
    assert d["overall"] == "HEALTHY"
    by_name = {x["name"]: x for x in d["components"]}
    assert by_name["database"]["status"] == "HEALTHY"
    assert by_name["listener"]["status"] == "HEALTHY"
    assert d["read_only"] is True


def test_diagnostics_reports_stale_listener_and_pending_migration():
    pg = {"backend": "postgres", "healthy": False, "status": "WARNING", "schema": {"pending_versions": [27]}}
    d = od.build_diagnostics(_health(listener="STALE", ingest="STALE", detail="heartbeat old"), pg, {"status": "HEALTHY"})
    by_name = {x["name"]: x for x in d["components"]}
    assert by_name["listener"]["status"] == "DEGRADED"
    assert "27" in by_name["postgres_security"]["reason"]
    assert d["overall"] in {"DEGRADED", "FAILED"}


def test_safe_config_summary_excludes_credentials():
    cfg = {
        "backend": "postgres", "listen_ports": [514],
        "postgres": {"host": "db.internal", "port": 5432, "dbname": "prod", "user": "dash", "password": "supersecret", "sslmode": "require"},
        "postgres_privilege_boundary": {"enabled": True, "maintenance_role": "minisiem_maintenance", "password": "bad"},
    }
    out = od.safe_config_summary(cfg)
    blob = json.dumps(out)
    assert "supersecret" not in blob
    assert "db.internal" not in blob
    assert '"user"' not in blob
    assert '"password": "<redacted>"' in blob
    assert out["postgres"]["host_configured"] is True


def test_support_bundle_is_allowlisted_and_secret_minimized(monkeypatch):
    monkeypatch.setattr(od, "service_status_text", lambda: "[listener]\nActiveState=active\n")
    cfg = {"backend": "postgres", "listen_ports": [514], "postgres": {"host": "db", "dbname": "siem", "user": "u", "password": "DO_NOT_LEAK"}}
    payload, manifest = od.build_support_bundle(
        _health(), {"overall": "HEALTHY"}, {"backend": "postgres", "status": "HEALTHY"}, {"status": "HEALTHY"}, cfg,
        version_info={"version": "test"}, extra_files={"schema_status.json": '{"ready": true}', "evil.txt": "no"},
    )
    assert payload[:2] == b"\x1f\x8b"
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tf:
        names = set(tf.getnames())
        assert "manifest.json" in names
        assert "schema_status.json" in names
        assert "evil.txt" not in names
        assert "journal_tail.txt" in names
        all_bytes = b"".join(tf.extractfile(n).read() for n in names if tf.getmember(n).isfile())
    assert b"DO_NOT_LEAK" not in all_bytes
    assert b"raw event" in all_bytes.lower()  # omission rationale, not an event payload
    assert manifest["contains_raw_events"] is False
    assert manifest["contains_credentials"] is False


def test_static_webconsole_contracts_present():
    db_health = (ROOT / "web_blueprints" / "db_health.py").read_text()
    health = (ROOT / "templates" / "health.html").read_text()
    setup = (ROOT / "templates" / "setup.html").read_text()
    listener = (ROOT / "listener.py").read_text()
    assert '@bp.get("/api/diagnostics/status")' in db_health
    assert '@bp.post("/api/diagnostics/run")' in db_health
    assert '@bp.post("/api/support/bundle")' in db_health
    assert "Incident diagnostics" in health and "dependencyGrid" in health
    assert "Support bundle" in setup and "/api/support/bundle" in setup
    assert "troublePipeline" in setup
    assert 'payload["sources"]' in listener
    assert "PIPELINE_DIAGNOSTIC_RUN" in (ROOT / "dashboard.py").read_text()


def test_support_bundle_journal_is_omitted_by_design():
    text = od.journal_tail_text().lower()
    assert "intentionally omitted" in text
    assert "raw event" in text

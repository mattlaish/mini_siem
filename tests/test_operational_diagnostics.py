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



def test_critical_unknown_does_not_report_false_green():
    d = od.build_diagnostics(
        _health(listener="UNKNOWN", ingest="UNKNOWN", detail="listener heartbeat has not been recorded"),
        {"backend": "sqlite", "status": "NOT_APPLICABLE"},
        {"status": "HEALTHY"},
    )
    assert d["overall"] == "UNKNOWN"
    by_name = {x["name"]: x for x in d["components"]}
    assert by_name["listener"]["status"] == "UNKNOWN"
    assert by_name["ingest"]["status"] == "UNKNOWN"


def test_concrete_failure_is_not_hidden_by_other_unknown_components():
    d = od.build_diagnostics(
        _health(database="FAILED", listener="UNKNOWN", ingest="UNKNOWN", detail="database unavailable"),
        {"backend": "postgres", "status": "ERROR", "error": "database unavailable"},
        {"status": "UNKNOWN"},
    )
    assert d["overall"] == "FAILED"


def test_operator_text_sanitizer_redacts_connection_and_auth_credentials():
    pem = "-----BEGIN PRIVATE KEY-----\nvery-secret-material\n-----END PRIVATE KEY-----"
    raw = (
        "connect postgresql://dashboard:s3cr3t@db.internal/siem failed; "
        "Authorization: Bearer abcDEF123456789; api_key=sk-liveSecret123456; "
        "Authorization: Basic dXNlcjpwYXNz; " + pem
    )
    safe = od.sanitize_text(raw)
    for secret in ("s3cr3t", "abcDEF123456789", "sk-liveSecret123456", "dXNlcjpwYXNz", "very-secret-material"):
        assert secret not in safe
    assert "postgresql://dashboard:<redacted>@db.internal/siem" in safe
    assert "Authorization=<redacted>" in safe
    assert "<redacted-private-key>" in safe


def test_support_bundle_sanitizes_allowlisted_extra_json(monkeypatch):
    monkeypatch.setattr(od, "service_status_text", lambda: "ActiveState=active\n")
    extra = {
        "runtime_status.json": json.dumps({
            "detail": "postgresql://dash:pw123456@db/siem Authorization: Bearer token123456",
            "api_key": "sk-extraSecret123456",
        })
    }
    payload, manifest = od.build_support_bundle(
        _health(), {"overall": "HEALTHY"}, {"backend": "postgres", "status": "HEALTHY"},
        {"status": "HEALTHY"}, {"backend": "postgres"}, extra_files=extra,
    )
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tf:
        data = tf.extractfile("runtime_status.json").read().decode("utf-8")
    for secret in ("pw123456", "token123456", "sk-extraSecret123456"):
        assert secret not in data
    assert "<redacted>" in data
    assert manifest["contains_credentials"] is False


def test_support_bundle_rejects_invalid_allowlisted_extra_json(monkeypatch):
    monkeypatch.setattr(od, "service_status_text", lambda: "ActiveState=active\n")
    try:
        od.build_support_bundle(
            _health(), {"overall": "HEALTHY"}, {}, {}, {},
            extra_files={"runtime_status.json": "not-json password=secret"},
        )
    except ValueError as exc:
        assert "not valid UTF-8 JSON" in str(exc)
    else:
        raise AssertionError("invalid support-bundle JSON must fail closed")


def test_support_bundle_rejects_oversized_allowlisted_extra_json(monkeypatch):
    monkeypatch.setattr(od, "service_status_text", lambda: "ActiveState=active\n")
    oversized = json.dumps({"detail": "x" * od.MAX_EXTRA_FILE_BYTES})
    try:
        od.build_support_bundle(
            _health(), {"overall": "HEALTHY"}, {}, {}, {},
            extra_files={"runtime_status.json": oversized},
        )
    except ValueError as exc:
        assert "exceeds" in str(exc)
    else:
        raise AssertionError("oversized support-bundle JSON must fail closed")


def test_p9_diagnostic_routes_use_operator_safe_exception_text():
    source = (ROOT / "web_blueprints" / "db_health.py").read_text()
    for line in source.splitlines():
        if "postgres =" in line and '"status": "ERROR"' in line:
            assert "safe_exception(exc)" in line
        if "archive =" in line and '"status": "ERROR"' in line:
            assert "safe_exception(exc)" in line
    diagnostic_section = source[source.index('@bp.get("/api/diagnostics/status")'):]
    assert '"error": diagnostics_mod.safe_exception(exc)' in diagnostic_section

import json
from pathlib import Path

import db
import pytest

from performance_runtime_v2 import qualification_runner as qr


def _sqlite_cfg(tmp_path, name="perf-test.db"):
    path = tmp_path / "db-config.json"
    path.write_text(json.dumps({
        "backend": "sqlite",
        "sqlite": {"path": str(tmp_path / name)},
        "postgres": {"host": "localhost", "port": 5432, "dbname": "minisiem", "user": "", "password": ""},
    }))
    cfg = db.load_config(str(path))
    db.initialize(cfg)
    return path


def test_safe_target_requires_qualification_name_or_explicit_ack(tmp_path):
    cfg_path = _sqlite_cfg(tmp_path, "siem.db")
    cfg = db.load_config(str(cfg_path))
    with pytest.raises(RuntimeError, match="refusing write benchmark"):
        qr._assert_safe_target(cfg, False)
    qr._assert_safe_target(cfg, True)


def test_safe_target_does_not_accept_qualification_token_as_arbitrary_substring(tmp_path):
    cfg_path = _sqlite_cfg(tmp_path, "device-prod.db")
    cfg = db.load_config(str(cfg_path))
    with pytest.raises(RuntimeError, match="refusing write benchmark"):
        qr._assert_safe_target(cfg, False)

    qualified = db.config_from_path(str(tmp_path / "mini-siem-perf.db"))
    qr._assert_safe_target(qualified, False)


def test_measured_runner_exercises_real_parser_ingest_query_correlation_and_cleanup(tmp_path):
    cfg_path = _sqlite_cfg(tmp_path)
    report = qr.run(
        cfg_path,
        events=80,
        batch_size=20,
        parser_events=100,
        query_iterations=4,
        correlation_iterations=2,
        thresholds={},
    )
    assert report["format"] == "mini-siem-performance-qualification-v1"
    assert report["evaluation"]["status"] == "MEASURED_NO_THRESHOLDS"
    assert report["measurements"]["parser"]["events_per_second"] > 0
    assert report["measurements"]["ingest"]["events"] == 80
    assert report["measurements"]["ingest"]["events_per_second"] > 0
    assert report["measurements"]["query"]["count"] == 4
    assert report["measurements"]["query"]["rows_observed"] > 0
    assert report["measurements"]["correlation"]["count"] == 2
    assert report["measurements"]["correlation"]["groups_observed"] > 0
    assert report["measurements"]["resources"]["storage_after_bytes"] >= report["measurements"]["resources"]["storage_before_bytes"]
    assert report["measurement_integrity"]["valid"] is True
    assert report["evidence"]["status"] == "VALID"
    assert report["cleanup"]["completed"] is True
    conn = db.connect(db.load_config(str(cfg_path)))
    try:
        assert conn.execute("SELECT COUNT(*) AS n FROM logs WHERE app_name LIKE 'perf-qualification-%'").fetchone()["n"] == 0
    finally:
        conn.close()


def test_threshold_evaluation_never_calls_unthresholded_measurement_pass(tmp_path):
    measurements = {
        "parser": {"events_per_second": 1000},
        "ingest": {"events_per_second": 500},
        "query": {"p95_ms": 5},
        "correlation": {"p95_ms": 10},
        "resources": {"rss_growth_mb": 2, "storage_growth_mb": 3},
    }
    assert qr._evaluate(measurements, {})["status"] == "MEASURED_NO_THRESHOLDS"
    passed = qr._evaluate(measurements, {"min_ingest_eps": 400, "max_query_p95_ms": 10})
    assert passed["status"] == "PASS"
    failed = qr._evaluate(measurements, {"min_ingest_eps": 600})
    assert failed["status"] == "FAIL"


def test_sqlite_storage_measurement_includes_wal_but_not_shm(tmp_path):
    db_path = tmp_path / "perf-test.db"
    db_path.write_bytes(b"x" * 100)
    Path(str(db_path) + "-wal").write_bytes(b"w" * 50)
    Path(str(db_path) + "-shm").write_bytes(b"s" * 25)
    cfg = db.config_from_path(str(db_path))
    assert qr._storage_bytes(None, cfg) == 150


def test_long_run_latency_reservoir_is_bounded_but_keeps_exact_count_and_mean():
    r = qr._LatencyReservoir(cap=5)
    for value in range(1, 101):
        r.add(float(value))
    summary = r.summary()
    assert summary["count"] == 100
    assert summary["sample_count"] == 5
    assert summary["sample_cap"] == 5
    assert summary["percentiles_approximate"] is True
    assert summary["min_ms"] == 1.0
    assert summary["max_ms"] == 100.0
    assert summary["mean_ms"] == 50.5


def test_cleanup_failure_marks_evidence_invalid(tmp_path, monkeypatch):
    cfg_path = _sqlite_cfg(tmp_path)

    def fail_cleanup(conn, marker):
        raise RuntimeError("simulated cleanup failure")

    monkeypatch.setattr(qr, "_cleanup", fail_cleanup)
    report = qr.run(
        cfg_path, events=20, batch_size=10, parser_events=20,
        query_iterations=2, correlation_iterations=1, thresholds={},
    )
    assert report["evaluation"]["status"] == "MEASURED_NO_THRESHOLDS"
    assert report["cleanup"]["completed"] is False
    assert report["evidence"]["status"] == "INVALID"
    assert "cleanup" in report["evidence"]["invalid_reasons"][0]


def test_measurement_integrity_rejects_empty_query_or_correlation_observation(tmp_path, monkeypatch):
    cfg_path = _sqlite_cfg(tmp_path)
    original_query = qr._query_benchmark

    def empty_query(conn, marker, iterations):
        result = original_query(conn, marker, iterations)
        result["rows_observed"] = 0
        result["nonempty_iterations"] = 0
        return result

    monkeypatch.setattr(qr, "_query_benchmark", empty_query)
    report = qr.run(
        cfg_path, events=20, batch_size=10, parser_events=20,
        query_iterations=2, correlation_iterations=1, thresholds={},
    )
    assert report["measurement_integrity"]["query_observed_benchmark_rows"] is False
    assert report["measurement_integrity"]["valid"] is False
    assert report["evidence"]["status"] == "INVALID"
    assert report["cleanup"]["completed"] is True


def test_invalid_run_parameters_and_thresholds_fail_closed():
    with pytest.raises(RuntimeError, match="batch_size"):
        qr._validate_run_inputs(
            events=1, batch_size=0, query_iterations=1, correlation_iterations=1,
            duration_seconds=0, parser_events=1, thresholds={},
        )
    with pytest.raises(RuntimeError, match="threshold"):
        qr._validate_run_inputs(
            events=1, batch_size=1, query_iterations=1, correlation_iterations=1,
            duration_seconds=0, parser_events=1, thresholds={"min_ingest_eps": float("nan")},
        )


def test_benchmark_exception_attempts_cleanup_before_propagating(tmp_path, monkeypatch):
    cfg_path = _sqlite_cfg(tmp_path)
    called = {"cleanup": 0}
    real_cleanup = qr._cleanup

    def tracking_cleanup(conn, marker):
        called["cleanup"] += 1
        return real_cleanup(conn, marker)

    def explode_query(conn, marker, iterations):
        raise RuntimeError("simulated query failure")

    monkeypatch.setattr(qr, "_cleanup", tracking_cleanup)
    monkeypatch.setattr(qr, "_query_benchmark", explode_query)
    with pytest.raises(RuntimeError, match="simulated query failure"):
        qr.run(
            cfg_path, events=20, batch_size=10, parser_events=20,
            query_iterations=2, correlation_iterations=1, thresholds={},
        )
    assert called["cleanup"] == 1
    conn = db.connect(db.load_config(str(cfg_path)))
    try:
        assert conn.execute(
            "SELECT COUNT(*) AS n FROM logs WHERE app_name LIKE 'perf-qualification-%'"
        ).fetchone()["n"] == 0
    finally:
        conn.close()

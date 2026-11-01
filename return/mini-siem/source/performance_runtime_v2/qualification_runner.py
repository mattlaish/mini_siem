#!/usr/bin/env python3
"""Measured mini-SIEM performance qualification harness.

This runner exercises the real parser, Storage batch ingest, database query and
correlation paths.  It records parser/ingest EPS, query/correlation latency,
RSS/storage growth and PostgreSQL connection count when applicable.  It is
safe-by-default: database writes require a qualification-looking target name or
an explicit --allow-production-target acknowledgement.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db
from correlations import run_correlation
from listener import Storage, parse_syslog

QUALIFICATION_TOKENS = ("bench", "benchmark", "perf", "qual", "test", "staging", "stage", "dev")
LATENCY_SAMPLE_CAP = 50000


def _percentile(samples: list[float], percentile: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    if len(ordered) == 1:
        return float(ordered[0])
    pos = (len(ordered) - 1) * percentile
    lo = math.floor(pos); hi = math.ceil(pos)
    if lo == hi:
        return float(ordered[lo])
    frac = pos - lo
    return float(ordered[lo] * (1 - frac) + ordered[hi] * frac)


def _latency_summary(samples_ms: list[float]) -> dict:
    if not samples_ms:
        return {"count": 0, "min_ms": 0.0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}
    return {
        "count": len(samples_ms),
        "min_ms": round(min(samples_ms), 3),
        "mean_ms": round(statistics.fmean(samples_ms), 3),
        "p50_ms": round(_percentile(samples_ms, 0.50), 3),
        "p95_ms": round(_percentile(samples_ms, 0.95), 3),
        "p99_ms": round(_percentile(samples_ms, 0.99), 3),
        "max_ms": round(max(samples_ms), 3),
    }




class _LatencyReservoir:
    """Bounded latency sampler for long-running qualification.

    Exact count/min/max/mean are retained for every observation while percentile
    samples use deterministic reservoir sampling.  This prevents a 24h/72h run
    from turning the qualification harness itself into an unbounded RSS source.
    """

    def __init__(self, cap: int = LATENCY_SAMPLE_CAP):
        self.cap = max(1, int(cap))
        self.count = 0
        self.total = 0.0
        self.minimum = None
        self.maximum = None
        self.samples: list[float] = []
        self._rng = random.Random(0x5A17C0DE)

    def add(self, value: float) -> None:
        value = float(value)
        self.count += 1
        self.total += value
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)
        if len(self.samples) < self.cap:
            self.samples.append(value)
            return
        slot = self._rng.randrange(self.count)
        if slot < self.cap:
            self.samples[slot] = value

    def summary(self) -> dict:
        if self.count == 0:
            out = _latency_summary([])
            out.update({"sample_count": 0, "sample_cap": self.cap, "percentiles_approximate": False})
            return out
        ordered = sorted(self.samples)
        return {
            "count": self.count,
            "sample_count": len(ordered),
            "sample_cap": self.cap,
            "percentiles_approximate": self.count > len(ordered),
            "min_ms": round(float(self.minimum), 3),
            "mean_ms": round(self.total / self.count, 3),
            "p50_ms": round(_percentile(ordered, 0.50), 3),
            "p95_ms": round(_percentile(ordered, 0.95), 3),
            "p99_ms": round(_percentile(ordered, 0.99), 3),
            "max_ms": round(float(self.maximum), 3),
        }


def _rss_mb() -> float:
    status = Path("/proc/self/status")
    if status.is_file():
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                return round(float(line.split()[1]) / 1024.0, 3)
    try:
        import resource
        value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        if sys.platform == "darwin":
            value /= 1024.0 * 1024.0
        else:
            value /= 1024.0
        return round(value, 3)
    except Exception:
        return 0.0


def _config(config_path: Path, identity: str | None = None) -> dict:
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    pb = raw.get("postgres_privilege_boundary") or {}
    if raw.get("backend") == "postgres" and pb.get("enabled") and identity:
        filename = {
            "listener": "db-listener-credentials.json",
            "dashboard": "db-dashboard-credentials.json",
            "maintenance": "db-maintenance-credentials.json",
        }[identity]
        cred = config_path.parent / filename
        if not cred.is_file():
            raise RuntimeError(f"missing {identity} PostgreSQL credential overlay: {cred}")
        return db.load_config(str(config_path), credentials_path=str(cred))
    return db.load_config(str(config_path))


def _target_name(cfg: dict) -> str:
    if cfg.get("backend") == "postgres":
        return str(cfg.get("postgres", {}).get("dbname") or "")
    return Path(str(cfg.get("sqlite", {}).get("path") or "siem.db")).name


def _qualification_name_tokens(name: str) -> set[str]:
    return {part for part in re.split(r"[^a-z0-9]+", str(name).lower()) if part}


def _assert_safe_target(cfg: dict, allow_production_target: bool) -> None:
    if allow_production_target:
        return
    name = _target_name(cfg).lower()
    tokens = _qualification_name_tokens(name)
    if not tokens.intersection(QUALIFICATION_TOKENS):
        raise RuntimeError(
            f"refusing write benchmark against target {name!r}; use a dedicated qualification database "
            "whose name contains a qualification token as a separate segment "
            f"({', '.join(QUALIFICATION_TOKENS)}) or pass --allow-production-target explicitly"
        )


def _storage_bytes(conn, cfg: dict) -> int:
    if cfg.get("backend") == "postgres":
        row = conn.execute("SELECT pg_database_size(current_database()) AS n").fetchone()
        return int(row["n"] if hasattr(row, "keys") else row[0])
    # SQLite runs in WAL mode.  Counting only the main database file can report
    # near-zero growth while newly ingested pages are still resident in -wal.
    # -shm is coordination state rather than durable database content, so it is
    # intentionally excluded from the storage-growth measurement.
    path = Path(str(cfg.get("sqlite", {}).get("path") or "siem.db"))
    total = 0
    for candidate in (path, Path(str(path) + "-wal")):
        try:
            total += candidate.stat().st_size
        except FileNotFoundError:
            pass
    return total


def _postgres_connections(conn, cfg: dict) -> int | None:
    if cfg.get("backend") != "postgres":
        return None
    row = conn.execute("SELECT COUNT(*) AS n FROM pg_stat_activity WHERE datname=current_database()").fetchone()
    return int(row["n"] if hasattr(row, "keys") else row[0])


def _raw_event(seq: int, marker: str) -> str:
    octet = seq % 250 + 1
    return f"<134>Sep 23 12:00:00 perfhost perfapp: perfqual marker={marker} seq={seq} user=user{seq % 100} src=198.51.100.{octet}"


def _event(seq: int, marker: str) -> tuple[dict, dict]:
    octet = seq % 250 + 1
    event = parse_syslog(_raw_event(seq, marker), f"198.51.100.{octet}")
    event["app_name"] = marker
    fields = {"benchmark_marker": marker, "sequence": str(seq), "user": f"user{seq % 100}"}
    return event, fields


def _parser_benchmark(events: int, marker: str) -> dict:
    count = max(1, int(events))
    started = time.perf_counter()
    for i in range(count):
        parse_syslog(_raw_event(i, marker), f"198.51.100.{i % 250 + 1}")
    elapsed = max(time.perf_counter() - started, 1e-9)
    return {"events": count, "duration_seconds": round(elapsed, 6), "events_per_second": round(count / elapsed, 2)}


def _ingest(storage: Storage, *, marker: str, events: int, batch_size: int, duration_seconds: float) -> dict:
    total = 0
    commit_latency = _LatencyReservoir()
    started = time.perf_counter()
    seq = 0
    target_events = max(1, int(events))
    while True:
        if duration_seconds > 0:
            if total > 0 and time.perf_counter() - started >= duration_seconds:
                break
        elif total >= target_events:
            break
        count = max(1, int(batch_size))
        if duration_seconds <= 0:
            count = min(count, target_events - total)
        batch = [_event(seq + i, marker) for i in range(count)]
        ids, elapsed_ms = storage.insert_log_batch(batch)
        if len(ids) != count:
            raise RuntimeError(
                f"batch ingest inserted {len(ids)} rows for {count} submitted events; "
                "qualification measurement is invalid"
            )
        total += len(ids)
        seq += count
        commit_latency.add(float(elapsed_ms))
    elapsed = max(time.perf_counter() - started, 1e-9)
    return {
        "events": total,
        "duration_seconds": round(elapsed, 6),
        "events_per_second": round(total / elapsed, 2),
        "batch_commit_latency": commit_latency.summary(),
    }


def _query_benchmark(conn, marker: str, iterations: int) -> dict:
    samples: list[float] = []
    query_count = max(1, int(iterations))
    rows_observed = 0
    nonempty_iterations = 0
    for i in range(query_count):
        started = time.perf_counter()
        if i % 2:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM logs WHERE app_name=? AND source_ip=?",
                (marker, f"198.51.100.{i % 250 + 1}"),
            ).fetchone()
            observed = int(row["n"] if hasattr(row, "keys") else row[0])
        else:
            observed = len(conn.execute(
                "SELECT id,received_at,severity,message FROM logs WHERE app_name=? ORDER BY id DESC LIMIT 100",
                (marker,),
            ).fetchall())
        rows_observed += observed
        if observed > 0:
            nonempty_iterations += 1
        samples.append((time.perf_counter() - started) * 1000.0)
    result = _latency_summary(samples)
    result.update({"rows_observed": rows_observed, "nonempty_iterations": nonempty_iterations})
    return result


def _correlation_benchmark(conn, marker: str, iterations: int) -> dict:
    samples: list[float] = []
    groups = 0
    groups_observed = 0
    for _ in range(max(1, int(iterations))):
        started = time.perf_counter()
        out = run_correlation(conn, {
            "type": "threshold",
            "pattern": r"perfqual",
            "group_by": "source_ip",
            "threshold": 1,
            "window_minutes": 60,
        })
        samples.append((time.perf_counter() - started) * 1000.0)
        groups = int(out.get("group_count") or 0)
        groups_observed += groups
    result = _latency_summary(samples)
    result["last_group_count"] = groups
    result["groups_observed"] = groups_observed
    return result


def _cleanup(conn, marker: str) -> dict:
    removed = 0
    try:
        conn.execute("DELETE FROM security_events WHERE legacy_log_id IN (SELECT id FROM logs WHERE app_name=?)", (marker,))
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
    try:
        conn.execute("DELETE FROM log_fields WHERE log_id IN (SELECT id FROM logs WHERE app_name=?)", (marker,))
        cur = conn.execute("DELETE FROM logs WHERE app_name=?", (marker,))
        removed = int(getattr(cur, "rowcount", 0) or 0)
        conn.commit()
        row = conn.execute("SELECT COUNT(*) AS n FROM logs WHERE app_name=?", (marker,)).fetchone()
        remaining = int(row["n"] if hasattr(row, "keys") else row[0])
        if remaining:
            raise RuntimeError(f"cleanup left {remaining} benchmark log rows behind")
    except Exception:
        conn.rollback()
        raise
    return {"removed_logs": removed, "remaining_logs": 0}


def _validate_run_inputs(*, events: int, batch_size: int, query_iterations: int,
                         correlation_iterations: int, duration_seconds: float,
                         parser_events: int, thresholds: dict) -> None:
    integer_values = {
        "events": events,
        "batch_size": batch_size,
        "query_iterations": query_iterations,
        "correlation_iterations": correlation_iterations,
        "parser_events": parser_events,
    }
    for name, value in integer_values.items():
        if int(value) <= 0:
            raise RuntimeError(f"{name} must be greater than zero")
    if not math.isfinite(float(duration_seconds)) or float(duration_seconds) < 0:
        raise RuntimeError("duration_seconds must be a finite value greater than or equal to zero")
    for name, value in (thresholds or {}).items():
        numeric = float(value or 0)
        if not math.isfinite(numeric) or numeric < 0:
            raise RuntimeError(f"threshold {name} must be a finite value greater than or equal to zero")


def _marker_count(conn, marker: str) -> int:
    row = conn.execute("SELECT COUNT(*) AS n FROM logs WHERE app_name=?", (marker,)).fetchone()
    return int(row["n"] if hasattr(row, "keys") else row[0])


def _evaluate(measurements: dict, thresholds: dict) -> dict:
    checks = []
    mapping = [
        ("min_parser_eps", measurements["parser"]["events_per_second"], ">="),
        ("min_ingest_eps", measurements["ingest"]["events_per_second"], ">="),
        ("max_query_p95_ms", measurements["query"]["p95_ms"], "<="),
        ("max_correlation_p95_ms", measurements["correlation"]["p95_ms"], "<="),
        ("max_rss_growth_mb", measurements["resources"]["rss_growth_mb"], "<="),
        ("max_storage_growth_mb", measurements["resources"]["storage_growth_mb"], "<="),
    ]
    for name, actual, operator in mapping:
        limit = float(thresholds.get(name) or 0)
        if limit <= 0:
            continue
        passed = actual >= limit if operator == ">=" else actual <= limit
        checks.append({"name": name, "actual": actual, "operator": operator, "threshold": limit, "passed": bool(passed)})
    if not checks:
        status = "MEASURED_NO_THRESHOLDS"
    else:
        status = "PASS" if all(c["passed"] for c in checks) else "FAIL"
    return {"status": status, "checks": checks}


def run(config_path: Path, *, events: int = 5000, batch_size: int = 250,
        query_iterations: int = 25, correlation_iterations: int = 5,
        duration_seconds: float = 0.0, parser_events: int = 10000,
        allow_production_target: bool = False, cleanup: bool = True,
        thresholds: dict | None = None) -> dict:
    thresholds = thresholds or {}
    _validate_run_inputs(
        events=events, batch_size=batch_size, query_iterations=query_iterations,
        correlation_iterations=correlation_iterations, duration_seconds=duration_seconds,
        parser_events=parser_events, thresholds=thresholds,
    )
    listener_cfg = _config(config_path, "listener")
    query_cfg = _config(config_path, "dashboard")
    _assert_safe_target(listener_cfg, allow_production_target)
    marker = f"perf-qualification-{uuid.uuid4().hex[:12]}"
    started_at = datetime.now(timezone.utc)
    rss_before = _rss_mb()

    storage = Storage(db_config=listener_cfg)
    query_conn = db.connect(query_cfg)
    maintenance_conn = None
    cleanup_result = {"requested": bool(cleanup), "completed": False}
    try:
        storage_before = _storage_bytes(query_conn, query_cfg)
        connections_before = _postgres_connections(query_conn, query_cfg)
        parser = _parser_benchmark(parser_events, marker)
        ingest = _ingest(storage, marker=marker, events=events, batch_size=batch_size, duration_seconds=duration_seconds)
        visible_marker_rows = _marker_count(query_conn, marker)
        query = _query_benchmark(query_conn, marker, query_iterations)
        correlation = _correlation_benchmark(query_conn, marker, correlation_iterations)
        storage_after = _storage_bytes(query_conn, query_cfg)
        connections_after = _postgres_connections(query_conn, query_cfg)
        rss_after = _rss_mb()

        measurements = {
            "parser": parser,
            "ingest": ingest,
            "query": query,
            "correlation": correlation,
            "resources": {
                "rss_before_mb": rss_before,
                "rss_after_mb": rss_after,
                "rss_growth_mb": round(max(0.0, rss_after - rss_before), 3),
                "storage_before_bytes": storage_before,
                "storage_after_bytes": storage_after,
                "storage_growth_mb": round(max(0, storage_after - storage_before) / (1024.0 * 1024.0), 3),
                "postgres_connections_before": connections_before,
                "postgres_connections_after": connections_after,
            },
        }
        measurement_integrity = {
            "marker_row_count_matches_ingest": visible_marker_rows == ingest["events"],
            "visible_marker_rows": visible_marker_rows,
            "expected_marker_rows": ingest["events"],
            "query_observed_benchmark_rows": query.get("rows_observed", 0) > 0,
            "correlation_observed_benchmark_groups": correlation.get("groups_observed", 0) > 0,
        }
        measurement_integrity["valid"] = all(
            value for key, value in measurement_integrity.items()
            if key not in {"visible_marker_rows", "expected_marker_rows", "valid"}
        )
        evaluation = _evaluate(measurements, thresholds)

        if cleanup:
            try:
                maintenance_cfg = _config(config_path, "maintenance")
                maintenance_conn = db.connect(maintenance_cfg)
                cleanup_result.update(_cleanup(maintenance_conn, marker))
                cleanup_result["completed"] = True
            except Exception as exc:
                cleanup_result["error"] = f"{type(exc).__name__}: {exc}"

        evidence_valid = measurement_integrity["valid"] and (not cleanup or cleanup_result["completed"])
        invalid_reasons = []
        if not measurement_integrity["valid"]:
            invalid_reasons.append("benchmark rows were not observed consistently across measurement paths")
        if cleanup and not cleanup_result["completed"]:
            invalid_reasons.append("requested benchmark cleanup did not complete")

        return {
            "format": "mini-siem-performance-qualification-v1",
            "started_at_utc": started_at.isoformat(),
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
            "backend": listener_cfg.get("backend"),
            "target": _target_name(listener_cfg),
            "marker": marker,
            "requested": {
                "events": int(events), "batch_size": int(batch_size),
                "duration_seconds": float(duration_seconds), "parser_events": int(parser_events),
                "query_iterations": int(query_iterations), "correlation_iterations": int(correlation_iterations),
            },
            "measurements": measurements,
            "measurement_integrity": measurement_integrity,
            "thresholds": thresholds,
            "evaluation": evaluation,
            "evidence": {
                "status": "VALID" if evidence_valid else "INVALID",
                "invalid_reasons": invalid_reasons,
            },
            "cleanup": cleanup_result,
            "production_target_acknowledged": bool(allow_production_target),
        }
    except Exception:
        # A failed benchmark must not silently leave its synthetic rows behind.
        # Best-effort cleanup is attempted before propagating the original error.
        if cleanup and not cleanup_result.get("completed"):
            try:
                maintenance_cfg = _config(config_path, "maintenance")
                maintenance_conn = db.connect(maintenance_cfg)
                cleanup_result.update(_cleanup(maintenance_conn, marker))
                cleanup_result["completed"] = True
            except Exception:
                pass
        raise
    finally:
        if maintenance_conn is not None:
            maintenance_conn.close()
        query_conn.close()
        storage.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Measured mini-SIEM performance qualification")
    ap.add_argument("--db-config", default=str(ROOT / "db-config.json"))
    ap.add_argument("--events", type=int, default=5000)
    ap.add_argument("--batch-size", type=int, default=250)
    ap.add_argument("--parser-events", type=int, default=10000)
    ap.add_argument("--query-iterations", type=int, default=25)
    ap.add_argument("--correlation-iterations", type=int, default=5)
    ap.add_argument("--duration-seconds", type=float, default=0.0)
    ap.add_argument("--sustained-hours", type=float, default=0.0,
                    help="run ingest continuously for N hours; overrides --duration-seconds")
    ap.add_argument("--allow-production-target", action="store_true")
    ap.add_argument("--no-cleanup", action="store_true")
    ap.add_argument("--output", default="")
    ap.add_argument("--min-parser-eps", type=float, default=0.0)
    ap.add_argument("--min-ingest-eps", type=float, default=0.0)
    ap.add_argument("--max-query-p95-ms", type=float, default=0.0)
    ap.add_argument("--max-correlation-p95-ms", type=float, default=0.0)
    ap.add_argument("--max-rss-growth-mb", type=float, default=0.0)
    ap.add_argument("--max-storage-growth-mb", type=float, default=0.0)
    args = ap.parse_args()
    duration = args.sustained_hours * 3600.0 if args.sustained_hours > 0 else args.duration_seconds
    thresholds = {
        "min_parser_eps": args.min_parser_eps,
        "min_ingest_eps": args.min_ingest_eps,
        "max_query_p95_ms": args.max_query_p95_ms,
        "max_correlation_p95_ms": args.max_correlation_p95_ms,
        "max_rss_growth_mb": args.max_rss_growth_mb,
        "max_storage_growth_mb": args.max_storage_growth_mb,
    }
    try:
        report = run(
            Path(args.db_config).resolve(), events=args.events, batch_size=args.batch_size,
            parser_events=args.parser_events, query_iterations=args.query_iterations,
            correlation_iterations=args.correlation_iterations, duration_seconds=duration,
            allow_production_target=args.allow_production_target, cleanup=not args.no_cleanup,
            thresholds=thresholds,
        )
        text = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
        print(text, end="")
        if report["evaluation"]["status"] == "FAIL" or report["evidence"]["status"] != "VALID":
            return 1
        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

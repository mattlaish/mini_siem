"""
mini-SIEM lightweight performance telemetry
===========================================
Process-local, bounded latency histograms for dashboard query classes plus
health-state derivation from ingest backpressure and query latency. No query
text, filter values, usernames, IPs, or other potentially sensitive values are
stored in telemetry.
"""

from collections import deque
from datetime import datetime, timezone
import threading
import time


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _percentile(values, pct):
    if not values:
        return 0.0
    data = sorted(float(v) for v in values)
    if len(data) == 1:
        return data[0]
    pos = (len(data) - 1) * float(pct)
    lo = int(pos)
    hi = min(lo + 1, len(data) - 1)
    frac = pos - lo
    return data[lo] * (1.0 - frac) + data[hi] * frac


class QueryTelemetry:
    """Bounded in-memory latency tracking by coarse query class.

    It intentionally records only class names and timings. This keeps slow-query
    diagnostics useful without duplicating SIEM search terms into application
    logs or runtime state.
    """

    def __init__(self, max_samples=512, slow_ms=250):
        self.max_samples = max(32, min(int(max_samples), 4096))
        self.slow_ms = max(1.0, float(slow_ms))
        self._lock = threading.Lock()
        self._samples = {}
        self._counts = {}
        self._slow_counts = {}
        self._last_slow_at = {}
        self._last_slow_log = {}

    def record(self, query_class, duration_ms):
        name = str(query_class or "other")[:64]
        ms = max(0.0, float(duration_ms))
        should_log = False
        now_mono = time.monotonic()
        with self._lock:
            samples = self._samples.setdefault(name, deque(maxlen=self.max_samples))
            samples.append(ms)
            self._counts[name] = self._counts.get(name, 0) + 1
            if ms >= self.slow_ms:
                self._slow_counts[name] = self._slow_counts.get(name, 0) + 1
                self._last_slow_at[name] = _utc_now_iso()
                # Rate-limit slow-query stdout diagnostics to one line per
                # class per 30 seconds. The line contains no query/filter text.
                last = self._last_slow_log.get(name, 0.0)
                if now_mono - last >= 30.0:
                    self._last_slow_log[name] = now_mono
                    should_log = True
        if should_log:
            print(f"[slow-query] class={name} duration_ms={ms:.1f}")

    def snapshot(self):
        with self._lock:
            out = {}
            for name, samples in self._samples.items():
                vals = list(samples)
                out[name] = {
                    "count": int(self._counts.get(name, 0)),
                    "samples": len(vals),
                    "avg_ms": round(sum(vals) / len(vals), 3) if vals else 0.0,
                    "p50_ms": round(_percentile(vals, 0.50), 3),
                    "p95_ms": round(_percentile(vals, 0.95), 3),
                    "max_ms": round(max(vals), 3) if vals else 0.0,
                    "slow_count": int(self._slow_counts.get(name, 0)),
                    "last_slow_at": self._last_slow_at.get(name),
                }
            return out


def derive_operational_health(ingest, query_stats, config):
    """Return HEALTHY / DEGRADED / OVERLOADED with non-secret reasons."""
    cfg = (config or {}).get("overload") or {}
    warn_pct = max(1.0, min(float(cfg.get("queue_warn_percent", 80)), 100.0))
    overload_pct = max(warn_pct, min(float(cfg.get("queue_overload_percent", 95)), 100.0))
    commit_warn = max(1.0, float(cfg.get("commit_p95_warn_ms", 50)))
    query_warn = max(1.0, float(cfg.get("query_p95_warn_ms", 250)))
    stale_s = max(5.0, float(cfg.get("telemetry_stale_seconds", 30)))

    reasons_degraded = []
    reasons_overloaded = []
    signals = []
    ingest = ingest or {}

    def queue_check(label, depth_key, capacity_key):
        try:
            depth = float(ingest.get(depth_key) or 0)
            cap = float(ingest.get(capacity_key) or 0)
        except (TypeError, ValueError):
            return
        if cap <= 0:
            return
        pct = depth * 100.0 / cap
        state = "OK"
        if pct >= overload_pct:
            state = "OVERLOADED"
            reasons_overloaded.append(f"{label} queue {pct:.0f}% full")
        elif pct >= warn_pct:
            state = "DEGRADED"
            reasons_degraded.append(f"{label} queue {pct:.0f}% full")
        signals.append({"name": label, "kind": "queue", "state": state,
                        "depth": int(depth), "capacity": int(cap),
                        "percent": round(pct, 1)})

    queue_check("ingest", "queue_depth", "queue_capacity")
    queue_check("DB writer", "db_queue_depth", "db_queue_capacity")
    queue_check("post-processing", "post_queue_depth", "post_queue_capacity")
    queue_check("forwarder", "forward_queue_depth", "forward_queue_capacity")

    # Prefer interval deltas published by Phase 5 so one historical drop does
    # not leave the system permanently OVERLOADED. Cumulative counters remain
    # available in the UI for incident history.
    dropped = (int(ingest.get("interval_dropped") or 0)
               + int(ingest.get("interval_db_queue_dropped") or 0)
               + int(ingest.get("interval_forward_dropped") or 0))
    failures = int(ingest.get("interval_failed") or 0) + int(ingest.get("interval_db_write_failed") or 0)
    if dropped > 0:
        reasons_overloaded.append(f"{dropped} ingest/DB queue drops observed")
    if failures > 0:
        reasons_degraded.append(f"{failures} processing/DB failures observed")

    try:
        commit_p95 = float(ingest.get("db_commit_ms_p95") or 0)
        if commit_p95 >= commit_warn:
            reasons_degraded.append(f"DB commit p95 {commit_p95:.1f} ms")
    except (TypeError, ValueError):
        pass

    worst_query = None
    for name, stats in (query_stats or {}).items():
        try:
            p95 = float(stats.get("p95_ms") or 0)
        except (TypeError, ValueError):
            continue
        if worst_query is None or p95 > worst_query[1]:
            worst_query = (name, p95)
    if worst_query and worst_query[1] >= query_warn:
        reasons_degraded.append(f"query {worst_query[0]} p95 {worst_query[1]:.1f} ms")

    published = ingest.get("published_at")
    if published:
        try:
            dt = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds()
            if age > stale_s:
                reasons_degraded.append(f"ingest telemetry stale ({int(age)}s)")
        except Exception:
            pass

    thresholds = {
        "queue_warn_percent": warn_pct,
        "queue_overload_percent": overload_pct,
        "commit_p95_warn_ms": commit_warn,
        "query_p95_warn_ms": query_warn,
        "telemetry_stale_seconds": stale_s,
    }
    if reasons_overloaded:
        return {"state": "OVERLOADED", "reasons": reasons_overloaded + reasons_degraded,
                "signals": signals, "thresholds": thresholds}
    if reasons_degraded:
        return {"state": "DEGRADED", "reasons": reasons_degraded,
                "signals": signals, "thresholds": thresholds}
    return {"state": "HEALTHY", "reasons": [], "signals": signals,
            "thresholds": thresholds}

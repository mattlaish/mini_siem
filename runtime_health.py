"""Runtime health evidence helpers for mini-SIEM.

The listener and dashboard are separate systemd processes, so operational
health must not rely only on in-process globals.  The listener publishes a
small heartbeat into ``runtime_stats``; the dashboard reads that heartbeat and
marks it stale if updates stop.  No privileged service-control action lives
here.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import time


@dataclass
class RuntimeHealth:
    database: str = "UNKNOWN"
    listener: str = "UNKNOWN"
    ingest: str = "UNKNOWN"
    worker: str = "UNKNOWN"
    uptime_seconds: float = 0.0
    queue_depth: int = 0
    processed_events: int = 0
    failed_events: int = 0
    dropped_events: int = 0
    dropped_udp: int = 0
    last_event_at: str | None = None
    heartbeat_at: str | None = None
    detail: str = ""

    def snapshot(self):
        return asdict(self)


_started_at = time.time()
_health = RuntimeHealth()


def get_runtime_health():
    """Backward-compatible in-process snapshot used by unit tests/callers."""
    _health.uptime_seconds = max(0.0, time.time() - _started_at)
    return _health.snapshot()


def update_runtime_health(**kwargs):
    for key, value in kwargs.items():
        if hasattr(_health, key):
            setattr(_health, key, value)
    return get_runtime_health()


def _parse_iso(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def listener_snapshot_from_db(conn, stale_after_seconds=10):
    """Read the cross-process listener heartbeat from runtime_stats.

    Missing/stale heartbeat is a status signal only; the function never starts,
    stops, or repairs a service.
    """
    import db as dbmod

    out = RuntimeHealth(database="READY").snapshot()
    out["dashboard"] = "RUNNING"
    try:
        row = dbmod.read_runtime_stats(conn, ["listener_health"]).get("listener_health")
    except Exception as exc:
        out.update({
            "database": "FAILED",
            "listener": "UNKNOWN",
            "ingest": "UNKNOWN",
            "worker": "UNKNOWN",
            "detail": f"runtime health unavailable: {type(exc).__name__}",
        })
        return out
    if not row or not row.get("value_text"):
        out.update({
            "listener": "UNKNOWN",
            "ingest": "UNKNOWN",
            "worker": "UNKNOWN",
            "detail": "listener heartbeat has not been recorded",
        })
        return out
    try:
        payload = json.loads(row.get("value_text") or "{}")
        if not isinstance(payload, dict):
            raise ValueError("listener health is not an object")
    except Exception:
        out.update({
            "listener": "UNKNOWN",
            "ingest": "UNKNOWN",
            "worker": "UNKNOWN",
            "detail": "listener heartbeat payload is invalid",
        })
        return out

    for key in (
        "listener", "ingest", "worker", "uptime_seconds", "queue_depth",
        "processed_events", "failed_events", "dropped_events", "dropped_udp",
        "last_event_at", "detail", "sources",
    ):
        if key in payload:
            out[key] = payload[key]
    heartbeat_at = row.get("updated_at") or payload.get("heartbeat_at")
    out["heartbeat_at"] = heartbeat_at
    dt = _parse_iso(heartbeat_at)
    if dt is None:
        out.update({"listener": "UNKNOWN", "ingest": "UNKNOWN", "worker": "UNKNOWN"})
        out["detail"] = "listener heartbeat timestamp is invalid"
        return out
    age = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds())
    out["heartbeat_age_seconds"] = round(age, 1)
    if age > max(2, int(stale_after_seconds)):
        out["listener"] = "STALE"
        out["ingest"] = "STALE"
        out["worker"] = "STALE"
        out["detail"] = f"listener heartbeat is {round(age, 1)}s old"
    return out

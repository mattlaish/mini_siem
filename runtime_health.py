"""Runtime health evidence helpers for mini-SIEM.

This module provides lightweight status collection primitives.
It does not replace the existing application runtime.
"""

from dataclasses import dataclass, asdict
import time


@dataclass
class RuntimeHealth:
    database: str = "UNKNOWN"
    listener: str = "UNKNOWN"
    ingest: str = "UNKNOWN"
    worker: str = "UNKNOWN"
    uptime_seconds: float = 0.0
    queue_depth: int = 0
    dropped_events: int = 0
    last_event_timestamp: float | None = None

    def snapshot(self):
        return asdict(self)


_started_at = time.time()
_health = RuntimeHealth()


def get_runtime_health():
    _health.uptime_seconds = max(0.0, time.time() - _started_at)
    return _health.snapshot()


def update_runtime_health(**kwargs):
    for key, value in kwargs.items():
        if hasattr(_health, key):
            setattr(_health, key, value)
    return get_runtime_health()

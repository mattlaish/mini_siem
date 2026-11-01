"""Archive-first evidence lifecycle and conservative online maintenance.

No time-based log deletion lives here. The background worker optionally creates
sealed archive segments through :mod:`archive`; SQLite housekeeping is limited
to non-destructive online operations (PASSIVE checkpoint, incremental free-page
reclamation, PRAGMA optimize, and rate-limited quick_check).
"""

from datetime import datetime, timezone
import json
import os
import threading
import time

import archive as archive_mod
import db as dbmod


def _utc_now():
    return datetime.now(timezone.utc)


def _bounded_int(value, default, lo, hi):
    try:
        return max(lo, min(int(value), hi))
    except (TypeError, ValueError):
        return default


def _maintenance_cfg(config):
    base = {
        "wal_checkpoint_mb": 256,
        "incremental_vacuum_pages": 2000,
        "quick_check_interval_seconds": 86400,
    }
    base.update((config or {}).get("maintenance") or {})
    return base


def _status_write(storage, status):
    payload = json.dumps(status, separators=(",", ":"), sort_keys=True)
    with storage.lock:
        try:
            dbmod.runtime_stat_upsert(
                storage.conn, "maintenance_status", value_text=payload,
                updated_at=_utc_now().isoformat())
            storage.conn.commit()
            storage._pending = 0
            storage._last_commit = time.time()
        except Exception:
            storage.rollback_locked()
            raise


def _pragma_value(row):
    if row is None:
        return None
    if isinstance(row, dict):
        vals = list(row.values())
        return vals[0] if vals else None
    try:
        return row[0]
    except Exception:
        return None


def sqlite_housekeeping_locked(storage, config):
    """Conservative online SQLite housekeeping; caller holds storage.lock."""
    if storage.backend != "sqlite":
        return {"backend": storage.backend}
    cfg = _maintenance_cfg(config)
    sqlite_cfg = (config or {}).get("sqlite") or {}
    path = str(sqlite_cfg.get("path") or "siem.db")
    out = {
        "backend": "sqlite",
        "checkpointed": False,
        "vacuum_pages_requested": 0,
        "quick_check": "not_due",
    }
    try:
        wal_bytes = os.path.getsize(path + "-wal")
    except OSError:
        wal_bytes = 0
    out["wal_bytes"] = wal_bytes
    threshold = _bounded_int(cfg.get("wal_checkpoint_mb"), 256, 1, 16384) * 1024 * 1024
    if wal_bytes >= threshold:
        try:
            row = storage.conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
            out["checkpointed"] = True
            if row is not None:
                out["checkpoint_result"] = list(row)
        except Exception as exc:
            out["checkpoint_error"] = type(exc).__name__

    try:
        auto_vac = int(_pragma_value(storage.conn.execute("PRAGMA auto_vacuum").fetchone()) or 0)
    except Exception:
        auto_vac = 0
    out["auto_vacuum"] = auto_vac
    pages = _bounded_int(cfg.get("incremental_vacuum_pages"), 2000, 0, 100000)
    if auto_vac == 2 and pages > 0:
        allowed = {
            100: "PRAGMA incremental_vacuum(100)",
            500: "PRAGMA incremental_vacuum(500)",
            1000: "PRAGMA incremental_vacuum(1000)",
            2000: "PRAGMA incremental_vacuum(2000)",
            5000: "PRAGMA incremental_vacuum(5000)",
            10000: "PRAGMA incremental_vacuum(10000)",
        }
        chosen = max((n for n in allowed if n <= pages), default=100)
        try:
            storage.conn.execute(allowed[chosen])
            out["vacuum_pages_requested"] = chosen
        except Exception as exc:
            out["vacuum_error"] = type(exc).__name__

    try:
        storage.conn.execute("PRAGMA optimize")
        out["optimized"] = True
    except Exception as exc:
        out["optimize_error"] = type(exc).__name__

    try:
        out["page_count"] = int(_pragma_value(storage.conn.execute("PRAGMA page_count").fetchone()) or 0)
        out["freelist_count"] = int(_pragma_value(storage.conn.execute("PRAGMA freelist_count").fetchone()) or 0)
        page_size = int(_pragma_value(storage.conn.execute("PRAGMA page_size").fetchone()) or 0)
        out["free_bytes_estimate"] = out["freelist_count"] * page_size
    except Exception:
        pass

    interval = _bounded_int(cfg.get("quick_check_interval_seconds"), 86400, 3600, 604800)
    try:
        runtime = dbmod.read_runtime_stats(storage.conn, ["sqlite_quick_check"])
        previous = runtime.get("sqlite_quick_check") or {}
        last_at = previous.get("updated_at")
        due = True
        if last_at:
            try:
                dt = datetime.fromisoformat(str(last_at).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                due = (_utc_now() - dt.astimezone(timezone.utc)).total_seconds() >= interval
            except Exception:
                due = True
        if due:
            row = storage.conn.execute("PRAGMA quick_check(1)").fetchone()
            result = str(_pragma_value(row) or "unknown")
            out["quick_check"] = result
            dbmod.runtime_stat_upsert(
                storage.conn, "sqlite_quick_check", value_text=result,
                updated_at=_utc_now().isoformat())
        elif previous.get("value_text"):
            out["quick_check"] = previous.get("value_text")
    except Exception as exc:
        out["quick_check_error"] = type(exc).__name__
    return out


def run_maintenance_cycle(storage, config, now=None):
    now = now or _utc_now()
    status = {
        "started_at": now.isoformat(),
        "error": "",
        "archive": {},
        "sqlite": {},
    }
    try:
        status["archive"] = archive_mod.run_archive_cycle(storage, config, now=now)
        with storage.lock:
            if getattr(storage, "_pending", 0) > 0:
                storage.commit_locked()
            status["sqlite"] = sqlite_housekeeping_locked(storage, config)
            try:
                oldest = storage.conn.execute(
                    "SELECT received_at FROM logs ORDER BY received_at ASC,id ASC LIMIT 1"
                ).fetchone()
                status["oldest_hot_log"] = oldest["received_at"] if oldest else None
                status["archive_summary"] = archive_mod.archive_summary(storage.conn)
                storage.conn.commit()
                storage._pending = 0
                storage._last_commit = time.time()
            except Exception:
                storage.rollback_locked()
                raise
    except Exception as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
    status["finished_at"] = _utc_now().isoformat()
    acfg = archive_mod._cfg(config)
    interval = _bounded_int(acfg.get("run_interval_seconds"), 3600, 60, 86400)
    status["next_run_at"] = datetime.fromtimestamp(time.time() + interval, tz=timezone.utc).isoformat()
    _status_write(storage, status)
    return status


# Compatibility name for callers/plugins that imported the old Phase-5 symbol.
# It is deliberately non-destructive: no retention deletion occurs.
def run_retention_cycle(storage, config, now=None):
    return run_maintenance_cycle(storage, config, now=now)


class MaintenanceWorker:
    def __init__(self, storage, config):
        self.storage = storage
        self.config = config
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="maintenance")
        self._thread.start()

    def _run(self):
        # Do not archive immediately during startup; let schema/ingest settle.
        if self._stop.wait(5.0):
            return
        while not self._stop.is_set():
            try:
                run_maintenance_cycle(self.storage, self.config)
            except Exception as exc:
                print(f"[maintenance] failed: {type(exc).__name__}: {exc}")
            interval = _bounded_int(
                archive_mod._cfg(self.config).get("run_interval_seconds"),
                3600, 60, 86400)
            if self._stop.wait(interval):
                break

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)

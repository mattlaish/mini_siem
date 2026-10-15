"""Explicitly configured telemetry expectations; silence never proves health."""
import json
import threading
from datetime import datetime, timezone

import detection
from windows_events import timestamp

TELEMETRY_KEY = "detection_telemetry_v1"
SOURCES = {"4688": "security_4688", "1": "sysmon_1", "4104": "powershell_4104"}


class TelemetryMonitor:
    def __init__(self, storage, interval=15):
        self.storage, self.interval = storage, interval
        self._pending = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="detection-health")

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)

    def observe(self, fields):
        source = SOURCES.get(fields.get("event.id"))
        host = fields.get("host.name", "").casefold()
        if not source or not host:
            return
        with self._lock:
            self._pending[host + "|" + source] = {
                "last_received_at": datetime.now(timezone.utc).isoformat(),
                "last_event_time": fields.get("event.time"),
            }
            if len(self._pending) > 1000:
                self._pending.pop(next(iter(self._pending)))

    def tick(self, now=None):
        now = now or datetime.now(timezone.utc)
        with self._lock:
            pending = dict(self._pending)
        with self.storage.lock:
            conn = self.storage.conn
            try:
                config = detection.load_config(conn)
                state = detection._locked_json(conn, TELEMETRY_KEY, {})
                active_keys = set()
                for host in config["hosts"]:
                    if not host.get("telemetry_enabled"):
                        continue
                    for source in host.get("expected_sources", ["security_4688"]):
                        key = host["hostname"].casefold() + "|" + source
                        active_keys.add(key)
                        entry = state.setdefault(key, {"expected_since": now.isoformat()})
                        observation = pending.get(key)
                        if observation and observation["last_received_at"] > entry.get("last_received_at", ""):
                            entry.update(observation)
                        anchor = timestamp(entry.get("last_received_at") or entry["expected_since"])
                        silent = max(0, (now - anchor).total_seconds())
                        status = "silent" if silent > host["max_silence_seconds"] else ("receiving" if entry.get("last_received_at") else "waiting")
                        if status == "silent" and not entry.get("outage_alert_id"):
                            alert_id = conn.insert_returning_id(
                                "INSERT INTO alerts(created_at,rule_name,severity,source_ip,description,log_ids) VALUES(?,?,?,?,?,?)",
                                (now.isoformat(), "telemetry_silence", "warning", host["hostname"],
                                 f"Expected {source} telemetry missing from {host['hostname']}; last receipt/expectation {anchor.isoformat()}; silence {int(silent)}s. Verify NXLog, audit policy and transport delivery.", ""))
                            entry["outage_alert_id"] = alert_id
                        elif status == "receiving":
                            entry.pop("outage_alert_id", None)
                        entry.update(status=status, silence_seconds=round(silent), checked_at=now.isoformat())
                state = {k: v for k, v in state.items() if k in active_keys}
                conn.execute("UPDATE app_config SET value=? WHERE key=?", (json.dumps(state), TELEMETRY_KEY))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        with self._lock:
            for key, value in pending.items():
                if self._pending.get(key) == value:
                    self._pending.pop(key, None)
        return state

    def _run(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:
                print(f"[detection-health] {type(exc).__name__}: {exc}")
            self._stop.wait(self.interval)

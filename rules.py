"""
mini-SIEM rule engine
======================
A small, dependency-free correlation engine. Each rule inspects
incoming log events (already parsed) and maintains its own sliding
window of state; when a threshold is crossed it writes a row to the
`alerts` table via Storage.insert_alert().

Add new rules by subclassing Rule and appending an instance to
RuleEngine.rules in __init__.
"""

import re
import time
import threading
from collections import defaultdict, deque

import severity as severity_mod


IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def extract_ip(text: str):
    m = IP_RE.search(text or "")
    return m.group(1) if m else None


class Rule:
    name = "base_rule"
    severity = "warning"

    def evaluate(self, log_id: int, event: dict, storage):
        """Return None, or (source_ip, description, [log_ids]) if the rule fires."""
        raise NotImplementedError


class ThresholdRule(Rule):
    """Fires when `pattern` matches an event's message `threshold` times
    from the same key (default: source IP extracted from the message,
    falling back to the packet's source_ip) within `window_seconds`."""

    def __init__(self, name, pattern, threshold, window_seconds, severity="warning",
                 description=None, key_from_message=True):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.severity = severity
        self.description = description or f"{name}: {threshold}+ matches in {window_seconds}s"
        self.key_from_message = key_from_message
        self._hits = defaultdict(deque)  # key -> deque[(timestamp, log_id)]

    def evaluate(self, log_id: int, event: dict, storage):
        text = event.get("message", "")
        if not self.pattern.search(text):
            return None

        key = None
        if self.key_from_message:
            key = extract_ip(text)
        key = key or event.get("source_ip") or "unknown"

        now = time.time()
        dq = self._hits[key]
        dq.append((now, log_id))
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        if len(dq) >= self.threshold:
            log_ids = [i for _, i in dq]
            desc = f"{self.description} (source: {key}, {len(dq)} hits)"
            dq.clear()  # avoid re-alerting on every subsequent hit within the same burst
            return key, desc, log_ids
        return None


# Threshold rules are defined once and shared by the live engine and the
# read-only near-miss replay, so "why didn't this fire?" can never drift from
# what actually runs. Thresholds/windows come from the detection config.
THRESHOLD_RULE_SPECS = [
    {"name": "ssh_bruteforce", "pattern": r"failed password|authentication failure|invalid user",
     "description": "Possible SSH brute-force attempt"},
    {"name": "firewall_deny_burst", "pattern": r"\b(deny|denied|block|blocked|drop|dropped)\b",
     "description": "Burst of firewall denies (possible scan)"},
    {"name": "repeated_login_failures", "pattern": r"login failed|access denied|unauthorized",
     "description": "Repeated login/access failures"},
]


def replay_threshold_rules(rows, config_rules, top=10):
    """Replay threshold rules over stored events, oldest first. Read-only.

    ``rows`` yields dicts with received_at (ISO), source_ip and message. Uses
    the same key and sliding-window logic as ThresholdRule, with received_at
    as the clock. Live counters are in memory and reset when the collector
    restarts or a threshold changes, so a replay can show a fire the live
    engine missed across a restart; that difference is itself the answer.
    Returns per-rule peaks per key against the configured threshold.
    """
    from datetime import datetime
    by_id = {r["id"]: r for r in config_rules}
    specs = []
    for spec in THRESHOLD_RULE_SPECS:
        cfg = by_id.get(spec["name"], {})
        specs.append({**spec, "regex": re.compile(spec["pattern"], re.IGNORECASE),
                      "threshold": int(cfg.get("threshold") or 1), "window": int(cfg.get("window_seconds") or 60),
                      "enabled": bool(cfg.get("enabled", True)), "hits": defaultdict(deque), "keys": {}})
    for row in rows:
        text = row.get("message") or ""
        try:
            ts = datetime.fromisoformat(str(row.get("received_at")).replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        for spec in specs:
            if not spec["regex"].search(text):
                continue
            key = extract_ip(text) or row.get("source_ip") or "unknown"
            dq = spec["hits"][key]
            dq.append(ts)
            while dq and dq[0] < ts - spec["window"]:
                dq.popleft()
            stat = spec["keys"].setdefault(key, {"key": key, "matches": 0, "peak": 0, "fires": 0, "last_at": None})
            stat["matches"] += 1
            stat["peak"] = max(stat["peak"], len(dq))
            stat["last_at"] = row.get("received_at")
            if len(dq) >= spec["threshold"]:
                stat["fires"] += 1
                dq.clear()
    out = []
    for spec in specs:
        keys = sorted(spec["keys"].values(), key=lambda k: (k["fires"] > 0, k["peak"], k["last_at"] or ""), reverse=True)
        out.append({"id": spec["name"], "description": spec["description"], "enabled": spec["enabled"],
                    "threshold": spec["threshold"], "window_seconds": spec["window"],
                    "fires": sum(k["fires"] for k in keys), "sources": len(keys), "top": keys[:top]})
    return out


def _is_nxlog_windows_event(event: dict) -> bool:
    """Return True only for the Windows JSON shape emitted by nxlog.conf.

    NXLog sends ``to_json()`` records with EventID plus Security/System
    channel metadata.  Keeping this detector narrow is deliberate: firewall
    syslog/CEF must not inherit the NXLog warning/error trigger policy.
    """
    if (event.get("format") or "").lower() != "json":
        return False
    obj = event.get("_json")
    if not isinstance(obj, dict):
        return False
    eid = obj.get("EventID") or obj.get("event_id") or obj.get("EventId")
    channel = str(obj.get("Channel") or "").strip().lower()
    return eid not in (None, "") and channel in {"security", "system"}


class NxlogSeverityRule(Rule):
    """NXLog-only trigger: warning or more severe Windows events.

    This rule controls only *when* a Windows/NXLog investigation starts.
    Related evidence is gathered separately by ``ai_soc`` across all sources
    and severities after the trigger fires.
    """

    TRIGGER_SEVERITIES = {"emergency", "alert", "critical", "error", "warning"}

    def __init__(self, name="nxlog_severity_event", severity="warning"):
        self.name = name
        self.severity = severity

    def evaluate(self, log_id: int, event: dict, storage):
        if not _is_nxlog_windows_event(event):
            return None
        sev = severity_mod.normalize(event.get("severity"))
        if sev not in self.TRIGGER_SEVERITIES:
            return None
        src = event.get("source_ip") or "unknown"
        desc = f"NXLog Windows {sev} severity event: {event.get('message', '')[:200]}"
        return src, desc, [log_id], sev


class SeverityRule(Rule):
    """Preserve the pre-existing generic critical/alert/emergency trigger.

    NXLog Windows records are excluded here so they have exactly one trigger
    path (``NxlogSeverityRule``).  Non-NXLog sources, including firewall/API
    sources, otherwise retain the original generic high-severity behavior.
    """

    HIGH_SEVERITIES = {"emergency", "alert", "critical"}

    def __init__(self, name="high_severity_event", severity="critical"):
        self.name = name
        self.severity = severity

    def evaluate(self, log_id: int, event: dict, storage):
        if _is_nxlog_windows_event(event):
            return None
        sev = severity_mod.normalize(event.get("severity"))
        if sev in self.HIGH_SEVERITIES:
            src = event.get("source_ip") or "unknown"
            desc = f"Device reported {sev} severity event: {event.get('message', '')[:200]}"
            # Preserve the original generic-rule alert severity contract.
            return src, desc, [log_id]
        return None


class RuleEngine:
    def __init__(self, storage):
        self.storage = storage
        self._lock = threading.RLock()
        self._reload_at = 0
        import detection
        self.config = detection.defaults()
        self._monitor = None
        self._all_events_rules = False
        self.errors = 0
        self.last_error = None
        self._last_error_logged = 0.0
        self.rules = [
            *[ThresholdRule(name=spec["name"], pattern=spec["pattern"],
                            threshold=detection.BUILTINS[spec["name"]]["threshold"],
                            window_seconds=detection.BUILTINS[spec["name"]]["window_seconds"],
                            severity=detection.BUILTINS[spec["name"]]["severity"],
                            description=spec["description"]) for spec in THRESHOLD_RULE_SPECS],
            NxlogSeverityRule(name="nxlog_severity_event", severity="warning"),
            SeverityRule(name="high_severity_event", severity="critical"),
        ]

    def process(self, log_id: int, event: dict, fields: dict | None = None):
        """Evaluate one stored event. Never raises.

        Callers run IOC matching and forwarding after this; a detection
        failure (bad stored config, database error while writing an alert)
        must not silently skip those for every event. Errors are counted,
        logged and the connection is rolled back so the next writer starts
        clean.
        """
        try:
            with self._lock:
                self._reload_config()
                self._process(log_id, event, fields)
        except Exception as exc:  # noqa: BLE001 - isolation boundary
            self._report("process", exc)
            self._rollback()

    def _report(self, where, exc):
        self.errors += 1
        message = f"{type(exc).__name__}: {exc}"
        now = time.monotonic()
        # Log a new error immediately; repeat a persistent one once a minute.
        if message != self.last_error or now - self._last_error_logged >= 60:
            print(f"[detection] {where} failed ({self.errors} total): {message}")
            self._last_error_logged = now
        self.last_error = message

    def _rollback(self):
        try:
            with self.storage.lock:
                self.storage.conn.rollback()
        except Exception:  # noqa: BLE001 - best effort
            pass

    def _reload_config(self):
        if time.monotonic() < self._reload_at or not hasattr(self.storage, "conn"):
            return
        # Whatever happens, do not retry on every event.
        self._reload_at = time.monotonic() + 5
        import detection
        try:
            with self.storage.lock:
                config = detection.load_config(self.storage.conn)
        except Exception as exc:  # noqa: BLE001 - keep the last good config
            self._report("config reload (keeping last good configuration)", exc)
            self._rollback()
            return
        self.config = config
        by_id = {r["id"]: r for r in config["rules"]}
        for rule in self.rules:
            cfg = by_id[rule.name]
            rule.severity = cfg["severity"]
            if isinstance(rule, ThresholdRule):
                if (rule.threshold, rule.window_seconds) != (cfg["threshold"], cfg["window_seconds"]):
                    rule._hits.clear()
                rule.threshold, rule.window_seconds = cfg["threshold"], cfg["window_seconds"]
        self._all_events_rules = any(r["enabled"] and r["kind"] == "match" and r.get("scope", "windows") == "all"
                                     for r in config["rules"])

    def start_monitor(self):
        if self._monitor is None:
            from detection_runtime import TelemetryMonitor
            self._monitor = TelemetryMonitor(self.storage)
            self._monitor.start()

    def stop_monitor(self):
        if self._monitor:
            self._monitor.stop()

    def _process(self, log_id, event, fields=None):
        import detection
        from datetime import datetime, timezone
        from windows_events import normalize_windows, resolve_host_time, timestamp
        normalize_windows(event)
        normalized = resolve_host_time(event, self.config)
        if self._monitor and normalized:
            self._monitor.observe(normalized)
        enabled = {r["id"] for r in self.config["rules"] if r["enabled"]}
        for rule in self.rules:
            if rule.name not in enabled:
                continue
            if normalized:
                host = detection.profile_for(self.config, normalized)
                dt = timestamp(normalized.get("event.time"), host.get("timezone"))
                if detection.exception_for(self.config, rule.name, normalized, host, dt, datetime.now(timezone.utc)):
                    continue
            result = rule.evaluate(log_id, event, self.storage)
            if result:
                if len(result) == 4:
                    source_ip, description, log_ids, alert_severity = result
                else:
                    source_ip, description, log_ids = result
                    alert_severity = rule.severity
                self.storage.insert_alert(
                    rule_name=rule.name,
                    severity=alert_severity,
                    source_ip=source_ip,
                    description=description,
                    log_ids=log_ids,
                )
                print(f"  [ALERT] {rule.name} ({alert_severity}) — {description}")
        if not normalized and not self._all_events_rules:
            return
        # Windows canonical fields win over the generic/extracted view.
        candidate = {**detection.generic_fields(event, fields), **(normalized or {})}
        result = detection.evaluate(self.config, candidate)
        for finding in result["findings"]:
            with self.storage.lock:
                try:
                    detection.emit(self.storage.conn, finding, log_id, event.get("source_ip", "unknown"))
                except Exception as exc:  # noqa: BLE001 - keep emitting the other findings
                    self.storage.conn.rollback()
                    self._report(f"alert write for {finding['rule_id']}", exc)

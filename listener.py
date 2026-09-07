#!/usr/bin/env python3
"""
mini-SIEM syslog listener
==========================
Receives syslog messages over UDP and/or TCP (default port 514),
parses RFC3164 ("BSD syslog") and RFC5424 formats, stores every
event in SQLite, and runs them through a lightweight correlation
rule engine that raises alerts (see rules.py).

Usage:
    python3 listener.py                       # UDP+TCP on 0.0.0.0:514 (needs root, see README)
    python3 listener.py --port 5514           # unprivileged port, no root needed
    python3 listener.py --protocol udp        # UDP only
    python3 listener.py --db /path/siem.db

Port 514 is a privileged port on Linux/macOS: run with sudo, grant
the interpreter CAP_NET_BIND_SERVICE, or bind an unprivileged port
and forward 514 -> it. Details in README.md.
"""

import argparse
import json
import queue
from collections import deque
import re
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone

from forwarder import ForwarderManager

# Source profiles (data-driven JSON field mapping). Refreshed from the DB by
# the storage layer; empty until set, in which case the parser falls back to
# the built-in hardcoded key lists so ingestion always works.
_PROFILES = []
_PROFILES_LOCK = threading.Lock()


def set_profiles(profiles):
    """Install the current source-profile list (called periodically by the
    storage layer so the parser sees UI edits without a restart)."""
    global _PROFILES
    with _PROFILES_LOCK:
        _PROFILES = list(profiles or [])


def _get_profiles():
    with _PROFILES_LOCK:
        return list(_PROFILES)
from rules import RuleEngine
from threatintel import IOCMatcher
from normalize import FieldIndexer, write_fields
import severity as severity_mod
import db as dbmod
from maintenance import MaintenanceWorker

# --------------------------------------------------------------------------
# Syslog parsing
# --------------------------------------------------------------------------

# RFC3164:  <PRI>Mon dd hh:mm:ss hostname tag: message
RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<hostname>\S+)\s"
    r"(?P<tag>[^:\s\[]+)(\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$"
)

# RFC5424:  <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s"
    r"(?P<timestamp>\S+)\s"
    r"(?P<hostname>\S+)\s"
    r"(?P<appname>\S+)\s"
    r"(?P<procid>\S+)\s"
    r"(?P<msgid>\S+)\s"
    r"(?P<sd>(-|\[.*?\](?:\[.*?\])*))\s?"
    r"(?P<message>.*)$"
)

FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]
SEVERITIES = [
    "emergency", "alert", "critical", "error",
    "warning", "notice", "informational", "debug",
]


def _try_parse_json_event(raw: str, source_ip: str):
    """If `raw` is a bare JSON object (as sent by NXLog's to_json(), or
    similar structured shippers), parse it into a normalized event whose
    fields come from the JSON keys — instead of letting the syslog parser
    whitespace-split it. Returns None if `raw` is not a JSON object.

    The parsed JSON dict is attached as event['_json'] so the field
    indexer materializes each key as a proper searchable field rather
    than regex-splitting the serialized text."""
    s = raw.lstrip()
    if not s.startswith("{"):
        return None
    try:
        obj = json.loads(s)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None

    def first(*keys, default=""):
        for k in keys:
            if k in obj and obj[k] not in (None, ""):
                return obj[k]
        return default

    # --- Try a data-driven source profile first ---------------------------
    # If a profile matches this event, its key mappings take priority over the
    # built-in hardcoded lists below. Only fields the profile actually resolves
    # override the fallback, so a partial profile still benefits from defaults.
    prof_map = None
    matched_profile = None
    try:
        profs = _get_profiles()
        if profs:
            import profiles as _profiles_mod
            matched_profile = _profiles_mod.match_profile(profs, obj, source_ip)
            if matched_profile:
                prof_map = _profiles_mod.apply_profile(matched_profile, obj)
    except Exception:
        prof_map = None  # never let a bad profile break ingestion

    hostname = str(first("Hostname", "hostname", "host", "Computer", "MachineName",
                          "location", "endpoint_name", "device"))
    app = str(first("SourceName", "Channel", "app", "app_name", "ProviderName",
                    "type", "product",
                    default="eventlog"))
    sev = _json_severity(obj)
    msg = obj.get("Message") or obj.get("message") or obj.get("name") or obj.get("description")
    if not msg:
        eid = first("EventID", "event_id", "EventId")
        task = first("Task", "Category", "OpcodeValue")
        msg = f"EventID={eid}" + (f" Task={task}" if task else "")
    device_ts = str(first("EventTime", "TimeCreated", "timestamp", "@timestamp",
                          "when", "created_at"))

    # profile-resolved values override the fallback where non-empty
    if prof_map:
        hostname = prof_map.get("hostname") or hostname
        app = prof_map.get("app_name") or app
        msg = prof_map.get("message") or msg
        device_ts = prof_map.get("device_timestamp") or device_ts
        if prof_map.get("severity"):
            sev = prof_map["severity"]
        prof_msgid = prof_map.get("msg_id")
    else:
        prof_msgid = None

    event = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "peer_ip": source_ip,
        "format": "json",
        "priority": None,
        "facility": "",
        "severity": sev,
        "device_timestamp": device_ts,
        "hostname": hostname,
        "app_name": app,
        "proc_id": str(first("ProcessID", "ProcessId", "proc_id", default="")),
        "msg_id": str(prof_msgid if prof_msgid else
                      first("EventID", "event_id", "EventId", "type", default="")),
        "message": str(msg),
        "raw": raw,
        "_json": obj,
        "_profile": (matched_profile.get("name") if matched_profile else None),
    }
    return enrich_src_dst(event)


def _json_severity(obj: dict) -> str:
    """Severity for a JSON event. For Windows security events the built-in
    Level/Severity is almost always 4/"INFO" regardless of how serious the
    event is (Windows uses Level to mean 'audit record', not 'danger'), so
    the EventID is the meaningful signal and takes priority. Falls back to
    an explicit severity/level string, then numeric Level, for non-Windows
    JSON that uses those fields meaningfully."""
    # 1. EventID-driven severity for known Windows security events.
    eid = obj.get("EventID") or obj.get("event_id") or obj.get("EventId")
    try:
        eid = int(eid)
    except (TypeError, ValueError):
        eid = None
    if eid is not None:
        sev = _WIN_EVENTID_SEVERITY.get(eid)
        if sev:
            return sev
        # any other Windows security/system event we forward is at least
        # 'notice' — above raw informational noise, so it stands out.
        if "SourceModuleType" in obj or "Channel" in obj or "EventID" in obj:
            return "notice"
    # 2. Explicit severity/level STRING (non-Windows JSON that means it).
    explicit = obj.get("severity") or obj.get("level")
    if isinstance(explicit, str) and explicit.strip():
        name = explicit.strip().lower()
        aliases = {"err": "error", "warn": "warning", "info": "informational",
                   "information": "informational", "crit": "critical",
                   "informational": "informational"}
        return aliases.get(name, name)
    # 3. Numeric Level, last (Windows security events rarely reach here).
    lvl = obj.get("Level")
    if isinstance(lvl, int) or (isinstance(lvl, str) and str(lvl).isdigit()):
        return {1: "critical", 2: "error", 3: "warning",
                4: "informational", 0: "informational"}.get(int(lvl), "informational")
    return "informational"


# EventID -> severity, curated for the security events we forward. Tuned so
# the SIEM surfaces what matters: tampering/lockout/failed-auth as warning+,
# routine-but-notable activity as notice, high-frequency logons as info.
_WIN_EVENTID_SEVERITY = {
    # tampering / high-signal — these should jump out
    1102: "error",     # audit log cleared
    4719: "error",     # audit policy changed
    4740: "warning",   # account locked out
    4625: "warning",   # failed logon
    4648: "warning",   # explicit-credential logon (lateral movement)
    4728: "warning",   # added to global security group
    4732: "warning",   # added to local security group
    4756: "warning",   # added to universal security group
    4720: "warning",   # user account created
    4726: "warning",   # user account deleted
    4724: "warning",   # password reset attempt
    7045: "warning",   # new service installed
    4698: "warning",   # scheduled task created
    # notable but lower — notice
    4722: "notice",    # account enabled
    4725: "notice",    # account disabled
    4723: "notice",    # password change attempt
    4702: "notice",    # scheduled task updated
    4729: "notice",    # removed from global security group
    4733: "notice",    # removed from local security group
    4738: "notice",    # user account changed
    4757: "notice",    # removed from universal security group
    4672: "notice",    # special privileges assigned (admin logon marker)
    7040: "notice",    # service start type changed
    7034: "warning",   # service crashed unexpectedly
    # high-frequency, routine — keep as informational
    4624: "informational",  # successful logon
    4634: "informational",  # logoff
    4647: "informational",  # user-initiated logoff
    4688: "informational",  # process creation
}


def parse_syslog(raw: str, source_ip: str) -> dict:
    """Parse a raw syslog line into a normalized dict. Falls back to a
    best-effort record if the message doesn't match either RFC format
    (some devices send non-conformant syslog). After parsing, message
    text is scanned for explicit src/dst IP fields (see enrich_src_dst),
    which override source_ip/hostname when present."""
    raw = raw.strip("\x00").strip()

    # JSON payload (e.g. NXLog to_json(), or any product POSTing/sending a
    # bare JSON object as the syslog body). Detected before the RFC parsers
    # so structured logs get their keys mapped instead of whitespace-split.
    jparsed = _try_parse_json_event(raw, source_ip)
    if jparsed is not None:
        return jparsed

    m = RFC5424_RE.match(raw)
    if m:
        pri = int(m.group("pri"))
        facility, severity = divmod(pri, 8)
        return enrich_src_dst({
            "received_at": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "peer_ip": source_ip,   # true network sender; never overwritten by enrich_src_dst
            "format": "rfc5424",
            "priority": pri,
            "facility": FACILITIES[facility] if facility < len(FACILITIES) else str(facility),
            "severity": SEVERITIES[severity] if severity < len(SEVERITIES) else str(severity),
            "device_timestamp": m.group("timestamp"),
            "hostname": m.group("hostname"),
            "app_name": m.group("appname"),
            "proc_id": m.group("procid"),
            "msg_id": m.group("msgid"),
            "message": m.group("message"),
            "raw": raw,
        })

    m = RFC3164_RE.match(raw)
    if m:
        pri = int(m.group("pri"))
        facility, severity = divmod(pri, 8)
        return enrich_src_dst({
            "received_at": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "peer_ip": source_ip,   # true network sender; never overwritten by enrich_src_dst
            "format": "rfc3164",
            "priority": pri,
            "facility": FACILITIES[facility] if facility < len(FACILITIES) else str(facility),
            "severity": SEVERITIES[severity] if severity < len(SEVERITIES) else str(severity),
            "device_timestamp": m.group("timestamp"),
            "hostname": m.group("hostname"),
            "app_name": m.group("tag"),
            "proc_id": m.group("pid") or "",
            "msg_id": "",
            "message": m.group("message"),
            "raw": raw,
        })

    # Non-conformant fallback: keep the raw text, don't drop the event.
    # No PRI header means no authoritative severity, so classify from
    # severity keywords in the text (e.g. "ERROR", "warn") if present.
    return enrich_src_dst({
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
            "peer_ip": source_ip,   # true network sender; never overwritten by enrich_src_dst
        "format": "unknown",
        "priority": None,
        "facility": "",
        "severity": severity_mod.extract_from_text(raw),
        "device_timestamp": "",
        "hostname": "",
        "app_name": "",
        "proc_id": "",
        "msg_id": "",
        "message": raw,
        "raw": raw,
    })


# --------------------------------------------------------------------------
# Source/destination IP enrichment
# --------------------------------------------------------------------------
# Many firewall/IDS/appliance logs carry the real actor and target as
# explicit fields in the message ("src=1.2.3.4 dst=5.6.7.8",
# "Source IP: ...", "srcip=...", "destination address ..."). When present
# these are more meaningful than the packet's transport source (which may
# just be a relay/collector), so we lift them into source_ip / hostname.

_IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
_SRC_LABEL = r"(?:src(?:ip|_ip|_addr|address)?|source(?:\s*ip|\s*address)?|from(?:\s*ip)?|client(?:\s*ip)?)"
_DST_LABEL = r"(?:dst(?:ip|_ip|_addr|address)?|dest(?:ination)?(?:\s*ip|\s*address)?|to(?:\s*ip)?|target(?:\s*ip)?)"
_SRC_RE = re.compile(_SRC_LABEL + r"\s*[=:]?\s*" + _IPV4, re.IGNORECASE)
_DST_RE = re.compile(_DST_LABEL + r"\s*[=:]?\s*" + _IPV4, re.IGNORECASE)


def extract_src_dst(message: str):
    """Return (src_ip_or_None, dst_ip_or_None) found in message text."""
    src = _SRC_RE.search(message or "")
    dst = _DST_RE.search(message or "")
    return (src.group(1) if src else None, dst.group(1) if dst else None)


def enrich_src_dst(event: dict) -> dict:
    """Lift explicit src/dst fields into source_ip and a dedicated
    'destination' field. Checks the message text AND, for JSON events, the
    parsed JSON keys (dst/dest/destination/target). 'destination' never
    clobbers hostname (the host that generated the log)."""
    msg = event.get("message", "")
    src, dst = extract_src_dst(msg)
    if src:
        event["source_ip"] = src
    dest_val = ""
    if dst:
        dest_val = dst
    else:
        dststr = _DST_STR_RE.search(msg or "")
        if dststr:
            dest_val = dststr.group(1)
    # JSON events: also honor an explicit destination-ish key
    if not dest_val:
        j = event.get("_json")
        if isinstance(j, dict):
            for k in ("dst", "dest", "destination", "dst_ip", "dstip",
                      "dest_ip", "target", "dst_host", "DestinationIp",
                      "DestAddress"):
                if j.get(k) not in (None, ""):
                    dest_val = str(j[k])
                    break
    event["destination"] = dest_val
    return event


# destination as a string value (hostname/domain/IP), not only an IP —
# "dst=host.example", "destination: foo.bar", "target=10.0.0.5"
_DST_STR_RE = re.compile(
    _DST_LABEL + r"\s*[=:]\s*([^\s,;]+)", re.IGNORECASE)


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

class Storage:
    """Thread-serialized wrapper over the configured database backend
    (sqlite or postgres, per db-config.json). One connection guarded by
    a lock — fine for the write volumes a small/medium syslog feed
    produces, and the lock is what keeps the shared connection safe
    across the UDP/TCP listener threads (important for postgres, whose
    connections are not safe for concurrent use).

    Accepts either a sqlite path (back-compat with the old --db flag) or
    an explicit db config dict."""

    def __init__(self, db_path: str = None, db_config: dict = None):
        cfg = db_config if db_config is not None else dbmod.config_from_path(db_path)
        dbmod.initialize(cfg)
        self.conn = dbmod.connect(cfg)
        self.backend = self.conn.backend
        self.lock = threading.Lock()

        # --- Commit batching (defends slow-disk servers against per-event
        # fsync cost). Insert stays synchronous so log_id is available for
        # rules/IOC/field extraction; only the COMMIT is batched. Runtime
        # defaults are 100 events / 100 ms via db.DEFAULT_CONFIG. Operators
        # can tune these in db-config.json; use size=1, delay=0 only when
        # immediate per-event durability is worth the throughput cost:
        #   "commit_batch_size":  N   -> commit after N pending write units
        #   "commit_max_delay_ms": T  -> or after T ms, whichever comes first
        sqlite_cfg = cfg.get("sqlite", {}) if isinstance(cfg, dict) else {}
        try:
            self._commit_batch_size = max(1, int(cfg.get("commit_batch_size",
                                          sqlite_cfg.get("commit_batch_size", dbmod.DEFAULT_CONFIG["commit_batch_size"]))))
        except (ValueError, TypeError):
            self._commit_batch_size = dbmod.DEFAULT_CONFIG["commit_batch_size"]
        try:
            self._commit_max_delay_ms = max(0, int(cfg.get("commit_max_delay_ms",
                                            sqlite_cfg.get("commit_max_delay_ms", dbmod.DEFAULT_CONFIG["commit_max_delay_ms"]))))
        except (ValueError, TypeError):
            self._commit_max_delay_ms = dbmod.DEFAULT_CONFIG["commit_max_delay_ms"]
        self._pending = 0
        self._last_commit = time.time()
        self._stop = threading.Event()
        self._flush_thread = None
        # background flusher only needed when batching is enabled
        if self._commit_batch_size > 1 or self._commit_max_delay_ms > 0:
            self._flush_thread = threading.Thread(
                target=self._flush_loop, daemon=True, name="storage-commit-flush")
            self._flush_thread.start()

    def _flush_loop(self):
        """Commit any pending writes once they've waited longer than the
        max delay — so a low-traffic tail isn't left uncommitted."""
        while not self._stop.is_set():
            delay = self._commit_max_delay_ms or 1000
            if self._stop.wait(max(0.05, delay / 1000.0)):
                break
            with self.lock:
                if self._pending > 0:
                    due = (self._commit_max_delay_ms == 0 or
                           (time.time() - self._last_commit) * 1000 >= self._commit_max_delay_ms)
                    if due:
                        self.commit_locked()

    def _maybe_commit_locked(self):
        """Called with self.lock held after an insert. Commits now if the
        batch is full or the max delay has elapsed; otherwise defers."""
        self._pending += 1
        if self._commit_batch_size <= 1 and self._commit_max_delay_ms <= 0:
            self.commit_locked()
            return
        size_due = self._pending >= self._commit_batch_size
        time_due = (self._commit_max_delay_ms > 0 and
                    (time.time() - self._last_commit) * 1000 >= self._commit_max_delay_ms)
        if size_due or time_due:
            self.commit_locked()

    def commit_locked(self):
        """Commit the shared connection and reset the batch accounting.

        Caller must hold ``storage.lock``. Auxiliary writers use this instead
        of committing the connection directly, so they cannot leave stale
        pending counters behind.
        """
        self.conn.commit()
        self._pending = 0
        self._last_commit = time.time()

    def rollback_locked(self):
        """Abort the current transaction and reset batch accounting.

        A database write failure invalidates the in-flight batch (especially on
        PostgreSQL), so recovery is fail-closed rather than later committing a
        partial event.
        """
        self.conn.rollback()
        self._pending = 0
        self._last_commit = time.time()

    def insert_log(self, event: dict, fields: dict = None) -> int:
        """Persist one log and, when supplied, its normalized fields atomically.

        Both writes share one storage-lock acquisition and one commit-batch unit,
        eliminating the former second lock + per-event field commit.
        """
        with self.lock:
            try:
                new_id = self.conn.insert_returning_id(
                    """INSERT INTO logs
                       (received_at, source_ip, peer_ip, format, priority, facility, severity,
                        device_timestamp, hostname, destination, app_name, proc_id, msg_id, message, raw)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        event["received_at"], event["source_ip"], event.get("peer_ip", ""),
                        event["format"], event["priority"],
                        event["facility"], event["severity"], event["device_timestamp"],
                        event["hostname"], event.get("destination", ""), event["app_name"],
                        event["proc_id"], event["msg_id"], event["message"], event["raw"],
                    ),
                )
                if fields:
                    write_fields(self.conn, new_id, fields)
                dbmod.update_log_rollups(self.conn, [event])
                self._maybe_commit_locked()
                return new_id
            except Exception:
                self.rollback_locked()
                raise

    def insert_log_batch(self, items):
        """Persist a micro-batch of ``(event, fields)`` tuples in one commit.

        The log row, normalized fields, total counter, hourly severity rollup,
        and per-source last-seen record share the same transaction. IDs are
        returned in input order so the post-persist detection stage can keep
        its log references exact.
        """
        if not items:
            return [], 0.0
        started = time.perf_counter()
        with self.lock:
            try:
                # Do not let a compatibility-path pending transaction become
                # part of the dedicated writer's latency/accounting window.
                if self._pending > 0:
                    self.commit_locked()
                ids = []
                source_rollup = {}
                hourly = {}
                for event, fields in items:
                    new_id = self.conn.insert_returning_id(
                        """INSERT INTO logs
                           (received_at, source_ip, peer_ip, format, priority, facility, severity,
                            device_timestamp, hostname, destination, app_name, proc_id, msg_id, message, raw)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            event["received_at"], event["source_ip"], event.get("peer_ip", ""),
                            event["format"], event["priority"], event["facility"], event["severity"],
                            event["device_timestamp"], event["hostname"], event.get("destination", ""),
                            event["app_name"], event["proc_id"], event["msg_id"], event["message"], event["raw"],
                        ),
                    )
                    if fields:
                        write_fields(self.conn, new_id, fields)
                    ids.append(new_id)
                    received = str(event.get("received_at") or "")
                    src = str(event.get("source_ip") or "").strip()
                    if src and received:
                        old = source_rollup.get(src)
                        if old is None:
                            source_rollup[src] = [received, received, 1]
                        else:
                            old[0] = min(old[0], received)
                            old[1] = max(old[1], received)
                            old[2] += 1
                    if received:
                        bucket = received[:13] + ":00:00+00:00"
                        sev = str(event.get("severity") or "").lower()
                        hourly[(bucket, sev)] = hourly.get((bucket, sev), 0) + 1

                now = datetime.now(timezone.utc).isoformat()
                dbmod.runtime_stat_increment(self.conn, "total_logs", len(ids), updated_at=now)
                for src, (first_seen, last_seen, count) in source_rollup.items():
                    self.conn.execute(
                        """INSERT INTO source_last_seen(source_ip, first_seen, last_seen, event_count)
                           VALUES (?,?,?,?)
                           ON CONFLICT(source_ip) DO UPDATE SET
                             first_seen=CASE WHEN excluded.first_seen < source_last_seen.first_seen
                                             THEN excluded.first_seen ELSE source_last_seen.first_seen END,
                             last_seen=CASE WHEN excluded.last_seen > source_last_seen.last_seen
                                            THEN excluded.last_seen ELSE source_last_seen.last_seen END,
                             event_count=source_last_seen.event_count + excluded.event_count""",
                        (src, first_seen, last_seen, count),
                    )
                for (bucket, sev), count in hourly.items():
                    self.conn.execute(
                        """INSERT INTO hourly_log_stats(bucket_hour, severity, count)
                           VALUES (?,?,?)
                           ON CONFLICT(bucket_hour, severity) DO UPDATE SET
                             count=hourly_log_stats.count + excluded.count""",
                        (bucket, sev, count),
                    )
                self.conn.commit()
                self._pending = 0
                self._last_commit = time.time()
            except Exception:
                self.rollback_locked()
                raise
        return ids, (time.perf_counter() - started) * 1000.0

    def publish_ingest_telemetry(self, telemetry: dict):
        """Publish one compact JSON telemetry snapshot for the dashboard."""
        payload = json.dumps(telemetry, separators=(",", ":"), sort_keys=True)
        with self.lock:
            try:
                dbmod.runtime_stat_upsert(
                    self.conn, "ingest_telemetry", value_text=payload,
                    updated_at=datetime.now(timezone.utc).isoformat())
                self.conn.commit()
                self._pending = 0
                self._last_commit = time.time()
            except Exception:
                self.rollback_locked()
                raise

    def write_log_fields(self, log_id: int, fields: dict) -> int:
        """Compatibility path for field writes outside atomic insert_log()."""
        if not fields:
            return 0
        with self.lock:
            try:
                count = write_fields(self.conn, log_id, fields)
                self._maybe_commit_locked()
                return count
            except Exception:
                self.rollback_locked()
                raise

    def execute_batched(self, sql: str, params=()):
        """Run one auxiliary write through the same commit-batching policy."""
        with self.lock:
            try:
                cur = self.conn.execute(sql, params)
                self._maybe_commit_locked()
                return cur
            except Exception:
                self.rollback_locked()
                raise

    def flush(self):
        """Commit pending batched writes immediately."""
        with self.lock:
            if self._pending > 0:
                self.commit_locked()

    def close(self):
        """Stop the commit flusher, persist the low-traffic tail, and close."""
        self._stop.set()
        if self._flush_thread is not None and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=2)
        self.flush()
        with self.lock:
            self.conn.close()

    def insert_alert(self, rule_name: str, severity: str, source_ip: str,
                      description: str, log_ids: list) -> int:
        with self.lock:
            try:
                new_id = self.conn.insert_returning_id(
                    """INSERT INTO alerts (created_at, rule_name, severity, source_ip, description, log_ids)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        datetime.now(timezone.utc).isoformat(), rule_name, severity,
                        source_ip, description, ",".join(str(i) for i in log_ids),
                    ),
                )
                dbmod.runtime_stat_increment(
                    self.conn, "total_alerts", 1,
                    updated_at=datetime.now(timezone.utc).isoformat())
                self.commit_locked()
                return new_id
            except Exception:
                self.rollback_locked()
                raise


# --------------------------------------------------------------------------
# Bounded ingest pipeline
# --------------------------------------------------------------------------

class DBWriter:
    """Single-owner log writer with bounded queue and micro-batched commits."""

    _SENTINEL = object()

    def __init__(self, storage, output_queue, queue_size=20000, batch_size=100,
                 max_delay_ms=75, failure_callback=None):
        self.storage = storage
        self.output_queue = output_queue
        self.queue_size = max(1, int(queue_size))
        self.batch_size = max(1, int(batch_size))
        self.max_delay_ms = max(0, int(max_delay_ms))
        self.failure_callback = failure_callback
        self._queue = queue.Queue(maxsize=self.queue_size)
        self._lock = threading.Lock()
        self._written = 0
        self._failed = 0
        self._batches = 0
        self._batch_events = 0
        self._high_water = 0
        self._latencies = deque(maxlen=256)
        self._thread = threading.Thread(target=self._run, daemon=True, name="db-writer")
        self._thread.start()

    def submit(self, event, fields, timeout=0.10):
        try:
            self._queue.put((event, fields), timeout=timeout)
        except queue.Full:
            return False
        with self._lock:
            self._high_water = max(self._high_water, self._queue.qsize())
        return True

    def _record_batch(self, count, latency_ms):
        with self._lock:
            self._written += count
            self._batches += 1
            self._batch_events += count
            self._latencies.append(float(latency_ms))

    def _record_failure(self, count):
        with self._lock:
            self._failed += count

    def _run(self):
        stop_after_batch = False
        while True:
            first = self._queue.get()
            if first is self._SENTINEL:
                self._queue.task_done()
                return
            batch = [first]
            deadline = time.monotonic() + (self.max_delay_ms / 1000.0)
            while len(batch) < self.batch_size:
                remaining = deadline - time.monotonic()
                if self.max_delay_ms <= 0 or remaining <= 0:
                    break
                try:
                    item = self._queue.get(timeout=remaining)
                except queue.Empty:
                    break
                if item is self._SENTINEL:
                    self._queue.task_done()
                    stop_after_batch = True
                    break
                batch.append(item)
            try:
                if hasattr(self.storage, "insert_log_batch"):
                    ids, latency_ms = self.storage.insert_log_batch(batch)
                else:
                    # Lightweight test/embedding compatibility. Production
                    # Storage always provides the atomic micro-batch method.
                    started = time.perf_counter()
                    ids = [self.storage.insert_log(event, fields=fields) for event, fields in batch]
                    latency_ms = (time.perf_counter() - started) * 1000.0
                self._record_batch(len(ids), latency_ms)
                # Persisted events are never dropped from post-processing. If
                # that bounded queue is full the DB writer waits, which pushes
                # back to its own bounded input queue and makes overload visible.
                for log_id, (event, fields) in zip(ids, batch):
                    self.output_queue.put((log_id, event, fields))
            except Exception as exc:
                self._record_failure(len(batch))
                if self.failure_callback:
                    self.failure_callback(len(batch), exc)
            finally:
                for _ in batch:
                    self._queue.task_done()
            if stop_after_batch:
                return

    def stats(self):
        with self._lock:
            lat = sorted(self._latencies)
            def pct(p):
                if not lat:
                    return 0.0
                idx = min(len(lat) - 1, max(0, int(round((len(lat) - 1) * p))))
                return lat[idx]
            return {
                "db_written": self._written,
                "db_failed": self._failed,
                "db_batches": self._batches,
                "db_queue_depth": self._queue.qsize(),
                "db_queue_capacity": self.queue_size,
                "db_queue_high_water": self._high_water,
                "db_batch_size_config": self.batch_size,
                "db_batch_avg": (self._batch_events / self._batches) if self._batches else 0.0,
                "db_commit_ms_avg": (sum(lat) / len(lat)) if lat else 0.0,
                "db_commit_ms_p50": pct(0.50),
                "db_commit_ms_p95": pct(0.95),
            }

    def stop(self, drain=True):
        if not drain:
            while True:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except queue.Empty:
                    break
        # Producers are already stopped by IngestPipeline before this call. Put
        # the sentinel behind all accepted jobs *before* waiting: if the writer
        # is holding a low-traffic partial batch, it consumes the sentinel and
        # flushes immediately instead of sleeping for the configured max delay.
        self._queue.put(self._SENTINEL)
        self._queue.join()
        self._thread.join(timeout=5)


class IngestPipeline:
    """Three-stage bounded ingest pipeline.

    Stage 1 socket/API receivers enqueue raw events. Stage 2 parser workers
    parse/enrich/extract and enqueue prepared writes. One DBWriter owns the
    high-volume log transaction path and commits micro-batches. Persisted rows
    then enter a bounded post-persist queue for rule/IOC/forwarder processing.
    This preserves the rule invariant that every alert references a durable
    log ID while allowing the single database writer to batch efficiently.
    """

    _SENTINEL = object()

    def __init__(self, storage, engine, ioc, fields, forwarders,
                 worker_count: int = 4, queue_size: int = 10000,
                 db_writer_queue_size: int = 20000, db_writer_batch_size: int = 100,
                 db_writer_max_delay_ms: int = 75,
                 event_logging: bool = False, stats_interval_seconds: int = 10):
        self.storage = storage
        self.engine = engine
        self.ioc = ioc
        self.fields = fields
        self.forwarders = forwarders
        self.worker_count = max(1, int(worker_count))
        self.queue_size = max(1, int(queue_size))
        self.event_logging = bool(event_logging)
        try:
            self.stats_interval_seconds = max(0, int(stats_interval_seconds))
        except (TypeError, ValueError):
            self.stats_interval_seconds = 10
        self._queue = queue.Queue(maxsize=self.queue_size)
        self._post_queue = queue.Queue(maxsize=max(1000, int(db_writer_queue_size)))
        self._stats_lock = threading.Lock()
        self._accepting = True
        self._received = 0
        self._enqueued = 0
        self._prepared = 0
        self._processed = 0
        self._failed = 0
        self._dropped = 0
        self._dropped_udp = 0
        self._dropped_other = 0
        self._db_queue_dropped = 0
        self._db_write_failed = 0
        self._high_water = 0
        self._post_high_water = 0
        self._workers = []
        self._post_workers = []
        self._report_stop = threading.Event()
        self._reporter = None
        self.db_writer = DBWriter(
            storage, self._post_queue,
            queue_size=db_writer_queue_size,
            batch_size=db_writer_batch_size,
            max_delay_ms=db_writer_max_delay_ms,
            failure_callback=self._on_db_failure,
        )
        for idx in range(self.worker_count):
            t = threading.Thread(target=self._worker_loop, daemon=True,
                                 name=f"ingest-parser-{idx + 1}")
            t.start()
            self._workers.append(t)
        for idx in range(self.worker_count):
            t = threading.Thread(target=self._post_worker_loop, daemon=True,
                                 name=f"ingest-post-{idx + 1}")
            t.start()
            self._post_workers.append(t)
        if self.stats_interval_seconds > 0:
            self._reporter = threading.Thread(
                target=self._stats_report_loop, daemon=True, name="ingest-stats")
            self._reporter.start()

    def _on_db_failure(self, count, exc):
        with self._stats_lock:
            self._failed += count
            self._db_write_failed += count
        print(f"[ingest] DB batch failed ({count} event(s)): {type(exc).__name__}: {exc}", file=sys.stderr)

    def _publish_telemetry(self, current, rate):
        data = dict(current)
        data["ingest_rate_eps"] = round(float(rate), 3)
        data["published_at"] = datetime.now(timezone.utc).isoformat()
        try:
            self.storage.publish_ingest_telemetry(data)
        except Exception as exc:
            print(f"[ingest] telemetry publish failed: {type(exc).__name__}: {exc}", file=sys.stderr)

    def _stats_report_loop(self):
        previous = self.stats()
        previous_forward = self.forwarders.stats() if hasattr(self.forwarders, "stats") else {}
        previous_at = time.monotonic()
        while not self._report_stop.wait(self.stats_interval_seconds):
            current = self.stats()
            current_forward = self.forwarders.stats() if hasattr(self.forwarders, "stats") else {}
            now = time.monotonic()
            elapsed = max(0.001, now - previous_at)
            rate = (current["processed"] - previous.get("processed", 0)) / elapsed
            changed = any(current[k] != previous.get(k) for k in
                          ("received", "processed", "failed", "dropped", "db_written"))
            if changed or current["queue_depth"] or current["db_queue_depth"]:
                print(
                    "[ingest] "
                    f"processed={current['processed']} received={current['received']} "
                    f"dropped={current['dropped']} failed={current['failed']} "
                    f"queue={current['queue_depth']}/{current['queue_capacity']} "
                    f"dbq={current['db_queue_depth']}/{current['db_queue_capacity']} "
                    f"batch={current['db_batch_avg']:.1f} "
                    f"commit_p95={current['db_commit_ms_p95']:.1f}ms rate={rate:.1f}/s"
                )
            publish = dict(current)
            publish["interval_dropped"] = max(0, current["dropped"] - previous.get("dropped", 0))
            publish["interval_failed"] = max(0, current["failed"] - previous.get("failed", 0))
            publish["interval_db_queue_dropped"] = max(0, current["db_queue_dropped"] - previous.get("db_queue_dropped", 0))
            publish["interval_db_write_failed"] = max(0, current["db_write_failed"] - previous.get("db_write_failed", 0))
            publish["forward_queue_depth"] = int(current_forward.get("queue_depth") or 0)
            publish["forward_queue_capacity"] = int(current_forward.get("queue_capacity") or 0)
            publish["forward_queue_high_water"] = int(current_forward.get("queue_high_water") or 0)
            publish["forward_dropped"] = int(current_forward.get("dropped") or 0)
            publish["interval_forward_dropped"] = max(0, int(current_forward.get("dropped") or 0) - int(previous_forward.get("dropped") or 0))
            self._publish_telemetry(publish, rate)
            previous, previous_forward, previous_at = current, current_forward, now

    def submit(self, raw, source_ip: str, transport: str = "api", received_at: str = None):
        if not self._accepting:
            return False
        item = (raw, source_ip, received_at or datetime.now(timezone.utc).isoformat(), transport)
        with self._stats_lock:
            self._received += 1
        try:
            if transport == "udp":
                self._queue.put_nowait(item)
            else:
                self._queue.put(item, timeout=0.10)
        except queue.Full:
            with self._stats_lock:
                self._dropped += 1
                if transport == "udp":
                    self._dropped_udp += 1
                else:
                    self._dropped_other += 1
                dropped = self._dropped
            if dropped == 1 or dropped % 100 == 0:
                print(f"[ingest] queue full: dropped={dropped} transport={transport} capacity={self.queue_size}", file=sys.stderr)
            return False
        with self._stats_lock:
            self._enqueued += 1
            self._high_water = max(self._high_water, self._queue.qsize())
        return True

    def stats(self):
        with self._stats_lock:
            base = {
                "received": self._received,
                "enqueued": self._enqueued,
                "prepared": self._prepared,
                "processed": self._processed,
                "failed": self._failed,
                "dropped": self._dropped,
                "dropped_udp": self._dropped_udp,
                "dropped_other": self._dropped_other,
                "db_queue_dropped": self._db_queue_dropped,
                "db_write_failed": self._db_write_failed,
                "queue_depth": self._queue.qsize(),
                "queue_capacity": self.queue_size,
                "queue_high_water": self._high_water,
                "post_queue_depth": self._post_queue.qsize(),
                "post_queue_capacity": self._post_queue.maxsize,
                "post_queue_high_water": self._post_high_water,
                "workers": self.worker_count,
            }
        base.update(self.db_writer.stats())
        return base

    def _worker_loop(self):
        while True:
            item = self._queue.get()
            try:
                if item is self._SENTINEL:
                    return
                raw, source_ip, received_at, _transport = item
                raw = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                event = parse_syslog(raw, source_ip)
                event["received_at"] = received_at
                extracted = self.fields.extract(event)
                if not self.db_writer.submit(event, extracted):
                    with self._stats_lock:
                        self._failed += 1
                        self._db_queue_dropped += 1
                    continue
                with self._stats_lock:
                    self._prepared += 1
            except Exception as exc:
                with self._stats_lock:
                    self._failed += 1
                print(f"[ingest] preparation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            finally:
                self._queue.task_done()

    def _post_worker_loop(self):
        while True:
            item = self._post_queue.get()
            try:
                if item is self._SENTINEL:
                    return
                log_id, event, extracted = item
                self.engine.process(log_id, event)
                self.ioc.process(log_id, event)
                try:
                    self.fields.capture_unidentified(log_id, event, len(extracted))
                except Exception:
                    pass
                self.forwarders.forward(event)
                if self.event_logging:
                    sev = event["severity"] or "-"
                    print(f"[{event['received_at']}] {event.get('source_ip','')} [{sev}] {event['message'][:120]}")
                with self._stats_lock:
                    self._processed += 1
                    self._post_high_water = max(self._post_high_water, self._post_queue.qsize())
            except Exception as exc:
                with self._stats_lock:
                    self._failed += 1
                print(f"[ingest] post-processing failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            finally:
                self._post_queue.task_done()

    def stop(self, drain: bool = True):
        self._accepting = False
        self._report_stop.set()
        if drain:
            self._queue.join()
        else:
            while True:
                try:
                    self._queue.get_nowait(); self._queue.task_done()
                except queue.Empty:
                    break
        # Parser workers cannot produce any more DB jobs after this join.
        for _ in self._workers:
            self._queue.put(self._SENTINEL)
        self._queue.join()
        for t in self._workers:
            t.join(timeout=3)

        self.db_writer.stop(drain=drain)
        if drain:
            self._post_queue.join()
        for _ in self._post_workers:
            self._post_queue.put(self._SENTINEL)
        self._post_queue.join()
        for t in self._post_workers:
            t.join(timeout=3)
        if self._reporter is not None:
            self._reporter.join(timeout=1)
        # Publish one final zero-window snapshot without claiming an event rate.
        try:
            self._publish_telemetry(self.stats(), 0.0)
        except Exception:
            pass


# --------------------------------------------------------------------------
# Network listeners
# --------------------------------------------------------------------------

def udp_listener(host: str, port: int, on_message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    print(f"[udp] listening on {host}:{port}")
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            on_message(data, addr[0])
        except Exception as exc:
            print(f"[udp] error: {exc}", file=sys.stderr)


def _handle_tcp_client(conn: socket.socket, addr, on_message):
    # Syslog over TCP frames messages either with a trailing newline
    # (non-transparent framing, RFC6587) or a leading octet-count
    # (transparent framing). We handle newline framing here, which is
    # what the overwhelming majority of devices send.
    buf = b""
    with conn:
        while True:
            try:
                chunk = conn.recv(65535)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    on_message(line, addr[0])


def tcp_listener(host: str, port: int, on_message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(50)
    print(f"[tcp] listening on {host}:{port}")
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=_handle_tcp_client, args=(conn, addr, on_message), daemon=True).start()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="mini-SIEM syslog listener")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("--port", default="514",
                    help="syslog port(s), comma-separated (default 514; e.g. 514,10514)")
    ap.add_argument("--protocol", choices=["udp", "tcp", "both"], default="both")
    ap.add_argument("--db", default="siem.db", help="SQLite database path (used only when no db-config.json / --db-config selects a backend)")
    ap.add_argument("--db-config", default=None, help="path to db-config.json (sqlite/postgres selector)")
    args = ap.parse_args()

    db_cfg = dbmod.load_config(args.db_config, sqlite_fallback=args.db)
    print(f"[db] backend: {dbmod.describe(db_cfg)}")

    # Resolve listen ports. --port on the command line wins; otherwise use
    # listen_ports saved in db-config.json (e.g. set from the Setup page);
    # otherwise default 514.
    port_arg_given = any(a == "--port" or a.startswith("--port=") for a in sys.argv[1:])
    if port_arg_given:
        try:
            ports = [int(p.strip()) for p in str(args.port).split(",") if p.strip()]
        except ValueError:
            print(f"[error] invalid --port value: {args.port!r}", file=sys.stderr); sys.exit(1)
    else:
        ports = db_cfg.get("listen_ports") or [int(p.strip()) for p in str(args.port).split(",") if p.strip()]
    if not ports:
        ports = [514]
    print(f"[listen] syslog ports: {', '.join(map(str, ports))}")

    storage = Storage(db_config=db_cfg)
    engine = RuleEngine(storage)
    forwarders = ForwarderManager(
        storage, listen_port=ports[0],
        queue_size=int(db_cfg.get("forward_queue_size", 10000)),
    )
    ioc = IOCMatcher(storage)
    fields = FieldIndexer(storage)
    pipeline = IngestPipeline(
        storage, engine, ioc, fields, forwarders,
        worker_count=int(db_cfg.get("ingest_workers", 4)),
        queue_size=int(db_cfg.get("ingest_queue_size", 10000)),
        db_writer_queue_size=int(db_cfg.get("db_writer_queue_size", 20000)),
        db_writer_batch_size=int(db_cfg.get("db_writer_batch_size", 100)),
        db_writer_max_delay_ms=int(db_cfg.get("db_writer_max_delay_ms", 75)),
        event_logging=bool(db_cfg.get("ingest_event_logging", False)),
        stats_interval_seconds=int(db_cfg.get("ingest_stats_interval_seconds", 10)),
    )
    maintenance = MaintenanceWorker(storage, db_cfg)

    threads = []
    for p in ports:
        if args.protocol in ("udp", "both"):
            on_udp = lambda raw, source_ip: pipeline.submit(raw, source_ip, transport="udp")
            threads.append(threading.Thread(target=udp_listener, args=(args.host, p, on_udp), daemon=True))
        if args.protocol in ("tcp", "both"):
            on_tcp = lambda raw, source_ip: pipeline.submit(raw, source_ip, transport="tcp")
            threads.append(threading.Thread(target=tcp_listener, args=(args.host, p, on_tcp), daemon=True))

    if not threads:
        print("No protocol selected.", file=sys.stderr)
        sys.exit(1)

    for t in threads:
        t.start()

    print(f"mini-SIEM listener running. DB: {args.db}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down.")
        maintenance.stop()
        pipeline.stop(drain=True)
        forwarders.stop(drain=True)
        fields.stop()
        ioc.stop()
        storage.close()
        print(f"[ingest] final stats: {pipeline.stats()}")
        print(f"[forwarder] final stats: {forwarders.stats()}")


if __name__ == "__main__":
    main()

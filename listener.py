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
from normalize import FieldIndexer
import severity as severity_mod
import db as dbmod

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
        # rules/IOC/field extraction; only the COMMIT is batched. Defaults
        # (size=1, delay=0) reproduce the original commit-every-event
        # behavior, so nothing changes until tuned in db-config.json:
        #   "commit_batch_size":  N   -> commit after N pending inserts
        #   "commit_max_delay_ms": T  -> or after T ms, whichever comes first
        # On fast NVMe leave defaults; on HDD/RAID servers raise both.
        sqlite_cfg = cfg.get("sqlite", {}) if isinstance(cfg, dict) else {}
        try:
            self._commit_batch_size = max(1, int(cfg.get("commit_batch_size",
                                          sqlite_cfg.get("commit_batch_size", 1))))
        except (ValueError, TypeError):
            self._commit_batch_size = 1
        try:
            self._commit_max_delay_ms = max(0, int(cfg.get("commit_max_delay_ms",
                                            sqlite_cfg.get("commit_max_delay_ms", 0))))
        except (ValueError, TypeError):
            self._commit_max_delay_ms = 0
        self._pending = 0
        self._last_commit = time.time()
        # background flusher only needed when batching is enabled
        if self._commit_batch_size > 1 or self._commit_max_delay_ms > 0:
            t = threading.Thread(target=self._flush_loop, daemon=True)
            t.start()

    def _flush_loop(self):
        """Commit any pending writes once they've waited longer than the
        max delay — so a low-traffic tail isn't left uncommitted."""
        while True:
            delay = self._commit_max_delay_ms or 1000
            time.sleep(max(0.05, delay / 1000.0))
            with self.lock:
                if self._pending > 0:
                    due = (self._commit_max_delay_ms == 0 or
                           (time.time() - self._last_commit) * 1000 >= self._commit_max_delay_ms)
                    if due:
                        self.conn.commit()
                        self._pending = 0
                        self._last_commit = time.time()

    def _maybe_commit_locked(self):
        """Called with self.lock held after an insert. Commits now if the
        batch is full or the max delay has elapsed; otherwise defers."""
        self._pending += 1
        if self._commit_batch_size <= 1 and self._commit_max_delay_ms <= 0:
            self.conn.commit()
            self._pending = 0
            self._last_commit = time.time()
            return
        size_due = self._pending >= self._commit_batch_size
        time_due = (self._commit_max_delay_ms > 0 and
                    (time.time() - self._last_commit) * 1000 >= self._commit_max_delay_ms)
        if size_due or time_due:
            self.conn.commit()
            self._pending = 0
            self._last_commit = time.time()

    def insert_log(self, event: dict) -> int:
        with self.lock:
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
            self._maybe_commit_locked()
            return new_id

    def insert_alert(self, rule_name: str, severity: str, source_ip: str,
                      description: str, log_ids: list) -> int:
        with self.lock:
            new_id = self.conn.insert_returning_id(
                """INSERT INTO alerts (created_at, rule_name, severity, source_ip, description, log_ids)
                   VALUES (?,?,?,?,?,?)""",
                (
                    datetime.now(timezone.utc).isoformat(), rule_name, severity,
                    source_ip, description, ",".join(str(i) for i in log_ids),
                ),
            )
            self.conn.commit()
            return new_id


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
            on_message(data.decode("utf-8", errors="replace"), addr[0])
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
                    on_message(line.decode("utf-8", errors="replace"), addr[0])


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
    forwarders = ForwarderManager(storage, listen_port=ports[0])
    ioc = IOCMatcher(storage)
    fields = FieldIndexer(storage)

    def on_message(raw: str, source_ip: str):
        event = parse_syslog(raw, source_ip)
        log_id = storage.insert_log(event)
        engine.process(log_id, event)
        ioc.process(log_id, event)
        fields.process(log_id, event)
        forwarders.forward(event)  # relay the original raw message downstream
        sev = event["severity"] or "-"
        print(f"[{event['received_at']}] {source_ip} [{sev}] {event['message'][:120]}")

    threads = []
    for p in ports:
        if args.protocol in ("udp", "both"):
            threads.append(threading.Thread(target=udp_listener, args=(args.host, p, on_message), daemon=True))
        if args.protocol in ("tcp", "both"):
            threads.append(threading.Thread(target=tcp_listener, args=(args.host, p, on_message), daemon=True))

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


if __name__ == "__main__":
    main()

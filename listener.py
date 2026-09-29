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
import queue
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

# Keep TCP syslog framing bounded. UDP is already bounded by the datagram
# receive size; TCP otherwise permits a peer that never terminates a frame to
# grow the per-connection buffer without limit. One MiB is intentionally well
# above normal syslog/CEF event sizes while remaining a hard safety ceiling.
MAX_SYSLOG_FRAME_BYTES = 1024 * 1024



def _cef_unescape(value: str) -> str:
    """Decode the common CEF escaping rules without interpreting arbitrary escapes."""
    out = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            mapped = {"n": "\n", "r": "\r", "\\": "\\", "=": "=", "|": "|"}.get(nxt)
            if mapped is not None:
                out.append(mapped)
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _split_cef_payload(text: str):
    """Return the seven CEF header fields plus extension, honoring escaped pipes."""
    pos = text.find("CEF:")
    if pos < 0:
        return None
    payload = text[pos:]
    fields = []
    buf = []
    escaped = False
    for ch in payload:
        if escaped:
            buf.append("\\")
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "|" and len(fields) < 7:
            fields.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if escaped:
        buf.append("\\")
    fields.append("".join(buf))
    if len(fields) < 7 or not re.fullmatch(r"CEF:\d+", fields[0].strip()):
        return None
    header = [_cef_unescape(v) for v in fields[:7]]
    extension = fields[7] if len(fields) > 7 else ""
    return header, extension


def _parse_cef_extension(extension: str) -> dict:
    fields = {}
    # CEF extension values may contain spaces; the next key=value token marks
    # the boundary. Escaped '=' remains part of the current value.
    token_re = re.compile(r"(?:^|\s)([A-Za-z0-9_.-]{1,64})=")
    matches = list(token_re.finditer(extension or ""))
    for idx, match in enumerate(matches):
        value_start = match.end()
        value_end = matches[idx + 1].start() if idx + 1 < len(matches) else len(extension)
        value = extension[value_start:value_end].rstrip()
        fields[match.group(1)] = _cef_unescape(value)
    return fields


def _normalize_cef_severity(value: str) -> str:
    text = str(value or "").strip()
    try:
        score = int(text)
    except ValueError:
        lowered = text.lower()
        if lowered in {"very-high", "very high", "critical", "fatal"}:
            return "critical"
        if lowered in {"high", "error"}:
            return "error"
        if lowered in {"medium", "moderate", "warning", "warn"}:
            return "warning"
        return "informational"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "error"
    if score >= 4:
        return "warning"
    return "informational"


def _cef_payload_at_start(text: str):
    """Return a CEF payload only when it starts the actual syslog message.

    CEF may be sent bare, with a PRI-only prefix, or as the MSG portion of an
    RFC3164/RFC5424 envelope.  An arbitrary ``CEF:`` substring inside normal
    log text is *not* sufficient: quoted examples and parser-error messages
    must not be reclassified as CEF events.
    """
    text = str(text or "")
    candidate = text.lstrip("\ufeff \t")
    if candidate.startswith("CEF:"):
        return candidate

    pri_only = re.match(r"^<(?P<pri>\d{1,3})>(?P<payload>.*)$", candidate, re.DOTALL)
    if pri_only:
        payload = pri_only.group("payload").lstrip("\ufeff \t")
        if payload.startswith("CEF:"):
            return payload
    return None


def _try_parse_cef_event(raw: str, source_ip: str):
    """Parse bare or RFC-wrapped CEF into a complete normalised event.

    Malformed CEF returns ``None`` so the ordinary RFC/non-conformant fallback
    still preserves the raw evidence instead of dropping the event.
    """
    envelope = {
        "priority": None,
        "facility": "",
        "device_timestamp": "",
        "hostname": "",
        "app_name": "",
        "proc_id": "",
        "msg_id": "",
    }
    cef_text = _cef_payload_at_start(raw)
    m = RFC5424_RE.match(raw)
    rfc_message = None
    if m:
        rfc_message = _cef_payload_at_start(m.group("message"))
    if m and rfc_message is not None:
        pri = int(m.group("pri"))
        facility, _sev = divmod(pri, 8)
        envelope.update({
            "priority": pri,
            "facility": FACILITIES[facility] if facility < len(FACILITIES) else str(facility),
            "device_timestamp": m.group("timestamp"),
            "hostname": m.group("hostname"),
            "app_name": m.group("appname"),
            "proc_id": m.group("procid"),
            "msg_id": m.group("msgid"),
        })
        cef_text = rfc_message
    else:
        m = RFC3164_RE.match(raw)
        rfc_message = _cef_payload_at_start(m.group("message")) if m else None
        if m and rfc_message is not None:
            pri = int(m.group("pri"))
            facility, _sev = divmod(pri, 8)
            envelope.update({
                "priority": pri,
                "facility": FACILITIES[facility] if facility < len(FACILITIES) else str(facility),
                "device_timestamp": m.group("timestamp"),
                "hostname": m.group("hostname"),
                "app_name": m.group("tag"),
                "proc_id": m.group("pid") or "",
            })
            cef_text = rfc_message

    if cef_text is None:
        return None

    parsed = _split_cef_payload(cef_text)
    if parsed is None:
        return None
    header, extension = parsed
    version = header[0].split(":", 1)[1]
    vendor, product, device_version, signature_id, event_name, cef_severity = header[1:]
    cef_fields = _parse_cef_extension(extension)

    # Make CEF header semantics searchable through the same structured-field
    # indexing path used by JSON, while preserving every vendor extension.
    structured = dict(cef_fields)
    structured.update({
        "vendor": vendor,
        "product": product,
        "device_version": device_version,
        "event_code": signature_id,
        "event_type": event_name,
        "cef_severity": cef_severity,
    })
    transport_source = source_ip
    event = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": str(cef_fields.get("src") or transport_source),
        "peer_ip": transport_source,
        "format": "cef",
        "priority": envelope["priority"],
        "facility": envelope["facility"],
        "severity": _normalize_cef_severity(cef_severity),
        "device_timestamp": envelope["device_timestamp"],
        "hostname": str(cef_fields.get("shost") or envelope["hostname"] or ""),
        "destination": str(cef_fields.get("dst") or cef_fields.get("dhost") or ""),
        "app_name": envelope["app_name"] or product,
        "proc_id": envelope["proc_id"],
        "msg_id": envelope["msg_id"],
        "message": cef_text,
        "raw": raw,
        "cef_version": version,
        "device_vendor": vendor,
        "device_product": product,
        "device_version": device_version,
        "signature_id": signature_id,
        "event_name": event_name,
        "cef_severity": cef_severity,
        "destination_ip": str(cef_fields.get("dst") or ""),
        "username": str(cef_fields.get("suser") or cef_fields.get("duser") or ""),
        "action": str(cef_fields.get("act") or ""),
        "destination_port": str(cef_fields.get("dpt") or ""),
        "_cef": structured,
    }
    return event

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

    cparsed = _try_parse_cef_event(raw, source_ip)
    if cparsed is not None:
        return cparsed

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
        dbmod.ensure_runtime_ready(cfg)
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

    def insert_log(self, event: dict, fields=None) -> int:
        """Append raw evidence plus the PostgreSQL typed projection atomically.

        SQLite keeps the historical raw/log_fields behavior.  PostgreSQL adds
        Event Storage v2 in the same transaction, so a committed raw log cannot
        silently exist without its typed query projection on the normal ingest
        path.
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
                        event["format"], event["priority"], event["facility"], event["severity"],
                        event["device_timestamp"], event["hostname"], event.get("destination", ""),
                        event["app_name"], event["proc_id"], event["msg_id"], event["message"], event["raw"],
                    ),
                )
                if fields:
                    from normalize import write_fields
                    write_fields(self.conn, int(new_id), fields)
                from event_storage_v2 import append_projection
                append_projection(self.conn, int(new_id), event, fields or {})
                self._maybe_commit_locked()
                return int(new_id)
            except Exception:
                self.rollback_locked()
                raise

    def insert_log_batch(self, items):
        """Insert ``(event, fields)`` pairs atomically enough for archive tooling.

        This is the conservative batch API expected by archive/performance
        helpers.  It returns ``(ids, commit_ms)`` and never bypasses the same
        configured database identity.
        """
        started = time.monotonic()
        ids = []
        with self.lock:
            try:
                for event, fields in items:
                    log_id = self.conn.insert_returning_id(
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
                    ids.append(int(log_id))
                    from normalize import write_fields
                    write_fields(self.conn, int(log_id), fields or {})
                    from event_storage_v2 import append_projection
                    append_projection(self.conn, int(log_id), event, fields or {})
                self.conn.commit()
                self._pending = 0
                self._last_commit = time.time()
            except Exception:
                self.rollback_locked()
                raise
        return ids, round((time.monotonic() - started) * 1000.0, 3)

    def commit_locked(self):
        self.conn.commit()
        self._pending = 0
        self._last_commit = time.time()

    def rollback_locked(self):
        try:
            self.conn.rollback()
        finally:
            self._pending = 0
            self._last_commit = time.time()

    def close(self):
        with self.lock:
            if self._pending > 0:
                self.commit_locked()
            self.conn.close()

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


class IngestPipeline:
    """Bounded asynchronous ingest pipeline used by high-throughput paths.

    The pipeline keeps transport handling separate from parsing and storage.
    Queue overflow is reported instead of blocking UDP receive workers.
    """

    def __init__(self, storage, rules=None, ioc_matcher=None, fields=None,
                 forwarders=None, worker_count=1, queue_size=1000):
        self.storage = storage
        self.rules = rules
        self.ioc_matcher = ioc_matcher
        self.fields = fields
        self.forwarders = forwarders
        self.queue = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._stats = {"processed": 0, "failed": 0, "dropped": 0,
                       "dropped_udp": 0}
        self._lock = threading.Lock()
        self.workers = []
        for _ in range(max(1, int(worker_count))):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self.workers.append(t)

    def submit(self, raw, source_ip, transport="udp", received_at=None):
        item = (raw, source_ip, transport, received_at)
        try:
            self.queue.put_nowait(item)
            return True
        except queue.Full:
            with self._lock:
                self._stats["dropped"] += 1
                if transport == "udp":
                    self._stats["dropped_udp"] += 1
            return False

    def _worker(self):
        while not self._stop.is_set() or not self.queue.empty():
            try:
                raw, source_ip, transport, received_at = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                event = parse_syslog(raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw,
                                     source_ip)
                if received_at:
                    event["received_at"] = received_at
                fields = self.fields.extract(event) if self.fields else {}
                self.storage.insert_log(event, fields=fields)
                if self.forwarders:
                    self.forwarders.forward(event)
                with self._lock:
                    self._stats["processed"] += 1
            except Exception:
                with self._lock:
                    self._stats["failed"] += 1
            finally:
                self.queue.task_done()

    def stats(self):
        with self._lock:
            return dict(self._stats)

    def stop(self, drain=False):
        if drain:
            self.queue.join()
        self._stop.set()
        for t in self.workers:
            t.join(timeout=1)



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


class _TCPFramingError(ValueError):
    pass


class _SyslogTCPFramer:
    """Incremental RFC6587/newline syslog stream framer.

    The framing mode is selected from the first frame and then remains fixed
    for the connection.  Octet-counted frames are never emitted partially;
    newline-framed connections may emit one final unterminated frame at EOF,
    matching common one-message-per-connection senders.
    """

    def __init__(self, max_frame_bytes=MAX_SYSLOG_FRAME_BYTES):
        self.max_frame_bytes = int(max_frame_bytes)
        if self.max_frame_bytes < 1:
            raise ValueError("max_frame_bytes must be positive")
        self.buffer = b""
        self.mode = None

    def _select_mode(self, eof=False):
        if self.mode is not None or not self.buffer:
            return
        # RFC6587 octet counting: MSG-LEN SP SYSLOG-MSG.  Wait briefly for a
        # partial decimal prefix, but do not let an arbitrary digit-starting
        # line stall forever once it is clearly not an octet-count prefix.
        m = re.match(rb"^([1-9][0-9]{0,9}) ", self.buffer)
        if m:
            self.mode = "octet"
            return
        if self.buffer[:1].isdigit() and b"\n" not in self.buffer:
            prefix = self.buffer.split(b" ", 1)[0]
            if prefix.isdigit() and len(prefix) <= 10 and not eof:
                return
        self.mode = "newline"

    def feed(self, chunk=b"", eof=False):
        if chunk:
            self.buffer += bytes(chunk)
        frames = []
        self._select_mode(eof=eof)

        if self.mode == "octet":
            while self.buffer:
                m = re.match(rb"^([1-9][0-9]{0,9}) ", self.buffer)
                if not m:
                    # A connection that selected octet counting cannot switch
                    # framing mid-stream without risking message-boundary
                    # confusion.
                    if eof or len(self.buffer) > 11:
                        raise _TCPFramingError("invalid RFC6587 octet-count prefix")
                    break
                size = int(m.group(1))
                if size > self.max_frame_bytes:
                    raise _TCPFramingError("RFC6587 frame exceeds maximum size")
                start = m.end()
                end = start + size
                if len(self.buffer) < end:
                    if eof:
                        raise _TCPFramingError("truncated RFC6587 octet-counted frame")
                    break
                frame = self.buffer[start:end]
                self.buffer = self.buffer[end:]
                if frame.strip():
                    frames.append(frame)
            return frames

        if self.mode == "newline":
            while b"\n" in self.buffer:
                frame, self.buffer = self.buffer.split(b"\n", 1)
                if len(frame) > self.max_frame_bytes:
                    raise _TCPFramingError("newline-framed syslog message exceeds maximum size")
                if frame.strip():
                    frames.append(frame)
            if len(self.buffer) > self.max_frame_bytes:
                raise _TCPFramingError("unterminated syslog message exceeds maximum size")
            if eof and self.buffer.strip():
                frames.append(self.buffer)
                self.buffer = b""
            return frames

        # A short, incomplete numeric prefix can remain undecided until more
        # data arrives.  It is bounded here even before framing is selected.
        if len(self.buffer) > self.max_frame_bytes + 11:
            raise _TCPFramingError("undecided syslog frame exceeds maximum size")
        if eof and self.buffer:
            self._select_mode(eof=True)
            return self.feed(b"", eof=True)
        return frames


def _handle_tcp_client(conn: socket.socket, addr, on_message):
    framer = _SyslogTCPFramer()
    with conn:
        while True:
            try:
                chunk = conn.recv(65535)
            except Exception:
                break
            if not chunk:
                try:
                    for frame in framer.feed(eof=True):
                        on_message(frame.decode("utf-8", errors="replace"), addr[0])
                except _TCPFramingError as exc:
                    print(f"[tcp] framing error from {addr[0]}: {exc}", file=sys.stderr)
                break
            try:
                for frame in framer.feed(chunk):
                    on_message(frame.decode("utf-8", errors="replace"), addr[0])
            except _TCPFramingError as exc:
                print(f"[tcp] framing error from {addr[0]}: {exc}", file=sys.stderr)
                break


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
# Cross-process runtime heartbeat
# --------------------------------------------------------------------------

class ListenerRuntimeReporter:
    """Publish bounded listener health into runtime_stats for the Web Console."""

    def __init__(self, db_config, interval=2.0):
        self.db_config = db_config
        self.interval = max(1.0, float(interval))
        self.started = time.time()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = []
        self._stats = {
            "processed_events": 0, "failed_events": 0,
            "dropped_events": 0, "dropped_udp": 0,
            "last_event_at": None, "detail": "starting",
        }
        # Bounded per-peer counters support Setup > Troubleshoot correlation
        # without storing payloads in runtime health telemetry.
        self._sources = {}
        self._thread = threading.Thread(target=self._run, daemon=True, name="runtime-health")

    def set_threads(self, threads):
        self._threads = list(threads or [])

    def start(self):
        self._write()
        self._thread.start()

    def _record_source(self, source_ip, field):
        if not source_ip:
            return
        now = datetime.now(timezone.utc).isoformat()
        entry = self._sources.setdefault(str(source_ip), {"accepted": 0, "failed": 0, "last_seen": now})
        entry[field] = int(entry.get(field) or 0) + 1
        entry["last_seen"] = now
        if len(self._sources) > 64:
            oldest = sorted(self._sources, key=lambda key: self._sources[key].get("last_seen") or "")[:16]
            for key in oldest:
                self._sources.pop(key, None)

    def record_success(self, event_at=None, source_ip=None):
        with self._lock:
            self._stats["processed_events"] += 1
            self._stats["last_event_at"] = event_at or datetime.now(timezone.utc).isoformat()
            self._stats["detail"] = ""
            self._record_source(source_ip, "accepted")

    def record_failure(self, exc=None, source_ip=None):
        with self._lock:
            self._stats["failed_events"] += 1
            self._record_source(source_ip, "failed")
            if exc is not None:
                self._stats["detail"] = f"last ingest error: {type(exc).__name__}"

    def snapshot(self):
        with self._lock:
            payload = dict(self._stats)
            payload["sources"] = {key: dict(value) for key, value in self._sources.items()}
        alive = [t.is_alive() for t in self._threads]
        if not alive:
            listener_state = "STARTING"
        elif all(alive):
            listener_state = "READY"
        elif any(alive):
            listener_state = "DEGRADED"
        else:
            listener_state = "FAILED"
        payload.update({
            "database": "READY",
            "listener": listener_state,
            "ingest": "RUNNING" if listener_state == "READY" else listener_state,
            "worker": "DIRECT",
            "queue_depth": 0,
            "uptime_seconds": round(max(0.0, time.time() - self.started), 1),
            "heartbeat_at": datetime.now(timezone.utc).isoformat(),
        })
        return payload

    def _write(self):
        payload = self.snapshot()
        conn = None
        try:
            conn = dbmod.connect(self.db_config)
            dbmod.runtime_stat_upsert(
                conn, "listener_health", value_text=json.dumps(payload, separators=(",", ":"), sort_keys=True),
                updated_at=payload["heartbeat_at"],
            )
            conn.commit()
        except Exception as exc:
            print(f"[health] heartbeat write failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def _run(self):
        while not self._stop.wait(self.interval):
            self._write()

    def stop(self):
        self._stop.set()
        self._write()
        if self._thread.is_alive():
            self._thread.join(timeout=1)


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
    ap.add_argument("--db-credentials", default=None, help="PostgreSQL component credential overlay (user/password only)")
    args = ap.parse_args()

    db_cfg = dbmod.load_config(args.db_config, sqlite_fallback=args.db,
                               credentials_path=args.db_credentials)
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
    runtime_reporter = ListenerRuntimeReporter(db_cfg)

    def on_message(raw: str, source_ip: str):
        try:
            event = parse_syslog(raw, source_ip)
            extracted_fields = fields.extract(event)
            log_id = storage.insert_log(event, fields=extracted_fields)
            # Preserve unidentified-source diagnostics without a second write
            # path; raw/log_fields/security_events were committed together.
            try:
                fields._maybe_capture_unidentified(log_id, event, len(extracted_fields))
            except Exception:
                pass
            engine.process(log_id, event)
            ioc.process(log_id, event)
            forwarders.forward(event)  # relay the original raw message downstream
            runtime_reporter.record_success(event.get("received_at"), source_ip=source_ip)
            sev = event["severity"] or "-"
            print(f"[{event['received_at']}] {source_ip} [{sev}] {event['message'][:120]}")
        except Exception as exc:
            runtime_reporter.record_failure(exc, source_ip=source_ip)
            raise

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
    runtime_reporter.set_threads(threads)
    runtime_reporter.start()

    print(f"mini-SIEM listener running. DB: {args.db}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        runtime_reporter.stop()


if __name__ == "__main__":
    main()

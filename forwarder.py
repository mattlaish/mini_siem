"""
mini-SIEM syslog forwarder
===========================
Relays the ORIGINAL raw syslog message (exactly as received, before any
parsing) to one or more downstream syslog receivers, in addition to the
normal store-and-correlate pipeline.

Configuration lives in the `forwarders` table in the shared SQLite DB
and is edited from the dashboard's /setup page. The ForwarderManager
running inside listener.py hot-reloads that table every few seconds,
so adding/toggling/removing a destination takes effect without
restarting the listener.

Per-destination options:
  protocol        udp or tcp (tcp uses newline framing, auto-reconnects)
  min_severity    only forward events at or above this syslog severity
                  (events whose severity couldn't be parsed are treated
                  as informational)
  filter_pattern  optional regex; only messages matching it are forwarded

Delivery semantics match syslog norms: UDP is fire-and-forget; TCP
failures set last_error and drop the message (no buffering/replay).
"""

import re
import socket
import threading
import time
from datetime import datetime, timezone

import severity as severity_mod

SEVERITY_ORDER = severity_mod.ORDER  # canonical name -> index (0 = most severe)


# --------------------------------------------------------------------------
# Origin preservation
# --------------------------------------------------------------------------
# A relay hides the original sender: the downstream collector sees packets
# coming from the SIEM, not from the device. These helpers put the origin
# back INTO the message, which works over both UDP and TCP and needs no
# raw sockets / root (unlike source-IP spoofing).
#
#   hostname : fill the syslog HOSTNAME field when the device left it
#              empty ("-" or absent). RFC 3164/5424 both prescribe this
#              behavior for relays. No-op when a hostname is present.
#   sd       : attach an [origin ip="..."] structured-data element, so
#              attribution is always present and machine-parseable even
#              when the device DID send a hostname.
#   both     : do both.

def _sd_escape(v: str) -> str:
    """Escape a structured-data PARAM-VALUE per RFC 5424 (\\ " ])."""
    return (str(v).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]"))


def _fill_hostname(raw: str, event: dict, origin_ip: str) -> str:
    """Insert the sender's IP as HOSTNAME only when the message lacks one."""
    have = (event.get("hostname") or "").strip()
    if have and have != "-":
        return raw                      # device sent a hostname; leave it alone
    fmt = event.get("format")
    if fmt == "rfc5424":
        # <PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID SD MSG
        parts = raw.split(" ", 3)
        if len(parts) >= 3 and parts[2] in ("-", ""):
            parts[2] = origin_ip
            return " ".join(parts)
        return raw
    if fmt == "rfc3164":
        # <PRI>MMM dd hh:mm:ss HOSTNAME TAG: msg  — the regex only matches
        # when a hostname token exists, so an empty one is rare; insert
        # after the 3-token timestamp when it happens.
        import re as _re
        m = _re.match(r"^(<\d+>)(\w{3}\s+\d+\s[\d:]{8})\s+(.*)$", raw)
        if m:
            return f"{m.group(1)}{m.group(2)} {origin_ip} {m.group(3)}"
        return raw
    # non-conformant: no reliable structure to edit; sd mode covers these
    return raw


def _attach_origin_sd(raw: str, event: dict, origin_ip: str) -> str:
    """Attach [origin ip="..."] so attribution survives even when the
    device supplied its own hostname."""
    sd = f'[origin ip="{_sd_escape(origin_ip)}"]'
    if event.get("format") == "rfc5424":
        # SD is field 7; replace a NILVALUE "-" or prepend to existing SD.
        parts = raw.split(" ", 6)
        if len(parts) == 7:
            rest = parts[6]
            if rest.startswith("- "):
                parts[6] = sd + rest[1:]
                return " ".join(parts)
            if rest.startswith("["):
                parts[6] = sd + rest       # concatenated SD elements are legal
                return " ".join(parts)
        return raw + " " + sd
    # RFC 3164 and non-conformant messages have no SD field — append,
    # which keeps the original text intact and readable.
    return raw + " " + sd


def apply_origin(raw: str, event: dict, mode: str) -> str:
    """Return the message to relay, with origin info applied per `mode`."""
    mode = (mode or "off").lower()
    if mode == "off":
        return raw
    # peer_ip is the true network sender; source_ip may have been
    # overwritten by a src= field inside the message text.
    origin_ip = event.get("peer_ip") or event.get("source_ip") or ""
    if not origin_ip:
        return raw
    out = raw
    if mode in ("hostname", "both"):
        out = _fill_hostname(out, event, origin_ip)
    if mode in ("sd", "both"):
        out = _attach_origin_sd(out, event, origin_ip)
    return out


class _RuntimeForwarder:
    """Runtime state (sockets, counters) for one forwarder config row."""

    def __init__(self, row: dict):
        self.id = row["id"]
        self.name = row["name"]
        self.host = row["host"]
        self.port = int(row["port"])
        self.protocol = (row["protocol"] or "udp").lower()
        self.enabled = bool(row["enabled"])
        self.filter_pattern = row.get("filter_pattern") or ""
        self.min_severity = (row.get("min_severity") or "").lower()
        self.origin_mode = (row.get("origin_mode") or "off").lower()
        self.tcp_framing = (row.get("tcp_framing") or "newline").lower()
        self._regex = re.compile(self.filter_pattern, re.IGNORECASE) if self.filter_pattern else None
        self._tcp_sock = None
        # in-memory counters, flushed to DB periodically
        self.pending_count = 0
        self.last_forward_at = None
        self.last_error = None

    def config_signature(self):
        return (self.name, self.host, self.port, self.protocol,
                self.enabled, self.filter_pattern, self.min_severity,
                self.origin_mode, self.tcp_framing)

    # -- filtering ---------------------------------------------------------

    def wants(self, event: dict) -> bool:
        if not self.enabled:
            return False
        min_canon = severity_mod.normalize(self.min_severity)
        if min_canon:
            ev_sev = severity_mod.index_of(event.get("severity"))
            if ev_sev > SEVERITY_ORDER[min_canon]:
                return False
        if self._regex and not self._regex.search(event.get("raw") or ""):
            return False
        return True

    # -- sending -----------------------------------------------------------

    def send(self, raw: str, udp_sock: socket.socket):
        try:
            if self.protocol == "tcp":
                self._send_tcp(raw)
            else:
                udp_sock.sendto(raw.encode("utf-8", errors="replace"), (self.host, self.port))
            self.pending_count += 1
            self.last_forward_at = datetime.now(timezone.utc).isoformat()
            self.last_error = None
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._close_tcp()

    def _send_tcp(self, raw: str):
        if self._tcp_sock is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.host, self.port))
            self._tcp_sock = s
        payload = raw.encode("utf-8", errors="replace")
        if self.tcp_framing == "octet":
            # RFC 6587 octet-counting: "<byte-length> <message>" with no
            # trailing delimiter; the receiver reads exactly that many bytes.
            framed = f"{len(payload)} ".encode("ascii") + payload
        else:
            # non-transparent framing: LF-delimited (legacy default).
            framed = payload + b"\n"
        self._tcp_sock.sendall(framed)

    def _close_tcp(self):
        if self._tcp_sock is not None:
            try:
                self._tcp_sock.close()
            except OSError:
                pass
            self._tcp_sock = None


class ForwarderManager:
    """Hot-reloads forwarder config from the DB and fans each received
    raw syslog message out to every matching destination."""

    def __init__(self, storage, listen_port: int, reload_interval: int = 5,
                 flush_interval: int = 10):
        self.storage = storage
        self.listen_port = listen_port
        self.reload_interval = reload_interval
        self.flush_interval = flush_interval
        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._forwarders = {}   # id -> _RuntimeForwarder
        self._warned_loops = set()  # forwarder ids already warned about
        self._fw_lock = threading.Lock()
        self._reload()
        t = threading.Thread(target=self._background_loop, daemon=True)
        t.start()

    # -- public API ----------------------------------------------------------

    def forward(self, event: dict):
        raw = event.get("raw")
        if not raw:
            return
        with self._fw_lock:
            targets = [fw for fw in self._forwarders.values() if fw.wants(event)]
        for fw in targets:
            # per-destination: byte-faithful passthrough, or origin-annotated
            fw.send(apply_origin(raw, event, fw.origin_mode), self._udp_sock)

    # -- config reload + stats flush ------------------------------------------

    def _background_loop(self):
        last_flush = time.time()
        while True:
            time.sleep(self.reload_interval)
            try:
                self._reload()
            except Exception as exc:
                print(f"[forwarder] config reload failed: {exc}")
            if time.time() - last_flush >= self.flush_interval:
                try:
                    self._flush_stats()
                except Exception as exc:
                    print(f"[forwarder] stats flush failed: {exc}")
                last_flush = time.time()

    def _is_self_loop(self, row: dict) -> bool:
        return (row["host"] in ("127.0.0.1", "localhost", "::1")
                and int(row["port"]) == self.listen_port)

    def _reload(self):
        with self.storage.lock:
            rows = [dict(r) for r in self.storage.conn.execute(
                """SELECT id, name, host, port, protocol, enabled,
                          filter_pattern, min_severity, origin_mode, tcp_framing
                   FROM forwarders"""
            ).fetchall()]

        with self._fw_lock:
            seen_ids = set()
            for row in rows:
                if self._is_self_loop(row):
                    if row["id"] in self._forwarders:
                        del self._forwarders[row["id"]]
                    if row["id"] not in self._warned_loops:
                        self._warned_loops.add(row["id"])
                        print(f"[forwarder] skipping '{row['name']}': points at this "
                              f"listener's own port ({row['host']}:{row['port']}) — "
                              f"that would create a forwarding loop")
                    continue
                seen_ids.add(row["id"])
                existing = self._forwarders.get(row["id"])
                candidate = _RuntimeForwarder(row)
                if existing is None:
                    self._forwarders[row["id"]] = candidate
                    print(f"[forwarder] loaded '{candidate.name}' -> "
                          f"{candidate.protocol}://{candidate.host}:{candidate.port} "
                          f"(enabled={candidate.enabled})")
                elif existing.config_signature() != candidate.config_signature():
                    # carry over unflushed counters, drop stale sockets
                    candidate.pending_count = existing.pending_count
                    candidate.last_forward_at = existing.last_forward_at
                    existing._close_tcp()
                    self._forwarders[row["id"]] = candidate
                    print(f"[forwarder] reloaded '{candidate.name}'")
            # remove deleted forwarders
            for fw_id in list(self._forwarders):
                if fw_id not in seen_ids:
                    self._forwarders[fw_id]._close_tcp()
                    print(f"[forwarder] removed '{self._forwarders[fw_id].name}'")
                    del self._forwarders[fw_id]

    def _flush_stats(self):
        with self._fw_lock:
            snapshots = [
                (fw.pending_count, fw.last_forward_at, fw.last_error, fw.id)
                for fw in self._forwarders.values()
                if fw.pending_count or fw.last_error or fw.last_forward_at
            ]
            for fw in self._forwarders.values():
                fw.pending_count = 0
        if not snapshots:
            return
        with self.storage.lock:
            for count, last_at, last_err, fw_id in snapshots:
                self.storage.conn.execute(
                    """UPDATE forwarders
                       SET forwarded_count = forwarded_count + ?,
                           last_forward_at = COALESCE(?, last_forward_at),
                           last_error = ?
                       WHERE id = ?""",
                    (count, last_at, last_err, fw_id),
                )
            self.storage.conn.commit()

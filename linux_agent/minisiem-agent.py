#!/usr/bin/env python3
"""
mini-SIEM Linux agent
=====================
Ships logs from a Linux host to mini-SIEM as RFC3164 syslog over UDP or TCP.

Sources:
  * journald  — via `journalctl -o json --follow`, using the cursor to resume
                exactly where it left off across restarts. journald's numeric
                PRIORITY maps 1:1 onto syslog severity, so severities arrive
                correct rather than guessed.
  * log files — tail-follow arbitrary files (e.g. /var/log/nginx/access.log)
                with byte offsets persisted, and rotation/truncation detection.
  * heartbeat — a periodic informational event so the SIEM's "silent sources"
                card can tell "host is fine and quiet" from "host is gone".

Design notes:
  * stdlib only — no pip installs on the endpoint.
  * State (journald cursor + file offsets) is persisted so a restart doesn't
    replay or skip events.
  * UDP is fire-and-forget; TCP reconnects with backoff and never blocks the
    reader loop forever.
  * Long messages are truncated to a configurable limit (syslog receivers
    commonly cap around 2048; the SIEM listener accepts more, but keep it sane).
  * The agent never executes anything from the log content it reads.

Usage:
  ./minisiem-agent.py --config agent-config.json
  ./minisiem-agent.py --config agent-config.json --test   # send one test event and exit
  ./minisiem-agent.py --config agent-config.json --dry-run  # print, don't send
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

DEFAULT_CONFIG = {
    "siem_host": "10.0.0.10",
    "siem_port": 514,
    "protocol": "udp",                # udp | tcp
    "facility": 16,                   # local0
    "hostname": "",                  # "" = use system hostname
    "max_message_bytes": 1800,
    "state_file": "/var/lib/mini-siem-agent/state.json",

    "journald": {
        "enabled": True,
        "units": [],                  # [] = all units; else ["sshd.service", ...]
        "min_priority": 6,            # 0=emerg .. 7=debug ; 6 = informational and above
        "extra_args": []             # e.g. ["--dmesg"]
    },

    "files": {
        "enabled": False,
        "poll_seconds": 2,
        "paths": []                  # [{"path": "/var/log/nginx/error.log", "app_name": "nginx"}]
    },

    "heartbeat_minutes": 15
}

# journald PRIORITY -> syslog severity (identical numbering, 0..7)
PRIORITY_NAMES = ["emergency", "alert", "critical", "error",
                  "warning", "notice", "informational", "debug"]

# crude severity guess for plain log files (only used when a file line has no
# obvious structure; the SIEM re-derives severity from text anyway)
_SEV_PATTERNS = [
    (re.compile(r"\b(emerg|panic)\b", re.I), 0),
    (re.compile(r"\balert\b", re.I), 1),
    (re.compile(r"\b(crit|critical|fatal)\b", re.I), 2),
    (re.compile(r"\b(err|error|fail(ed|ure)?)\b", re.I), 3),
    (re.compile(r"\bwarn(ing)?\b", re.I), 4),
    (re.compile(r"\bnotice\b", re.I), 5),
    (re.compile(r"\bdebug\b", re.I), 7),
]


def guess_severity(line: str) -> int:
    for pat, sev in _SEV_PATTERNS:
        if pat.search(line):
            return sev
    return 6  # informational


def log(msg: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

class Sender:
    """UDP or TCP syslog sender. TCP reconnects with backoff; UDP is stateless."""

    def __init__(self, host, port, protocol="udp", dry_run=False):
        self.host = host
        self.port = int(port)
        self.protocol = protocol.lower()
        self.dry_run = dry_run
        self.sock = None
        self.lock = threading.Lock()
        self._backoff = 1
        self.sent = 0
        self.failed = 0

    def _connect_tcp(self):
        s = socket.create_connection((self.host, self.port), timeout=10)
        s.settimeout(10)
        return s

    def send(self, line: str):
        if self.dry_run:
            print(line)
            self.sent += 1
            return True
        data = line.encode("utf-8", "replace")
        with self.lock:
            try:
                if self.protocol == "tcp":
                    if self.sock is None:
                        self.sock = self._connect_tcp()
                        self._backoff = 1
                    # RFC6587 octet-counting is safer, but LF-delimited is what
                    # the SIEM listener reads; keep it simple and newline-framed.
                    self.sock.sendall(data + b"\n")
                else:
                    if self.sock is None:
                        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.sock.sendto(data, (self.host, self.port))
                self.sent += 1
                return True
            except Exception as exc:
                self.failed += 1
                try:
                    if self.sock:
                        self.sock.close()
                except Exception:
                    pass
                self.sock = None
                log(f"send failed ({type(exc).__name__}: {exc}); backing off {self._backoff}s")
                time.sleep(min(self._backoff, 30))
                self._backoff = min(self._backoff * 2, 30)
                return False

    def close(self):
        with self.lock:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None


# ---------------------------------------------------------------------------
# Message formatting (RFC3164)
# ---------------------------------------------------------------------------

def format_syslog(facility: int, severity: int, hostname: str, app: str,
                  pid, message: str, max_bytes: int) -> str:
    pri = facility * 8 + severity
    # RFC3164 timestamp: "Mmm dd hh:mm:ss" with space-padded day
    ts = datetime.now().strftime("%b %e %H:%M:%S")
    if len(ts) == 14:  # some platforms don't space-pad %e
        ts = ts[:4] + " " + ts[4:]
    tag = (app or "agent")[:32]
    proc = f"[{pid}]" if pid else ""
    # collapse newlines: one syslog line per event
    message = " ".join(str(message).splitlines()).strip()
    line = f"<{pri}>{ts} {hostname} {tag}{proc}: {message}"
    b = line.encode("utf-8", "replace")
    if len(b) > max_bytes:
        line = b[:max_bytes - 3].decode("utf-8", "ignore") + "..."
    return line


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class State:
    def __init__(self, path):
        self.path = path
        self.data = {"cursor": None, "files": {}}
        self.lock = threading.Lock()
        self.load()

    def load(self):
        try:
            with open(self.path) as f:
                self.data.update(json.load(f))
            log(f"state loaded from {self.path}")
        except FileNotFoundError:
            pass
        except Exception as exc:
            log(f"could not read state ({exc}); starting fresh")

    def save(self):
        with self.lock:
            try:
                os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                tmp = self.path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(self.data, f)
                os.replace(tmp, self.path)   # atomic
            except Exception as exc:
                log(f"could not save state: {exc}")


# ---------------------------------------------------------------------------
# journald reader
# ---------------------------------------------------------------------------

def journald_loop(cfg, sender, state, stop):
    jcfg = cfg["journald"]
    hostname = cfg["_hostname"]
    args = ["journalctl", "-o", "json", "--follow", "--no-pager"]
    cursor = state.data.get("cursor")
    if cursor:
        args += ["--after-cursor", cursor]
        log("resuming journald from saved cursor")
    else:
        args += ["-n", "0"]   # only new entries on first run
    for unit in jcfg.get("units") or []:
        args += ["-u", unit]
    args += list(jcfg.get("extra_args") or [])
    min_pri = int(jcfg.get("min_priority", 6))

    log(f"journald: starting ({' '.join(args[:6])}…)")
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except FileNotFoundError:
        log("journald: journalctl not found — is this a systemd host? disabling journald source")
        return

    saved = 0
    try:
        for raw in proc.stdout:
            if stop.is_set():
                break
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            try:
                pri = int(entry.get("PRIORITY", 6))
            except (TypeError, ValueError):
                pri = 6
            if pri > min_pri:
                continue
            msg = entry.get("MESSAGE", "")
            if isinstance(msg, list):   # journald can return byte arrays
                try:
                    msg = bytes(msg).decode("utf-8", "replace")
                except Exception:
                    msg = str(msg)
            app = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or "journald"
            pid = entry.get("_PID") or entry.get("SYSLOG_PID")
            line = format_syslog(cfg["facility"], pri, hostname, app, pid,
                                 msg, cfg["max_message_bytes"])
            sender.send(line)
            cur = entry.get("__CURSOR")
            if cur:
                state.data["cursor"] = cur
                saved += 1
                if saved % 20 == 0:
                    state.save()
    finally:
        state.save()
        try:
            proc.terminate()
        except Exception:
            pass
        log("journald: stopped")


# ---------------------------------------------------------------------------
# file tailer
# ---------------------------------------------------------------------------

def file_loop(cfg, sender, state, stop):
    fcfg = cfg["files"]
    hostname = cfg["_hostname"]
    poll = float(fcfg.get("poll_seconds", 2))
    specs = fcfg.get("paths") or []
    if not specs:
        return
    log(f"files: watching {len(specs)} path(s)")

    # on first sight of a file, start at the END (don't replay history)
    for spec in specs:
        p = spec["path"]
        if p not in state.data["files"]:
            try:
                state.data["files"][p] = {"offset": os.path.getsize(p), "inode": os.stat(p).st_ino}
            except OSError:
                state.data["files"][p] = {"offset": 0, "inode": None}
    state.save()

    while not stop.is_set():
        for spec in specs:
            path = spec["path"]
            app = spec.get("app_name") or os.path.basename(path)
            st = state.data["files"].setdefault(path, {"offset": 0, "inode": None})
            try:
                sres = os.stat(path)
            except OSError:
                continue  # file gone (rotated away); pick it up when it returns
            # rotation / truncation detection
            if st.get("inode") not in (None, sres.st_ino) or sres.st_size < st["offset"]:
                log(f"files: {path} rotated/truncated — resuming from start")
                st["offset"] = 0
            st["inode"] = sres.st_ino
            if sres.st_size == st["offset"]:
                continue
            try:
                with open(path, "r", errors="replace") as f:
                    f.seek(st["offset"])
                    # NOTE: use readline(), not `for line in f` — Python disables
                    # tell() during iteration, so offsets would never advance and
                    # every line would be re-sent on each poll.
                    while True:
                        pos = f.tell()
                        line = f.readline()
                        if not line:
                            break
                        if not line.endswith("\n"):
                            f.seek(pos)      # partial line; wait for the rest
                            break
                        line = line.rstrip("\n")
                        if line.strip():
                            sender.send(format_syslog(
                                cfg["facility"], guess_severity(line), hostname,
                                app, None, line, cfg["max_message_bytes"]))
                        st["offset"] = f.tell()
            except OSError as exc:
                log(f"files: cannot read {path}: {exc}")
                continue
        state.save()
        stop.wait(poll)
    log("files: stopped")


# ---------------------------------------------------------------------------
# heartbeat
# ---------------------------------------------------------------------------

def heartbeat_loop(cfg, sender, stop):
    minutes = int(cfg.get("heartbeat_minutes", 15))
    if minutes <= 0:
        return
    hostname = cfg["_hostname"]
    while not stop.is_set():
        line = format_syslog(cfg["facility"], 6, hostname, "minisiem-agent", None,
                             f"agent heartbeat status=alive sent={sender.sent} failed={sender.failed}",
                             cfg["max_message_bytes"])
        sender.send(line)
        stop.wait(minutes * 60)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if path and os.path.exists(path):
        with open(path) as f:
            user = json.load(f)
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    cfg["_hostname"] = cfg.get("hostname") or socket.gethostname()
    return cfg


def main():
    ap = argparse.ArgumentParser(description="mini-SIEM Linux agent")
    ap.add_argument("--config", default="/etc/mini-siem-agent/agent-config.json")
    ap.add_argument("--test", action="store_true", help="send one test event and exit")
    ap.add_argument("--dry-run", action="store_true", help="print events instead of sending")
    args = ap.parse_args()

    cfg = load_config(args.config)
    sender = Sender(cfg["siem_host"], cfg["siem_port"], cfg["protocol"], dry_run=args.dry_run)
    log(f"mini-SIEM agent -> {cfg['siem_host']}:{cfg['siem_port']}/{cfg['protocol']} "
        f"as host '{cfg['_hostname']}'")

    if args.test:
        line = format_syslog(cfg["facility"], 5, cfg["_hostname"], "minisiem-agent", None,
                             "agent test event — if you see this in the SIEM, the agent works",
                             cfg["max_message_bytes"])
        ok = sender.send(line)
        log(f"test event {'sent' if ok else 'FAILED'}: {line}")
        sender.close()
        return 0 if ok else 1

    state = State(cfg["state_file"])
    stop = threading.Event()
    threads = []

    # systemd stops services with SIGTERM; without a handler Python exits
    # immediately and the journald cursor / file offsets are never persisted,
    # causing replayed or skipped events on the next start.
    import signal

    def _shutdown(signum, _frame):
        log(f"signal {signum} received — flushing state and stopping")
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    if cfg["journald"].get("enabled"):
        threads.append(threading.Thread(target=journald_loop,
                                        args=(cfg, sender, state, stop), daemon=True))
    if cfg["files"].get("enabled"):
        threads.append(threading.Thread(target=file_loop,
                                        args=(cfg, sender, state, stop), daemon=True))
    threads.append(threading.Thread(target=heartbeat_loop,
                                    args=(cfg, sender, stop), daemon=True))
    for t in threads:
        t.start()

    try:
        while not stop.is_set() and any(t.is_alive() for t in threads):
            stop.wait(0.5)
    except KeyboardInterrupt:
        log("shutting down…")
    finally:
        stop.set()
        # give the journald reader a moment to break out of its read loop
        for t in threads:
            t.join(timeout=2)
        state.save()
        sender.close()
        log(f"stopped. sent={sender.sent} failed={sender.failed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

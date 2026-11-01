#!/usr/bin/env python3
"""Constrained syslog packet-capture helper for Setup -> Troubleshoot.

Installed root-owned outside the project tree by install-services.sh and invoked
through a narrowly-scoped sudoers rule.  The caller can supply only one source
IP and a bounded duration.  Capture ports come from the root-owned helper
configuration; arbitrary tcpdump expressions are never accepted.

No payload bytes are requested or returned.  tcpdump output is limited to
packet headers/summaries for the configured syslog listener ports.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

HELPER_CONFIG = Path("/etc/mini-siem/syslog-capture.json")
MAX_SECONDS = 5
MAX_PACKETS = 50
MAX_SAMPLES = 8


def _fail(message: str, code: int = 1) -> int:
    print(json.dumps({"ok": False, "error": message}))
    return code


def _load_ports() -> list[int]:
    try:
        cfg = json.loads(HELPER_CONFIG.read_text(encoding="utf-8"))
        db_config_path = Path(str(cfg["db_config_path"]))
        db_cfg = json.loads(db_config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(f"capture configuration unavailable: {exc}") from exc

    raw_ports = db_cfg.get("listen_ports") or [514]
    ports: list[int] = []
    for value in raw_ports:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    if not ports:
        ports = [514]
    return ports


def _filter_tokens(source_ip: str, ports: list[int]) -> list[str]:
    port_terms: list[str] = []
    for port in ports:
        if port_terms:
            port_terms.append("or")
        port_terms.extend(["dst", "port", str(port)])
    return ["src", "host", source_ip, "and", "(", "udp", "or", "tcp", ")",
            "and", "(", *port_terms, ")"]


def _summarize(lines: list[str]) -> dict:
    udp = 0
    tcp = 0
    for line in lines:
        upper = line.upper()
        if " UDP" in upper or "UDP," in upper:
            udp += 1
        elif "FLAGS [" in upper or "TCP" in upper:
            tcp += 1
    return {
        "packets": len(lines),
        "udp_packets": udp,
        "tcp_packets": tcp,
        "samples": lines[:MAX_SAMPLES],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Bounded mini-SIEM syslog packet capture")
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--seconds", type=int, default=4)
    args = parser.parse_args(argv)

    try:
        source = str(ipaddress.ip_address(args.source_ip.strip()))
    except ValueError:
        return _fail("source IP is not a valid IPv4 or IPv6 address", 2)
    if not 1 <= args.seconds <= MAX_SECONDS:
        return _fail(f"seconds must be between 1 and {MAX_SECONDS}", 2)

    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return _fail("tcpdump is not installed on the SIEM host")

    try:
        ports = _load_ports()
    except RuntimeError as exc:
        return _fail(str(exc))

    command = [
        tcpdump, "-nn", "-q", "-l", "-s", "96", "-i", "any", "-c", str(MAX_PACKETS),
        *_filter_tokens(source, ports),
    ]
    started = time.monotonic()
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=args.seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=1)

    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if proc.returncode not in (0, -15) and not timed_out and not lines:
        err = " ".join(stderr.strip().splitlines()[-2:])[:300]
        return _fail(err or f"tcpdump exited with status {proc.returncode}")

    summary = _summarize(lines)
    print(json.dumps({
        "ok": True,
        "source_ip": source,
        "ports": ports,
        "duration_seconds": round(time.monotonic() - started, 2),
        "seen": bool(lines),
        **summary,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

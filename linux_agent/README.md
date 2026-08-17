# mini-SIEM Linux agent

Ships logs from a Linux host to mini-SIEM as RFC3164 syslog (UDP or TCP).

Unlike the Windows agent, **this one has been executed and tested** — file
tailing, journald reading, state persistence, rotation handling, SIGTERM
shutdown, and end-to-end delivery into the SIEM's database were all run for
real. Two genuine bugs were caught and fixed that way (duplicate-flooding on
file tails, and lost cursors on `systemctl stop`).

## What it collects

| Source | How | Notes |
|---|---|---|
| **journald** | `journalctl -o json --follow` | Resumes exactly where it left off via the journal cursor. journald's numeric `PRIORITY` maps 1:1 onto syslog severity, so severities are *correct*, not guessed. |
| **Log files** | tail-follow with byte offsets | Detects rotation (rename) and truncation (`copytruncate`). Never replays history on first sight of a file. |
| **Heartbeat** | periodic event | Lets the SIEM's "Silent sources" card distinguish *host is fine and quiet* from *host is gone*. |

## Install

From this directory, on the host you want to monitor:

```bash
sudo ./install-linux-agent.sh --siem-host 10.0.0.10
# TCP instead of UDP:
sudo ./install-linux-agent.sh --siem-host 10.0.0.10 --tcp
# just verify connectivity, don't install the service:
sudo ./install-linux-agent.sh --siem-host 10.0.0.10 --test-only
```

This creates a system user `minisiem`, installs to `/opt/mini-siem-agent`,
writes `/etc/mini-siem-agent/agent-config.json`, sends a test event, then
enables a hardened systemd unit.

**The agent does not run as root.** It's added to the `systemd-journal` group
so it can read the journal, and the unit sets `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, and a 128 MB memory cap. It opens no
listening ports; it only sends.

```bash
journalctl -u minisiem-agent -f      # watch it
systemctl restart minisiem-agent     # after a config change
sudo ./install-linux-agent.sh --uninstall
```

## Configuration

`/etc/mini-siem-agent/agent-config.json`:

```jsonc
{
  "siem_host": "10.0.0.10",
  "siem_port": 514,
  "protocol": "udp",            // udp | tcp
  "hostname": "",               // "" = system hostname
  "facility": 16,               // 16 = local0

  "journald": {
    "enabled": true,
    "units": [],                // [] = everything; or ["sshd.service", "nginx.service"]
    "min_priority": 6           // 0=emerg … 7=debug; 6 keeps info and above
  },

  "files": {
    "enabled": false,
    "poll_seconds": 2,
    "paths": [
      { "path": "/var/log/nginx/error.log", "app_name": "nginx" }
    ]
  },

  "heartbeat_minutes": 15
}
```

The `minisiem` user must be able to **read** any file you add under `files`.
Check with `sudo -u minisiem head /var/log/whatever.log`.

## Manual run / debugging

```bash
# print events instead of sending them
python3 minisiem-agent.py --config agent-config.json --dry-run

# send one test event and exit (exit code 0 = sent)
python3 minisiem-agent.py --config agent-config.json --test
```

## Choosing a transport

- **UDP** (default) — fire-and-forget, no backpressure on the host, but
  delivery is not guaranteed and a "sent" result proves nothing. Fine on a
  LAN.
- **TCP** — reconnects with backoff, so bursts survive a SIEM restart. Use it
  across anything less reliable than a switch.

Neither is encrypted. If the logs cross an untrusted network, tunnel them
(WireGuard, stunnel, ssh -L) — the SIEM's syslog listener has no TLS.

## Do you even need an agent?

If the host already runs rsyslog or syslog-ng, forwarding is one line and no
extra process:

```
# /etc/rsyslog.d/99-minisiem.conf
*.*  @10.0.0.10:514        # @@ for TCP
```

Use this agent when you want journald cursors, per-file tailing, heartbeats,
or a host with no syslog daemon. Otherwise rsyslog is less to run.

## Resource use (measured on the test host, not estimated)

Measured on the test host: a single Python process at **~14 MB resident**
while tailing a file, effectively 0% CPU between events.
The `MemoryMax=128M` in the unit is a guard rail, not a target. On a legacy
box, raise `poll_seconds` and narrow `journald.units` if you want it quieter.

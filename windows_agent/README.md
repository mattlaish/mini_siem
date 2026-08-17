# mini-SIEM Windows Agent v2

A PowerShell agent with two collectors, each independently enabled:

1. **Event Log collector** — polls Windows Event Log channels
   (Security, System, Application, or any custom channel), converts new
   events to RFC5424 syslog, and forwards them to the mini-SIEM
   listener. Per-channel filtering by minimum level and Event ID
   include/exclude lists.
2. **Syslog relay** (optional) — listens on a local UDP port and relays
   every received syslog message **raw, byte-for-byte** to the SIEM.
   Useful when nearby devices can send syslog to the Windows box but
   can't reach the SIEM directly.

Pure Windows PowerShell 5.1+ — no dependencies to install.

```
windows_agent/
  MiniSiemAgent.ps1            the agent (v2)
  Install-ScheduledTask.ps1    registers it as an auto-restarting task at boot
  agent-config.json            configuration
```

## 1. Configure (agent-config.json)

```json
{
  "SiemHost": "10.0.0.10",          // mini-SIEM listener IP
  "SiemPort": 514,
  "Protocol": "UDP",                 // or "TCP" (reliable, see below)

  "EventLog": {
    "Enabled": true,
    "PollIntervalSeconds": 10,
    "BatchSizePerChannel": 500,
    "Channels": [
      { "Name": "Security" },                                   // everything
      { "Name": "System",      "MinimumLevel": "Warning" },     // Warning + Error + Critical
      { "Name": "Application", "MinimumLevel": "Warning",
        "ExcludeEventIds": [1001] },                            // ...minus noisy 1001s
      { "Name": "Microsoft-Windows-PowerShell/Operational",
        "IncludeEventIds": [4103, 4104] }                       // only script-block logging
    ]
  },

  "SyslogRelay": {
    "Enabled": false,                // set true to relay syslog from other devices
    "ListenAddress": "0.0.0.0",
    "ListenPort": 514
  },

  "Facility": 16,                    // syslog facility (16 = local0)
  "HeartbeatMinutes": 15,            // periodic "I'm alive + counters" message (0 = off)
  "StateFilePath": "C:\\ProgramData\\mini-siem-agent\\state.json",
  "LogFilePath": "C:\\ProgramData\\mini-siem-agent\\agent.log",
  "MaxLogFileSizeMB": 10             // agent.log rotates to agent.log.1 at this size
}
```

Channel filter reference:
- `MinimumLevel`: `Critical`, `Error`, `Warning`, `Information`, or
  `Verbose` — collects that level **and worse**. Omit to collect
  everything. (Security channel events are level 0/LogAlways and are
  always included regardless.)
- `IncludeEventIds`: collect **only** these Event IDs.
- `ExcludeEventIds`: collect everything except these.
- Filters are applied server-side (XPath), so excluded events are never
  even read — cheap on busy channels.

## 2. Test the connection first

```powershell
.\MiniSiemAgent.ps1 -TestConnection
```

Sends one test message and reports success/failure with the exact
error. With UDP a "success" only means the packet left this machine —
confirm it appears in the SIEM dashboard.

## 3. Run it

**Foreground (watch it work):**
```powershell
.\MiniSiemAgent.ps1
```

**One-shot collection pass (no loop, no relay):**
```powershell
.\MiniSiemAgent.ps1 -Once
```

**Persistent install (recommended)** — from an elevated PowerShell:
```powershell
.\Install-ScheduledTask.ps1
```
Registers a Scheduled Task running as SYSTEM at boot, auto-restarting
on failure, with no execution time limit. Manage with:
```powershell
Get-ScheduledTask -TaskName MiniSiemAgent | Get-ScheduledTaskInfo
Stop-ScheduledTask  -TaskName MiniSiemAgent
Start-ScheduledTask -TaskName MiniSiemAgent
Unregister-ScheduledTask -TaskName MiniSiemAgent -Confirm:$false
```

## 4. Enabling the syslog relay

Set `"SyslogRelay": { "Enabled": true, ... }`, then allow inbound UDP
on Windows Firewall (elevated):

```powershell
New-NetFirewallRule -DisplayName "mini-SIEM syslog relay" -Direction Inbound `
  -Protocol UDP -LocalPort 514 -Action Allow
```

Point devices at the Windows box's IP, port 514. Each message is
relayed to the SIEM exactly as received.

**Relay limitation to know about:** the SIEM records `source_ip` as
the Windows relay's IP, not the original device — that's inherent to
UDP relaying. The hostname *inside* the syslog message still identifies
the true origin, so correlation by hostname works normally.

## 5. Reliability semantics

- **TCP mode**: per-channel state advances only past events that were
  actually delivered. If the SIEM is unreachable mid-batch, the agent
  stops, keeps its place, and resumes from the exact next event on the
  following poll — nothing is lost or duplicated across outages or
  agent restarts.
- **UDP mode**: standard syslog fire-and-forget. If the SIEM is down,
  packets sent during the outage are gone (state advances regardless).
  Choose TCP if delivery matters more than simplicity.
- **Bursts**: events are read oldest-first with `-MaxEvents`, so bursts
  larger than `BatchSizePerChannel` are caught up chronologically over
  successive polls rather than skipped.
- **Relay**: fire-and-forget end to end (UDP in, immediate forward
  out); it is drained every ~200ms with a 1MB receive buffer.

## 6. Permissions

Reading the **Security** log needs elevation: run as SYSTEM (what the
installer does) or add the service account to the built-in **Event Log
Readers** group. System/Application are readable by regular users. The
relay on port 514 (a low port) also requires elevation.

## 7. Verify end-to-end

```powershell
Write-EventLog -LogName Application -Source "Application" -EventId 9999 `
  -EntryType Warning -Message "mini-siem test event"
```
It should appear in the SIEM dashboard within one poll interval. The
heartbeat message (every `HeartbeatMinutes`) is also an easy liveness
check — search the dashboard for `mini-siem-agent`.

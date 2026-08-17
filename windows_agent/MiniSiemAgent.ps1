<#
.SYNOPSIS
    mini-SIEM Windows agent v2 — collects Windows Event Logs AND relays
    syslog, forwarding everything to the mini-SIEM listener.

.DESCRIPTION
    Two collectors in one agent, each independently enabled in config:

    1. EVENT LOG COLLECTOR — polls Windows Event Log channels
       (Security/System/Application/custom), converts new events to
       RFC5424 syslog, forwards them. Tracks last-forwarded record per
       channel so restarts never duplicate. Supports per-channel
       filtering by minimum level and include/exclude Event ID lists.

    2. SYSLOG RELAY (optional) — listens for syslog on a local UDP port
       and relays each received message RAW (byte-for-byte) to the
       SIEM. Lets the Windows box collect from nearby devices that
       can't reach the SIEM directly.

    Improvements over v1:
      - TCP delivery is now reliable: channel state only advances past
        events that were actually sent; failures are retried next cycle
        instead of silently lost.
      - Per-channel level and Event ID filters (server-side XPath, so
        filtered events are never even read).
      - Agent log rotation (size-capped).
      - Periodic heartbeat with forwarding counters.
      - -TestConnection and -Once switches for troubleshooting and
        scheduled one-shot collection.

.PARAMETER ConfigPath
    Path to JSON config. Defaults to agent-config.json next to this script.

.PARAMETER Once
    Run one collection pass over all channels, then exit (no loop, no
    syslog relay). Useful for cron-style scheduled tasks or testing.

.PARAMETER TestConnection
    Send a single test message to the SIEM and exit, reporting success
    or the exact failure.

.NOTES
    PowerShell 5.1 compatible. Reading the Security log requires admin
    rights or "Event Log Readers" membership. The syslog relay needs an
    inbound Windows Firewall rule (see README).

.EXAMPLE
    .\MiniSiemAgent.ps1 -TestConnection
    .\MiniSiemAgent.ps1
    .\MiniSiemAgent.ps1 -Once
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "agent-config.json"),
    [switch]$Once,
    [switch]$TestConnection
)

$ErrorActionPreference = "Stop"

# ====================================================================
# Config loading (with defaults for anything omitted)
# ====================================================================

if (-not (Test-Path $ConfigPath)) { throw "Config file not found: $ConfigPath" }
$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json

function Get-Val($obj, [string]$name, $default) {
    if ($null -ne $obj -and $obj.PSObject.Properties[$name] -and $null -ne $obj.$name) { return $obj.$name }
    return $default
}

$SiemHost   = Get-Val $cfg "SiemHost" $null
$SiemPort   = [int](Get-Val $cfg "SiemPort" 514)
$Protocol   = ([string](Get-Val $cfg "Protocol" "UDP")).ToUpper()
$Facility   = [int](Get-Val $cfg "Facility" 16)
$StatePath  = Get-Val $cfg "StateFilePath" "C:\ProgramData\mini-siem-agent\state.json"
$LogPath    = Get-Val $cfg "LogFilePath"   "C:\ProgramData\mini-siem-agent\agent.log"
$MaxLogMB   = [int](Get-Val $cfg "MaxLogFileSizeMB" 10)
$HeartbeatMinutes = [int](Get-Val $cfg "HeartbeatMinutes" 15)

$evCfg      = Get-Val $cfg "EventLog" $null
$EvEnabled  = [bool](Get-Val $evCfg "Enabled" $true)
$PollSecs   = [int](Get-Val $evCfg "PollIntervalSeconds" 10)
$BatchSize  = [int](Get-Val $evCfg "BatchSizePerChannel" 500)
$Channels   = @(Get-Val $evCfg "Channels" @())

$relayCfg     = Get-Val $cfg "SyslogRelay" $null
$RelayEnabled = [bool](Get-Val $relayCfg "Enabled" $false)
$RelayAddr    = [string](Get-Val $relayCfg "ListenAddress" "0.0.0.0")
$RelayPort    = [int](Get-Val $relayCfg "ListenPort" 514)

if (-not $SiemHost) { throw "SiemHost is required in $ConfigPath" }
if ($Protocol -notin @("UDP", "TCP")) { throw "Protocol must be UDP or TCP" }

foreach ($p in @($StatePath, $LogPath)) {
    $dir = Split-Path $p -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

$Hostname = $env:COMPUTERNAME

# ====================================================================
# Agent log (local troubleshooting log, size-rotated)
# ====================================================================

function Write-AgentLog {
    param([string]$Message, [string]$Level = "INFO")
    try {
        if ((Test-Path $LogPath) -and ((Get-Item $LogPath).Length -gt ($MaxLogMB * 1MB))) {
            Move-Item -Path $LogPath -Destination "$LogPath.1" -Force
        }
    } catch { }
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $LogPath -Value $line
    Write-Host $line
}

# ====================================================================
# State (last EventRecordId per channel) — PS 5.1 compatible
# ====================================================================

function Load-State {
    if (Test-Path $StatePath) {
        try {
            $obj = Get-Content $StatePath -Raw | ConvertFrom-Json
            $hash = @{}
            if ($obj) { foreach ($prop in $obj.PSObject.Properties) { $hash[$prop.Name] = [int64]$prop.Value } }
            return $hash
        } catch {
            Write-AgentLog "State file unreadable, starting fresh: $_" "WARN"
            return @{}
        }
    }
    return @{}
}

function Save-State($state) {
    ($state | ConvertTo-Json) | Set-Content -Path $StatePath -Encoding UTF8
}

$State = Load-State

# ====================================================================
# Syslog transport (UDP fire-and-forget / TCP reliable with reconnect)
# ====================================================================

$script:UdpClient = $null
$script:TcpClient = $null
$script:TcpStream = $null
$script:SentCount  = 0
$script:RelayCount = 0

function Get-UdpClient {
    if (-not $script:UdpClient) { $script:UdpClient = New-Object System.Net.Sockets.UdpClient }
    return $script:UdpClient
}

function Connect-Tcp {
    if ($script:TcpClient -and $script:TcpClient.Connected) { return $true }
    try {
        if ($script:TcpClient) { $script:TcpClient.Close() }
        $script:TcpClient = New-Object System.Net.Sockets.TcpClient
        $script:TcpClient.SendTimeout = 5000
        $script:TcpClient.Connect($SiemHost, $SiemPort)
        $script:TcpStream = $script:TcpClient.GetStream()
        Write-AgentLog "TCP connected to $SiemHost`:$SiemPort"
        return $true
    } catch {
        $script:TcpClient = $null; $script:TcpStream = $null
        return $false
    }
}

function Send-Syslog {
    # Returns $true if the message can be considered delivered
    # (always true for UDP once handed to the stack; for TCP, true only
    # if the write succeeded).
    param([string]$Message)
    if ($Protocol -eq "TCP") {
        if (-not (Connect-Tcp)) { return $false }
        try {
            $framed = [System.Text.Encoding]::UTF8.GetBytes($Message + "`n")
            $script:TcpStream.Write($framed, 0, $framed.Length)
            $script:TcpStream.Flush()
            $script:SentCount++
            return $true
        } catch {
            Write-AgentLog "TCP send failed (will retry): $($_.Exception.Message)" "ERROR"
            try { $script:TcpClient.Close() } catch { }
            $script:TcpClient = $null; $script:TcpStream = $null
            return $false
        }
    } else {
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
            (Get-UdpClient).Send($bytes, $bytes.Length, $SiemHost, $SiemPort) | Out-Null
            $script:SentCount++
            return $true
        } catch {
            Write-AgentLog "UDP send failed: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
}

# ====================================================================
# Windows level <-> syslog severity, RFC5424 formatting
# ====================================================================

$LevelNameMap = @{ "critical" = 1; "error" = 2; "warning" = 3; "information" = 4; "verbose" = 5 }

function Get-SyslogSeverity([int]$WinLevel) {
    switch ($WinLevel) {
        1 { return 2 } 2 { return 3 } 3 { return 4 } 4 { return 6 } 5 { return 7 }
        default { return 6 }
    }
}

function Format-Rfc5424Event {
    param($Event, [string]$ChannelName)
    $severity = Get-SyslogSeverity ([int]$Event.Level)
    $pri = ($Facility * 8) + $severity
    $timestamp = $Event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $appName = "WindowsEventLog"
    if ($Event.ProviderName) { $appName = ($Event.ProviderName -replace '\s', '_') }
    $procId = "-"
    if ($Event.ProcessId) { $procId = $Event.ProcessId }

    $rawMsg = $Event.Message
    if (-not $rawMsg) { $rawMsg = "(no message text available)" }
    $flatMsg = ($rawMsg -replace "`r`n", " | " -replace "`n", " | ").Trim()

    $sd = "[mini_siem@32473 recordid=`"$($Event.RecordId)`" channel=`"$ChannelName`" eventid=`"$($Event.Id)`" level=`"$($Event.LevelDisplayName)`"]"
    $body = "EventID=$($Event.Id) Channel=$ChannelName Level=$($Event.LevelDisplayName) User=$($Event.UserId) : $flatMsg"
    return "<$pri>1 $timestamp $Hostname $appName $procId $($Event.Id) $sd $body"
}

# ====================================================================
# Event Log collector
# ====================================================================

function Build-XPath {
    param([int64]$LastId, $ChanCfg)
    $conds = @("EventRecordID > $LastId")

    $minLevel = Get-Val $ChanCfg "MinimumLevel" $null
    if ($minLevel) {
        $lvlNum = $LevelNameMap[([string]$minLevel).ToLower()]
        if ($lvlNum) { $conds += "Level <= $lvlNum" }  # lower = more severe; 0 (LogAlways) always included
        else { Write-AgentLog "Unknown MinimumLevel '$minLevel' on channel $($ChanCfg.Name) — ignoring" "WARN" }
    }

    $include = @(Get-Val $ChanCfg "IncludeEventIds" @())
    if ($include.Count -gt 0) {
        $ors = ($include | ForEach-Object { "EventID=$_" }) -join " or "
        $conds += "($ors)"
    }
    $exclude = @(Get-Val $ChanCfg "ExcludeEventIds" @())
    foreach ($eid in $exclude) { $conds += "EventID != $eid" }

    return "*[System[" + ($conds -join " and ") + "]]"
}

function Process-Channel {
    param($ChanCfg)
    $name = $ChanCfg.Name
    if (-not $name) { return }

    $lastId = [int64]0
    if ($State.ContainsKey($name)) { $lastId = [int64]$State[$name] }
    $xpath = Build-XPath -LastId $lastId -ChanCfg $ChanCfg

    try {
        $events = @(Get-WinEvent -LogName $name -FilterXPath $xpath -MaxEvents $BatchSize -Oldest -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match "No events were found") { return }
        Write-AgentLog "Failed to read channel '$name': $($_.Exception.Message)" "ERROR"
        return
    }
    if ($events.Count -eq 0) { return }

    $sentUpTo = $lastId
    $sentCount = 0
    foreach ($ev in $events) {
        $line = Format-Rfc5424Event -Event $ev -ChannelName $name
        if (Send-Syslog -Message $line) {
            if ($ev.RecordId -gt $sentUpTo) { $sentUpTo = $ev.RecordId }
            $sentCount++
        } else {
            # Delivery failed (TCP down): stop here. State advances only
            # past what was actually sent; the rest is retried next poll.
            Write-AgentLog "Delivery failed mid-batch on '$name' after $sentCount event(s); will resume from RecordId $sentUpTo" "WARN"
            break
        }
    }

    if ($sentUpTo -gt $lastId) {
        $State[$name] = $sentUpTo
        Save-State $State
        Write-AgentLog "Forwarded $sentCount event(s) from '$name' (up to RecordId $sentUpTo)"
    }
}

# ====================================================================
# Syslog relay (optional local UDP receiver -> relays RAW to SIEM)
# ====================================================================

$script:RelayUdp = $null

function Start-SyslogRelay {
    try {
        $ep = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($RelayAddr), $RelayPort)
        $script:RelayUdp = New-Object System.Net.Sockets.UdpClient $ep
        $script:RelayUdp.Client.ReceiveBufferSize = 1MB
        Write-AgentLog "Syslog relay listening on udp://$RelayAddr`:$RelayPort (relaying raw to $SiemHost`:$SiemPort)"
    } catch {
        Write-AgentLog "Syslog relay failed to start on $RelayAddr`:$RelayPort — $($_.Exception.Message). Check the port isn't in use and run elevated for ports <1024." "ERROR"
        $script:RelayUdp = $null
    }
}

function Drain-SyslogRelay {
    if (-not $script:RelayUdp) { return }
    $drained = 0
    while ($script:RelayUdp.Available -gt 0 -and $drained -lt 1000) {
        $remoteEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 0)
        try {
            $bytes = $script:RelayUdp.Receive([ref]$remoteEP)
        } catch {
            Write-AgentLog "Relay receive error: $($_.Exception.Message)" "ERROR"
            return
        }
        $raw = [System.Text.Encoding]::UTF8.GetString($bytes)
        if (Send-Syslog -Message $raw) { $script:RelayCount++ }
        $drained++
    }
}

# ====================================================================
# Heartbeat / test / main
# ====================================================================

function Send-Heartbeat {
    param([string]$Text)
    $ts = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $pri = ($Facility * 8) + 6
    Send-Syslog -Message "<$pri>1 $ts $Hostname mini-siem-agent - - - $Text" | Out-Null
}

if ($TestConnection) {
    Write-Host "Testing $Protocol connection to $SiemHost`:$SiemPort ..."
    $ok = Send-Syslog -Message ("<" + (($Facility * 8) + 6) + ">1 " + [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") + " $Hostname mini-siem-agent - - - Connection test from $Hostname")
    if ($ok) {
        if ($Protocol -eq "TCP") { Write-Host "OK — TCP connection and send succeeded." }
        else { Write-Host "OK — UDP packet sent (fire-and-forget: confirm it appears in the SIEM dashboard)." }
        exit 0
    } else {
        Write-Host "FAILED — see error above. Check SiemHost/SiemPort, network path, and the SIEM host's firewall."
        exit 1
    }
}

Send-Heartbeat "Agent v2 started. EventLog=$EvEnabled ($(($Channels | ForEach-Object { $_.Name }) -join ',')); SyslogRelay=$RelayEnabled; Protocol=$Protocol; Target=$SiemHost`:$SiemPort"
Write-AgentLog "Agent v2 started. Target=$SiemHost`:$SiemPort Protocol=$Protocol EventLog=$EvEnabled Relay=$RelayEnabled"

if ($Once) {
    if ($EvEnabled) { foreach ($chan in $Channels) { Process-Channel -ChanCfg $chan } }
    Write-AgentLog "Single pass complete (-Once). Sent $($script:SentCount) message(s)."
    exit 0
}

if ($RelayEnabled) { Start-SyslogRelay }

$lastPoll = [DateTime]::MinValue
$lastHeartbeat = [DateTime]::UtcNow

while ($true) {
    Drain-SyslogRelay   # runs every ~200ms so relayed syslog stays near-real-time

    if ($EvEnabled -and ([DateTime]::UtcNow - $lastPoll).TotalSeconds -ge $PollSecs) {
        foreach ($chan in $Channels) { Process-Channel -ChanCfg $chan }
        $lastPoll = [DateTime]::UtcNow
    }

    if ($HeartbeatMinutes -gt 0 -and ([DateTime]::UtcNow - $lastHeartbeat).TotalMinutes -ge $HeartbeatMinutes) {
        Send-Heartbeat "Heartbeat: $($script:SentCount) message(s) forwarded total, $($script:RelayCount) via syslog relay. Uptime OK."
        $lastHeartbeat = [DateTime]::UtcNow
    }

    Start-Sleep -Milliseconds 200
}

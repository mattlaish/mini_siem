<#
.SYNOPSIS
    mini-SIEM WEF single-machine TEST setup (no domain, no GPO, no second box).

.DESCRIPTION
    Configures ONE Windows machine to be its own WEF source AND collector, so
    you can validate the whole pipeline before touching Group Policy or the
    200-machine fleet:

        this machine's events
              -> local WEF subscription
              -> "Forwarded Events" log
              -> mini-SIEM Windows agent (reads ForwardedEvents)
              -> mini-SIEM

    What it does:
      1. Starts + auto-starts the Windows Event Collector service (wecsvc).
      2. Enables the WinRM listener the collector needs (winrm quickconfig).
      3. Creates a source-initiated subscription from Subscription.xml.
      4. Points this machine at ITSELF as the collector (adds its own
         forwarder GPO-equivalent registry key) so it forwards locally.
      5. Adds the Network Service account to the Event Log Readers group so
         the collector can read the Security log.

    This is a TEST harness. On the real fleet these steps are delivered by
    Group Policy to 200 machines and a dedicated collector — see WEF-README.md.

.NOTES
    Run in an ELEVATED PowerShell (Administrator).
    Reversible with -Undo.
#>

[CmdletBinding()]
param(
    [string]$SubscriptionXml = "",
    [string]$CollectorFqdn = "",
    [switch]$Undo
)

$ErrorActionPreference = "Stop"

# Resolve the script's own folder robustly. $PSScriptRoot can be empty
# depending on how the script is launched (dot-sourced, ISE, piped), so fall
# back to $MyInvocation and finally the current directory.
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }

if (-not $SubscriptionXml) {
    $SubscriptionXml = Join-Path $scriptDir "Subscription.xml"
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
}

Assert-Admin

$SubName = "mini-SIEM-Test"
function Get-SelfFqdn {
    # Try several sources; any can be empty depending on domain/DNS state.
    $candidates = @()
    try {
        $ci = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($ci -and $ci.DNSHostName) {
            if ($ci.Domain -and $ci.Domain -ne "WORKGROUP") {
                $candidates += "$($ci.DNSHostName).$($ci.Domain)"
            }
            $candidates += $ci.DNSHostName
        }
    } catch {}
    try {
        $dns = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)
        if ($dns.HostName) { $candidates += $dns.HostName }
    } catch {}
    if ($env:COMPUTERNAME) { $candidates += $env:COMPUTERNAME }
    # first non-empty
    foreach ($c in $candidates) { if ($c -and $c.Trim()) { return $c.Trim() } }
    return ""
}

$selfFqdn = if ($CollectorFqdn) { $CollectorFqdn } else { Get-SelfFqdn }
if (-not $selfFqdn) {
    throw "Could not determine this machine's hostname/FQDN. Re-run with -CollectorFqdn <name.domain>."
}

if ($Undo) {
    Write-Host "Removing test WEF configuration..." -ForegroundColor Yellow
    try { wecutil ds $SubName 2>$null } catch {}
    # remove the self-forwarding policy key
    $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
    if (Test-Path $key) { Remove-Item $key -Recurse -Force }
    Write-Host "Done. (wecsvc/WinRM left enabled; disable manually if desired.)" -ForegroundColor Green
    return
}

Write-Host "=== mini-SIEM WEF single-machine test setup ===" -ForegroundColor Cyan
Write-Host "Collector = source = this machine: $selfFqdn`n"

# 1. Event Collector service
Write-Host "[1/5] Starting Windows Event Collector service (wecsvc)..."
Set-Service -Name wecsvc -StartupType Automatic
Start-Service -Name wecsvc
# initialize the collector subsystem if first run
& wecutil qc /q 2>$null

# 2. WinRM (WEF transport)
Write-Host "[2/5] Configuring WinRM listener..."
& winrm quickconfig -quiet 2>$null
# source-initiated forwarding needs the WinRM service running
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

# 3. Create the subscription
Write-Host "[3/5] Creating subscription '$SubName' from $SubscriptionXml..."
if (-not (Test-Path $SubscriptionXml)) { throw "Subscription XML not found: $SubscriptionXml" }
& wecutil cs $SubscriptionXml
Write-Host "      Subscriptions now configured:"
& wecutil es | ForEach-Object { "        $_" }

# 4. Point this machine at itself as collector (the bit GPO normally does)
Write-Host "[4/5] Pointing this machine at itself as collector..."
$smKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
New-Item -Path $smKey -Force | Out-Null
# Server=http URL for source-initiated pull of subscription info
if (-not $selfFqdn) { throw "Refusing to write SubscriptionManager URL with empty host." }
$serverUrl = "Server=http://${selfFqdn}:5985/wsman/SubscriptionManager/WEC,Refresh=60"
New-ItemProperty -Path $smKey -Name "1" -Value $serverUrl -PropertyType String -Force | Out-Null
Write-Host "      SubscriptionManager = $serverUrl"

# 5. Let the collector read the Security log
Write-Host "[5/5] Granting log read access (Event Log Readers)..."
try {
    Add-LocalGroupMember -Group "Event Log Readers" -Member "NETWORK SERVICE" -ErrorAction Stop
    Write-Host "      Added NETWORK SERVICE to Event Log Readers."
} catch {
    Write-Host "      (NETWORK SERVICE already a member or not required.)"
}

# restart the forwarding service so it picks up the new SubscriptionManager
Restart-Service -Name Wecsvc

Write-Host "`n=== Setup complete ===" -ForegroundColor Green
Write-Host @"
Next steps:
  1. Give it a minute, then generate an event (lock/unlock your screen for a
     4624/4634 logon event, or run a program for 4688 if audit is on).
  2. Check events are arriving in the collector:
        Get-WinEvent -LogName 'ForwardedEvents' -MaxEvents 5
  3. Point the mini-SIEM Windows agent at the 'ForwardedEvents' channel
     (see wef-agent-config.json) and start it:
        .\MiniSiemAgent.ps1 -TestConnection
        .\MiniSiemAgent.ps1
  4. Confirm the events appear in the mini-SIEM dashboard's Live logs.

To undo this test setup:  .\Setup-WEF-Test.ps1 -Undo
"@

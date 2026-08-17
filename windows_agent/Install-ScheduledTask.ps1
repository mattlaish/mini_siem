<#
.SYNOPSIS
    Registers the mini-SIEM agent as a Scheduled Task that starts at
    boot, runs as SYSTEM, and restarts automatically if it stops.

.DESCRIPTION
    This avoids needing a third-party service wrapper (e.g. NSSM).
    Task Scheduler can run a long-lived process and restart it on
    failure just like a Windows Service would.

.PARAMETER ScriptPath
    Full path to Send-EventLogsToSiem.ps1. Defaults to the copy next
    to this installer.

.PARAMETER ConfigPath
    Full path to agent-config.json. Defaults to the copy next to this
    installer.

.EXAMPLE
    Right-click PowerShell -> Run as Administrator, then:
    .\Install-ScheduledTask.ps1
#>

[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path $PSScriptRoot "MiniSiemAgent.ps1"),
    [string]$ConfigPath = (Join-Path $PSScriptRoot "agent-config.json"),
    [string]$TaskName   = "MiniSiemAgent"
)

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated (Administrator) PowerShell prompt."
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -ConfigPath `"$ConfigPath`""

$trigger = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)   # no time limit - this runs forever

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null

Write-Host "Scheduled task '$TaskName' registered. Starting it now..."
Start-ScheduledTask -TaskName $TaskName

Start-Sleep -Seconds 2
Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo

Write-Host ""
Write-Host "Check C:\ProgramData\mini-siem-agent\agent.log for activity."
Write-Host "To stop:      Stop-ScheduledTask -TaskName $TaskName"
Write-Host "To uninstall: Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"

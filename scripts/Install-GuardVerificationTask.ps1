[CmdletBinding()]
param([Parameter(Mandatory)][string]$PolicyPath,[switch]$ConfirmInstall)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmInstall) { throw 'Task installation requires -ConfirmInstall.' }
$moduleScript = Join-Path $PSScriptRoot 'Test-WorkspaceIntegrity.ps1'
$policy = (Resolve-Path -LiteralPath $PolicyPath).Path
$p = (Get-Content -LiteralPath $policy -Raw | ConvertFrom-Json)
$taskName = $p.verification.taskName
if ($taskName -notmatch '^AIWorkspaceGuard-[A-Za-z0-9_-]+-Verify$') { throw 'Task name does not meet the required prefix format.' }
$args = "-NoProfile -ExecutionPolicy RemoteSigned -File `"$moduleScript`" -PolicyPath `"$policy`""
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument $args
$trigger = New-ScheduledTaskTrigger -Daily -At '3:15 AM'
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Get-ScheduledTask -TaskName $taskName | Select-Object TaskName,State

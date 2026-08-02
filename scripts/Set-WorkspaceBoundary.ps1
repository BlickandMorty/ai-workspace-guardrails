[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PolicyPath,
    [ValidateSet('Plan','Apply')][string]$Mode = 'Plan',
    [switch]$ConfirmApply,
    [string]$Acknowledgement
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WorkspaceGuard.psm1') -Force
$bundle = Get-WorkspacePolicy -PolicyPath $PolicyPath
$p = $bundle.Value
$root = Assert-SafeWorkspaceRoot -Root $p.workspaceRoot
$marker = Join-Path $root '.workspace-guard-root.json'
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Workspace root does not exist: $root" }
if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw "Root marker missing: $marker" }

$plan = foreach ($zone in $p.zones) {
    $path = Join-Path $root $zone.relativePath
    [pscustomobject]@{ Zone=$zone.id; Path=$path; Roles=@($zone.allowedRoles); Operations=@($zone.allowedOperations) }
}

if ($Mode -eq 'Plan') {
    [pscustomobject]@{ Mode='Plan'; PolicyHash=$bundle.Hash; Changes=@($plan); AcknowledgementRequired='APPLY WORKSPACE BOUNDARY' } | ConvertTo-Json -Depth 8
    exit 0
}

if (-not $ConfirmApply -or $Acknowledgement -cne 'APPLY WORKSPACE BOUNDARY') {
    throw 'Apply requires -ConfirmApply -Acknowledgement "APPLY WORKSPACE BOUNDARY".'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Apply requires an elevated administrator session.' }

$backupRoot = Join-Path $p.evidenceRoot 'acl-backups'
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$backup = Join-Path $backupRoot ("{0:yyyyMMdd-HHmmss}.acl-backup" -f (Get-Date))
& icacls.exe $root /save $backup /t /c | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'ACL backup failed; no changes were applied.' }

$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$prop = [Security.AccessControl.PropagationFlags]::None
foreach ($zone in $p.zones) {
    $path = Join-Path $root $zone.relativePath
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.NTAccount]'NT AUTHORITY\SYSTEM')
    foreach ($sidAndRights in @(
        @('S-1-5-18','FullControl'),
        @('S-1-5-32-544','FullControl')
    )) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidAndRights[0])
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,$sidAndRights[1],$inherit,$prop,'Allow')
        $acl.AddAccessRule($rule)
    }
    foreach ($mapped in $p.principals) {
        if (@($zone.allowedRoles | Where-Object { @($mapped.roles) -contains $_ }).Count -eq 0) { continue }
        $ops = @($zone.allowedOperations)
        $rights = if ($ops -contains 'UpdateOutput' -or $ops -contains 'CreateOutput') { 'Modify' } else { 'ReadAndExecute' }
        $sid = [Security.Principal.SecurityIdentifier]::new($mapped.sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,$rights,$inherit,$prop,'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}

$ledger = Join-Path $p.evidenceRoot $p.verification.ledgerName
Write-GuardLedgerEvent -LedgerPath $ledger -Event @{ type='acl-apply'; projectId=$p.projectId; policyHash=$bundle.Hash; backup=$backup; zones=@($p.zones.id) } | Out-Null
[pscustomobject]@{ Mode='Apply'; Applied=$true; Backup=$backup; ZoneCount=@($p.zones).Count } | ConvertTo-Json -Depth 5

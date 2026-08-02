[CmdletBinding()]
param([Parameter(Mandatory)][string]$PolicyPath)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WorkspaceGuard.psm1') -Force
$bundle = Get-WorkspacePolicy -PolicyPath $PolicyPath
$p = $bundle.Value
$errors = [Collections.Generic.List[string]]::new()

foreach ($required in 'policyId','projectId','workspaceRoot','evidenceRoot','principals','roles','zones','verification') {
    if (-not $p.PSObject.Properties.Name.Contains($required)) { $errors.Add("Missing property: $required") }
}
try { $root = Assert-SafeWorkspaceRoot -Root $p.workspaceRoot } catch { $errors.Add($_.Exception.Message) }
if ($p.workspaceRoot -ieq $p.evidenceRoot) { $errors.Add('evidenceRoot must be separate from workspaceRoot.') }
if (@($p.zones).Count -eq 0) { $errors.Add('At least one zone is required.') }

$zoneIds = @{}
foreach ($zone in @($p.zones)) {
    if (-not $zone.id -or -not $zone.relativePath) { $errors.Add('Every zone needs id and relativePath.'); continue }
    if ($zoneIds.ContainsKey($zone.id)) { $errors.Add("Duplicate zone id: $($zone.id)") }
    $zoneIds[$zone.id] = $true
    if ([IO.Path]::IsPathRooted($zone.relativePath) -or $zone.relativePath -match '(^|[\\/])\.\.([\\/]|$)') {
        $errors.Add("Unsafe relativePath in zone $($zone.id)")
    }
    foreach ($role in @($zone.allowedRoles)) {
        if (-not $p.roles.PSObject.Properties.Name.Contains($role)) { $errors.Add("Zone $($zone.id) references unknown role $role") }
    }
}

foreach ($principal in @($p.principals)) {
    if ($principal.sid -notmatch '^S-1-\d+(-\d+)+$') { $errors.Add("Principal $($principal.id) must use a SID.") }
    foreach ($role in @($principal.roles)) {
        if (-not $p.roles.PSObject.Properties.Name.Contains($role)) { $errors.Add("Principal $($principal.id) references unknown role $role") }
    }
}

$result = [pscustomobject]@{ Valid=($errors.Count -eq 0); PolicyId=$p.policyId; PolicyHash=$bundle.Hash; Errors=@($errors) }
$result | ConvertTo-Json -Depth 5
if (-not $result.Valid) { exit 2 }

[CmdletBinding()]
param([Parameter(Mandatory)][string]$PolicyPath)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WorkspaceGuard.psm1') -Force
$bundle = Get-WorkspacePolicy -PolicyPath $PolicyPath
$p = $bundle.Value
$manifestPath = Join-Path (Join-Path $p.evidenceRoot 'manifests') $p.verification.manifestName
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "Manifest not found: $manifestPath" }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$current = @(Get-GuardedFiles -Policy $p)
$expectedByPath = @{}; foreach ($item in $manifest.files) { $expectedByPath[$item.relativePath] = $item }
$currentByPath = @{}; foreach ($item in $current) { $currentByPath[$item.relativePath] = $item }
$drift = [Collections.Generic.List[object]]::new()
foreach ($path in $expectedByPath.Keys) {
    if (-not $currentByPath.ContainsKey($path)) { $drift.Add([pscustomobject]@{ Path=$path; State='Missing' }) }
    elseif ($currentByPath[$path].sha256 -ne $expectedByPath[$path].sha256) { $drift.Add([pscustomobject]@{ Path=$path; State='Changed' }) }
}
foreach ($path in $currentByPath.Keys) { if (-not $expectedByPath.ContainsKey($path)) { $drift.Add([pscustomobject]@{ Path=$path; State='Unexpected' }) } }
if ($manifest.policyHash -ne $bundle.Hash) { $drift.Add([pscustomobject]@{ Path='[policy]'; State='PolicyChanged' }) }
$ok = $drift.Count -eq 0
Write-GuardLedgerEvent -LedgerPath (Join-Path $p.evidenceRoot $p.verification.ledgerName) -Event @{ type='integrity-verify'; projectId=$p.projectId; policyHash=$bundle.Hash; ok=$ok; driftCount=$drift.Count } | Out-Null
[pscustomobject]@{ Valid=$ok; Drift=@($drift); CheckedFiles=$current.Count } | ConvertTo-Json -Depth 6
if (-not $ok) { exit 4 }

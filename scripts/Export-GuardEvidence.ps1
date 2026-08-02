[CmdletBinding()]
param([Parameter(Mandatory)][string]$PolicyPath,[Parameter(Mandatory)][string]$Destination)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WorkspaceGuard.psm1') -Force
$bundle = Get-WorkspacePolicy -PolicyPath $PolicyPath
$p = $bundle.Value
$out = Get-NormalizedPath $Destination
if (Test-PathWithinRoot -Root $p.workspaceRoot -Path $out) { throw 'Evidence export must be outside the guarded workspace.' }
New-Item -ItemType Directory -Path $out -Force | Out-Null
$ledger = Join-Path $p.evidenceRoot $p.verification.ledgerName
$manifest = Join-Path (Join-Path $p.evidenceRoot 'manifests') $p.verification.manifestName
if (Test-Path -LiteralPath $ledger) { Copy-Item -LiteralPath $ledger -Destination (Join-Path $out 'guard-events.jsonl') }
if (Test-Path -LiteralPath $manifest) { Copy-Item -LiteralPath $manifest -Destination (Join-Path $out 'workspace.manifest.json') }
[pscustomobject]@{ schemaVersion=1; projectId=$p.projectId; policyHash=$bundle.Hash; exportedUtc=[DateTime]::UtcNow.ToString('o'); contentIncluded=$false } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'evidence-summary.json') -Encoding UTF8
Get-ChildItem -LiteralPath $out -File | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $out 'evidence-hashes.json') -Encoding UTF8
[pscustomobject]@{ Destination=$out; ContentIncluded=$false } | ConvertTo-Json

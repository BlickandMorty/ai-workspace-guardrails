[CmdletBinding()]
param([Parameter(Mandatory)][string]$PolicyPath)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WorkspaceGuard.psm1') -Force
$bundle = Get-WorkspacePolicy -PolicyPath $PolicyPath
$p = $bundle.Value
$manifestRoot = Join-Path $p.evidenceRoot 'manifests'
New-Item -ItemType Directory -Path $manifestRoot -Force | Out-Null
$manifestPath = Join-Path $manifestRoot $p.verification.manifestName
$manifest = [ordered]@{
    schemaVersion=1; projectId=$p.projectId; policyHash=$bundle.Hash
    createdUtc=[DateTime]::UtcNow.ToString('o'); files=@(Get-GuardedFiles -Policy $p | Sort-Object relativePath)
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$hash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-GuardLedgerEvent -LedgerPath (Join-Path $p.evidenceRoot $p.verification.ledgerName) -Event @{ type='manifest-create'; projectId=$p.projectId; policyHash=$bundle.Hash; manifestHash=$hash; fileCount=@($manifest.files).Count } | Out-Null
[pscustomobject]@{ Manifest=$manifestPath; ManifestHash=$hash; FileCount=@($manifest.files).Count } | ConvertTo-Json

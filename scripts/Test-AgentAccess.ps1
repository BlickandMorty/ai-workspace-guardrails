[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PolicyPath,
    [Parameter(Mandatory)][string]$TargetPath,
    [Parameter(Mandatory)][ValidateSet('Read','CreateOutput','UpdateOutput','Review','ApproveExport','Administer')][string]$Operation,
    [string[]]$IdentitySid,
    [switch]$NoLedger
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WorkspaceGuard.psm1') -Force
$bundle = Get-WorkspacePolicy -PolicyPath $PolicyPath
$p = $bundle.Value
$sids = if ($IdentitySid) { $IdentitySid } else { Get-CurrentIdentitySids }
$decision = Test-WorkspaceAuthorization -Policy $p -TargetPath $TargetPath -Operation $Operation -IdentitySids $sids

if (-not $NoLedger) {
    $ledger = Join-Path $p.evidenceRoot $p.verification.ledgerName
    Write-GuardLedgerEvent -LedgerPath $ledger -Event @{
        type='access-decision'; projectId=$p.projectId; policyHash=$bundle.Hash; operation=$Operation
        targetHash=(Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes((Get-NormalizedPath $TargetPath)))) -Algorithm SHA256).Hash.ToLowerInvariant()
        allowed=$decision.Allowed; reason=$decision.Reason; zone=$decision.Zone; roles=@($decision.Roles)
    } | Out-Null
}

$decision | ConvertTo-Json -Depth 5
if (-not $decision.Allowed) { exit 3 }

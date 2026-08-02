$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$required = @(
    'README.md','DISCLAIMER.md','LICENSE','config/example.policy.json','scripts/WorkspaceGuard.psm1',
    'scripts/Test-WorkspacePolicy.ps1','scripts/Test-AgentAccess.ps1','scripts/Set-WorkspaceBoundary.ps1',
    'scripts/New-IntegrityManifest.ps1','scripts/Test-WorkspaceIntegrity.ps1','scripts/Export-GuardEvidence.ps1',
    'docs/THREAT-MODEL.md','docs/DEPLOYMENT.md','docs/INCIDENT-RESPONSE.md'
)
foreach ($item in $required) { if (-not (Test-Path -LiteralPath (Join-Path $root $item))) { throw "Missing $item" } }

$errors = [Collections.Generic.List[string]]::new()
Get-ChildItem -LiteralPath (Join-Path $root 'scripts') -Include *.ps1,*.psm1 -Recurse | ForEach-Object {
    $tokens = $null; $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$parseErrors) | Out-Null
    foreach ($parseError in @($parseErrors)) { $errors.Add("$($_.Name): $($parseError.Message)") }
}
$policy = Get-Content -LiteralPath (Join-Path $root 'config/example.policy.json') -Raw | ConvertFrom-Json
if ($policy.schemaVersion -ne 1) { $errors.Add('Example policy schemaVersion must be 1.') }
if ($errors.Count) { throw ($errors -join [Environment]::NewLine) }
"Static checks passed for $($required.Count) required artifacts."

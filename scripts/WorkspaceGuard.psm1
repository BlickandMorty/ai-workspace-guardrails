Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-WorkspacePolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PolicyPath)

    $resolved = (Resolve-Path -LiteralPath $PolicyPath).Path
    $raw = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8
    $policy = $raw | ConvertFrom-Json
    if ($policy.schemaVersion -ne 1) { throw 'Unsupported or missing schemaVersion. Expected 1.' }
    [pscustomobject]@{
        Path = $resolved
        Raw = $raw
        Hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        Value = $policy
    }
}

function Get-NormalizedPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path)).TrimEnd('\')
}

function Test-PathWithinRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)][string]$Path)
    $rootPath = (Get-NormalizedPath $Root) + '\'
    $candidate = (Get-NormalizedPath $Path) + '\'
    $candidate.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-SafeWorkspaceRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    $full = Get-NormalizedPath $Root
    $drive = [IO.Path]::GetPathRoot($full).TrimEnd('\')
    if ($full.TrimEnd('\') -ieq $drive) { throw 'A drive root cannot be guarded.' }
    $blocked = @(
        $env:WINDIR,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        [Environment]::GetFolderPath('UserProfile')
    ) | Where-Object { $_ }
    foreach ($item in $blocked) {
        if ($full -ieq (Get-NormalizedPath $item)) { throw "Refusing protected broad location: $full" }
    }
    $permanent = Join-Path $env:ProgramData 'WindowsLockdownKit'
    if (Test-PathWithinRoot -Root $permanent -Path $full -ErrorAction SilentlyContinue) {
        throw 'Permanent lockdown artifacts are outside this tool''s scope.'
    }
    $full
}

function Get-CurrentIdentitySids {
    [CmdletBinding()]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    @($identity.User.Value) + @($identity.Groups | ForEach-Object Value) | Select-Object -Unique
}

function Get-WorkspaceZone {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string]$TargetPath)
    $root = Get-NormalizedPath $Policy.workspaceRoot
    $target = Get-NormalizedPath $TargetPath
    if (-not (Test-PathWithinRoot -Root $root -Path $target)) { return $null }
    $matches = foreach ($zone in $Policy.zones) {
        $zonePath = Join-Path $root $zone.relativePath
        if (Test-PathWithinRoot -Root $zonePath -Path $target -or $target -ieq (Get-NormalizedPath $zonePath)) {
            [pscustomobject]@{ Zone = $zone; Length = (Get-NormalizedPath $zonePath).Length }
        }
    }
    $best = @($matches | Sort-Object Length -Descending)
    if ($best.Count -eq 0) { return $null }
    $best[0].Zone
}

function Test-WorkspaceAuthorization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][string]$TargetPath,
        [Parameter(Mandatory)][ValidateSet('Read','CreateOutput','UpdateOutput','Review','ApproveExport','Administer')][string]$Operation,
        [string[]]$IdentitySids = (Get-CurrentIdentitySids)
    )
    $zone = Get-WorkspaceZone -Policy $Policy -TargetPath $TargetPath
    if (-not $zone) { return [pscustomobject]@{ Allowed=$false; Reason='PathOutsideDefinedZone'; Zone=$null; Roles=@() } }
    $roles = foreach ($principal in $Policy.principals) {
        if ($IdentitySids -contains $principal.sid) { @($principal.roles) }
    }
    $roles = @($roles | Select-Object -Unique)
    if ($roles.Count -eq 0) { return [pscustomobject]@{ Allowed=$false; Reason='IdentityNotMapped'; Zone=$zone.id; Roles=@() } }
    $roleAllows = $false
    foreach ($role in $roles) {
        $ops = @($Policy.roles.$role)
        if ($ops -contains $Operation) { $roleAllows = $true }
    }
    $zoneAllows = @($zone.allowedRoles | Where-Object { $roles -contains $_ }).Count -gt 0 -and @($zone.allowedOperations) -contains $Operation
    [pscustomobject]@{
        Allowed = [bool]($roleAllows -and $zoneAllows)
        Reason = if ($roleAllows -and $zoneAllows) { 'PolicyAllows' } else { 'RoleOrZoneDenied' }
        Zone = $zone.id
        Roles = $roles
    }
}

function Write-GuardLedgerEvent {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LedgerPath,[Parameter(Mandatory)][hashtable]$Event)
    $parent = Split-Path -Parent $LedgerPath
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $previous = 'GENESIS'
    if (Test-Path -LiteralPath $LedgerPath) {
        $last = Get-Content -LiteralPath $LedgerPath -Tail 1
        if ($last) { $previous = (($last | ConvertFrom-Json).eventHash) }
    }
    $record = [ordered]@{ timestampUtc=[DateTime]::UtcNow.ToString('o'); previousHash=$previous }
    foreach ($key in ($Event.Keys | Sort-Object)) { $record[$key] = $Event[$key] }
    $withoutHash = $record | ConvertTo-Json -Compress -Depth 8
    $bytes = [Text.Encoding]::UTF8.GetBytes($previous + "`n" + $withoutHash)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $record.eventHash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    Add-Content -LiteralPath $LedgerPath -Value ($record | ConvertTo-Json -Compress -Depth 8) -Encoding UTF8
    [pscustomobject]$record
}

function Get-GuardedFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Policy)
    $root = Get-NormalizedPath $Policy.workspaceRoot
    foreach ($zone in $Policy.zones | Where-Object integrity) {
        $zoneRoot = Join-Path $root $zone.relativePath
        if (Test-Path -LiteralPath $zoneRoot) {
            Get-ChildItem -LiteralPath $zoneRoot -File -Recurse -Force | Where-Object {
                -not ($Policy.denyReparsePoints -and ($_.Attributes -band [IO.FileAttributes]::ReparsePoint))
            } | ForEach-Object {
                [pscustomobject]@{
                    zone = $zone.id
                    relativePath = $_.FullName.Substring($root.Length).TrimStart('\').Replace('\','/')
                    length = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
        }
    }
}

Export-ModuleMember -Function Get-WorkspacePolicy,Get-NormalizedPath,Test-PathWithinRoot,Assert-SafeWorkspaceRoot,Get-CurrentIdentitySids,Get-WorkspaceZone,Test-WorkspaceAuthorization,Write-GuardLedgerEvent,Get-GuardedFiles

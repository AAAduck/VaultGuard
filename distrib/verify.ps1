[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    throw "Distribution manifest check failed: $Message"
}

function Read-YamlScalar([string]$Path, [string]$Key) {
    $pattern = '^\s*' + [regex]::Escape($Key) + ':\s*(.*?)\s*$'
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match $pattern) {
            return $Matches[1].Trim().Trim('"').Trim("'")
        }
    }
    Fail "missing $Key in $Path"
}

function Assert-Sha256([string]$Value, [string]$Label) {
    if ($Value -notmatch '^[0-9A-Fa-f]{64}$') {
        Fail "$Label must be a 64-character SHA-256 value"
    }
}

$scoopPath = Join-Path $Root 'distrib\scoop\VaultGuard.json'
if (-not (Test-Path -LiteralPath $scoopPath)) { Fail "missing $scoopPath" }
$scoop = Get-Content -Raw -LiteralPath $scoopPath | ConvertFrom-Json
$version = [string]$scoop.version
if ($version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') { Fail "invalid Scoop version: $version" }
$releaseUrl = "https://github.com/AAAduck/VaultGuard/releases/download/v$version/VaultGuard.exe"
if ([string]$scoop.url -ne $releaseUrl) { Fail "Scoop URL does not match version $version" }
Assert-Sha256 ([string]$scoop.hash) 'Scoop hash'
if ([string]$scoop.bin -ne 'VaultGuard.exe') { Fail 'Scoop bin must be VaultGuard.exe' }

$wingetBase = Join-Path $Root 'distrib\winget\manifests\a\AAAduck\VaultGuard'
$versionDirs = @(Get-ChildItem -LiteralPath $wingetBase -Directory | Where-Object { $_.Name -match '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$' })
if ($versionDirs.Count -eq 0) { Fail "no winget version directory under $wingetBase" }
$wingetDir = $versionDirs | Sort-Object Name | Select-Object -Last 1
if ($wingetDir.Name -ne $version) { Fail "Scoop version $version differs from latest winget version $($wingetDir.Name)" }

$manifests = @(Get-ChildItem -LiteralPath $wingetDir.FullName -Filter '*.yaml' -File)
if ($manifests.Count -ne 4) { Fail "expected four winget manifests, found $($manifests.Count)" }
foreach ($manifest in $manifests) {
    $manifestVersion = Read-YamlScalar $manifest.FullName 'PackageVersion'
    if ($manifestVersion -ne $version) { Fail "$($manifest.Name) declares version $manifestVersion, expected $version" }
}

$installerPath = Join-Path $wingetDir.FullName 'AAAduck.VaultGuard.installer.yaml'
$installerUrl = Read-YamlScalar $installerPath 'InstallerUrl'
if ($installerUrl -ne $releaseUrl) { Fail "winget installer URL does not match version $version" }
Assert-Sha256 (Read-YamlScalar $installerPath 'InstallerSha256') 'winget installer hash'

Write-Output "Distribution manifests are consistent for VaultGuard $version."

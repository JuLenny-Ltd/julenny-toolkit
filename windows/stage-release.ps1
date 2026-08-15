# Stage the freshly-built Windows MSIX (and its .cer) into the release folder
# under the canonical names used by all prior JuLenny FHE releases:
#
#   julenny-toolkit-linux-amd64
#   julenny-toolkit-linux-amd64.deb
#   julenny-toolkit-windows-amd64.msix
#   julenny-toolkit-windows-amd64.cer
#   SHA256SUMS
#
# No version substring in the artifact filename - the version lives in the
# folder name (v0.X.Y/). Platform label is `amd64`, not `x64`. This script is
# idempotent and will fix up legacy / mistakenly-named files left in the folder.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File windows\stage-release.ps1
#   powershell -ExecutionPolicy Bypass -File windows\stage-release.ps1 -Version 0.4.0

[CmdletBinding()]
param(
    [string]$Version = "0.4.0"
)

$ErrorActionPreference = "Stop"

$projDir    = Join-Path $PSScriptRoot "JuLennyFHE"
$releaseDir = "C:\Users\David\fhe-toolkit-releases\v$Version"
$pkgDir     = Join-Path $projDir "AppPackages\JuLennyFHE\JuLennyFHE_${Version}.0_x64_Test"
$msixSrc    = Join-Path $pkgDir "JuLennyFHE_${Version}.0_x64.msix"
$cerSrc     = Join-Path $pkgDir "JuLennyFHE_${Version}.0_x64.cer"

if (-not (Test-Path $releaseDir)) { throw "Release dir not found: $releaseDir" }
if (-not (Test-Path $msixSrc))    { throw "Source MSIX not found: $msixSrc" }
if (-not (Test-Path $cerSrc))     { throw "Source CER not found: $cerSrc" }

# Canonical destination names (no version, amd64 label).
$linuxBin = Join-Path $releaseDir "julenny-toolkit-linux-amd64"
$linuxDeb = Join-Path $releaseDir "julenny-toolkit-linux-amd64.deb"
$winMsix  = Join-Path $releaseDir "julenny-toolkit-windows-amd64.msix"
$winCer   = Join-Path $releaseDir "julenny-toolkit-windows-amd64.cer"

# Fix up any non-canonical filenames left in the release folder from earlier
# attempts (e.g. `julenny-toolkit-0.4.0-linux-amd64`, `julenny-toolkit-0.4.0-windows-x64.msix`).
Get-ChildItem $releaseDir -File | ForEach-Object {
    $name = $_.Name
    $rename = $null
    switch -Regex ($name) {
        "^julenny-toolkit-${Version}-linux-amd64$"    { $rename = "julenny-toolkit-linux-amd64" }
        "^julenny-toolkit-${Version}-linux-amd64\.deb$" { $rename = "julenny-toolkit-linux-amd64.deb" }
        "^julenny-toolkit-${Version}-windows-x64\.msix$"  { $rename = "julenny-toolkit-windows-amd64.msix" }
        "^julenny-toolkit-${Version}-windows-x64\.cer$"   { $rename = "julenny-toolkit-windows-amd64.cer" }
        "^julenny-toolkit-${Version}-windows-amd64\.msix$" { $rename = "julenny-toolkit-windows-amd64.msix" }
        "^julenny-toolkit-${Version}-windows-amd64\.cer$"  { $rename = "julenny-toolkit-windows-amd64.cer" }
    }
    if ($rename -and $rename -ne $name) {
        $dst = Join-Path $releaseDir $rename
        if (Test-Path $dst) {
            Write-Host "  Removing legacy duplicate: $name (canonical $rename already present)"
            Remove-Item -Force $_.FullName
        } else {
            Write-Host "  Renaming legacy: $name -> $rename"
            Rename-Item -Force $_.FullName $rename
        }
    }
}

# Copy the Windows artifacts to their canonical names (overwrite if present).
Write-Host "Staging Windows artifacts:"
Write-Host "  $msixSrc"
Write-Host "    -> $winMsix"
Copy-Item -Force $msixSrc $winMsix
Write-Host "  $cerSrc"
Write-Host "    -> $winCer"
Copy-Item -Force $cerSrc $winCer

# Sanity-check: all four expected artifacts present.
$expected = @($linuxBin, $linuxDeb, $winMsix, $winCer)
$missing = $expected | Where-Object { -not (Test-Path $_) }
if ($missing) {
    Write-Host ""
    Write-Host "Missing expected release artifacts:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

# Regenerate SHA256SUMS. Order matches prior releases: linux bin, linux deb,
# windows msix, windows cer. Two spaces between hash and filename, lowercase.
$order = @(
    "julenny-toolkit-linux-amd64",
    "julenny-toolkit-linux-amd64.deb",
    "julenny-toolkit-windows-amd64.msix",
    "julenny-toolkit-windows-amd64.cer"
)
$lines = $order | ForEach-Object {
    $path = Join-Path $releaseDir $_
    $hash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
    "{0}  {1}" -f $hash, $_
}
$sumsPath = Join-Path $releaseDir "SHA256SUMS"
# Force LF-terminated lines (matches v0.3.x). Out-File would add CRLF.
[System.IO.File]::WriteAllText($sumsPath, ($lines -join "`n") + "`n")

Write-Host ""
Write-Host "Release folder contents:" -ForegroundColor Green
Get-ChildItem $releaseDir -File | Sort-Object Name | ForEach-Object {
    "  {0,12:N0}  {1}" -f $_.Length, $_.Name
}
Write-Host ""
Write-Host "SHA256SUMS:"
Get-Content $sumsPath | ForEach-Object { "  $_" }

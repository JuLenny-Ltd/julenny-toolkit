# Stage the freshly-built Windows installer into the release folder under the
# canonical names used by all JuLenny FHE releases:
#
#   julenny-toolkit-linux-amd64
#   julenny-toolkit-linux-amd64.deb
#   julenny-toolkit-setup-windows-amd64.exe
#   SHA256SUMS
#
# The Windows artifact is now the Inno installer, not an MSIX + .cer pair
# (packaging D2, decided 2026-08-15: one installer carries the app, the CLI, the
# MCP server and the example scripts). Any leftover .msix/.cer in the release
# folder is deleted so nobody downloads a stale, separately-installable app.
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

$releaseDir = "C:\Users\David\fhe-toolkit-releases\v$Version"
$setupSrc   = Join-Path $PSScriptRoot "installer\Output\julenny-toolkit-setup-windows-amd64.exe"

if (-not (Test-Path $releaseDir)) { throw "Release dir not found: $releaseDir" }
if (-not (Test-Path $setupSrc)) {
    throw "Installer not found: $setupSrc`nBuild it first: iscc windows\installer\julenny-toolkit.iss"
}

# Canonical destination names (no version, amd64 label).
$linuxBin = Join-Path $releaseDir "julenny-toolkit-linux-amd64"
$linuxDeb = Join-Path $releaseDir "julenny-toolkit-linux-amd64.deb"
$winSetup = Join-Path $releaseDir "julenny-toolkit-setup-windows-amd64.exe"

# Fix up any non-canonical filenames left in the release folder from earlier
# attempts (e.g. `julenny-toolkit-0.4.0-linux-amd64`).
Get-ChildItem $releaseDir -File | ForEach-Object {
    $name = $_.Name
    $rename = $null
    switch -Regex ($name) {
        "^julenny-toolkit-${Version}-linux-amd64$"       { $rename = "julenny-toolkit-linux-amd64" }
        "^julenny-toolkit-${Version}-linux-amd64\.deb$"  { $rename = "julenny-toolkit-linux-amd64.deb" }
        "^julenny-toolkit-${Version}-windows-amd64\.exe$" { $rename = "julenny-toolkit-setup-windows-amd64.exe" }
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

# The MSIX and its .cer are no longer release artifacts (packaging D2: the app
# ships inside the installer). Clear out any left over from a previous release
# so customers are not offered a stale, separately-installable app.
foreach ($stale in @("julenny-toolkit-windows-amd64.msix", "julenny-toolkit-windows-amd64.cer")) {
    $p = Join-Path $releaseDir $stale
    if (Test-Path $p) {
        Write-Host "  Removing superseded artifact: $stale (app now ships inside the installer)"
        Remove-Item -Force $p
    }
}

# Copy the Windows installer to its canonical name (overwrite if present).
Write-Host "Staging Windows artifact:"
Write-Host "  $setupSrc"
Write-Host "    -> $winSetup"
Copy-Item -Force $setupSrc $winSetup

# Sanity-check: all three expected artifacts present.
$expected = @($linuxBin, $linuxDeb, $winSetup)
$missing = $expected | Where-Object { -not (Test-Path $_) }
if ($missing) {
    Write-Host ""
    Write-Host "Missing expected release artifacts:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

# Regenerate SHA256SUMS. Order: linux bin, linux deb, windows installer.
# Two spaces between hash and filename, lowercase.
$order = @(
    "julenny-toolkit-linux-amd64",
    "julenny-toolkit-linux-amd64.deb",
    "julenny-toolkit-setup-windows-amd64.exe"
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

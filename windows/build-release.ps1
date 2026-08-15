# Build the JuLenny FHE WinUI 3 app as an UNPACKAGED, self-contained Release|x64
# payload, ready for the Inno installer to bundle.
#
# This no longer produces an MSIX. Packaging is D2 (decided 2026-08-15): one
# installer carries the app, the CLI, the MCP server and the example scripts, so
# a standalone MSIX would be a second artifact to build, sign and keep in sync
# for no one's benefit.
#
# Usage (from any PowerShell prompt):
#   pwsh windows\build-release.ps1            # default: Release|x64, Clean+Rebuild
#   pwsh windows\build-release.ps1 -NoClean   # incremental
#
# What it does:
#   1. Locates VS 2026 via vswhere and enters an x64 dev shell.
#   2. Ensures nuget.exe is present, restores packages.config.
#   3. Invokes msbuild on JuLennyFHE.vcxproj for Release|x64, producing
#        windows\JuLennyFHE\x64\Release\JuLennyFHE\
#      containing JuLennyFHE.exe plus the Windows App SDK runtime.
#   4. Checks the payload is present and self-contained, and reports its size.
#
# Prerequisites already documented in windows\README.md:
#   OpenFHE installed at C:\Users\David\openfhe-install
#   fhe_toolkit_core.lib built at fhe-toolkit\build\core\Release
#   OpenSSL at C:\Program Files\OpenSSL-Win64
#   VS 2026 with WinUI 3 / C++ tooling, plus LLVM (for libomp.dll)

[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [switch]$NoClean
)

$ErrorActionPreference = "Stop"
$scriptDir = $PSScriptRoot
$projDir   = Join-Path $scriptDir "JuLennyFHE"
$vcxproj   = Join-Path $projDir "JuLennyFHE.vcxproj"
$logFile   = Join-Path $scriptDir "build-release.log"

if (-not (Test-Path $vcxproj)) { throw "vcxproj not found at $vcxproj" }

# 1. VS dev shell.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; install VS 2026 first." }
$vsInstall = & $vswhere -latest -property installationPath
if (-not $vsInstall) { throw "No Visual Studio installation found." }
Import-Module "$vsInstall\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vsInstall -SkipAutomaticLocation `
    -DevCmdArguments "-arch=x64 -host_arch=x64" | Out-Null
if ($env:VSCMD_ARG_TGT_ARCH -ne "x64") {
    throw "VSCMD_ARG_TGT_ARCH=$($env:VSCMD_ARG_TGT_ARCH); expected x64."
}
Write-Host "VS install: $vsInstall"
Write-Host "Target arch: $env:VSCMD_ARG_TGT_ARCH"

# 2. NuGet restore (packages.config style).
$nugetExe = "$env:LOCALAPPDATA\Microsoft\NuGet\nuget.exe"
if (-not (Test-Path $nugetExe)) {
    Write-Host "Downloading nuget.exe..."
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $nugetExe) | Out-Null
    Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" `
        -OutFile $nugetExe
}
Push-Location $projDir
try {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $nugetExe restore "packages.config" -PackagesDirectory "packages" -NonInteractive
        $nugetExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prevEAP }
    if ($nugetExit -ne 0) { throw "nuget restore failed (exit $nugetExit)." }
}
finally { Pop-Location }

# 3. msbuild.
# We do NOT pass GenerateAppxPackageOnBuild / AppxBundle / UapAppxPackageBuildMode
# any more. Packaging is D2 (decided 2026-08-15): the app ships inside the single
# Inno installer, not as a standalone MSIX, so building one is wasted time and a
# second artifact to keep in sync.
#
# The project is already set up for this - WindowsPackageType=None and
# WindowsAppSDKSelfContained=true in JuLennyFHE.vcxproj - so a plain Build
# produces an unpackaged, self-contained payload with the Windows App SDK
# runtime alongside the exe. Those msbuild flags were the only thing forcing the
# MSIX path.
$target = if ($NoClean) { "Build" } else { "Clean;Rebuild" }
$msbuildArgs = @(
    $vcxproj,
    "/t:$target",
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    "/m",
    "/v:minimal",
    "/clp:Summary"
)
Write-Host ""
Write-Host "msbuild $($msbuildArgs -join ' ')"
Write-Host "Log: $logFile"
Write-Host ""

# Truncate log, then tee.
# msbuild writes warnings to stderr while still succeeding; drop EAP to Continue
# around the native call and gate on $LASTEXITCODE.
"" | Out-File -FilePath $logFile -Encoding utf8
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & msbuild @msbuildArgs 2>&1 | Tee-Object -FilePath $logFile -Append
    $exit = $LASTEXITCODE
} finally { $ErrorActionPreference = $prevEAP }
if ($exit -ne 0) {
    Write-Host ""
    Write-Host "BUILD FAILED (exit $exit). See $logFile." -ForegroundColor Red
    exit $exit
}

# 4. Check the unpackaged payload. This folder is what the Inno installer's
# AppSourceDir points at, so if it is missing or thin the installer will build
# but ship a broken app.
$payloadDir = Join-Path $projDir "$Platform\$Configuration\JuLennyFHE"
if (-not (Test-Path $payloadDir)) {
    Write-Host ""
    Write-Host "BUILD reported success but the app payload was not produced:" -ForegroundColor Red
    Write-Host "  $payloadDir" -ForegroundColor Red
    Write-Host "Check the log: $logFile" -ForegroundColor Red
    exit 1
}

$exe = Join-Path $payloadDir "JuLennyFHE.exe"
if (-not (Test-Path $exe)) {
    Write-Host "No JuLennyFHE.exe in $payloadDir." -ForegroundColor Red
    exit 1
}

# Self-contained means the Windows App SDK runtime sits next to the exe. If it
# does not, the app will fail to start on a machine without the SDK installed,
# and that failure would only show up on the customer's machine.
$runtimeMarker = Join-Path $payloadDir "Microsoft.WindowsAppRuntime.dll"
if (-not (Test-Path $runtimeMarker)) {
    Write-Host ""
    Write-Host "WARNING: Microsoft.WindowsAppRuntime.dll is not next to the exe." -ForegroundColor Yellow
    Write-Host "The payload may not be self-contained; the app would then need the" -ForegroundColor Yellow
    Write-Host "Windows App SDK installed on the target machine. Check that" -ForegroundColor Yellow
    Write-Host "WindowsAppSDKSelfContained is still true in the vcxproj." -ForegroundColor Yellow
}

$all      = Get-ChildItem $payloadDir -Recurse -File
$totalMB  = [math]::Round((($all | Measure-Object Length -Sum).Sum) / 1MB, 1)
$pdbMB    = [math]::Round((($all | Where-Object { $_.Extension -eq '.pdb' } | Measure-Object Length -Sum).Sum) / 1MB, 1)

Write-Host ""
Write-Host "BUILD SUCCEEDED" -ForegroundColor Green
Write-Host "App payload: $payloadDir"
Write-Host "  files:     $($all.Count)"
Write-Host "  size:      $totalMB MB  (of which $pdbMB MB is .pdb, excluded by the installer)"
Write-Host "  exe:       $exe"
Write-Host "  SHA256:    $((Get-FileHash $exe).Hash)"
Write-Host "Log:         $logFile"
Write-Host ""
Write-Host "Next: windows\installer\julenny-toolkit.iss packages this into setup.exe." -ForegroundColor Cyan

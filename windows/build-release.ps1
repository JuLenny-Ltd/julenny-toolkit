# Build the JuLenny FHE WinUI 3 app as a Release|x64 packaged MSIX.
#
# Usage (from any PowerShell prompt):
#   pwsh windows\build-release.ps1            # default: Release|x64, Clean+Rebuild
#   pwsh windows\build-release.ps1 -NoClean   # incremental
#
# What it does:
#   1. Locates VS 2026 via vswhere and enters an x64 dev shell.
#   2. Ensures nuget.exe is present, restores packages.config.
#   3. Invokes msbuild on JuLennyFHE.vcxproj for Release|x64, producing
#      the packaged MSIX in
#        windows\JuLennyFHE\AppPackages\JuLennyFHE\JuLennyFHE_<ver>_x64_Test\
#   4. Prints MSIX path, size, and SHA256.
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
# Note GenerateAppxPackageOnBuild=true: command-line msbuild defaults this to
# false for WinUI 3 / Windows App SDK projects, so without it the .exe builds
# but no MSIX is produced. The VS IDE sets it via the project template.
$target = if ($NoClean) { "Build" } else { "Clean;Rebuild" }
$msbuildArgs = @(
    $vcxproj,
    "/t:$target",
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    "/p:AppxBundle=Never",
    "/p:UapAppxPackageBuildMode=SideloadOnly",
    "/p:GenerateAppxPackageOnBuild=true",
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

# 4. Locate the produced MSIX. Read the version from the manifest so we match
# the exact expected output dir rather than picking the youngest stale dir.
[xml]$manifest = Get-Content (Join-Path $projDir "Package.appxmanifest")
$nsMgr = New-Object System.Xml.XmlNamespaceManager $manifest.NameTable
$nsMgr.AddNamespace("a", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
$ver = $manifest.SelectSingleNode("/a:Package/a:Identity", $nsMgr).Version
if (-not $ver) { throw "Could not read Version from Package.appxmanifest." }
Write-Host "Manifest version: $ver"

$verDir = Join-Path "$projDir\AppPackages\JuLennyFHE" "JuLennyFHE_${ver}_${Platform}_Test"
if (-not (Test-Path $verDir)) {
    Write-Host ""
    Write-Host "BUILD reported success but expected output dir was not produced:" -ForegroundColor Red
    Write-Host "  $verDir" -ForegroundColor Red
    Write-Host "Check the log for whether the packaging targets actually ran:" -ForegroundColor Red
    Write-Host "  $logFile" -ForegroundColor Red
    exit 1
}
$msix = Get-ChildItem $verDir -Filter "JuLennyFHE_${ver}_${Platform}.msix" | Select-Object -First 1
if (-not $msix) {
    Write-Host "No JuLennyFHE_${ver}_${Platform}.msix found in $verDir." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "BUILD SUCCEEDED" -ForegroundColor Green
Write-Host "MSIX:   $($msix.FullName)"
Write-Host "Size:   $([math]::Round($msix.Length/1MB,2)) MB"
Write-Host "SHA256: $((Get-FileHash $msix.FullName).Hash)"
Write-Host "Log:    $logFile"

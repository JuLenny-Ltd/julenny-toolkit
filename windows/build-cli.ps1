# Build the `julenny-fhe` CLI executable for Windows.
#
# Toolchain: clang-cl (mandatory for OpenFHE compatibility), same as
# build-core.ps1. Reuses the existing build\ directory when present (the
# configure just flips FHE_TOOLKIT_BUILD_CLI on), so run build-core.ps1
# first if you want a clean tree. Produces
#   build\cli\Release\julenny-fhe.exe
# which stage-release.ps1 ships as julenny-fhe-windows-amd64.exe; installed
# (on PATH) it is invoked as plain `julenny-fhe`, same as on Linux.
#
# Usage from any PowerShell:
#   powershell -ExecutionPolicy Bypass -File windows\build-cli.ps1
#   powershell -ExecutionPolicy Bypass -File windows\build-cli.ps1 -Clean

[CmdletBinding()]
param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$repoRoot  = Split-Path -Parent $PSScriptRoot   # ...\fhe-toolkit
$buildDir  = Join-Path $repoRoot "build"
$logFile   = Join-Path $PSScriptRoot "build-cli.log"
$exePath   = Join-Path $buildDir "cli\Release\julenny-fhe.exe"

if (-not (Test-Path (Join-Path $repoRoot "cli\CMakeLists.txt"))) {
    throw "cli/CMakeLists.txt not found; script must live at <repo>/windows/."
}

# 1. VS dev shell, x64.
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

# 2. Optionally wipe the build dir.
if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "Removing existing build dir: $buildDir"
    Remove-Item -Recurse -Force $buildDir
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

# 3. Configure + build. Same flags as build-core.ps1 except the CLI is ON.
# Note: cmake writes warnings to stderr while exiting 0; PowerShell's
# $ErrorActionPreference="Stop" + 2>&1 turns those into terminating errors.
# Drop EAP to Continue around native calls and gate on $LASTEXITCODE.
"" | Out-File -FilePath $logFile -Encoding utf8
Push-Location $buildDir
try {
    Write-Host ""
    Write-Host "Configuring (VS 18 2026 / ClangCL / x86_64-pc-windows-msvc, CLI=ON)..."
    $cmakeArgs = @(
        "..",
        "-G", "Visual Studio 18 2026",
        "-A", "x64",
        "-T", "ClangCL",
        "-Wno-deprecated",
        "-DCMAKE_C_COMPILER_TARGET=x86_64-pc-windows-msvc",
        "-DCMAKE_CXX_COMPILER_TARGET=x86_64-pc-windows-msvc",
        "-DCMAKE_PREFIX_PATH=C:/Users/David/openfhe-install",
        "-DOPENSSL_ROOT_DIR=C:/Program Files/OpenSSL-Win64",
        "-DFHE_TOOLKIT_USE_OPENFHE=ON",
        "-DFHE_TOOLKIT_BUILD_CLI=ON",
        "-DFHE_TOOLKIT_BUILD_TESTS=OFF"
    )
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & cmake @cmakeArgs 2>&1 | Tee-Object -FilePath $logFile -Append
        $cmakeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prevEAP }
    if ($cmakeExit -ne 0) { throw "cmake configure failed (exit $cmakeExit). See $logFile." }

    Write-Host ""
    Write-Host "Building julenny-fhe (Release, parallel)..."
    $ErrorActionPreference = "Continue"
    try {
        & cmake --build . --config Release --target julenny-fhe --parallel 2>&1 | Tee-Object -FilePath $logFile -Append
        $cmakeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prevEAP }
    if ($cmakeExit -ne 0) { throw "cmake build failed (exit $cmakeExit). See $logFile." }
}
finally { Pop-Location }

# 4. Verify the exe was produced and runs.
if (-not (Test-Path $exePath)) {
    throw "Build reported success but $exePath was not produced."
}
$exeInfo = Get-Item $exePath
Write-Host ""
Write-Host "BUILD SUCCEEDED" -ForegroundColor Green
Write-Host "Exe:    $($exeInfo.FullName)"
Write-Host "Size:   $([math]::Round($exeInfo.Length/1MB,2)) MB"
Write-Host "Mtime:  $($exeInfo.LastWriteTime)"
Write-Host "Log:    $logFile"
Write-Host ""
Write-Host "Smoke test (--version):"
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & $exePath --version 2>&1
    $smokeExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $prevEAP }
if ($smokeExit -ne 0) { throw "julenny-fhe.exe --version exited $smokeExit." }

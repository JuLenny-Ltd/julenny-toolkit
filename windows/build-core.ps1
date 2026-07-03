# Rebuild the toolkit's `core` static library for Windows.
#
# Toolchain: clang-cl (mandatory for OpenFHE compatibility). VS 18 2026
# generator with ClangCL toolset. Produces
#   build\core\Release\fhe_toolkit_core.lib
# which the WinUI 3 app (built with MSVC) links against. The two toolsets
# are MSVC-ABI compatible so this mixing works.
#
# Usage from any PowerShell:
#   powershell -ExecutionPolicy Bypass -File windows\build-core.ps1
#   powershell -ExecutionPolicy Bypass -File windows\build-core.ps1 -NoClean
#
# Run this whenever core/ sources change. ~5-10 minutes on a clean build.

[CmdletBinding()]
param(
    [switch]$NoClean
)

$ErrorActionPreference = "Stop"
$repoRoot  = Split-Path -Parent $PSScriptRoot   # ...\fhe-toolkit
$buildDir  = Join-Path $repoRoot "build"
$logFile   = Join-Path $PSScriptRoot "build-core.log"
$libPath   = Join-Path $buildDir "core\Release\fhe_toolkit_core.lib"

if (-not (Test-Path (Join-Path $repoRoot "core\CMakeLists.txt"))) {
    throw "core/CMakeLists.txt not found; script must live at <repo>/windows/."
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

# 2. Wipe build dir on clean rebuilds.
if (-not $NoClean -and (Test-Path $buildDir)) {
    Write-Host "Removing existing build dir: $buildDir"
    Remove-Item -Recurse -Force $buildDir
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

# 3. Configure + build.
# Note: cmake writes warnings (e.g. deprecation notices from transitive deps)
# to stderr while still exiting 0. PowerShell's $ErrorActionPreference="Stop"
# combined with 2>&1 turns those into terminating errors. Drop EAP to Continue
# around the native calls and gate on $LASTEXITCODE ourselves.
"" | Out-File -FilePath $logFile -Encoding utf8
Push-Location $buildDir
try {
    Write-Host ""
    Write-Host "Configuring (VS 18 2026 / ClangCL / x86_64-pc-windows-msvc)..."
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
        "-DFHE_TOOLKIT_BUILD_CLI=OFF",
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
    Write-Host "Building (Release, parallel)..."
    $ErrorActionPreference = "Continue"
    try {
        & cmake --build . --config Release --parallel 2>&1 | Tee-Object -FilePath $logFile -Append
        $cmakeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prevEAP }
    if ($cmakeExit -ne 0) { throw "cmake build failed (exit $cmakeExit). See $logFile." }
}
finally { Pop-Location }

# 4. Verify lib was produced.
if (-not (Test-Path $libPath)) {
    throw "Build reported success but $libPath was not produced."
}
$libInfo = Get-Item $libPath
Write-Host ""
Write-Host "BUILD SUCCEEDED" -ForegroundColor Green
Write-Host "Lib:    $($libInfo.FullName)"
Write-Host "Size:   $([math]::Round($libInfo.Length/1MB,2)) MB"
Write-Host "Mtime:  $($libInfo.LastWriteTime)"
Write-Host "Log:    $logFile"
Write-Host ""
Write-Host "Next: powershell -ExecutionPolicy Bypass -File windows\build-release.ps1"

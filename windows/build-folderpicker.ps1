# Build folderpicker.dll - the modern folder-picker helper for the installer.
#
# IMPORTANT: Inno Setup's setup.exe is a 32-bit process, so this DLL MUST be x86
# or the wizard's LoadLibrary will fail. (Our app/CLI are x64; this helper is a
# separate, installer-only artifact.) Output goes where julenny-toolkit.iss expects
# it, next to the .iss (windows\installer\folderpicker.dll, dontcopy-bundled).
#
# Usage from any PowerShell:
#   powershell -ExecutionPolicy Bypass -File windows\build-folderpicker.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$here   = $PSScriptRoot                              # ...\fhe-toolkit\windows
$src    = Join-Path $here "folderpicker\folderpicker.cpp"
$def    = Join-Path $here "folderpicker\folderpicker.def"
$objDir = Join-Path $here "folderpicker\build"
$outDll = Join-Path $here "installer\folderpicker.dll"

foreach ($f in @($src, $def)) {
    if (-not (Test-Path $f)) { throw "missing source: $f" }
}

# 1. VS dev shell, x86 (32-bit target to match the 32-bit setup.exe).
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; install VS 2026 first." }
$vsInstall = & $vswhere -latest -property installationPath
if (-not $vsInstall) { throw "No Visual Studio installation found." }
Import-Module "$vsInstall\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vsInstall -SkipAutomaticLocation `
    -DevCmdArguments "-arch=x86 -host_arch=x64" | Out-Null
if ($env:VSCMD_ARG_TGT_ARCH -ne "x86") {
    throw "VSCMD_ARG_TGT_ARCH=$($env:VSCMD_ARG_TGT_ARCH); expected x86."
}
Write-Host "VS install: $vsInstall  (target arch: $($env:VSCMD_ARG_TGT_ARCH))"

# 2. Compile the DLL. Intermediates land in $objDir; only the .dll is emitted to
#    windows\installer\. cl writes benign notes to stderr while exiting 0, so drop
#    EAP to Continue around the native call and gate on $LASTEXITCODE.
New-Item -ItemType Directory -Force -Path $objDir | Out-Null
if (Test-Path $outDll) { Remove-Item -Force $outDll }
$prevEAP = $ErrorActionPreference
Push-Location $objDir
try {
    $ErrorActionPreference = "Continue"
    try {
        & cl /nologo /LD /O2 /EHsc /DUNICODE /D_UNICODE `
            "$src" /Fe:"$outDll" `
            /link /DEF:"$def" /IMPLIB:"folderpicker.lib" `
            ole32.lib shell32.lib uuid.lib 2>&1 | Write-Host
        $clExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prevEAP }
    if ($clExit -ne 0) { throw "cl failed (exit $clExit)." }
}
finally { Pop-Location }

if (-not (Test-Path $outDll)) { throw "compile reported success but $outDll was not produced." }

# 3. Verify: the export is present and UNDECORATED (so Inno can bind it).
Write-Host ""
Write-Host "BUILD SUCCEEDED" -ForegroundColor Green
$info = Get-Item $outDll
Write-Host "DLL:  $($info.FullName)"
Write-Host "Size: $([math]::Round($info.Length/1KB,1)) KB"
Write-Host ""
Write-Host "Exports (expect a bare 'ShowFolderDialog', no _@16 decoration):"
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try { & dumpbin /exports "$outDll" 2>&1 | Select-String -Pattern "ShowFolderDialog" }
finally { $ErrorActionPreference = $prevEAP }

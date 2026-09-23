# Copy the JuLenny FHE Toolkit scripts out of the install directory into
# a folder you can run and edit. Windows counterpart to linux/julenny-toolkit-scripts.
#
# The installer calls this with -Dest and -Workdir from its wizard pages. It is also
# safe to run standalone afterwards, which is how you get a second copy or refresh one:
#
#   & "$env:LOCALAPPDATA\Programs\julenny-toolkit\julenny-toolkit-scripts.ps1"
#
# TWO destinations, because the tree has two kinds of thing in it:
#
#   the SCRIPTS go to -Dest, a folder you own and can edit;
#   the SAMPLE DATA goes to <workdir>\samples\, because that is where the scripts and
#     the connector both look for it. Keeping a second copy beside the scripts is what
#     let a stale fixture be run against a fresh one on 2026-09-17 and return a
#     correct-looking zero.
#
# There is no -Role any more. The scripts no longer come in two halves: which side of
# a collaboration this machine is comes from the permission, so there is nothing to
# choose at install time.
#
# Windows PowerShell 5.1 compatible (no ternary, no null-coalescing).
[CmdletBinding()]
param(
    [string] $Dest = '',

    # Where the read-only copy lives. Defaults to the examples folder next to this script.
    [string] $Source = '',

    # The JuLenny working folder; sample data lands in its samples\ subfolder. Resolved
    # the same way the scripts and the connector resolve it when not given.
    [string] $Workdir = '',

    [switch] $Force,

    # Skip the confirmation prompt (used by the installer, and by CI).
    [switch] $Yes
)

$ErrorActionPreference = 'Stop'

function Write-Info    { param([string] $m) Write-Host $m -ForegroundColor DarkGray }
function Write-Ok      { param([string] $m) Write-Host $m -ForegroundColor Green }
function Fail          { param([string] $m) Write-Host "error: $m" -ForegroundColor Red; exit 1 }

# ---------- locate the source tree ----------
if ([string]::IsNullOrWhiteSpace($Source)) {
    $Source = Join-Path $PSScriptRoot 'examples'
}
if (-not (Test-Path -LiteralPath $Source)) {
    Fail "example sources not found at $Source`nPass -Source to override."
}

$destDefault = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'julenny-scripts'

# ---------- destination ----------
if ([string]::IsNullOrWhiteSpace($Dest)) {
    $entered = Read-Host "Where should the scripts go? [$destDefault]"
    if ([string]::IsNullOrWhiteSpace($entered)) { $Dest = $destDefault } else { $Dest = $entered }
}
$Dest = [Environment]::ExpandEnvironmentVariables($Dest)

if (Test-Path -LiteralPath $Dest) {
    $existing = Get-ChildItem -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) {
        Fail "$Dest exists and is not empty.`nPass -Force to overwrite it, or choose a different folder."
    }
}

# ---------- working folder ----------
# Same resolution order as scripts\_core\lib.ps1 and mcp\src\tools\lib\paths.ts, so
# all three surfaces agree on where the samples are. Keep them in step.
if ([string]::IsNullOrWhiteSpace($Workdir)) {
    if ($env:JULENNY_WORKDIR) {
        $Workdir = $env:JULENNY_WORKDIR
    } else {
        try {
            $saved = (Get-ItemProperty -Path 'HKCU:\Software\JuLenny\Toolkit' -Name 'WorkDir' -ErrorAction Stop).WorkDir
            if ($saved -and "$saved".Trim()) { $Workdir = "$saved".Trim() }
        } catch {
            # No installer has run here, or the value was removed. Fall through.
        }
    }
    if ([string]::IsNullOrWhiteSpace($Workdir)) {
        $Workdir = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'julenny-workdir'
    }
}
$Workdir = [Environment]::ExpandEnvironmentVariables($Workdir)
$samplesDest = Join-Path $Workdir 'samples'

# ---------- confirm ----------
if (-not $Yes) {
    Write-Host ""
    Write-Host "  scripts:      $Dest"
    Write-Host "  sample data:  $samplesDest"
    Write-Host ""
    $ok = Read-Host "Proceed? [Y/n]"
    if ([string]::IsNullOrWhiteSpace($ok)) { $ok = 'Y' }
    if ($ok -notmatch '^[Yy]') { Write-Info "Cancelled. Nothing was copied."; exit 0 }
}

# ---------- copy the scripts ----------
# Copy everything, then drop what this machine cannot run. Pruning rather than
# enumerating what to include means a newly added shared file is picked up
# automatically instead of being silently left behind.
if (-not (Test-Path -LiteralPath $Dest)) {
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
}
Copy-Item -Path (Join-Path $Source '*') -Destination $Dest -Recurse -Force

function Remove-IfPresent {
    param([string] $Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force -Confirm:$false
    }
}

# Nothing is pruned by side any more.
#
#   _core\lead and _core\main no longer exist. There is one numbered set of phase
#   scripts, and each phase branches internally on whichever role governs it.
#
#   NEITHER side profile is dropped, even though only one is used at a time. A
#   permission created in the other direction inside the same collaboration makes this
#   machine the other data role, and the scripts follow that by loading the other
#   profile mid-run. Deleting it would turn a supported case into a missing file.

# Drop the Linux scripts. Windows cannot run a .sh, and leaving them beside
# their .ps1 twins invites someone to try the wrong one.
Get-ChildItem -LiteralPath $Dest -Recurse -Filter *.sh -File |
    Remove-Item -Force -Confirm:$false
# The .env side profiles are the bash twins of the .ps1 ones; same reasoning.
Get-ChildItem -LiteralPath $Dest -Recurse -Filter *.env -File |
    Remove-Item -Force -Confirm:$false

# ---------- place the sample data in the working folder ----------
# Overwrite rather than skip. These are shipped fixtures, not the operator's own data,
# and a stale one is the failure this move exists to prevent. The operator's own files
# live flat at the top of the working folder and are never touched here.
$samplesSrc = Join-Path $Source 'samples'
Remove-IfPresent (Join-Path $Dest 'samples')   # never leave a second copy beside the scripts
if (Test-Path -LiteralPath $samplesSrc) {
    if (-not (Test-Path -LiteralPath $samplesDest)) {
        New-Item -ItemType Directory -Force -Path $samplesDest | Out-Null
    }
    Copy-Item -Path (Join-Path $samplesSrc '*') -Destination $samplesDest -Recurse -Force
    Write-Ok "Sample data installed to $samplesDest"
} else {
    Write-Info "No samples\ folder in $Source; skipping sample data."
}

# ---------- next steps ----------
Write-Host ""
Write-Ok "Scripts installed to $Dest"

# List what was actually copied, and give a command that can be pasted as-is.
# A "<scenario>" placeholder is not a next step; the operator should not have to
# go and work out what the options are.
$scenarios = @(Get-ChildItem -LiteralPath $Dest -Directory |
               Where-Object { $_.Name -ne '_core' -and $_.Name -ne 'samples' } |
               Select-Object -ExpandProperty Name)

Write-Host ""
Write-Host "Scenarios available"
foreach ($s in $scenarios) {
    if ($s -eq 'joint-record-overlap') {
        Write-Host "  $s   (simplest: exact whole-number answers)"
    } else {
        Write-Host "  $s"
    }
}

# Prefer joint-record-overlap for the worked example: BFV, so the answer is an
# exact integer the operator can check by hand.
$first = 'joint-record-overlap'
if (-not (Test-Path -LiteralPath (Join-Path $Dest $first))) {
    if ($scenarios.Count -gt 0) { $first = $scenarios[0] } else { $first = '<scenario>' }
}

Write-Host ""
Write-Host "To start"
Write-Host "  cd `"$Dest\$first`""
Write-Host "  .\run.ps1"
Write-Host ""
Write-Info "run.ps1 is menu-driven and resumes wherever you left off. It waits when it"
Write-Info "needs the other side to act. It does not ask which side you are: that comes"
Write-Info "from the permission you pick."
Write-Info "Each scenario's README.md gives its sample data and the expected answer, so"
Write-Info "you can confirm the result is correct. $Dest\README.md has the full phase breakdown."
Write-Host ""
Write-Info "To drive BOTH sides from this one host, give each shell its own working"
Write-Info "folder (`$env:JL_ROOT); see README.md."

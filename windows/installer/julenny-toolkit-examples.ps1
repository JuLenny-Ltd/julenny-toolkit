# Copy the JuLenny FHE Toolkit example scripts out of the install directory into
# a folder you can run and edit. Windows counterpart to linux/julenny-toolkit-examples.
#
# The installer calls this with -Role and -Dest from its wizard pages. It is also
# safe to run standalone afterwards, which is how you change which side is
# installed or get a second copy:
#
#   & "$env:LOCALAPPDATA\Programs\julenny-toolkit\julenny-toolkit-examples.ps1"
#
# Windows PowerShell 5.1 compatible (no ternary, no null-coalescing).
[CmdletBinding()]
param(
    # owner = data owner (acme/), consumer = data consumer (beta/), both = everything.
    [ValidateSet('owner', 'consumer', 'both', '')]
    [string] $Role = '',

    [string] $Dest = '',

    # Where the read-only copy lives. Defaults to the examples folder next to this script.
    [string] $Source = '',

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

$destDefault = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'julenny-examples'

# ---------- role ----------
if ([string]::IsNullOrWhiteSpace($Role)) {
    Write-Host ""
    Write-Host "Which side of the collaboration is this machine?"
    Write-Host ""
    Write-Host "  1) Data owner      - holds the data being queried      (acme\ scripts)"
    Write-Host "  2) Data consumer   - triggers the run, sees the result (beta\ scripts)"
    Write-Host "  3) Both            - single-machine testing"
    Write-Host "  4) Cancel          - don't install the examples"
    Write-Host ""
    $choice = Read-Host "Choose (1-4) [1]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '1' }
    switch ($choice) {
        '1' { $Role = 'owner' }
        '2' { $Role = 'consumer' }
        '3' { $Role = 'both' }
        '4' { Write-Info "Cancelled. Nothing was copied."; exit 0 }
        default { Fail "invalid choice: $choice" }
    }
}

# ---------- destination ----------
if ([string]::IsNullOrWhiteSpace($Dest)) {
    $entered = Read-Host "Where should they go? [$destDefault]"
    if ([string]::IsNullOrWhiteSpace($entered)) { $Dest = $destDefault } else { $Dest = $entered }
}
$Dest = [Environment]::ExpandEnvironmentVariables($Dest)

if (Test-Path -LiteralPath $Dest) {
    $existing = Get-ChildItem -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) {
        Fail "$Dest exists and is not empty.`nPass -Force to overwrite it, or choose a different folder."
    }
}

# ---------- confirm ----------
if (-not $Yes) {
    Write-Host ""
    Write-Host "  role:        $Role"
    Write-Host "  destination: $Dest"
    Write-Host ""
    $ok = Read-Host "Proceed? [Y/n]"
    if ([string]::IsNullOrWhiteSpace($ok)) { $ok = 'Y' }
    if ($ok -notmatch '^[Yy]') { Write-Info "Cancelled. Nothing was copied."; exit 0 }
}

# ---------- copy ----------
# Copy everything, then prune the side that was not asked for. Pruning rather
# than enumerating what to include means a newly added shared file is picked up
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

if ($Role -ne 'both') {
    if ($Role -eq 'owner') {
        $sideToDrop = 'beta'; $roleDirToDrop = 'main'; $profileToDrop = 'data-consumer.env'
    } else {
        $sideToDrop = 'acme'; $roleDirToDrop = 'lead'; $profileToDrop = 'data-owner.env'
    }
    Get-ChildItem -LiteralPath $Dest -Directory | ForEach-Object {
        Remove-IfPresent (Join-Path $_.FullName $sideToDrop)
    }
    Remove-IfPresent (Join-Path $Dest "_core\$roleDirToDrop")
    Remove-IfPresent (Join-Path $Dest "_core\sides\$profileToDrop")
}

# ---------- next steps ----------
if ($Role -eq 'consumer') { $sideDir = 'beta' } else { $sideDir = 'acme' }

Write-Host ""
Write-Ok "Examples installed to $Dest"
Write-Host ""
Write-Host "Next steps"
Write-Host "  1. Pick a scenario:   dir `"$Dest`""
Write-Host "  2. Run your side:     cd `"$Dest\<scenario>\$sideDir`"; .\run.ps1"
Write-Host ""
Write-Info "Start with $Dest\README.md for the prerequisites and the phase breakdown,"
Write-Info "and each scenario's README.md for its sample data and expected result."
if ($Role -eq 'both') {
    Write-Host ""
    Write-Info "You installed both sides. To drive them from one host, give each shell"
    Write-Info "its own workdir (`$env:JL_WORKDIR); see README.md."
}

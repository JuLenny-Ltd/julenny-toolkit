# Shared single-command driver for a JuLenny collaboration. ONE script, BOTH
# sides. Reads the permission's keysetup state from the platform and chains the
# numbered scripts. Fully interactive: it inspects platform state at startup and
# asks; there are no flags except -Help.
#
# Which side we are (data-owner / data-consumer) comes from JULENNY_OUR_SIDE,
# set by the scenario's per-side bootstrap before this runs. The matching side
# profile is dot-sourced below, and the only per-side behaviour lives in the
# branches marked OWNER / CONSUMER.
#
# PowerShell twin of run.sh.

[CmdletBinding()]
param([switch] $Help)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

if ($Help) {
    Get-Content $PSCommandPath | Select-Object -Skip 1 -First 10 | ForEach-Object { $_ -replace '^#\s?', '' }
    exit 0
}

# Which side are we? Dot-source the matching profile BEFORE lib.ps1, whose guard
# requires the profile vars.
$side = $env:JULENNY_OUR_SIDE
if (-not $side) {
    throw "Set JULENNY_OUR_SIDE=data-owner or data-consumer before running (the scenario bootstrap does this)."
}
if ($side -ne 'data-owner' -and $side -ne 'data-consumer') {
    throw "JULENNY_OUR_SIDE must be data-owner or data-consumer, got '$side'"
}
. "$here\sides\$side.ps1"
. "$here\lib.ps1"

function Test-JlIsOwner { return ($script:JULENNY_OUR_SIDE -eq 'data-owner') }

# Resolve the active collab and point the path vars at it (if there is one).
$initialJk = Get-JlActiveJointKey
if ($initialJk) { Set-JlActiveJointKey $initialJk }

# Internal mode flags, set by the interactive front matter below.
$watchMode   = $false
$newTest     = $false
$switchCollab = $false
$onlyDecrypt = $false

$roleDir = $script:JL_ROLE_DIR

# ---------------- State detection ----------------
function Test-JlPeerUploaded {
    param([string] $MessageType)
    return ($null -ne (Get-JlPeerMessageOfType $MessageType))
}

function Test-JlExecutionInState {
    param([string] $State)
    $resp = Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/executions?state=$State&limit=1" -AllowFailure
    if ($null -eq $resp -or -not ((Test-JlHasProperty $resp 'executions'))) { return $false }
    return (@($resp.executions).Count -gt 0)
}

function Get-JlLatestExecutionState {
    $resp = Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/executions?limit=1" -AllowFailure
    if ($null -eq $resp -or -not ((Test-JlHasProperty $resp 'executions'))) { return '' }
    $execs = @($resp.executions)
    if ($execs.Count -eq 0) { return '' }
    return "$($execs[0].state)"
}

# Has this machine already finished its part of the latest released execution?
#
# Which file proves that depends on which flow this side runs, and that is set by
# resultVisibility, not by owner/consumer. The viewer writes my-partial-<id>.bin;
# the releaser writes releaser-partial-<id>.bin. Checking only the viewer's file
# left the consumer-as-releaser case (resultVisibility: dataOwner) believing a
# cycle was still live, so it skipped the trigger and sat in the releaser flow
# waiting for an execution nobody would create, while the owner waited for the
# same execution. Either marker means this cycle is done here.
function Test-JlLatestReleasedDecrypted {
    $resp = Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/executions?state=released&limit=1" -AllowFailure
    if ($null -eq $resp -or -not ((Test-JlHasProperty $resp 'executions'))) { return $false }
    $execs = @($resp.executions)
    if ($execs.Count -eq 0) { return $false }
    $id = $execs[0].id
    if (Test-Path -LiteralPath (Join-Path $script:JL_KEYS_DIR "my-partial-$id.bin"))       { return $true }
    return (Test-Path -LiteralPath (Join-Path $script:JL_KEYS_DIR "releaser-partial-$id.bin"))
}

# Pin the newest released execution that has NOT been decrypted on this machine,
# writing it to the same last_exec_id marker the consumer side uses. The viewer
# flow already honours that marker and waits for that specific execution, so this
# is how the owner-as-viewer asks for the NEXT cycle rather than the stale one.
# Returns $false while every released execution has already been revealed here.
function Set-JlNextUndecryptedExecution {
    $resp = Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/executions?state=released" -AllowFailure
    if ($null -eq $resp -or -not ((Test-JlHasProperty $resp 'executions'))) { return $false }
    foreach ($e in @($resp.executions)) {
        $mine     = Join-Path $script:JL_KEYS_DIR "my-partial-$($e.id).bin"
        $released = Join-Path $script:JL_KEYS_DIR "releaser-partial-$($e.id).bin"
        if ((-not (Test-Path -LiteralPath $mine)) -and (-not (Test-Path -LiteralPath $released))) {
            Set-Content -LiteralPath (Join-Path $script:JL_WORKDIR 'last_exec_id') -Value $e.id -Encoding ascii
            return $true
        }
    }
    return $false
}

# We always gate on the PEER's bundle uploads. The lead publishes pk-share as
# bundle 1; the main publishes relin-round1-continue. Each side waits for the
# other's bundle-1 message type; bundle 2 is the same type both ways.
# An additive-only function (requiredEvalKeys: []) has no relin exchange at all, so
# bundle 1 is just the pk-share pair and there is no bundle 2. Waiting for
# relin-round1-continue there hangs forever: the platform goes straight to
# awaiting-finalization and refuses further messages.
$script:JlNeedsRelin = Test-JlFunctionRequiresRelinKeys
if (Test-JlIsOwner -and $script:JlNeedsRelin) { $peerBundle1Type = 'relin-round1-continue' } else { $peerBundle1Type = 'pk-share' }
if (Test-JlIsOwner) { $ownBundle1Marker = 'fhe_public_key.bin' } else { $ownBundle1Marker = 'joint_public_key.bin' }
if ($script:JlNeedsRelin) { if (Test-JlIsOwner) { $ownBundle1Marker = 'lead-relin-r1.bin' } else { $ownBundle1Marker = 'main-relin-r1.bin' } }

# ---------------- Gate: wait, or exit and let the operator re-run ----------------
function Invoke-JlGate {
    param(
        [Parameter(Mandatory = $true)][string] $Description,
        [Parameter(Mandatory = $true)][scriptblock] $Check
    )
    if (& $Check) { return }

    if ($watchMode) {
        Write-JlInfo "Watching: $Description"
        $delay = 15
        $elapsed = 0
        while (-not (& $Check)) {
            Start-Sleep -Seconds $delay
            $elapsed += $delay
            Write-Host ("  (still waiting for {0}, {1}s elapsed)" -f $Description, $elapsed)
            if ($delay -lt 120) { $delay += 15 }
        }
        Write-JlSuccess "$Description satisfied."
        return
    }

    Write-Host ""
    Write-JlInfo "Waiting for: $Description"
    Write-JlInfo "Rerun this script when $($script:JL_PEER_LABEL) is done (or use watch mode to poll here)."
    exit 0
}

# Runs a numbered phase script as its own process, exactly as run.sh does.
function Invoke-JlPhase {
    param([Parameter(Mandatory = $true)][string] $ScriptName)
    $path = Join-Path (Join-Path $here $roleDir) $ScriptName
    if (-not (Test-Path -LiteralPath $path)) { Stop-JlWithError "Phase script not found: $path" }
    # Clear it first. Invoking a PowerShell script does NOT set $LASTEXITCODE: it
    # keeps whatever the last NATIVE process left behind. Without this reset, a
    # stale non-zero from any earlier command is blamed on the phase, and a phase
    # that returned normally - "final keys already submitted", which is the
    # idempotent success path - is reported as "exited with code 1" and stops the
    # run. The bash phases end with an explicit exit 0; these do not.
    $global:LASTEXITCODE = 0
    & $path
    if ($LASTEXITCODE -ne 0) {
        Stop-JlWithError "$ScriptName exited with code $LASTEXITCODE"
    }
}

# ---------------- Interactive front matter ----------------
$sessionExists = $false
$currentPerm = ''
$currentFn = ''
$latestState = ''

if ($script:JL_CONFIG -and (Test-Path -LiteralPath $script:JL_CONFIG)) {
    $sessionExists = $true
    Import-JlSession
    $currentPerm = $script:JULENNY_PERMISSION_ID
    $def = Get-JlFunctionDefObject
    if ($def) { $currentFn = "$($def.slug) v$($def.version)" }
    $latestState = Get-JlLatestExecutionState
    if (-not $latestState) { $latestState = 'none' }
}

Write-Host ""
Write-Host "============================================================"
Write-Host " $($script:JL_OUR_LABEL.ToUpper()) RUN: what would you like to do?"
Write-Host "============================================================"

if ($sessionExists) {
    Write-Host " Current permission: $currentPerm"
    Write-Host " Current function:   $(if ($currentFn) { $currentFn } else { 'unknown' })"
    Write-Host " Latest exec state:  $latestState"
    Write-Host "------------------------------------------------------------"
    Write-Host ""
    Write-Host " 1) Continue the current cycle on this permission"
    if (Test-JlIsOwner) {
        Write-Host "    (resume whichever phase isn't done: keysetup, encrypt,"
        Write-Host "     or release after $($script:JL_PEER_LABEL) triggers)."
    } else {
        Write-Host "    (resume whichever phase isn't done: keysetup, encrypt,"
        Write-Host "     trigger execution, or decrypt)."
    }
    Write-Host ""
    Write-Host " 2) Start a NEW test cycle on this permission (keysetup reused)"
    Write-Host ""
    Write-Host " 3) Switch to a different permission or collaboration"
    Write-Host ""

    if (Test-JlIsOwner) {
        Write-Host " 4) Quit"
        Write-Host ""
        switch -Regex ($latestState) {
            '^(awaiting-release|computing|queued)$' { $defaultAction = '1' }
            '^released$'                            { $defaultAction = '2' }
            '^(none|)$'                             { $defaultAction = '2' }
            default                                 { $defaultAction = '1' }
        }
        $action = Read-JlValue "Choose (1-4)" $defaultAction
    } else {
        Write-Host " 4) Just decrypt the latest released execution"
        Write-Host ""
        Write-Host " 5) Quit"
        Write-Host ""
        switch -Regex ($latestState) {
            '^released$'                            { $defaultAction = '4' }
            '^(awaiting-release|computing|queued)$' { $defaultAction = '1' }
            '^(none|)$'                             { $defaultAction = '2' }
            default                                 { $defaultAction = '1' }
        }
        $action = Read-JlValue "Choose (1-5)" $defaultAction
    }
} else {
    Write-Host " No active session detected - looks like a first run on this machine."
    Write-Host ""
    Write-Host " 1) Set up: pick a collaboration + permission, fetch the function def."
    Write-Host ""
    Write-Host " 2) Quit"
    Write-Host ""
    $action = Read-JlValue "Choose (1-2)" '1'
}

switch ($action) {
    '1' { }
    '2' {
        if ($sessionExists) { $newTest = $true } else { Write-JlInfo "Exiting."; exit 0 }
    }
    '3' { $switchCollab = $true }
    '4' {
        if (Test-JlIsOwner) { Write-JlInfo "Exiting."; exit 0 } else { $onlyDecrypt = $true }
    }
    '5' {
        if (Test-JlIsOwner) { Stop-JlWithError "Invalid choice: $action" } else { Write-JlInfo "Exiting."; exit 0 }
    }
    default { Stop-JlWithError "Invalid choice: $action" }
}

Write-Host ""
Write-Host " Watch mode polls the platform until each peer-dependent phase is"
Write-Host " satisfied. Without it, the script exits at the first wait and you"
Write-Host " re-run when the peer is done."
$watch = Read-JlValue "Use watch mode? (Y/n)" 'Y'
if ($watch -match '^[Yy]') { $watchMode = $true }

# Switching clears the active-collab pointer so 00-init's picker re-runs. The
# previous collab's state stays on disk under JL_COLLABS_DIR.
if ($switchCollab) {
    Write-JlInfo "Switching collab: clearing $($script:JL_CURRENT_FILE)."
    Write-JlInfo "  Previous collab's state remains on disk under $($script:JL_COLLABS_DIR)"
    Remove-Item -LiteralPath $script:JL_CURRENT_FILE -Force -ErrorAction SilentlyContinue
    $script:JL_WORKDIR = ''; $script:JL_CONFIG = ''
    $script:JL_KEYS_DIR = ''; $script:JL_ENV_DIR = ''; $script:JL_PEER_DIR = ''
}

# ---------------- Main dispatch ----------------

# Phase 0: ensure a session exists.
if (-not $script:JL_CONFIG -or -not (Test-Path -LiteralPath $script:JL_CONFIG)) {
    Write-JlStep "$($script:JL_OUR_LABEL): initial session setup"
    Invoke-JlPhase '00-init.ps1'
    $jk = Get-JlActiveJointKey
    if ($jk) { Set-JlActiveJointKey $jk }
}
Import-JlSession

# Re-fetch the function-def (mutable per slug/version); soft-fails offline.
try { Update-JlFunctionDef | Out-Null } catch { Write-JlWarn "Could not refresh the function definition; using the local copy." }

# Consumer shortcut: skip everything and just decrypt. 06-decrypt is
# self-contained (polls, and picks if there are several).
if ($onlyDecrypt) {
    Write-JlStep "$($script:JL_OUR_LABEL): decrypt latest released execution"
    Invoke-JlPhase '06-decrypt.ps1'
    exit 0
}

# Show which permission and function this run will use.
$def = Get-JlFunctionDefObject
if ($def) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host " CURRENT PERMISSION / FUNCTION FOR THIS RUN:"
    Write-Host "   Permission ID : $($script:JULENNY_PERMISSION_ID)"
    Write-Host "   Function      : $($def.slug) v$($def.version)"
    if ((Test-JlHasProperty $def 'description') -and $def.description) {
        Write-Host "   Description   : $($def.description)"
    }
    Write-Host "   (To use a different permission/function: switch at startup.)"
    Write-Host "============================================================"
    Write-Host ""
}

# Phase 1-2: keysetup, driven by platform state.
$perm = Get-JlPermission
$ksState = "$($perm.keysetupState)"
Write-JlInfo "Permission keysetup state (platform-reported): $ksState"

switch -Regex ($ksState) {
    '^(abandoned|failed-keysetup)$' {
        Stop-JlWithError "Keysetup is in state '$ksState'. Needs an operator decision (retry or recreate) via the web UI."
    }
    '^complete$' {
        # A joint key completed by an earlier keysetup pair. Bundles can only be
        # skipped if THIS machine still holds its secret share; without it the
        # end-of-cycle crypto cannot run.
        $myShare = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE
        if (-not (Test-Path -LiteralPath $myShare)) {
            Write-JlErr "Joint key is complete on the platform, but this machine is missing"
            Write-JlErr "  $myShare"
            Write-JlErr "That secret share was produced by the original keysetup. Without it, this"
            Write-JlErr "machine can't contribute partial decryptions, so we can't proceed."
            Write-Host ""
            Write-JlErr "Recovery: restore ~\.julenny-collab from the machine that participated in"
            Write-JlErr "the keysetup, or create a NEW collaboration so a fresh keysetup generates"
            Write-JlErr "a new secret share on this machine."
            Stop-JlWithError "Cannot proceed."
        }
        Write-JlInfo "Joint key is already complete (reused or finalized). Skipping bundles."
    }
    '^(pending-keysetup|in-progress)$' {
        if (Test-JlIsOwner) {
            # OWNER: publish bundle 1, wait, publish bundle 2, wait.
            if (-not (Test-Path -LiteralPath (Join-Path $script:JL_KEYS_DIR $ownBundle1Marker))) {
                Write-JlStep "$($script:JL_OUR_LABEL): keysetup bundle 1"
                Invoke-JlPhase '01-keysetup-1.ps1'
            }
            Invoke-JlGate "$($script:JL_PEER_LABEL) to complete bundle 1 ($peerBundle1Type)" { Test-JlPeerUploaded $peerBundle1Type }
            if ($script:JlNeedsRelin) {
                if (-not (Test-Path -LiteralPath (Join-Path $script:JL_KEYS_DIR 'lead-relin-r2.bin'))) {
                    Write-JlStep "$($script:JL_OUR_LABEL): keysetup bundle 2"
                    Invoke-JlPhase '02-keysetup-2.ps1'
                }
                Invoke-JlGate "$($script:JL_PEER_LABEL) to complete bundle 2 (relin-round2)" { Test-JlPeerUploaded 'relin-round2' }
            }
        } else {
            # CONSUMER: wait for bundle 1, publish, wait for bundle 2, publish.
            if (-not (Test-Path -LiteralPath (Join-Path $script:JL_KEYS_DIR $ownBundle1Marker))) {
                Invoke-JlGate "$($script:JL_PEER_LABEL) to publish bundle 1 (pk-share)" { Test-JlPeerUploaded $peerBundle1Type }
                Write-JlStep "$($script:JL_OUR_LABEL): keysetup bundle 1"
                Invoke-JlPhase '01-keysetup-1.ps1'
            }
            if ($script:JlNeedsRelin) {
                if (-not (Test-Path -LiteralPath (Join-Path $script:JL_KEYS_DIR 'main-relin-r2.bin'))) {
                    Invoke-JlGate "$($script:JL_PEER_LABEL) to publish bundle 2 (relin-round2)" { Test-JlPeerUploaded 'relin-round2' }
                    Write-JlStep "$($script:JL_OUR_LABEL): keysetup bundle 2"
                    Invoke-JlPhase '02-keysetup-2.ps1'
                }
            }
        }
        $perm = Get-JlPermission
        $ksState = "$($perm.keysetupState)"
        Write-JlInfo "Permission keysetup state (after bundles): $ksState"
    }
    default {
        Write-JlWarn "Unrecognized keysetupState: '$ksState'. Proceeding optimistically."
    }
}

# Phase 3: finalize when needed (fresh keysetup, or a reused joint key whose
# finalKeys row for THIS permission is not populated yet). 03 is idempotent.
if ($ksState -eq 'awaiting-finalization' -or $ksState -eq 'complete') {
    Write-JlStep "$($script:JL_OUR_LABEL): finalize keysetup"
    Invoke-JlPhase '03-finalize-keysetup.ps1'
}

# Phase 4: encrypt + upload/declare this side's dataset(s).
# Gate on whether THIS permission's required inputs for OUR role are declared,
# NOT on a project-wide dataset count. In a multi-function collaboration,
# datasets declared for one permission must not suppress the upload step for a
# different permission sharing the same project.
if (Test-JlIsOwner) { $myFnRole = 'dataOwner' } else { $myFnRole = 'queryAnalyst' }

$def = Get-JlFunctionDefObject
$myInputNames = @()
if ($def -and ((Test-JlHasProperty $def 'inputs')) -and $def.inputs) {
    $myInputNames = @($def.inputs | Where-Object { $_.role -eq $myFnRole } | ForEach-Object { $_.name })
}

$undeclared = @()
if ($myInputNames.Count -gt 0) {
    $declared = Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/preferred-datasets" -AllowFailure
    foreach ($n in $myInputNames) {
        $id = ''
        if ($declared -and ((Test-JlHasProperty $declared $n)) -and $declared.$n) { $id = $declared.$n.datasetId }
        if (-not $id) { $undeclared += $n }
    }
}

if ($myInputNames.Count -eq 0) {
    Write-JlInfo "Function declares no inputs for $($script:JL_OUR_LABEL)'s role ($myFnRole); nothing to upload."
} elseif ($newTest) {
    Write-JlStep "$($script:JL_OUR_LABEL): encrypt and upload dataset (new test cycle)"
    $env:JULENNY_NEW_TEST = '1'
    try { Invoke-JlPhase '04-encrypt.ps1' } finally { Remove-Item Env:\JULENNY_NEW_TEST -ErrorAction SilentlyContinue }
} elseif ($undeclared.Count -gt 0) {
    Write-JlStep "$($script:JL_OUR_LABEL): declare/upload dataset(s) for this permission"
    Write-JlInfo "Inputs not yet declared for this permission: $($undeclared -join ' ')"
    Write-JlInfo "(Pick an existing dataset to reuse it, or 'u' to upload a fresh one.)"
    Invoke-JlPhase '04-encrypt.ps1'
} else {
    Write-JlInfo "All of $($script:JL_OUR_LABEL)'s inputs are already declared for this permission. Skipping upload."
}

# Phase 4.5: rotation key augmentation. A no-op unless the function-def declares
# rotation in requiredEvalKeys; the script itself decides.
Write-JlStep "$($script:JL_OUR_LABEL): rotation key augmentation (if required by function)"
Invoke-JlPhase '04.5-rotation-keysetup.ps1'

# Phase 5: end-of-cycle. Both end-of-cycle scripts dispatch internally on
# resultVisibility. The difference here is structural: the consumer triggers the
# execution; the owner waits for that trigger and then releases.
if (Test-JlIsOwner) {
    if ((Test-JlExecutionInState 'released') -and
        (-not (Test-JlExecutionInState 'awaiting-release')) -and
        (Test-JlAmReleaser)) {
        if (-not $newTest) {
            Write-JlInfo "Latest execution is already released."
            $ans = Read-JlValue "Wait for a new test cycle to be triggered by $($script:JL_PEER_LABEL)? (y/N)" 'N'
            if ($ans -notmatch '^[Yy]') {
                Write-JlInfo "Exiting. (Start a new test cycle next time to skip this prompt.)"
                exit 0
            }
            $newTest = $true
        }
        Write-JlInfo "Waiting for $($script:JL_PEER_LABEL) to trigger a new execution..."
    }
    elseif ((-not $newTest) -and (-not (Test-JlAmReleaser)) -and
            (Test-JlExecutionInState 'released') -and
            (-not (Test-JlExecutionInState 'awaiting-release')) -and
            (Test-JlLatestReleasedDecrypted)) {
        # Owner-as-viewer (resultVisibility: dataOwner). The branch above only covers
        # the owner when it is the RELEASER, so with no guard here the viewer flow
        # picked up the previous cycle's released execution and revealed its answer
        # again. That reads exactly like a fresh pass, which is how a replayed CPU
        # answer could be recorded as a GPU one. The consumer path has had the
        # equivalent check all along.
        Write-JlInfo "Latest released execution is already decrypted on this machine."
        $ans = Read-JlValue "Wait for a new test cycle to be triggered by $($script:JL_PEER_LABEL)? (y/N)" 'N'
        if ($ans -notmatch '^[Yy]') {
            Write-JlInfo "Exiting. (Start a new test cycle next time to skip this prompt.)"
            exit 0
        }
        $newTest = $true
        Write-JlInfo "Waiting for $($script:JL_PEER_LABEL) to trigger a new execution..."
        Invoke-JlGate "a new execution to be released by $($script:JL_PEER_LABEL)" { Set-JlNextUndecryptedExecution }
    }
    Write-JlStep "$($script:JL_OUR_LABEL): end-of-cycle (resultVisibility: $($script:JULENNY_RESULT_VISIBILITY))"
    Invoke-JlPhase '05-release.ps1'
    Write-Host ""
    Write-JlSuccess "All $($script:JL_OUR_LABEL) phases done."
} else {
    $anyExec = (Test-JlExecutionInState 'awaiting-release') -or
               (Test-JlExecutionInState 'released') -or
               (Test-JlExecutionInState 'computing') -or
               (Test-JlExecutionInState 'queued')

    $needTrigger = $false
    if (-not $anyExec) {
        $needTrigger = $true
    } elseif ($newTest) {
        Write-JlInfo "New test cycle: triggering a fresh execution even though prior ones exist."
        $needTrigger = $true
    } elseif (Test-JlLatestReleasedDecrypted) {
        Write-JlInfo "Latest released execution is already decrypted on this machine."
        $ans = Read-JlValue "Start a new test cycle (trigger a fresh execution)? (y/N)" 'N'
        if ($ans -match '^[Yy]') {
            $newTest = $true
            $needTrigger = $true
        } else {
            Write-JlInfo "Exiting. (Start a new test cycle next time to skip this prompt.)"
            exit 0
        }
    }

    if ($needTrigger) {
        Invoke-JlGate "all function inputs to be declared by both sides" { Test-JlAllRequiredInputsDeclared }
        Write-JlStep "$($script:JL_OUR_LABEL): trigger function execution"
        Invoke-JlPhase '05-run-query.ps1'
    }

    Write-JlStep "$($script:JL_OUR_LABEL): end-of-cycle (resultVisibility: $($script:JULENNY_RESULT_VISIBILITY))"
    Invoke-JlPhase '06-decrypt.ps1'
    Write-Host ""
    Write-JlSuccess "All $($script:JL_OUR_LABEL) phases done. Answer is above."
}

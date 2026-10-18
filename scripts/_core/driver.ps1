# The driver behind ..\run.ps1. ONE script, BOTH sides, every scenario. Reads the
# permission's keysetup state from the platform and chains the numbered scripts.
# Fully interactive: it inspects platform state at startup and asks; there are no
# flags except -Help.
#
# Run ..\run.ps1 rather than this directly; it is the documented entry point and
# this file's location is an implementation detail.
#
# Which side we are (data-owner / data-consumer) comes from the PERMISSION, via the
# collaboration's config.env that 00-init writes. lib.ps1 resolves it and loads the
# matching side profile; the only per-side behaviour here lives in the branches
# marked OWNER / CONSUMER.
#
# On a first run there is no permission yet and so no side, which is a normal state
# and not an error. The operator is never asked which side this is, because picking a
# permission answers it.
#
# There is ONE numbered set of phase scripts, not one per role. A set per data role
# would be wrong, because the keysetup role is a separate thing and a permission created
# in the other direction inside the same collaboration makes the two disagree. Each
# phase branches internally on whichever role actually governs it: keysetup role for
# 01, 02, 03 and 04.5; data role for 00-init and 04-encrypt; resultVisibility for
# 06-end-of-cycle.
#
# PowerShell twin of run.sh.

[CmdletBinding()]
param([switch] $Help)

# Captured here because a function's $PSBoundParameters is its own, and
# Invoke-JlOfferAnotherCycle re-invokes this script with its original arguments.
$script:JlScriptArgs = $PSBoundParameters

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

if ($Help) {
    Get-Content $PSCommandPath | Select-Object -Skip 1 -First 10 | ForEach-Object { $_ -replace '^#\s?', '' }
    exit 0
}

# lib.ps1 resolves the side: JULENNY_OUR_SIDE if something set it (a direct run, or a
# test driving both sides from one host), else the active collaboration's config.env,
# else neutral until a permission is picked.
#
# Do not demand JULENNY_OUR_SIDE up front: nothing in a fresh window sets it, so a
# check that passes only where a stale value is left in the shell fails the moment
# anyone opens a new one.
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
            Set-Content -LiteralPath (Get-JlExecMarkerPath) -Value $e.id -Encoding ascii
            return $true
        }
    }
    return $false
}

# We always gate on the PEER's bundle uploads. The LEAD publishes pk-share as bundle 1;
# the MAIN publishes relin-round1-continue. Each side waits for the other's bundle-1
# message type; bundle 2 is the same type both ways.
#
# This branches on the KEYSETUP role, not the DATA role: the two give the same answer
# only while the roles agree. On a permission created in the other direction the data
# role would wait for the message type this machine had itself just published, and look
# for its own key share under the other half's filename.
#
# An additive-only function (requiredEvalKeys: []) has no relin exchange at all, so
# bundle 1 is just the pk-share pair and there is no bundle 2. Waiting for
# relin-round1-continue there hangs forever: the platform goes straight to
# awaiting-finalization and refuses further messages.
#
# Recomputed after 00-init, because on a first run neither the function-def nor the
# keysetup role is known yet. Kept in one function so the two calls cannot drift.
#
# The lines this replaced also read `if (Test-JlIsOwner -and $x)`, which does not mean
# what it looks like: a function with no param block swallows `-and` and the operand
# into $args and returns its own value, so the second condition never applied.
function Resolve-JlBundleMarkers {
    $script:JlNeedsRelin = Test-JlFunctionRequiresRelinKeys
    # A bundle is done when its LAST round is on the platform, not when a local file exists:
    # a file appears halfway through a bundle, so trusting it would take a crash after it
    # for a finished bundle and skip that bundle for good. Twin of driver.sh.
    $needsSum = Test-JlFunctionRequiresSumKeys
    if (Test-JlAmKeysetupLead) {
        if ($script:JlNeedsRelin) { $script:JlPeerBundle1Type = 'relin-round1-continue' }
        else { $script:JlPeerBundle1Type = 'pk-share' }
        $script:JlOwnBundle1Round = 1
        if ($script:JlNeedsRelin) { $script:JlOwnBundle1Round = 2 }
        if ($needsSum) { $script:JlOwnBundle1Round = 5 }
    } else {
        $script:JlPeerBundle1Type = 'pk-share'
        $script:JlOwnBundle1Round = 1
        if ($script:JlNeedsRelin) { $script:JlOwnBundle1Round = 3 }
        if ($needsSum) { $script:JlOwnBundle1Round = 6 }
    }
    $script:JlOwnBundle2Round = 4
}
Resolve-JlBundleMarkers

# ---------------- Gate: wait, or exit and let the operator re-run ----------------
function Invoke-JlGate {
    param(
        [Parameter(Mandatory = $true)][string] $Description,
        [Parameter(Mandatory = $true)][scriptblock] $Check
    )
    if (& $Check) { return }

    if ($watchMode) {
        Start-JlWait "Watching: $Description"
        # The first check above already failed.
        while ($true) {
            Write-JlWaitDot
            Start-Sleep -Seconds 15
            if (& $Check) { break }
        }
        Complete-JlWait
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
    $path = Join-Path $here $ScriptName
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
    # The dataset size a large-dataset permission was set up for, beside its function.
    $currentSize = Get-JlPermissionSizeText
    if ($currentSize) { $currentFn = "$(if ($currentFn) { $currentFn } else { 'unknown' }), size: $currentSize" }
    $latestState = Get-JlLatestExecutionState
    if (-not $latestState) { $latestState = 'none' }
}

# Re-entry from "wait for another cycle" at the end of a previous run. The answers are
# already known, so skip the menu entirely rather than asking the operator to retype
# them: same permission, a new cycle, still watching.
if ($env:JL_NEXT_CYCLE -eq '1') {
    $newTest = $true
    $watchMode = $true
    Remove-Item Env:\JL_NEXT_CYCLE -ErrorAction SilentlyContinue
    Write-JlStep "$($script:JL_OUR_LABEL): next test cycle on the same permission"
}

if (-not $newTest) {
Write-Host ""
Write-Host "============================================================"
# Always a neutral heading. The side is decided per PERMISSION, and this menu comes
# before any is picked: the loaded side is the current permission's, so a heading built
# from it could name the wrong side for the permission about to be picked. The side is
# shown on the current permission's line instead, where it is true for that permission.
# Twin of driver.sh.
Write-Host " JULENNY RUN: what would you like to do?"
Write-Host "============================================================"

if ($sessionExists) {
    if ($script:JL_SIDE_KNOWN) {
        Write-Host " Current permission: $currentPerm (you: $($script:JL_OUR_LABEL), $($script:JL_ROLE_LABEL))"
    } else {
        Write-Host " Current permission: $currentPerm"
    }
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
        $maxAction = 4
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
        $maxAction = 5
    }
} else {
    Write-Host " No collaboration is open on this machine yet."
    Write-Host ""
    Write-Host " 1) Start: choose one of your collaborations and permissions, or create a new one"
    Write-Host ""
    Write-Host " 2) Quit"
    Write-Host ""
    $maxAction = 2
    $defaultAction = '1'
}

while ($true) {
    $action = Read-JlValue "Choose (1-$maxAction)" $defaultAction
    if ($action -match ('^[1-{0}]$' -f $maxAction)) { break }
    Write-JlWarn "Invalid choice: '$action' (must be 1-$maxAction). Try again."
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
}  # end of the interactive front matter (skipped on a next-cycle re-entry)

# Switching clears the active-collab pointer so 00-init's picker re-runs. The
# previous collab's state stays on disk under JL_COLLABS_DIR.
if ($switchCollab) {
    Write-JlInfo "Switching collab: clearing $($script:JL_CURRENT_FILE)."
    Write-JlInfo "  Previous collab's state remains on disk under $($script:JL_COLLABS_DIR)"
    Remove-Item -LiteralPath $script:JL_CURRENT_FILE -Force -ErrorAction SilentlyContinue
    $script:JL_WORKDIR = ''; $script:JL_CONFIG = ''
    $script:JL_KEYS_DIR = ''; $script:JL_ENV_DIR = ''; $script:JL_PEER_DIR = ''
    # The previous permission's side goes with it: until the next one is picked this
    # machine has no side, and 00-init would otherwise read it back from the environment
    # and label the whole setup with it.
    Import-JlNeutralSide
    Remove-Item Env:JULENNY_OUR_SIDE -ErrorAction SilentlyContinue
}

# ---------------- Main dispatch ----------------

# Phase 0: ensure a session exists.
if (-not $script:JL_CONFIG -or -not (Test-Path -LiteralPath $script:JL_CONFIG)) {
    if ($script:JL_SIDE_KNOWN) { Write-JlStep "$($script:JL_OUR_LABEL): initial session setup" } else { Write-JlStep 'Initial session setup' }
    while ($true) {
        Invoke-JlPhase '00-init.ps1'
        # 00-init also ends without a selection when there is no collaboration yet and the
        # operator declines to create one. Check the CURRENT pointer itself, not
        # Get-JlActiveJointKey's most-recent-collaboration fallback, which would pick some
        # other collaboration. Twin of driver.sh.
        $selected = ''
        if (Test-Path -LiteralPath $script:JL_CURRENT_FILE) {
            $selected = ([System.IO.File]::ReadAllText($script:JL_CURRENT_FILE)).Trim()
        }
        if ($selected -and (Test-Path -LiteralPath (Join-Path (Join-Path $script:JL_COLLABS_DIR $selected) 'config.env'))) {
            Set-JlActiveJointKey $selected
            break
        }
        Write-Host ''
        Write-JlInfo 'No collaboration is selected yet.'
        Write-Host '  1) Look again'
        Write-Host '  2) Exit'
        while ($true) {
            $nextMove = Read-JlValue 'Choose 1 or 2' '1'
            if ($nextMove -eq '1' -or $nextMove -eq '2') { break }
            Write-JlWarn "Invalid choice: '$nextMove' (must be 1 or 2). Try again."
        }
        if ($nextMove -eq '2') { exit 0 }
    }
}
Import-JlSession

# Re-fetch the function-def (mutable per slug/version); soft-fails offline.
try { Update-JlFunctionDef | Out-Null } catch { Write-JlWarn "Could not refresh the function definition; using the local copy." }

# Recomputed here, AFTER 00-init has fetched the function definition AND written the
# keysetup role to config.env. Both inputs are unknown before phase 1: the values set
# then are a guess rather than a reading. bash guessed the other way and its consumer
# skipped keysetup bundle 2 entirely, deadlocking against an owner waiting for it.
Resolve-JlBundleMarkers

# Consumer shortcut: skip everything and just decrypt. 06-end-of-cycle is
# self-contained (polls, and picks if there are several).
if ($onlyDecrypt) {
    Write-JlStep "$($script:JL_OUR_LABEL): decrypt latest released execution"
    Invoke-JlPhase '06-end-of-cycle.ps1'
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
    $runSize = Get-JlPermissionSizeText
    if ($runSize) { Write-Host "   Dataset size  : $runSize" }
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
            Write-JlErr "Recovery: restore your working folder from the machine that participated in"
            Write-JlErr "the keysetup, or create a NEW collaboration so a fresh keysetup generates"
            Write-JlErr "a new secret share on this machine."
            Stop-JlWithError "Cannot proceed."
        }
        # The joint key exists, but it may have been built for a function needing FEWER
        # evaluation keys than this permission's function needs. Skipping the bundles then
        # left the run to fail much later, at finalize, asking for a local file that was
        # never made and telling the operator to re-run a phase that would skip again.
        #
        # A collaboration is not limited by the scope of its first permission, so the rounds
        # for whatever it still lacks are run here. The phases are re-runnable now: they reuse
        # this machine's existing key share instead of generating over it, and every round
        # already submitted is idempotent on the platform.
        #
        # No extra wait is added: the consumer's 01 already waits for the owner's sum-round1,
        # and 03 waits for the peer's sum-round1-continue before combining.
        # @() around the call, not just inside the function: PowerShell unwraps an
        # empty array on RETURN, so a function that gives back @() hands the caller
        # $null - and $null.Count is a terminating error under Set-StrictMode 2.0.
        # That made the HEALTHY path (nothing missing) the one that crashed, while the
        # path with a missing key worked, which is why the first run never hit it.
        $missingEvalKeys = @(Get-JlMissingEvalKeys)
        if ($missingEvalKeys.Count -gt 0) {
            $missingList = $missingEvalKeys -join ', '
            Write-JlWarn "This collaboration is missing: $missingList"
            Write-JlWarn "Its joint key was built for a function that did not need it."
            Write-JlInfo "Running the extra key-setup rounds. Both sides have to do this."
            Write-Host ""
            Write-JlStep "$($script:JL_OUR_LABEL): key-setup rounds for $missingList"
            Invoke-JlPhase '01-keysetup-1.ps1'
            Write-JlStep "$($script:JL_OUR_LABEL): finalize the added key"
            Invoke-JlPhase '03-finalize-keysetup.ps1'
        } else {
            Write-JlInfo "Joint key is already complete (reused or finalized). Skipping bundles."
        }
    }
    '^(pending-keysetup|in-progress)$' {
        # Ordering is by KEYSETUP role, not by data role: the lead goes first because
        # its contributions depend on nothing, and the main chains on them.
        if (Test-JlAmKeysetupLead) {
            # LEAD: publish bundle 1, wait, publish bundle 2, wait.
            if (-not (Test-JlRoundPublished -Round $script:JlOwnBundle1Round)) {
                Write-JlStep "$($script:JL_OUR_LABEL): keysetup bundle 1"
                Invoke-JlPhase '01-keysetup-1.ps1'
            }
            Invoke-JlGate "$($script:JL_PEER_LABEL) to complete bundle 1 ($($script:JlPeerBundle1Type))" { Test-JlPeerUploaded $script:JlPeerBundle1Type }
            if ($script:JlNeedsRelin) {
                if (-not (Test-JlRoundPublished -Round $script:JlOwnBundle2Round)) {
                    Write-JlStep "$($script:JL_OUR_LABEL): keysetup bundle 2"
                    Invoke-JlPhase '02-keysetup-2.ps1'
                }
                Invoke-JlGate "$($script:JL_PEER_LABEL) to complete bundle 2 (relin-round2)" { Test-JlPeerUploaded 'relin-round2' }
            }
        } else {
            # MAIN: wait for bundle 1, publish, wait for bundle 2, publish.
            if (-not (Test-JlRoundPublished -Round $script:JlOwnBundle1Round)) {
                Invoke-JlGate "$($script:JL_PEER_LABEL) to publish bundle 1 (pk-share)" { Test-JlPeerUploaded $script:JlPeerBundle1Type }
                Write-JlStep "$($script:JL_OUR_LABEL): keysetup bundle 1"
                Invoke-JlPhase '01-keysetup-1.ps1'
            }
            if ($script:JlNeedsRelin) {
                if (-not (Test-JlRoundPublished -Round $script:JlOwnBundle2Round)) {
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

# If the state is STILL in-progress after our bundles, the peer owes a round. Falling
# through from here would run phase 4.5 with no joint public key, which it cannot refetch
# (the platform has none until finalize), so it would 404 on a loop that looks like a
# platform fault. Wait for the peer here instead, where the message says who we are
# waiting for.
if ($ksState -eq 'pending-keysetup' -or $ksState -eq 'in-progress') {
    Invoke-JlGate "$($script:JL_PEER_LABEL) to finish their remaining keysetup rounds" {
        $p2 = Get-JlPermission
        $s2 = "$($p2.keysetupState)"
        ($s2 -eq 'awaiting-finalization' -or $s2 -eq 'complete')
    }
    $perm = Get-JlPermission
    $ksState = "$($perm.keysetupState)"
    Write-JlInfo "Permission keysetup state (after peer): $ksState"
}

# Phase 3: finalize after a fresh keysetup. A permission that is already complete has
# nothing to finalize: it runs on the keys the collaboration holds, and a missing key was
# finalized above with its own rounds. Finalizing every complete permission dates from when
# keys were recorded per permission; it registered keys nobody needed and then waited on a
# partner who had nothing to do. Twin of driver.sh.
if ($ksState -eq 'awaiting-finalization') {
    Write-JlStep "$($script:JL_OUR_LABEL): finalize keysetup"
    Invoke-JlPhase '03-finalize-keysetup.ps1'
}

# Keysetup is finished, so the platform now knows what every public key should be. Check
# the copies on this machine before anything is encrypted or computed with them. Placed
# here because it is the first moment the comparison is possible and the last one before
# the keys are used. A stale key found any later costs a whole run, and can go unnoticed
# for far longer than that.
Write-JlStep "$($script:JL_OUR_LABEL): check local keys against the platform"
Invoke-JlVerifyLocalKeys

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

# Re-declare this side's inputs for a fresh cycle. Phase 4 runs BEFORE phase 5, so a
# "start a new test cycle?" answered down in phase 5 would otherwise trigger over
# whatever was already declared and never ask which datasets to use - the same words as
# menu option 2 but quietly different behaviour. Every phase-5 path that turns $newTest
# on calls this first, so both routes into a new cycle ask the same question.
function Invoke-JlNewCycleDatasets {
    if ($myInputNames.Count -eq 0) {
        Write-JlInfo "Function declares no inputs for $($script:JL_OUR_LABEL)'s role ($myFnRole); nothing to upload."
        return
    }
    Write-JlStep "$($script:JL_OUR_LABEL): encrypt and upload dataset (new test cycle)"
    $env:JULENNY_NEW_TEST = '1'
    try { Invoke-JlPhase '04-encrypt.ps1' } finally { Remove-Item Env:\JULENNY_NEW_TEST -ErrorAction SilentlyContinue }

    # Rotation indices are derived from the DECLARED plaintext data, so re-declaring can
    # invalidate the rotation keys and reopen rotation keysetup on the platform. This
    # rewind is called from phase 5, which is past 4.5, so without re-running it the side
    # that rewound never re-contributes and both sides deadlock on awaiting-contributions
    # while the peer waits for a contribution that is never coming. 4.5 is a no-op when
    # the function declares no rotation, and idempotent when nothing changed.
    Write-JlStep "$($script:JL_OUR_LABEL): rotation key augmentation (after re-declaring datasets)"
    Invoke-JlPhase '04.5-rotation-keysetup.ps1'
}

# A run drives ONE cycle and then exits, so the side that finishes first is gone by the
# time the peer starts the next one - which is how "start a new cycle" on one machine
# left the other showing the previous cycle's answer. In watch mode, offer to stay and
# run another. Re-invoke rather than loop: 00-init and the keysetup phases are idempotent
# and cheap, and re-entering from the top is exactly what the operator does by hand.
function Invoke-JlOfferAnotherCycle {
    if (-not $watchMode) { return }
    Write-Host ""
    $again = Read-JlValue "Wait for another test cycle on this permission? (y/N)" 'N'
    if ($again -notmatch '^[Yy]') { return }
    Write-Host ""
    Write-JlInfo "Starting another cycle on the same permission."
    $env:JL_NEXT_CYCLE = '1'
    # $PSBoundParameters inside a function is the FUNCTION's, so the script's own
    # arguments are captured at the top as $script:JlScriptArgs.
    & $PSCommandPath @script:JlScriptArgs
    exit $LASTEXITCODE
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
            Invoke-JlNewCycleDatasets
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
        Invoke-JlNewCycleDatasets
        Write-JlInfo "Waiting for $($script:JL_PEER_LABEL) to trigger a new execution..."
        Invoke-JlGate "a new execution to be released by $($script:JL_PEER_LABEL)" { Set-JlNextUndecryptedExecution }
    }
    Write-JlStep "$($script:JL_OUR_LABEL): end-of-cycle (resultVisibility: $($script:JULENNY_RESULT_VISIBILITY))"
    Invoke-JlPhase '06-end-of-cycle.ps1'
    Write-Host ""
    Write-JlSuccess "All $($script:JL_OUR_LABEL) phases done."
    Invoke-JlOfferAnotherCycle
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
            Invoke-JlNewCycleDatasets
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
    Invoke-JlPhase '06-end-of-cycle.ps1'
    Write-Host ""
    if (Test-JlAmViewer) {
        Write-JlSuccess "All $($script:JL_OUR_LABEL) phases done. Answer is above."
    } else {
        Write-JlSuccess "All $($script:JL_OUR_LABEL) phases done. Released; only $($script:JL_PEER_LABEL) can read the result."
    }
Invoke-JlOfferAnotherCycle
}

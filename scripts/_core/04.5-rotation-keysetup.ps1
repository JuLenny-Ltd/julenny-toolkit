# Rotation key augmentation (phase 4.5). BOTH sides run it.
#
# Only runs when the function-def declares "rotation" in requiredEvalKeys; otherwise it
# is a no-op, which is why the driver can call it unconditionally.
#
# Rotation is the one evaluation key that cannot be built before the function and its
# data are known: the index set is DERIVED from the bound plaintext datasets. So this
# phase sits after 04-encrypt, and starts by waiting for the platform to derive it.
#
# The two halves, by KEYSETUP role:
#
#   LEAD  contributes first, with nothing to chain on, and publishes rotation-round1.
#         Then it waits for the main's continuation.
#   MAIN  waits for the lead's rotation-round1, chains on it, and publishes
#         rotation-round1-continue.
#
# Both then run the same deterministic combine and upload rotation-combine; the
# platform checks the two agree.
#
# It also re-derives the rotation indices locally and compares them with the platform's
# set. Rotation keys generated against the wrong index set would produce a wrong answer
# rather than an error, so this refuses to continue on a mismatch.
#
# PowerShell twin of 04.5-rotation-keysetup.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
# lib.ps1 resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
. "$here\lib.ps1"
Import-JlSession

$functionDef = Join-Path $script:JL_WORKDIR 'function-def.json'

Write-JlStep "$($script:JL_OUR_LABEL): rotation key augmentation (phase 4.5, keysetup role: $($script:JULENNY_ROLE))"

# ---- Guard: only run if the function-def actually requires rotation ----
if (-not (Test-JlFunctionRequiresRotationKeys $functionDef)) {
    Write-JlInfo "Function does not declare rotation in requiredEvalKeys. Skipping 4.5."
    return
}

# ---- Guard: skip if already complete ----
if ((Get-JlRotationStatus) -eq 'complete') {
    Write-JlInfo "Rotation keysetup is already complete for this permission. Skipping."
    return
}

# ---- Joint public key (needed for both contribute and combine) ----
$jointPk = Join-Path $script:JL_KEYS_DIR 'joint_public_key.bin'
if (-not (Test-Path -LiteralPath $jointPk)) {
    Write-JlInfo "Joint public key missing locally; refetching..."
    # From config.env, not from a scan of the permissions list. The lead half used to
    # scan, which meant it needed the permission to still be listed and to be listed
    # under the view its data role uses - two ways to fail for a value already on disk.
    $jointKeyId = ''
    if (Get-Variable -Name JULENNY_JOINT_KEY_ID -Scope Script -ErrorAction SilentlyContinue) {
        $jointKeyId = $script:JULENNY_JOINT_KEY_ID
    }
    if ([string]::IsNullOrWhiteSpace($jointKeyId)) {
        Stop-JlWithError "config.env has no JULENNY_JOINT_KEY_ID; base keysetup must finish before 4.5."
    }
    Save-JlApiFile -Path "/api/fhe-joint-keys/$jointKeyId/public-key" -OutFile $jointPk
    Write-JlSuccess "Joint pk fetched -> $jointPk"
}

# Named for the KEYSETUP role; Import-JlSession picked the filename from JULENNY_ROLE.
$mySecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE
if (-not (Test-Path -LiteralPath $mySecret)) {
    Stop-JlWithError "Missing FHE secret share at $mySecret (produced by base keysetup)."
}

# ---- Step 1: wait for the platform to derive indices ----
# The platform derives them once the plaintext datasets they come from are all bound
# via preferred-datasets, which happens in 04-encrypt. Whichever side owns those inputs,
# the wait here is the same: poll until the index set appears.
Wait-JlPendingRotationIndices "the platform to derive rotation indices from the bound plaintext data"

$indicesCsv = Get-JlPendingRotationIndicesCsv
if ([string]::IsNullOrWhiteSpace($indicesCsv)) {
    # Empty derived set: status has already transitioned to complete, because no
    # rotation keys are actually needed for this execution.
    Write-JlInfo "Empty derived index set. No rotation keys needed; phase 4.5 done."
    return
}
$indexCount = @($indicesCsv -split ',').Count
Write-JlSuccess "Platform-derived index set: $indexCount indices."

# ---- Step 1b: cross-check the platform's index set against a local derivation ----
# Skipped when the sidecar has no rule_pairs path: the operator reused an existing
# dataset rather than uploading a fresh one, or the other side owns that input. The
# check is defensive, not load-bearing, so skipping it is not an error.
#
# It says so at info level, not warn. Only the side that uploaded the file can run the
# check at all, so on the other side a warning would fire on every normal run and mean
# nothing. This was a warning while the two sides had separate scripts.
$ptSidecar = Join-Path $script:JL_WORKDIR 'my_plaintext_paths.json'
if (Test-Path -LiteralPath $ptSidecar) {
    $sidecar = Get-Content -LiteralPath $ptSidecar -Raw | ConvertFrom-Json
    $ptPairs = ''
    if ((Test-JlHasProperty $sidecar 'rule_pairs')) { $ptPairs = $sidecar.rule_pairs.path }

    if ($ptPairs -and (Test-Path -LiteralPath $ptPairs)) {
        Write-JlInfo "Re-deriving rotation indices locally to cross-check the platform..."
        $localJson = Invoke-JlCli @(
            'crypto', 'derive-rotation-indices',
            '--rule-pairs',   $ptPairs,
            '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--json'
        ) -PassThru
        $localCsv = (@(($localJson | ConvertFrom-Json).indices) -join ',')

        if ($localCsv -eq $indicesCsv) {
            Write-JlSuccess "Local-derived indices MATCH platform-derived set ($indexCount indices)."
        } else {
            Write-JlErr "Index set MISMATCH between toolkit and platform!"
            Write-JlErr "  Platform: $indicesCsv"
            Write-JlErr "  Local:    $localCsv"
            Write-JlErr "Possible causes: FNV1a constants drifted, normalization rule drift,"
            Write-JlErr "                 rule_pairs file modified after upload, or platform"
            Write-JlErr "                 used a different dataset than expected."
            Stop-JlWithError "Refusing to generate rotation keys against a mismatched index set."
        }
    } else {
        Write-JlInfo "No rule_pairs path in the sidecar; skipping the local-derivation cross-check."
        Write-JlInfo "  (It is written by 04-encrypt when this machine uploads a fresh plaintext dataset.)"
    }
} else {
    Write-JlInfo "No plaintext sidecar at $ptSidecar; skipping the local-derivation cross-check."
}

# ---- Steps 2 and 3: contribute in the right order for this role ----
# Idempotency, both halves: reuse an existing share rather than regenerating.
# rotation-contribute uses fresh randomness each call, so a regenerated share would not
# match the one the platform already accepted (it keeps the first-accepted payload), and
# the combine would then produce the wrong result on this machine only.
#
# Set JULENNY_FORCE_ROTATION_REGEN=1 to override: do that if the derived index set has
# changed, or this machine's FHE secret share was rotated since the file was written.
$forceRegen = ($env:JULENNY_FORCE_ROTATION_REGEN -eq '1')

if (Test-JlAmKeysetupLead) {
    $myRotShare = Join-Path $script:JL_KEYS_DIR 'rotation-round1.bin'
    if ((Test-Path -LiteralPath $myRotShare) -and (-not $forceRegen)) {
        Write-JlInfo "Reusing existing rotation-round1 share at $myRotShare ($((Get-Item -LiteralPath $myRotShare).Length) bytes)."
    } else {
        Write-JlInfo "Computing $($script:JL_OUR_LABEL)'s rotation-round1 contribution (lead)..."
        Invoke-JlCli @(
            'crypto', 'rotation-contribute',
            '--role', 'lead',
            '--secret-key',   $mySecret,
            '--indices',      $indicesCsv,
            '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--output',       $myRotShare
        )
        Write-JlSuccess "Rotation-round1 share written -> $myRotShare ($((Get-Item -LiteralPath $myRotShare).Length) bytes)"
    }

    $roundR1 = Get-JlRotationRoundOffset 'round1'
    Publish-JlEnvelope -BinPath $myRotShare -Round $roundR1 -MessageType 'rotation-round1'

    # Now wait for the main's continuation, which the combine needs.
    Wait-JlPeerShare 'rotation-round1-continue' -MaxWaitSeconds 1800
    $peerShare = Join-Path $script:JL_PEER_DIR 'rotation-round1-continue.bin'
    Save-JlPeerShare -MessageType 'rotation-round1-continue' -OutPath $peerShare

    $leadShare = $myRotShare
    $mainShare = $peerShare
} else {
    # The main cannot start until the lead has published: its contribution chains on it.
    Wait-JlPeerShare 'rotation-round1' -MaxWaitSeconds 1800
    $peerShare = Join-Path $script:JL_PEER_DIR 'rotation-round1.bin'
    Save-JlPeerShare -MessageType 'rotation-round1' -OutPath $peerShare

    $myRotShare = Join-Path $script:JL_KEYS_DIR 'rotation-round1-continue.bin'
    if ((Test-Path -LiteralPath $myRotShare) -and (-not $forceRegen)) {
        Write-JlInfo "Reusing existing continue share at $myRotShare ($((Get-Item -LiteralPath $myRotShare).Length) bytes)."
    } else {
        Write-JlInfo "Computing $($script:JL_OUR_LABEL)'s rotation-round1-continue contribution (main)..."
        Invoke-JlCli @(
            'crypto', 'rotation-contribute',
            '--role', 'main',
            '--secret-key',   $mySecret,
            '--peer-share',   $peerShare,
            '--joint-pk',     $jointPk,
            '--indices',      $indicesCsv,
            '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--output',       $myRotShare
        )
        Write-JlSuccess "Continue share written -> $myRotShare ($((Get-Item -LiteralPath $myRotShare).Length) bytes)"
    }

    $roundContinue = Get-JlRotationRoundOffset 'round1-continue'
    Publish-JlEnvelope -BinPath $myRotShare -Round $roundContinue -MessageType 'rotation-round1-continue'

    $leadShare = $peerShare
    $mainShare = $myRotShare
}

# If the peer finished the rotation while we got here, there is nothing to do.
if ((Get-JlRotationStatus) -eq 'complete') {
    Write-JlSuccess "Rotation keysetup already complete; skipping combine."
    return
}

# ---- Step 4: combine and upload ----
# share-a = LEAD's share, share-b = MAIN's continue, on both machines. Both sides must
# produce byte-identical output; the platform verifies the SHA256.
$rotCombined = Join-Path $script:JL_KEYS_DIR 'rotation-combined.bin'
Write-JlInfo "Computing rotation-combine output..."
Invoke-JlCli @(
    'crypto', 'rotation-combine',
    '--share-a',      $leadShare,
    '--share-b',      $mainShare,
    '--joint-pk',     $jointPk,
    '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
    '--output',       $rotCombined
)
Write-JlSuccess "Rotation key map combined -> $rotCombined ($((Get-Item -LiteralPath $rotCombined).Length) bytes)"

$roundCombine = Get-JlRotationRoundOffset 'combine'
Publish-JlEnvelope -BinPath $rotCombined -Round $roundCombine -MessageType 'rotation-combine'

# ---- Step 5: wait for the platform to verify both sides match ----
Wait-JlRotationStatus 'complete' -MaxWaitSeconds 600

Write-Host ""
Write-JlSuccess "Phase 4.5 done. Rotation keys are installed; execution can proceed."

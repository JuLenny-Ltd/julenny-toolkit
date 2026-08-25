# Data-consumer: rotation key augmentation (phase 4.5).
#
# Only runs when the function-def declares "rotation" in requiredEvalKeys;
# otherwise it is a no-op. This side waits for the owner's round-1 share, then
# contributes its continue share, then both sides combine.
#
# It also re-derives the rotation indices locally and compares them with the
# platform's set. Rotation keys generated against the wrong index set would
# produce a wrong answer rather than an error, so this refuses to continue on a
# mismatch.
#
# PowerShell twin of 04.5-rotation-keysetup.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\..\sides\data-consumer.ps1"
. "$here\..\lib.ps1"
Import-JlSession

$functionDef = Join-Path $script:JL_WORKDIR 'function-def.json'

Write-JlStep "$($script:JL_OUR_LABEL): rotation key augmentation (phase 4.5)"

# ---- Guard: only run if the function actually needs rotation keys ----
if (-not (Test-JlFunctionRequiresRotationKeys $functionDef)) {
    Write-JlInfo "Function does not declare rotation in requiredEvalKeys. Skipping 4.5."
    return
}

# ---- Guard: skip if already complete ----
if ((Get-JlRotationStatus) -eq 'complete') {
    Write-JlInfo "Rotation keysetup is already complete for this permission. Skipping."
    return
}

# ---- Joint public key ----
$jointPk = Join-Path $script:JL_KEYS_DIR 'joint_public_key.bin'
if (-not (Test-Path -LiteralPath $jointPk)) {
    Write-JlInfo "Joint public key missing locally; refetching..."
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

# Secret-share filename is asymmetric by design; it comes from the side profile.
$mySecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE
if (-not (Test-Path -LiteralPath $mySecret)) {
    Stop-JlWithError "Missing FHE secret share at $mySecret (produced by base keysetup)."
}

# ---- Step 1: wait for the platform to derive indices ----
Wait-JlPendingRotationIndices "platform to derive rotation indices from plaintext data"

$indicesCsv = Get-JlPendingRotationIndicesCsv
if ([string]::IsNullOrWhiteSpace($indicesCsv)) {
    Write-JlInfo "Empty derived index set. No rotation keys needed; phase 4.5 done."
    return
}
$indexCount = @($indicesCsv -split ',').Count
Write-JlSuccess "Platform-derived index set: $indexCount indices."

# ---- Step 1b: cross-check the platform's index set against a local derivation ----
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
        Write-JlWarn "No rule_pairs path in sidecar; skipping local-derivation cross-check."
        Write-JlWarn "  (The sidecar is written by 04-encrypt when fresh plaintext datasets are uploaded.)"
    }
} else {
    Write-JlWarn "No plaintext sidecar at $ptSidecar; skipping local-derivation cross-check."
}

# ---- Step 2: wait for the owner's round-1 share ----
Wait-JlPeerShare 'rotation-round1' -MaxWaitSeconds 1800

$rotOwnerShare = Join-Path $script:JL_PEER_DIR 'rotation-round1.bin'
Save-JlPeerShare -MessageType 'rotation-round1' -OutPath $rotOwnerShare

# ---- Step 3: contribute the continue share, upload it ----
# Reuse an existing share if present: rotation-contribute uses fresh randomness
# each call, so regenerating produces a DIFFERENT share that will not match what
# the platform already accepted. Set JULENNY_FORCE_ROTATION_REGEN=1 to override.
$myRotShare = Join-Path $script:JL_KEYS_DIR 'rotation-round1-continue.bin'
$forceRegen = ($env:JULENNY_FORCE_ROTATION_REGEN -eq '1')

if ((Test-Path -LiteralPath $myRotShare) -and (-not $forceRegen)) {
    Write-JlInfo "Reusing existing continue share at $myRotShare ($((Get-Item -LiteralPath $myRotShare).Length) bytes)."
} else {
    Write-JlInfo "Computing $($script:JL_OUR_LABEL)'s rotation-round1-continue contribution..."
    Invoke-JlCli @(
        'crypto', 'rotation-contribute',
        '--role', 'main',
        '--secret-key',   $mySecret,
        '--peer-share',   $rotOwnerShare,
        '--joint-pk',     $jointPk,
        '--indices',      $indicesCsv,
        '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
        '--output',       $myRotShare
    )
    Write-JlSuccess "Continue share written -> $myRotShare ($((Get-Item -LiteralPath $myRotShare).Length) bytes)"
}

$roundContinue = Get-JlRotationRoundOffset 'round1-continue'
Publish-JlEnvelope -BinPath $myRotShare -Round $roundContinue -MessageType 'rotation-round1-continue'

# If the peer finished the rotation while we got here, there is nothing to do.
if ((Get-JlRotationStatus) -eq 'complete') {
    Write-JlSuccess "Rotation keysetup already complete; skipping combine."
    return
}

# ---- Step 4: combine and upload ----
# share-a = LEAD's share, share-b = MAIN's continue, on both machines. Both
# sides must produce byte-identical output; the platform verifies the SHA256.
$rotCombined = Join-Path $script:JL_KEYS_DIR 'rotation-combined.bin'
Write-JlInfo "Computing rotation-combine output..."
Invoke-JlCli @(
    'crypto', 'rotation-combine',
    '--share-a',      $rotOwnerShare,
    '--share-b',      $myRotShare,
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

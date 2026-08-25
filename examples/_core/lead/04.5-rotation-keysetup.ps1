# Data-owner: rotation key augmentation (phase 4.5).
#
# Only runs when the function-def declares "rotation" in requiredEvalKeys;
# otherwise it is a no-op. The owner contributes first, then waits for the
# consumer's continue share, then both sides combine.
#
# PowerShell twin of 04.5-rotation-keysetup.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\..\sides\data-owner.ps1"
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
    $perms = Invoke-JlApi GET "/api/fhe-permissions?status=active&view=permissioned"
    $jointKeyId = ''
    if ($perms -and ((Test-JlHasProperty $perms 'permissions'))) {
        $match = @($perms.permissions | Where-Object { $_.id -eq $script:JULENNY_PERMISSION_ID })
        if ($match.Count -gt 0) { $jointKeyId = $match[0].jointKeyId }
    }
    if ([string]::IsNullOrWhiteSpace($jointKeyId)) {
        Stop-JlWithError "Permission has no jointKeyId; base keysetup must finish before 4.5."
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
# The platform derives these once the consumer has bound its plaintext datasets,
# so from this side the wait covers "their 04-encrypt has finished".
Wait-JlPendingRotationIndices "$($script:JL_PEER_LABEL) to bind plaintext datasets so the platform can derive rotation indices"

$indicesCsv = Get-JlPendingRotationIndicesCsv
if ([string]::IsNullOrWhiteSpace($indicesCsv)) {
    Write-JlInfo "Empty derived index set. No rotation keys needed; phase 4.5 done."
    return
}
$indexCount = @($indicesCsv -split ',').Count
Write-JlSuccess "Platform-derived index set: $indexCount indices."

# ---- Steps 2-3: contribute as lead, upload rotation-round1 ----
# Reuse an existing share if present: rotation-contribute uses fresh randomness
# each call, so regenerating produces a DIFFERENT share that will not match what
# the platform already accepted (it keeps the first-accepted payload). Local and
# stored bytes must stay identical or the combine is wrong.
#
# Set JULENNY_FORCE_ROTATION_REGEN=1 to override, e.g. if the derived index set
# changed or the FHE secret share was rotated since this file was written.
$myRotShare = Join-Path $script:JL_KEYS_DIR 'rotation-round1.bin'
$forceRegen = ($env:JULENNY_FORCE_ROTATION_REGEN -eq '1')

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

# ---- Step 4: wait for the peer's continue share ----
Wait-JlPeerShare 'rotation-round1-continue' -MaxWaitSeconds 1800

$peerContinue = Join-Path $script:JL_PEER_DIR 'rotation-round1-continue.bin'
Save-JlPeerShare -MessageType 'rotation-round1-continue' -OutPath $peerContinue

# If the peer finished the rotation while we got here, there is nothing to do.
if ((Get-JlRotationStatus) -eq 'complete') {
    Write-JlSuccess "Rotation keysetup already complete; skipping combine."
    return
}

# ---- Step 5: combine and upload ----
# share-a = LEAD's share, share-b = MAIN's continue, on both machines. Both
# sides must produce byte-identical output; the platform verifies the SHA256.
$rotCombined = Join-Path $script:JL_KEYS_DIR 'rotation-combined.bin'
Write-JlInfo "Computing rotation-combine output..."
Invoke-JlCli @(
    'crypto', 'rotation-combine',
    '--share-a',      $myRotShare,
    '--share-b',      $peerContinue,
    '--joint-pk',     $jointPk,
    '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
    '--output',       $rotCombined
)
Write-JlSuccess "Rotation key map combined -> $rotCombined ($((Get-Item -LiteralPath $rotCombined).Length) bytes)"

$roundCombine = Get-JlRotationRoundOffset 'combine'
Publish-JlEnvelope -BinPath $rotCombined -Round $roundCombine -MessageType 'rotation-combine'

# ---- Step 6: wait for the platform to verify both sides match ----
Wait-JlRotationStatus 'complete' -MaxWaitSeconds 600

Write-Host ""
Write-JlSuccess "Phase 4.5 done. Rotation keys are installed; execution can proceed."

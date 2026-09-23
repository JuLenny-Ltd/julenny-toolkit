# Keysetup bundle 1. BOTH sides run it, and the two halves are genuinely different
# work, not the same work with different labels:
#
#   LEAD  generates a fresh key share and publishes the three contributions that
#         depend on nothing else: pk-share, relin-round1, sum-round1.
#   MAIN  waits for those three, chains on each of them, and publishes what the
#         chaining produces: the joint public key as its pk-share, then
#         relin-round1-continue and sum-round1-continue.
#
# Which half this machine runs is the KEYSETUP role, read from the platform by 00-init,
# NOT the data role: a permission created in the other direction inside the same
# collaboration makes the data owner the keysetup main. Running the wrong half is worse
# than an error - the shares would not match the joint key, and nothing would say so
# until a decryption came out wrong.
#
# Relin and sum are each skipped when the function does not declare them. An
# additive-only function needs neither, and publishing a round the platform has already
# moved past leaves both sides waiting on an exchange that will not happen.
#
# PowerShell twin of 01-keysetup-1.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
# lib.ps1 resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
. "$here\lib.ps1"
Import-JlSession

# This machine's FHE secret share. Named for the KEYSETUP role: Import-JlSession picked
# the filename from JULENNY_ROLE, so a reversed permission writes the other side's name
# and the name always describes the material the file holds.
$mySecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE

$needsRelin = Test-JlFunctionRequiresRelinKeys
$needsSum   = Test-JlFunctionRequiresSumKeys

if (Test-JlAmKeysetupLead) {
    Write-JlStep "$($script:JL_OUR_LABEL) keysetup bundle 1 (lead): pk-share + relin-round1 (+ sum, only if the function needs one)"

    $myPublic = Join-Path $script:JL_KEYS_DIR 'fhe_public_key.bin'
    $relinR1  = Join-Path $script:JL_KEYS_DIR 'lead-relin-r1.bin'
    $sumR1    = Join-Path $script:JL_KEYS_DIR 'lead-sum-r1.bin'

    # -------- 1. pk-share (round 1) --------
    # REUSE an existing secret share rather than generating over it.
    #
    # This phase used to generate unconditionally, which made it destructive to re-run: a
    # new share does not match the joint key already built from the old one, so this
    # machine could no longer partial-decrypt anything. That is why the only advice on a
    # half-built collaboration was to start a new one.
    #
    # It has to be re-runnable, because a collaboration whose joint key was built for a
    # function needing fewer keys still owes the rounds for the keys it lacks, and those
    # rounds are built FROM this share. A fresh ceremony has no share to find, so it
    # still generates one.
    if ((Test-Path -LiteralPath $mySecret) -and (Test-Path -LiteralPath $myPublic)) {
        Write-JlInfo "Reusing this machine's existing FHE key share; not generating a new one."
        Write-JlInfo "  $mySecret"
    } else {
        Write-JlInfo "Generating FHE keypair ($($script:JL_OUR_LABEL)'s contribution)..."
        Invoke-JlCli @(
            'crypto', 'keysetup-contribute',
            '--context-spec',  $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--role',          'lead',
            '--output-secret', $mySecret,
            '--output-public', $myPublic
        )
        Write-JlSuccess "FHE secret: $mySecret  (stays here, never upload)"
        Write-JlSuccess "FHE public contribution: $myPublic"
    }

    Publish-JlEnvelope -BinPath $myPublic -Round 1 -MessageType 'pk-share'

    # -------- 2. relin-round1 (round 2), only if the function needs a relin key --------
    if ($needsRelin) {
        Write-JlInfo "Generating relinearization key round-1 contribution..."
        Invoke-JlCli @(
            'crypto', 'relin-contribute',
            '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--round', '1', '--role', 'lead',
            '--secret-key', $mySecret,
            '--output',     $relinR1
        )
        Write-JlSuccess "Relin round-1: $relinR1"

        Publish-JlEnvelope -BinPath $relinR1 -Round 2 -MessageType 'relin-round1'
    } else {
        Write-JlInfo "Function does not require a relinearization key; skipping relin-round1."
    }

    # -------- 3. sum-round1 (round 5), only if the function needs a sum key --------
    if ($needsSum) {
        Write-JlInfo "Generating sum key round-1 contribution..."
        Invoke-JlCli @(
            'crypto', 'sum-contribute',
            '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--role', 'lead',
            '--secret-key', $mySecret,
            '--output',     $sumR1
        )
        Write-JlSuccess "Sum round-1: $sumR1"

        Publish-JlEnvelope -BinPath $sumR1 -Round 5 -MessageType 'sum-round1'
    } else {
        Write-JlInfo "Function does not require a sum key (requiredEvalKeys); skipping sum-round1."
    }

    $bundleMsgs = @('pk-share')
    if ($needsRelin) { $bundleMsgs += 'relin-round1' }
    if ($needsSum)   { $bundleMsgs += 'sum-round1' }
    $peerOwes = 'bundle 1'
} else {
    Write-JlStep "$($script:JL_OUR_LABEL) keysetup bundle 1 (main): joint-pk + relin-round1-continue (+ sum, only if the function needs one)"

    $jointPk = Join-Path $script:JL_KEYS_DIR 'joint_public_key.bin'
    $relinR1 = Join-Path $script:JL_KEYS_DIR 'main-relin-r1.bin'
    $sumR1   = Join-Path $script:JL_KEYS_DIR 'main-sum-r1.bin'

    $peerPk      = Join-Path $script:JL_PEER_DIR 'lead-pk.bin'
    $peerRelinR1 = Join-Path $script:JL_PEER_DIR 'lead-relin-r1.bin'
    $peerSumR1   = Join-Path $script:JL_PEER_DIR 'lead-sum-r1.bin'

    # -------- 1. Wait for and download the lead's three shares --------
    Write-JlInfo "Fetching $($script:JL_PEER_LABEL)'s bundle 1 contributions..."
    Wait-JlPeerShare 'pk-share'
    Save-JlPeerShare -MessageType 'pk-share' -OutPath $peerPk

    # Additive-only functions declare requiredEvalKeys: [] and never send relin-round1.
    if ($needsRelin) {
        Wait-JlPeerShare 'relin-round1'
        Save-JlPeerShare -MessageType 'relin-round1' -OutPath $peerRelinR1
    }

    if ($needsSum) {
        Wait-JlPeerShare 'sum-round1'
        Save-JlPeerShare -MessageType 'sum-round1' -OutPath $peerSumR1
    }

    # -------- 2. Derive the joint pk (chains on the lead's pk-share) --------
    # REUSE an existing share rather than deriving over it. Same reason as the lead half:
    # a new share does not match the joint key already built from the old one, so
    # re-running this phase used to leave the machine unable to partial-decrypt. It has
    # to be re-runnable, because the rounds for a key the collaboration still lacks are
    # built FROM this share.
    if ((Test-Path -LiteralPath $mySecret) -and (Test-Path -LiteralPath $jointPk)) {
        Write-JlInfo "Reusing this machine's existing FHE key share; not deriving a new one."
        Write-JlInfo "  $mySecret"
    } else {
        Write-JlInfo "Deriving joint public key..."
        Invoke-JlCli @(
            'crypto', 'keysetup-contribute',
            '--context-spec',  $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--role',          'main',
            '--peer-share',    $peerPk,
            '--output-secret', $mySecret,
            '--output-public', $jointPk
        )
        Write-JlSuccess "$($script:JL_OUR_LABEL)'s share secret: $mySecret  (stays here, never upload)"
        Write-JlSuccess "Joint public key: $jointPk"
    }

    Publish-JlEnvelope -BinPath $jointPk -Round 1 -MessageType 'pk-share'

    # -------- 3. relin-round1-continue (round 3), only if a relin key is needed --------
    if ($needsRelin) {
        Write-JlInfo "Generating relin round-1 continue..."
        Invoke-JlCli @(
            'crypto', 'relin-contribute',
            '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--round', '1', '--role', 'main',
            '--secret-key', $mySecret,
            '--peer-share', $peerRelinR1,
            '--output',     $relinR1
        )
        Write-JlSuccess "$($script:JL_OUR_LABEL) relin round-1: $relinR1"

        Publish-JlEnvelope -BinPath $relinR1 -Round 3 -MessageType 'relin-round1-continue'
    } else {
        Write-JlInfo "Function does not require a relinearization key; skipping relin-round1-continue."
    }

    # -------- 4. sum-round1-continue (round 6), only if the function needs a sum key --------
    if ($needsSum) {
        Write-JlInfo "Generating sum round-1 continue..."
        Invoke-JlCli @(
            'crypto', 'sum-contribute',
            '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--role', 'main',
            '--secret-key', $mySecret,
            '--peer-share', $peerSumR1,
            '--joint-pk',   $jointPk,
            '--output',     $sumR1
        )
        Write-JlSuccess "$($script:JL_OUR_LABEL) sum round-1: $sumR1"

        Publish-JlEnvelope -BinPath $sumR1 -Round 6 -MessageType 'sum-round1-continue'
    } else {
        Write-JlInfo "Function does not require a sum key (requiredEvalKeys); skipping sum-round1-continue."
    }

    $bundleMsgs = @('pk-share')
    if ($needsRelin) { $bundleMsgs += 'relin-round1-continue' }
    if ($needsSum)   { $bundleMsgs += 'sum-round1-continue' }
    # Bundle 2 is the relin exchange, so there is no bundle 2 to wait for when the
    # function declares no relin key. The main side used to say "bundle 2" either way,
    # which pointed the operator at a phase that exits immediately.
    if ($needsRelin) { $peerOwes = 'bundle 2' } else { $peerOwes = '' }
}

Write-Host ""
Write-JlSuccess "Bundle 1 uploaded ($($bundleMsgs -join ', '))."

if ($needsRelin) { $nextStep = '02-keysetup-2.ps1' } else { $nextStep = '03-finalize-keysetup.ps1' }

if ($peerOwes) {
    Write-JlWaitMessage @"
Tell $($script:JL_PEER_LABEL) to run their side of keysetup $peerOwes on their own machine
(their run.sh / run.ps1 handles it, or the equivalent MCP verbs).

When $($script:JL_PEER_LABEL)'s $peerOwes is uploaded, come back here and run:
    $here\$nextStep
"@
} else {
    Write-Host ""
    Write-JlInfo "Next step: finalize the joint keys. Both machines run it:"
    Write-Host "  $here\$nextStep"
}

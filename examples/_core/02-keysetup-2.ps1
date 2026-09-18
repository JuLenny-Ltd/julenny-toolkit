# Keysetup bundle 2: relin-round2. BOTH sides run it.
#
# Each side combines the two round-1 relin shares - deterministically, so the two
# combines must agree byte for byte - and then contributes its own round-2 share.
#
# What differs between the sides is only where the pieces come from:
#
#   LEAD  produced lead-relin-r1 itself in bundle 1 and collects the peer's
#         relin-round1-continue here, along with the joint public key, which arrives
#         as the peer's pk-share.
#   MAIN  produced main-relin-r1 and derived the joint public key in bundle 1, and
#         already holds the lead's relin-round1 from the same phase.
#
# Which half this machine runs is the KEYSETUP role, read from the platform by 00-init,
# NOT the data role: a permission created in the other direction inside the same
# collaboration makes the data owner the keysetup main.
#
# PowerShell twin of 02-keysetup-2.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
# lib.ps1 resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
. "$here\lib.ps1"
Import-JlSession

Write-JlStep "$($script:JL_OUR_LABEL) keysetup bundle 2: relin-round2 (keysetup role: $($script:JULENNY_ROLE))"

# Bundle 2 is the second relin round and nothing else. An additive-only function
# (requiredEvalKeys: []) has no relin key, so there is nothing to do and the file
# checks below would stop on intermediates that were never created.
if (-not (Test-JlFunctionRequiresRelinKeys)) {
    Write-JlInfo "Function does not require a relinearization key; bundle 2 has nothing to do."
    Write-JlInfo "Go straight to 03-finalize-keysetup."
    return
}

$mySecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE

# The combine takes the LEAD's share as -a and the MAIN's as -b, on both machines.
# That ordering is what makes the two outputs identical; it is not "mine then theirs".
if (Test-JlAmKeysetupLead) {
    $myR1        = Join-Path $script:JL_KEYS_DIR 'lead-relin-r1.bin'
    $peerR1      = Join-Path $script:JL_PEER_DIR 'main-relin-r1.bin'
    $peerR1Msg   = 'relin-round1-continue'
    $relinR1Lead = $myR1
    $relinR1Main = $peerR1
    $myR2        = Join-Path $script:JL_KEYS_DIR 'lead-relin-r2.bin'
    # The lead never derives the joint pk; the main's pk-share IS the joint pk, so it
    # arrives here, in this phase.
    $jointPk         = Join-Path $script:JL_PEER_DIR 'joint-pk.bin'
    $jointPkFromPeer = $true
} else {
    $myR1        = Join-Path $script:JL_KEYS_DIR 'main-relin-r1.bin'
    $peerR1      = Join-Path $script:JL_PEER_DIR 'lead-relin-r1.bin'
    $peerR1Msg   = 'relin-round1'
    $relinR1Lead = $peerR1
    $relinR1Main = $myR1
    $myR2        = Join-Path $script:JL_KEYS_DIR 'main-relin-r2.bin'
    # The main derived the joint pk in bundle 1 and keeps it under its own keys.
    $jointPk         = Join-Path $script:JL_KEYS_DIR 'joint_public_key.bin'
    $jointPkFromPeer = $false
}

$combinedR1 = Join-Path $script:JL_KEYS_DIR 'combined-relin-r1.bin'

if (-not (Test-Path -LiteralPath $myR1))     { Stop-JlWithError "Missing $myR1. Did 01-keysetup-1.ps1 run successfully?" }
if (-not (Test-Path -LiteralPath $mySecret)) { Stop-JlWithError "Missing $mySecret. Did 01-keysetup-1.ps1 run successfully?" }

# -------- 1. Collect what the peer owes this phase --------
# Waiting before downloading, rather than downloading blind, covers the lead (whose
# peer has genuinely not published yet when this phase starts) and costs the main
# nothing: it already downloaded this share in bundle 1, so the file is there and
# neither the wait nor the download runs.
if (-not (Test-Path -LiteralPath $peerR1)) {
    Write-JlInfo "Waiting for $($script:JL_PEER_LABEL)'s $peerR1Msg contribution..."
    Wait-JlPeerShare $peerR1Msg
    Save-JlPeerShare -MessageType $peerR1Msg -OutPath $peerR1
}

if (-not (Test-Path -LiteralPath $jointPk)) {
    if ($jointPkFromPeer) {
        Write-JlInfo "Fetching the joint public key from $($script:JL_PEER_LABEL)'s pk-share..."
        Wait-JlPeerShare 'pk-share'
        Save-JlPeerShare -MessageType 'pk-share' -OutPath $jointPk
    } else {
        Stop-JlWithError "Missing $jointPk. Did 01-keysetup-1.ps1 run successfully?"
    }
}

# -------- 2. Deterministic combine (must match the peer's, byte for byte) --------
Write-JlInfo "Combining round-1 relin shares (deterministic; must match $($script:JL_PEER_LABEL)'s)..."
Invoke-JlCli @(
    'crypto', 'relin-combine',
    '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
    '--round', '1',
    '--share-a', $relinR1Lead,
    '--share-b', $relinR1Main,
    '--joint-pk', $jointPk,
    '--output',   $combinedR1
)
Write-JlSuccess "Combined relin-r1: $combinedR1"

# -------- 3. relin-round2 (round 4) --------
Write-JlInfo "Generating relin-round2 contribution..."
Invoke-JlCli @(
    'crypto', 'relin-contribute',
    '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
    '--round', '2',
    '--secret-key',  $mySecret,
    '--combined-r1', $combinedR1,
    '--joint-pk',    $jointPk,
    '--output',      $myR2
)
Write-JlSuccess "$($script:JL_OUR_LABEL) relin-r2: $myR2"

Publish-JlEnvelope -BinPath $myR2 -Round 4 -MessageType 'relin-round2'

Write-Host ""
Write-JlSuccess "Bundle 2 uploaded. $($script:JL_OUR_LABEL)'s bundle-2 contribution is in."
Write-Host ""
Write-JlInfo "Next step: finalize the joint keys. Both machines run it:"
Write-Host "  $here\03-finalize-keysetup.ps1"

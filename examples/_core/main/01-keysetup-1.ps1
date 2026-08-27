# Data-consumer bundle 1: joint-pk + relin-round1-continue + sum-round1-continue.
# Chains on the data owner's bundle 1, so it waits for their shares first.
#
# PowerShell twin of 01-keysetup-1.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\..\sides\data-consumer.ps1"
. "$here\..\lib.ps1"
Import-JlSession

Write-JlStep "$($script:JL_OUR_LABEL) keysetup bundle 1: joint-pk + relin-round1-continue + sum-round1-continue"

$myShareSecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE
$jointPk       = Join-Path $script:JL_KEYS_DIR 'joint_public_key.bin'
$mainRelinR1   = Join-Path $script:JL_KEYS_DIR 'main-relin-r1.bin'
$mainSumR1     = Join-Path $script:JL_KEYS_DIR 'main-sum-r1.bin'

$leadPkBin      = Join-Path $script:JL_PEER_DIR 'lead-pk.bin'
$leadRelinR1Bin = Join-Path $script:JL_PEER_DIR 'lead-relin-r1.bin'
$leadSumR1Bin   = Join-Path $script:JL_PEER_DIR 'lead-sum-r1.bin'

# -------- 1. Wait for and download the peer's shares --------
Write-JlInfo "Fetching $($script:JL_PEER_LABEL)'s bundle 1 contributions..."
$needsRelin = Test-JlFunctionRequiresRelinKeys

Wait-JlPeerShare 'pk-share'
Save-JlPeerShare -MessageType 'pk-share' -OutPath $leadPkBin

# Additive-only functions declare requiredEvalKeys: [] and never send relin-round1.
if ($needsRelin) {
    Wait-JlPeerShare 'relin-round1'
    Save-JlPeerShare -MessageType 'relin-round1' -OutPath $leadRelinR1Bin
}

$needsSum = Test-JlFunctionRequiresSumKeys
if ($needsSum) {
    Wait-JlPeerShare 'sum-round1'
    Save-JlPeerShare -MessageType 'sum-round1' -OutPath $leadSumR1Bin
}

# -------- 2. Derive the joint pk (chains on the peer's pk-share) --------
Write-JlInfo "Deriving joint public key..."
Invoke-JlCli @(
    'crypto', 'keysetup-contribute',
    '--context-spec',  $script:JULENNY_CRYPTO_CONTEXT_SPEC,
    '--role',          'main',
    '--peer-share',    $leadPkBin,
    '--output-secret', $myShareSecret,
    '--output-public', $jointPk
)
Write-JlSuccess "$($script:JL_OUR_LABEL)'s share secret: $myShareSecret  (stays here, never upload)"
Write-JlSuccess "Joint public key: $jointPk"

Publish-JlEnvelope -BinPath $jointPk -Round 1 -MessageType 'pk-share'

# -------- 3. relin-round1-continue (round 3), only if a relin key is needed --------
if ($needsRelin) {
    Write-JlInfo "Generating relin round-1 continue..."
    Invoke-JlCli @(
        'crypto', 'relin-contribute',
        '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
        '--round', '1', '--role', 'main',
        '--secret-key', $myShareSecret,
        '--peer-share', $leadRelinR1Bin,
        '--output',     $mainRelinR1
    )
    Write-JlSuccess "$($script:JL_OUR_LABEL) relin round-1: $mainRelinR1"

    Publish-JlEnvelope -BinPath $mainRelinR1 -Round 3 -MessageType 'relin-round1-continue'
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
        '--secret-key', $myShareSecret,
        '--peer-share', $leadSumR1Bin,
        '--joint-pk',   $jointPk,
        '--output',     $mainSumR1
    )
    Write-JlSuccess "$($script:JL_OUR_LABEL) sum round-1: $mainSumR1"

    Publish-JlEnvelope -BinPath $mainSumR1 -Round 6 -MessageType 'sum-round1-continue'
} else {
    Write-JlInfo "Function does not require a sum key (requiredEvalKeys); skipping sum-round1-continue."
}

Write-Host ""
Write-JlSuccess "Bundle 1 uploaded."
# With no relin key there is no bundle 2; finalization is the next step.
if (Test-JlFunctionRequiresRelinKeys) { $nextStep = "02-keysetup-2.ps1" } else { $nextStep = "03-finalize-keysetup.ps1" }
Write-JlWaitMessage @"
Tell $($script:JL_PEER_LABEL) to run 02-keysetup-2 in their acme folder.

When their bundle 2 is uploaded, come back here and run:
    $here\$nextStep
"@

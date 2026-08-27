# Data-owner bundle 1: pk-share + relin-round1 + sum-round1.
# These three are independent of any peer input, so we can produce and upload
# all of them in one sitting.
#
# PowerShell twin of 01-keysetup-1.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\..\sides\data-owner.ps1"
. "$here\..\lib.ps1"
Import-JlSession

Write-JlStep "$($script:JL_OUR_LABEL) keysetup bundle 1: pk-share + relin-round1 + sum-round1"

$fheSecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE
$fhePublic = Join-Path $script:JL_KEYS_DIR 'fhe_public_key.bin'
$relinR1   = Join-Path $script:JL_KEYS_DIR 'lead-relin-r1.bin'
$sumR1     = Join-Path $script:JL_KEYS_DIR 'lead-sum-r1.bin'

# -------- 1. pk-share (round 1) --------
Write-JlInfo "Generating FHE keypair ($($script:JL_OUR_LABEL)'s contribution)..."
Invoke-JlCli @(
    'crypto', 'keysetup-contribute',
    '--context-spec',  $script:JULENNY_CRYPTO_CONTEXT_SPEC,
    '--role',          'lead',
    '--output-secret', $fheSecret,
    '--output-public', $fhePublic
)
Write-JlSuccess "FHE secret: $fheSecret  (stays here, never upload)"
Write-JlSuccess "FHE public contribution: $fhePublic"

Publish-JlEnvelope -BinPath $fhePublic -Round 1 -MessageType 'pk-share'

# -------- 2. relin-round1 (round 2), only if the function needs a relin key --------
# Additive-only functions (federated-average) declare requiredEvalKeys: [] and need
# no relin key at all. Publishing round 1 anyway leaves both sides waiting on an
# exchange the platform has already moved past.
if (Test-JlFunctionRequiresRelinKeys) {
    Write-JlInfo "Generating relinearization key round-1 contribution..."
    Invoke-JlCli @(
        'crypto', 'relin-contribute',
        '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
        '--round', '1', '--role', 'lead',
        '--secret-key', $fheSecret,
        '--output',     $relinR1
    )
    Write-JlSuccess "Relin round-1: $relinR1"

    Publish-JlEnvelope -BinPath $relinR1 -Round 2 -MessageType 'relin-round1'
} else {
    Write-JlInfo "Function does not require a relinearization key; skipping relin-round1."
}

# -------- 3. sum-round1 (round 5), only if the function needs a sum key --------
if (Test-JlFunctionRequiresSumKeys) {
    Write-JlInfo "Generating sum key round-1 contribution..."
    Invoke-JlCli @(
        'crypto', 'sum-contribute',
        '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
        '--role', 'lead',
        '--secret-key', $fheSecret,
        '--output',     $sumR1
    )
    Write-JlSuccess "Sum round-1: $sumR1"

    Publish-JlEnvelope -BinPath $sumR1 -Round 5 -MessageType 'sum-round1'
} else {
    Write-JlInfo "Function does not require a sum key (requiredEvalKeys); skipping sum-round1."
}

Write-Host ""
Write-JlSuccess "Bundle 1 uploaded."
# With no relin key there is no bundle 2; finalization is the next step.
if (Test-JlFunctionRequiresRelinKeys) { $nextStep = "02-keysetup-2.ps1" } else { $nextStep = "03-finalize-keysetup.ps1" }
Write-JlWaitMessage @"
Tell $($script:JL_PEER_LABEL) to run 01-keysetup-1 in their beta folder.

When their bundle 1 is uploaded, come back here and run:
    $here\$nextStep
"@

# Data-consumer bundle 2: relin-round2.
#
# The round-1 combine here must match the data owner's byte-for-byte: both sides
# run the same deterministic combine over the same two shares, and the platform
# compares the resulting key hashes.
#
# PowerShell twin of 02-keysetup-2.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\..\sides\data-consumer.ps1"
. "$here\..\lib.ps1"
Import-JlSession

Write-JlStep "$($script:JL_OUR_LABEL) keysetup bundle 2: relin-round2"

$myShareSecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE
$relinR1Main   = Join-Path $script:JL_KEYS_DIR 'main-relin-r1.bin'
$jointPk       = Join-Path $script:JL_KEYS_DIR 'joint_public_key.bin'
$relinR1Lead   = Join-Path $script:JL_PEER_DIR 'lead-relin-r1.bin'
$combinedR1    = Join-Path $script:JL_KEYS_DIR 'combined-relin-r1.bin'
$relinR2       = Join-Path $script:JL_KEYS_DIR 'main-relin-r2.bin'

if (-not (Test-Path -LiteralPath $relinR1Main))   { Stop-JlWithError "Missing $relinR1Main. Did 01-keysetup-1.ps1 run successfully?" }
if (-not (Test-Path -LiteralPath $myShareSecret)) { Stop-JlWithError "Missing $myShareSecret. Did 01-keysetup-1.ps1 run successfully?" }
if (-not (Test-Path -LiteralPath $jointPk))       { Stop-JlWithError "Missing $jointPk. Did 01-keysetup-1.ps1 run successfully?" }

# -------- 1. Re-fetch the peer's relin-round1 if we lost it --------
if (-not (Test-Path -LiteralPath $relinR1Lead)) {
    Save-JlPeerShare -MessageType 'relin-round1' -OutPath $relinR1Lead
}

# -------- 2. Deterministic combine (must match the peer's byte-for-byte) --------
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
    '--secret-key',  $myShareSecret,
    '--combined-r1', $combinedR1,
    '--joint-pk',    $jointPk,
    '--output',      $relinR2
)
Write-JlSuccess "$($script:JL_OUR_LABEL) relin-r2: $relinR2"

Publish-JlEnvelope -BinPath $relinR2 -Round 4 -MessageType 'relin-round2'

Write-Host ""
Write-JlSuccess "Bundle 2 uploaded."
Write-Host ""
Write-JlInfo "Next step: finalize the joint keys (manual, on both machines):"
Write-Host "  $here\03-finalize-keysetup.ps1"

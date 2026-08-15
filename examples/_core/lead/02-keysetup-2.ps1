# Data-owner bundle 2: relin-round2.
# Needs the peer's bundle 1 first, so it waits for their shares before
# combining round-1 and producing our round-2 contribution.
#
# PowerShell twin of 02-keysetup-2.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\..\sides\data-owner.ps1"
. "$here\..\lib.ps1"
Import-JlSession

Write-JlStep "$($script:JL_OUR_LABEL) keysetup bundle 2: relin-round2"

$fheSecret   = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE
$relinR1Lead = Join-Path $script:JL_KEYS_DIR 'lead-relin-r1.bin'
$relinR1Main = Join-Path $script:JL_PEER_DIR 'main-relin-r1.bin'
$jointPk     = Join-Path $script:JL_PEER_DIR 'joint-pk.bin'
$combinedR1  = Join-Path $script:JL_KEYS_DIR 'combined-relin-r1.bin'
$relinR2     = Join-Path $script:JL_KEYS_DIR 'lead-relin-r2.bin'

if (-not (Test-Path -LiteralPath $relinR1Lead)) { Stop-JlWithError "Missing $relinR1Lead. Did 01-keysetup-1.ps1 run successfully?" }
if (-not (Test-Path -LiteralPath $fheSecret))   { Stop-JlWithError "Missing $fheSecret. Did 01-keysetup-1.ps1 run successfully?" }

# -------- 1. Wait for and download the peer's bundle 1 --------
Write-JlInfo "Waiting for $($script:JL_PEER_LABEL) to upload bundle 1..."
Wait-JlPeerShare 'relin-round1-continue'
Wait-JlPeerShare 'pk-share'

Save-JlPeerShare -MessageType 'relin-round1-continue' -OutPath $relinR1Main
Save-JlPeerShare -MessageType 'pk-share'              -OutPath $jointPk

# -------- 2. Deterministic combine of round-1 shares --------
Write-JlInfo "Combining round-1 relin shares (deterministic)..."
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
    '--secret-key',  $fheSecret,
    '--combined-r1', $combinedR1,
    '--joint-pk',    $jointPk,
    '--output',      $relinR2
)
Write-JlSuccess "$($script:JL_OUR_LABEL) relin-r2: $relinR2"

Publish-JlEnvelope -BinPath $relinR2 -Round 4 -MessageType 'relin-round2'

Write-Host ""
Write-JlSuccess "Bundle 2 uploaded."
Write-JlWaitMessage @"
Tell $($script:JL_PEER_LABEL) to run 02-keysetup-2 in their beta folder.

Once both sides have finished bundles 1 and 2, finalize the joint keys
(a manual step on both machines):
    $here\03-finalize-keysetup.ps1
"@

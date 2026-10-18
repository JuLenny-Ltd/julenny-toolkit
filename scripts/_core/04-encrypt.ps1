# Pick a dataset for each function-def input THIS side is responsible for. Both sides
# run it, and both do the same work.
#
# Which inputs those are comes from the DATA role: the function definition labels each
# input dataOwner or queryAnalyst. This is one of only two phases that reads the data
# role rather than the keysetup role, because it is about whose data goes in, not about
# who holds which half of the key.
#
# Each input branches on its declared encoding and layout: plaintext files are
# uploaded raw, encrypted-bundle inputs go through the encodingRecipe first, and
# everything else is encrypted under the joint key. Which is which is entirely
# function-def driven, so one script serves every scenario.
#
# The shared implementation is Invoke-JlEncryptAndUploadInputs in lib.ps1.
#
# PowerShell twin of 04-encrypt.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
# lib.ps1 resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
. "$here\lib.ps1"
Import-JlSession

Invoke-JlEncryptAndUploadInputs -MyRole (Get-JlMyFunctionInputRole)

Write-Host ""
Write-JlInfo "Next step:"
Write-Host "  If the function needs rotation keys:  $here\04.5-rotation-keysetup.ps1"
if ($script:JULENNY_OUR_SIDE -eq 'data-consumer') {
    # The consumer triggers the execution; the owner waits for it and then takes its
    # part in the end-of-cycle. That split is by DATA role and does not move.
    Write-Host "  Then trigger the run:                 $here\05-run-query.ps1"
} else {
    Write-Host "  Then wait for the trigger and reveal: $here\06-end-of-cycle.ps1"
}

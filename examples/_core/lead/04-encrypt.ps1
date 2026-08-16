# Data owner: pick a dataset for each dataOwner input the function-def declares.
#
# Iterates over the inputs whose role matches this side's responsibility,
# uploads each, and declares preferred-datasets.
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
. "$here\..\sides\data-owner.ps1"
. "$here\..\lib.ps1"
Import-JlSession

Invoke-JlEncryptAndUploadInputs -MyRole 'dataOwner'

Write-Host ""
Write-JlInfo "Next step:"
Write-Host "  Once $($script:JL_PEER_LABEL) has run their 04-encrypt and triggered the run,"
Write-Host "  run your end-of-cycle step:  $here\05-release.ps1"

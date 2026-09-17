# Data-consumer: finalize the joint keysetup.
#
# Downloads the peer's round-2 (and sum) shares, runs the deterministic final
# combines, hashes the results, uploads them to object storage, and posts a
# signed envelope declaring what was uploaded. The platform compares both
# parties' hashes; when they match, the permission becomes active.
#
# The shared implementation is Invoke-JlFinalizeKeysetup in lib.ps1: both sides
# do the same work, and keeping it in one place is what stops the two combines
# drifting apart. Run after 02-keysetup-2 has finished on BOTH machines.
#
# PowerShell twin of 03-finalize-keysetup.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
# The side profile is chosen by the DATA role, which the scenario bootstrap exports.
# Sourced dynamically so this phase can be driven for either side: the keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
#
# The fallback keeps a DIRECT run of this script working, which is how the numbered
# scripts are documented to be runnable on their own.
$jlSide = if ($env:JULENNY_OUR_SIDE) { $env:JULENNY_OUR_SIDE } else { 'data-consumer' }
. "$here\..\sides\$jlSide.ps1"
. "$here\..\lib.ps1"
Import-JlSession

Invoke-JlFinalizeKeysetup

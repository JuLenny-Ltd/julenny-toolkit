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
. "$here\..\sides\data-consumer.ps1"
. "$here\..\lib.ps1"
Import-JlSession

Invoke-JlFinalizeKeysetup

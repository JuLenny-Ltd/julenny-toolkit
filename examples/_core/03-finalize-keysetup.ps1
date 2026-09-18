# Finalize the joint keysetup. BOTH sides run it, and both do the SAME work: collect
# whichever round-2 and sum shares the peer owes, run the deterministic final combines,
# hash the results, upload them to object storage, and post a signed envelope declaring
# what was uploaded. The platform compares both parties' hashes; when they match, the
# permission becomes active.
#
# The only thing the KEYSETUP role changes is which share in each combine is already on
# this machine and which has to be fetched, plus the message type the peer's sum share
# arrives under. The combines take the LEAD's share as -a and the MAIN's as -b on both
# machines, because that ordering is what makes the two outputs identical.
#
# The shared implementation is Invoke-JlFinalizeKeysetup in lib.ps1: both sides do the
# same work, and keeping it in one place is what stops the two combines drifting apart.
# Run after 02-keysetup-2 has finished on BOTH machines.
#
# PowerShell twin of 03-finalize-keysetup.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
# lib.ps1 resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
. "$here\lib.ps1"
Import-JlSession

Invoke-JlFinalizeKeysetup

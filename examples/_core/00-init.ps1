# Session setup. BOTH sides run it.
#
# Function-agnostic: this backs every scenario, because the function is picked
# from the platform's live list at run time rather than hardcoded here.
#
# Walks through picking or creating a collaboration and permission, resolving
# the joint key, fetching the function definition, generating and registering
# the signing keypair, and writing config.env so the later scripts pick it all
# up automatically.
#
# EITHER member may create a permission. The platform takes a permission's data owner
# from whoever posts it, so creating one here makes this machine that permission's data
# owner - which is how one collaboration comes to hold permissions running in both
# directions. The data role is then read back FROM THE PLATFORM rather than assumed
# from which scenario folder was run.
#
# PowerShell twin of 00-init.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
# lib.ps1 resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
. "$here\lib.ps1"

Invoke-JlInitSession

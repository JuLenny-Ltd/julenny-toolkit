# Data-owner (keysetup lead) session setup.
#
# Function-agnostic: this backs every scenario, because the function is picked
# from the platform's live list at run time rather than hardcoded here.
#
# Walks through picking or creating a collaboration and permission, resolving
# the joint key, fetching the function definition, generating and registering
# the signing keypair, and writing config.env so the later scripts pick it all
# up automatically.
#
# The data owner may create permissions, so this side gets that option.
#
# PowerShell twin of 00-init.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
# The side profile is chosen by the DATA role, which the scenario bootstrap exports.
# Sourced dynamically so this phase can be driven for either side: the keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
#
# The fallback keeps a DIRECT run of this script working, which is how the numbered
# scripts are documented to be runnable on their own.
$jlSide = if ($env:JULENNY_OUR_SIDE) { $env:JULENNY_OUR_SIDE } else { 'data-owner' }
. "$here\..\sides\$jlSide.ps1"
. "$here\..\lib.ps1"

Invoke-JlInitSession -CanCreatePermission

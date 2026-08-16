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
. "$here\..\sides\data-owner.ps1"
. "$here\..\lib.ps1"

Invoke-JlInitSession -CanCreatePermission

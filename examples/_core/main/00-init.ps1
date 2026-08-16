# Data-consumer (keysetup main) session setup.
#
# Function-agnostic: this backs every scenario, because the function is picked
# from the platform's live list at run time rather than hardcoded here.
#
# Walks through picking a collaboration and permission, resolving the joint key,
# fetching the function definition, generating and registering the signing
# keypair, and writing config.env so the later scripts pick it all up
# automatically.
#
# Only the data owner can create a permission, so once a collaboration is picked
# this side can only choose among the permissions already granted to it. If
# there are none, it says so and stops rather than offering a path that would be
# rejected by the platform.
#
# PowerShell twin of 00-init.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\..\sides\data-consumer.ps1"
. "$here\..\lib.ps1"

Invoke-JlInitSession

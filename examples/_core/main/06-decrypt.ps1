# Data-consumer end-of-cycle step.
#
# Which flow runs depends on resultVisibility, not on which side you are: the
# viewer combines both partials and sees the answer, the releaser contributes a
# partial and never does. Both flows live in lib.ps1; this only picks one.
#
# PowerShell twin of 06-decrypt.sh.

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

$myShareSecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE

if (Test-JlAmViewer) {
    Invoke-JlViewerFlow -MySecret $myShareSecret
} else {
    Invoke-JlReleaserFlow -MySecret $myShareSecret
}

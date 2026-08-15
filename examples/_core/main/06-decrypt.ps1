# Data-consumer end-of-cycle step.
#
# Which flow runs depends on resultVisibility, not on which side you are: the
# viewer combines both partials and sees the answer, the releaser contributes a
# partial and never does. Both flows live in lib.ps1; this only picks one.
#
# PowerShell twin of 06-decrypt.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\..\sides\data-consumer.ps1"
. "$here\..\lib.ps1"
Import-JlSession

$myShareSecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE

if (Test-JlAmViewer) {
    Invoke-JlViewerFlow -MySecret $myShareSecret
} else {
    Invoke-JlReleaserFlow -MySecret $myShareSecret
}

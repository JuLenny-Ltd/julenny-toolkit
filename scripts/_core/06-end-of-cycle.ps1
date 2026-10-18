# End-of-cycle: this machine's part of revealing the answer. BOTH sides run it.
#
# Which part that is comes from the permission's resultVisibility, not from which side
# you are: the viewer combines both partials and sees the answer, the releaser
# contributes a partial and never does. Both flows live in lib.ps1; this only picks one.
#
# It is one script, not a "release" script and a "decrypt" script: either name would
# describe what one side does under the default visibility, and neither would be true
# when it is reversed.
#
# PowerShell twin of 06-end-of-cycle.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\lib.ps1"
Import-JlSession

# Named for the KEYSETUP role, which Import-JlSession resolved from config.env. The
# partial decryption this produces is role-specific, so reading the other role's file
# would yield a wrong answer rather than an error.
$mySecret = Join-Path $script:JL_KEYS_DIR $script:JL_SECRET_SHARE_FILE
if (-not (Test-Path -LiteralPath $mySecret)) {
    Stop-JlWithError "Missing this machine's FHE secret share at $mySecret (produced by keysetup)."
}

if (Test-JlAmViewer) {
    Invoke-JlViewerFlow -MySecret $mySecret
} else {
    Invoke-JlReleaserFlow -MySecret $mySecret
}

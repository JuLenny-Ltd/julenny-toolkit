# negotiation-matrix, DATA-CONSUMER (Beta) side. Thin scenario bootstrap: selects our side
# and this scenario's data dir, then hands off to the shared _core driver. The
# function is picked at 00-init time, so one folder can run any function of its
# family.
#
# PowerShell twin of run.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

# Passed to the driver as environment variables: run.ps1 is launched as a child
# process, so this is how it and lib.ps1 pick them up.
$env:JULENNY_OUR_SIDE = 'data-consumer'
$env:JL_DATA_DIR      = Join-Path $here 'data'

$core = $null
foreach ($cand in @((Join-Path $here '_core'), (Join-Path $here '..\..\_core'))) {
    if (Test-Path -LiteralPath (Join-Path $cand 'run.ps1')) { $core = $cand; break }
}
if (-not $core) {
    throw "could not locate the _core driver (looked in $here\_core and $here\..\..\_core)"
}

& (Join-Path $core 'run.ps1') @args
exit $LASTEXITCODE

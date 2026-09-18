# negotiation-matrix. Thin scenario bootstrap: names the scenario, then hands off to the
# shared _core driver. The function is picked at 00-init time.
#
# It does NOT say which side of the collaboration this machine is. There used to be two
# of these, acme\run.ps1 and beta\run.ps1, and that was a question the operator should
# never have been asked: picking a permission answers it, and the platform is the only
# thing that actually knows. The side now arrives with the permission, and decides both
# which sample folder is offered and which half of the key ceremony this machine runs.
#
# PowerShell twin of run.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

# Passed to the driver as an environment variable: run.ps1 is launched as a child
# process, so this is how it and lib.ps1 pick it up. The scenario name selects the
# sample folder under the working folder:
#     <workdir>\samples\negotiation-matrix\<data-owner or data-consumer>\
# Taken from the folder name so renaming the folder renames the samples with it.
$env:JL_SCENARIO = Split-Path -Leaf $here

$core = $null
foreach ($cand in @((Join-Path $here '_core'), (Join-Path $here '..\_core'))) {
    if (Test-Path -LiteralPath (Join-Path $cand 'run.ps1')) { $core = $cand; break }
}
if (-not $core) {
    throw "could not locate the _core driver (looked in $here\_core and $here\..\_core)"
}

& (Join-Path $core 'run.ps1') @args
exit $LASTEXITCODE

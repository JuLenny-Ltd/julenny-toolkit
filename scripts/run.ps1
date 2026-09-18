# Run a JuLenny collaboration. ONE entry point, every scenario, both sides.
#
#     .\run.ps1
#
# It asks nothing that the platform already knows. Pick a permission at the first
# prompt and that single choice settles:
#
#   the FUNCTION       - pinned on the permission, count or itemized included;
#   the SCENARIO       - the function's family, which selects the sample data;
#   your DATA ROLE     - owner or consumer, from the permission's yourRole;
#   your KEYSETUP ROLE - lead or main, from the joint key, and NOT the same question.
#
# There used to be ten of these, a folder per scenario times a folder per side, and
# choosing among them was how you declared all four. Every one of those declarations
# was a chance to contradict the platform, and a contradiction about the keysetup role
# does not fail loudly: it produces the wrong partial decryption and a wrong answer.
#
# The driver is menu-driven and resumes wherever you left off, waiting when it needs
# the other side to act. The numbered phase scripts in _core\ can also be run one at a
# time, in order, to follow the protocol step by step.
#
# PowerShell twin of run.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

& (Join-Path (Join-Path $here '_core') 'driver.ps1') @args
exit $LASTEXITCODE

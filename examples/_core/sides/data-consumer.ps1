# _core side profile: DATA CONSUMER (the "Beta" role in the demos). PowerShell
# twin of data-consumer.env.
#
# Static, per-side parameters the shared driver reads. Dot-sourced by run.ps1
# before lib.ps1, whose guard requires these. Do NOT put per-collaboration state
# here (that stays in the workdir's config.env).
#
# KEEP IN SYNC with data-consumer.env. The two files describe the same side;
# only the syntax differs. If you change a value here, change it there.

$script:JULENNY_OUR_SIDE = 'data-consumer'

# Display labels. A scenario may override JL_OUR_LABEL / JL_PEER_LABEL in its
# scenario config to fit a narrative; these are the defaults if it does not.
#
# Tested with Get-Variable rather than by reading the variable: a phase script
# launched by run.ps1 inherits Set-StrictMode, under which reading a variable
# that was never set is a terminating error.
if (-not (Get-Variable -Name JL_OUR_LABEL  -Scope Script -ErrorAction SilentlyContinue)) { $script:JL_OUR_LABEL  = 'Beta' }
if (-not (Get-Variable -Name JL_PEER_LABEL -Scope Script -ErrorAction SilentlyContinue)) { $script:JL_PEER_LABEL = 'Acme' }
$script:JL_ROLE_LABEL = 'data consumer / main'

# This side stores its FHE secret share under this filename. ASYMMETRIC by
# design - the owner side uses a different name. Do not unify.
$script:JL_SECRET_SHARE_FILE = 'my_share_secret.bin'

# Platform API: how this side lists its permissions, and which
# collaboration-id field on a permission points at the PEER.
$script:JL_PERM_VIEW = 'received'
# Collaboration ID (XXXX-XXXX) of the peer.
$script:JL_PEER_COLLAB_FIELD = 'dataOwnerCollaborationId'
$script:JL_ROLE_DIR = 'main'

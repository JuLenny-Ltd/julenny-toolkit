# _core side profile: DATA OWNER (the "Acme" role in the demos). PowerShell twin
# of data-owner.env.
#
# Static, per-side parameters the shared driver reads. Dot-sourced by run.ps1
# before lib.ps1, whose guard requires these. Do NOT put per-collaboration state
# here (that stays in the workdir's config.env).
#
# KEEP IN SYNC with data-owner.env. The two files describe the same side; only
# the syntax differs. If you change a value here, change it there.

$script:JULENNY_OUR_SIDE = 'data-owner'

# Display labels. A scenario may override JL_OUR_LABEL / JL_PEER_LABEL to fit a
# narrative (e.g. Buyer / Supplier); these are the defaults if it does not.
if (-not $script:JL_OUR_LABEL)  { $script:JL_OUR_LABEL  = 'Acme' }
if (-not $script:JL_PEER_LABEL) { $script:JL_PEER_LABEL = 'Beta' }
$script:JL_ROLE_LABEL = 'data owner / lead'

# This side stores its FHE secret share under this filename. ASYMMETRIC by
# design - the consumer side uses a different name. Do not unify.
$script:JL_SECRET_SHARE_FILE = 'fhe_secret_key.bin'

# Platform API: how this side lists its permissions, and which
# collaboration-id field on a permission points at the PEER.
$script:JL_PERM_VIEW = 'permissioned'
# Collaboration ID (XXXX-XXXX) of the peer.
$script:JL_PEER_COLLAB_FIELD = 'dataConsumerCollaborationId'
$script:JL_ROLE_DIR = 'lead'

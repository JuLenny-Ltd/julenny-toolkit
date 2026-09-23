# _core side profile: DATA OWNER (the "Acme" role in the demos). PowerShell twin
# of data-owner.env.
#
# Static, per-side parameters the shared driver reads. Dot-sourced by lib.ps1 once it
# has resolved which side this machine is. Do NOT put per-collaboration state here
# (that stays in the workdir's config.env).
#
# Everything here describes the DATA role. The KEYSETUP role is a separate question:
# a permission can be created in either direction inside one collaboration, so the
# data owner is not always the keysetup lead. The two fallbacks below are the only
# things in this file that touch it, and only until the platform answers.
#
# KEEP IN SYNC with data-owner.env. The two files describe the same side; only
# the syntax differs. If you change a value here, change it there.

$script:JULENNY_OUR_SIDE = 'data-owner'

# Display labels. A scenario may override JL_OUR_LABEL / JL_PEER_LABEL to fit a
# narrative (e.g. Buyer / Supplier); these are the defaults if it does not.
#
# Tested with Get-Variable rather than by reading the variable: a phase script
# launched by run.ps1 inherits Set-StrictMode, under which reading a variable
# that was never set is a terminating error.
if (-not (Get-Variable -Name JL_OUR_LABEL  -Scope Script -ErrorAction SilentlyContinue)) { $script:JL_OUR_LABEL  = 'Acme' }
if (-not (Get-Variable -Name JL_PEER_LABEL -Scope Script -ErrorAction SilentlyContinue)) { $script:JL_PEER_LABEL = 'Beta' }
# The DATA role only. It used to read 'data owner / lead', which claimed a keysetup
# role at a point in the run where nothing has asked the platform for one yet.
$script:JL_ROLE_LABEL = 'data owner'
$script:JL_PEER_ROLE_LABEL = 'data consumer'

# FALLBACK ONLY. The secret-share filename follows the KEYSETUP role, and
# Import-JlSession overrides this from JULENNY_ROLE in config.env. This value stands
# only before 00-init has written one, and is correct wherever the two roles agree.
# ASYMMETRIC by design - the other name holds different key material, so do not unify.
$script:JL_SECRET_SHARE_FILE = 'fhe_secret_key.bin'

# FALLBACK ONLY, for the same reason: the half of the key ceremony to assume when the
# platform records none. Joint keys built before it recorded one are not backfilled.
$script:JL_DEFAULT_KEYSETUP_ROLE = 'lead'

# Platform API: how this side lists its permissions, and which
# collaboration-id field on a permission points at the PEER.
# 'granted' and 'received' are the only two values the API special-cases; anything
# else falls through to a default that happens to match 'granted' for an API key.
# This said 'permissioned', which is not a value the platform knows.
$script:JL_PERM_VIEW = 'granted'
# Collaboration ID (XXXX-XXXX) of the peer.
$script:JL_PEER_COLLAB_FIELD = 'dataConsumerCollaborationId'

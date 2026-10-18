#!/usr/bin/env bash
# End-of-cycle: this machine's part of revealing the answer. BOTH sides run it.
#
# Which part that is comes from the permission's resultVisibility, not from which side
# you are:
#
#   The VIEWER polls for released, downloads the result and the peer's partial,
#   partial-decrypts locally, combines, and renders the plaintext answer.
#
#   The RELEASER polls for awaiting-release, partial-decrypts, signs and uploads. It
#   never sees the plaintext.
#
# resultVisibility "dataConsumer" (the default) makes the consumer the viewer;
# "dataOwner" makes the owner the viewer. Both flows live in lib.sh as releaser_flow /
# viewer_flow, and this script only picks which one to call.
#
# It is one script, not a "release" script and a "decrypt" script: either name would
# describe what one side does under the default visibility, and neither would be true
# when it is reversed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_session

# Named for the KEYSETUP role, which load_session resolved from config.env. The partial
# decryption this produces is role-specific, so reading the other role's file would
# yield a wrong answer rather than an error.
MY_SECRET="$JL_KEYS_DIR/$JL_SECRET_SHARE_FILE"
[[ -f "$MY_SECRET" ]] \
    || die "Missing this machine's FHE secret share at $MY_SECRET (produced by keysetup)."

if am_i_viewer; then
    viewer_flow "$MY_SECRET"
else
    releaser_flow "$MY_SECRET"
fi

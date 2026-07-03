#!/usr/bin/env bash
# Acme's end-of-cycle script. Dispatches based on the permission's
# resultVisibility (0.5.5):
#
#   resultVisibility = "dataConsumer" (default): Acme is the releaser.
#     Run the releaser flow - poll for awaiting-release, partial-decrypt,
#     sign, upload. Beta will see the plaintext answer.
#
#   resultVisibility = "dataOwner": Acme is the viewer. Run the viewer
#     flow - poll for released, download result + Beta's partial,
#     partial-decrypt locally, combine, render the plaintext answer.
#
# Both flows live in _lib.sh as releaser_flow / viewer_flow; this script
# only picks which one to call. Renamed in 0.5.5 to "Acme's end-of-cycle"
# instead of "release" since the script's role depends on visibility now.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/../sides/data-owner.env"
source "$SCRIPT_DIR/../lib.sh"
load_session

FHE_SECRET="$JL_KEYS_DIR/fhe_secret_key.bin"

if am_i_viewer; then
    viewer_flow "$FHE_SECRET"
else
    releaser_flow "$FHE_SECRET"
fi

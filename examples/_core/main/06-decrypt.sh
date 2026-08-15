#!/usr/bin/env bash
# Beta's end-of-cycle script. Dispatches based on the permission's
# resultVisibility (0.5.5):
#
#   resultVisibility = "dataConsumer" (default): Beta is the viewer. Run
#     the viewer flow - poll for released, download result + Acme's
#     partial, partial-decrypt locally, combine, render the plaintext
#     answer.
#
#   resultVisibility = "dataOwner": Beta is the releaser. Run the
#     releaser flow - poll for awaiting-release, partial-decrypt, sign,
#     upload. Acme will see the plaintext answer.
#
# Both flows live in lib.sh as releaser_flow / viewer_flow; this script
# only picks which one to call.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../sides/data-consumer.env
source "$SCRIPT_DIR/../sides/data-consumer.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"
load_session

MY_SHARE_SECRET="$JL_KEYS_DIR/my_share_secret.bin"

if am_i_viewer; then
    viewer_flow "$MY_SHARE_SECRET"
else
    releaser_flow "$MY_SHARE_SECRET"
fi

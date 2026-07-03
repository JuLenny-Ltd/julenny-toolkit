#!/usr/bin/env bash
# joint-record-overlap, DATA-CONSUMER (Beta) side. Thin scenario bootstrap:
# selects our side + this scenario's data dir, then hands off to the shared
# _core driver. The function (count or itemized) is picked at 00-init time.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export JULENNY_OUR_SIDE="data-consumer"
export JL_DATA_DIR="$HERE/data"
CORE=""
for cand in "$HERE/_core" "$HERE/../../_core"; do
    [[ -f "$cand/run.sh" ]] && CORE="$cand" && break
done
[[ -n "$CORE" ]] || { echo "could not locate the _core driver (looked in $HERE/_core and $HERE/../../_core)" >&2; exit 1; }
exec "$CORE/run.sh" "$@"

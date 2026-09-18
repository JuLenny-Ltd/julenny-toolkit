#!/usr/bin/env bash
# federated-average. Thin scenario bootstrap: names the scenario, then hands off to the
# shared _core driver. The function is picked at 00-init time.
#
# It does NOT say which side of the collaboration this machine is. There used to be two
# of these, acme/run.sh and beta/run.sh, and that was a question the operator should
# never have been asked: picking a permission answers it, and the platform is the only
# thing that actually knows. The side now arrives with the permission, and decides both
# which sample folder is offered and which half of the key ceremony this machine runs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# The scenario name selects the sample folder under the working folder:
#     <workdir>/samples/federated-average/<data-owner|data-consumer>/
# Taken from the folder name so renaming the folder renames the samples with it.
export JL_SCENARIO="$(basename "$HERE")"

CORE=""
for cand in "$HERE/_core" "$HERE/../_core"; do
    [[ -f "$cand/run.sh" ]] && CORE="$cand" && break
done
[[ -n "$CORE" ]] || { echo "could not locate the _core driver (looked in $HERE/_core and $HERE/../_core)" >&2; exit 1; }
exec "$CORE/run.sh" "$@"

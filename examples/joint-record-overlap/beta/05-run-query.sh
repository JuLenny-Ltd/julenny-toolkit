#!/usr/bin/env bash
# Beta (data consumer): trigger the FHE function execution on the platform.
# Polls until the execution reaches 'awaiting-release', then prints the
# execution ID for Acme to use in their 05-release.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"
load_session

step "Beta: trigger FHE function execution"

# -------- Dataset binding (read declared picks from the platform) --------
# Each side's 04-encrypt PUTs its picks to
#   /api/fhe-permissions/{grantId}/preferred-datasets/{inputName}
# We GET the full set here just to show the operator exactly what the
# execution will use, then trigger /execute WITHOUT an inputDatasetIds
# body. The platform resolves dataset bindings from the declarations and
# returns 409 with a clear "X has not declared..." message if any input is
# still missing a pick.

FUNCTION_DEF="$JL_WORKDIR/function-def.json"
[[ -f "$FUNCTION_DEF" ]] \
    || die "Function-def not found at $FUNCTION_DEF. Re-run ./00-init.sh to fetch it."

info "Fetching declared dataset picks from the platform..."
DECLARED="$(curl_jl GET "/api/fhe-permissions/$JULENNY_PERMISSION_ID/preferred-datasets")"

# Sanity check: confirm every input the function-def requires has a
# declaration before we hit /execute. Saves a round trip and surfaces the
# "ask the peer to run 04-encrypt" message slightly earlier.
MISSING=""
for input in $(jq -r '.inputs[]?.name // empty' "$FUNCTION_DEF"); do
    if [[ -z "$(echo "$DECLARED" | jq -r --arg n "$input" '.[$n].datasetId // empty')" ]]; then
        MISSING="${MISSING}${MISSING:+, }$input"
    fi
done
if [[ -n "$MISSING" ]]; then
    warn "Function inputs without a declared pick yet: $MISSING"
    warn "Ask the responsible side to run their 04-encrypt for those inputs."
    die "Cannot proceed."
fi

echo
echo "============================================================"
echo " DECLARED DATASET PICKS FOR THIS EXECUTION:"
echo "$DECLARED" | jq -r 'to_entries[] | select(.value != null) |
    "   \(.key):\n       datasetId   = \(.value.datasetId)\n       declaredBy  = \(.value.companyId)\n       declaredAt  = \(.value.declaredAt // "?")"'
echo "============================================================"

echo
info "Triggering execution on permission $JULENNY_PERMISSION_ID (datasets resolved from declarations)..."
RESP="$(curl_jl POST "/api/grants/$JULENNY_PERMISSION_ID/execute" \
        -H "Content-Type: application/json" \
        --data-binary '{}')"

# 409 from the platform means a declaration is missing for at least one
# input. Surface it with a hint rather than just dumping the raw error.
if echo "$RESP" | jq -e '.error' > /dev/null 2>&1; then
    err "/execute rejected the trigger:"
    echo "$RESP" | jq . >&2
    ERR_MSG="$(echo "$RESP" | jq -r '.error // ""')"
    if [[ "$ERR_MSG" == *"has not declared"* ]]; then
        err
        err "That input still needs its owner to run 04-encrypt. Once they do,"
        err "this script can be rerun without changes."
    fi
    die "Cannot proceed."
fi

EXEC_ID="$(echo "$RESP" | jq -r '.executionId // empty')"
[[ -n "$EXEC_ID" ]] || die "No executionId returned. Response: $RESP"

success "Execution triggered. ID: $EXEC_ID"
# Note: we don't persist the ID anywhere. Both Acme's 05-release and Beta's
# 06-decrypt discover the right execution via the platform's list endpoint,
# so there's nothing to cache locally.

# -------- Poll until awaiting-release (external permission) --------
info "Polling for execution to complete..."
elapsed=0
delay=5
while true; do
    EXEC_DOC="$(curl_jl GET "/api/executions/$EXEC_ID")"
    state="$(echo "$EXEC_DOC" | jq -r '.state // "unknown"')"
    case "$state" in
        queued|computing)
            printf "  state: %s (%ds elapsed)\n" "$state" "$elapsed"
            ;;
        awaiting-release)
            success "Computation done. Awaiting Acme's partial-decrypt release."
            break
            ;;
        succeeded)
            success "Computation done (internal permission; result directly available)."
            break
            ;;
        failed)
            err "Execution failed. Full execution doc:"
            echo "$EXEC_DOC" | jq . >&2
            die "See above for failureReason / error."
            ;;
        *)
            warn "Unexpected state: $state"
            ;;
    esac
    sleep "$delay"
    elapsed=$(( elapsed + delay ))
    if   (( elapsed > 60 ));  then delay=15
    elif (( elapsed > 30 ));  then delay=10
    fi
    (( elapsed > 1800 )) && die "Timed out after 30 min."
done

echo
info "Next step:"
echo "  Acme can now run ./05-release.sh on their machine. Their script"
echo "  discovers this execution via the platform API; no manual handoff needed."
echo
echo "  Once Acme releases, come back here and run:"
echo "    $SCRIPT_DIR/06-decrypt.sh"

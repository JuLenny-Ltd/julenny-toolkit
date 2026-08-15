#!/usr/bin/env bash
# Data consumer: trigger the FHE function execution on the platform.
# Shows a cost estimate + confirmation (credit system), then triggers and
# polls until the execution reaches 'awaiting-release'.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../sides/data-consumer.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"
load_session

step "${JL_OUR_LABEL}: trigger FHE function execution"

FUNCTION_DEF="$JL_WORKDIR/function-def.json"
[[ -f "$FUNCTION_DEF" ]] \
    || die "Function-def not found at $FUNCTION_DEF. Re-run 00-init to fetch it."

# -------- Engine selection (multi-engine functions) --------
# We do NOT derive the engine list from the function-def's .supportedEngines:
# that is what the function COULD use in theory, not what THIS account may
# actually run. Instead we estimate engine-agnostically below; the platform's
# /estimate .options[] comes back already filtered to the engines this plan is
# eligible for (GPU only if the plan allows it), each with its own cost and
# quoteToken. That drives the menu.
CHOSEN_ENGINE=""
QUOTE_TOKEN=""

info "Fetching declared dataset picks from the platform..."
DECLARED="$(curl_jl GET "/api/fhe-permissions/$JULENNY_PERMISSION_ID/preferred-datasets")"

# Confirm every input the function-def requires has a declaration.
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
    "   \(.key):\n       datasetId   = \(.value.datasetId)\n       declaredAt  = \(.value.declaredAt // "?")"'
echo "============================================================"

# -------- Cost estimate + confirmation (credit system, 2026-06) --------
# The platform auto-reserves credits on every execution regardless. The
# estimate endpoint adds a per-engine cost + balance breakdown and a
# quoteToken that locks the estimate (5 min) and makes the credit hold
# precise. We show it, let the operator confirm, and pass the token to
# /execute. If the endpoint is unavailable we fall back to a plain trigger
# (the platform still reserves credits server-side).
# CRITICAL: /estimate and /execute map inputDatasetIds to function inputs BY
# POSITION, in the function-def's .inputs[] order. Build the array in exactly
# that order. The declared-picks object's key order is arbitrary (declaration
# order), so deriving the array from it directly sends ciphertexts into the
# wrong slots (e.g. plaintext rule_pairs landing in left_indicator).
INPUT_IDS="$(jq -c --argjson dec "$DECLARED" '[.inputs[].name as $n | $dec[$n].datasetId]' "$FUNCTION_DEF")"

# Both /estimate and /execute return {"error":"No remaining executions."} once
# this permission's allowedExecutions are used up. Instead of dying, tell the
# operator to ask the data owner to top up the SAME permission (supported now:
# it increments the existing grant, no new keysetup), then re-check or stop.
is_no_executions() { [[ "$1" == *"No remaining executions"* ]]; }

recheck_or_stop() {
    echo
    warn "This permission has no remaining executions left."
    local allowed
    allowed="$(fetch_permission "$JULENNY_PERMISSION_ID" 2>/dev/null | jq -r '.allowedExecutions // empty')"
    [[ -n "$allowed" ]] && info "  (executions granted so far: $allowed, remaining: 0)"
    info "Ask ${JL_PEER_LABEL} (the data owner) to add more executions to this"
    info "permission ($JULENNY_PERMISSION_ID). It tops up the existing grant -"
    info "no new keysetup and no new permission needed."
    echo
    prompt_for MORE "Have they added more? Re-check now? (y/N)" "N"
    if [[ "${MORE,,}" == "y" ]]; then
        info "Re-checking with the platform..."
        return 0
    fi
    info "No executions added. Stopping. Re-run this script once ${JL_PEER_LABEL} grants more."
    exit 0
}

EXEC_ID=""
while [[ -z "$EXEC_ID" ]]; do
    CHOSEN_ENGINE=""
    QUOTE_TOKEN=""
    echo
    info "Estimating execution cost..."
    # Engine-agnostic estimate: .options[] returns one entry per engine THIS
    # account may actually run (the platform filters GPU out unless the plan
    # allows it), each with its own cost and quoteToken.
    EST="$(curl_jl POST "/api/grants/$JULENNY_PERMISSION_ID/estimate" \
            -H "Content-Type: application/json" \
            --data-binary "$(jq -n --argjson ids "$INPUT_IDS" '{inputDatasetIds: $ids}')" \
            2>/dev/null || echo '{}')"

    N_OPTS="$(echo "$EST" | jq -r '(.options | length) // 0' 2>/dev/null || echo 0)"
    if [[ "$N_OPTS" =~ ^[0-9]+$ ]] && (( N_OPTS >= 1 )); then
        # The eligible-engine options drive the menu. One option -> auto-select.
        OPT_IDX=0
        if (( N_OPTS > 1 )); then
            echo
            echo "This function can run on more than one engine available to you:"
            for i in $(seq 0 $(( N_OPTS - 1 ))); do
                e="$(  echo "$EST" | jq -r ".options[$i].engine         // \"?\"")"
                c50="$(echo "$EST" | jq -r ".options[$i].costP50Credits // \"?\"")"
                c90="$(echo "$EST" | jq -r ".options[$i].costP90Credits // \"?\"")"
                case "$e" in
                    openfhe-cpu)       label="CPU (OpenFHE)" ;;
                    fideslib-ckks-gpu) label="GPU (FIDESlib, L4)" ;;
                    *)                 label="$e" ;;
                esac
                printf "   [%d] %-18s %-18s ~%s CR (P90: %s CR)\n" "$(( i + 1 ))" "$e" "$label" "$c50" "$c90"
            done
            prompt_for ENG_PICK "Choose engine (1-$N_OPTS)" "1"
            if [[ "$ENG_PICK" =~ ^[0-9]+$ ]] && (( ENG_PICK >= 1 && ENG_PICK <= N_OPTS )); then
                OPT_IDX=$(( ENG_PICK - 1 ))
            fi
        fi
        CHOSEN_ENGINE="$(echo "$EST" | jq -r ".options[$OPT_IDX].engine         // empty")"
        QUOTE_TOKEN="$(  echo "$EST" | jq -r ".options[$OPT_IDX].quoteToken     // empty")"
        COST_P50="$(     echo "$EST" | jq -r ".options[$OPT_IDX].costP50Credits // \"?\"")"
        COST_P90="$(     echo "$EST" | jq -r ".options[$OPT_IDX].costP90Credits // \"?\"")"
        BAL="$(  echo "$EST" | jq -r '.balance.credits     // "?"')"
        AVAIL="$(echo "$EST" | jq -r '.balance.available   // "?"')"
        HELD="$( echo "$EST" | jq -r '.balance.heldCredits // "?"')"
        echo
        echo "   Engine:         ${CHOSEN_ENGINE:-?}"
        echo "   Estimated cost: $COST_P50 CR (P90: $COST_P90 CR)"
        echo "   Credit balance: $BAL CR (available: $AVAIL, held: $HELD)"
        echo
        prompt_for PROCEED "Proceed with execution? (Y/n)" "Y"
        if [[ -n "$PROCEED" && "${PROCEED,,}" != "y" ]]; then
            info "Execution cancelled. No credits were held."
            exit 0
        fi
    else
        EST_ERR="$(echo "$EST" | jq -r '.error // ""')"
        if is_no_executions "$EST_ERR"; then
            recheck_or_stop
            continue
        fi
        warn "Cost estimate unavailable; the platform will auto-reserve credits at trigger time."
    fi

    echo
    info "Triggering execution on permission $JULENNY_PERMISSION_ID..."
    if [[ -n "$QUOTE_TOKEN" ]]; then
        RESP="$(curl_jl POST "/api/grants/$JULENNY_PERMISSION_ID/execute" \
                -H "Content-Type: application/json" \
                --data-binary "$(jq -n --argjson ids "$INPUT_IDS" --arg tok "$QUOTE_TOKEN" --arg eng "$CHOSEN_ENGINE" '{inputDatasetIds: $ids, quoteToken: $tok} + (if $eng != "" then {engine: $eng} else {} end)')")"
    else
        RESP="$(curl_jl POST "/api/grants/$JULENNY_PERMISSION_ID/execute" \
                -H "Content-Type: application/json" \
                --data-binary "$(jq -n --arg eng "$CHOSEN_ENGINE" '(if $eng != "" then {engine: $eng} else {} end)')")"
    fi

    if echo "$RESP" | jq -e '.error' > /dev/null 2>&1; then
        ERR_MSG="$(echo "$RESP" | jq -r '.error // ""')"
        if is_no_executions "$ERR_MSG"; then
            recheck_or_stop
            continue
        fi
        err "/execute rejected the trigger:"
        echo "$RESP" | jq . >&2
        if [[ "$ERR_MSG" == *"has not declared"* ]]; then
            err
            err "That input still needs its owner to run 04-encrypt. Once they do,"
            err "this script can be rerun without changes."
        fi
        if [[ "$ERR_MSG" == *redit* || "$ERR_MSG" == *uote* ]]; then
            err
            err "Looks credit/quote related: the quoteToken may have expired (5 min)"
            err "or the balance is insufficient. Re-run to fetch a fresh estimate."
        fi
        die "Cannot proceed."
    fi

    EXEC_ID="$(echo "$RESP" | jq -r '.executionId // empty')"
    [[ -n "$EXEC_ID" ]] || die "No executionId returned. Response: $RESP"
done

success "Execution triggered. ID: $EXEC_ID"

# Persist this cycle's execution id so the viewer flow (06-decrypt) waits for
# THIS execution to be released instead of offering older released ones.
echo "$EXEC_ID" > "$JL_WORKDIR/last_exec_id"

# -------- Poll until awaiting-release --------
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
            success "Computation done. Awaiting ${JL_PEER_LABEL}'s partial-decrypt release."
            break
            ;;
        released)
            # The peer's releaser was watching and released between our
            # polls; nothing left to wait for.
            success "Computation done and already released by ${JL_PEER_LABEL}."
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
info "Next step: ${JL_PEER_LABEL} runs their end-of-cycle (release); then run 06-decrypt here."

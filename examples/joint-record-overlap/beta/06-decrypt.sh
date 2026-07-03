#!/usr/bin/env bash
# Beta (data consumer): download the encrypted result + Acme's partial
# decrypt, produce Beta's own partial decrypt locally, combine both
# partials, and display the plaintext answer.
#
# Run this after Acme has run 05-release.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"
load_session

step "Beta: combine partials and reveal the plaintext"

# Fetch all 'released' executions for this permission via the platform's
# list endpoint. Newest is at index 0 (the API returns them ordered by
# triggeredAt desc). If there are none yet, poll with backoff until at
# least one shows up. Then present the list and let the operator pick;
# auto-pick if there's only one.
info "Polling for released executions on permission $JULENNY_PERMISSION_ID..."
elapsed=0
delay=5
LIST_RESP=""
COUNT=0
while true; do
    LIST_RESP="$(curl_jl GET \
        "/api/fhe-permissions/$JULENNY_PERMISSION_ID/executions?state=released")"
    COUNT="$(echo "$LIST_RESP" | jq '.executions | length')"
    if (( COUNT > 0 )); then
        break
    fi
    printf "  (no released execution yet, %ds elapsed)\n" "$elapsed"
    sleep "$delay"
    elapsed=$(( elapsed + delay ))
    if   (( elapsed > 60 ));  then delay=15
    elif (( elapsed > 30 ));  then delay=10
    fi
    (( elapsed > 1800 )) \
        && die "Timed out after 30 min waiting for a released execution. Did Acme run 05-release.sh?"
done

if (( COUNT == 1 )); then
    EXEC_ID="$(echo "$LIST_RESP" | jq -r '.executions[0].id')"
    EXEC_WHEN="$(echo "$LIST_RESP" | jq -r '.executions[0].releasedAt // .executions[0].triggeredAt // "unknown date"')"
    success "Single released execution: $EXEC_ID ($EXEC_WHEN)"
else
    info "Found $COUNT released executions (newest first):"
    echo "$LIST_RESP" | jq -r '.executions | to_entries[] | "  \(.key + 1)) \(.value.id)  (\(.value.releasedAt // .value.triggeredAt // "unknown date"))"'
    prompt_for CHOICE "Pick an execution (1-$COUNT)" "1"
    if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || (( CHOICE < 1 || CHOICE > COUNT )); then
        die "Invalid choice: $CHOICE (must be between 1 and $COUNT)"
    fi
    EXEC_ID="$(echo "$LIST_RESP" | jq -r ".executions[$((CHOICE - 1))].id")"
    EXEC_WHEN="$(echo "$LIST_RESP" | jq -r ".executions[$((CHOICE - 1))].releasedAt // .executions[$((CHOICE - 1))].triggeredAt // \"unknown date\"")"
    success "Selected: $EXEC_ID ($EXEC_WHEN)"
fi

MY_SHARE_SECRET="$JL_KEYS_DIR/my_share_secret.bin"
[[ -f "$MY_SHARE_SECRET" ]] || die "Missing $MY_SHARE_SECRET. Did keysetup complete on this machine?"

RESULT_BIN="$JL_KEYS_DIR/result-$EXEC_ID.bin"
OWNER_PARTIAL_BIN="$JL_KEYS_DIR/owner-partial-$EXEC_ID.bin"
MY_PARTIAL_BIN="$JL_KEYS_DIR/my-partial-$EXEC_ID.bin"

# -------- 1. Download encrypted result --------
info "Downloading encrypted result from platform..."
HTTP_CODE="$(curl -sS -w '%{http_code}' -o "$RESULT_BIN" \
    -H "x-api-key: $JULENNY_API_KEY" \
    "$JULENNY_API_BASE/api/executions/$EXEC_ID/result")"

if [[ "$HTTP_CODE" == "403" ]]; then
    rm -f "$RESULT_BIN"
    die "Platform says the result isn't released yet. Have Acme run 05-release.sh first."
elif [[ "$HTTP_CODE" != "200" ]]; then
    err "Platform returned HTTP $HTTP_CODE when downloading the result."
    cat "$RESULT_BIN" >&2 || true
    rm -f "$RESULT_BIN"
    die "Cannot proceed."
fi
[[ -s "$RESULT_BIN" ]] || die "Result file is empty."
success "Encrypted result: $RESULT_BIN ($(stat -c%s "$RESULT_BIN") bytes)"

# -------- 2. Download Acme's partial decrypt --------
info "Downloading Acme's partial decrypt..."
HTTP_CODE="$(curl -sS -w '%{http_code}' -o "$OWNER_PARTIAL_BIN" \
    -H "x-api-key: $JULENNY_API_KEY" \
    "$JULENNY_API_BASE/api/executions/$EXEC_ID/partial")"

if [[ "$HTTP_CODE" != "200" ]]; then
    err "Platform returned HTTP $HTTP_CODE when downloading the partial."
    cat "$OWNER_PARTIAL_BIN" >&2 || true
    rm -f "$OWNER_PARTIAL_BIN"
    die "Acme may not have released yet. Ask them to run 05-release.sh."
fi
[[ -s "$OWNER_PARTIAL_BIN" ]] || die "Partial is empty."
success "Acme's partial: $OWNER_PARTIAL_BIN ($(stat -c%s "$OWNER_PARTIAL_BIN") bytes)"

# -------- 3. Produce Beta's own partial decrypt locally (non-lead) --------
info "Producing Beta's local partial decryption..."
julenny-fhe crypto partial-decrypt \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --input "$RESULT_BIN" \
    --secret-key "$MY_SHARE_SECRET" \
    --output "$MY_PARTIAL_BIN" \
    > /dev/null
success "Beta's partial: $MY_PARTIAL_BIN"

# -------- 4. Combine and reveal plaintext --------
# Branching is driven by the function-def's output.layout, NOT by whether
# combine reports the result is "uniform":
#   - output.layout = "scalar"            -> count-style answer; print it.
#   - output.layout = "packed-int-vector" -> itemized indicator vector;
#     resolve non-zero slot positions back to record names via Beta's CSV.
# The "uniform" detection in `crypto combine` triggers on any constant-value
# vector (e.g. all-ones indicator with 1 match), so trusting it would
# misrender itemized output as a single count.
FUNCTION_DEF="$JL_WORKDIR/function-def.json"
OUTPUT_LAYOUT="scalar"
if [[ -f "$FUNCTION_DEF" ]]; then
    OUTPUT_LAYOUT="$(jq -r '.output.layout // "scalar"' "$FUNCTION_DEF")"
fi

step "Decrypting the answer (combining both partials)..."
COMBINE_JSON="$(julenny-fhe crypto combine \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --partials "$OWNER_PARTIAL_BIN" "$MY_PARTIAL_BIN" \
    --non-zero --json)"

NON_ZERO="$(   echo "$COMBINE_JSON" | jq -r '.nonZeroSlots')"
TOTAL_SLOTS="$(echo "$COMBINE_JSON" | jq -r '.totalSlots')"
info "Combined plaintext: $NON_ZERO non-zero slot(s) out of $TOTAL_SLOTS."
info "Function output layout: $OUTPUT_LAYOUT"

case "$OUTPUT_LAYOUT" in
    scalar)
        # Count-style aggregate. The combine command's uniform-detection
        # collapses the replicated slots into .answer; use it.
        ANSWER="$(echo "$COMBINE_JSON" | jq -r '.answer // empty')"
        echo
        if [[ -n "$ANSWER" ]]; then
            success "Answer: $ANSWER"
        else
            warn "Output is declared 'scalar' but combine didn't report a uniform answer."
            warn "Raw non-zero slot positions and values:"
            echo "$COMBINE_JSON" | jq -r '.nonZeroValues | to_entries[] | "    [\(.key)] = \(.value)"'
        fi
        ;;

    packed-int-vector|indicator-hash)
        # Itemized indicator vector. Non-zero slot positions identify the
        # hash buckets where both parties had a record. Re-hash Beta's local
        # CSV to recover the actual record strings.
        #
        # CRITICAL: the CSV we resolve against MUST be the exact CSV that
        # was encrypted to produce Beta's dataset for THIS execution. Using
        # any other CSV (e.g. the most recently configured JULENNY_INPUT_CSV)
        # silently produces wrong results - records won't be found if the
        # dataset came from a different file.
        #
        # We look up the dataset->CSV map that 04-encrypt populates on
        # upload. For pre-existing datasets uploaded before the map was
        # introduced, we prompt the operator rather than guessing.
        INPUT_NAME="${JULENNY_INPUT_NAME:-dataset_b}"

        if (( NON_ZERO == 0 )); then
            echo
            success "Answer: 0 matches.  (No slots overlapped; the two datasets are disjoint.)"
        elif [[ ! -f "$FUNCTION_DEF" ]]; then
            warn "No function-def at $FUNCTION_DEF; cannot resolve indicator slots."
            echo "$COMBINE_JSON" | jq -r '.nonZeroValues | to_entries[] | "    [\(.key)] = \(.value)"'
        else
            # 1. Identify Beta's dataset ID in this execution.
            EXEC_DOC="$(curl_jl GET "/api/executions/$EXEC_ID")"
            EXEC_INPUT_IDS="$(echo "$EXEC_DOC" | jq -r '.inputDatasetIds[]? // empty')"
            if [[ -z "$EXEC_INPUT_IDS" ]]; then
                warn "Execution $EXEC_ID has no inputDatasetIds; cannot identify Beta's dataset."
            fi
            MY_DATASETS_JSON="$(my_datasets_in_project)"
            MY_DSET_ID=""
            MY_DSET_NAME=""
            while IFS= read -r id; do
                [[ -z "$id" ]] && continue
                if echo "$MY_DATASETS_JSON" | jq -e --arg id "$id" '.[] | select(.id == $id)' > /dev/null; then
                    MY_DSET_ID="$id"
                    MY_DSET_NAME="$(echo "$MY_DATASETS_JSON" | jq -r --arg id "$id" '.[] | select(.id == $id) | .name')"
                    break
                fi
            done <<< "$EXEC_INPUT_IDS"

            # 2. Look up the originating CSV.
            CSV_MAP_FILE="$JL_WORKDIR/dataset_csv_map.json"
            INPUT_CSV=""
            if [[ -n "$MY_DSET_ID" && -f "$CSV_MAP_FILE" ]]; then
                INPUT_CSV="$(jq -r --arg id "$MY_DSET_ID" '.[$id] // empty' "$CSV_MAP_FILE")"
            fi

            if [[ -n "$MY_DSET_ID" ]]; then
                info "Beta's dataset for this execution: '$MY_DSET_NAME' ($MY_DSET_ID)"
            fi

            # 3. Validate or prompt.
            if [[ -n "$INPUT_CSV" && -f "$INPUT_CSV" ]]; then
                info "Originating CSV (from dataset map): $INPUT_CSV"
            else
                if [[ -n "$INPUT_CSV" ]]; then
                    warn "Map says the CSV was $INPUT_CSV but that file no longer exists."
                elif [[ -n "$MY_DSET_ID" ]]; then
                    warn "No CSV mapping for dataset $MY_DSET_ID (uploaded before the map existed,"
                    warn "  or the workdir was reset). The CSV you provide MUST be the EXACT one"
                    warn "  that was encrypted to create this dataset, otherwise resolve will"
                    warn "  silently report no matches."
                fi
                prompt_for INPUT_CSV "Path to the originating CSV for dataset '${MY_DSET_NAME:-?}'" "${JULENNY_INPUT_CSV:-}"
                [[ -f "$INPUT_CSV" ]] || die "CSV not found: $INPUT_CSV"

                # Persist the mapping so future runs (and the next
                # 04-encrypt picker) don't re-prompt for this dataset.
                if [[ -n "$MY_DSET_ID" ]]; then
                    EXISTING_MAP='{}'
                    [[ -f "$CSV_MAP_FILE" ]] && EXISTING_MAP="$(cat "$CSV_MAP_FILE")"
                    echo "$EXISTING_MAP" \
                        | jq --arg id "$MY_DSET_ID" --arg p "$INPUT_CSV" '. + {($id): $p}' \
                        > "$CSV_MAP_FILE.tmp" \
                        && mv "$CSV_MAP_FILE.tmp" "$CSV_MAP_FILE"
                    info "Mapped dataset $MY_DSET_ID -> $INPUT_CSV in $CSV_MAP_FILE."
                fi
            fi

            SLOTS_CSV="$(echo "$COMBINE_JSON" | jq -r '.nonZeroValues | keys | join(",")')"
            echo
            step "Resolving $NON_ZERO non-zero slot(s) against $INPUT_CSV..."
            julenny-fhe crypto resolve-indicator \
                --slots "$SLOTS_CSV" \
                --input "$INPUT_CSV" \
                --function-def "$FUNCTION_DEF" \
                --input-name "$INPUT_NAME"
        fi
        ;;

    *)
        warn "Unknown output.layout '$OUTPUT_LAYOUT'. Showing raw combine output."
        echo "$COMBINE_JSON" | jq .
        ;;
esac

echo
success "Decryption complete. The plaintext answer is shown above."
echo
info "If the answer is what you expected: keysetup, encryption, computation, and decryption all worked end-to-end."

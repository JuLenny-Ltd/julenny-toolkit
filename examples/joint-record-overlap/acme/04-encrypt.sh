#!/usr/bin/env bash
# Acme: pick a dataset for each dataOwner input the function-def declares.
#
# For every input in the function-def whose role is "dataOwner" (i.e.
# Acme's responsibility on this permission), this script:
#   1. Lists existing Acme datasets already in the project.
#   2. Prompts the operator to either (a) pick one of them, or (b) upload a
#      freshly encrypted CSV to add a new one.
#   3. Records the chosen dataset ID under the input's name in
#      $JL_WORKDIR/my_dataset_picks.json.
#
# Acme's picks file is local to Acme's machine. Beta's 05-run-query reads
# its own picks for queryAnalyst inputs and queries the platform for Acme's
# dataset candidates, prompting at trigger time. (Cross-machine sharing of
# the "currently selected" dataset would need a platform endpoint; not in
# scope for the demo.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"
load_session

MY_ROLE="dataOwner"
PICK_FILE="$JL_WORKDIR/my_dataset_picks.json"
FUNCTION_DEF="$JL_WORKDIR/function-def.json"

step "Acme: pick datasets for $MY_ROLE inputs"

[[ -f "$FUNCTION_DEF" ]] \
    || die "Function-def not found at $FUNCTION_DEF. Re-run ./00-init.sh."

# Filter function-def inputs to just the ones Acme is responsible for.
MY_INPUTS_JSON="$(jq --arg r "$MY_ROLE" '[.inputs[]? | select(.role == $r)]' "$FUNCTION_DEF")"
MY_INPUT_COUNT="$(echo "$MY_INPUTS_JSON" | jq 'length')"
if (( MY_INPUT_COUNT == 0 )); then
    info "Function declares no $MY_ROLE inputs. Nothing for Acme to upload."
    exit 0
fi

info "Function requires $MY_INPUT_COUNT $MY_ROLE input(s) from Acme."

# -------- Fetch the joint public key once (reused across encrypts) --------
JOINT_PK=""
for candidate in "$JL_KEYS_DIR/joint_public_key.bin" "$JL_PEER_DIR/joint-pk.bin"; do
    if [[ -f "$candidate" ]]; then JOINT_PK="$candidate"; break; fi
done
if [[ -z "$JOINT_PK" ]]; then
    info "Fetching joint public key from platform..."
    JOINT_KEY_ID="$(curl_jl GET "/api/fhe-permissions?status=active" \
        | jq -r --arg id "$JULENNY_PERMISSION_ID" '.permissions[] | select(.id == $id) | .jointKeyId')"
    [[ -n "$JOINT_KEY_ID" && "$JOINT_KEY_ID" != "null" ]] \
        || die "Permission has no jointKeyId. Keysetup may not be complete."
    JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"
    curl_jl GET "/api/fhe-joint-keys/$JOINT_KEY_ID/public-key" -o "$JOINT_PK"
    success "Joint pk downloaded -> $JOINT_PK"
fi

# -------- Per-input loop --------
PICKS_JSON='{}'
mkdir -p "$JL_WORKDIR"

for ((i = 0; i < MY_INPUT_COUNT; i++)); do
    INPUT_NAME="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].name")"

    echo
    echo "============================================================"
    echo " INPUT $((i + 1)) / $MY_INPUT_COUNT : '$INPUT_NAME' (role: $MY_ROLE)"
    echo "============================================================"

    # Re-fetch existing every iteration: if a previous iteration uploaded
    # a new dataset, it's in the pool now and pickable for subsequent inputs.
    EXISTING="$(my_datasets_in_project)"
    EXISTING_COUNT="$(echo "$EXISTING" | jq 'length')"

    PICKED_ID=""
    if (( EXISTING_COUNT > 0 )); then
        info "Existing Acme dataset(s) in this project:"
        echo "$EXISTING" \
            | jq -r 'to_entries[] | "  \(.key + 1)) \(.value.name)  (id: \(.value.id), uploaded \((.value.createdAt // "?") | .[0:10]))"'
        echo "  u) Upload a NEW dataset (encrypt a fresh CSV and add it to the pool)"
        echo

        # With --new-test, default to upload-new. Otherwise default to
        # newest existing (option 1), matching prior auto-pick behaviour.
        if [[ "${JULENNY_NEW_TEST:-0}" == "1" ]]; then
            DEFAULT_PICK="u"
        else
            DEFAULT_PICK="1"
        fi
        prompt_for CHOICE "Pick for '$INPUT_NAME' (1-$EXISTING_COUNT, or u)" "$DEFAULT_PICK"

        if [[ "${CHOICE,,}" != "u" ]]; then
            if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || (( CHOICE < 1 || CHOICE > EXISTING_COUNT )); then
                die "Invalid choice: '$CHOICE' (must be 1-$EXISTING_COUNT or 'u')"
            fi
            PICKED_ID="$(echo "$EXISTING"   | jq -r ".[$((CHOICE - 1))].id")"
            PICKED_NAME="$(echo "$EXISTING" | jq -r ".[$((CHOICE - 1))].name")"
            success "Selected existing '$PICKED_NAME' ($PICKED_ID) for '$INPUT_NAME'."
        fi
    fi

    # Upload-new path (either chosen explicitly or forced because pool is empty).
    if [[ -z "$PICKED_ID" ]]; then
        INPUT_CSV="${JULENNY_INPUT_CSV:-$HOME/data.csv}"
        prompt_for INPUT_CSV "Path to Acme's CSV for input '$INPUT_NAME'" "$INPUT_CSV"
        [[ -f "$INPUT_CSV" ]] || die "Input CSV not found: $INPUT_CSV"

        # Persist for default-next-time.
        if [[ "$INPUT_CSV" != "${JULENNY_INPUT_CSV:-}" ]]; then
            echo "JULENNY_INPUT_CSV=\"$INPUT_CSV\"" >> "$JL_CONFIG"
        fi

        echo
        echo "============================================================"
        echo " ENCRYPTING FILE FOR '$INPUT_NAME': $INPUT_CSV"
        echo "    $(wc -l < "$INPUT_CSV") lines, $(stat -c%s "$INPUT_CSV") bytes"
        echo "============================================================"

        CIPHERTEXT="$JL_KEYS_DIR/$(basename "$INPUT_CSV").$INPUT_NAME.enc.bin"
        julenny-fhe crypto encrypt \
            --input "$INPUT_CSV" \
            --joint-public-key "$JOINT_PK" \
            --output "$CIPHERTEXT" \
            --function-def "$FUNCTION_DEF" \
            --input-name "$INPUT_NAME" \
            > /dev/null
        success "Encrypted: $CIPHERTEXT ($(stat -c%s "$CIPHERTEXT") bytes)"

        prompt_for DATASET_NAME "Display name for the uploaded dataset" \
                   "Acme $INPUT_NAME ($(date +%Y-%m-%d))"

        info "Uploading to /api/fhe-data-upload..."
        UPLOAD_RESP="$(curl -sS -X POST \
            -H "x-api-key: $JULENNY_API_KEY" \
            -F "file=@$CIPHERTEXT" \
            -F "name=$DATASET_NAME" \
            "$JULENNY_API_BASE/api/fhe-data-upload?permissionId=$JULENNY_PERMISSION_ID")"

        if echo "$UPLOAD_RESP" | jq -e '.error' > /dev/null 2>&1; then
            err "Dataset upload failed:"
            echo "$UPLOAD_RESP" | jq . >&2
            die "Cannot proceed."
        fi

        PICKED_ID="$(echo "$UPLOAD_RESP" | jq -r '.datasetId // empty')"
        [[ -n "$PICKED_ID" ]] || die "Upload succeeded but no datasetId returned: $UPLOAD_RESP"
        success "Uploaded as '$DATASET_NAME' ($PICKED_ID)."
    fi

    # Declare the pick on the platform so Beta's 05-run-query can read it
    # without re-prompting. The platform's /execute endpoint resolves
    # inputDatasetIds from these declarations when the request body omits
    # them. Authz: caller must own the dataset and match the input's role.
    info "Declaring '$INPUT_NAME' = $PICKED_ID on the platform..."
    DECLARE_RESP="$(curl_jl PUT "/api/fhe-permissions/$JULENNY_PERMISSION_ID/preferred-datasets/$INPUT_NAME" \
        -H "Content-Type: application/json" \
        --data-binary "$(jq -n --arg id "$PICKED_ID" '{datasetId: $id}')")"
    if echo "$DECLARE_RESP" | jq -e '.error' > /dev/null 2>&1; then
        err "Declaration failed for input '$INPUT_NAME':"
        echo "$DECLARE_RESP" | jq . >&2
        die "Cannot proceed."
    fi
    success "Platform now knows: $INPUT_NAME -> $PICKED_ID."

    # Record the pick locally too (matches Beta's structure; not consumed
    # by Acme directly, but useful as a paper trail).
    PICKS_JSON="$(echo "$PICKS_JSON" | jq --arg n "$INPUT_NAME" --arg id "$PICKED_ID" '. + {($n): $id}')"
done

echo "$PICKS_JSON" > "$PICK_FILE"
echo
success "Acme's dataset picks for this execution:"
echo "$PICKS_JSON" | jq .
info "Saved to $PICK_FILE (local to Acme's machine)."

echo
info "Next step:"
echo "  Once Beta has also run their 04-encrypt and triggers, you'll run:"
echo "    $SCRIPT_DIR/05-release.sh"
echo "  (Beta's 05-run-query will list Acme's available datasets and prompt"
echo "   at trigger time, since it can't read this picks file across machines.)"

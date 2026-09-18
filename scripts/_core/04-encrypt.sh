#!/usr/bin/env bash
# Pick a dataset for each function-def input THIS side is responsible for. Both sides
# run it, and both do the same work.
#
# Which inputs those are comes from the DATA role: the function definition labels each
# input dataOwner or queryAnalyst. This is one of only two phases that reads the data
# role rather than the keysetup role, because it is about whose data goes in, not about
# who holds which half of the key.
#
# Each input branches on inputs[i].encoding:
#   - If it starts with "plaintext-" (for example rule-based-cross-match's
#     left_dictionary, right_dictionary and rule_pairs), the raw file is
#     uploaded via upload_plaintext_dataset (multipart POST with the
#     kind=plaintext flag). No `julenny-toolkit crypto encrypt` pass.
#   - Plaintext inputs also skip the dataset_csv_map.json bookkeeping, because
#     06-end-of-cycle's resolve-indicator only applies to encrypted indicator
#     outputs, not plaintext attachments.
#
# Which inputs are plaintext is entirely function-def driven, so this branch is
# what lets one script serve every scenario.
#
# There were two copies of this until 2026-09-18, one per side. They had drifted: the
# owner's lacked the signed-URL path for uploads over the inline cap, the picker that
# re-prompts instead of aborting on a bad entry, the CSV map for a reused dataset, and
# the plaintext sidecar that phase 4.5 cross-checks rotation indices against. This is
# the consumer's copy, which had all four.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# lib.sh resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_session

MY_ROLE="$(my_function_input_role)"
PICK_FILE="$JL_WORKDIR/my_dataset_picks.json"
FUNCTION_DEF="$JL_WORKDIR/function-def.json"

step "${JL_OUR_LABEL}: pick datasets for $MY_ROLE inputs"

[[ -f "$FUNCTION_DEF" ]] \
    || die "Function-def not found at $FUNCTION_DEF. Re-run ./00-init.sh."

MY_INPUTS_JSON="$(jq --arg r "$MY_ROLE" '[.inputs[]? | select(.role == $r)]' "$FUNCTION_DEF")"
MY_INPUT_COUNT="$(echo "$MY_INPUTS_JSON" | jq 'length')"
if (( MY_INPUT_COUNT == 0 )); then
    info "Function declares no $MY_ROLE inputs. Nothing for ${JL_OUR_LABEL} to upload."
    exit 0
fi

info "Function requires $MY_INPUT_COUNT $MY_ROLE input(s) from ${JL_OUR_LABEL}."

# -------- Fetch the joint public key. Needed for ciphertext inputs AND for
# encrypted-bundle inputs: the bundle is encrypted under the joint key after the
# encodingRecipe executor structures the domain file client-side. --------
JOINT_PK=""
NEEDS_JOINT_PK=false
for ((i = 0; i < MY_INPUT_COUNT; i++)); do
    ENC="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].encoding // \"\"")"
    LAY="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].layout // \"\"")"
    if [[ "$ENC" != plaintext-* || "$LAY" == "encrypted-bundle" ]]; then
        NEEDS_JOINT_PK=true
        break
    fi
done

if $NEEDS_JOINT_PK; then
    for candidate in "$JL_KEYS_DIR/joint_public_key.bin" "$JL_PEER_DIR/joint-pk.bin"; do
        if [[ -f "$candidate" ]]; then JOINT_PK="$candidate"; break; fi
    done
    if [[ -z "$JOINT_PK" ]]; then
        info "Fetching joint public key from platform..."
        JOINT_KEY_ID="${JULENNY_JOINT_KEY_ID:-}"
        [[ -n "$JOINT_KEY_ID" && "$JOINT_KEY_ID" != "null" ]] \
            || die "config.env has no JULENNY_JOINT_KEY_ID; re-run 00-init."
        JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"
        curl_jl GET "/api/fhe-joint-keys/$JOINT_KEY_ID/public-key" -o "$JOINT_PK"
        success "Joint pk downloaded -> $JOINT_PK"
    fi
fi

# -------- Per-input loop --------
PICKS_JSON='{}'
mkdir -p "$JL_WORKDIR"

for ((i = 0; i < MY_INPUT_COUNT; i++)); do
    INPUT_NAME="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].name")"
    INPUT_ENC="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].encoding // \"\"")"
    # The hashing choice lives in `schema`, NOT `encoding`. They are different fields with
    # different vocabularies: the overlap family is encoding "integer-packed" and schema
    # "indicator-hash". Gating the column question on `encoding` compared a schema name
    # against an encoding name, so it matched nothing and the question was never asked.
    INPUT_SCHEMA="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].schema // \"\"")"
    IS_PLAINTEXT=false
    [[ "$INPUT_ENC" == plaintext-* ]] && IS_PLAINTEXT=true
    # encrypted-bundle: structured client-side by the encodingRecipe executor,
    # then encrypted (NOT a raw plaintext passthrough, NOT a flat ciphertext).
    INPUT_LAYOUT="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].layout // \"\"")"
    IS_BUNDLE=false
    [[ "$INPUT_LAYOUT" == "encrypted-bundle" ]] && IS_BUNDLE=true

    echo
    echo "============================================================"
    if $IS_BUNDLE; then
        echo " INPUT $((i + 1)) / $MY_INPUT_COUNT : '$INPUT_NAME' (encrypted bundle via recipe, role: $MY_ROLE)"
    elif $IS_PLAINTEXT; then
        echo " INPUT $((i + 1)) / $MY_INPUT_COUNT : '$INPUT_NAME' (PLAINTEXT, role: $MY_ROLE)"
    else
        echo " INPUT $((i + 1)) / $MY_INPUT_COUNT : '$INPUT_NAME' (ciphertext, role: $MY_ROLE)"
    fi
    echo "============================================================"

    EXISTING="$(my_datasets_in_project "$JULENNY_PERMISSION_ID" "$INPUT_NAME")"
    EXISTING_COUNT="$(echo "$EXISTING" | jq 'length')"

    PICKED_ID=""
    if (( EXISTING_COUNT > 0 )); then
        info "Existing ${JL_OUR_LABEL} dataset(s) in this project:"
        echo "$EXISTING" \
            | jq -r 'to_entries[] | "  \(.key + 1)) \(.value.name)  (id: \(.value.id), uploaded \((.value.createdAt // "?") | .[0:10]))"'
        echo "  u) Upload a NEW dataset"
        echo

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

            # Track originating CSV ONLY for ciphertext indicator inputs.
            # Plaintext attachments don't go through resolve-indicator at
            # decrypt time, so there's no map to maintain for them.
            if ! $IS_PLAINTEXT; then
                # Both maps live at the ROOT of the working folder, shared with the
                # connector. This branch used to write the CSV map into the per-collaboration
                # folder instead, so a dataset reused here was invisible to every other
                # surface and to any other collaboration.
                CSV_MAP_FILE="$JL_ROOT/dataset_csv_map.json"
                MAPPED_CSV=""
                [[ -f "$CSV_MAP_FILE" ]] \
                    && MAPPED_CSV="$(jq -r --arg id "$PICKED_ID" '.[$id] // empty' "$CSV_MAP_FILE")"

                if [[ -n "$MAPPED_CSV" && -f "$MAPPED_CSV" ]]; then
                    info "Originating CSV (from map): $MAPPED_CSV"
                else
                    if [[ -n "$MAPPED_CSV" ]]; then
                        warn "Map says CSV is $MAPPED_CSV but that file no longer exists."
                    else
                        info "No CSV mapping yet for this dataset. Supplying one now lets"
                        info "06-end-of-cycle resolve indicator-hash output back to record names."
                    fi
                    prompt_for CSV_FOR_DSET "Originating CSV for '$PICKED_NAME' (blank to skip)" "${JULENNY_INPUT_CSV:-}"
                    if [[ -n "$CSV_FOR_DSET" ]]; then
                        [[ -f "$CSV_FOR_DSET" ]] || die "CSV not found: $CSV_FOR_DSET"
                        remember_dataset_csv "$PICKED_ID" "$CSV_FOR_DSET"
                    else
                        warn "Skipped CSV mapping. 06-end-of-cycle will re-prompt for this dataset."
                    fi
                fi

                # The column choice belongs to the DATASET, decided when it was encrypted.
                # Reusing a dataset must not ask again - answering differently here would
                # describe bytes that were hashed another way. But a dataset encrypted on
                # another machine has no record on this one, and resolve would then have
                # nothing to go on, so ask exactly once and only then.
                if [[ "$INPUT_SCHEMA" == "indicator-hash" ]]; then
                    RECALLED="$(recall_column_choice "$PICKED_ID")"
                    if [[ -n "$RECALLED" ]]; then
                        info "Columns recorded for this dataset at encrypt time: $RECALLED"
                    else
                        warn "Nothing is recorded about which columns this dataset was hashed on."
                        warn "  It was encrypted on another machine, or by another tool."
                        warn "  Answer with the SAME columns that were used then, or nothing will match."
                        REUSE_COLS="$(ask_column_choice "$INPUT_NAME")"
                        remember_column_choice "$PICKED_ID" "${REUSE_COLS:-all}"
                    fi
                fi
            fi
        fi
    fi

    if [[ -z "$PICKED_ID" ]]; then
        # Pick a local file for this input: list this scenario's sample files for
        # THIS side for one-key selection, with 'o) Other' for a free-text path. The
        # picker runs PER INPUT so the operator can map each function-def input to its
        # matching file (e.g. right_dictionary -> all_ingredients.txt).
        DATA_DIR="$(jl_data_dir)"
        DATA_FILES=()
        if [[ -n "$DATA_DIR" && -d "$DATA_DIR" ]]; then
            while IFS= read -r f; do DATA_FILES+=("$f"); done \
                < <(find "$DATA_DIR" -maxdepth 1 -type f | sort)
        fi
        DATA_COUNT=${#DATA_FILES[@]}

        echo
        if (( DATA_COUNT > 0 )); then
            info "Files available in $DATA_DIR:"
            for ((j = 0; j < DATA_COUNT; j++)); do
                printf "  [%d] %s\n" "$((j + 1))" "$(basename "${DATA_FILES[j]}")"
            done
        elif [[ -n "$DATA_DIR" ]]; then
            info "No sample files under $DATA_DIR."
        fi
        echo "  o) Other (type a path)"
        echo

        # Forgiving picker: re-prompt on a bad entry instead of aborting.
        INPUT_FILE=""
        while true; do
            if (( DATA_COUNT == 0 )); then
                DATA_CHOICE="o"
                info "No sample files to choose from; type a path instead."
            else
                prompt_for DATA_CHOICE "Pick file for input '$INPUT_NAME' (1-$DATA_COUNT, or o)" "1"
            fi

            if [[ "${DATA_CHOICE,,}" == "o" ]]; then
                if $IS_PLAINTEXT; then
                    prompt_for INPUT_FILE "Path to ${JL_OUR_LABEL}'s plaintext file for input '$INPUT_NAME'" "$HOME/$INPUT_NAME.txt"
                else
                    prompt_for INPUT_FILE "Path to ${JL_OUR_LABEL}'s CSV for input '$INPUT_NAME'" "${JULENNY_INPUT_CSV:-$HOME/data.csv}"
                fi
                if [[ -f "$INPUT_FILE" ]]; then break; fi
                warn "File not found: '$INPUT_FILE' - please try again."
            elif [[ "$DATA_CHOICE" =~ ^[0-9]+$ ]] && (( DATA_CHOICE >= 1 && DATA_CHOICE <= DATA_COUNT )); then
                INPUT_FILE="${DATA_FILES[$((DATA_CHOICE - 1))]}"
                success "Selected for '$INPUT_NAME': $INPUT_FILE"
                break
            else
                warn "Invalid choice: '$DATA_CHOICE' - enter a number 1-$DATA_COUNT, or 'o' to type a path."
            fi
        done
        [[ -f "$INPUT_FILE" ]] || die "Input file not found: $INPUT_FILE"

        # Persist JULENNY_INPUT_CSV only when it's the canonical CSV input;
        # for plaintext attachments the path isn't useful as a default.
        if ! $IS_PLAINTEXT && [[ "$INPUT_FILE" != "${JULENNY_INPUT_CSV:-}" ]]; then
            echo "JULENNY_INPUT_CSV=\"$INPUT_FILE\"" >> "$JL_CONFIG"
        fi

        # Name the source file, not just the input and the date. The old default was
        # "<side> <input> (<date>)", so every upload for the same input on the same day
        # collided and the picker showed several identically-named datasets with no way
        # to tell which file each held. The default is what people actually accept.
        prompt_for DATASET_NAME "Display name for the uploaded dataset" \
                   "${JL_OUR_LABEL} $INPUT_NAME $(basename "$INPUT_FILE") ($(date +%Y-%m-%d))"

        if $IS_BUNDLE; then
            # encrypted-bundle: run the function-def's encodingRecipe (cleartext,
            # via the recipe executor) to structure the domain file into a generic
            # bundle-input, then encrypt that under the joint key, then upload the
            # opaque bundle (kind=ciphertext; encrypted under the joint key, stored opaquely).
            [[ -n "$JOINT_PK" ]] || die "encrypted-bundle input needs the joint public key, but none was fetched."
            command -v node >/dev/null 2>&1 || die "node is required to run the encodingRecipe executor (scripts/_core/recipe/recipe-encode.mjs)."
            echo
            echo "============================================================"
            echo " ENCODING + ENCRYPTING BUNDLE FOR '$INPUT_NAME': $INPUT_FILE"
            echo "    recipe (cleartext) -> bundle-input -> encrypt under joint key"
            echo "============================================================"

            BUNDLE_INPUT="$JL_KEYS_DIR/$(basename "$INPUT_FILE").$INPUT_NAME.bundle-input.json"
            node "$SCRIPT_DIR/recipe/recipe-encode.mjs" \
                "$FUNCTION_DEF" "$INPUT_NAME" "$INPUT_FILE" "$BUNDLE_INPUT" \
                || die "recipe executor failed for '$INPUT_NAME'."

            MODEL_BUNDLE="$JL_KEYS_DIR/$(basename "$INPUT_FILE").$INPUT_NAME.bundle.bin"
            julenny-toolkit crypto encrypt \
                --function-def "$FUNCTION_DEF" \
                --input-name "$INPUT_NAME" \
                --input "$BUNDLE_INPUT" \
                --joint-public-key "$JOINT_PK" \
                --output "$MODEL_BUNDLE" \
                > /dev/null
            success "Encrypted bundle: $MODEL_BUNDLE ($(stat -c%s "$MODEL_BUNDLE") bytes)"

            PICKED_ID="$(upload_plaintext_dataset "$MODEL_BUNDLE" "$DATASET_NAME" "ciphertext" "$INPUT_NAME")" \
                || die "Bundle upload failed."
            success "Uploaded encrypted bundle '$DATASET_NAME' ($PICKED_ID)."

        elif $IS_PLAINTEXT; then
            echo
            echo "============================================================"
            echo " UPLOADING PLAINTEXT FILE FOR '$INPUT_NAME': $INPUT_FILE"
            echo "    encoding=$INPUT_ENC, $(stat -c%s "$INPUT_FILE") bytes"
            echo "============================================================"
            PICKED_ID="$(upload_plaintext_dataset "$INPUT_FILE" "$DATASET_NAME" "plaintext" "$INPUT_NAME")" \
                || die "Plaintext upload failed."
            success "Uploaded plaintext '$DATASET_NAME' ($PICKED_ID)."

            # Record local plaintext path for 04.5's rotation-index verification.
            # Maps INPUT_NAME -> local file path; 04.5 reads this and calls
            # `julenny-toolkit crypto derive-rotation-indices` to cross-check against
            # the platform-derived index set in pendingRotationKeySetup.indices.
            # We also record the dataset id so 04.5 can verify the platform's
            # derivedFromDatasetIds actually contains the datasets WE uploaded.
            PT_SIDECAR="$JL_WORKDIR/my_plaintext_paths.json"
            EXISTING_PT='{}'
            [[ -f "$PT_SIDECAR" ]] && EXISTING_PT="$(cat "$PT_SIDECAR")"
            echo "$EXISTING_PT" \
                | jq --arg n "$INPUT_NAME" --arg p "$INPUT_FILE" --arg id "$PICKED_ID" \
                     '. + {($n): {path: $p, datasetId: $id}}' \
                > "$PT_SIDECAR.tmp" \
                && mv "$PT_SIDECAR.tmp" "$PT_SIDECAR"

        else
            echo
            echo "============================================================"
            echo " ENCRYPTING FILE FOR '$INPUT_NAME': $INPUT_FILE"
            echo "    encoding=$INPUT_ENC, $(wc -l < "$INPUT_FILE") lines, $(stat -c%s "$INPUT_FILE") bytes"
            echo "============================================================"

            CIPHERTEXT="$JL_KEYS_DIR/$(basename "$INPUT_FILE").$INPUT_NAME.enc.bin"
            # Hash-based inputs can match on a subset of columns. Ask once, here, and
            # remember it below: resolve must rehash exactly the same way or it matches
            # nothing and reports zero with no error at all.
            COL_CHOICE=""
            if [[ "$INPUT_SCHEMA" == "indicator-hash" ]]; then
                COL_CHOICE="$(ask_column_choice "$INPUT_NAME")"
                [[ -n "$COL_CHOICE" ]] && info "Matching on column(s): $COL_CHOICE"
            fi
            ENC_ARGS=(--input "$INPUT_FILE" --joint-public-key "$JOINT_PK"
                      --output "$CIPHERTEXT" --function-def "$FUNCTION_DEF"
                      --input-name "$INPUT_NAME")
            [[ -n "$COL_CHOICE" ]] && ENC_ARGS+=(--columns "$COL_CHOICE")
            julenny-toolkit crypto encrypt "${ENC_ARGS[@]}" > /dev/null
            success "Encrypted: $CIPHERTEXT ($(stat -c%s "$CIPHERTEXT") bytes)"

            UPLOAD_SIZE="$(stat -c%s "$CIPHERTEXT")"
            if (( UPLOAD_SIZE < JL_INLINE_THRESHOLD_BYTES )); then
                info "Uploading to /api/fhe-data-upload (single-shot, ${UPLOAD_SIZE} bytes)..."
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
            else
                # Large bundle: signed-URL flow (upload-url -> PUT to object storage -> confirm),
                # so the bytes never hit the API body cap (the 413 path). Mirrors keysetup.
                info "Uploading to object storage via signed URL (${UPLOAD_SIZE} bytes, exceeds inline cap)..."
                URL_RESP="$(curl_jl POST "/api/fhe-data-upload/upload-url" \
                    -H "Content-Type: application/json" \
                    --data-binary "$(jq -n --arg n "$DATASET_NAME" --arg p "$JULENNY_PERMISSION_ID" \
                        '{name: $n, permissionId: $p}')")"
                UP_URL="$(echo "$URL_RESP" | jq -r '.uploadUrl // empty')"
                PICKED_ID="$(echo "$URL_RESP" | jq -r '.datasetId // empty')"
                [[ -n "$UP_URL" && -n "$PICKED_ID" ]] || die "upload-url failed: $URL_RESP"
                info "  PUT-ing payload to object storage..."
                PUT_CODE="$(curl -sS -o /dev/null -w '%{http_code}' \
                    -X PUT "$UP_URL" \
                    -H "Content-Type: application/octet-stream" \
                    --data-binary "@$CIPHERTEXT")"
                [[ "$PUT_CODE" == "200" || "$PUT_CODE" == "204" ]] \
                    || die "object storage PUT returned HTTP $PUT_CODE"
                CONFIRM_RESP="$(curl_jl POST "/api/fhe-data-upload/confirm" \
                    -H "Content-Type: application/json" \
                    --data-binary "$(jq -n --arg id "$PICKED_ID" --arg n "$DATASET_NAME" \
                        --arg f "$(basename "$CIPHERTEXT")" --arg p "$JULENNY_PERMISSION_ID" \
                        '{datasetId: $id, name: $n, kind: "ciphertext", fileName: $f, permissionId: $p, retentionDays: 90}')")"
                if echo "$CONFIRM_RESP" | jq -e '.error' > /dev/null 2>&1; then
                    err "Dataset confirm failed:"
                    echo "$CONFIRM_RESP" | jq . >&2
                    die "Cannot proceed."
                fi
                PICKED_ID="$(echo "$CONFIRM_RESP" | jq -r '.datasetId // empty')"
                [[ -n "$PICKED_ID" ]] || die "Confirm succeeded but no datasetId returned: $CONFIRM_RESP"
            fi
            success "Uploaded as '$DATASET_NAME' ($PICKED_ID)."

            # Map originating CSV for this ciphertext input. Plaintext inputs
            # don't need this - 06-end-of-cycle's resolve-indicator only looks
            # up encrypted indicators, not plaintext attachments.
            remember_dataset_csv "$PICKED_ID" "$INPUT_FILE"
            remember_column_choice "$PICKED_ID" "${COL_CHOICE:-all}"
        fi
    fi

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

    PICKS_JSON="$(echo "$PICKS_JSON" | jq --arg n "$INPUT_NAME" --arg id "$PICKED_ID" '. + {($n): $id}')"
done

echo "$PICKS_JSON" > "$PICK_FILE"
echo
success "${JL_OUR_LABEL}'s dataset picks for this execution:"
echo "$PICKS_JSON" | jq .
info "Saved to $PICK_FILE; 05-run-query will pass them on the trigger."

echo
info "Next step (on this machine), once ${JL_PEER_LABEL} has also run their 04-encrypt:"
if [[ "$JULENNY_OUR_SIDE" == "data-consumer" ]]; then
    # The consumer triggers the execution; the owner waits for it and then takes its
    # part in the end-of-cycle. That split is by DATA role and does not move.
    echo "  $SCRIPT_DIR/05-run-query.sh"
    echo "  (The trigger will use the picks above; for ${JL_PEER_LABEL}'s inputs you will be"
    echo "   prompted at trigger time, since this machine cannot read their local picks.)"
else
    echo "  $SCRIPT_DIR/06-end-of-cycle.sh"
    echo "  (It waits for ${JL_PEER_LABEL} to trigger the execution, then takes this"
    echo "   machine's part in revealing the answer.)"
fi

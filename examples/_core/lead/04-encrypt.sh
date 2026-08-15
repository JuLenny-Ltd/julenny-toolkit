#!/usr/bin/env bash
# Data owner: pick a dataset for each dataOwner input the function-def declares.
#
# Iterates over the inputs whose role matches this side's responsibility
# (dataOwner), uploads each, and declares preferred-datasets.
#
# Each input branches on inputs[i].encoding: if the encoding string starts
# with "plaintext-" (e.g. plaintext-line-list, plaintext-csv), the raw file
# is uploaded via the upload_plaintext_dataset helper instead of being run
# through `julenny-fhe crypto encrypt`. Which inputs are plaintext is entirely
# function-def driven, so this branch is what lets one script serve every
# scenario.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../sides/data-owner.env
source "$SCRIPT_DIR/../sides/data-owner.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"
load_session

MY_ROLE="dataOwner"
PICK_FILE="$JL_WORKDIR/my_dataset_picks.json"
FUNCTION_DEF="$JL_WORKDIR/function-def.json"

step "Acme: pick datasets for $MY_ROLE inputs"

[[ -f "$FUNCTION_DEF" ]] \
    || die "Function-def not found at $FUNCTION_DEF. Re-run ./00-init.sh."

MY_INPUTS_JSON="$(jq --arg r "$MY_ROLE" '[.inputs[]? | select(.role == $r)]' "$FUNCTION_DEF")"
MY_INPUT_COUNT="$(echo "$MY_INPUTS_JSON" | jq 'length')"
if (( MY_INPUT_COUNT == 0 )); then
    info "Function declares no $MY_ROLE inputs. Nothing for Acme to upload."
    exit 0
fi

info "Function requires $MY_INPUT_COUNT $MY_ROLE input(s) from Acme."

# -------- Fetch the joint public key (only needed for ciphertext inputs) --------
JOINT_PK=""
HAS_CIPHERTEXT_INPUT=false
for ((i = 0; i < MY_INPUT_COUNT; i++)); do
    ENC="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].encoding // \"\"")"
    LAY="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].layout // \"\"")"
    if [[ "$ENC" != plaintext-* || "$LAY" == "encrypted-bundle" ]]; then
        HAS_CIPHERTEXT_INPUT=true
        break
    fi
done

if $HAS_CIPHERTEXT_INPUT; then
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
fi

# -------- Per-input loop --------
PICKS_JSON='{}'
mkdir -p "$JL_WORKDIR"

for ((i = 0; i < MY_INPUT_COUNT; i++)); do
    INPUT_NAME="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].name")"
    INPUT_ENC="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].encoding // \"\"")"
    INPUT_LAYOUT="$(echo "$MY_INPUTS_JSON" | jq -r ".[$i].layout // \"\"")"
    IS_BUNDLE=false
    [[ "$INPUT_LAYOUT" == "encrypted-bundle" ]] && IS_BUNDLE=true
    IS_PLAINTEXT=false
    [[ "$INPUT_ENC" == plaintext-* && "$INPUT_LAYOUT" != "encrypted-bundle" ]] && IS_PLAINTEXT=true

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

    EXISTING="$(my_datasets_in_project)"
    EXISTING_COUNT="$(echo "$EXISTING" | jq 'length')"

    PICKED_ID=""
    if (( EXISTING_COUNT > 0 )); then
        info "Existing Acme dataset(s) in this project:"
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
        fi
    fi

    if [[ -z "$PICKED_ID" ]]; then
        # Pick a local file for this input. Same shape as the picker in
        # 00-init: list files in $SCRIPT_DIR/data/ for one-key selection,
        # with 'o) Other' for a free-text path. Runs per input so the
        # operator can map each function-def input to its matching file.
        DATA_DIR="${JL_DATA_DIR:-$SCRIPT_DIR/data}"
        DATA_FILES=()
        if [[ -d "$DATA_DIR" ]]; then
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
        else
            info "No files found under $DATA_DIR."
        fi
        echo "  o) Other (type a path)"
        echo

        if (( DATA_COUNT == 0 )); then
            DATA_CHOICE="o"
            info "No files in data/; defaulting to 'o' (type a path)."
        else
            prompt_for DATA_CHOICE "Pick file for input '$INPUT_NAME' (1-$DATA_COUNT, or o)" "1"
        fi

        if [[ "${DATA_CHOICE,,}" == "o" ]]; then
            prompt_for INPUT_FILE "Path to Acme's file for input '$INPUT_NAME'" "${JULENNY_INPUT_CSV:-$HOME/data.csv}"
        else
            if ! [[ "$DATA_CHOICE" =~ ^[0-9]+$ ]] || (( DATA_CHOICE < 1 || DATA_CHOICE > DATA_COUNT )); then
                die "Invalid choice: '$DATA_CHOICE' (must be 1-$DATA_COUNT or 'o')"
            fi
            INPUT_FILE="${DATA_FILES[$((DATA_CHOICE - 1))]}"
            success "Selected for '$INPUT_NAME': $INPUT_FILE"
        fi
        [[ -f "$INPUT_FILE" ]] || die "Input file not found: $INPUT_FILE"

        if [[ "$INPUT_FILE" != "${JULENNY_INPUT_CSV:-}" ]]; then
            echo "JULENNY_INPUT_CSV=\"$INPUT_FILE\"" >> "$JL_CONFIG"
        fi

        prompt_for DATASET_NAME "Display name for the uploaded dataset" \
                   "Acme $INPUT_NAME ($(date +%Y-%m-%d))"

        if $IS_BUNDLE; then
            # ---- Encrypted-bundle path: recipe-encode -> encrypt -> upload (kind=ciphertext) ----
            [[ -n "$JOINT_PK" ]] || die "encrypted-bundle input needs the joint public key, but none was fetched."
            command -v node >/dev/null 2>&1 || die "node is required to run the encodingRecipe executor (examples/_core/recipe/recipe-encode.mjs)."
            echo
            echo "============================================================"
            echo " ENCODING + ENCRYPTING BUNDLE FOR '$INPUT_NAME': $INPUT_FILE"
            echo "    recipe (cleartext) -> bundle-input -> encrypt under joint key"
            echo "============================================================"
            BUNDLE_INPUT="$JL_KEYS_DIR/$(basename "$INPUT_FILE").$INPUT_NAME.bundle-input.json"
            node "$SCRIPT_DIR/../recipe/recipe-encode.mjs" \
                "$FUNCTION_DEF" "$INPUT_NAME" "$INPUT_FILE" "$BUNDLE_INPUT" \
                || die "recipe executor failed for '$INPUT_NAME'."
            BUNDLE_BIN="$JL_KEYS_DIR/$(basename "$INPUT_FILE").$INPUT_NAME.bundle.bin"
            julenny-fhe crypto encrypt \
                --function-def "$FUNCTION_DEF" \
                --input-name "$INPUT_NAME" \
                --input "$BUNDLE_INPUT" \
                --joint-public-key "$JOINT_PK" \
                --output "$BUNDLE_BIN" \
                > /dev/null
            success "Encrypted bundle: $BUNDLE_BIN ($(stat -c%s "$BUNDLE_BIN") bytes)"
            PICKED_ID="$(upload_plaintext_dataset "$BUNDLE_BIN" "$DATASET_NAME" "ciphertext")" \
                || die "Bundle upload failed."
            success "Uploaded encrypted bundle '$DATASET_NAME' ($PICKED_ID)."

        elif $IS_PLAINTEXT; then
            # ---- Plaintext path: upload raw, no encrypt pass ----
            echo
            echo "============================================================"
            echo " UPLOADING PLAINTEXT FILE FOR '$INPUT_NAME': $INPUT_FILE"
            echo "    encoding=$INPUT_ENC, $(stat -c%s "$INPUT_FILE") bytes"
            echo "============================================================"
            PICKED_ID="$(upload_plaintext_dataset "$INPUT_FILE" "$DATASET_NAME")" \
                || die "Plaintext upload failed."
            success "Uploaded plaintext '$DATASET_NAME' ($PICKED_ID)."

        else
            # ---- Ciphertext path: encrypt then upload ----
            echo
            echo "============================================================"
            echo " ENCRYPTING FILE FOR '$INPUT_NAME': $INPUT_FILE"
            echo "    encoding=$INPUT_ENC, $(wc -l < "$INPUT_FILE") lines, $(stat -c%s "$INPUT_FILE") bytes"
            echo "============================================================"

            CIPHERTEXT="$JL_KEYS_DIR/$(basename "$INPUT_FILE").$INPUT_NAME.enc.bin"
            julenny-fhe crypto encrypt \
                --input "$INPUT_FILE" \
                --joint-public-key "$JOINT_PK" \
                --output "$CIPHERTEXT" \
                --function-def "$FUNCTION_DEF" \
                --input-name "$INPUT_NAME" \
                > /dev/null
            success "Encrypted: $CIPHERTEXT ($(stat -c%s "$CIPHERTEXT") bytes)"

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
success "Acme's dataset picks for this execution:"
echo "$PICKS_JSON" | jq .
info "Saved to $PICK_FILE (local to Acme's machine)."

echo
info "Next step:"
echo "  Once Beta has also run their 04-encrypt and triggers, you'll run:"
echo "    $SCRIPT_DIR/05-release.sh"

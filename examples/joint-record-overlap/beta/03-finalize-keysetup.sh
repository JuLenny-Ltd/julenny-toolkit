#!/usr/bin/env bash
# Beta: finalize the joint keysetup.
#
# After both sides have completed bundles 1 and 2, this script:
#   1. Downloads Acme's relin-round2 and sum-round1 shares.
#   2. Runs the deterministic combines locally (must produce byte-identical
#      output to Acme's runs of the same combines).
#   3. SHA-256-hashes each of the three final joint keys.
#   4. Requests one signed object storage upload URL per keyType, PUTs the blob.
#   5. Builds the to-sign JSON locally (mimicking what the web UI would emit).
#   6. Calls `julenny-fhe crypto wrap-final-keys-envelope` to sign the envelope.
#   7. POSTs the signed envelope to /keysetup/final-keys.
#   8. Reports the resulting permission state.
#
# Strictly mirrors the web UI's option-B finalization flow: the toolkit binary
# is offline (combines + signing only); platform calls happen here in bash.
#
# Install location: ~/julenny-demo/beta/03-finalize-keysetup.sh
# Run after acme/02-keysetup-2.sh + beta/02-keysetup-2.sh have both finished.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"
load_session

step "Beta: finalize joint keysetup"

# -------- Idempotence marker: skip if already submitted for THIS permission --------
# 03 registers the finalKeys references against the permission's own document.
# When a new permission is created under an existing complete joint key, the
# crypto work in this script is already done (keys exist locally) but we still
# need to POST the finalKeys envelope against the new permission ID. The
# marker prevents re-submitting for the same permission.
MARKER="$JL_WORKDIR/finalkeys_submitted_$JULENNY_PERMISSION_ID"
if [[ -f "$MARKER" ]]; then
    info "Final keys already submitted for permission $JULENNY_PERMISSION_ID."
    info "(Remove $MARKER and rerun if you need to re-submit.)"
    exit 0
fi

# -------- Locate already-produced files --------
MAIN_R2="$JL_KEYS_DIR/main-relin-r2.bin"
MAIN_SUM="$JL_KEYS_DIR/main-sum-r1.bin"
COMBINED_R1="$JL_KEYS_DIR/combined-relin-r1.bin"
JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"

[[ -f "$MAIN_R2"     ]] || die "Missing $MAIN_R2. Did 02-keysetup-2.sh run?"
[[ -f "$MAIN_SUM"    ]] || die "Missing $MAIN_SUM. Did 01-keysetup-1.sh run?"
[[ -f "$COMBINED_R1" ]] || die "Missing $COMBINED_R1. Did 02-keysetup-2.sh run?"
[[ -f "$JOINT_PK"    ]] || die "Missing $JOINT_PK. Did 01-keysetup-1.sh run?"

# -------- 1. Download Acme's relin-round2 and sum-round1 --------
# Skip download if we already have them locally (idempotence: a reused-joint-
# key permission won't have a fresh peer upload for THIS permission, but the
# bytes from the original keysetup are still on disk and still correct).
LEAD_R2="$JL_PEER_DIR/lead-relin-r2.bin"
LEAD_SUM="$JL_PEER_DIR/lead-sum-r1.bin"

if [[ ! -f "$LEAD_R2" ]]; then
    info "Waiting for Acme's relin-round2 contribution..."
    wait_for_peer_share "relin-round2"
    download_peer_share "relin-round2" "$LEAD_R2"
else
    info "Reusing existing peer share: $LEAD_R2"
fi
if [[ ! -f "$LEAD_SUM" ]]; then
    download_peer_share "sum-round1" "$LEAD_SUM"
else
    info "Reusing existing peer share: $LEAD_SUM"
fi

# -------- 2. Run the two final combines (deterministic on both sides) --------
# Skip if the final key already exists locally - combines are deterministic
# so re-running just re-produces the same bytes.
FINAL_RELIN="$JL_KEYS_DIR/final_relin_key.bin"
FINAL_SUM="$JL_KEYS_DIR/final_sum_key.bin"

if [[ ! -f "$FINAL_RELIN" ]]; then
    info "Combining round-2 relin shares -> final relin key..."
    julenny-fhe crypto relin-combine \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --round 2 \
        --share-a "$LEAD_R2" \
        --share-b "$MAIN_R2" \
        --combined-r1 "$COMBINED_R1" \
        --output "$FINAL_RELIN" \
        > /dev/null
    success "Final relin key: $FINAL_RELIN ($(stat -c%s "$FINAL_RELIN") bytes)"
else
    info "Reusing existing final relin key: $FINAL_RELIN"
fi

if [[ ! -f "$FINAL_SUM" ]]; then
    info "Combining sum-round-1 shares -> final sum key..."
    julenny-fhe crypto sum-combine \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --share-a "$LEAD_SUM" \
        --share-b "$MAIN_SUM" \
        --joint-pk "$JOINT_PK" \
        --output "$FINAL_SUM" \
        > /dev/null
    success "Final sum key: $FINAL_SUM ($(stat -c%s "$FINAL_SUM") bytes)"
else
    info "Reusing existing final sum key: $FINAL_SUM"
fi

info "Joint public key: $JOINT_PK ($(stat -c%s "$JOINT_PK") bytes)"

# -------- 3. SHA-256 hashes (cross-party byte-equality check) --------
JOINT_PK_SHA="$(sha256sum "$JOINT_PK"     | awk '{print $1}')"
RELIN_SHA="$(   sha256sum "$FINAL_RELIN"  | awk '{print $1}')"
SUM_SHA="$(     sha256sum "$FINAL_SUM"    | awk '{print $1}')"

info "Hashes computed."
info "  joint_public_key: $JOINT_PK_SHA"
info "  joint_relin_key:  $RELIN_SHA"
info "  eval_sum_key:     $SUM_SHA"

# -------- 4. Request upload URLs, PUT each blob to object storage --------
request_final_key_upload_url() {
    local key_type="$1"
    local resp
    resp="$(curl_jl POST "/api/fhe-permissions/$JULENNY_PERMISSION_ID/keysetup/final-keys/upload-url" \
        -H "Content-Type: application/json" \
        --data-binary "$(jq -n --arg t "$key_type" '{keyType: $t}')")"
    local url key
    url="$(echo "$resp" | jq -r '.uploadUrl // empty')"
    key="$(echo "$resp" | jq -r '.objectKey // empty')"
    [[ -n "$url" && -n "$key" ]] \
        || die "upload-url for $key_type failed: $resp"
    echo "${url}|${key}"
}

put_blob_to_storage() {
    local url="$1"
    local path="$2"
    local code
    code="$(curl -sS -o /dev/null -w '%{http_code}' \
        -X PUT "$url" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$path")"
    [[ "$code" == "200" || "$code" == "204" ]] \
        || die "object storage PUT returned HTTP $code for $path"
}

info "Requesting upload URLs (3 keyTypes)..."
JPK_URL_AND_KEY="$(request_final_key_upload_url joint_public_key)"
JPK_URL="${JPK_URL_AND_KEY%|*}"
JPK_OBJ="${JPK_URL_AND_KEY#*|}"

REL_URL_AND_KEY="$(request_final_key_upload_url joint_relin_key)"
REL_URL="${REL_URL_AND_KEY%|*}"
REL_OBJ="${REL_URL_AND_KEY#*|}"

SUM_URL_AND_KEY="$(request_final_key_upload_url eval_sum_key)"
SUM_URL="${SUM_URL_AND_KEY%|*}"
SUM_OBJ="${SUM_URL_AND_KEY#*|}"

info "Uploading the three final keys to object storage..."
put_blob_to_storage "$JPK_URL" "$JOINT_PK"
success "  joint_public_key -> $JPK_OBJ"
put_blob_to_storage "$REL_URL" "$FINAL_RELIN"
success "  joint_relin_key  -> $REL_OBJ"
put_blob_to_storage "$SUM_URL" "$FINAL_SUM"
success "  eval_sum_key     -> $SUM_OBJ"

# -------- 5. Build to-sign JSON (mimics web UI's emitted file) --------
TO_SIGN="$JL_ENV_DIR/final-keys-to-sign.json"
SIGNED_OUT="$JL_ENV_DIR/final-keys-signed.json"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

jq -n \
    --arg from    "$JULENNY_COMPANY_ID" \
    --arg perm    "$JULENNY_PERMISSION_ID" \
    --arg ts      "$TIMESTAMP" \
    --arg sum_ok  "$SUM_OBJ"  --arg sum_sha "$SUM_SHA" \
    --arg jpk_ok  "$JPK_OBJ"  --arg jpk_sha "$JOINT_PK_SHA" \
    --arg rel_ok  "$REL_OBJ"  --arg rel_sha "$RELIN_SHA" \
    '{
        fromCompanyId: $from,
        keys: [
            {keyType: "eval_sum_key",     objectKey: $sum_ok, sha256Hex: $sum_sha},
            {keyType: "joint_public_key", objectKey: $jpk_ok, sha256Hex: $jpk_sha},
            {keyType: "joint_relin_key",  objectKey: $rel_ok, sha256Hex: $rel_sha}
        ],
        permissionId: $perm,
        timestamp: $ts
    }' > "$TO_SIGN"
success "To-sign JSON: $TO_SIGN"

# -------- 6. Sign the envelope via the offline toolkit --------
info "Signing the envelope (offline)..."
julenny-fhe crypto wrap-final-keys-envelope \
    --to-sign "$TO_SIGN" \
    --secret-key "$JULENNY_SIGNING_SECRET" \
    --output "$SIGNED_OUT" \
    > /dev/null
success "Signed envelope: $SIGNED_OUT"

# -------- 7. POST the signed envelope --------
info "POSTing signed envelope to /keysetup/final-keys..."
RESP="$(curl_jl POST "/api/fhe-permissions/$JULENNY_PERMISSION_ID/keysetup/final-keys" \
    -H "Content-Type: application/json" \
    --data-binary "@$SIGNED_OUT")"

# -------- 8. Report --------
STATE="$(echo "$RESP" | jq -r '.permissionState // .state // empty')"
MSG="$(  echo "$RESP" | jq -r '.message    // empty')"
ERR="$(  echo "$RESP" | jq -r '.error      // empty')"

echo
case "$STATE" in
    active|complete)
        success "Keysetup is COMPLETE. Permission is active."
        success "  Server: $MSG"
        touch "$MARKER"
        echo
        info "Next step (on this machine):"
        echo "  $SCRIPT_DIR/04-encrypt.sh"
        ;;
    awaiting-peer-submission|awaiting-finalization)
        info "Your submission is in. Waiting for Acme to run their finalize."
        info "  Server: $MSG"
        touch "$MARKER"
        echo
        info "Tell Acme to run:"
        echo "    cd ~/julenny-demo/acme && ./03-finalize-keysetup.sh"
        ;;
    *)
        if [[ -n "$ERR" ]]; then
            err "Submission failed: $ERR"
            echo "$RESP" | jq . >&2
            exit 1
        else
            warn "Unexpected response state: $STATE"
            echo "$RESP" | jq . >&2
        fi
        ;;
esac

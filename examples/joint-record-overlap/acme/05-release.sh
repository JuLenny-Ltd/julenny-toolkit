#!/usr/bin/env bash
# Acme (data owner): download the encrypted result, produce a partial
# decryption with Acme's FHE secret key, sign it, and release it via the
# platform's partial-decrypt endpoint.
#
# Run this AFTER Beta has run 05-run-query.sh and the execution state
# has reached 'awaiting-release'.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"
load_session

step "Acme partial-decrypt and release"

# Discover the execution awaiting release via the platform's list endpoint.
# No prompt: scripts pull from the platform, not from the operator.
# /api/fhe-permissions/{id}/executions returns executions ordered by
# triggeredAt desc, so the first one is the newest.
info "Polling for an execution awaiting release on permission $JULENNY_PERMISSION_ID..."
elapsed=0
delay=5
EXEC_ID=""
while true; do
    LIST_RESP="$(curl_jl GET \
        "/api/fhe-permissions/$JULENNY_PERMISSION_ID/executions?state=awaiting-release&limit=1")"
    EXEC_ID="$(echo "$LIST_RESP" | jq -r '.executions[0].id // empty')"
    if [[ -n "$EXEC_ID" ]]; then
        success "Found execution awaiting release: $EXEC_ID"
        break
    fi
    printf "  (no awaiting-release execution yet, %ds elapsed)\n" "$elapsed"
    sleep "$delay"
    elapsed=$(( elapsed + delay ))
    if   (( elapsed > 60 ));  then delay=15
    elif (( elapsed > 30 ));  then delay=10
    fi
    (( elapsed > 1800 )) \
        && die "Timed out after 30 min waiting for an awaiting-release execution. Did Beta run 05-run-query.sh?"
done

FHE_SECRET="$JL_KEYS_DIR/fhe_secret_key.bin"
[[ -f "$FHE_SECRET" ]] || die "Missing $FHE_SECRET. Did keysetup complete on this machine?"

RESULT_BIN="$JL_KEYS_DIR/result-$EXEC_ID.bin"
PARTIAL_BIN="$JL_KEYS_DIR/owner-partial-$EXEC_ID.bin"
SIG_BIN="$JL_KEYS_DIR/owner-partial-$EXEC_ID.sig"

# -------- 1. Download encrypted result --------
info "Downloading encrypted result from platform..."
HTTP_CODE="$(curl -sS -w '%{http_code}' -o "$RESULT_BIN" \
    -H "x-api-key: $JULENNY_API_KEY" \
    "$JULENNY_API_BASE/api/executions/$EXEC_ID/result")"

if [[ "$HTTP_CODE" != "200" ]]; then
    err "Platform returned HTTP $HTTP_CODE when downloading the result."
    cat "$RESULT_BIN" >&2 || true
    rm -f "$RESULT_BIN"
    die "Cannot proceed. Check execution state on the platform UI."
fi
[[ -s "$RESULT_BIN" ]] || die "Result file is empty."
success "Encrypted result: $RESULT_BIN ($(stat -c%s "$RESULT_BIN") bytes)"

# -------- 2. Partial-decrypt locally (Acme is the lead in the threshold pair) --------
info "Producing partial decryption (as lead)..."
julenny-fhe crypto partial-decrypt \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --input "$RESULT_BIN" \
    --secret-key "$FHE_SECRET" \
    --output "$PARTIAL_BIN" \
    --lead \
    > /dev/null
success "Partial decrypt: $PARTIAL_BIN ($(stat -c%s "$PARTIAL_BIN") bytes)"

# -------- 3. Sign the partial bytes for the x-jl-signature header --------
info "Signing the partial decrypt with Acme's registered signing key..."
julenny-fhe crypto sign \
    --input "$PARTIAL_BIN" \
    --secret-key "$JULENNY_SIGNING_SECRET" \
    --output "$SIG_BIN" \
    > /dev/null

SIG_HEX="$(xxd -p -c 256 "$SIG_BIN" | tr -d '\n')"
[[ ${#SIG_HEX} -eq 128 ]] \
    || die "Signature is ${#SIG_HEX} hex chars, expected 128."

# -------- 4. Upload via multipart formdata --------
info "Uploading partial decrypt to platform..."
RESP="$(curl -sS -X POST \
    -H "x-api-key: $JULENNY_API_KEY" \
    -H "x-jl-signature: $SIG_HEX" \
    -F "file=@$PARTIAL_BIN" \
    "$JULENNY_API_BASE/api/executions/$EXEC_ID/partial-decrypt")"

STATE="$(echo "$RESP" | jq -r '.state // empty')"
if [[ "$STATE" == "released" ]]; then
    success "Released. Execution state: $STATE."
else
    err "Upload may have failed. Response: $RESP"
    exit 1
fi

echo
info "Next step:"
echo "  Beta can now run ./06-decrypt.sh on their machine. Their script"
echo "  already has the execution ID (saved locally when they ran 05-run-query)."

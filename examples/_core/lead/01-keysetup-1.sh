#!/usr/bin/env bash
# Acme bundle 1: pk-share + relin-round1 + sum-round1.
# These three are independent of any peer input; we can produce and upload
# all of them in one sitting.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../sides/data-owner.env
source "$SCRIPT_DIR/../sides/data-owner.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"
load_session

step "Acme keysetup bundle 1: pk-share + relin-round1 + sum-round1"

FHE_SECRET="$JL_KEYS_DIR/fhe_secret_key.bin"
FHE_PUBLIC="$JL_KEYS_DIR/fhe_public_key.bin"
RELIN_R1="$JL_KEYS_DIR/lead-relin-r1.bin"
SUM_R1="$JL_KEYS_DIR/lead-sum-r1.bin"

# -------- 1. pk-share (round 1) --------
info "Generating FHE keypair (Acme's contribution)..."
julenny-toolkit crypto keysetup-contribute \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --role lead \
    --output-secret "$FHE_SECRET" \
    --output-public "$FHE_PUBLIC" \
    > /dev/null
success "FHE secret: $FHE_SECRET  (stays here, never upload)"
success "FHE public contribution: $FHE_PUBLIC"

wrap_and_upload "$FHE_PUBLIC" 1 "pk-share"

# -------- 2. relin-round1 (round 2) --------
info "Generating relinearization key round-1 contribution..."
julenny-toolkit crypto relin-contribute \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --round 1 --role lead \
    --secret-key "$FHE_SECRET" \
    --output "$RELIN_R1" \
    > /dev/null
success "Relin round-1: $RELIN_R1"

wrap_and_upload "$RELIN_R1" 2 "relin-round1"

# -------- 3. sum-round1 (round 5) -- only if the function needs a sum key --------
if function_requires_sum_keys; then
    info "Generating sum key round-1 contribution..."
    julenny-toolkit crypto sum-contribute \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --role lead \
        --secret-key "$FHE_SECRET" \
        --output "$SUM_R1" \
        > /dev/null
    success "Sum round-1: $SUM_R1"

    wrap_and_upload "$SUM_R1" 5 "sum-round1"
else
    info "Function does not require a sum key (requiredEvalKeys); skipping sum-round1."
fi

echo
success "Bundle 1 uploaded. 3 messages submitted (pk-share, relin-round1, sum-round1)."
wait_msg "Tell Beta to run on their machine:
    cd ~/julenny-demo/beta && ./01-keysetup-1.sh

When Beta's bundle 1 is uploaded, come back here and run:
    $SCRIPT_DIR/02-keysetup-2.sh"

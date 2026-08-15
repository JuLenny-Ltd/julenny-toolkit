#!/usr/bin/env bash
# Beta bundle 1: joint-pk derivation + relin-round1-continue + sum-round1-continue.
# Downloads Acme's three shares first, then chains on each.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../sides/data-consumer.env
source "$SCRIPT_DIR/../sides/data-consumer.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"
load_session

step "Beta keysetup bundle 1: joint-pk + relin-round1-continue + sum-round1-continue"

MY_SHARE_SECRET="$JL_KEYS_DIR/my_share_secret.bin"
JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"
MAIN_RELIN_R1="$JL_KEYS_DIR/main-relin-r1.bin"
MAIN_SUM_R1="$JL_KEYS_DIR/main-sum-r1.bin"

LEAD_PK_BIN="$JL_PEER_DIR/lead-pk.bin"
LEAD_RELIN_R1_BIN="$JL_PEER_DIR/lead-relin-r1.bin"
LEAD_SUM_R1_BIN="$JL_PEER_DIR/lead-sum-r1.bin"

# -------- 1. Wait for and download Acme's three shares --------
info "Fetching Acme's bundle 1 contributions..."
wait_for_peer_share "pk-share"
wait_for_peer_share "relin-round1"

download_peer_share "pk-share"      "$LEAD_PK_BIN"
download_peer_share "relin-round1"  "$LEAD_RELIN_R1_BIN"

if function_requires_sum_keys; then
    wait_for_peer_share "sum-round1"
    download_peer_share "sum-round1"    "$LEAD_SUM_R1_BIN"
fi

# -------- 2. Derive joint pk (chain on Acme's pk-share) --------
info "Deriving joint public key..."
julenny-fhe crypto keysetup-contribute \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --role main \
    --peer-share "$LEAD_PK_BIN" \
    --output-secret "$MY_SHARE_SECRET" \
    --output-public "$JOINT_PK" \
    > /dev/null
success "Beta's share secret: $MY_SHARE_SECRET  (stays here, never upload)"
success "Joint public key: $JOINT_PK"

wrap_and_upload "$JOINT_PK" 1 "pk-share"

# -------- 3. relin-round1-continue (round 3) --------
info "Generating relin round-1 continue..."
julenny-fhe crypto relin-contribute \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --round 1 --role main \
    --secret-key "$MY_SHARE_SECRET" \
    --peer-share "$LEAD_RELIN_R1_BIN" \
    --output "$MAIN_RELIN_R1" \
    > /dev/null
success "Beta relin round-1: $MAIN_RELIN_R1"

wrap_and_upload "$MAIN_RELIN_R1" 3 "relin-round1-continue"

# -------- 4. sum-round1-continue (round 6) -- only if the function needs a sum key --------
if function_requires_sum_keys; then
    info "Generating sum round-1 continue..."
    julenny-fhe crypto sum-contribute \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --role main \
        --secret-key "$MY_SHARE_SECRET" \
        --peer-share "$LEAD_SUM_R1_BIN" \
        --joint-pk "$JOINT_PK" \
        --output "$MAIN_SUM_R1" \
        > /dev/null
    success "Beta sum round-1: $MAIN_SUM_R1"

    wrap_and_upload "$MAIN_SUM_R1" 6 "sum-round1-continue"
else
    info "Function does not require a sum key (requiredEvalKeys); skipping sum-round1-continue."
fi

echo
success "Bundle 1 uploaded. 3 messages submitted."
wait_msg "Tell Acme to run on their machine:
    cd ~/julenny-demo/acme && ./02-keysetup-2.sh

When Acme's bundle 2 is uploaded, come back here and run:
    $SCRIPT_DIR/02-keysetup-2.sh"

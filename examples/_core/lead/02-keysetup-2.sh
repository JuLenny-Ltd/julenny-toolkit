#!/usr/bin/env bash
# Acme bundle 2: relin-round2.
# Combines lead's + main's round-1 relin shares (deterministic), then
# generates Acme's relin-round2 contribution.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../sides/data-owner.env
source "$SCRIPT_DIR/../sides/data-owner.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"
load_session

step "Acme keysetup bundle 2: relin-round2"

# Bundle 2 is the second relin round and nothing else. An additive-only function
# (requiredEvalKeys: []) has no relin key, so there is nothing to do and the file
# checks below would stop on intermediates that were never created.
if ! function_requires_relin_keys; then
    info "Function does not require a relinearization key; bundle 2 has nothing to do."
    info "Go straight to 03-finalize-keysetup."
    exit 0
fi

FHE_SECRET="$JL_KEYS_DIR/fhe_secret_key.bin"
RELIN_R1_LEAD="$JL_KEYS_DIR/lead-relin-r1.bin"
RELIN_R1_MAIN="$JL_PEER_DIR/main-relin-r1.bin"
JOINT_PK="$JL_PEER_DIR/joint-pk.bin"
COMBINED_R1="$JL_KEYS_DIR/combined-relin-r1.bin"
RELIN_R2="$JL_KEYS_DIR/lead-relin-r2.bin"

[[ -f "$RELIN_R1_LEAD" ]] || die "Missing $RELIN_R1_LEAD. Did 01-keysetup-1.sh run successfully?"
[[ -f "$FHE_SECRET"    ]] || die "Missing $FHE_SECRET. Did 01-keysetup-1.sh run successfully?"

# -------- 1. Wait for and download Beta's relin-round1-continue + joint-pk --------
info "Waiting for Beta to upload bundle 1..."
wait_for_peer_share "relin-round1-continue"
wait_for_peer_share "pk-share"

download_peer_share "relin-round1-continue" "$RELIN_R1_MAIN"
download_peer_share "pk-share"              "$JOINT_PK"

# -------- 2. Deterministic combine of round-1 shares --------
info "Combining round-1 relin shares (deterministic)..."
julenny-toolkit crypto relin-combine \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --round 1 \
    --share-a "$RELIN_R1_LEAD" \
    --share-b "$RELIN_R1_MAIN" \
    --joint-pk "$JOINT_PK" \
    --output "$COMBINED_R1" \
    > /dev/null
success "Combined relin-r1: $COMBINED_R1"

# -------- 3. relin-round2 (round 4) --------
info "Generating relin-round2 contribution..."
julenny-toolkit crypto relin-contribute \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --round 2 \
    --secret-key "$FHE_SECRET" \
    --combined-r1 "$COMBINED_R1" \
    --joint-pk "$JOINT_PK" \
    --output "$RELIN_R2" \
    > /dev/null
success "Acme relin-r2: $RELIN_R2"

wrap_and_upload "$RELIN_R2" 4 "relin-round2"

echo
success "Bundle 2 uploaded. Acme's bundle-2 contribution is in."
wait_msg "Tell Beta to run their side of keysetup bundle 2 on their own machine
(their run.sh / run.ps1 handles it, or the equivalent MCP verbs).

Once both sides have finished bundles 1 and 2, finalize the joint keys
(this is a manual step on both machines, not auto):
    $SCRIPT_DIR/03-finalize-keysetup.sh"

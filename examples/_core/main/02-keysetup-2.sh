#!/usr/bin/env bash
# Beta bundle 2: relin-round2.
# Combines round-1 relin shares (deterministic, must match Acme's combine),
# then produces Beta's relin-round2.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../sides/data-consumer.env
source "$SCRIPT_DIR/../sides/data-consumer.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"
load_session

step "Beta keysetup bundle 2: relin-round2"

# Bundle 2 is the second relin round and nothing else. An additive-only function
# (requiredEvalKeys: []) has no relin key, so there is nothing to do and the file
# checks below would stop on intermediates that were never created.
if ! function_requires_relin_keys; then
    info "Function does not require a relinearization key; bundle 2 has nothing to do."
    info "Go straight to 03-finalize-keysetup."
    exit 0
fi

MY_SHARE_SECRET="$JL_KEYS_DIR/my_share_secret.bin"
RELIN_R1_MAIN="$JL_KEYS_DIR/main-relin-r1.bin"
JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"
RELIN_R1_LEAD="$JL_PEER_DIR/lead-relin-r1.bin"
COMBINED_R1="$JL_KEYS_DIR/combined-relin-r1.bin"
RELIN_R2="$JL_KEYS_DIR/main-relin-r2.bin"

[[ -f "$RELIN_R1_MAIN"   ]] || die "Missing $RELIN_R1_MAIN. Did 01-keysetup-1.sh run successfully?"
[[ -f "$MY_SHARE_SECRET" ]] || die "Missing $MY_SHARE_SECRET. Did 01-keysetup-1.sh run successfully?"
[[ -f "$JOINT_PK"        ]] || die "Missing $JOINT_PK. Did 01-keysetup-1.sh run successfully?"

# -------- 1. Re-fetch Acme's relin-round1 if we lost it --------
if [[ ! -f "$RELIN_R1_LEAD" ]]; then
    download_peer_share "relin-round1" "$RELIN_R1_LEAD"
fi

# -------- 2. Deterministic combine (must match Acme's combine byte-for-byte) --------
info "Combining round-1 relin shares (deterministic; must match Acme's)..."
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
    --secret-key "$MY_SHARE_SECRET" \
    --combined-r1 "$COMBINED_R1" \
    --joint-pk "$JOINT_PK" \
    --output "$RELIN_R2" \
    > /dev/null
success "Beta relin-r2: $RELIN_R2"

wrap_and_upload "$RELIN_R2" 4 "relin-round2"

echo
success "Bundle 2 uploaded. Beta's bundle-2 contribution is in."
echo
info "Next step: finalize the joint keys (manual, on both machines):"
echo "  $SCRIPT_DIR/03-finalize-keysetup.sh"

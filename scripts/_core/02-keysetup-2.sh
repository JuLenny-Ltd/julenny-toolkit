#!/usr/bin/env bash
# Keysetup bundle 2: relin-round2. BOTH sides run it.
#
# Each side combines the two round-1 relin shares - deterministically, so the two
# combines must agree byte for byte - and then contributes its own round-2 share.
#
# What differs between the sides is only where the pieces come from:
#
#   LEAD  produced lead-relin-r1 itself in bundle 1 and collects the peer's
#         relin-round1-continue here, along with the joint public key, which arrives
#         as the peer's pk-share.
#   MAIN  produced main-relin-r1 and derived the joint public key in bundle 1, and
#         already holds the lead's relin-round1 from the same phase.
#
# Which half this machine runs is the KEYSETUP role, read from the platform by 00-init,
# NOT the data role: a permission created in the other direction inside the same
# collaboration makes the data owner the keysetup main.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# lib.sh resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_session

step "${JL_OUR_LABEL} keysetup bundle 2: relin-round2 (keysetup role: ${JULENNY_ROLE:-unknown})"

# Bundle 2 is the second relin round and nothing else. An additive-only function
# (requiredEvalKeys: []) has no relin key, so there is nothing to do and the file
# checks below would stop on intermediates that were never created.
if ! function_requires_relin_keys; then
    info "Function does not require a relinearization key; bundle 2 has nothing to do."
    info "Go straight to 03-finalize-keysetup."
    exit 0
fi

MY_SECRET="$JL_KEYS_DIR/$JL_SECRET_SHARE_FILE"

# The combine takes the LEAD's share as -a and the MAIN's as -b, on both machines.
# That ordering is what makes the two outputs identical; it is not "mine then theirs".
if i_am_keysetup_lead; then
    MY_R1="$JL_KEYS_DIR/lead-relin-r1.bin"
    PEER_R1="$JL_PEER_DIR/main-relin-r1.bin"
    PEER_R1_MSG="relin-round1-continue"
    RELIN_R1_LEAD="$MY_R1"
    RELIN_R1_MAIN="$PEER_R1"
    MY_R2="$JL_KEYS_DIR/lead-relin-r2.bin"
    # The lead never derives the joint pk; the main's pk-share IS the joint pk, so it
    # arrives here, in this phase.
    JOINT_PK="$JL_PEER_DIR/joint-pk.bin"
    JOINT_PK_FROM_PEER=true
else
    MY_R1="$JL_KEYS_DIR/main-relin-r1.bin"
    PEER_R1="$JL_PEER_DIR/lead-relin-r1.bin"
    PEER_R1_MSG="relin-round1"
    RELIN_R1_LEAD="$PEER_R1"
    RELIN_R1_MAIN="$MY_R1"
    MY_R2="$JL_KEYS_DIR/main-relin-r2.bin"
    # The main derived the joint pk in bundle 1 and keeps it under its own keys.
    JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"
    JOINT_PK_FROM_PEER=false
fi

COMBINED_R1="$JL_KEYS_DIR/combined-relin-r1.bin"

[[ -f "$MY_R1"     ]] || die "Missing $MY_R1. Did 01-keysetup-1.sh run successfully?"
[[ -f "$MY_SECRET" ]] || die "Missing $MY_SECRET. Did 01-keysetup-1.sh run successfully?"

# -------- 1. Collect what the peer owes this phase --------
# Waiting before downloading, rather than downloading blind, covers the lead (whose
# peer has genuinely not published yet when this phase starts) and costs the main
# nothing: it already downloaded this share in bundle 1, so the file is there and
# neither the wait nor the download runs.
if [[ ! -f "$PEER_R1" ]]; then
    info "Waiting for ${JL_PEER_LABEL}'s $PEER_R1_MSG contribution..."
    wait_for_peer_share "$PEER_R1_MSG"
    download_peer_share "$PEER_R1_MSG" "$PEER_R1"
fi

if [[ ! -f "$JOINT_PK" ]]; then
    if $JOINT_PK_FROM_PEER; then
        info "Fetching the joint public key from ${JL_PEER_LABEL}'s pk-share..."
        wait_for_peer_share "pk-share"
        download_peer_share "pk-share" "$JOINT_PK"
    else
        die "Missing $JOINT_PK. Did 01-keysetup-1.sh run successfully?"
    fi
fi

# -------- 2. Deterministic combine (must match the peer's, byte for byte) --------
info "Combining round-1 relin shares (deterministic; must match ${JL_PEER_LABEL}'s)..."
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
    --secret-key "$MY_SECRET" \
    --combined-r1 "$COMBINED_R1" \
    --joint-pk "$JOINT_PK" \
    --output "$MY_R2" \
    > /dev/null
success "${JL_OUR_LABEL} relin-r2: $MY_R2"

wrap_and_upload "$MY_R2" 4 "relin-round2"

echo
success "Bundle 2 uploaded. ${JL_OUR_LABEL}'s bundle-2 contribution is in."
echo
info "Next step: finalize the joint keys. Both machines run it:"
echo "  $SCRIPT_DIR/03-finalize-keysetup.sh"

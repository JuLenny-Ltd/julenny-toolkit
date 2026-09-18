#!/usr/bin/env bash
# Keysetup bundle 1. BOTH sides run it, and the two halves are genuinely different
# work, not the same work with different labels:
#
#   LEAD  generates a fresh key share and publishes the three contributions that
#         depend on nothing else: pk-share, relin-round1, sum-round1.
#   MAIN  waits for those three, chains on each of them, and publishes what the
#         chaining produces: the joint public key as its pk-share, then
#         relin-round1-continue and sum-round1-continue.
#
# Which half this machine runs is the KEYSETUP role, read from the platform by 00-init,
# NOT the data role: a permission created in the other direction inside the same
# collaboration makes the data owner the keysetup main. Running the wrong half is worse
# than an error - the shares would not match the joint key, and nothing would say so
# until a decryption came out wrong.
#
# Relin and sum are each skipped when the function does not declare them. An
# additive-only function needs neither, and publishing a round the platform has already
# moved past leaves both sides waiting on an exchange that will not happen.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# lib.sh resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_session

# This machine's FHE secret share. Named for the KEYSETUP role: load_session picked the
# filename from JULENNY_ROLE, so a reversed permission writes the other side's name and
# the name always describes the material the file holds.
MY_SECRET="$JL_KEYS_DIR/$JL_SECRET_SHARE_FILE"

if i_am_keysetup_lead; then
    step "${JL_OUR_LABEL} keysetup bundle 1 (lead): pk-share + relin-round1 (+ sum, only if the function needs one)"

    MY_PUBLIC="$JL_KEYS_DIR/fhe_public_key.bin"
    RELIN_R1="$JL_KEYS_DIR/lead-relin-r1.bin"
    SUM_R1="$JL_KEYS_DIR/lead-sum-r1.bin"

    # -------- 1. pk-share (round 1) --------
    # REUSE an existing secret share rather than generating over it.
    #
    # This phase used to generate unconditionally, which made it destructive to re-run: a
    # new share does not match the joint key already built from the old one, so this
    # machine could no longer partial-decrypt anything. That is why the only advice on a
    # half-built collaboration was to start a new one.
    #
    # It has to be re-runnable, because a collaboration whose joint key was built for a
    # function needing fewer keys still owes the rounds for the keys it lacks, and those
    # rounds are built FROM this share. A fresh ceremony has no share to find, so it
    # still generates one.
    if [[ -f "$MY_SECRET" && -f "$MY_PUBLIC" ]]; then
        info "Reusing this machine's existing FHE key share; not generating a new one."
        info "  $MY_SECRET"
    else
        info "Generating FHE keypair (${JL_OUR_LABEL}'s contribution)..."
        julenny-toolkit crypto keysetup-contribute \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --role lead \
            --output-secret "$MY_SECRET" \
            --output-public "$MY_PUBLIC" \
            > /dev/null
        success "FHE secret: $MY_SECRET  (stays here, never upload)"
        success "FHE public contribution: $MY_PUBLIC"
    fi

    wrap_and_upload "$MY_PUBLIC" 1 "pk-share"

    # -------- 2. relin-round1 (round 2) -- only if the function needs a relin key --------
    if function_requires_relin_keys; then
        info "Generating relinearization key round-1 contribution..."
        julenny-toolkit crypto relin-contribute \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --round 1 --role lead \
            --secret-key "$MY_SECRET" \
            --output "$RELIN_R1" \
            > /dev/null
        success "Relin round-1: $RELIN_R1"

        wrap_and_upload "$RELIN_R1" 2 "relin-round1"
    else
        info "Function does not require a relinearization key; skipping relin-round1."
    fi

    # -------- 3. sum-round1 (round 5) -- only if the function needs a sum key --------
    if function_requires_sum_keys; then
        info "Generating sum key round-1 contribution..."
        julenny-toolkit crypto sum-contribute \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --role lead \
            --secret-key "$MY_SECRET" \
            --output "$SUM_R1" \
            > /dev/null
        success "Sum round-1: $SUM_R1"

        wrap_and_upload "$SUM_R1" 5 "sum-round1"
    else
        info "Function does not require a sum key (requiredEvalKeys); skipping sum-round1."
    fi

    echo
    BUNDLE1_MSGS="pk-share"
    function_requires_relin_keys && BUNDLE1_MSGS="$BUNDLE1_MSGS, relin-round1"
    function_requires_sum_keys   && BUNDLE1_MSGS="$BUNDLE1_MSGS, sum-round1"
    success "Bundle 1 uploaded ($BUNDLE1_MSGS)."
    PEER_OWES="bundle 1"
else
    step "${JL_OUR_LABEL} keysetup bundle 1 (main): joint-pk + relin-round1-continue (+ sum, only if the function needs one)"

    JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"
    RELIN_R1="$JL_KEYS_DIR/main-relin-r1.bin"
    SUM_R1="$JL_KEYS_DIR/main-sum-r1.bin"

    PEER_PK="$JL_PEER_DIR/lead-pk.bin"
    PEER_RELIN_R1="$JL_PEER_DIR/lead-relin-r1.bin"
    PEER_SUM_R1="$JL_PEER_DIR/lead-sum-r1.bin"

    # -------- 1. Wait for and download the lead's three shares --------
    info "Fetching ${JL_PEER_LABEL}'s bundle 1 contributions..."
    wait_for_peer_share "pk-share"
    download_peer_share "pk-share" "$PEER_PK"

    # Additive-only functions declare requiredEvalKeys: [] and never send relin-round1.
    if function_requires_relin_keys; then
        wait_for_peer_share "relin-round1"
        download_peer_share "relin-round1" "$PEER_RELIN_R1"
    fi

    if function_requires_sum_keys; then
        wait_for_peer_share "sum-round1"
        download_peer_share "sum-round1" "$PEER_SUM_R1"
    fi

    # -------- 2. Derive the joint pk (chain on the lead's pk-share) --------
    # REUSE an existing share rather than deriving over it. Same reason as the lead half:
    # a new share does not match the joint key already built from the old one, so
    # re-running this phase used to leave the machine unable to partial-decrypt. It has
    # to be re-runnable, because the rounds for a key the collaboration still lacks are
    # built FROM this share.
    if [[ -f "$MY_SECRET" && -f "$JOINT_PK" ]]; then
        info "Reusing this machine's existing FHE key share; not deriving a new one."
        info "  $MY_SECRET"
    else
        info "Deriving joint public key..."
        julenny-toolkit crypto keysetup-contribute \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --role main \
            --peer-share "$PEER_PK" \
            --output-secret "$MY_SECRET" \
            --output-public "$JOINT_PK" \
            > /dev/null
        success "${JL_OUR_LABEL}'s share secret: $MY_SECRET  (stays here, never upload)"
        success "Joint public key: $JOINT_PK"
    fi

    wrap_and_upload "$JOINT_PK" 1 "pk-share"

    # -------- 3. relin-round1-continue (round 3) -- only if a relin key is needed --------
    if function_requires_relin_keys; then
        info "Generating relin round-1 continue..."
        julenny-toolkit crypto relin-contribute \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --round 1 --role main \
            --secret-key "$MY_SECRET" \
            --peer-share "$PEER_RELIN_R1" \
            --output "$RELIN_R1" \
            > /dev/null
        success "${JL_OUR_LABEL} relin round-1: $RELIN_R1"

        wrap_and_upload "$RELIN_R1" 3 "relin-round1-continue"
    else
        info "Function does not require a relinearization key; skipping relin-round1-continue."
    fi

    # -------- 4. sum-round1-continue (round 6) -- only if the function needs a sum key --------
    if function_requires_sum_keys; then
        info "Generating sum round-1 continue..."
        julenny-toolkit crypto sum-contribute \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --role main \
            --secret-key "$MY_SECRET" \
            --peer-share "$PEER_SUM_R1" \
            --joint-pk "$JOINT_PK" \
            --output "$SUM_R1" \
            > /dev/null
        success "${JL_OUR_LABEL} sum round-1: $SUM_R1"

        wrap_and_upload "$SUM_R1" 6 "sum-round1-continue"
    else
        info "Function does not require a sum key (requiredEvalKeys); skipping sum-round1-continue."
    fi

    echo
    BUNDLE1_MSGS="pk-share"
    function_requires_relin_keys && BUNDLE1_MSGS="$BUNDLE1_MSGS, relin-round1-continue"
    function_requires_sum_keys   && BUNDLE1_MSGS="$BUNDLE1_MSGS, sum-round1-continue"
    success "Bundle 1 uploaded ($BUNDLE1_MSGS)."
    # Bundle 2 is the relin exchange, so there is no bundle 2 to wait for when the
    # function declares no relin key. The main side used to say "bundle 2" either way,
    # which pointed the operator at a phase that exits immediately.
    if function_requires_relin_keys; then PEER_OWES="bundle 2"; else PEER_OWES=""; fi
fi

if function_requires_relin_keys; then
    NEXT_STEP="02-keysetup-2.sh"
else
    NEXT_STEP="03-finalize-keysetup.sh"
fi

if [[ -n "$PEER_OWES" ]]; then
    wait_msg "Tell ${JL_PEER_LABEL} to run their side of keysetup $PEER_OWES on their own machine
(their run.sh / run.ps1 handles it, or the equivalent MCP verbs).

When ${JL_PEER_LABEL}'s $PEER_OWES is uploaded, come back here and run:
    $SCRIPT_DIR/$NEXT_STEP"
else
    echo
    info "Next step: finalize the joint keys. Both machines run it:"
    echo "  $SCRIPT_DIR/$NEXT_STEP"
fi

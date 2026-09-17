#!/usr/bin/env bash
# Acme bundle 1: pk-share + relin-round1 + sum-round1.
# These three are independent of any peer input; we can produce and upload
# all of them in one sitting.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# The side profile is chosen by the DATA role, which the scenario bootstrap exports.
# Sourced dynamically so this phase can be driven for either side: the keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
#
# The fallback keeps a DIRECT run of this script working, which is how the numbered
# scripts are documented to be runnable on their own.
# shellcheck source=../sides/data-owner.env
source "$SCRIPT_DIR/../sides/${JULENNY_OUR_SIDE:-data-owner}.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"
load_session

step "Acme keysetup bundle 1: pk-share + relin-round1 (+ sum, only if the function needs one)"

FHE_SECRET="$JL_KEYS_DIR/fhe_secret_key.bin"
FHE_PUBLIC="$JL_KEYS_DIR/fhe_public_key.bin"
RELIN_R1="$JL_KEYS_DIR/lead-relin-r1.bin"
SUM_R1="$JL_KEYS_DIR/lead-sum-r1.bin"

# -------- 1. pk-share (round 1) --------
# REUSE an existing secret share rather than generating over it.
#
# This phase used to generate unconditionally, which made it destructive to re-run: a new
# share does not match the joint key already built from the old one, so this machine could
# no longer partial-decrypt anything. That is why the only advice on a half-built
# collaboration was to start a new one.
#
# It has to be re-runnable, because a collaboration whose joint key was built for a function
# needing fewer keys still owes the rounds for the keys it lacks, and those rounds are built
# FROM this share. A fresh ceremony has no share to find, so it still generates one.
if [[ -f "$FHE_SECRET" && -f "$FHE_PUBLIC" ]]; then
    info "Reusing this machine's existing FHE key share; not generating a new one."
    info "  $FHE_SECRET"
else
    info "Generating FHE keypair (Acme's contribution)..."
    julenny-toolkit crypto keysetup-contribute \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --role lead \
        --output-secret "$FHE_SECRET" \
        --output-public "$FHE_PUBLIC" \
        > /dev/null
    success "FHE secret: $FHE_SECRET  (stays here, never upload)"
    success "FHE public contribution: $FHE_PUBLIC"
fi

wrap_and_upload "$FHE_PUBLIC" 1 "pk-share"

# -------- 2. relin-round1 (round 2) -- only if the function needs a relin key --------
# Additive-only functions (federated-average) declare requiredEvalKeys: [] and need no
# relin key. Publishing round 1 anyway leaves both sides waiting on an exchange the
# platform has already moved past.
if function_requires_relin_keys; then
    info "Generating relinearization key round-1 contribution..."
    julenny-toolkit crypto relin-contribute \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --round 1 --role lead \
        --secret-key "$FHE_SECRET" \
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
        --secret-key "$FHE_SECRET" \
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
if function_requires_relin_keys; then
    NEXT_STEP="02-keysetup-2.sh"
else
    NEXT_STEP="03-finalize-keysetup.sh"
fi
wait_msg "Tell Beta to run their side of keysetup bundle 1 on their own machine
(their run.sh / run.ps1 handles it, or the equivalent MCP verbs).

When Beta's bundle 1 is uploaded, come back here and run:
    $SCRIPT_DIR/$NEXT_STEP"

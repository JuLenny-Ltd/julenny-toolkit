#!/usr/bin/env bash
# Beta (consumer / main): rotation key augmentation phase.
#
# Runs ONLY when the function definition declares
#     "requiredEvalKeys": ["rotation", ...]
# (see plans/rotation-key-augmentation-contract.md on the platform).
# For pre-existing functions whose definition does not require rotation
# (joint-record-overlap, etc.) this script exits 0 immediately.
#
# Protocol mapping for Beta:
#   1. Wait for platform to derive rotation indices from the bound
#      plaintext datasets (rule_pairs + left_dictionary + right_dictionary).
#   2. Wait for Acme to upload `rotation-round1` (the owner's initial
#      contribution; Acme can't run this until indices are derived either).
#   3. Download Acme's share, call `rotation-contribute --role main`,
#      upload as `rotation-round1-continue`.
#   4. Run `rotation-combine` locally, upload as `rotation-combine`. The
#      platform verifies our combine output byte-matches Acme's.
#   5. Wait for status to transition to `complete`.
#
# Once complete the platform unblocks the execution gate at /execute.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/../sides/data-consumer.env"
source "$SCRIPT_DIR/../lib.sh"
load_session

FUNCTION_DEF="$JL_WORKDIR/function-def.json"

step "Beta: rotation key augmentation (phase 4.5)"

# ---- Guard: only run if the function-def actually requires rotation ----
if ! function_requires_rotation_keys "$FUNCTION_DEF"; then
    info "Function does not declare rotation in requiredEvalKeys. Skipping 4.5."
    exit 0
fi

# ---- Guard: skip if already complete ----
status="$(get_rotation_status)"
if [[ "$status" == "complete" ]]; then
    info "Rotation keysetup is already complete for this permission. Skipping."
    exit 0
fi

# ---- Fetch the joint public key (needed for both contribute and combine) ----
JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"
if [[ ! -f "$JOINT_PK" ]]; then
    info "Joint public key missing locally; refetching..."
    JOINT_KEY_ID="${JULENNY_JOINT_KEY_ID:-}"
    [[ -n "$JOINT_KEY_ID" && "$JOINT_KEY_ID" != "null" ]] \
        || die "config.env has no JULENNY_JOINT_KEY_ID; base keysetup must finish before 4.5."
    curl_jl GET "/api/fhe-joint-keys/$JOINT_KEY_ID/public-key" -o "$JOINT_PK"
    success "Joint pk fetched -> $JOINT_PK"
fi

MY_SECRET="$JL_KEYS_DIR/my_share_secret.bin"
[[ -f "$MY_SECRET" ]] || die "Missing FHE secret share at $MY_SECRET (produced by base keysetup)."

# ---- Step 1: wait for the platform to derive indices ----
wait_for_pending_rotation_indices "platform to derive rotation indices from plaintext data"

INDICES_CSV="$(get_pending_rotation_indices_csv)"
if [[ -z "$INDICES_CSV" ]]; then
    # Empty derived set: status already transitioned to complete (no rotation
    # keys actually needed for this execution).
    info "Empty derived index set. No rotation keys needed; phase 4.5 done."
    exit 0
fi
INDEX_COUNT="$(echo "$INDICES_CSV" | tr ',' '\n' | wc -l)"
success "Platform-derived index set: $INDEX_COUNT indices."

# ---- Step 1b: defensive local re-derivation (hash-based, 0.5.5) ----
# Re-derive the rotation index set locally from the rule_pairs file Beta
# uploaded in 04-encrypt, then compare to the platform's set. Catches silent
# drift between toolkit's and platform's FNV1a-mod-slotcount derivation
# (whitespace handling, CSV split rules, case sensitivity, hash constants).
# Skipped if the rule_pairs path is missing from the sidecar (e.g. operator
# reused an existing dataset rather than uploading a fresh one), with a warn
# but not a die — the gate is defensive, not load-bearing.
PT_SIDECAR="$JL_WORKDIR/my_plaintext_paths.json"
if [[ -f "$PT_SIDECAR" ]]; then
    PT_PAIRS="$(jq -r '.rule_pairs.path // empty' "$PT_SIDECAR")"
    if [[ -n "$PT_PAIRS" && -f "$PT_PAIRS" ]]; then
        info "Re-deriving rotation indices locally to cross-check the platform..."
        LOCAL_JSON="$(julenny-fhe crypto derive-rotation-indices \
            --rule-pairs "$PT_PAIRS" \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --json)" \
            || die "Local index derivation failed. Re-uploaded rule_pairs may be malformed."
        LOCAL_CSV="$(echo "$LOCAL_JSON" | jq -r '.indices | join(",")')"
        if [[ "$LOCAL_CSV" == "$INDICES_CSV" ]]; then
            success "Local-derived indices MATCH platform-derived set ($INDEX_COUNT indices)."
        else
            err "Index set MISMATCH between toolkit and platform!"
            err "  Platform: $INDICES_CSV"
            err "  Local:    $LOCAL_CSV"
            err "Possible causes: FNV1a constants drifted, normalization rule drift,"
            err "                 rule_pairs file modified after upload, or platform"
            err "                 used a different dataset than expected."
            die "Refusing to generate rotation keys against a mismatched index set."
        fi
    else
        warn "No rule_pairs path in sidecar; skipping local-derivation cross-check."
        warn "  (Sidecar is populated by 04-encrypt when fresh plaintext datasets are uploaded;"
        warn "   picking existing datasets bypasses it. The platform indices will still be used.)"
    fi
else
    warn "No my_plaintext_paths.json sidecar found; skipping local-derivation cross-check."
fi

# ---- Step 2: wait for Acme's rotation-round1 share ----
wait_for_peer_share "rotation-round1" 1800

# ---- Step 3: download Acme's share, contribute as main, upload continue ----
ROT_OWNER_SHARE="$JL_PEER_DIR/rotation-round1.bin"
download_peer_share "rotation-round1" "$ROT_OWNER_SHARE"

# Idempotency: same rationale as Acme's lead-share reuse. If the local
# rotation-round1-continue.bin already exists from a prior partial run,
# reuse it — regenerating produces fresh randomness that won't match what
# the platform's idempotency kept on round 8. Set
# JULENNY_FORCE_ROTATION_REGEN=1 to override (e.g. peer's share changed,
# function-def indices changed, etc.).
MY_ROT_SHARE="$JL_KEYS_DIR/rotation-round1-continue.bin"
if [[ -f "$MY_ROT_SHARE" && "${JULENNY_FORCE_ROTATION_REGEN:-0}" != "1" ]]; then
    info "Reusing existing Beta rotation-round1-continue share at $MY_ROT_SHARE ($(stat -c%s "$MY_ROT_SHARE") bytes)."
else
    info "Computing Beta's rotation-round1-continue contribution..."
    julenny-fhe crypto rotation-contribute \
        --role main \
        --secret-key "$MY_SECRET" \
        --peer-share "$ROT_OWNER_SHARE" \
        --joint-pk "$JOINT_PK" \
        --indices "$INDICES_CSV" \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --output "$MY_ROT_SHARE" \
        > /dev/null
    success "Beta's continue share written -> $MY_ROT_SHARE ($(stat -c%s "$MY_ROT_SHARE") bytes)"
fi

ROUND_CONTINUE="$(get_rotation_round_offset round1-continue)"
wrap_and_upload "$MY_ROT_SHARE" "$ROUND_CONTINUE" "rotation-round1-continue"

# If the peer already finished the rotation while we got here, there is
# nothing to combine or upload - move on.
if [[ "$(get_rotation_status)" == "complete" ]]; then
    success "Rotation keysetup already complete; skipping combine."
    exit 0
fi

# ---- Step 4: combine locally, upload combine ----
# Both parties run combine independently with the same inputs (Acme's share +
# Beta's continue + joint_pk) and the platform verifies the byte-equality.
ROT_COMBINED="$JL_KEYS_DIR/rotation-combined.bin"
info "Computing Beta's rotation-combine output..."
julenny-fhe crypto rotation-combine \
    --share-a "$ROT_OWNER_SHARE" \
    --share-b "$MY_ROT_SHARE" \
    --joint-pk "$JOINT_PK" \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --output "$ROT_COMBINED" \
    > /dev/null
success "Rotation key map combined -> $ROT_COMBINED ($(stat -c%s "$ROT_COMBINED") bytes)"

ROUND_COMBINE="$(get_rotation_round_offset combine)"
wrap_and_upload "$ROT_COMBINED" "$ROUND_COMBINE" "rotation-combine"

# ---- Step 5: wait for status -> complete (platform verifies SHA256 match) ----
wait_for_rotation_status "complete" 600

echo
success "Phase 4.5 done. Rotation keys are installed; execution can proceed."

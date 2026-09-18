#!/usr/bin/env bash
# Rotation key augmentation. BOTH sides run it.
#
# Runs only when the function definition declares "rotation" in requiredEvalKeys. For
# every other function it exits 0 immediately, which is why the driver can call it
# unconditionally.
#
# Rotation is the one evaluation key that cannot be built before the function and its
# data are known: the index set is DERIVED from the bound plaintext datasets. So this
# phase sits after 04-encrypt, and starts by waiting for the platform to derive it.
#
# The two halves, by KEYSETUP role:
#
#   LEAD  contributes first, with nothing to chain on, and publishes rotation-round1.
#         Then it waits for the main's continuation.
#   MAIN  waits for the lead's rotation-round1, chains on it, and publishes
#         rotation-round1-continue.
#
# Both then run the same deterministic combine over (lead share, main continuation,
# joint pk) and upload rotation-combine; the platform checks the two agree.
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

FUNCTION_DEF="$JL_WORKDIR/function-def.json"

step "${JL_OUR_LABEL}: rotation key augmentation (phase 4.5, keysetup role: ${JULENNY_ROLE:-unknown})"

# ---- Guard: only run if the function-def actually requires rotation ----
if ! function_requires_rotation_keys "$FUNCTION_DEF"; then
    info "Function does not declare rotation keys; phase 4.5 is a no-op."
    exit 0
fi

# ---- Guard: skip if rotation keysetup is already complete ----
if [[ "$(get_rotation_status)" == "complete" ]]; then
    success "Rotation keysetup already complete for this permission; nothing to do."
    exit 0
fi

# ---- Fetch the joint public key (needed for both contribute and combine) ----
JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"
if [[ ! -f "$JOINT_PK" ]]; then
    info "Joint public key missing locally; refetching..."
    # From config.env, not from a scan of the permissions list. The lead half used to
    # scan, which meant it needed the permission to still be listed and to be listed
    # under the view its data role uses - two ways to fail for a value already on disk.
    JOINT_KEY_ID="${JULENNY_JOINT_KEY_ID:-}"
    [[ -n "$JOINT_KEY_ID" && "$JOINT_KEY_ID" != "null" ]] \
        || die "config.env has no JULENNY_JOINT_KEY_ID; base keysetup must finish before 4.5."
    curl_jl GET "/api/fhe-joint-keys/$JOINT_KEY_ID/public-key" -o "$JOINT_PK"
    success "Joint pk fetched -> $JOINT_PK"
fi

# Named for the KEYSETUP role; load_session picked the filename from JULENNY_ROLE.
MY_SECRET="$JL_KEYS_DIR/$JL_SECRET_SHARE_FILE"
[[ -f "$MY_SECRET" ]] || die "Missing FHE secret share at $MY_SECRET (produced by base keysetup)."

# ---- Step 1: wait for the platform to derive indices ----
# The platform derives them once the plaintext datasets they come from are all bound
# via preferred-datasets, which happens in 04-encrypt. Whichever side owns those inputs,
# the wait here is the same: poll until the index set appears.
wait_for_pending_rotation_indices "the platform to derive rotation indices from the bound plaintext data"

INDICES_CSV="$(get_pending_rotation_indices_csv)"
if [[ -z "$INDICES_CSV" ]]; then
    # Empty derived set: status has already transitioned to complete, because no
    # rotation keys are actually needed for this execution.
    info "Empty derived index set. No rotation keys needed; phase 4.5 done."
    exit 0
fi
INDEX_COUNT="$(echo "$INDICES_CSV" | tr ',' '\n' | wc -l)"
success "Platform-derived index set: $INDEX_COUNT indices."

# ---- Step 1b: defensive local re-derivation ----
# Re-derive the index set locally from the rule_pairs file this machine uploaded, then
# compare. Catches silent drift between the toolkit's and the platform's derivation
# (whitespace handling, CSV split rules, case sensitivity, hash constants).
#
# Skipped when the sidecar has no rule_pairs path: the operator reused an existing
# dataset rather than uploading a fresh one, or the other side owns that input. The
# check is defensive, not load-bearing, so skipping it is not an error.
#
# It says so at info level, not warn. Only the side that uploaded the file can run the
# check at all, so on the other side a warning would fire on every normal run and mean
# nothing. This was a warning while the two sides had separate scripts.
PT_SIDECAR="$JL_WORKDIR/my_plaintext_paths.json"
if [[ -f "$PT_SIDECAR" ]]; then
    PT_PAIRS="$(jq -r '.rule_pairs.path // empty' "$PT_SIDECAR")"
    if [[ -n "$PT_PAIRS" && -f "$PT_PAIRS" ]]; then
        info "Re-deriving rotation indices locally to cross-check the platform..."
        LOCAL_JSON="$(julenny-toolkit crypto derive-rotation-indices \
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
        info "No rule_pairs path in the sidecar; skipping the local-derivation cross-check."
        info "  (It is written by 04-encrypt when this machine uploads a fresh plaintext"
        info "   dataset. The platform's indices are used either way.)"
    fi
else
    info "No my_plaintext_paths.json sidecar; skipping the local-derivation cross-check."
fi

# ---- Steps 2 and 3: contribute in the right order for this role ----
# Idempotency, both halves: reuse an existing share rather than regenerating. The
# contribution uses fresh randomness each call, so a regenerated share would not match
# the one the platform already accepted (its idempotency keeps the first payload), and
# the combine would then produce the wrong result on this machine only.
#
# Set JULENNY_FORCE_ROTATION_REGEN=1 to override: do that if the derived index set has
# changed, or this machine's FHE secret share was rotated since the file was written.
LEAD_SHARE=""
MAIN_SHARE=""

if i_am_keysetup_lead; then
    MY_ROT_SHARE="$JL_KEYS_DIR/rotation-round1.bin"
    if [[ -f "$MY_ROT_SHARE" && "${JULENNY_FORCE_ROTATION_REGEN:-0}" != "1" ]]; then
        info "Reusing existing rotation-round1 share at $MY_ROT_SHARE ($(stat -c%s "$MY_ROT_SHARE") bytes)."
    else
        info "Computing ${JL_OUR_LABEL}'s rotation-round1 contribution (lead)..."
        julenny-toolkit crypto rotation-contribute \
            --role lead \
            --secret-key "$MY_SECRET" \
            --indices "$INDICES_CSV" \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --output "$MY_ROT_SHARE" \
            > /dev/null
        success "${JL_OUR_LABEL}'s rotation-round1 share written -> $MY_ROT_SHARE ($(stat -c%s "$MY_ROT_SHARE") bytes)"
    fi

    ROUND_R1="$(get_rotation_round_offset round1)"
    wrap_and_upload "$MY_ROT_SHARE" "$ROUND_R1" "rotation-round1"

    # Now wait for the main's continuation, which the combine needs.
    wait_for_peer_share "rotation-round1-continue" 1800
    PEER_SHARE="$JL_PEER_DIR/rotation-round1-continue.bin"
    download_peer_share "rotation-round1-continue" "$PEER_SHARE"

    LEAD_SHARE="$MY_ROT_SHARE"
    MAIN_SHARE="$PEER_SHARE"
else
    # The main cannot start until the lead has published: its contribution chains on it.
    wait_for_peer_share "rotation-round1" 1800
    PEER_SHARE="$JL_PEER_DIR/rotation-round1.bin"
    download_peer_share "rotation-round1" "$PEER_SHARE"

    MY_ROT_SHARE="$JL_KEYS_DIR/rotation-round1-continue.bin"
    if [[ -f "$MY_ROT_SHARE" && "${JULENNY_FORCE_ROTATION_REGEN:-0}" != "1" ]]; then
        info "Reusing existing rotation-round1-continue share at $MY_ROT_SHARE ($(stat -c%s "$MY_ROT_SHARE") bytes)."
    else
        info "Computing ${JL_OUR_LABEL}'s rotation-round1-continue contribution (main)..."
        julenny-toolkit crypto rotation-contribute \
            --role main \
            --secret-key "$MY_SECRET" \
            --peer-share "$PEER_SHARE" \
            --joint-pk "$JOINT_PK" \
            --indices "$INDICES_CSV" \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --output "$MY_ROT_SHARE" \
            > /dev/null
        success "${JL_OUR_LABEL}'s continue share written -> $MY_ROT_SHARE ($(stat -c%s "$MY_ROT_SHARE") bytes)"
    fi

    ROUND_CONTINUE="$(get_rotation_round_offset round1-continue)"
    wrap_and_upload "$MY_ROT_SHARE" "$ROUND_CONTINUE" "rotation-round1-continue"

    LEAD_SHARE="$PEER_SHARE"
    MAIN_SHARE="$MY_ROT_SHARE"
fi

# If the peer already finished the rotation while we got here, there is nothing to
# combine or upload - move on.
if [[ "$(get_rotation_status)" == "complete" ]]; then
    success "Rotation keysetup already complete; skipping combine."
    exit 0
fi

# ---- Step 4: combine locally, upload combine ----
# The combine takes the LEAD's share as -a and the MAIN's continuation as -b, on both
# machines. That ordering is what makes the two outputs identical; the platform verifies
# the SHA256 match on submission.
ROT_COMBINED="$JL_KEYS_DIR/rotation-combined.bin"
info "Computing ${JL_OUR_LABEL}'s rotation-combine output..."
julenny-toolkit crypto rotation-combine \
    --share-a "$LEAD_SHARE" \
    --share-b "$MAIN_SHARE" \
    --joint-pk "$JOINT_PK" \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --output "$ROT_COMBINED" \
    > /dev/null
success "Rotation key map combined -> $ROT_COMBINED ($(stat -c%s "$ROT_COMBINED") bytes)"

ROUND_COMBINE="$(get_rotation_round_offset combine)"
wrap_and_upload "$ROT_COMBINED" "$ROUND_COMBINE" "rotation-combine"

# ---- Step 5: wait for status -> complete (platform verifies the SHA256 match) ----
wait_for_rotation_status "complete" 600

echo
success "Phase 4.5 done. Rotation keys are installed; execution can proceed."

#!/usr/bin/env bash
# Acme (data owner / lead): rotation key augmentation phase.
#
# Runs ONLY when the function definition declares
#     "requiredEvalKeys": ["rotation", ...]
# (see plans/rotation-key-augmentation-contract.md on the platform).
# For pre-existing functions whose definition does not require rotation
# (joint-record-overlap, etc.) this script exits 0 immediately.
#
# Protocol mapping for Acme:
#   1. Wait for platform to derive rotation indices. Indices come from
#      Beta's plaintext uploads (rule_pairs + dictionaries); the platform
#      derives them server-side as the bindings land. Acme has nothing to
#      upload at this step; we just wait for them to appear.
#   2. Call `rotation-contribute --role lead` to produce Acme's initial
#      contribution for the derived index set.
#   3. Upload as `rotation-round1` (Acme is the OWNER in contract terms).
#   4. Wait for Beta's `rotation-round1-continue` continuation.
#   5. Run `rotation-combine` locally and upload as `rotation-combine`.
#      The platform verifies our combine output byte-matches Beta's.
#   6. Wait for status to transition to `complete`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../sides/data-owner.env
source "$SCRIPT_DIR/../sides/data-owner.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"
load_session

FUNCTION_DEF="$JL_WORKDIR/function-def.json"

step "Acme: rotation key augmentation (phase 4.5)"

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

# ---- Fetch the joint public key ----
JOINT_PK="$JL_KEYS_DIR/joint_public_key.bin"
if [[ ! -f "$JOINT_PK" ]]; then
    info "Joint public key missing locally; refetching..."
    JOINT_KEY_ID="$(curl_jl GET "/api/fhe-permissions?status=active&view=permissioned" \
        | jq -r --arg id "$JULENNY_PERMISSION_ID" \
              '.permissions[] | select(.id == $id) | .jointKeyId')"
    [[ -n "$JOINT_KEY_ID" && "$JOINT_KEY_ID" != "null" ]] \
        || die "Permission has no jointKeyId; base keysetup must finish before 4.5."
    curl_jl GET "/api/fhe-joint-keys/$JOINT_KEY_ID/public-key" -o "$JOINT_PK"
    success "Joint pk fetched -> $JOINT_PK"
fi

# Acme stores its secret share as fhe_secret_key.bin (Beta uses my_share_secret.bin).
# Asymmetric naming legacy from the original keysetup scripts; do not "unify"
# without changing 01-keysetup-1.sh / 02-keysetup-2.sh / 05-release.sh on the
# Acme side and 01 / 02 / 06-decrypt.sh on the Beta side.
MY_SECRET="$JL_KEYS_DIR/fhe_secret_key.bin"
[[ -f "$MY_SECRET" ]] || die "Missing FHE secret share at $MY_SECRET (produced by base keysetup)."

# ---- Step 1: wait for the platform to derive indices ----
# The platform derives indices once Beta has bound all 3 plaintext datasets
# (rule_pairs, left_dictionary, right_dictionary) via the preferred-datasets
# endpoint. From Acme's side this means: wait until Beta's 04-encrypt has
# finished. The polling loop below covers that wait transparently.
wait_for_pending_rotation_indices "Beta to bind plaintext datasets so the platform can derive rotation indices"

INDICES_CSV="$(get_pending_rotation_indices_csv)"
if [[ -z "$INDICES_CSV" ]]; then
    info "Empty derived index set. No rotation keys needed; phase 4.5 done."
    exit 0
fi
INDEX_COUNT="$(echo "$INDICES_CSV" | tr ',' '\n' | wc -l)"
success "Platform-derived index set: $INDEX_COUNT indices."

# ---- Step 2 + 3: contribute as lead, upload rotation-round1 ----
# Idempotency: if rotation-round1.bin already exists from a prior partial
# run, reuse it. rotation_round1_initial uses fresh randomness each call,
# so regenerating produces a NEW share that won't match what the platform
# already accepted (the platform's idempotency keeps the first-accepted
# round-7 payload; subsequent uploads return "already submitted"). Reusing
# the local file keeps Acme's local + platform's stored byte-identical,
# which is required for combine to produce the correct result.
#
# Set JULENNY_FORCE_ROTATION_REGEN=1 to override; do this if the function-
# def's rotation indices changed (new derivation set) or your FHE secret
# share was rotated since the file was written.
MY_ROT_SHARE="$JL_KEYS_DIR/rotation-round1.bin"
if [[ -f "$MY_ROT_SHARE" && "${JULENNY_FORCE_ROTATION_REGEN:-0}" != "1" ]]; then
    info "Reusing existing Acme rotation-round1 share at $MY_ROT_SHARE ($(stat -c%s "$MY_ROT_SHARE") bytes)."
else
    info "Computing Acme's rotation-round1 contribution (lead)..."
    julenny-fhe crypto rotation-contribute \
        --role lead \
        --secret-key "$MY_SECRET" \
        --indices "$INDICES_CSV" \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --output "$MY_ROT_SHARE" \
        > /dev/null
    success "Acme's rotation-round1 share written -> $MY_ROT_SHARE ($(stat -c%s "$MY_ROT_SHARE") bytes)"
fi

ROUND_R1="$(get_rotation_round_offset round1)"
wrap_and_upload "$MY_ROT_SHARE" "$ROUND_R1" "rotation-round1"

# ---- Step 4: wait for Beta's continue share ----
wait_for_peer_share "rotation-round1-continue" 1800

PEER_CONTINUE="$JL_PEER_DIR/rotation-round1-continue.bin"
download_peer_share "rotation-round1-continue" "$PEER_CONTINUE"

# If the peer already finished the rotation while we got here, there is
# nothing to combine or upload - move on.
if [[ "$(get_rotation_status)" == "complete" ]]; then
    success "Rotation keysetup already complete; skipping combine."
    exit 0
fi

# ---- Step 5: combine locally, upload combine ----
# Acme's share (a) + Beta's continue (b) + joint_pk -> combined rotation key
# map. Both parties produce byte-identical output from the same inputs;
# platform verifies SHA256 match on submission.
ROT_COMBINED="$JL_KEYS_DIR/rotation-combined.bin"
info "Computing Acme's rotation-combine output..."
julenny-fhe crypto rotation-combine \
    --share-a "$MY_ROT_SHARE" \
    --share-b "$PEER_CONTINUE" \
    --joint-pk "$JOINT_PK" \
    --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
    --output "$ROT_COMBINED" \
    > /dev/null
success "Rotation key map combined -> $ROT_COMBINED ($(stat -c%s "$ROT_COMBINED") bytes)"

ROUND_COMBINE="$(get_rotation_round_offset combine)"
wrap_and_upload "$ROT_COMBINED" "$ROUND_COMBINE" "rotation-combine"

# ---- Step 6: wait for status -> complete (platform verifies SHA256 match) ----
wait_for_rotation_status "complete" 600

echo
success "Phase 4.5 done. Rotation keys are installed; execution can proceed."

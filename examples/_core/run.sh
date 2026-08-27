#!/usr/bin/env bash
# Shared single-command driver for a JuLenny collaboration. ONE script, BOTH
# sides. Reads the active permission's keysetupState from the platform and
# chains the numbered scripts. Fully interactive: it inspects platform state
# at startup and prompts; there are no flags except -h/--help.
#
# Which side we are (data-owner / data-consumer) comes from JULENNY_OUR_SIDE,
# set by the scenario's per-side bootstrap before this runs. The matching side
# profile (peer label, API view, secret-share filename, ...) is sourced below,
# and the only per-side behavior lives in the branches marked OWNER / CONSUMER.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Which side are we? Source the matching side profile BEFORE lib.sh, whose
# guard requires the profile vars. Export so the numbered subprocess scripts
# inherit the side too.
JULENNY_OUR_SIDE="${JULENNY_OUR_SIDE:?set JULENNY_OUR_SIDE=data-owner or data-consumer before running (the scenario bootstrap does this)}"
case "$JULENNY_OUR_SIDE" in
    data-owner|data-consumer) ;;
    *) echo "JULENNY_OUR_SIDE must be data-owner or data-consumer, got '$JULENNY_OUR_SIDE'" >&2; exit 2 ;;
esac
export JULENNY_OUR_SIDE
# shellcheck source=/dev/null
source "$SCRIPT_DIR/sides/${JULENNY_OUR_SIDE}.env"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

is_owner() { [[ "$JULENNY_OUR_SIDE" == "data-owner" ]]; }

# Migrate any pre-refactor workdir into the per-collab layout. No-op if already done.
migrate_legacy_workdir_if_needed

# Resolve the active collab (most recent if multiple) and point our path vars at it.
_jl_run_initial_jk="$(_jl_active_joint_key)"
[[ -n "$_jl_run_initial_jk" ]] && set_active_joint_key "$_jl_run_initial_jk"
unset _jl_run_initial_jk

for arg in "$@"; do
    case "$arg" in
        -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) err "Unknown argument: $arg (this script takes no flags - it asks at startup)"; exit 2 ;;
    esac
done

# Internal mode flags set by the interactive front matter below.
WATCH_MODE=false
NEW_TEST=false
SWITCH=false
ONLY_DECRYPT=false   # consumer-only path

# -------- State-detection helpers --------
peer_has_uploaded() {
    local msg_type="$1"
    local resp; resp="$(get_peer_messages 2>/dev/null || echo '{}')"
    echo "$resp" | jq -e --arg t "$msg_type" '.messages[]? | select(.messageType == $t)' > /dev/null 2>&1
}

execution_in_state() {
    local state="$1"
    local resp; resp="$(curl_jl GET \
        "/api/fhe-permissions/$JULENNY_PERMISSION_ID/executions?state=$state&limit=1" \
        2>/dev/null || echo '{}')"
    [[ -n "$(echo "$resp" | jq -r '.executions[0].id // empty')" ]]
}

# State of the most recently triggered execution (defined for BOTH sides; the
# owner driver used to reference this without defining it, so its menu always
# showed "none").
latest_execution_state() {
    local resp; resp="$(curl_jl GET \
        "/api/fhe-permissions/$JULENNY_PERMISSION_ID/executions?limit=1" \
        2>/dev/null || echo '{}')"
    echo "$resp" | jq -r '.executions[0].state // empty'
}

# Consumer-side: has the latest released execution already been decrypted here?
latest_released_decrypted() {
    local resp; resp="$(curl_jl GET \
        "/api/fhe-permissions/$JULENNY_PERMISSION_ID/executions?state=released&limit=1" \
        2>/dev/null || echo '{}')"
    local id; id="$(echo "$resp" | jq -r '.executions[0].id // empty')"
    [[ -n "$id" ]] && [[ -f "$JL_KEYS_DIR/my-partial-$id.bin" ]]
}

# -------- Gate (wait or exit) --------
gate() {
    local description="$1"
    local check_fn="$2"
    if $check_fn; then return 0; fi
    if $WATCH_MODE; then
        info "Watching: $description"
        local delay=15
        local elapsed=0
        while ! $check_fn; do
            sleep "$delay"
            elapsed=$(( elapsed + delay ))
            printf "  (still waiting for %s, %ds elapsed)\n" "$description" "$elapsed"
            (( delay < 120 )) && delay=$(( delay + 15 ))
        done
        success "$description satisfied."
        return 0
    fi
    echo
    info "Waiting for: $description"
    info "Rerun this script when ${JL_PEER_LABEL} is done (or use watch mode to poll here)."
    exit 0
}

# -------- Peer-state check fns --------
# We always gate on the PEER's bundle uploads. The lead (owner) publishes
# pk-share as bundle 1; the main (consumer) publishes relin-round1-continue.
# Each side waits for the other's bundle-1 message type; bundle 2 is the same
# message type both ways.
#
# An additive-only function (requiredEvalKeys: []) has no relin exchange at all, so
# bundle 1 is just the pk-share pair and there is no bundle 2. Waiting for
# relin-round1-continue there hangs forever: the platform goes straight to
# awaiting-finalization and refuses further messages.
if function_requires_relin_keys; then
    JL_NEEDS_RELIN=1
else
    JL_NEEDS_RELIN=0
fi

if is_owner; then
    if (( JL_NEEDS_RELIN )); then
        PEER_BUNDLE1_TYPE="relin-round1-continue"
        OWN_BUNDLE1_MARKER="lead-relin-r1.bin"
    else
        PEER_BUNDLE1_TYPE="pk-share"
        OWN_BUNDLE1_MARKER="fhe_public_key.bin"
    fi
else
    PEER_BUNDLE1_TYPE="pk-share"
    if (( JL_NEEDS_RELIN )); then
        OWN_BUNDLE1_MARKER="main-relin-r1.bin"
    else
        OWN_BUNDLE1_MARKER="joint_public_key.bin"
    fi
fi
peer_did_bundle1() { peer_has_uploaded "$PEER_BUNDLE1_TYPE"; }
peer_did_bundle2() { peer_has_uploaded "relin-round2"; }

# -------- Interactive front matter --------
SESSION_EXISTS=false
CURRENT_PERM=""
CURRENT_FN=""
LATEST_STATE=""
if [[ -f "$JL_CONFIG" ]]; then
    SESSION_EXISTS=true
    # shellcheck disable=SC1090
    source "$JL_CONFIG"
    CURRENT_PERM="${JULENNY_PERMISSION_ID:-}"
    if [[ -f "$JL_WORKDIR/function-def.json" ]]; then
        CURRENT_FN="$(jq -r '.slug // "?"' "$JL_WORKDIR/function-def.json") v$(jq -r '.version // "?"' "$JL_WORKDIR/function-def.json")"
    fi
    LATEST_STATE="$(latest_execution_state 2>/dev/null || echo "")"
    [[ -z "$LATEST_STATE" ]] && LATEST_STATE="none"
fi

echo
echo "============================================================"
echo " ${JL_OUR_LABEL^^} RUN: what would you like to do?"
echo "============================================================"
if $SESSION_EXISTS; then
    echo " Current permission: ${CURRENT_PERM:-?}"
    echo " Current function:   ${CURRENT_FN:-unknown}"
    echo " Latest exec state:  $LATEST_STATE"
    echo "------------------------------------------------------------"
    echo
    echo " 1) Continue the current cycle on this permission"
    if is_owner; then
        echo "    (resume whichever phase isn't done: keysetup, encrypt,"
        echo "     or release after ${JL_PEER_LABEL} triggers)."
    else
        echo "    (resume whichever phase isn't done: keysetup, encrypt,"
        echo "     trigger execution, or decrypt)."
    fi
    echo
    echo " 2) Start a NEW test cycle on this permission (keysetup reused)"
    echo
    echo " 3) Switch to a different permission or collaboration"
    echo
    if is_owner; then
        echo " 4) Quit"
        echo
        case "$LATEST_STATE" in
            awaiting-release|computing|queued) DEFAULT_ACTION="1" ;;
            released)                          DEFAULT_ACTION="2" ;;
            none|"")                           DEFAULT_ACTION="2" ;;
            *)                                 DEFAULT_ACTION="1" ;;
        esac
        prompt_for ACTION "Choose (1-4)" "$DEFAULT_ACTION"
    else
        echo " 4) Just decrypt the latest released execution"
        echo
        echo " 5) Quit"
        echo
        case "$LATEST_STATE" in
            released)                          DEFAULT_ACTION="4" ;;
            awaiting-release|computing|queued) DEFAULT_ACTION="1" ;;
            none|"")                           DEFAULT_ACTION="2" ;;
            *)                                 DEFAULT_ACTION="1" ;;
        esac
        prompt_for ACTION "Choose (1-5)" "$DEFAULT_ACTION"
    fi
else
    echo " No active session detected - looks like a first run on this machine."
    echo
    echo " 1) Set up: pick a collaboration + permission, fetch the function def."
    echo
    echo " 2) Quit"
    echo
    prompt_for ACTION "Choose (1-2)" "1"
fi

case "$ACTION" in
    1) ;;  # continue / first-time setup
    2)
        if $SESSION_EXISTS; then NEW_TEST=true; else info "Exiting."; exit 0; fi
        ;;
    3) SWITCH=true ;;
    4)
        if is_owner; then info "Exiting."; exit 0; else ONLY_DECRYPT=true; fi
        ;;
    5)
        if ! is_owner; then info "Exiting."; exit 0; else die "Invalid choice: $ACTION"; fi
        ;;
    *) die "Invalid choice: $ACTION" ;;
esac

echo
echo " Watch mode polls the platform until each peer-dependent phase is"
echo " satisfied. Without it, the script exits at the first wait and you"
echo " re-run when the peer is done."
prompt_for WATCH "Use watch mode? (Y/n)" "Y"
if [[ "${WATCH,,}" == "y" || -z "$WATCH" ]]; then
    WATCH_MODE=true
fi

# Switch clears the active-collab pointer so 00-init's picker re-runs. Per-collab
# state for the previous collab is preserved on disk under $JL_COLLABS_DIR/.
if $SWITCH; then
    info "Switching collab: clearing $JL_CURRENT_FILE."
    info "  Previous collab's state remains on disk under $JL_COLLABS_DIR/"
    rm -f "$JL_CURRENT_FILE"
    JL_WORKDIR=""; JL_CONFIG=""; JL_KEYS_DIR=""; JL_ENV_DIR=""; JL_PEER_DIR=""
fi

# -------- Main dispatch --------

# Phase 1: ensure config exists.
if [[ ! -f "$JL_CONFIG" ]]; then
    step "${JL_OUR_LABEL}: initial session setup"
    "$SCRIPT_DIR/$JL_ROLE_DIR/00-init.sh"
fi
load_session

# Re-fetch the function-def (mutable per slug/version); fails softly offline.
refresh_function_def

# Consumer-only shortcut: skip everything and just decrypt the latest released
# execution. 06-decrypt is self-contained (polls the platform, picks if many).
if $ONLY_DECRYPT; then
    step "${JL_OUR_LABEL}: decrypt latest released execution"
    "$SCRIPT_DIR/$JL_ROLE_DIR/06-decrypt.sh"
    exit 0
fi

# Show which permission + function this run will use.
if [[ -f "$JL_WORKDIR/function-def.json" ]]; then
    FN_SLUG="$(   jq -r '.slug    // "?"' "$JL_WORKDIR/function-def.json")"
    FN_VERSION="$(jq -r '.version // "?"' "$JL_WORKDIR/function-def.json")"
    FN_DESC="$(   jq -r '.description // ""' "$JL_WORKDIR/function-def.json")"
    echo
    echo "============================================================"
    echo " CURRENT PERMISSION / FUNCTION FOR THIS RUN:"
    echo "   Permission ID : $JULENNY_PERMISSION_ID"
    echo "   Function      : $FN_SLUG v$FN_VERSION"
    if [[ -n "$FN_DESC" ]]; then
        echo "   Description   : $FN_DESC" | fold -s -w 72 | sed '2,$s/^/                   /'
    fi
    echo "   (To use a different permission/function: switch at startup.)"
    echo "============================================================"
    echo
fi

# Phase 2: keysetup, driven by platform state.
KS_STATE="$(fetch_permission_state)"
info "Permission keysetup state (platform-reported): $KS_STATE"

case "$KS_STATE" in
    abandoned|failed-keysetup)
        die "Keysetup is in state '$KS_STATE'. Needs operator decision (retry or recreate) via the web UI."
        ;;
    complete)
        # Joint key completed by a prior keysetup pair. We can skip bundles ONLY
        # if THIS machine has its local secret share - otherwise the end-of-cycle
        # crypto would fail.
        if [[ ! -f "$JL_KEYS_DIR/$JL_SECRET_SHARE_FILE" ]]; then
            err "Joint key is complete on the platform, but this machine is missing"
            err "  $JL_KEYS_DIR/$JL_SECRET_SHARE_FILE"
            err "That secret share was produced by the original keysetup. Without it, this"
            err "machine can't contribute partial decryptions, so we can't proceed."
            echo
            err "Recovery: restore ~/.julenny-collab from the machine that participated in"
            err "the keysetup, or create a NEW collaboration so a fresh keysetup generates"
            err "a new secret share on this machine."
            die "Cannot proceed."
        fi
        info "Joint key is already complete (reused or finalized). Skipping bundles."
        ;;
    pending-keysetup|in-progress)
        if is_owner; then
            # Lead: publish bundle 1, wait for main's bundle 1, publish bundle 2, wait.
            if [[ ! -f "$JL_KEYS_DIR/$OWN_BUNDLE1_MARKER" ]]; then
                step "${JL_OUR_LABEL}: keysetup bundle 1"
                "$SCRIPT_DIR/$JL_ROLE_DIR/01-keysetup-1.sh"
            fi
            gate "${JL_PEER_LABEL} to complete bundle 1 ($PEER_BUNDLE1_TYPE)" peer_did_bundle1
            if (( JL_NEEDS_RELIN )); then
                if [[ ! -f "$JL_KEYS_DIR/lead-relin-r2.bin" ]]; then
                    step "${JL_OUR_LABEL}: keysetup bundle 2"
                    "$SCRIPT_DIR/$JL_ROLE_DIR/02-keysetup-2.sh"
                fi
                gate "${JL_PEER_LABEL} to complete bundle 2 (relin-round2)" peer_did_bundle2
            fi
        else
            # Main: wait for lead's bundle 1, publish, wait for bundle 2, publish.
            if [[ ! -f "$JL_KEYS_DIR/$OWN_BUNDLE1_MARKER" ]]; then
                gate "${JL_PEER_LABEL} to publish bundle 1 (pk-share)" peer_did_bundle1
                step "${JL_OUR_LABEL}: keysetup bundle 1"
                "$SCRIPT_DIR/$JL_ROLE_DIR/01-keysetup-1.sh"
            fi
            if (( JL_NEEDS_RELIN )); then
                if [[ ! -f "$JL_KEYS_DIR/main-relin-r2.bin" ]]; then
                    gate "${JL_PEER_LABEL} to publish bundle 2 (relin-round2)" peer_did_bundle2
                    step "${JL_OUR_LABEL}: keysetup bundle 2"
                    "$SCRIPT_DIR/$JL_ROLE_DIR/02-keysetup-2.sh"
                fi
            fi
        fi
        KS_STATE="$(fetch_permission_state)"
        info "Permission keysetup state (after bundles): $KS_STATE"
        ;;
    *)
        warn "Unrecognized keysetupState: '$KS_STATE'. Proceeding optimistically."
        ;;
esac

# Phase 3: finalize if needed (fresh keysetup, or a reused joint key whose
# finalKeys row for THIS permission isn't populated yet). 03 is idempotent.
if [[ "$KS_STATE" == "awaiting-finalization" || "$KS_STATE" == "complete" ]]; then
    step "${JL_OUR_LABEL}: finalize keysetup"
    "$SCRIPT_DIR/$JL_ROLE_DIR/03-finalize-keysetup.sh"
fi

# Phase 4: encrypt + upload/declare local dataset(s).
# Gate on whether THIS permission's required inputs (for OUR role) are all
# declared - NOT on a project-wide dataset count. In a multi-function collab,
# datasets declared for one permission must not suppress the upload/declare
# step for a DIFFERENT permission that shares the same project (that bug left
# a new-function permission with no declared inputs and hung the trigger).
case "$JULENNY_OUR_SIDE" in
    data-owner)    MY_FN_ROLE="dataOwner" ;;
    data-consumer) MY_FN_ROLE="queryAnalyst" ;;
    *) die "Unknown JULENNY_OUR_SIDE='$JULENNY_OUR_SIDE'" ;;
esac
mapfile -t MY_INPUT_NAMES < <(jq -r --arg r "$MY_FN_ROLE" \
    '.inputs[]? | select(.role == $r) | .name' "$JL_WORKDIR/function-def.json")
DECLARED_JSON="$(curl_jl GET "/api/fhe-permissions/$JULENNY_PERMISSION_ID/preferred-datasets")"
UNDECLARED=()
for in_name in "${MY_INPUT_NAMES[@]}"; do
    if [[ -z "$(echo "$DECLARED_JSON" | jq -r --arg n "$in_name" '.[$n].datasetId // empty')" ]]; then
        UNDECLARED+=("$in_name")
    fi
done

if (( ${#MY_INPUT_NAMES[@]} == 0 )); then
    info "Function declares no inputs for ${JL_OUR_LABEL}'s role ($MY_FN_ROLE); nothing to upload."
elif $NEW_TEST; then
    step "${JL_OUR_LABEL}: encrypt and upload dataset (new test cycle)"
    JULENNY_NEW_TEST=1 "$SCRIPT_DIR/$JL_ROLE_DIR/04-encrypt.sh"
elif (( ${#UNDECLARED[@]} > 0 )); then
    step "${JL_OUR_LABEL}: declare/upload dataset(s) for this permission"
    info "Inputs not yet declared for this permission: ${UNDECLARED[*]}"
    info "(Pick an existing dataset to reuse it, or 'u' to upload a fresh one.)"
    "$SCRIPT_DIR/$JL_ROLE_DIR/04-encrypt.sh"
else
    info "All of ${JL_OUR_LABEL}'s inputs are already declared for this permission. Skipping upload."
fi

# Phase 4.5: rotation key augmentation. No-op unless the function-def declares
# requiredEvalKeys including rotation; the script decides.
step "${JL_OUR_LABEL}: rotation key augmentation (if required by function)"
"$SCRIPT_DIR/$JL_ROLE_DIR/04.5-rotation-keysetup.sh"

# Phase 5: end-of-cycle. The end-of-cycle SCRIPT (05-release / 06-decrypt) each
# dispatch internally on resultVisibility (releaser_flow / viewer_flow). The
# difference here is structural: the consumer triggers the execution; the owner
# does not, it waits for the consumer's trigger and then releases.
if is_owner; then
    if execution_in_state "released" && ! execution_in_state "awaiting-release" && am_i_releaser; then
        if ! $NEW_TEST; then
            info "Latest execution is already released."
            prompt_for ACTION "Wait for a new test cycle to be triggered by ${JL_PEER_LABEL}? (y/N)" "N"
            if [[ "${ACTION,,}" != "y" ]]; then
                info "Exiting. (Start a new test cycle next time to skip this prompt.)"
                exit 0
            fi
            NEW_TEST=true
        fi
        info "Waiting for ${JL_PEER_LABEL} to trigger a new execution..."
    fi
    step "${JL_OUR_LABEL}: end-of-cycle (resultVisibility: $JULENNY_RESULT_VISIBILITY)"
    "$SCRIPT_DIR/$JL_ROLE_DIR/05-release.sh"
    echo
    success "All ${JL_OUR_LABEL} phases done."
else
    # Consumer: trigger a new execution if needed, then decrypt.
    ANY_EXEC=false
    if execution_in_state "awaiting-release" \
           || execution_in_state "released" \
           || execution_in_state "computing" \
           || execution_in_state "queued"; then
        ANY_EXEC=true
    fi

    NEED_TRIGGER=false
    if ! $ANY_EXEC; then
        NEED_TRIGGER=true
    elif $NEW_TEST; then
        info "New test cycle: triggering a fresh execution even though prior ones exist."
        NEED_TRIGGER=true
    elif latest_released_decrypted; then
        info "Latest released execution is already decrypted on this machine."
        prompt_for ACTION "Start a new test cycle (trigger a fresh execution)? (y/N)" "N"
        if [[ "${ACTION,,}" == "y" ]]; then
            NEW_TEST=true
            NEED_TRIGGER=true
        else
            info "Exiting. (Start a new test cycle next time to skip this prompt.)"
            exit 0
        fi
    fi

    if $NEED_TRIGGER; then
        gate "all function inputs to be declared by both sides" all_required_inputs_declared
        step "${JL_OUR_LABEL}: trigger function execution"
        "$SCRIPT_DIR/$JL_ROLE_DIR/05-run-query.sh"
    fi

    step "${JL_OUR_LABEL}: end-of-cycle (resultVisibility: $JULENNY_RESULT_VISIBILITY)"
    "$SCRIPT_DIR/$JL_ROLE_DIR/06-decrypt.sh"
    echo
    success "All ${JL_OUR_LABEL} phases done. Answer is above."
fi

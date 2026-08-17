#!/usr/bin/env bash
# Data-consumer (keysetup main) session setup.
#
# Function-agnostic: this backs every scenario, because the function is picked
# from the platform's live list at run time rather than hardcoded here.
#
#   1. The collaboration picker lists existing data-consumer collaborations
#      up front and appends an "n) Create a NEW collaboration + permission"
#      option, mirroring the dataset picker in 04-encrypt.sh and the
#      data-owner picker. Picking 'n' POSTs to /api/fhe-projects and
#      /api/fhe-permissions (see lib.sh's create_collaboration /
#      create_permission helpers). On this side the 'n' path is primarily
#      useful in the single-machine smoke-test scenario where one shell drives
#      both sides; in the standard two-party flow, the data owner creates the
#      collaboration and the consumer picks an existing one. With zero existing
#      collaborations, 'n' becomes the only and default choice.
#   2. No scheme guard: both BFV and CKKS are supported by the toolkit core,
#      so the function-def's declared scheme is let through.
#
# Note: the permission picker (once a collaboration is picked) does NOT offer
# 'n) Create new permission' because only the data owner (Acme) can permission a
# permission. If zero permissions are found under a Beta-side collaboration,
# the script tells Beta to wait for Acme to add one.
#
# Saves everything to ~/.julenny-collab/config.env so later scripts pick
# it up automatically.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../sides/data-consumer.env
source "$SCRIPT_DIR/../sides/data-consumer.env"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"

mkdir -p "$JL_ROOT" "$JL_SIGNING_DIR" "$JL_COLLABS_DIR"
chmod 700 "$JL_ROOT"

migrate_legacy_workdir_if_needed

step "JuLenny collaboration setup ($JL_OUR_LABEL: $JL_ROLE_LABEL)"

# -------- API connection --------
# An inherited JULENNY_API_BASE is honoured so a run can be pointed at a staging
# host, but it is announced rather than applied silently: a stale value sends
# every call to the wrong host, and the only symptom is an empty collaboration
# list, which reads as "you have no collaborations".
JULENNY_API_BASE="${JULENNY_API_BASE:-https://julenny.net}"
if [[ "$JULENNY_API_BASE" != "https://julenny.net" ]]; then
    warn "Using a non-default platform host from JULENNY_API_BASE:"
    warn "    $JULENNY_API_BASE"
    warn "Unset JULENNY_API_BASE to use https://julenny.net."
fi

# A key already exported in the environment wins, so the operator can supply it
# without an interactive paste:
#     export JULENNY_API_KEY="$(cat ~/my-key)"
# Terminals vary in how they treat a pasted secret at a hidden prompt, and this
# is also the route a scripted or CI run would take.
if [[ -n "${JULENNY_API_KEY:-}" ]]; then
    info "Using JULENNY_API_KEY from the environment (${#JULENNY_API_KEY} characters)."
else
    prompt_secret JULENNY_API_KEY "Beta's API key (starts with sk_live_)"
fi
[[ "$JULENNY_API_KEY" == sk_live_* ]] || die "API key must start with sk_live_"

export JULENNY_API_BASE JULENNY_API_KEY

# -------- Pick OR create collaboration --------
# Fetch existing data-consumer collaborations up front, list them, and
# append an "n) Create a NEW collaboration + permission" option. Same shape as
# the dataset picker in 04-encrypt.sh and the Acme-side picker. Picking
# 'n' drops into the single-machine smoke-test creation flow (uncommon for
# Beta in real two-party scenarios).
step "Fetching your collaborations..."
ALL_PROJECTS="$(list_collaborations)"
# Primary signal: the platform's yourPermissionRoles array (dataOwner/
# dataConsumer per collab, added 2026-06-18); permissionCount>0 is a fallback.
# Show collaborations where THIS account has at least one data-consumer
# permission, regardless of who owns the project. permissionCount is derived
# from view=received (see list_collaborations), so >0 means "I'm the consumer
# in >=1 active permission here". Filtering on project ownership instead
# (ownerCompanyName != null) wrongly hid collabs this account created itself
# (single-machine setup, or any consumer-initiated collab) even though
# yourRole on those permissions is dataConsumer.
PARTNER_PROJECTS="$(echo "$ALL_PROJECTS" \
    | jq '[.[] | select(((.yourPermissionRoles // []) | any(. == "dataConsumer")) or (.permissionCount > 0))] | sort_by(.createdAt) | reverse')"
PROJECT_COUNT="$(echo "$PARTNER_PROJECTS" | jq 'length')"

echo
if (( PROJECT_COUNT > 0 )); then
    info "Active collaborations where you're the data consumer (newest first):"
    echo "$PARTNER_PROJECTS" \
        | jq -r 'to_entries[] | "  [\(.key + 1)] \(.value.name // "(unnamed)")  |  peer: \(.value.ownerCompanyName // .value.partnerCompanyName // "?")  |  \(.value.permissionCount) permission(s)  |  keysetup: \(.value.keysetupState // "n/a")  |  created \(.value.createdAt // "?" | .[0:10])  |  id: \(.value.id)"'
else
    info "No active collaborations where you're the data consumer."
fi
echo "  n) Create a NEW collaboration + permission via the API"
echo "     (uncommon for Beta - usually Acme initiates. Useful for single-machine smoke tests.)"
echo

if (( PROJECT_COUNT == 0 )); then
    PROJECT_CHOICE="n"
    info "No existing collaborations; defaulting to 'n' (create new)."
else
    prompt_for PROJECT_CHOICE "Pick a collaboration (1-$PROJECT_COUNT, or n)" "1"
fi

JULENNY_PROJECT_ID=""
JULENNY_JOINT_KEY_ID=""
PERM_ID=""

if [[ "${PROJECT_CHOICE,,}" == "n" ]]; then
    # -------- Create-new path (single-machine smoke-test usage) --------
    # Beta as project initiator is unusual; in real flows Acme creates
    # the project and adds Beta as partner. We expose the API path here
    # so single-machine tests can drive both sides from one shell.
    warn "Heads up: in the normal two-party flow, Acme creates the collaboration."
    warn "Use this path only for single-machine smoke tests where you're driving both sides."
    echo

    echo "Which scheme should the function use?"
    echo "  1) CKKS  (rule-based-cross-match, real-valued analytics, etc.)"
    echo "  2) BFV   (joint-record-overlap, exact-integer functions)"
    echo "  3) Any"
    prompt_for SCHEME_CHOICE "Choose (1-3)" "1"

    case "$SCHEME_CHOICE" in
        1) FUNCS_JSON="$(list_functions_by_scheme CKKS)" ; SCHEME_LABEL="CKKS" ;;
        2) FUNCS_JSON="$(list_functions_by_scheme BFV)"  ; SCHEME_LABEL="BFV"  ;;
        3) FUNCS_JSON="$(list_functions)"                ; SCHEME_LABEL="any" ;;
        *) die "Invalid choice: $SCHEME_CHOICE" ;;
    esac

    FUNC_COUNT="$(echo "$FUNCS_JSON" | jq 'length')"
    if (( FUNC_COUNT == 0 )); then
        die "No functions found for scheme '$SCHEME_LABEL'."
    fi

    echo
    info "Functions available (scheme=$SCHEME_LABEL):"
    echo "$FUNCS_JSON" \
        | jq -r 'to_entries[] | "  [\(.key + 1)] \(.value.slug) v\(.value.version // "?")  |  scheme: \(.value.scheme // "?")  |  \(.value.description // "" | .[0:80])"'
    echo

    if (( FUNC_COUNT == 1 )); then
        FUNC_PICK=1
        info "Only one function; selecting [1]."
    else
        prompt_for FUNC_PICK "Pick a function (1-$FUNC_COUNT)" "1"
    fi
    FN_OBJ="$(echo "$FUNCS_JSON" | jq ".[$((FUNC_PICK - 1))]")"
    FN_SLUG="$(echo "$FN_OBJ" | jq -r '.slug')"
    FN_VERSION="$(echo "$FN_OBJ" | jq -r '.version')"

    # Operator types Acme's Collaboration ID (XXXX-XXXX, visible on Acme's
    # Company page in the JuLenny web UI). It is passed straight to the API,
    # which resolves it internally - the toolkit never handles a company id.
    info "Ask Acme for their Collaboration ID (format XXXX-XXXX, visible on"
    info "their Company page in the JuLenny web UI)."
    prompt_for PARTNER_INPUT "Data-owner (Acme) Collaboration ID (XXXX-XXXX)"
    [[ -n "$PARTNER_INPUT" ]] || die "Partner Collaboration ID is required."
    PARTNER_ID="$PARTNER_INPUT"

    DEFAULT_COLLAB_NAME="Beta x Acme ($FN_SLUG, $(date +%Y-%m-%d))"
    prompt_for COLLAB_NAME "Collaboration name" "$DEFAULT_COLLAB_NAME"

    step "Creating collaboration via POST /api/fhe-projects..."
    JULENNY_PROJECT_ID="$(create_collaboration "$PARTNER_ID" "$COLLAB_NAME")" \
        || die "Collaboration creation failed."
    success "Collaboration created: $JULENNY_PROJECT_ID"

    # When Beta creates the project, Beta is the project's owner-from-API-
    # perspective; the platform records dataOwner / dataConsumer based on
    # permission body (where dataConsumerCompanyId is passed). For a Beta-
    # initiated test we pass our own company id as the consumer here so
    # the resulting permission has Beta as consumer (matching the normal flow).
    # The data-owner side of the permission defaults to the project initiator
    # (i.e. Acme is set by the partner field). Confirm by reading back
    # below.
    # Ask the operator how many executions this permission should allow. The
    # data owner decides this; the platform decrements per execution.
    prompt_for ALLOWED_EXEC "How many executions should this permission allow?" "10"
    [[ "$ALLOWED_EXEC" =~ ^[0-9]+$ ]] && (( ALLOWED_EXEC > 0 )) \
        || die "Allowed executions must be a positive integer (got: '$ALLOWED_EXEC')."

    # Optional expiration. Operator decides; blank = no expiry.
    prompt_for EXPIRY_DAYS "Permission expiration in days from now (blank = no expiry)" ""
    EXPIRATION=""
    if [[ -n "$EXPIRY_DAYS" ]]; then
        [[ "$EXPIRY_DAYS" =~ ^[0-9]+$ ]] && (( EXPIRY_DAYS > 0 )) \
            || die "Expiration days must be a positive integer or blank (got: '$EXPIRY_DAYS')."
        EXPIRATION="$(date -u -d "+${EXPIRY_DAYS} days" +%Y-%m-%dT%H:%M:%S.%3NZ)"
        info "Permission will expire: $EXPIRATION"
    else
        info "Permission will not expire (no expiration date set)."
    fi

    step "Creating permission via POST /api/fhe-permissions..."
    # The platform resolves the partner Collaboration ID internally and
    # derives the acting company from the api key; no company id is handled here.
    PERM_ID="$(create_permission "$JULENNY_PROJECT_ID" "$FN_SLUG" "$FN_VERSION" "$PARTNER_ID" "$ALLOWED_EXEC" "dataConsumer" "$EXPIRATION")" \
        || die "Permission creation failed."
    success "Permission created: $PERM_ID  ($FN_SLUG v$FN_VERSION)"

    info "Resolving joint key id from refreshed project doc..."
    ALL_PROJECTS="$(list_collaborations)"
    JULENNY_JOINT_KEY_ID="$(echo "$ALL_PROJECTS" \
        | jq -r --arg id "$JULENNY_PROJECT_ID" '.[] | select(.id == $id) | .jointKeyId // empty')"
    if [[ -z "$JULENNY_JOINT_KEY_ID" ]]; then
        warn "Project has no jointKeyId yet. The keysetup state machine will create it"
        warn "when the first peer message lands; subsequent scripts will pick it up."
    else
        success "Joint key: $JULENNY_JOINT_KEY_ID"
    fi
else
    # -------- Resolve the chosen existing collaboration --------
    if ! [[ "$PROJECT_CHOICE" =~ ^[0-9]+$ ]] || (( PROJECT_CHOICE < 1 || PROJECT_CHOICE > PROJECT_COUNT )); then
        die "Invalid choice: '$PROJECT_CHOICE' (must be 1-$PROJECT_COUNT or 'n')"
    fi

    PROJECT_OBJ="$(echo "$PARTNER_PROJECTS" | jq ".[$((PROJECT_CHOICE - 1))]")"
    JULENNY_PROJECT_ID="$(echo "$PROJECT_OBJ" | jq -r '.id')"
    JULENNY_JOINT_KEY_ID="$(echo "$PROJECT_OBJ" | jq -r '.jointKeyId // empty')"
    [[ -n "$JULENNY_JOINT_KEY_ID" ]] \
        || die "Selected collaboration has no jointKeyId. Cannot proceed."

    success "Collaboration: $JULENNY_PROJECT_ID  (joint key: $JULENNY_JOINT_KEY_ID)"

    # -------- Pick a permission under this collaboration --------
    # Beta can't create permissions (only the data owner can), so there's no
    # 'n) Create new' option here. If no permissions exist, Beta must wait
    # for Acme to add one.
    step "Fetching permissions under this collaboration..."
    PERMISSIONS_JSON="$(list_permissions_for_joint_key "$JULENNY_JOINT_KEY_ID")"
    PERMISSION_COUNT="$(echo "$PERMISSIONS_JSON" | jq 'length')"

    if (( PERMISSION_COUNT == 0 )); then
        err "No active permissions found under joint key $JULENNY_JOINT_KEY_ID."
        err "Ask the data owner to add a permission, then re-run."
        exit 1
    fi

    PERMISSIONS_JSON="$(echo "$PERMISSIONS_JSON" | jq 'sort_by(.createdAt) | reverse')"

    echo
    info "Active permissions in this collaboration (newest first):"
    echo "$PERMISSIONS_JSON" \
        | jq -r 'to_entries[] | "  [\(.key + 1)] \(.value.fheFunction) v\(.value.functionVersion // "?")  |  execs left: \(.value.remainingExecutions // "?")/\(.value.allowedExecutions // "?")  |  scheme: \(.value.cryptoContextSpec // "?")  |  created \(.value.createdAt // "?" | .[0:10])  |  id: \(.value.id)"'
    echo

    if (( PERMISSION_COUNT == 1 )); then
        PERMISSION_CHOICE=1
        info "Only one permission; selecting [1]."
    else
        prompt_for PERMISSION_CHOICE "Pick a permission (1-$PERMISSION_COUNT)" "1"
        if ! [[ "$PERMISSION_CHOICE" =~ ^[0-9]+$ ]] || (( PERMISSION_CHOICE < 1 || PERMISSION_CHOICE > PERMISSION_COUNT )); then
            die "Invalid choice: $PERMISSION_CHOICE"
        fi
    fi

    PERM_OBJ="$(echo "$PERMISSIONS_JSON" | jq ".[$((PERMISSION_CHOICE - 1))]")"
    PERM_ID="$(echo "$PERM_OBJ" | jq -r '.id')"
fi

# -------- Activate the per-collab workdir --------
# Now that we know the joint key id, switch JL_WORKDIR / JL_CONFIG / JL_KEYS_DIR
# etc. to point at this collab's subdir (creating it if needed). All later
# writes (config.env, function-def.json, keysetup bundles, ...) land there,
# so two collaborations on the same machine never collide.
if [[ -z "$JULENNY_JOINT_KEY_ID" ]]; then
    # Edge case: the create-new branch wasn't able to resolve the joint key
    # id from the project doc yet. Re-fetch it from the permission, which
    # will have it by the time this code runs.
    JULENNY_JOINT_KEY_ID="$(curl_jl GET "/api/fhe-permissions?status=active&view=${JL_PERM_VIEW}" \
        | jq -r --arg id "$PERM_ID" '.permissions[]? | select(.id == $id) | .jointKeyId // empty')"
    [[ -n "$JULENNY_JOINT_KEY_ID" ]] \
        || die "Could not resolve joint key id for permission $PERM_ID; cannot proceed."
fi
set_active_joint_key "$JULENNY_JOINT_KEY_ID"

if [[ -f "$JL_CONFIG" ]]; then
    info "Refreshing session config for the selected permission ($JL_CONFIG)."
    rm -f "$JL_CONFIG"
fi

# -------- Re-fetch picked permission via the self-healing list endpoint --------
PERM_OBJ="$(fetch_permission "$PERM_ID")"

YOUR_ROLE="$(echo "$PERM_OBJ" | jq -r '.yourRole // empty')"
PEER_COLLAB="$(echo "$PERM_OBJ" | jq -r '.dataOwnerCollaborationId // empty')"
FN_SLUG="$(echo "$PERM_OBJ" | jq -r '.fheFunction')"
FN_VERSION="$(echo "$PERM_OBJ" | jq -r '.functionVersion')"
CTX_SPEC="$(echo "$PERM_OBJ" | jq -r '.cryptoContextSpec // empty')"
# resultVisibility (0.5.5): read from permission, default to "dataConsumer"
# for permissions that pre-date this field. Beta never creates permissions
# herself (Acme is the collab creator), so this is always platform-sourced.
JULENNY_RESULT_VISIBILITY="$(echo "$PERM_OBJ" | jq -r '.resultVisibility // "dataConsumer"')"

[[ -z "$YOUR_ROLE" || "$YOUR_ROLE" == "dataConsumer" ]] \
    || die "Permission yourRole is '$YOUR_ROLE'; expected dataConsumer. Run from the data-consumer side."
[[ -n "$FN_SLUG" && "$FN_SLUG" != "null" ]] \
    || die "Selected permission has no fheFunction slug."
[[ -n "$FN_VERSION" && "$FN_VERSION" != "null" ]] \
    || die "Selected permission has no functionVersion."
[[ -n "$CTX_SPEC" ]] \
    || die "Selected permission has no cryptoContextSpec. Cannot register signing key."

success "Permission resolved: $PERM_ID  ($FN_SLUG v$FN_VERSION)"
info "  Beta is:     data consumer / keysetup main"
info "  Acme (peer): data owner / keysetup lead${PEER_COLLAB:+ (collab $PEER_COLLAB)}"

# -------- Default for downstream prompts --------
# JULENNY_INPUT_CSV is referenced as a default in the o)Other fallback prompts
# in 04-encrypt and 06-decrypt. We silently populate it with the first file
# (alphabetically) under $SCRIPT_DIR/data/, if such a file exists. No prompt
# at 00-init time; the operator never has to pick a single "input" file when
# the function actually has 4 of them. Downstream pickers still ask per-input.
JULENNY_INPUT_CSV=""
if [[ -d "$SCRIPT_DIR/data" ]]; then
    _first_data_file="$(find "$SCRIPT_DIR/data" -maxdepth 1 -type f | sort | head -1)"
    [[ -n "$_first_data_file" ]] && JULENNY_INPUT_CSV="$_first_data_file"
    unset _first_data_file
fi

# -------- Fetch function definition --------
step "Fetching function definition from platform..."
FN_DEF_PATH="$JL_WORKDIR/function-def.json"
FN_DEF_RESP="$(curl_jl GET "/api/functions/$FN_SLUG/$FN_VERSION/definition")"
if echo "$FN_DEF_RESP" | jq -e '.error' > /dev/null 2>&1; then
    err "Failed to fetch function-def for $FN_SLUG@$FN_VERSION:"
    echo "$FN_DEF_RESP" | jq . >&2
    die "Cannot proceed without function definition."
fi
echo "$FN_DEF_RESP" | jq . > "$FN_DEF_PATH"
chmod 600 "$FN_DEF_PATH"
success "Function definition saved: $FN_DEF_PATH ($FN_SLUG v$FN_VERSION)"

# -------- Scheme record (no guard) --------
JULENNY_SCHEME="$(echo "$FN_DEF_RESP" | jq -r '.scheme // empty')"
[[ -n "$JULENNY_SCHEME" ]] || die "Function definition has no scheme field; cannot proceed."
case "${JULENNY_SCHEME^^}" in
    BFV|CKKS) info "  Scheme:      $JULENNY_SCHEME ($CTX_SPEC)" ;;
    *)        die "Unknown / unsupported scheme: $JULENNY_SCHEME" ;;
esac

# -------- Signing keypair --------
SIGNING_SECRET="$JL_SIGNING_SECRET"
SIGNING_PUBLIC="$JL_SIGNING_PUBLIC"

if [[ -f "$SIGNING_SECRET" && -f "$SIGNING_PUBLIC" ]]; then
    info "Existing signing keypair found at $SIGNING_SECRET"
    prompt_for REGEN "Regenerate? (y/N)" "N"
    if [[ "${REGEN,,}" == "y" ]]; then
        rm -f "$SIGNING_SECRET" "$SIGNING_PUBLIC"
    fi
fi

if [[ ! -f "$SIGNING_SECRET" ]]; then
    step "Generating Ed25519 signing keypair for Beta"
    julenny-toolkit crypto signing-keygen \
        --output-secret "$SIGNING_SECRET" \
        --output-public "$SIGNING_PUBLIC" \
        > /dev/null
    success "Signing keypair generated."
fi

# -------- Register signing public key --------
step "Registering Beta's signing public key with the platform..."
SIGNING_PUBLIC_HEX="$(xxd -p -c 256 "$SIGNING_PUBLIC" | tr -d '\n')"
[[ ${#SIGNING_PUBLIC_HEX} -eq 64 ]] \
    || die "Signing public key hex is ${#SIGNING_PUBLIC_HEX} chars, expected 64."

REG_BODY="$(jq -n --arg ctx "$CTX_SPEC" --arg hex "$SIGNING_PUBLIC_HEX" \
    '{cryptoContextSpec: $ctx, signingPublicKeyHex: $hex}')"

REG_RESP="$(curl_jl POST "/api/companies/me/fhe-public-keys" \
    -H "Content-Type: application/json" \
    --data-binary "$REG_BODY")"

if echo "$REG_RESP" | jq -e '.error' > /dev/null 2>&1; then
    err "Failed to register signing public key:"
    echo "$REG_RESP" | jq . >&2
    die "Cannot proceed. As a fallback you can upload $SIGNING_PUBLIC via /company/collaborate/$JULENNY_PROJECT_ID."
fi
success "Signing public key registered for crypto context: $CTX_SPEC"

# -------- Write config.env --------
cat > "$JL_CONFIG" <<EOF
# JuLenny rule-based-cross-match session config for Beta (data consumer / main).
JULENNY_API_BASE="$JULENNY_API_BASE"
JULENNY_API_KEY="$JULENNY_API_KEY"
JULENNY_PROJECT_ID="$JULENNY_PROJECT_ID"
JULENNY_JOINT_KEY_ID="$JULENNY_JOINT_KEY_ID"
JULENNY_PERMISSION_ID="$PERM_ID"
JULENNY_OUR_SIDE="data-consumer"
JULENNY_ROLE="main"
JULENNY_RESULT_VISIBILITY="$JULENNY_RESULT_VISIBILITY"
JULENNY_SCHEME="$JULENNY_SCHEME"
JULENNY_CRYPTO_CONTEXT_SPEC="$CTX_SPEC"
JULENNY_INPUT_CSV="$JULENNY_INPUT_CSV"
JULENNY_SIGNING_SECRET="$SIGNING_SECRET"
JULENNY_SIGNING_PUBLIC="$SIGNING_PUBLIC"
EOF
chmod 600 "$JL_CONFIG"

success "Session config written to $JL_CONFIG"
echo
info "Next step (on this machine):"
echo "  $SCRIPT_DIR/run.sh             # one-command driver"
echo "  $SCRIPT_DIR/01-keysetup-1.sh   # or run the numbered scripts in order"

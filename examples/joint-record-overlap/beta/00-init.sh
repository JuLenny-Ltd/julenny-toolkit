#!/usr/bin/env bash
# Beta (data consumer / keysetup main) session setup.
#
# Run once per machine, per collaboration. Walks you through:
#   1. Picking a collaboration where you're the data consumer (partner).
#   2. Picking a permission (permission) under that collaboration.
#   3. Pointing at the local CSV you want encrypted.
#   4. Generating + registering your signing keypair.
#
# Saves everything to ~/.julenny-collab/config.env so later scripts pick it
# up automatically.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"

mkdir -p "$JL_ROOT" "$JL_SIGNING_DIR" "$JL_COLLABS_DIR"
chmod 700 "$JL_ROOT"

migrate_legacy_workdir_if_needed

step "JuLenny demo session setup (Beta: data consumer / main)"

# -------- API connection --------
# Platform URL. Defaults to the public JuLenny endpoint. To run against a
# non-production deployment (staging, a local emulator, or any alternate
# URL), export JULENNY_API_BASE in your shell before running this script:
#   export JULENNY_API_BASE="https://<your-staging-host>"
#   ./00-init.sh
JULENNY_API_BASE="${JULENNY_API_BASE:-https://julenny.net}"

prompt_secret JULENNY_API_KEY "Beta's API key (starts with sk_live_)"
[[ "$JULENNY_API_KEY" == sk_live_* ]] || die "API key must start with sk_live_"

export JULENNY_API_BASE JULENNY_API_KEY

# -------- Pick collaboration --------
# A collaboration (project) is a (owner, you, function-set) tuple with a
# shared joint key. One collaboration can hold many permissions (permissions).
# We list only collaborations where you're the partner (data consumer);
# collaborations where you're the owner belong to the acme/ folder.
step "Fetching your collaborations..."
ALL_PROJECTS="$(list_collaborations)"
PARTNER_PROJECTS="$(echo "$ALL_PROJECTS" | jq '[.[] | select(.ownerCompanyName != null)]')"
PROJECT_COUNT="$(echo "$PARTNER_PROJECTS" | jq 'length')"

if (( PROJECT_COUNT == 0 )); then
    err "No collaborations found where you are the data consumer (partner)."
    err "Ask the data owner to create one and add you as the partner, then re-run this script."
    exit 1
fi

echo
info "Active collaborations where you're the data consumer (newest first):"
echo "$PARTNER_PROJECTS" \
    | jq -r 'to_entries[] | "  [\(.key + 1)] \(.value.name // "(unnamed)")  |  owner: \(.value.ownerCompanyName // .value.companyId)  |  \(.value.permissionCount) permission(s)  |  keysetup: \(.value.keysetupState // "n/a")  |  created \(.value.createdAt // "?" | .[0:10])"'
echo

if (( PROJECT_COUNT == 1 )); then
    PROJECT_CHOICE=1
    info "Only one collaboration; selecting [1]."
else
    prompt_for PROJECT_CHOICE "Pick a collaboration (1-$PROJECT_COUNT)" "1"
    if ! [[ "$PROJECT_CHOICE" =~ ^[0-9]+$ ]] || (( PROJECT_CHOICE < 1 || PROJECT_CHOICE > PROJECT_COUNT )); then
        die "Invalid choice: $PROJECT_CHOICE"
    fi
fi

PROJECT_OBJ="$(echo "$PARTNER_PROJECTS" | jq ".[$((PROJECT_CHOICE - 1))]")"
JULENNY_PROJECT_ID="$(echo "$PROJECT_OBJ" | jq -r '.id')"
JULENNY_JOINT_KEY_ID="$(echo "$PROJECT_OBJ" | jq -r '.jointKeyId // empty')"
[[ -n "$JULENNY_JOINT_KEY_ID" ]] \
    || die "Selected collaboration has no jointKeyId. Cannot proceed."

success "Collaboration: $JULENNY_PROJECT_ID  (joint key: $JULENNY_JOINT_KEY_ID)"

# -------- Activate the per-collab workdir --------
# Now that we know the joint key id, switch JL_WORKDIR / JL_CONFIG / JL_KEYS_DIR
# etc. to point at this collab's subdir (creating it if needed). All later
# writes (config.env, function-def.json, keysetup bundles, ...) land there,
# so two collaborations on the same machine never collide.
set_active_joint_key "$JULENNY_JOINT_KEY_ID"

if [[ -f "$JL_CONFIG" ]]; then
    warn "Existing session config found at $JL_CONFIG"
    prompt_for OVERWRITE "Overwrite? (y/N)" "N"
    [[ "${OVERWRITE,,}" == "y" ]] || { info "Keeping existing config."; exit 0; }
    rm -f "$JL_CONFIG"
fi

# -------- Pick permission within collaboration --------
step "Fetching permissions under this collaboration..."
PERMISSIONS_JSON="$(list_permissions_for_joint_key "$JULENNY_JOINT_KEY_ID")"
PERMISSION_COUNT="$(echo "$PERMISSIONS_JSON" | jq 'length')"

if (( PERMISSION_COUNT == 0 )); then
    err "No active permissions found under joint key $JULENNY_JOINT_KEY_ID."
    err "Ask the data owner to add a permission (Add Permission button on the collaboration page), then re-run."
    exit 1
fi

PERMISSIONS_JSON="$(echo "$PERMISSIONS_JSON" | jq 'sort_by(.createdAt) | reverse')"

echo
info "Active permissions in this collaboration (newest first):"
echo "$PERMISSIONS_JSON" \
    | jq -r 'to_entries[] | "  [\(.key + 1)] \(.value.fheFunction) v\(.value.functionVersion // "?")  |  scheme: \(.value.cryptoContextSpec // "?")  |  created \(.value.createdAt // "?" | .[0:10])  |  id: \(.value.id)"'
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

# Re-fetch the picked permission via the single-permission endpoint. This triggers
# the platform's self-healing path, which populates functionVersion /
# cryptoContextSpec / keysetupState if they're missing (e.g. on permissions
# created via "Add Permission" before the function-def was fully indexed).
PERM_OBJ="$(fetch_permission "$PERM_ID")"

JULENNY_COMPANY_ID="$(echo "$PERM_OBJ" | jq -r '.dataConsumerCompanyId')"
JULENNY_PEER_COMPANY_ID="$(echo "$PERM_OBJ" | jq -r '.dataOwnerCompanyId')"
FN_SLUG="$(echo "$PERM_OBJ" | jq -r '.fheFunction')"
FN_VERSION="$(echo "$PERM_OBJ" | jq -r '.functionVersion')"
CTX_SPEC="$(echo "$PERM_OBJ" | jq -r '.cryptoContextSpec // empty')"

[[ -n "$JULENNY_COMPANY_ID" && "$JULENNY_COMPANY_ID" != "null" ]] \
    || die "Selected permission has no dataConsumerCompanyId."
[[ -n "$FN_SLUG" && "$FN_SLUG" != "null" ]] \
    || die "Selected permission has no fheFunction slug."
[[ -n "$FN_VERSION" && "$FN_VERSION" != "null" ]] \
    || die "Selected permission has no functionVersion."
[[ -n "$CTX_SPEC" ]] \
    || die "Selected permission has no cryptoContextSpec. Cannot register signing key."

success "Permission resolved: $PERM_ID  ($FN_SLUG v$FN_VERSION)"
info "  Beta is:     data consumer / keysetup main ($JULENNY_COMPANY_ID)"
info "  Acme (peer): data owner / keysetup lead ($JULENNY_PEER_COMPANY_ID)"

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

# -------- Fetch function definition from platform --------
# The function definition is the authoritative spec for how to encode
# this side's dataset (separator, columns, schema, etc.). Pulling it
# from the platform here means 04-encrypt.sh reads from a verified
# file rather than asking the operator to type defaults that might
# silently mismatch what the function expects.
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

# -------- Scheme guard --------
# The toolkit currently supports BFV only. CKKS support is in progress;
# refuse CKKS permissions up front rather than failing midway through encrypt.
JULENNY_SCHEME="$(echo "$FN_DEF_RESP" | jq -r '.scheme // empty')"
[[ -n "$JULENNY_SCHEME" ]] || die "Function definition has no scheme field; cannot proceed."
case "${JULENNY_SCHEME^^}" in
    BFV)
        info "  Scheme:      BFV ($CTX_SPEC)"
        ;;
    CKKS)
        err "This permission uses the CKKS scheme. The toolkit currently supports BFV only."
        err "CKKS implementation is in progress (toolkit task #18)."
        die "Pick a BFV permission for now, or wait for the CKKS toolkit update."
        ;;
    *)
        die "Unknown / unsupported scheme: $JULENNY_SCHEME"
        ;;
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
    julenny-fhe crypto signing-keygen \
        --output-secret "$SIGNING_SECRET" \
        --output-public "$SIGNING_PUBLIC" \
        > /dev/null
    success "Signing keypair generated."
fi

# -------- Register signing public key with the platform --------
# Idempotent (merge: true); safe to re-run.
step "Registering Beta's signing public key with the platform..."
SIGNING_PUBLIC_HEX="$(xxd -p -c 256 "$SIGNING_PUBLIC" | tr -d '\n')"
[[ ${#SIGNING_PUBLIC_HEX} -eq 64 ]] \
    || die "Signing public key hex is ${#SIGNING_PUBLIC_HEX} chars, expected 64."

REG_BODY="$(jq -n --arg ctx "$CTX_SPEC" --arg hex "$SIGNING_PUBLIC_HEX" \
    '{cryptoContextSpec: $ctx, signingPublicKeyHex: $hex}')"

REG_RESP="$(curl_jl POST "/api/companies/$JULENNY_COMPANY_ID/fhe-public-keys" \
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
# JuLenny demo session config for Beta (data consumer / main).
JULENNY_API_BASE="$JULENNY_API_BASE"
JULENNY_API_KEY="$JULENNY_API_KEY"
JULENNY_PROJECT_ID="$JULENNY_PROJECT_ID"
JULENNY_JOINT_KEY_ID="$JULENNY_JOINT_KEY_ID"
JULENNY_PERMISSION_ID="$PERM_ID"
JULENNY_COMPANY_ID="$JULENNY_COMPANY_ID"
JULENNY_PEER_COMPANY_ID="$JULENNY_PEER_COMPANY_ID"
JULENNY_OUR_SIDE="data-consumer"
JULENNY_ROLE="main"
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

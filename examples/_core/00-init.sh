#!/usr/bin/env bash
# Session setup. BOTH sides run it.
#
# Function-agnostic: this backs every scenario, because the function is picked
# from the platform's live list at run time rather than hardcoded here.
#
#   1. The collaboration picker lists the collaborations this account is in and
#      appends an "n) Create a NEW collaboration + permission" option, mirroring the
#      dataset picker in 04-encrypt.sh. Picking 'n' POSTs to /api/fhe-projects and
#      /api/fhe-permissions (see lib.sh's create_collaboration / create_permission).
#   2. No scheme guard: both BFV and CKKS are supported by the toolkit core,
#      so the function-def's declared scheme is let through and recorded in
#      config.env.
#   3. Once a collaboration is picked, the permission picker has the same shape:
#      list the existing permissions and append "n) Create a NEW permission via the
#      API". EITHER member may create one. The platform takes a permission's data
#      owner from whoever posts it, so creating one here makes this machine that
#      permission's data owner - which is how one collaboration comes to hold
#      permissions running in both directions.
#   4. The data role for the chosen permission is read back FROM THE PLATFORM, not
#      assumed from which scenario folder was run. Picking a permission that runs the
#      other way round switches this run's side profile rather than refusing.
#
# Saves everything to <workdir>/collabs/<jointKeyId>/config.env so later scripts pick
# it up automatically.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# lib.sh resolves which side of the collaboration this machine is and loads the
# matching side profile, so one copy of this phase serves both. The keysetup role
# (lead/main) and the data role (owner/consumer) are independent, and a permission can
# be created in either direction inside one collaboration.
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

mkdir -p "$JL_ROOT" "$JL_SIGNING_DIR" "$JL_COLLABS_DIR"
chmod 700 "$JL_ROOT"

migrate_legacy_workdir_if_needed

if (( JL_SIDE_KNOWN )); then
    step "JuLenny collaboration setup ($JL_OUR_LABEL: $JL_ROLE_LABEL)"
else
    step "JuLenny collaboration setup"
fi

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
elif load_account_key; then
    info "Using the API key remembered for this machine (${#JULENNY_API_KEY} characters)."
    info "Delete $JL_ACCOUNT_CONFIG to be asked again."
else
    if (( JL_SIDE_KNOWN )); then
        prompt_secret JULENNY_API_KEY "${JL_OUR_LABEL}'s API key (starts with sk_live_)"
    else
        prompt_secret JULENNY_API_KEY "Your JuLenny API key (starts with sk_live_)"
    fi
    save_account_key
fi
[[ "$JULENNY_API_KEY" == sk_live_* ]] || die "API key must start with sk_live_"

export JULENNY_API_BASE JULENNY_API_KEY

# -------- Pick OR create collaboration --------
# Fetch this account's collaborations up front, list them, and append an
# "n) Create a NEW collaboration + permission" option. Same shape as the dataset
# picker in 04-encrypt.sh and the permission picker further below. If the operator
# wants a fresh collaboration, picking 'n' drops into the /api/fhe-projects +
# /api/fhe-permissions creation flow.
#
# MY_ROLE_FIELD is the permission role this run STARTED as. It is used only to sort the
# list and to word it; it is neither a filter nor a decision. The role that counts is
# the one the platform reports for the permission finally chosen.
case "${JULENNY_OUR_SIDE:-}" in
    data-owner)    MY_ROLE_FIELD="dataOwner";    MY_ROLE_WORDS="data-owner" ;;
    data-consumer) MY_ROLE_FIELD="dataConsumer"; MY_ROLE_WORDS="data-consumer" ;;
    # No side yet: a first run, before any permission has been picked. Nothing to
    # prefer, so the list stays newest-first and nothing is flagged.
    "")            MY_ROLE_FIELD="";             MY_ROLE_WORDS="" ;;
    *) die "Unknown JULENNY_OUR_SIDE='$JULENNY_OUR_SIDE'" ;;
esac

step "Fetching your collaborations..."
ALL_PROJECTS="$(list_collaborations)"
# yourPermissionRoles (dataOwner/dataConsumer per collab) is the primary signal that
# this account already holds a permission of its role here; permissionCount, derived
# from the role-scoped permissions view in list_collaborations, is the fallback.
# A collaboration is only a container: the data owner is decided PER PERMISSION, so a
# member holding no permission of this role here can still create the first one. Listing
# only collaborations where this account already holds one made the reversed-role case
# impossible - the picker showed nothing, defaulted to 'n' and would have created a
# second collaboration. Collaborations where this account already has a permission of
# this role come first; the rest are still listed, flagged, and selectable.
ALL_SORTED="$(echo "$ALL_PROJECTS" | jq 'sort_by(.createdAt) | reverse')"
OWNED_PROJECTS="$(echo "$ALL_SORTED" | jq --arg role "$MY_ROLE_FIELD" '
    def has_my_role: ($role == "") or ((.yourPermissionRoles // []) | any(. == $role)) or (.permissionCount > 0);
    [ .[] | select(has_my_role) ]
    + [ .[] | select(has_my_role | not) | . + {noRoleYet: true} ]')"
PROJECT_COUNT="$(echo "$OWNED_PROJECTS" | jq 'length')"

echo
if (( PROJECT_COUNT > 0 )); then
    info "Your active collaborations (newest first):"
    echo "$OWNED_PROJECTS" \
        | jq -r --arg words "$MY_ROLE_WORDS" 'to_entries[] | "  [\(.key + 1)] \(.value.name // "(unnamed)")  |  peer: \(.value.partnerCollaborationId // .value.ownerCollaborationId // "?")  |  \(.value.permissionCount) permission(s)  |  keysetup: \(.value.keysetupState // "n/a")  |  created \(.value.createdAt // "?" | .[0:10])  |  id: \(.value.id)\(if (.value.noRoleYet and $words != "") then "  |  no " + $words + " permission yet - pick to create the first one" else "" end)"'
else
    info "You are not a member of any active collaboration yet."
fi
echo "  n) Create a NEW collaboration + permission via the API"
echo

if (( PROJECT_COUNT == 0 )); then
    # Do NOT default into creating one. An empty list usually means the other party has
    # not created the collaboration yet, or this machine is pointed at the wrong account
    # or host - not that a new collaboration is wanted. Auto-selecting 'n' here silently
    # created a duplicate the peer could not see, which is worse than stopping, because
    # the operator then waits on someone who has nothing to answer.
    #
    # The data-owner half used to auto-select 'n'. Either party can create one now, so
    # the same care applies on both sides.
    warn "No collaborations found for this account."
    warn "If ${JL_PEER_LABEL} has already created one and granted you a permission, check that"
    warn "this API key belongs to the account they invited, and that the platform host"
    warn "printed above is the right one."
    echo
    prompt_for CREATE_NEW "Create a NEW collaboration anyway? (y/N)" "N"
    if [[ "${CREATE_NEW,,}" == "y" || "${CREATE_NEW,,}" == "yes" ]]; then
        PROJECT_CHOICE="n"
    else
        info "Nothing to do until a collaboration exists. Exiting."
        exit 0
    fi
else
    prompt_for PROJECT_CHOICE "Pick a collaboration (1-$PROJECT_COUNT, or n)" "1"
fi

JULENNY_PROJECT_ID=""
JULENNY_JOINT_KEY_ID=""
PERM_ID=""

if [[ "${PROJECT_CHOICE,,}" == "n" ]]; then
    # -------- Create a new collaboration + permission via API --------
    step "Creating a new collaboration + permission via API"

    # 1) Pick scheme. rule-based-cross-match is CKKS, but the operator may
    #    want to point this script at a BFV function instead (e.g. for
    #    smoke-testing the new collab/permission/plaintext paths against a
    #    well-understood BFV function first).
    echo
    echo "Which scheme should the function use?"
    echo "  1) CKKS  (rule-based-cross-match, real-valued analytics, etc.)"
    echo "  2) BFV   (joint-record-overlap, exact-integer functions)"
    echo "  3) Any   (show all functions, pick whichever)"
    prompt_for SCHEME_CHOICE "Choose (1-3)" "1"

    case "$SCHEME_CHOICE" in
        1) FUNCS_JSON="$(list_functions_by_scheme CKKS)" ; SCHEME_LABEL="CKKS" ;;
        2) FUNCS_JSON="$(list_functions_by_scheme BFV)"  ; SCHEME_LABEL="BFV"  ;;
        3) FUNCS_JSON="$(list_functions)"                ; SCHEME_LABEL="any" ;;
        *) die "Invalid choice: $SCHEME_CHOICE" ;;
    esac

    FUNC_COUNT="$(echo "$FUNCS_JSON" | jq 'length')"
    if (( FUNC_COUNT == 0 )); then
        die "No functions found for scheme '$SCHEME_LABEL'. Ask the platform admin to seed one."
    fi

    # 2) Pick function.
    echo
    info "Functions available (scheme=$SCHEME_LABEL):"
    echo "$FUNCS_JSON" \
        | jq -r 'to_entries[] | "  [\(.key + 1)] \(.value.slug) v\(.value.version // "?")  |  scheme: \(.value.scheme // "?")  |  \(.value.description // "" | if length > 80 then ((.[0:77] | sub(" [^ ]*$";"")) + "...") else . end)"'
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

    # 3) The peer: operator types the PEER's Collaboration ID (XXXX-XXXX, visible on
    # their Company page in the JuLenny web UI). It is passed straight to the API,
    # which resolves it internally - the toolkit never handles a raw company id.
    echo
    info "The partner company (${JL_PEER_LABEL}) must already exist on the platform."
    info "Ask ${JL_PEER_LABEL} for their Collaboration ID (format XXXX-XXXX, visible on"
    info "their Company page in the JuLenny web UI)."
    # 4+5) Ask for the partner id and the name, create, and ask AGAIN if the platform
    # refuses. A collaboration id is typed by hand off the partner's company page, and ids
    # are PER PLATFORM: the same partner has a different one on dev and on prod, so pasting
    # the wrong one is an ordinary mistake rather than a rare accident. Ending the run over
    # it threw away the API key entry, the scheme choice and the function choice made before
    # this point.
    DEFAULT_COLLAB_NAME="${JL_OUR_LABEL} x ${JL_PEER_LABEL} ($FN_SLUG, $(date +%Y-%m-%d))"
    COLLAB_NAME=""
    JULENNY_PROJECT_ID=""
    while [[ -z "$JULENNY_PROJECT_ID" ]]; do
        prompt_for PARTNER_INPUT "Partner (${JL_PEER_LABEL}) Collaboration ID (XXXX-XXXX)"
        if [[ -z "$PARTNER_INPUT" ]]; then
            warn "A Collaboration ID is required."
            continue
        fi
        PARTNER_ID="$PARTNER_INPUT"

        # Asked once and kept across retries: the name was never the problem.
        if [[ -z "$COLLAB_NAME" ]]; then
            prompt_for COLLAB_NAME "Collaboration name" "$DEFAULT_COLLAB_NAME"
        fi

        step "Creating collaboration via POST /api/fhe-projects..."
        if ! JULENNY_PROJECT_ID="$(create_collaboration "$PARTNER_ID" "$COLLAB_NAME")"; then
            JULENNY_PROJECT_ID=""
            info "Check the id on ${JL_PEER_LABEL}'s Company page on THIS platform:"
            info "  $JULENNY_API_BASE"
            echo
        fi
    done
    success "Collaboration created: $JULENNY_PROJECT_ID"

    # 6) Create the permission.
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

    # Who sees the plaintext answer? (resultVisibility)
    # dataConsumer = the peer sees the answer (default, original behaviour).
    # dataOwner    = this machine sees it; the roles in the threshold-decrypt flow swap,
    #                so the peer uploads the partial and this side combines.
    #
    # Creating a permission makes THIS machine its data owner, whichever side script was
    # run, because the platform takes the owner from whoever posts it.
    echo
    info "Who should see the plaintext result of executions on this permission?"
    info "  1) The data consumer, ${JL_PEER_LABEL} - default"
    info "  2) The data owner, this machine"
    prompt_for RV_CHOICE "Choose (1-2)" "1"
    case "$RV_CHOICE" in
        1) JULENNY_RESULT_VISIBILITY="dataConsumer" ;;
        2) JULENNY_RESULT_VISIBILITY="dataOwner"    ;;
        *) die "Invalid choice: '$RV_CHOICE' (must be 1 or 2)" ;;
    esac
    success "Result visibility: $JULENNY_RESULT_VISIBILITY"

    step "Creating permission via POST /api/fhe-permissions..."
    PERM_ID="$(create_permission "$JULENNY_PROJECT_ID" "$FN_SLUG" "$FN_VERSION" "$PARTNER_ID" "$ALLOWED_EXEC" "$JULENNY_RESULT_VISIBILITY" "$EXPIRATION")" \
        || die "Permission creation failed."
    success "Permission created: $PERM_ID  ($FN_SLUG v$FN_VERSION)"
    # The platform takes a permission's data owner from whoever posts it, so this
    # machine is now the data owner of this one. Settle the side here rather than
    # waiting for the read-back below, so the prompts in between are accurate.
    adopt_data_role "dataOwner"

    # 7) Resolve the project's jointKeyId. POST /api/fhe-permissions
    #    triggers joint-key creation server-side; we need to refresh
    #    the project doc to read it back.
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

    PROJECT_OBJ="$(echo "$OWNED_PROJECTS" | jq ".[$((PROJECT_CHOICE - 1))]")"
    JULENNY_PROJECT_ID="$(echo "$PROJECT_OBJ" | jq -r '.id')"
    JULENNY_JOINT_KEY_ID="$(echo "$PROJECT_OBJ" | jq -r '.jointKeyId // empty')"
    [[ -n "$JULENNY_JOINT_KEY_ID" ]] \
        || die "Selected collaboration has no jointKeyId. Cannot proceed."

    success "Collaboration: $JULENNY_PROJECT_ID  (joint key: $JULENNY_JOINT_KEY_ID)"

    # -------- Pick or create a permission under this collaboration --------
    step "Fetching permissions under this collaboration..."
    PERMISSIONS_JSON="$(list_permissions_for_joint_key "$JULENNY_JOINT_KEY_ID")"
    PERMISSION_COUNT="$(echo "$PERMISSIONS_JSON" | jq 'length')"
    PERMISSIONS_JSON="$(echo "$PERMISSIONS_JSON" | jq 'sort_by(.createdAt) | reverse')"

    echo
    if (( PERMISSION_COUNT > 0 )); then
        info "Active permissions in this collaboration (newest first):"
        echo "$PERMISSIONS_JSON" \
            | jq -r 'to_entries[] | "  [\(.key + 1)] \(.value.fheFunction) v\(.value.functionVersion // "?")  |  execs left: \(.value.remainingExecutions // "?")/\(.value.allowedExecutions // "?")  |  scheme: \(.value.cryptoContextSpec // "?")  |  created \(.value.createdAt // "?" | .[0:10])  |  id: \(.value.id)"'
    else
        info "No active permissions found under this collaboration."
    fi
    echo "  n) Create a NEW permission via the API"
    echo

    if (( PERMISSION_COUNT == 0 )); then
        # Nothing to pick from; default and only path is to create one.
        PERMISSION_CHOICE="n"
        info "No existing permissions; defaulting to 'n' (create new)."
    else
        prompt_for PERMISSION_CHOICE "Pick a permission (1-$PERMISSION_COUNT, or n)" "1"
    fi

    if [[ "${PERMISSION_CHOICE,,}" == "n" ]]; then
        # -------- Create a permission under the existing collaboration --------
        # The platform takes a permission's data owner from whoever posts it, and only
        # checks that the caller is a party to the collaboration's joint key. So EITHER
        # member may create one here, and doing so makes this machine that permission's
        # data owner. That is how one collaboration comes to hold permissions running in
        # both directions.
        # /api/fhe-permissions directly (same call the create-new-collab
        # branch makes after creating its fresh project). The scheme/
        # function picker below is identical to that branch's picker.
        step "Creating a new permission under collaboration $JULENNY_PROJECT_ID"

        # The counterparty is already known from the project doc, but WHICH field holds
        # it depends on who created the project, not on who is running this script.
        # partnerCollaborationId is the non-creator; ownerCollaborationId is the creator.
        # Reading partnerCollaborationId unconditionally named THIS account as its own
        # partner whenever the other side had created the collaboration, which is exactly
        # the reversed-role case. yourRole ('owner' when this account created the project,
        # 'partner' otherwise) is what disambiguates it.
        PROJECT_ROLE="$(echo "$PROJECT_OBJ" | jq -r '.yourRole // empty')"
        if [[ "$PROJECT_ROLE" == "partner" ]]; then
            PARTNER_ID="$(echo "$PROJECT_OBJ" | jq -r '.ownerCollaborationId // empty')"
        else
            PARTNER_ID="$(echo "$PROJECT_OBJ" | jq -r '.partnerCollaborationId // empty')"
        fi
        [[ -n "$PARTNER_ID" ]] \
            || die "Project records no counterparty collaboration id; cannot create a permission."
        info "Partner (${JL_PEER_LABEL}) Collaboration ID: $PARTNER_ID"

        # 1) Determine scheme. A permission created under an EXISTING
        # collaboration MUST match that collaboration's joint key scheme
        # (one joint key per collab). Infer it from an existing permission's
        # cryptoContextSpec rather than asking - picking the other scheme would
        # need a separate joint key and break keysetup reuse. Fall back to a
        # prompt only if the collab has no existing permission to read from.
        # Prefer the project's own cryptoContextSpec: PERMISSIONS_JSON is scoped to the
        # permissions THIS account holds in its role, so it is empty for a member creating
        # their first grant here, and the scheme prompt that follows would then offer a
        # choice that cannot work (one joint key per collaboration).
        EXISTING_SPEC="$(echo "$PROJECT_OBJ" | jq -r '.cryptoContextSpec // empty')"
        [[ -n "$EXISTING_SPEC" ]] \
            || EXISTING_SPEC="$(echo "$PERMISSIONS_JSON" | jq -r '.[0].cryptoContextSpec // empty')"
        case "$EXISTING_SPEC" in
            ckks-*) SCHEME_LABEL="CKKS" ;;
            bfv-*)  SCHEME_LABEL="BFV"  ;;
            *)      SCHEME_LABEL="" ;;
        esac

        if [[ -n "$SCHEME_LABEL" ]]; then
            info "Collaboration's joint key is $SCHEME_LABEL ($EXISTING_SPEC); a new permission"
            info "must use the same scheme (keysetup is reused). Locking to $SCHEME_LABEL."
            FUNCS_JSON="$(list_functions_by_scheme "$SCHEME_LABEL")"
        else
            warn "Could not infer the collaboration's scheme from existing permissions."
            echo
            echo "Which scheme should the function use?"
            echo "  1) CKKS  (rule-based-cross-match, real-valued analytics, etc.)"
            echo "  2) BFV   (joint-record-overlap, exact-integer functions)"
            echo "  3) Any   (show all functions, pick whichever)"
            prompt_for SCHEME_CHOICE "Choose (1-3)" "1"
            case "$SCHEME_CHOICE" in
                1) FUNCS_JSON="$(list_functions_by_scheme CKKS)" ; SCHEME_LABEL="CKKS" ;;
                2) FUNCS_JSON="$(list_functions_by_scheme BFV)"  ; SCHEME_LABEL="BFV"  ;;
                3) FUNCS_JSON="$(list_functions)"                ; SCHEME_LABEL="any" ;;
                *) die "Invalid choice: $SCHEME_CHOICE" ;;
            esac
        fi

        FUNC_COUNT="$(echo "$FUNCS_JSON" | jq 'length')"
        if (( FUNC_COUNT == 0 )); then
            die "No functions found for scheme '$SCHEME_LABEL'. Ask the platform admin to seed one."
        fi

        # 2) Pick function.
        echo
        info "Functions available (scheme=$SCHEME_LABEL):"
        echo "$FUNCS_JSON" \
            | jq -r 'to_entries[] | "  [\(.key + 1)] \(.value.slug) v\(.value.version // "?")  |  scheme: \(.value.scheme // "?")  |  \(.value.description // "" | if length > 80 then ((.[0:77] | sub(" [^ ]*$";"")) + "...") else . end)"'
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

        # 3) Create the permission.
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

        # Who sees the plaintext answer? See the create-collaboration branch above.
        echo
        info "Who should see the plaintext result of executions on this permission?"
        info "  1) The data consumer, ${JL_PEER_LABEL} - default"
        info "  2) The data owner, this machine"
        prompt_for RV_CHOICE "Choose (1-2)" "1"
        case "$RV_CHOICE" in
            1) JULENNY_RESULT_VISIBILITY="dataConsumer" ;;
            2) JULENNY_RESULT_VISIBILITY="dataOwner"    ;;
            *) die "Invalid choice: '$RV_CHOICE' (must be 1 or 2)" ;;
        esac
        success "Result visibility: $JULENNY_RESULT_VISIBILITY"

        step "Creating permission via POST /api/fhe-permissions..."
        PERM_ID="$(create_permission "$JULENNY_PROJECT_ID" "$FN_SLUG" "$FN_VERSION" "$PARTNER_ID" "$ALLOWED_EXEC" "$JULENNY_RESULT_VISIBILITY" "$EXPIRATION")" \
            || die "Permission creation failed."
        success "Permission created: $PERM_ID  ($FN_SLUG v$FN_VERSION)"
        # As above: posting the permission makes this machine its data owner.
        adopt_data_role "dataOwner"
    else
        # -------- Pick an existing permission --------
        if ! [[ "$PERMISSION_CHOICE" =~ ^[0-9]+$ ]] || (( PERMISSION_CHOICE < 1 || PERMISSION_CHOICE > PERMISSION_COUNT )); then
            die "Invalid choice: '$PERMISSION_CHOICE' (must be 1-$PERMISSION_COUNT or 'n')"
        fi
        PERM_OBJ="$(echo "$PERMISSIONS_JSON" | jq ".[$((PERMISSION_CHOICE - 1))]")"
        PERM_ID="$(echo "$PERM_OBJ" | jq -r '.id')"
    fi
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
    # Both views. A permission just created here makes this machine its data owner
    # whichever side script was run, so it will not be under the view this run started
    # with if that was the consumer side.
    JULENNY_JOINT_KEY_ID="$(list_all_my_permissions \
        | jq -r --arg id "$PERM_ID" '.[] | select(.id == $id) | .jointKeyId // empty')"
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
FN_SLUG="$(echo "$PERM_OBJ" | jq -r '.fheFunction')"
FN_VERSION="$(echo "$PERM_OBJ" | jq -r '.functionVersion')"
CTX_SPEC="$(echo "$PERM_OBJ" | jq -r '.cryptoContextSpec // empty')"
# resultVisibility: read from the permission, defaulting to "dataConsumer" for
# permissions that pre-date the field. If we set it ourselves above (create-new path),
# respect that; otherwise pick up the platform's value.
JULENNY_RESULT_VISIBILITY="${JULENNY_RESULT_VISIBILITY:-$(echo "$PERM_OBJ" | jq -r '.resultVisibility // "dataConsumer"')}"

# -------- Adopt the data role the platform reports for THIS permission --------
# This used to be an assertion that the permission matched the side we started as, and
# it stopped the run when it did not. That made a permission created in the other
# direction unreachable from the scripts: the only way to reach it was to run the other
# side's folder, which then looked for this machine's key material under the other
# side's filenames.
#
# The permission's own yourRole is the answer, so take it. It may switch the side
# profile, which is why the peer collaboration-id field is read afterwards.
adopt_data_role "$YOUR_ROLE"
PEER_COLLAB="$(echo "$PERM_OBJ" | jq -r --arg f "$JL_PEER_COLLAB_FIELD" '.[$f] // empty')"

[[ -n "$FN_SLUG" && "$FN_SLUG" != "null" ]] \
    || die "Selected permission has no fheFunction slug."
[[ -n "$FN_VERSION" && "$FN_VERSION" != "null" ]] \
    || die "Selected permission has no functionVersion."
[[ -n "$CTX_SPEC" ]] \
    || die "Selected permission has no cryptoContextSpec. Cannot register signing key."

success "Permission resolved: $PERM_ID  ($FN_SLUG v$FN_VERSION)"
info "  ${JL_OUR_LABEL} is:     $JL_ROLE_LABEL"
info "  ${JL_PEER_LABEL} (peer): ${JL_PEER_ROLE_LABEL}${PEER_COLLAB:+ (collab $PEER_COLLAB)}"

# -------- Default for downstream prompts --------
# JULENNY_INPUT_CSV is referenced as a default in the o)Other fallback prompts
# in 04-encrypt and 06-end-of-cycle. We silently populate it with the first file
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
# Previously this script had a BFV-only guard. Toolkit now supports CKKS
# in core (context.cpp build_ckks_context, ciphertext.cpp ckksrns
# serializer, etc.), so we just record the scheme and move on.
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
    step "Generating Ed25519 signing keypair for ${JL_OUR_LABEL}"
    julenny-toolkit crypto signing-keygen \
        --output-secret "$SIGNING_SECRET" \
        --output-public "$SIGNING_PUBLIC" \
        > /dev/null
    success "Signing keypair generated."
fi

# -------- Register signing public key --------
step "Registering ${JL_OUR_LABEL}'s signing public key with the platform..."
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

# -------- Which half of the key ceremony this machine runs --------
# Ask the PLATFORM rather than assuming it from the data role. Lead and main build different
# key material and produce different partial decryptions, and the assignment is fixed once,
# when the joint key is built - so in a permission created in the other direction, the data
# owner is NOT the keysetup lead.
#
# The platform reports nothing for joint keys created before it recorded this, which are not
# backfilled. The fallback is the old assumption, correct wherever the two roles agree.
KEYSETUP_ROLE="$(curl -sS -H "x-api-key: $JULENNY_API_KEY"     "$JULENNY_API_BASE/api/fhe-permissions/$PERM_ID/keysetup" 2>/dev/null     | jq -r '.yourKeysetupRole // empty')"
if [[ -z "$KEYSETUP_ROLE" ]]; then
    KEYSETUP_ROLE="$JL_DEFAULT_KEYSETUP_ROLE"
    info "The platform does not record who leads this ceremony; assuming '$KEYSETUP_ROLE'."
else
    info "Keysetup role for this machine, as recorded by the platform: $KEYSETUP_ROLE"
fi

# -------- Write config.env --------
# JULENNY_OUR_SIDE is written from what the PLATFORM reported for this permission (see
# adopt_data_role above), not from which scenario folder was run. It is what every later
# phase reads to pick its side profile, so a reversed permission stays reversed for the
# whole of the rest of the collaboration.
cat > "$JL_CONFIG" <<EOF
# JuLenny session config for $JL_OUR_LABEL ($JL_ROLE_LABEL / keysetup $KEYSETUP_ROLE).
JULENNY_API_BASE="$JULENNY_API_BASE"
JULENNY_API_KEY="$JULENNY_API_KEY"
JULENNY_PROJECT_ID="$JULENNY_PROJECT_ID"
JULENNY_JOINT_KEY_ID="$JULENNY_JOINT_KEY_ID"
JULENNY_PERMISSION_ID="$PERM_ID"
JULENNY_OUR_SIDE="$JULENNY_OUR_SIDE"
JULENNY_ROLE="$KEYSETUP_ROLE"
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

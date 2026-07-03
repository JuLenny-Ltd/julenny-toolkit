#!/usr/bin/env bash
# Shared helpers for the Beta (data consumer / main) demo scripts.
# Sourced by every other script in this directory.

set -euo pipefail

# -------- Path layout --------
# Root workdir on this machine. Holds:
#   signing/                    Ed25519 signing keys (company-scoped, scheme-agnostic).
#                               Reused across every collaboration.
#   collabs/<jointKeyId>/       Per-collaboration state: config.env, keys/,
#                               envelopes/, peer/, function-def.json, etc.
#   CURRENT                     Plain text file holding the joint key id of
#                               the most recently activated collab. Used as
#                               the default when load_session is called by a
#                               numbered script.
#
# Set JL_ROOT in the environment to point at a different root (handy for tests).
JL_ROOT="${JL_ROOT:-$HOME/.julenny-collab}"
JL_SIGNING_DIR="$JL_ROOT/signing"
JL_SIGNING_SECRET="$JL_SIGNING_DIR/signing_secret_key.bin"
JL_SIGNING_PUBLIC="$JL_SIGNING_DIR/signing_public_key.bin"
JL_COLLABS_DIR="$JL_ROOT/collabs"
JL_CURRENT_FILE="$JL_ROOT/CURRENT"

# Per-collab paths. set_active_joint_key fills these in. They stay empty
# until a specific joint key is chosen (00-init.sh) or resolved at load
# time (load_session -> _jl_active_joint_key).
JL_WORKDIR=""
JL_CONFIG=""
JL_KEYS_DIR=""
JL_ENV_DIR=""
JL_PEER_DIR=""

# -------- pretty output --------
_red()    { printf '\033[31m%s\033[0m' "$*"; }
_green()  { printf '\033[32m%s\033[0m' "$*"; }
_yellow() { printf '\033[33m%s\033[0m' "$*"; }
_blue()   { printf '\033[34m%s\033[0m' "$*"; }
_bold()   { printf '\033[1m%s\033[0m' "$*"; }

info()    { echo "$(_blue '[info]')   $*" >&2; }
success() { echo "$(_green '[ok]')    $*" >&2; }
warn()    { echo "$(_yellow '[warn]')  $*" >&2; }
err()     { echo "$(_red '[err]')   $*" >&2; }
die()     { err "$*"; exit 1; }

step()    { echo >&2; echo "$(_bold "==> $*")" >&2; }
wait_msg() {
    echo
    echo "$(_yellow '────────────────────────────────────────────────')"
    echo "$(_yellow '  WAITING ON THE OTHER SIDE (Acme)')"
    echo "$(_yellow '────────────────────────────────────────────────')"
    echo "  $*"
    echo
}

# -------- session config / collab workdir --------

# Echo the joint key id of the currently active collab. Resolution order:
#   1. $JL_ROOT/CURRENT (written by set_active_joint_key)
#   2. most-recently-modified subdir under $JL_COLLABS_DIR
# Echoes nothing (and returns 0) if no collab workdir exists yet.
_jl_active_joint_key() {
    if [[ -f "$JL_CURRENT_FILE" ]]; then
        cat "$JL_CURRENT_FILE"
        return 0
    fi
    if [[ -d "$JL_COLLABS_DIR" ]]; then
        find "$JL_COLLABS_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %f\n' 2>/dev/null \
            | sort -rn | head -1 | awk '{print $2}'
    fi
}

# List known local collabs (one joint key id per line, newest first).
_jl_list_local_collabs() {
    [[ -d "$JL_COLLABS_DIR" ]] || return 0
    find "$JL_COLLABS_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %f\n' 2>/dev/null \
        | sort -rn | awk '{print $2}'
}

# Set the active joint key. Resolves all derived path variables and ensures
# the per-collab directory layout exists. Also writes $JL_CURRENT_FILE so
# later runs (numbered scripts, run.sh) can find this collab by default.
set_active_joint_key() {
    local jk="$1"
    [[ -n "$jk" ]] || die "set_active_joint_key: empty joint key id"
    JL_WORKDIR="$JL_COLLABS_DIR/$jk"
    JL_CONFIG="$JL_WORKDIR/config.env"
    JL_KEYS_DIR="$JL_WORKDIR/keys"
    JL_ENV_DIR="$JL_WORKDIR/envelopes"
    JL_PEER_DIR="$JL_WORKDIR/peer"
    mkdir -p "$JL_SIGNING_DIR" "$JL_WORKDIR" "$JL_KEYS_DIR" "$JL_ENV_DIR" "$JL_PEER_DIR"
    chmod 700 "$JL_ROOT"
    echo "$jk" > "$JL_CURRENT_FILE"
}

# Detect a pre-refactor (legacy) workdir laid out as
#     $JL_ROOT/{config.env, keys/, envelopes/, peer/, signing_*.bin}
# and migrate to the new layout. Signing keys move into $JL_SIGNING_DIR (they
# are scheme-agnostic and reusable across collabs). Everything else is parked
# under $JL_ROOT.legacy.<timestamp>/ because we cannot reliably tell which
# joint key the old keys/ subdir belonged to (the legacy layout had no
# manifest). The user can later move that legacy/ content into the correct
# collabs/<jointKeyId>/ once they know the id.
migrate_legacy_workdir_if_needed() {
    if [[ -f "$JL_ROOT/config.env" && ! -d "$JL_SIGNING_DIR" ]]; then
        step "Migrating legacy workdir to per-collab layout"
        mkdir -p "$JL_SIGNING_DIR"
        for f in signing_secret_key.bin signing_public_key.bin; do
            [[ -f "$JL_ROOT/$f" ]] && mv "$JL_ROOT/$f" "$JL_SIGNING_DIR/"
        done
        local legacy="$JL_ROOT.legacy.$(date +%s)"
        mkdir -p "$legacy"
        for entry in "$JL_ROOT"/*; do
            local base; base="$(basename "$entry")"
            case "$base" in signing|collabs|CURRENT) ;; *) mv "$entry" "$legacy/" ;; esac
        done
        info "Legacy state parked at $legacy"
        info "Signing keys kept at $JL_SIGNING_DIR/ (reusable across collabs)"
        info "Per-collab state will now live under $JL_COLLABS_DIR/<jointKeyId>/"
        echo >&2
        warn "If $legacy/keys/ holds FHE keysetup material for a prior collaboration,"
        warn "you can recover it by identifying that collaboration's joint key id and"
        warn "running:"
        warn "    jk=<jointKeyId>"
        warn "    mkdir -p $JL_COLLABS_DIR/\$jk"
        warn "    mv $legacy/keys $legacy/envelopes $legacy/peer \\"
        warn "       $legacy/config.env $legacy/function-def.json \\"
        warn "       $JL_COLLABS_DIR/\$jk/  2>/dev/null"
        echo >&2
    fi
}

load_session() {
    # If no joint key is active yet (e.g. a numbered script was launched
    # directly), resolve from $JL_CURRENT_FILE or the most-recent collab.
    if [[ -z "$JL_CONFIG" ]]; then
        local jk; jk="$(_jl_active_joint_key)"
        [[ -n "$jk" ]] || die "No active collab found under $JL_COLLABS_DIR. Run 00-init.sh first."
        set_active_joint_key "$jk"
    fi
    [[ -f "$JL_CONFIG" ]] || die "No session config at $JL_CONFIG. Run 00-init.sh first."
    # shellcheck disable=SC1090
    source "$JL_CONFIG"

    : "${JULENNY_API_KEY:?config.env missing JULENNY_API_KEY}"
    : "${JULENNY_API_BASE:?config.env missing JULENNY_API_BASE}"
    : "${JULENNY_PROJECT_ID:?config.env missing JULENNY_PROJECT_ID}"
    : "${JULENNY_PERMISSION_ID:?config.env missing JULENNY_PERMISSION_ID}"
    : "${JULENNY_COMPANY_ID:?config.env missing JULENNY_COMPANY_ID}"
    : "${JULENNY_SIGNING_SECRET:?config.env missing JULENNY_SIGNING_SECRET}"

    mkdir -p "$JL_KEYS_DIR" "$JL_ENV_DIR" "$JL_PEER_DIR"
}

# -------- curl wrapper --------
curl_jl() {
    # Usage: curl_jl <method> <path> [extra curl args...]
    local method="$1"; shift
    local path="$1"; shift
    curl -sS -X "$method" \
         -H "x-api-key: $JULENNY_API_KEY" \
         "$@" \
         "$JULENNY_API_BASE$path"
}

# -------- platform interactions --------
get_keysetup_state() {
    curl_jl GET "/api/fhe-permissions/$JULENNY_PERMISSION_ID/keysetup"
}

# Re-fetch the function-def from the platform and overwrite the local cache.
# Function-defs are mutable per (slug, version) - the platform owner can
# update fields like requiredEvalKeys or input lists without bumping the
# version. Calling this at the top of every ./run.sh ensures phases that
# read function-def.json see what the platform actually serves NOW, not
# what was cached at 00-init time. Safe to call when offline: warns and
# preserves the cached copy.
refresh_function_def() {
    local fn_def="${1:-$JL_WORKDIR/function-def.json}"
    [[ -f "$fn_def" ]] || return 0   # nothing cached yet; 00-init will fetch
    local slug version
    slug="$(jq -r '.slug // empty' "$fn_def")"
    version="$(jq -r '.version // empty' "$fn_def")"
    if [[ -z "$slug" || -z "$version" ]]; then
        warn "Cached function-def at $fn_def is missing slug/version; not refreshing."
        return 0
    fi
    local resp
    resp="$(curl_jl GET "/api/functions/$slug/$version/definition" 2>/dev/null)" || {
        warn "Could not refresh function-def for $slug v$version. Keeping cached copy."
        return 0
    }
    if echo "$resp" | jq -e '.error' > /dev/null 2>&1; then
        warn "Platform returned error refreshing $slug v$version: $(echo "$resp" | jq -r '.error')"
        warn "Keeping cached copy at $fn_def."
        return 0
    fi
    if ! echo "$resp" | jq -e '.slug and .version and .inputs' > /dev/null 2>&1; then
        warn "Platform response for $slug v$version doesn't look like a function-def. Keeping cached copy."
        return 0
    fi
    echo "$resp" > "$fn_def.tmp" && mv "$fn_def.tmp" "$fn_def"
    info "Refreshed function-def for $slug v$version."
}

get_peer_messages() {
    local peer_company_id="$1"
    curl_jl GET "/api/fhe-permissions/$JULENNY_PERMISSION_ID/keysetup/messages?from=$peer_company_id"
}

peer_company_id() {
    # Beta is the data consumer, so we use view=received to find its own
    # permission record and pull the peer's company ID from it.
    local perm
    perm="$(curl_jl GET "/api/fhe-permissions?status=active&view=received" \
        | jq -r --arg id "$JULENNY_PERMISSION_ID" '.permissions[]? | select(.id == $id)')"
    [[ -n "$perm" ]] || die "Could not load permission $JULENNY_PERMISSION_ID"

    echo "$perm" | jq -r '.dataOwnerCompanyId'
}

# Download a specific peer message's payload back to a .bin file.
# Handles both response shapes:
#   - Inline: message has payloadB64 (small payloads)
#   - Out-of-band: message has downloadUrl (large payloads stored on object storage)
# Usage: download_peer_share <messageType> <output-bin-path>
download_peer_share() {
    local msg_type="$1"
    local out_path="$2"
    local peer; peer="$(peer_company_id)"

    local resp; resp="$(get_peer_messages "$peer")"
    local msg
    msg="$(echo "$resp" \
        | jq -c --arg t "$msg_type" '[.messages[]? | select(.messageType == $t)] | .[0]')"
    [[ -n "$msg" && "$msg" != "null" ]] \
        || die "Acme has not yet submitted a '$msg_type' share. Tell them to run the previous step."

    local payload_b64 download_url
    payload_b64="$(echo "$msg" | jq -r '.payloadB64 // empty')"
    download_url="$(echo "$msg" | jq -r '.downloadUrl // empty')"

    if [[ -n "$payload_b64" ]]; then
        echo "$payload_b64" | base64 -d > "$out_path"
        success "Downloaded peer's $msg_type → $out_path (inline)"
    elif [[ -n "$download_url" ]]; then
        info "Downloading peer's $msg_type from object storage..."
        curl -sS -o "$out_path" "$download_url" \
            || die "object storage download failed for $msg_type"
        [[ -s "$out_path" ]] || die "Downloaded file is empty"
        success "Downloaded peer's $msg_type → $out_path ($(stat -c%s "$out_path") bytes, via object storage)"
    else
        die "Peer's '$msg_type' message has neither payloadB64 nor downloadUrl: $msg"
    fi
}

wait_for_peer_share() {
    local msg_type="$1"
    local max_wait_sec="${2:-1800}"
    local peer; peer="$(peer_company_id)"

    local elapsed=0
    local delay=5
    info "Waiting for Acme ($peer) to submit '$msg_type'..."
    while (( elapsed < max_wait_sec )); do
        local resp; resp="$(get_peer_messages "$peer" 2>/dev/null || echo '{}')"
        if echo "$resp" | jq -e --arg t "$msg_type" '.messages[]? | select(.messageType == $t)' > /dev/null 2>&1; then
            success "Acme submitted '$msg_type'."
            return 0
        fi
        sleep "$delay"
        elapsed=$(( elapsed + delay ))
        if   (( elapsed < 10 ));  then delay=5
        elif (( elapsed < 30 ));  then delay=10
        elif (( elapsed < 60 ));  then delay=15
        elif (( elapsed < 180 )); then delay=30
        else delay=60
        fi
        printf "  (still waiting, %ds elapsed)\n" "$elapsed"
    done
    die "Timed out after ${max_wait_sec}s waiting for Acme to submit '$msg_type'."
}

# Threshold above which we use the object storage-mediated upload path instead of
# inline payloadB64. 15 MB raw ~ 20 MB base64-encoded ~ 21 MB JSON body,
# leaving headroom under the platform's 32 MB request-body limit.
JL_INLINE_THRESHOLD_BYTES="${JL_INLINE_THRESHOLD_BYTES:-$((15 * 1024 * 1024))}"

# Request a signed object storage upload URL for a keysetup-message payload.
# Returns "<uploadUrl>|<objectKey>" on stdout. Dies on failure.
# Usage: request_upload_url <round>
request_upload_url() {
    local round="$1"
    local resp
    resp="$(curl_jl POST "/api/fhe-permissions/$JULENNY_PERMISSION_ID/keysetup/messages/upload-url" \
        -H "Content-Type: application/json" \
        --data-binary "$(jq -n --argjson r "$round" '{round: $r}')")"

    local url key
    url="$(echo "$resp" | jq -r '.uploadUrl // empty')"
    key="$(echo "$resp" | jq -r '.objectKey // empty')"
    [[ -n "$url" && -n "$key" ]] \
        || die "Failed to obtain upload URL for round $round: $resp"
    echo "${url}|${key}"
}

# Wrap a binary share into a signed envelope and POST it to the platform.
# Auto-selects between inline (payloadB64) and out-of-band (payloadRef +
# signed object storage PUT) based on payload size.
# Usage: wrap_and_upload <bin-path> <round> <message-type>
wrap_and_upload() {
    local bin_path="$1"
    local round="$2"
    local msg_type="$3"

    local json_path="$JL_ENV_DIR/${msg_type}.json"
    local size_bytes; size_bytes="$(stat -c%s "$bin_path")"

    if (( size_bytes < JL_INLINE_THRESHOLD_BYTES )); then
        # ---- Inline (payloadB64) ----
        info "Wrapping $msg_type (round $round, inline, ${size_bytes} bytes)"
        julenny-fhe crypto wrap-envelope \
            --payload "$bin_path" \
            --secret-key "$JULENNY_SIGNING_SECRET" \
            --output "$json_path" \
            --company-id "$JULENNY_COMPANY_ID" \
            --permission-id "$JULENNY_PERMISSION_ID" \
            --round "$round" \
            --message-type "$msg_type" \
            > /dev/null
    else
        # ---- Out-of-band (payloadRef + object storage) ----
        info "Wrapping $msg_type (round $round, object storage-mediated, ${size_bytes} bytes)"

        # Step 1: signed upload URL
        local url_and_key url object_key
        url_and_key="$(request_upload_url "$round")"
        url="${url_and_key%|*}"
        object_key="${url_and_key#*|}"

        # Step 2: PUT raw bytes to object storage
        info "  Uploading payload to object storage ($object_key)..."
        local put_code
        put_code="$(curl -sS -o /dev/null -w '%{http_code}' \
            -X PUT "$url" \
            -H "Content-Type: application/octet-stream" \
            --data-binary "@$bin_path")"
        [[ "$put_code" == "200" || "$put_code" == "204" ]] \
            || die "object storage PUT returned HTTP $put_code"
        success "  Uploaded to object storage"

        # Step 3: sign envelope referencing the object key
        julenny-fhe crypto wrap-envelope \
            --object-key "$object_key" \
            --size-bytes "$size_bytes" \
            --secret-key "$JULENNY_SIGNING_SECRET" \
            --output "$json_path" \
            --company-id "$JULENNY_COMPANY_ID" \
            --permission-id "$JULENNY_PERMISSION_ID" \
            --round "$round" \
            --message-type "$msg_type" \
            > /dev/null
    fi

    info "Posting envelope to /keysetup/messages..."
    local resp
    resp="$(curl_jl POST "/api/fhe-permissions/$JULENNY_PERMISSION_ID/keysetup/messages" \
            -H "Content-Type: application/json" \
            --data-binary "@$json_path")"

    if echo "$resp" | jq -e '.message' > /dev/null 2>&1; then
        success "Uploaded $msg_type: $(echo "$resp" | jq -r '.message')"
    else
        err "Upload of $msg_type failed: $resp"
        return 1
    fi
}

prompt_for() {
    local var_name="$1"
    local prompt_text="$2"
    local default_val="${3:-}"
    local value

    if [[ -n "$default_val" ]]; then
        read -r -p "$prompt_text [$default_val]: " value
        value="${value:-$default_val}"
    else
        read -r -p "$prompt_text: " value
    fi
    eval "$var_name=\"\$value\""
}

prompt_secret() {
    local var_name="$1"
    local prompt_text="$2"
    local value
    read -r -s -p "$prompt_text: " value
    echo
    eval "$var_name=\"\$value\""
}

# -------- platform-state helpers (collaboration-model refactor) --------
# A single joint key (and its keysetup state machine) can back multiple
# permissions in a project. These helpers query the platform directly so the
# scripts can decide what to do based on server state rather than local
# files - which may be stale, missing, or shared across permissions.

# Fetch the full permission JSON. The platform has no single-permission GET
# endpoint - we hit the LIST endpoint (which is also where the self-heal
# patches missing functionVersion / cryptoContextSpec / keysetupState) and
# filter client-side by id. Beta defaults to view=received; pass view=permissioned
# explicitly when needed.
fetch_permission() {
    local perm_id="${1:-$JULENNY_PERMISSION_ID}"
    local view="${2:-received}"
    local resp
    resp="$(curl_jl GET "/api/fhe-permissions?status=active&view=$view")"
    local doc
    doc="$(echo "$resp" | jq --arg id "$perm_id" '.permissions[]? | select(.id == $id)')"
    [[ -n "$doc" ]] \
        || die "Permission $perm_id not found in view=$view. Raw response: $resp"
    echo "$doc"
}

# Fetch keysetupState for the current (or specified) permission. Values:
#   pending-keysetup | in-progress | awaiting-finalization |
#   complete | abandoned | failed-keysetup
fetch_permission_state() {
    local perm_id="${1:-$JULENNY_PERMISSION_ID}"
    local resp
    resp="$(fetch_permission "$perm_id")"
    local state
    state="$(echo "$resp" | jq -r '.keysetupState // empty')"
    [[ -n "$state" ]] || die "Could not fetch keysetupState for permission $perm_id. Response: $resp"
    echo "$state"
}

# List collaborations the authenticated company is party to. Returns the
# JSON array on stdout; each entry includes partnerCompanyName, jointKeyId,
# keysetupState, permissionCount, createdAt.
list_collaborations() {
    local resp
    resp="$(curl_jl GET "/api/fhe-projects")"
    echo "$resp" | jq '.projects // []'
}

# List active permissions under a given jointKeyId from this side's perspective.
# Beta is the data consumer, so defaults to view=received.
# Usage: list_permissions_for_joint_key <jointKeyId> [view]
list_permissions_for_joint_key() {
    local jk_id="$1"
    local view="${2:-received}"
    local resp
    resp="$(curl_jl GET "/api/fhe-permissions?status=active&view=$view")"
    echo "$resp" | jq --arg jk "$jk_id" '[.permissions[]? | select(.jointKeyId == $jk)]'
}

# Return datasets in the current permission's project that belong to my
# company. Empty array if none. Each entry: { id, name, role, createdAt, ... }
my_datasets_in_project() {
    local perm_id="${1:-$JULENNY_PERMISSION_ID}"
    local resp
    resp="$(curl_jl GET "/api/fhe-permissions/$perm_id/datasets")"
    echo "$resp" | jq --arg me "$JULENNY_COMPANY_ID" '[.datasets[]? | select(.companyId == $me)]'
}

# Returns 0 if EVERY input declared in the function-def has a datasetId on
# the platform via /preferred-datasets, 1 otherwise. Used as a gate before
# triggering execution: if the peer has not yet finished their 04-encrypt,
# the platform side rejects with a "inputs without a declared pick yet"
# error. Better to gate on the script side so watch mode polls cleanly.
all_required_inputs_declared() {
    local fn_def="${1:-$JL_WORKDIR/function-def.json}"
    [[ -f "$fn_def" ]] || return 1
    local resp; resp="$(curl_jl GET "/api/fhe-permissions/$JULENNY_PERMISSION_ID/preferred-datasets" 2>/dev/null || echo "{}")"
    local input
    for input in $(jq -r ".inputs[]?.name // empty" "$fn_def"); do
        if [[ -z "$(echo "$resp" | jq -r --arg n "$input" ".[\$n].datasetId // empty")" ]]; then
            return 1
        fi
    done
    return 0
}

#!/usr/bin/env bash
# Shared helper library for the _core collaboration driver.
# Sourced by every numbered script and by run.sh.
#
# This one lib backs BOTH sides of EVERY scenario. The side-specific bits
# (peer label, permission API view, peer collaboration-id field, secret-share
# filename, role identity) come from a side profile sourced before this lib:
# _core/sides/data-owner.env or _core/sides/data-consumer.env. The scenario
# selects the function/scheme; the function-def then drives encoding,
# eval-key needs, output layout, and result visibility at runtime. See
# .plans/shared-core-example-scripts.md.
#
# Helpers included: keysetup, encrypt/upload (ciphertext + plaintext file +
# plaintext scalar), rotation-key augmentation, threshold release/decrypt
# dispatch on resultVisibility, collaboration + permission creation,
# function listing.

set -euo pipefail

# The side profile (_core/sides/<role>.env) must be sourced before this lib so
# the side-specific vars it defines are set. _core/run.sh does this. Fail
# loudly if a caller skipped it, rather than running with empty values.
: "${JL_PEER_LABEL:?side profile not sourced (run via _core/run.sh); JL_PEER_LABEL unset}"
: "${JL_PERM_VIEW:?side profile not sourced; JL_PERM_VIEW unset}"
: "${JL_SECRET_SHARE_FILE:?side profile not sourced; JL_SECRET_SHARE_FILE unset}"

# -------- Path layout --------
# Root workdir on this machine. Holds:
#   signing/                    Ed25519 signing keys (account-scoped, scheme-agnostic).
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

# Local time of the machine running the script, prefixed on every log line
# so logs from the two sides can be correlated.
_ts()     { date '+%H:%M:%S'; }
info()    { echo "[$(_ts)] $(_blue '[info]')   $*" >&2; }
success() { echo "[$(_ts)] $(_green '[ok]')    $*" >&2; }
warn()    { echo "[$(_ts)] $(_yellow '[warn]')  $*" >&2; }
err()     { echo "[$(_ts)] $(_red '[err]')   $*" >&2; }
die()     { err "$*"; exit 1; }

step()    { echo >&2; echo "$(_bold "==> $*")" >&2; }
wait_msg() {
    echo
    echo "$(_yellow '────────────────────────────────────────────────')"
    echo "$(_yellow "  WAITING ON THE OTHER SIDE (${JL_PEER_LABEL})")"
    echo "$(_yellow '────────────────────────────────────────────────')"
    echo "  $*"
    echo
}

# Offer the scenario's data files ($JL_DATA_DIR) for one-key selection, with
# 'o' for a free-text path. Echoes the chosen path on stdout (all UI goes to
# stderr, so it is safe in command substitution). Usage:
#   file="$(pick_data_file "Prompt text" [default_path])"
pick_data_file() {
    local prompt_text="$1" default_path="${2:-}"
    local data_dir="${JL_DATA_DIR:-}"
    local files=() f
    if [[ -n "$data_dir" && -d "$data_dir" ]]; then
        while IFS= read -r f; do files+=("$f"); done \
            < <(find "$data_dir" -maxdepth 1 -type f | sort)
    fi
    local n=${#files[@]} i choice
    if (( n > 0 )); then
        info "Files available in $data_dir:"
        for ((i = 0; i < n; i++)); do
            printf "  [%d] %s\n" "$((i + 1))" "$(basename "${files[$i]}")" >&2
        done
        echo "  o) Other (type a path)" >&2
        prompt_for choice "$prompt_text (1-$n, or o)" "1"
        if [[ "${choice,,}" != "o" ]]; then
            if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= n )); then
                echo "${files[$((choice - 1))]}"
                return 0
            fi
            die "Invalid choice: '$choice' (must be 1-$n or 'o')"
        fi
    fi
    local p
    prompt_for p "$prompt_text" "$default_path"
    [[ -f "$p" ]] || die "File not found: $p"
    echo "$p"
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
    : "${JULENNY_SIGNING_SECRET:?config.env missing JULENNY_SIGNING_SECRET}"

    mkdir -p "$JL_KEYS_DIR" "$JL_ENV_DIR" "$JL_PEER_DIR"
}

# -------- curl wrapper --------
curl_jl() {
    # Usage: curl_jl <method> <path> [extra curl args...]
    #
    # Checks the HTTP status. Without this a rejected key returns an error BODY with a
    # 401, callers pipe it through `jq '.projects // []'`, and the operator is told "no
    # collaborations found" - sent to look for a missing invitation when the real problem
    # is the key. A dev key pasted into a prod run reads exactly like an empty account.
    local method="$1"; shift
    local path="$1"; shift
    local out status body
    out="$(curl -sS -w $'
%{http_code}' -X "$method" \n         -H "x-api-key: $JULENNY_API_KEY" \n         "$@" \n         "$JULENNY_API_BASE$path")" || return 1
    status="${out##*$'
'}"
    body="${out%$'
'*}"
    case "$status" in
        401) die "The platform rejected this API key (401) at $JULENNY_API_BASE.
     The key is wrong, inactive, or belongs to a different environment.
     A dev key used against prod fails exactly this way." ;;
        403) die "This API key is not allowed to $method $path (403).
     Its permission group, or the role of the user who created it, is too narrow." ;;
        404) die "$method $path was not found on $JULENNY_API_BASE (404)." ;;
        5??) die "The platform returned $status for $method $path. Body: ${body:0:200}" ;;
    esac
    printf '%s' "$body"
}

# -------- platform interactions --------
get_keysetup_state() {
    curl_jl GET "/api/fhe-permissions/$JULENNY_PERMISSION_ID/keysetup"
}

# Result-visibility helpers (0.5.5).
#
# Every permission has a resultVisibility field telling the platform which
# side ultimately decrypts the plaintext answer: "dataConsumer" (default,
# Beta sees the answer) or "dataOwner" (Acme sees the answer). Both modes
# use threshold decryption; the difference is who plays the "viewer" role
# (downloads the encrypted result + peer's partial decryption, runs the
# final combine) vs the "releaser" role (downloads the encrypted result,
# produces and uploads a single-party partial, never sees plaintext).
#
# Mode "both" exists in the platform plan but is deferred (needs transport-
# key infrastructure for blind-relay between parties).

# Echo the resultVisibility for the current permission. Prefers the value
# cached in $JULENNY_RESULT_VISIBILITY (set at 00-init time); falls back to
# fetching from /api/fhe-permissions/{id} on demand; defaults to
# "dataConsumer" for old permissions that pre-date this field.
get_result_visibility() {
    if [[ -n "${JULENNY_RESULT_VISIBILITY:-}" ]]; then
        echo "$JULENNY_RESULT_VISIBILITY"
        return 0
    fi
    local resp; resp="$(fetch_permission "$JULENNY_PERMISSION_ID" 2>/dev/null || echo '{}')"
    local rv; rv="$(echo "$resp" | jq -r '.resultVisibility // "dataConsumer"')"
    echo "$rv"
}

# Returns 0 if this side is the viewer (does final combine, sees plaintext).
am_i_viewer() {
    local viewer; viewer="$(get_result_visibility)"
    case "$JULENNY_OUR_SIDE" in
        data-owner)    [[ "$viewer" == "dataOwner"    ]] ;;
        data-consumer) [[ "$viewer" == "dataConsumer" ]] ;;
        *) die "am_i_viewer: unknown JULENNY_OUR_SIDE '$JULENNY_OUR_SIDE'" ;;
    esac
}

# Returns 0 if this side is the releaser (partial-decrypts + uploads, never
# sees plaintext). Inverse of am_i_viewer.
am_i_releaser() {
    ! am_i_viewer
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
    # The platform resolves "peer" from the grant + our auth; no peer id needed.
    curl_jl GET "/api/fhe-permissions/$JULENNY_PERMISSION_ID/keysetup/messages?from=peer"
}

download_peer_share() {
    local msg_type="$1"
    local out_path="$2"
    local resp; resp="$(get_peer_messages)"
    local msg
    msg="$(echo "$resp" \
        | jq -c --arg t "$msg_type" '[.messages[]? | select(.messageType == $t)] | .[0]')"
    [[ -n "$msg" && "$msg" != "null" ]] \
        || die "${JL_PEER_LABEL} has not yet submitted a '$msg_type' share. Tell them to run the previous step."

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
    local elapsed=0
    local delay=5
    info "Waiting for ${JL_PEER_LABEL} to submit '$msg_type'..."
    while (( elapsed < max_wait_sec )); do
        local resp; resp="$(get_peer_messages 2>/dev/null || echo '{}')"
        if echo "$resp" | jq -e --arg t "$msg_type" '.messages[]? | select(.messageType == $t)' > /dev/null 2>&1; then
            success "${JL_PEER_LABEL} submitted '$msg_type'."
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
    die "Timed out after ${max_wait_sec}s waiting for ${JL_PEER_LABEL} to submit '$msg_type'."
}

JL_INLINE_THRESHOLD_BYTES="${JL_INLINE_THRESHOLD_BYTES:-$((15 * 1024 * 1024))}"

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

wrap_and_upload() {
    local bin_path="$1"
    local round="$2"
    local msg_type="$3"

    local json_path="$JL_ENV_DIR/${msg_type}.json"
    local size_bytes; size_bytes="$(stat -c%s "$bin_path")"

    if (( size_bytes < JL_INLINE_THRESHOLD_BYTES )); then
        info "Wrapping $msg_type (round $round, inline, ${size_bytes} bytes)"
        julenny-toolkit crypto wrap-envelope \
            --payload "$bin_path" \
            --secret-key "$JULENNY_SIGNING_SECRET" \
            --output "$json_path" \
            --permission-id "$JULENNY_PERMISSION_ID" \
            --round "$round" \
            --message-type "$msg_type" \
            > /dev/null
    else
        info "Wrapping $msg_type (round $round, object storage-mediated, ${size_bytes} bytes)"

        local url_and_key url object_key
        url_and_key="$(request_upload_url "$round")"
        url="${url_and_key%|*}"
        object_key="${url_and_key#*|}"

        info "  Uploading payload to object storage ($object_key)..."
        local put_code
        put_code="$(curl -sS -o /dev/null -w '%{http_code}' \
            -X PUT "$url" \
            -H "Content-Type: application/octet-stream" \
            --data-binary "@$bin_path")"
        [[ "$put_code" == "200" || "$put_code" == "204" ]] \
            || die "object storage PUT returned HTTP $put_code"
        success "  Uploaded to object storage"

        julenny-toolkit crypto wrap-envelope \
            --object-key "$object_key" \
            --size-bytes "$size_bytes" \
            --secret-key "$JULENNY_SIGNING_SECRET" \
            --output "$json_path" \
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
    elif echo "$resp" | jq -r '.error // ""' | grep -qiE "in state .?complete|already complete|cannot accept messages"; then
        info "$msg_type not needed: keysetup already complete ($(echo "$resp" | jq -r '.error'))."
    else
        err "Upload of $msg_type failed: $resp"
        return 1
    fi
}

# Where the interactive prompts read from. The controlling terminal when there
# is one, otherwise stdin so a piped run still works. The numbered phase scripts
# are subprocesses of run.sh and inherit whatever stdin the driver had; when
# that is not the keyboard, a plain `read` returns nothing and, under
# `set -euo pipefail`, takes the whole run down with no message on screen.
if [[ -r /dev/tty ]]; then JL_TTY="/dev/tty"; else JL_TTY="/dev/stdin"; fi

prompt_for() {
    local var_name="$1"
    local prompt_text="$2"
    local default_val="${3:-}"
    local value=""

    # `|| true`: end-of-input must surface as an empty answer we can report on,
    # never as a silent set -e exit.
    if [[ -n "$default_val" ]]; then
        read -r -p "$prompt_text [$default_val]: " value < "$JL_TTY" || true
        value="${value:-$default_val}"
    else
        read -r -p "$prompt_text: " value < "$JL_TTY" || true
    fi
    eval "$var_name=\"\$value\""
}

prompt_secret() {
    local var_name="$1"
    local prompt_text="$2"
    local value=""
    # Say up front that nothing will appear. A silent prompt with no echo and no
    # confirmation looks like a frozen terminal, and the operator cannot tell
    # whether a paste registered.
    echo "  (input is hidden - paste or type, then press Enter)" >&2
    read -r -s -p "$prompt_text: " value < "$JL_TTY" || true
    echo
    # Terminals differ in what they append to a paste. A trailing carriage
    # return or space would leave the value looking correct while failing the
    # sk_live_ prefix check, so trim before reporting or validating.
    value="${value//$'\r'/}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    # Confirm receipt without revealing the value: length, plus the first few
    # characters when it looks like an API key, so a mis-paste is obvious.
    if [[ -z "$value" ]]; then
        warn "Nothing received. If you pasted, the terminal may not have accepted it - try again."
    elif [[ "$value" == sk_live_* ]]; then
        success "Received ${#value} characters, starting 'sk_live_'."
    else
        info "Received ${#value} characters."
    fi
    eval "$var_name=\"\$value\""
}

# -------- platform-state helpers --------
fetch_permission() {
    local perm_id="${1:-$JULENNY_PERMISSION_ID}"
    local view="${2:-${JL_PERM_VIEW}}"
    local resp
    resp="$(curl_jl GET "/api/fhe-permissions?status=active&view=$view")"
    local doc
    doc="$(echo "$resp" | jq --arg id "$perm_id" '.permissions[]? | select(.id == $id)')"
    [[ -n "$doc" ]] \
        || die "Permission $perm_id not found in view=$view. Raw response: $resp"
    echo "$doc"
}

fetch_permission_state() {
    local perm_id="${1:-$JULENNY_PERMISSION_ID}"
    local resp
    resp="$(fetch_permission "$perm_id")"
    local state
    state="$(echo "$resp" | jq -r '.keysetupState // empty')"
    [[ -n "$state" ]] || die "Could not fetch keysetupState for permission $perm_id. Response: $resp"
    echo "$state"
}

list_collaborations() {
    local resp perms
    resp="$(curl_jl GET "/api/fhe-projects")"
    # The project docs carry NO permission count (the platform never sets
    # one; the picker used to print "null permission(s)"). Derive it from
    # the active-permissions list, grouped by jointKeyId. One extra call.
    perms="$(curl_jl GET "/api/fhe-permissions?status=active&view=${JL_PERM_VIEW}" \
        | jq '[.permissions[]?]')"
    echo "$resp" | jq --argjson perms "$perms" '
        (.projects // []) | map(. as $p | $p + {
            permissionCount: ([$perms[] | select((.jointKeyId // "none") == ($p.jointKeyId // "-"))] | length)
        })'
}

list_permissions_for_joint_key() {
    local jk_id="$1"
    local view="${2:-${JL_PERM_VIEW}}"
    local resp
    resp="$(curl_jl GET "/api/fhe-permissions?status=active&view=$view")"
    echo "$resp" | jq --arg jk "$jk_id" '[.permissions[]? | select(.jointKeyId == $jk)]'
}

my_datasets_in_project() {
    local perm_id="${1:-$JULENNY_PERMISSION_ID}"
    local resp
    resp="$(curl_jl GET "/api/fhe-permissions/$perm_id/datasets")"
    echo "$resp" | jq '[.datasets[]? | select(.isYours == true)]'
}

# ============================================================
# NEW (rule-based-cross-match): collaboration + permission creation via API
# ============================================================

# List ALL available functions on the platform, optionally filtered by scheme.
# Usage:
#   list_functions                -> all functions
#   list_functions_by_scheme BFV  -> only BFV functions
#   list_functions_by_scheme CKKS -> only CKKS functions
list_functions() {
    local resp
    resp="$(curl_jl GET "/api/functions")"
    echo "$resp" | jq '.functions // []'
}

list_functions_by_scheme() {
    local scheme="$1"
    list_functions | jq --arg s "$scheme" '[.[] | select((.scheme // "") == $s)]'
}

# Create a new collaboration (project). The platform returns the new
# project's id and (initially) no jointKey — the key gets attached when
# the first permission under the project is created.
# Usage: create_collaboration <partner collaboration id> <name> [description]
# Returns the project id on stdout.
create_collaboration() {
    local partner_id="$1"
    local name="$2"
    local description="${3:-Created from the JuLenny example scripts.}"

    local body
    body="$(jq -n \
        --arg partner "$partner_id" \
        --arg name    "$name" \
        --arg desc    "$description" \
        '{partnerCompanyId: $partner, name: $name, description: $desc}')"

    local resp
    resp="$(curl_jl POST "/api/fhe-projects" \
        -H "Content-Type: application/json" \
        --data-binary "$body")"

    if echo "$resp" | jq -e '.error' > /dev/null 2>&1; then
        err "POST /api/fhe-projects failed:"
        echo "$resp" | jq . >&2
        return 1
    fi

    local pid
    pid="$(echo "$resp" | jq -r '.project.id // .id // empty')"
    [[ -n "$pid" ]] \
        || { err "Project creation succeeded but no id returned: $resp"; return 1; }
    echo "$pid"
}

# Create a permission under an existing project.
# Usage: create_permission <projectId> <fnSlug> <fnVersion> <consumerCollaborationId>
#                          [allowedExecutions] [resultVisibility]
# resultVisibility is "dataConsumer" (default) or "dataOwner". Mode "both"
# is deferred (needs transport-key infrastructure).
# Returns the new permission id on stdout.
create_permission() {
    local project_id="$1"
    local fn_slug="$2"
    local fn_version="$3"
    local consumer_id="$4"
    local allowed="${5:-100}"
    local result_visibility="${6:-dataConsumer}"
    local expiration="${7:-}"

    local body
    body="$(jq -n \
        --arg pid       "$project_id" \
        --arg slug      "$fn_slug" \
        --arg ver       "$fn_version" \
        --arg consumer  "$consumer_id" \
        --argjson n     "$allowed" \
        --arg viewer    "$result_visibility" \
        --arg exp       "$expiration" \
        '{
            projectId:              $pid,
            fheFunction:            $slug,
            functionVersion:        $ver,
            dataConsumerCompanyId:  $consumer,
            allowedExecutions:      $n,
            resultVisibility:       $viewer,
            grantType:              "external"
        } + (if $exp != "" then {expirationDate: $exp} else {} end)')"

    local resp
    resp="$(curl_jl POST "/api/fhe-permissions" \
        -H "Content-Type: application/json" \
        --data-binary "$body")"

    if echo "$resp" | jq -e '.error' > /dev/null 2>&1; then
        err "POST /api/fhe-permissions failed:"
        echo "$resp" | jq . >&2
        return 1
    fi

    local pid
    pid="$(echo "$resp" | jq -r '.permission.id // .id // .permissionId // empty')"
    [[ -n "$pid" ]] \
        || { err "Permission creation succeeded but no id returned: $resp"; return 1; }
    echo "$pid"
}

# ============================================================
# NEW (rule-based-cross-match): rotation key augmentation (Path B)
# ============================================================
# Phase 4.5 helpers. Used by 04.5-rotation-keysetup.sh to drive the post-
# keysetup augmentation when the function definition's requiredEvalKeys
# includes "rotation" (see plans/rotation-key-augmentation-contract.md
# on the platform side).
#
# Symmetric with the data-consumer helpers: same contract, same shape, same
# polling cadence. The protocol roles differ (Acme = owner / lead, Beta =
# consumer / main) but the platform-state plumbing is identical.

function_requires_rotation_keys() {
    local fn_def="${1:-$JL_WORKDIR/function-def.json}"
    [[ -f "$fn_def" ]] || return 1
    jq -e '(.requiredEvalKeys // ["relinearization", "sum"]) | index("rotation")' \
        "$fn_def" > /dev/null 2>&1
}

# True if the function-def declares a "sum" eval key (legacy default includes it).
# Rotation-free functions (e.g. decision-tree v2) omit it, so keysetup skips the
# sum contribution/combine/upload entirely (no oversized eval-sum key).
function_requires_sum_keys() {
    local fn_def="${1:-$JL_WORKDIR/function-def.json}"
    [[ -f "$fn_def" ]] || return 1
    jq -e '(.requiredEvalKeys // ["relinearization", "sum"]) | index("sum")' \
        "$fn_def" > /dev/null 2>&1
}

# True if the function-def declares a "relinearization" eval key. Additive-only
# functions (federated-average) declare requiredEvalKeys: [], and for those the whole
# relin exchange - rounds 1, 2 and the final combine - must be skipped. The platform
# knows this and goes straight to awaiting-finalization, so a script that waits for
# relin-round1-continue waits forever.
function_requires_relin_keys() {
    local fn_def="${1:-$JL_WORKDIR/function-def.json}"
    [[ -f "$fn_def" ]] || return 1
    jq -e '(.requiredEvalKeys // ["relinearization", "sum"]) | index("relinearization")'         "$fn_def" > /dev/null 2>&1
}

get_pending_rotation_keysetup() {
    local state; state="$(get_keysetup_state)"
    echo "$state" | jq -c '.pendingRotationKeySetup // null'
}

get_pending_rotation_indices_csv() {
    local prks; prks="$(get_pending_rotation_keysetup)"
    [[ "$prks" == "null" || -z "$prks" ]] && { echo ""; return 0; }
    echo "$prks" | jq -r '.indices // [] | join(",")'
}

get_rotation_status() {
    local prks; prks="$(get_pending_rotation_keysetup)"
    [[ "$prks" == "null" || -z "$prks" ]] && { echo "absent"; return 0; }
    echo "$prks" | jq -r '.status // "absent"'
}

wait_for_pending_rotation_indices() {
    local description="${1:-platform to derive rotation indices}"
    local max_wait_sec="${2:-600}"
    local elapsed=0
    local delay=5
    info "Waiting for $description..."
    while (( elapsed < max_wait_sec )); do
        local prks; prks="$(get_pending_rotation_keysetup 2>/dev/null || echo "null")"
        if [[ "$prks" != "null" && -n "$prks" ]]; then
            local n; n="$(echo "$prks" | jq -r '.indices // [] | length')"
            if [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )); then
                success "Platform derived $n rotation indices."
                return 0
            fi
            local status; status="$(echo "$prks" | jq -r '.status // ""')"
            if [[ "$status" == "complete" ]]; then
                info "Platform derived an empty index set and transitioned to complete."
                info "No rotation keys needed for this execution."
                return 0
            fi
        fi
        sleep "$delay"
        elapsed=$(( elapsed + delay ))
        if   (( elapsed < 30 ));  then delay=5
        elif (( elapsed < 60 ));  then delay=10
        else delay=15
        fi
        printf "  (still waiting, %ds elapsed)\n" "$elapsed"
    done
    die "Timed out after ${max_wait_sec}s waiting for $description."
}

wait_for_rotation_status() {
    local target_status="$1"
    local max_wait_sec="${2:-1800}"
    local elapsed=0
    local delay=10
    info "Waiting for rotation keysetup status: $target_status"
    while (( elapsed < max_wait_sec )); do
        local current; current="$(get_rotation_status 2>/dev/null || echo "absent")"
        if [[ "$current" == "$target_status" ]]; then
            success "Rotation keysetup status is now '$target_status'."
            return 0
        fi
        sleep "$delay"
        elapsed=$(( elapsed + delay ))
        if   (( elapsed < 60 ));  then delay=10
        elif (( elapsed < 180 )); then delay=20
        else delay=60
        fi
        printf "  (status=%s, %ds elapsed)\n" "$current" "$elapsed"
    done
    die "Timed out after ${max_wait_sec}s waiting for rotation status '$target_status'."
}

get_rotation_round_offset() {
    local kind="$1"
    local state; state="$(get_keysetup_state)"
    local total; total="$(echo "$state" | jq -r '.totalRounds // 0')"
    local prks; prks="$(echo "$state" | jq -c '.pendingRotationKeySetup // null')"
    local base
    if [[ "$prks" == "null" || -z "$prks" ]]; then
        base="$total"
    else
        base=$(( total - 3 ))
    fi
    case "$kind" in
        round1)          echo $(( base + 1 )) ;;
        round1-continue) echo $(( base + 2 )) ;;
        combine)         echo $(( base + 3 )) ;;
        *) die "get_rotation_round_offset: unknown kind '$kind'" ;;
    esac
}

# ============================================================
# NEW (rule-based-cross-match): plaintext dataset upload
# ============================================================

# Upload a PLAINTEXT file to /api/fhe-data-upload (no julenny-toolkit encrypt
# pass). For functions like rule-based-cross-match whose function-def declares
# some inputs as plaintext (dictionaries, rule lists, etc.), each such
# input gets its own dataset bundle.
#
# The endpoint itself is the same multipart endpoint used for encrypted
# uploads; the platform treats the bytes opaquely. The script flags the
# upload as plaintext via a metadata field ("kind") so the platform / VS
# can audit later that this dataset was intentionally not encrypted.
#
# Usage: upload_plaintext_dataset <file-path> <dataset-name>
# Returns the new dataset id on stdout.
upload_plaintext_dataset() {
    local file_path="$1"
    local dataset_name="$2"
    local kind="${3:-plaintext}"   # "plaintext" (raw input) or "ciphertext" (encrypted bundle)

    [[ -f "$file_path" ]] || die "upload_plaintext_dataset: file not found: $file_path"

    local size_bytes; size_bytes="$(stat -c%s "$file_path")"
    local id
    if (( size_bytes < JL_INLINE_THRESHOLD_BYTES )); then
        info "Uploading ${kind^^} $file_path as '$dataset_name' (single-shot, ${size_bytes} bytes)..."
        local resp
        resp="$(curl -sS -X POST \
            -H "x-api-key: $JULENNY_API_KEY" \
            -F "file=@$file_path" \
            -F "name=$dataset_name" \
            -F "kind=$kind" \
            "$JULENNY_API_BASE/api/fhe-data-upload?permissionId=$JULENNY_PERMISSION_ID")"
        if echo "$resp" | jq -e '.error' > /dev/null 2>&1; then
            err "Plaintext upload failed:"
            echo "$resp" | jq . >&2
            return 1
        fi
        id="$(echo "$resp" | jq -r '.datasetId // empty')"
        [[ -n "$id" ]] \
            || { err "Plaintext upload succeeded but no datasetId returned: $resp"; return 1; }
    else
        # Large bundle: signed-URL flow (upload-url -> PUT to object storage -> confirm),
        # so the bytes bypass the ~32MB API body cap (the 413 path).
        info "Uploading ${kind^^} $file_path as '$dataset_name' via signed URL (${size_bytes} bytes, exceeds inline cap)..."
        local url_resp up_url
        url_resp="$(curl_jl POST "/api/fhe-data-upload/upload-url" \
            -H "Content-Type: application/json" \
            --data-binary "$(jq -n --arg n "$dataset_name" --arg p "$JULENNY_PERMISSION_ID" \
                '{name: $n, permissionId: $p}')")"
        up_url="$(echo "$url_resp" | jq -r '.uploadUrl // empty')"
        id="$(echo "$url_resp" | jq -r '.datasetId // empty')"
        [[ -n "$up_url" && -n "$id" ]] || { err "upload-url failed: $url_resp"; return 1; }
        local put_code
        put_code="$(curl -sS -o /dev/null -w '%{http_code}' \
            -X PUT "$up_url" \
            -H "Content-Type: application/octet-stream" \
            --data-binary "@$file_path")"
        [[ "$put_code" == "200" || "$put_code" == "204" ]] \
            || { err "object storage PUT returned HTTP $put_code"; return 1; }
        local confirm_resp
        confirm_resp="$(curl_jl POST "/api/fhe-data-upload/confirm" \
            -H "Content-Type: application/json" \
            --data-binary "$(jq -n --arg id "$id" --arg n "$dataset_name" \
                --arg f "$(basename "$file_path")" --arg p "$JULENNY_PERMISSION_ID" --arg k "$kind" \
                '{datasetId: $id, name: $n, kind: $k, fileName: $f, permissionId: $p, retentionDays: 90}')")"
        if echo "$confirm_resp" | jq -e '.error' > /dev/null 2>&1; then
            err "Plaintext upload confirm failed:"
            echo "$confirm_resp" | jq . >&2
            return 1
        fi
        id="$(echo "$confirm_resp" | jq -r '.datasetId // empty')"
        [[ -n "$id" ]] \
            || { err "Confirm succeeded but no datasetId returned: $confirm_resp"; return 1; }
    fi
    echo "$id"
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

# ============================================================
# Result-visibility flows (0.5.5): releaser_flow + viewer_flow
# ============================================================
# These two helpers do the threshold-decrypt work. Which one your side
# runs depends on resultVisibility (see am_i_viewer / am_i_releaser):
#
#   releaser_flow:  polls for an awaiting-release execution, downloads the
#                   encrypted result, produces this side's partial
#                   decryption (using our keysetup role, lead or main),
#                   signs it, and uploads it via /partial-decrypt. This
#                   side never sees the plaintext.
#
#   viewer_flow:    polls for a released execution, picks one if multiple,
#                   downloads the encrypted result + the peer's partial,
#                   produces this side's local partial, combines both
#                   partials, and renders the plaintext answer per the
#                   function-def's output.layout.
#
# Same code on both sides (Acme + Beta); the only side-specific piece is
# the path to the local FHE secret share, passed in as $1 (acme uses
# fhe_secret_key.bin, beta uses my_share_secret.bin -- legacy asymmetric
# naming, see plans/secret-share-filename-asymmetry.md).

# Run the releaser-side flow: poll awaiting-release, partial-decrypt, sign,
# upload. Takes one arg: the local FHE secret-share file path.
releaser_flow() {
    local my_secret="$1"
    [[ -f "$my_secret" ]] || die "Missing FHE secret share at $my_secret. Did keysetup complete on this machine?"

    step "Releaser flow: partial-decrypt and upload (resultVisibility: $(get_result_visibility))"

    # 1. Poll for awaiting-release executions. There can be MORE THAN ONE:
    # e.g. an older execution whose result is unusable (produced by a broken
    # engine build) cannot be released and still occupies the queue until the
    # platform can cancel it. Attempt EVERY one and skip failures, so a
    # poison execution does not block releasing the current cycle's run.
    info "Polling for awaiting-release executions on permission $JULENNY_PERMISSION_ID..."
    local elapsed=0 delay=5
    local -A skip_ids=()
    local released=0 failed=0
    local exec_ids=() pending=() exec_id

    while true; do
        local list_resp
        list_resp="$(curl_jl GET \
            "/api/fhe-permissions/$JULENNY_PERMISSION_ID/executions?state=awaiting-release")"
        mapfile -t exec_ids < <(echo "$list_resp" | jq -r '.executions[]?.id // empty')

        # Filter out executions we already tried and could not release; they
        # stay awaiting-release until the platform cancels them, and must not
        # block waiting for the current cycle's execution.
        pending=()
        for exec_id in "${exec_ids[@]}"; do
            [[ -n "${skip_ids[$exec_id]:-}" ]] || pending+=("$exec_id")
        done

        if (( ${#pending[@]} > 0 )); then
            info "Attempting ${#pending[@]} awaiting-release execution(s)..."
        for exec_id in "${pending[@]}"; do
            echo
            info "Releasing execution $exec_id..."
            local result_bin="$JL_KEYS_DIR/result-$exec_id.bin"
            local partial_bin="$JL_KEYS_DIR/releaser-partial-$exec_id.bin"
            local sig_bin="$JL_KEYS_DIR/releaser-partial-$exec_id.sig"

            # 2. Download encrypted result.
            local http_code; http_code="$(curl -sS -w '%{http_code}' -o "$result_bin" \
                -H "x-api-key: $JULENNY_API_KEY" \
                "$JULENNY_API_BASE/api/executions/$exec_id/result")"
            if [[ "$http_code" != "200" || ! -s "$result_bin" ]]; then
                warn "Could not download the result for $exec_id (HTTP $http_code). Skipping it."
                rm -f "$result_bin"
                skip_ids[$exec_id]=1
                failed=$(( failed + 1 ))
                continue
            fi
            success "Encrypted result: $result_bin ($(stat -c%s "$result_bin") bytes)"

            # 3. Partial-decrypt locally with the keysetup role (lead vs main).
            # JULENNY_ROLE is "lead" for Acme, "main" for Beta - this is
            # independent of resultVisibility (it was fixed at keysetup time).
            # Failure here is per-execution, not fatal: a result produced under a
            # foreign crypto context (broken engine build) aborts the CLI; that
            # execution is skipped and stays awaiting-release for the platform
            # to cancel.
            info "Producing partial decryption (keysetup role: $JULENNY_ROLE)..."
            local lead_flag=""
            [[ "$JULENNY_ROLE" == "lead" ]] && lead_flag="--lead"
            if ! julenny-toolkit crypto partial-decrypt \
                --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
                --input "$result_bin" \
                --secret-key "$my_secret" \
                --output "$partial_bin" \
                $lead_flag \
                > /dev/null; then
                warn "partial-decrypt FAILED for execution $exec_id (see error above)."
                warn "  Skipping it. It stays awaiting-release; ask the platform side to"
                warn "  cancel/fail it if its result is known to be unusable."
                skip_ids[$exec_id]=1
                failed=$(( failed + 1 ))
                continue
            fi
            success "Partial decrypt: $partial_bin ($(stat -c%s "$partial_bin") bytes)"

            # 4. Sign the partial bytes.
            info "Signing the partial decrypt with the registered signing key..."
            julenny-toolkit crypto sign \
                --input "$partial_bin" \
                --secret-key "$JULENNY_SIGNING_SECRET" \
                --output "$sig_bin" \
                > /dev/null
            local sig_hex; sig_hex="$(xxd -p -c 256 "$sig_bin" | tr -d '\n')"
            [[ ${#sig_hex} -eq 128 ]] || die "Signature is ${#sig_hex} hex chars, expected 128."

            # 5. Upload via multipart formdata.
            info "Uploading partial decrypt to platform..."
            local resp; resp="$(curl -sS -X POST \
                -H "x-api-key: $JULENNY_API_KEY" \
                -H "x-jl-signature: $sig_hex" \
                -F "file=@$partial_bin" \
                "$JULENNY_API_BASE/api/executions/$exec_id/partial-decrypt")"
            local state; state="$(echo "$resp" | jq -r '.state // empty')"
            if [[ "$state" == "released" ]]; then
                success "Released. Execution state: $state."
                released=$(( released + 1 ))
            else
                warn "Upload may have failed for $exec_id. Response: $resp"
                skip_ids[$exec_id]=1
                failed=$(( failed + 1 ))
            fi
        done
            (( released > 0 )) && break
            # Every pending execution failed and is now in skip_ids. Keep
            # polling for a NEW execution instead of giving up.
        fi
        if (( ${#exec_ids[@]} > 0 )); then
            printf "  (only unreleasable execution(s) in the queue [%s]; waiting for a new one, %ds elapsed)\n" \
                   "${exec_ids[*]}" "$elapsed"
        else
            printf "  (no awaiting-release execution yet, %ds elapsed)\n" "$elapsed"
        fi
        sleep "$delay"
        elapsed=$(( elapsed + delay ))
        if   (( elapsed > 60 ));  then delay=15
        elif (( elapsed > 30 ));  then delay=10
        fi
        (( elapsed > 1800 )) \
            && die "Timed out after 30 min waiting for a releasable execution. Has the viewer side triggered?"
    done

    echo
    success "Released $released execution(s)."
    if (( failed > 0 )); then
        warn "$failed execution(s) could NOT be released and remain awaiting-release"
        warn "  until the platform cancels them."
    fi

    echo
    info "Next step:"
    echo "  The viewer side can now run their decrypt script to combine partials and"
    echo "  reveal the plaintext answer."
}

# Run the viewer-side flow: poll released, pick exec, download result +
# peer partial, partial-decrypt locally, combine, render answer. Takes one
# arg: the local FHE secret-share file path.
viewer_flow() {
    local my_secret="$1"
    [[ -f "$my_secret" ]] || die "Missing FHE secret share at $my_secret. Did keysetup complete on this machine?"

    step "Viewer flow: combine partials and reveal the plaintext (resultVisibility: $(get_result_visibility))"

    # 1. Find the execution to decrypt.
    #
    # If THIS machine just triggered an execution, 05-run-query persisted its
    # id in $JL_WORKDIR/last_exec_id. In that case wait for that specific
    # execution to be released, rather than offering older released ones
    # (decrypting a stale execution was an easy operator mistake). Without a
    # marker, fall back to the released-executions picker, which supports
    # 'r' to refresh the list while the releaser side catches up.
    local want_exec=""
    [[ -f "$JL_WORKDIR/last_exec_id" ]] && want_exec="$(cat "$JL_WORKDIR/last_exec_id")"

    local elapsed=0 delay=5
    local list_resp count exec_id="" exec_when=""

    if [[ -n "$want_exec" ]]; then
        info "Waiting for this cycle's execution ($want_exec) to be released..."
    else
        info "Polling for released executions on permission $JULENNY_PERMISSION_ID..."
    fi

    while true; do
        if [[ -n "$want_exec" ]]; then
            local want_doc want_state
            want_doc="$(curl_jl GET "/api/executions/$want_exec")"
            want_state="$(echo "$want_doc" | jq -r '.state // "unknown"')"
            case "$want_state" in
                released)
                    exec_id="$want_exec"
                    exec_when="$(echo "$want_doc" | jq -r '.releasedAt // .triggeredAt // "unknown date"')"
                    rm -f "$JL_WORKDIR/last_exec_id"
                    success "This cycle's execution is released: $exec_id ($exec_when)"
                    break
                    ;;
                failed)
                    warn "Execution $want_exec failed; falling back to the released-executions picker."
                    echo "$want_doc" | jq . >&2
                    rm -f "$JL_WORKDIR/last_exec_id"
                    want_exec=""
                    continue
                    ;;
                *)
                    printf "  (execution %s is '%s', waiting for release, %ds elapsed)\n" \
                           "$want_exec" "$want_state" "$elapsed"
                    ;;
            esac
        else
            list_resp="$(curl_jl GET \
                "/api/fhe-permissions/$JULENNY_PERMISSION_ID/executions?state=released")"
            count="$(echo "$list_resp" | jq '.executions | length')"
            if (( count > 0 )); then
                break
            fi
            printf "  (no released execution yet, %ds elapsed)\n" "$elapsed"
        fi
        sleep "$delay"
        elapsed=$(( elapsed + delay ))
        if   (( elapsed > 60 ));  then delay=15
        elif (( elapsed > 30 ));  then delay=10
        fi
        (( elapsed > 1800 )) \
            && die "Timed out after 30 min waiting for a released execution. Has the releaser run their script?"
    done

    if [[ -z "$exec_id" ]]; then
        if (( count == 1 )); then
            exec_id="$(echo "$list_resp"   | jq -r '.executions[0].id')"
            exec_when="$(echo "$list_resp" | jq -r '.executions[0].releasedAt // .executions[0].triggeredAt // "unknown date"')"
            success "Single released execution: $exec_id ($exec_when)"
        else
            while true; do
                info "Found $count released executions (newest first):"
                echo "$list_resp" | jq -r '.executions | to_entries[] | "  \(.key + 1)) \(.value.id)  (\(.value.releasedAt // .value.triggeredAt // "unknown date"))"'
                local choice
                prompt_for choice "Pick an execution (1-$count, or r to refresh)" "1"
                if [[ "${choice,,}" == "r" ]]; then
                    info "Refreshing the released-executions list..."
                    list_resp="$(curl_jl GET \
                        "/api/fhe-permissions/$JULENNY_PERMISSION_ID/executions?state=released")"
                    count="$(echo "$list_resp" | jq '.executions | length')"
                    continue
                fi
                if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > count )); then
                    die "Invalid choice: $choice (must be between 1 and $count, or r)"
                fi
                exec_id="$(echo "$list_resp"   | jq -r ".executions[$((choice - 1))].id")"
                exec_when="$(echo "$list_resp" | jq -r ".executions[$((choice - 1))].releasedAt // .executions[$((choice - 1))].triggeredAt // \"unknown date\"")"
                success "Selected: $exec_id ($exec_when)"
                break
            done
        fi
    fi

    local result_bin="$JL_KEYS_DIR/result-$exec_id.bin"
    local peer_partial_bin="$JL_KEYS_DIR/peer-partial-$exec_id.bin"
    local my_partial_bin="$JL_KEYS_DIR/my-partial-$exec_id.bin"

    # 2. Download encrypted result.
    info "Downloading encrypted result from platform..."
    local http_code; http_code="$(curl -sS -w '%{http_code}' -o "$result_bin" \
        -H "x-api-key: $JULENNY_API_KEY" \
        "$JULENNY_API_BASE/api/executions/$exec_id/result")"
    if [[ "$http_code" == "403" ]]; then
        rm -f "$result_bin"
        die "Platform says the result isn't released yet. Has the releaser side run their script?"
    elif [[ "$http_code" != "200" ]]; then
        err "Platform returned HTTP $http_code when downloading the result."
        cat "$result_bin" >&2 || true
        rm -f "$result_bin"
        die "Cannot proceed."
    fi
    [[ -s "$result_bin" ]] || die "Result file is empty."
    success "Encrypted result: $result_bin ($(stat -c%s "$result_bin") bytes)"

    # 3. Download the releaser side's partial.
    info "Downloading peer's partial decrypt..."
    http_code="$(curl -sS -w '%{http_code}' -o "$peer_partial_bin" \
        -H "x-api-key: $JULENNY_API_KEY" \
        "$JULENNY_API_BASE/api/executions/$exec_id/partial")"
    if [[ "$http_code" != "200" ]]; then
        err "Platform returned HTTP $http_code when downloading the peer's partial."
        cat "$peer_partial_bin" >&2 || true
        rm -f "$peer_partial_bin"
        die "Releaser may not have uploaded yet."
    fi
    [[ -s "$peer_partial_bin" ]] || die "Peer's partial is empty."
    success "Peer's partial: $peer_partial_bin ($(stat -c%s "$peer_partial_bin") bytes)"

    # 4. Produce this side's local partial. Use the keysetup role flag.
    info "Producing this side's local partial decryption (keysetup role: $JULENNY_ROLE)..."
    local lead_flag=""
    [[ "$JULENNY_ROLE" == "lead" ]] && lead_flag="--lead"
    julenny-toolkit crypto partial-decrypt \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --input "$result_bin" \
        --secret-key "$my_secret" \
        --output "$my_partial_bin" \
        $lead_flag \
        > /dev/null
    success "Our partial: $my_partial_bin"

    # 5. Combine both partials and render the answer.
    # Branching driven by the function-def's output.layout. See
    # original 06-decrypt.sh for the full rationale.
    local function_def="$JL_WORKDIR/function-def.json"
    local output_layout="scalar"
    if [[ -f "$function_def" ]]; then
        output_layout="$(jq -r '.output.layout // "scalar"' "$function_def")"
    fi

    # Weight-vector functions (e.g. federated-average) produce REAL-valued
    # slots (fractional model weights). Integer rounding would destroy them,
    # so combine with --real and skip the indicator-style analysis entirely.
    local weight_inputs=0
    if [[ -f "$function_def" ]]; then
        weight_inputs="$(jq '[.inputs[]? | select(.schema == "weight-vector")] | length' "$function_def")"
    fi

    step "Decrypting the answer (combining both partials)..."

    if (( weight_inputs > 0 )); then
        # How many slots to show: the operator's own input vector length is
        # the best guess (JULENNY_INPUT_CSV is persisted by 04-encrypt);
        # JULENNY_SHOW_SLOTS overrides; fallback 16.
        local n_slots="${JULENNY_SHOW_SLOTS:-}"
        if [[ -z "$n_slots" && -n "${JULENNY_INPUT_CSV:-}" && -f "${JULENNY_INPUT_CSV:-}" ]]; then
            # grep -c '' not wc -l: wc counts newlines, so it undercounts by
            # one when the operator's file has no trailing newline.
            n_slots="$(grep -c '' < "$JULENNY_INPUT_CSV")"
        fi
        [[ -n "$n_slots" && "$n_slots" -gt 0 ]] || n_slots=16
        julenny-toolkit crypto combine \
            --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
            --partials "$peer_partial_bin" "$my_partial_bin" \
            --real --show-slots "$n_slots"
        echo
        success "Decryption complete. The combined (averaged) vector is shown above."
        echo
        info "Showing the first $n_slots slots. To see more: re-run 'julenny-toolkit crypto combine'"
        info "with a larger --show-slots, or set JULENNY_SHOW_SLOTS and re-run this script."
        return 0
    fi

    local combine_json; combine_json="$(julenny-toolkit crypto combine \
        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
        --partials "$peer_partial_bin" "$my_partial_bin" \
        --non-zero --json)"

    local non_zero total_slots
    non_zero="$(   echo "$combine_json" | jq -r '.nonZeroSlots')"
    total_slots="$(echo "$combine_json" | jq -r '.totalSlots')"
    info "Combined plaintext: $non_zero non-zero slot(s) out of $total_slots."
    info "Function output layout: $output_layout"

    case "$output_layout" in
        scalar|scalar-int)
            local answer; answer="$(echo "$combine_json" | jq -r '.answer // empty')"
            echo
            if [[ -n "$answer" ]]; then
                success "Answer: $answer"
            else
                warn "Output is declared '$output_layout' but combine didn't report a uniform answer."
                warn "Raw non-zero slot positions and values:"
                echo "$combine_json" | jq -r '(.significantValues // .nonZeroValues) | to_entries[] | "    [\(.key)] = \(.value)"'
            fi
            ;;
        packed-real-vector)
            # Real-valued score vector (e.g. decision-tree per-class scores).
            # Show the actual slot values; the predicted class is the argmax. This
            # is NOT an indicator vector, so do not resolve slots against a dataset.
            local n_show="${JULENNY_SHOW_SLOTS:-8}"
            echo
            julenny-toolkit crypto combine \
                --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
                --partials "$peer_partial_bin" "$my_partial_bin" \
                --real --show-slots "$n_show"
            echo
            success "Decryption complete. The real-valued result vector is shown above (predicted class = argmax)."
            ;;
        packed-int-vector|indicator-hash)
            # Itemized indicator vector: resolve hash-bucket positions back to
            # record names against THIS side's own
            # dataset CSV. Works for either viewer: each side resolves against
            # the encrypted indicator input matching its own role (dataOwner
            # for the owner, queryAnalyst for the consumer).
            local my_role input_name
            if [[ "$JULENNY_OUR_SIDE" == "data-owner" ]]; then my_role="dataOwner"; else my_role="queryAnalyst"; fi
            input_name="$(jq -r --arg r "$my_role" '[.inputs[]? | select(.role == $r) | select((.encoding // "") | startswith("plaintext") | not)][0].name // empty' "$function_def" 2>/dev/null)"
            [[ -n "$input_name" ]] || input_name="${JULENNY_INPUT_NAME:-}"
            # Rule-pair functions (rule-based-cross-match family): the output
            # slot index is the ROW NUMBER in the pair-list input (0-based,
            # blank lines skipped) - "a nonzero value at position i means
            # rule pair i was matched". Hash-based resolve-indicator does NOT
            # apply; print the matched rows of the pair list directly.
            local pair_input
            pair_input="$(jq -r '[.inputs[]? | select((.layout // "") == "pair-list")][0].name // empty' "$function_def" 2>/dev/null)"
            if [[ -n "$pair_input" ]]; then
                echo
                if (( non_zero == 0 )); then
                    success "Answer: 0 matches. (No rule pair was satisfied by both sides.)"
                else
                    # Best source for the pair list: the local path recorded
                    # when this side uploaded it (my_plaintext_paths.json).
                    local pair_file=""
                    if [[ -f "$JL_WORKDIR/my_plaintext_paths.json" ]]; then
                        pair_file="$(jq -r --arg n "$pair_input" '.[$n].path // empty' "$JL_WORKDIR/my_plaintext_paths.json")"
                    fi
                    if [[ -z "$pair_file" || ! -f "$pair_file" ]]; then
                        pair_file="$(pick_data_file "File with the '$pair_input' rows used for this run")"
                    fi
                    info "Pair list: $pair_file"
                    local _rows=() _row _slot
                    while IFS= read -r _row; do _rows+=("$_row"); done \
                        < <(grep -v '^[[:space:]]*$' "$pair_file")
                    success "Matched rule pairs (satisfied by BOTH sides):"
                    for _slot in $(echo "$combine_json" | jq -r '(.significantValues // .nonZeroValues) | keys_unsorted[]' | sort -n); do
                        if (( _slot < ${#_rows[@]} )); then
                            echo "    pair $_slot: ${_rows[$_slot]}"
                        else
                            warn "    pair $_slot: index beyond the pair list ($((${#_rows[@]})) rows) - wrong file?"
                        fi
                    done
                fi
            # binary-indicator functions (negotiation-matrix family): slots
            # are GRID POSITIONS in the agreed term grid, not hash buckets,
            # so resolve-indicator does not apply. Print positions directly.
            elif [[ -f "$function_def" && -n "$input_name" ]] && \
               jq -e --arg n "$input_name" \
                  '.inputs[]? | select(.name == $n and .schema == "binary-indicator")' \
                  "$function_def" >/dev/null 2>&1; then
                echo
                if (( non_zero == 0 )); then
                    success "Answer: 0 matches. (No grid position was accepted by both sides.)"
                else
                    success "Both sides accepted these grid positions:"
                    echo "$combine_json" | jq -r '(.significantValues // .nonZeroValues) | to_entries[] | "    position \(.key)  (slot value \(.value))"'
                    info "Map positions back to contract terms with your grid file (comment lines excluded)."
                fi
            elif true; then
                if (( non_zero == 0 )); then
                    echo
                    success "Answer: 0 matches.  (No slots overlapped; the two datasets are disjoint.)"
                elif [[ ! -f "$function_def" ]]; then
                    warn "No function-def at $function_def; cannot resolve indicator slots."
                    echo "$combine_json" | jq -r '(.significantValues // .nonZeroValues) | to_entries[] | "    [\(.key)] = \(.value)"'
                elif [[ -z "$input_name" ]]; then
                    warn "Could not determine this side's indicator input from the function-def."
                    warn "Set JULENNY_INPUT_NAME to your indicator input and re-run to resolve names."
                    echo "$combine_json" | jq -r '(.significantValues // .nonZeroValues) | to_entries[] | "    [\(.key)] = \(.value)"'
                else
                    local exec_doc input_idx my_datasets_json my_dset_id="" my_dset_name=""
                    exec_doc="$(curl_jl GET "/api/executions/$exec_id")"
                    # /execute maps inputDatasetIds positionally to the
                    # function-def's .inputs[] order, so the dataset behind
                    # OUR indicator input sits at that input's index.
                    # (Scanning for "any dataset of ours" picked the wrong
                    # one when this side owned several inputs.)
                    input_idx="$(jq -r --arg n "$input_name" '(.inputs | map(.name) | index($n)) // empty' "$function_def")"
                    [[ -n "$input_idx" ]] && my_dset_id="$(echo "$exec_doc" | jq -r ".inputDatasetIds[$input_idx] // empty")"
                    my_datasets_json="$(my_datasets_in_project)"
                    [[ -n "$my_dset_id" ]] && my_dset_name="$(echo "$my_datasets_json" | jq -r --arg id "$my_dset_id" '.[] | select(.id == $id) | .name // empty')"

                    local csv_map_file="$JL_WORKDIR/dataset_csv_map.json"
                    local input_csv=""
                    if [[ -n "$my_dset_id" && -f "$csv_map_file" ]]; then
                        input_csv="$(jq -r --arg id "$my_dset_id" '.[$id] // empty' "$csv_map_file")"
                    fi
                    [[ -n "$my_dset_id" ]] && info "Your dataset for this execution: '$my_dset_name' ($my_dset_id)"

                    if [[ -n "$input_csv" && -f "$input_csv" ]]; then
                        info "Originating CSV (from dataset map): $input_csv"
                    else
                        if [[ -n "$input_csv" ]]; then
                            warn "Map says the CSV was $input_csv but that file no longer exists."
                        elif [[ -n "$my_dset_id" ]]; then
                            warn "No CSV mapping for dataset $my_dset_id. The CSV you provide MUST"
                            warn "  be the EXACT one that was encrypted to create this dataset."
                        fi
                        input_csv="$(pick_data_file "Originating CSV for dataset '${my_dset_name:-?}'" "${JULENNY_INPUT_CSV:-}")"
                        [[ -f "$input_csv" ]] || die "CSV not found: $input_csv"
                        if [[ -n "$my_dset_id" ]]; then
                            local existing_map='{}'
                            [[ -f "$csv_map_file" ]] && existing_map="$(cat "$csv_map_file")"
                            echo "$existing_map" \
                                | jq --arg id "$my_dset_id" --arg p "$input_csv" '. + {($id): $p}' \
                                > "$csv_map_file.tmp" && mv "$csv_map_file.tmp" "$csv_map_file"
                            info "Mapped dataset $my_dset_id -> $input_csv in $csv_map_file."
                        fi
                    fi

                    local slots_csv; slots_csv="$(echo "$combine_json" | jq -r '(.significantValues // .nonZeroValues) | keys | join(",")')"
                    echo
                    step "Resolving $non_zero non-zero slot(s) against $input_csv..."
                    julenny-toolkit crypto resolve-indicator \
                        --context-spec "$JULENNY_CRYPTO_CONTEXT_SPEC" \
                        --slots "$slots_csv" \
                        --input "$input_csv" \
                        --function-def "$function_def" \
                        --input-name "$input_name"
                fi
            fi
            ;;
        *)
            warn "Unknown output.layout '$output_layout'. Showing raw combine output."
            echo "$combine_json" | jq .
            ;;
    esac

    echo
    success "Decryption complete. The plaintext answer is shown above."
    echo
    info "If the answer is what you expected: keysetup, encryption, computation, and decryption all worked end-to-end."
}

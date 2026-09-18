#!/usr/bin/env bash
# Merge the JuLenny MCP connector into Claude Desktop's config (Linux), preserving any
# other servers. Counterpart to windows/installer/merge-claude-config.ps1, and kept at
# parity with it: the Windows side pins the toolkit binary and the working folder, and
# a Linux install that set neither behaved differently for no good reason.
#
# Usage:
#   merge-claude-config.sh <api-key> [mcp-path] [api-url] [connector-name] [workdir]
#
# <workdir> is the ONE folder both surfaces use (the scripts read the same
# value). When given, it is written into the connector's environment AND recorded in
# $XDG_CONFIG_HOME/julenny/workdir, which is what scripts/_core/lib.sh reads. Leave it
# out and both fall back to ~/julenny-workdir.
set -euo pipefail

API_KEY="${1:?usage: merge-claude-config.sh <api-key> [mcp-path] [api-url] [connector-name] [workdir]}"
MCP_PATH="${2:-/usr/bin/julenny-mcp}"
API_URL="${3:-https://julenny.net}"
NAME="${4:-JuLenny}"
WORKDIR="${5:-}"

# The CLI the connector shells out to for every crypto verb. Pinned to an absolute path
# for the same reason Windows pins it: a desktop client inherits the PATH it was launched
# with, so a toolkit installed after the client started is invisible to it and every
# crypto verb fails with a bare "not found".
TOOLKIT_BIN="${JULENNY_TOOLKIT_BIN:-/usr/bin/julenny-toolkit}"

command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 1; }

CFG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/Claude"
CFG="$CFG_DIR/claude_desktop_config.json"
mkdir -p "$CFG_DIR"
[[ -s "$CFG" ]] || echo '{}' > "$CFG"

tmp="$(mktemp)"
jq --arg name "$NAME" \
   --arg cmd "$MCP_PATH" \
   --arg key "$API_KEY" \
   --arg url "$API_URL" \
   --arg bin "$TOOLKIT_BIN" \
   --arg wd  "$WORKDIR" \
   '.mcpServers = (.mcpServers // {})
    | .mcpServers[$name] = {
        command: $cmd,
        env: ({ JULENNY_API_KEY: $key, JULENNY_API_URL: $url, JULENNY_TOOLKIT_BIN: $bin }
              + (if $wd == "" then {} else { JULENNY_WORKDIR: $wd } end))
      }' \
   "$CFG" > "$tmp" && mv "$tmp" "$CFG"
echo "Merged '$NAME' MCP connector into $CFG"

# Record the working folder where BOTH surfaces look for it. Without this the connector
# would use the folder pinned above while the scripts used the default, which is
# exactly the split this file is here to end.
if [[ -n "$WORKDIR" ]]; then
    SETTINGS_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/julenny"
    mkdir -p "$SETTINGS_DIR"
    printf '%s\n' "$WORKDIR" > "$SETTINGS_DIR/workdir"
    mkdir -p "$WORKDIR"
    echo "Working folder set to $WORKDIR (recorded in $SETTINGS_DIR/workdir)"
fi

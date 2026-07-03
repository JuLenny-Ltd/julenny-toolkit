#!/usr/bin/env bash
# Merge the JuLenny MCP connector into Claude Desktop's config (Linux),
# preserving any other servers. Counterpart to windows/installer/merge-claude-config.ps1.
# Usage: merge-claude-config.sh <api-key> [mcp-path] [api-url] [connector-name]
set -euo pipefail
API_KEY="${1:?usage: merge-claude-config.sh <api-key> [mcp-path] [api-url] [connector-name]}"
MCP_PATH="${2:-/usr/bin/julenny-mcp}"
API_URL="${3:-https://julenny.net}"
NAME="${4:-JuLenny}"
command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 1; }
CFG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/Claude"
CFG="$CFG_DIR/claude_desktop_config.json"
mkdir -p "$CFG_DIR"
[[ -s "$CFG" ]] || echo '{}' > "$CFG"
tmp="$(mktemp)"
jq --arg name "$NAME" --arg cmd "$MCP_PATH" --arg key "$API_KEY" --arg url "$API_URL" \
   '.mcpServers = (.mcpServers // {}) | .mcpServers[$name] = {command: $cmd, env: {JULENNY_API_KEY: $key, JULENNY_API_URL: $url}}' \
   "$CFG" > "$tmp" && mv "$tmp" "$CFG"
echo "Merged '$NAME' MCP connector into $CFG"

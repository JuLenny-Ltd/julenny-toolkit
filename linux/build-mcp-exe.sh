#!/usr/bin/env bash
# Build the MCP server as a single self-contained executable (Node SEA), Linux.
# Produces mcp/sea/julenny-mcp (no Node needed at runtime). The .deb picks it up
# automatically (see CMakeLists.txt FHE_TOOLKIT_BUNDLE_MCP). Counterpart to
# windows/build-mcp-exe.ps1. Validated 2026-06-24: bundle + blob + inject + load.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MCP_DIR="$(cd "$HERE/../mcp" && pwd)"
SEA_DIR="$MCP_DIR/sea"
FUSE="NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"

cd "$MCP_DIR"
mkdir -p "$SEA_DIR"
echo "1/4 install build deps (esbuild, postject)..."
npm install --no-save esbuild postject >/dev/null
echo "2/4 bundle ESM TypeScript -> single CJS..."
npx esbuild src/index.ts --bundle --platform=node --format=cjs --target=node20 \
    --outfile="$SEA_DIR/julenny-mcp.cjs"
node --check "$SEA_DIR/julenny-mcp.cjs"
echo "3/4 generate the SEA blob..."
cat > "$SEA_DIR/sea-config.json" <<JSON
{ "main": "$SEA_DIR/julenny-mcp.cjs", "output": "$SEA_DIR/julenny-mcp.blob", "disableExperimentalSEAWarning": true }
JSON
node --experimental-sea-config "$SEA_DIR/sea-config.json"
echo "4/4 copy node + inject the blob..."
cp "$(command -v node)" "$SEA_DIR/julenny-mcp"
npx postject "$SEA_DIR/julenny-mcp" NODE_SEA_BLOB "$SEA_DIR/julenny-mcp.blob" --sentinel-fuse "$FUSE"
chmod +x "$SEA_DIR/julenny-mcp"
echo "Built: $SEA_DIR/julenny-mcp"
echo "Smoke test: printf '' | timeout 3 $SEA_DIR/julenny-mcp   (exit 124 = started clean)"

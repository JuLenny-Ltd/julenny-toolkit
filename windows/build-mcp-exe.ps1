# Build the MCP server as a single self-contained julenny-mcp.exe (Node SEA).
# No Node install required on the end-user machine. The exe still shells out to
# julenny-toolkit.exe at runtime (both ship in the installer).
#
# Recipe: bundle the ESM TypeScript to ONE CommonJS file (esbuild), generate a
# SEA blob, copy node.exe, and inject the blob with postject. The MCP has no
# native modules (only @modelcontextprotocol/sdk + zod, pure JS), so SEA is clean;
# the only wrinkle is ESM->CJS, which the esbuild bundle step handles.
#
# DRAFT (2026-06-22): NOT yet run end-to-end (sandbox VM was down for the spike).
# Validate the produced exe starts and serves MCP over stdio before shipping.
#
# Usage:  powershell -ExecutionPolicy Bypass -File windows\build-mcp-exe.ps1
[CmdletBinding()]
param([switch]$Sign)

$ErrorActionPreference = "Stop"
$Local = "Continue"   # tolerate native-tool stderr; gate on $LASTEXITCODE

$repoRoot = Split-Path -Parent $PSScriptRoot           # ...\fhe-toolkit
$mcpDir   = Join-Path $repoRoot "mcp"
$seaDir   = Join-Path $mcpDir "sea"
$bundle   = Join-Path $seaDir "julenny-mcp.cjs"
$blob     = Join-Path $seaDir "julenny-mcp.blob"
$exe      = Join-Path $seaDir "julenny-mcp.exe"
$seaCfg   = Join-Path $seaDir "sea-config.json"
$fuse     = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"

if (-not (Test-Path (Join-Path $mcpDir "package.json"))) { throw "mcp/package.json not found." }
New-Item -ItemType Directory -Force -Path $seaDir | Out-Null

Push-Location $mcpDir
try {
    Write-Host "1/5  Installing build deps (esbuild, postject)..."
    & npm install --no-save esbuild postject; if ($LASTEXITCODE -ne 0) { throw "npm install failed" }

    Write-Host "2/5  Bundling ESM TypeScript -> single CommonJS file..."
    & npx esbuild src/index.ts --bundle --platform=node --format=cjs --target=node20 --outfile="$bundle"
    if ($LASTEXITCODE -ne 0) { throw "esbuild bundle failed" }

    Write-Host "3/5  Writing SEA config + generating the blob..."
    # Node's --experimental-sea-config JSON parser rejects a UTF-8 BOM, which
    # Windows PowerShell's `Set-Content -Encoding UTF8` emits. Write UTF-8 WITHOUT
    # a BOM via .NET so node can parse it.
    $seaCfgJson = @{ main = $bundle; output = $blob; disableExperimentalSEAWarning = $true } | ConvertTo-Json
    [System.IO.File]::WriteAllText($seaCfg, $seaCfgJson, (New-Object System.Text.UTF8Encoding($false)))
    & node --experimental-sea-config "$seaCfg"; if ($LASTEXITCODE -ne 0) { throw "sea-config blob generation failed" }

    Write-Host "4/5  Copying node.exe -> julenny-mcp.exe..."
    Copy-Item (Get-Command node).Source $exe -Force
    # Strip node.exe's signature so postject can rewrite the resource section.
    # signtool ships with the Windows SDK and may not be on PATH; it's optional
    # (postject injects regardless - it just invalidates node's signature, which
    # is irrelevant for an unsigned dev build and re-signed at release time).
    if (Get-Command signtool -ErrorAction SilentlyContinue) {
        & signtool remove /s $exe 2>$null
    } else {
        Write-Host "     (signtool not on PATH; skipping signature strip)"
    }

    Write-Host "5/5  Injecting the SEA blob with postject..."
    & npx postject $exe NODE_SEA_BLOB $blob --sentinel-fuse $fuse
    if ($LASTEXITCODE -ne 0) { throw "postject injection failed" }

    if ($Sign) {
        Write-Host "Signing julenny-mcp.exe..."
        # signtool sign /fd SHA256 /a /tr <timestamp> /td SHA256 $exe
        Write-Warning "Pass your signing cert args here (left as a placeholder)."
    }

    Write-Host ""
    Write-Host "Built: $exe"
    Write-Host "Smoke test: run it and confirm it starts an MCP stdio server without crashing."
}
finally { Pop-Location }

# Merge the JuLenny MCP connector into Claude Desktop's config, preserving any
# other servers already present. Called by the Inno installer's [Run] step (only
# when the MCP component is selected). Safe to run standalone for testing.
#
# Claude Desktop stores its config in DIFFERENT places depending on how it was
# installed, and a packaged install cannot see the plain %APPDATA% path:
#   - Standalone (.exe) install:  %APPDATA%\Claude\claude_desktop_config.json
#   - Microsoft Store / MSIX:     %LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\claude_desktop_config.json
# We write to every location that is actually present so the connector is picked
# up regardless of install type. If none exist yet, we create the standalone one.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ApiKey,
    [string] $McpExePath = "$env:LOCALAPPDATA\Programs\julenny-fhe\julenny-mcp.exe",
    [string] $ApiUrl     = "https://julenny.net",
    # Optional. When non-empty, written as JULENNY_WORKDIR; blank = MCP default
    # (%LOCALAPPDATA%\julenny-fhe\workdir, created on first run).
    [string] $Workdir    = "",
    # The connector key shown in Claude Desktop's UI and used as the mcp__<key>__ namespace.
    [string] $ConnectorName = "JuLenny"
)

$ErrorActionPreference = "Stop"

# --- discover every Claude Desktop config directory on this machine ---
$cfgDirs = @()
$standalone = Join-Path $env:APPDATA "Claude"
if (Test-Path $standalone) { $cfgDirs += $standalone }
$pkgRoot = Join-Path $env:LOCALAPPDATA "Packages"
if (Test-Path $pkgRoot) {
    Get-ChildItem $pkgRoot -Filter "Claude_*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $packaged = Join-Path $_.FullName "LocalCache\Roaming\Claude"
        if (Test-Path $packaged) { $cfgDirs += $packaged }
    }
}
if ($cfgDirs.Count -eq 0) {
    # Neither install type has created a config dir yet; default to standalone.
    New-Item -ItemType Directory -Force -Path $standalone | Out-Null
    $cfgDirs += $standalone
}

# UTF-8 without BOM (matches what Claude Desktop writes; avoids a BOM at the top).
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

foreach ($cfgDir in $cfgDirs) {
    $cfgPath = Join-Path $cfgDir "claude_desktop_config.json"

    # Load existing config (or start fresh). Never clobber unrelated content.
    if (Test-Path $cfgPath) {
        $raw = Get-Content -Raw -Path $cfgPath
        if ([string]::IsNullOrWhiteSpace($raw)) {
            $cfg = [pscustomobject]@{}
        } else {
            $cfg = $raw | ConvertFrom-Json
        }
    } else {
        $cfg = [pscustomobject]@{}
    }

    # Ensure an mcpServers object exists.
    if (-not ($cfg.PSObject.Properties.Name -contains 'mcpServers')) {
        $cfg | Add-Member -NotePropertyName 'mcpServers' -NotePropertyValue ([pscustomobject]@{}) -Force
    }

    # Build (or overwrite) just our connector entry; other servers are untouched.
    $envObj = [pscustomobject]@{
        JULENNY_API_KEY = $ApiKey
        JULENNY_API_URL = $ApiUrl
    }
    # Only pin a workdir if the user gave one; otherwise the MCP uses its default.
    if (-not [string]::IsNullOrWhiteSpace($Workdir)) {
        $envObj | Add-Member -NotePropertyName 'JULENNY_WORKDIR' -NotePropertyValue $Workdir -Force
    }
    $entry = [pscustomobject]@{
        command = $McpExePath
        env     = $envObj
    }
    $cfg.mcpServers | Add-Member -NotePropertyName $ConnectorName -NotePropertyValue $entry -Force

    $json = $cfg | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($cfgPath, $json, $utf8NoBom)
    Write-Host "Merged '$ConnectorName' MCP connector into $cfgPath"
}

# Shared helper library for the _core collaboration driver. PowerShell twin of
# lib.sh, for the Windows scripts path.
#
# Dot-source AFTER the side profile:
#   . "$PSScriptRoot\sides\data-owner.ps1"
#   . "$PSScriptRoot\lib.ps1"
#
# ============================================================================
# PORT STATUS - this file is NOT yet a complete twin of lib.sh (53 functions).
#
#   DONE  paths and per-collab state, output helpers, config.env read/write,
#         session load, prompts, data-file picker, HTTP wrapper, download,
#         keysetup + result-visibility queries, permission/collab/function
#         listing.
#   TODO  peer share transfer (download_peer_share, wait_for_peer_share),
#         wrap_and_upload (envelope signing), create_collaboration,
#         create_permission, the rotation-key family, upload_plaintext_dataset,
#         all_required_inputs_declared, releaser_flow, viewer_flow.
#
# Do not ship a Windows release until the TODO list is empty and a real
# two-party run has been verified end to end.
# ============================================================================
#
# Differences from lib.sh, all deliberate:
#
#   * UI goes to Write-Host; values come back as return values. lib.sh sends all
#     UI to stderr so $(...) captures only the value. PowerShell returns objects,
#     so that split is unnecessary.
#   * The API wrapper returns PARSED objects (Invoke-JlApi) or writes bytes to a
#     file (Save-JlApiFile), rather than mirroring curl's flags. Callers use
#     property access instead of piping to jq.
#   * config.env keeps the bash KEY="value" format and is parsed by hand.
#     PowerShell cannot source a bash file, and inventing a second format would
#     mean the docs no longer describe what is on disk.
#
# Windows PowerShell 5.1 compatible: no ternary, no null-coalescing, no
# null-conditional. Binary file I/O goes through [System.IO.File] rather than
# Get-Content/Set-Content, which mangle bytes.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Invoke-WebRequest's progress bar costs more than the transfer on small calls.
$ProgressPreference = 'SilentlyContinue'

# Some Windows PowerShell 5.1 installs still default to TLS 1.0/1.1, which the
# platform refuses. Opt in explicitly rather than relying on the machine default.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# -------- guard: the side profile must be loaded first --------
if (-not (Get-Variable -Name JULENNY_OUR_SIDE -Scope Script -ErrorAction SilentlyContinue)) {
    throw "lib.ps1: no side profile loaded. Dot-source sides\data-owner.ps1 or sides\data-consumer.ps1 first."
}

# ============================================================================
# Paths
# ============================================================================
# Root workdir on this machine. Holds:
#   signing\                    Ed25519 signing keys (account-scoped,
#                               scheme-agnostic). Reused across collaborations.
#   collabs\<jointKeyId>\       Per-collaboration state: config.env, keys\,
#                               envelopes\, peer\, function-def.json.
#   CURRENT                     Plain text file holding the joint key id of the
#                               most recently activated collab.
#
# Set JL_WORKDIR_ROOT (or the JL_ROOT env var, matching lib.sh) to relocate it.
if ($env:JL_ROOT) {
    $script:JL_ROOT = $env:JL_ROOT
} else {
    $script:JL_ROOT = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.julenny-collab'
}
$script:JL_SIGNING_DIR    = Join-Path $script:JL_ROOT 'signing'
$script:JL_SIGNING_SECRET = Join-Path $script:JL_SIGNING_DIR 'signing_secret_key.bin'
$script:JL_SIGNING_PUBLIC = Join-Path $script:JL_SIGNING_DIR 'signing_public_key.bin'
$script:JL_COLLABS_DIR    = Join-Path $script:JL_ROOT 'collabs'
$script:JL_CURRENT_FILE   = Join-Path $script:JL_ROOT 'CURRENT'

# Per-collab paths. Set-JlActiveJointKey fills these in; empty until a joint key
# is chosen (00-init) or resolved at load time.
$script:JL_WORKDIR  = ''
$script:JL_CONFIG   = ''
$script:JL_KEYS_DIR = ''
$script:JL_ENV_DIR  = ''
$script:JL_PEER_DIR = ''

# Session values read out of config.env by Import-JlSession.
$script:JULENNY_API_KEY       = ''
$script:JULENNY_API_BASE      = ''
$script:JULENNY_PROJECT_ID    = ''
$script:JULENNY_PERMISSION_ID = ''
$script:JULENNY_SIGNING_SECRET = ''

# ============================================================================
# Output
# ============================================================================
# Local time of the machine running the script, prefixed on every log line so
# logs from the two sides can be correlated.
function Get-JlTimestamp { return (Get-Date -Format 'HH:mm:ss') }

function Write-JlInfo {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Message)
    Write-Host ("[{0}] " -f (Get-JlTimestamp)) -NoNewline
    Write-Host "[info]  " -ForegroundColor Blue -NoNewline
    Write-Host ($Message -join ' ')
}

function Write-JlSuccess {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Message)
    Write-Host ("[{0}] " -f (Get-JlTimestamp)) -NoNewline
    Write-Host "[ok]    " -ForegroundColor Green -NoNewline
    Write-Host ($Message -join ' ')
}

function Write-JlWarn {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Message)
    Write-Host ("[{0}] " -f (Get-JlTimestamp)) -NoNewline
    Write-Host "[warn]  " -ForegroundColor Yellow -NoNewline
    Write-Host ($Message -join ' ')
}

function Write-JlErr {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Message)
    Write-Host ("[{0}] " -f (Get-JlTimestamp)) -NoNewline
    Write-Host "[err]   " -ForegroundColor Red -NoNewline
    Write-Host ($Message -join ' ')
}

# Terminates the script. Mirrors lib.sh's die.
function Stop-JlWithError {
    param([Parameter(Mandatory = $true)][string] $Message)
    Write-JlErr $Message
    exit 1
}

function Write-JlStep {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Message)
    Write-Host ""
    Write-Host ("==> " + ($Message -join ' ')) -ForegroundColor White
}

function Write-JlWaitMessage {
    param([Parameter(Mandatory = $true)][string] $Message)
    Write-Host ""
    Write-Host "------------------------------------------------" -ForegroundColor Yellow
    Write-Host ("  WAITING ON THE OTHER SIDE ({0})" -f $script:JL_PEER_LABEL) -ForegroundColor Yellow
    Write-Host "------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  $Message"
    Write-Host ""
}

# ============================================================================
# Prompts
# ============================================================================
function Read-JlValue {
    param(
        [Parameter(Mandatory = $true)][string] $Prompt,
        [string] $Default = ''
    )
    if ([string]::IsNullOrEmpty($Default)) {
        $answer = Read-Host $Prompt
    } else {
        $answer = Read-Host ("{0} [{1}]" -f $Prompt, $Default)
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
    }
    return $answer
}

# Reads without echoing. Returns plain text: the value goes straight into
# config.env and an API header, so a SecureString would only be theatre.
function Read-JlSecret {
    param([Parameter(Mandatory = $true)][string] $Prompt)
    $secure = Read-Host $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

# Offers the scenario's data files ($JL_DATA_DIR) for one-key selection, with
# 'o' for a free-text path. Returns the chosen path.
function Select-JlDataFile {
    param(
        [Parameter(Mandatory = $true)][string] $Prompt,
        [string] $DefaultPath = ''
    )
    $dataDir = ''
    if (Get-Variable -Name JL_DATA_DIR -Scope Script -ErrorAction SilentlyContinue) {
        $dataDir = $script:JL_DATA_DIR
    }

    $files = @()
    if ($dataDir -and (Test-Path -LiteralPath $dataDir)) {
        $files = @(Get-ChildItem -LiteralPath $dataDir -File | Sort-Object Name)
    }

    Write-Host ""
    if ($files.Count -gt 0) {
        Write-JlInfo "Files available in ${dataDir}:"
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("  [{0}] {1}" -f ($i + 1), $files[$i].Name)
        }
    } else {
        Write-JlInfo "No files found under $dataDir."
    }
    Write-Host "  o) Other (type a path)"
    Write-Host ""

    if ($files.Count -eq 0) {
        $choice = 'o'
        Write-JlInfo "No files in data\; defaulting to 'o' (type a path)."
    } else {
        $choice = Read-JlValue ("{0} (1-{1}, or o)" -f $Prompt, $files.Count) '1'
    }

    if ($choice -match '^[Oo]$') {
        $picked = Read-JlValue $Prompt $DefaultPath
    } else {
        $n = 0
        if (-not [int]::TryParse($choice, [ref] $n) -or $n -lt 1 -or $n -gt $files.Count) {
            Stop-JlWithError "Invalid choice: '$choice' (must be 1-$($files.Count) or 'o')"
        }
        $picked = $files[$n - 1].FullName
        Write-JlSuccess "Selected: $picked"
    }

    if (-not (Test-Path -LiteralPath $picked -PathType Leaf)) {
        Stop-JlWithError "Input file not found: $picked"
    }
    return $picked
}

# ============================================================================
# config.env (bash KEY="value" format, shared with lib.sh)
# ============================================================================
# Parses config.env into a hashtable. Understands KEY=value and KEY="value",
# skips blanks and # comments, and strips a trailing inline comment only when
# the value was quoted (an unquoted # is part of the value in bash too).
function Read-JlConfigFile {
    param([Parameter(Mandatory = $true)][string] $Path)

    $map = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $map }

    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0)     { continue }
        if ($trimmed.StartsWith('#'))  { continue }
        if ($trimmed.StartsWith('export ')) { $trimmed = $trimmed.Substring(7).Trim() }

        $eq = $trimmed.IndexOf('=')
        if ($eq -lt 1) { continue }

        $key = $trimmed.Substring(0, $eq).Trim()
        $val = $trimmed.Substring($eq + 1).Trim()

        if ($val.Length -ge 2 -and $val.StartsWith('"') -and $val.EndsWith('"')) {
            $val = $val.Substring(1, $val.Length - 2)
            # bash unescapes \" and \\ inside double quotes.
            $val = $val.Replace('\"', '"').Replace('\\', '\')
        } elseif ($val.Length -ge 2 -and $val.StartsWith("'") -and $val.EndsWith("'")) {
            $val = $val.Substring(1, $val.Length - 2)
        }

        # Later assignments win, matching a re-sourced bash file.
        $map[$key] = $val
    }
    return $map
}

# Appends KEY="value" to config.env, in the same format lib.sh writes and reads.
# Appending rather than rewriting matches lib.sh, where later lines override.
function Set-JlConfigValue {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value
    )
    if ([string]::IsNullOrEmpty($script:JL_CONFIG)) {
        Stop-JlWithError "Set-JlConfigValue called before a collaboration was activated."
    }
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    $line = '{0}="{1}"' -f $Name, $escaped
    # LF, no BOM: the same file is read by lib.sh when both sides share a host.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::AppendAllText($script:JL_CONFIG, $line + "`n", $utf8NoBom)
}

# ============================================================================
# Per-collaboration state
# ============================================================================
function Get-JlLocalCollabs {
    if (-not (Test-Path -LiteralPath $script:JL_COLLABS_DIR)) { return @() }
    return @(Get-ChildItem -LiteralPath $script:JL_COLLABS_DIR -Directory |
             Sort-Object LastWriteTime -Descending)
}

# The joint key id to use when none was explicitly chosen: CURRENT if it still
# exists on disk, otherwise the most recently touched collab.
function Get-JlActiveJointKey {
    if (Test-Path -LiteralPath $script:JL_CURRENT_FILE) {
        $current = ([System.IO.File]::ReadAllText($script:JL_CURRENT_FILE)).Trim()
        if ($current -and (Test-Path -LiteralPath (Join-Path $script:JL_COLLABS_DIR $current))) {
            return $current
        }
    }
    $collabs = Get-JlLocalCollabs
    if ($collabs.Count -gt 0) { return $collabs[0].Name }
    return ''
}

# Points the per-collab path variables at one joint key, and records it as
# CURRENT so a later bare script run resolves to the same collaboration.
function Set-JlActiveJointKey {
    param([Parameter(Mandatory = $true)][string] $JointKeyId)

    $script:JL_WORKDIR  = Join-Path $script:JL_COLLABS_DIR $JointKeyId
    $script:JL_CONFIG   = Join-Path $script:JL_WORKDIR 'config.env'
    $script:JL_KEYS_DIR = Join-Path $script:JL_WORKDIR 'keys'
    $script:JL_ENV_DIR  = Join-Path $script:JL_WORKDIR 'envelopes'
    $script:JL_PEER_DIR = Join-Path $script:JL_WORKDIR 'peer'

    foreach ($d in @($script:JL_WORKDIR, $script:JL_KEYS_DIR, $script:JL_ENV_DIR, $script:JL_PEER_DIR)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Force -Path $d | Out-Null
        }
    }

    if (-not (Test-Path -LiteralPath $script:JL_ROOT)) {
        New-Item -ItemType Directory -Force -Path $script:JL_ROOT | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($script:JL_CURRENT_FILE, $JointKeyId + "`n", $utf8NoBom)
}

# Loads config.env for the active collaboration into the session variables.
function Import-JlSession {
    if ([string]::IsNullOrEmpty($script:JL_CONFIG)) {
        $jk = Get-JlActiveJointKey
        if ([string]::IsNullOrEmpty($jk)) {
            Stop-JlWithError "No active collab found under $($script:JL_COLLABS_DIR). Run 00-init.ps1 first."
        }
        Set-JlActiveJointKey $jk
    }
    if (-not (Test-Path -LiteralPath $script:JL_CONFIG)) {
        Stop-JlWithError "No session config at $($script:JL_CONFIG). Run 00-init.ps1 first."
    }

    $cfg = Read-JlConfigFile $script:JL_CONFIG

    foreach ($required in @('JULENNY_API_KEY', 'JULENNY_API_BASE', 'JULENNY_PROJECT_ID',
                            'JULENNY_PERMISSION_ID', 'JULENNY_SIGNING_SECRET')) {
        if (-not $cfg.ContainsKey($required) -or [string]::IsNullOrWhiteSpace($cfg[$required])) {
            Stop-JlWithError "config.env missing $required"
        }
    }

    $script:JULENNY_API_KEY        = $cfg['JULENNY_API_KEY']
    $script:JULENNY_API_BASE       = $cfg['JULENNY_API_BASE']
    $script:JULENNY_PROJECT_ID     = $cfg['JULENNY_PROJECT_ID']
    $script:JULENNY_PERMISSION_ID  = $cfg['JULENNY_PERMISSION_ID']
    $script:JULENNY_SIGNING_SECRET = $cfg['JULENNY_SIGNING_SECRET']

    # Anything else in config.env (JULENNY_INPUT_CSV, function slug, ...) is
    # exposed under the same name so phase scripts can read it.
    foreach ($k in $cfg.Keys) {
        Set-Variable -Name $k -Value $cfg[$k] -Scope Script -Force
    }
}

# ============================================================================
# Platform API
# ============================================================================
# Returns the parsed JSON body. Throws on transport failure; a non-2xx response
# surfaces as a terminating error carrying the platform's message.
function Invoke-JlApi {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string] $Method,
        [Parameter(Mandatory = $true)][string] $Path,
        $Body = $null,
        [switch] $AllowFailure
    )
    $uri = $script:JULENNY_API_BASE + $Path
    $headers = @{ 'x-api-key' = $script:JULENNY_API_KEY }

    $params = @{
        Method      = $Method
        Uri         = $uri
        Headers     = $headers
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) {
        $params['Body']        = (ConvertTo-Json $Body -Depth 20 -Compress)
        $params['ContentType'] = 'application/json'
    }

    try {
        return Invoke-RestMethod @params
    } catch {
        if ($AllowFailure) { return $null }
        $detail = $_.Exception.Message
        try {
            $resp = $_.Exception.Response
            if ($resp) {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $raw = $reader.ReadToEnd()
                if ($raw) { $detail = "$detail -- $raw" }
            }
        } catch { }
        Stop-JlWithError "$Method $Path failed: $detail"
    }
}

# Downloads to a file. Uses Invoke-WebRequest -OutFile, NOT Invoke-RestMethod:
# the latter parses the body, which corrupts ciphertext and key material.
function Save-JlApiFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $OutFile,
        [string] $Method = 'GET'
    )
    $uri = $script:JULENNY_API_BASE + $Path
    $headers = @{ 'x-api-key' = $script:JULENNY_API_KEY }

    $parent = Split-Path -Parent $OutFile
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    try {
        Invoke-WebRequest -Method $Method -Uri $uri -Headers $headers `
                          -OutFile $OutFile -UseBasicParsing -ErrorAction Stop | Out-Null
    } catch {
        Stop-JlWithError "download $Path failed: $($_.Exception.Message)"
    }
    if (-not (Test-Path -LiteralPath $OutFile)) {
        Stop-JlWithError "download $Path produced no file at $OutFile"
    }
}

# ============================================================================
# Permission / keysetup queries
# ============================================================================
function Get-JlKeysetupState {
    return Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/keysetup"
}

function Get-JlPermission {
    return Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)"
}

# "dataConsumer" (default) or "dataOwner": which side decrypts the plaintext.
# Mode "both" exists in the platform plan but is deferred (needs transport-key
# infrastructure for blind relay between parties).
function Get-JlResultVisibility {
    $perm = Get-JlPermission
    $vis = ''
    if ($perm -and $perm.PSObject.Properties.Name -contains 'resultVisibility') {
        $vis = $perm.resultVisibility
    }
    if ([string]::IsNullOrWhiteSpace($vis)) { $vis = 'dataConsumer' }
    return $vis
}

# The viewer downloads the encrypted result plus the peer's partial and runs the
# final combine. The releaser produces a partial and never sees plaintext.
function Test-JlAmViewer {
    $vis = Get-JlResultVisibility
    if ($script:JULENNY_OUR_SIDE -eq 'data-consumer') { return ($vis -eq 'dataConsumer') }
    return ($vis -eq 'dataOwner')
}

function Test-JlAmReleaser {
    return (-not (Test-JlAmViewer))
}

function Get-JlPeerMessages {
    return Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/messages" -AllowFailure
}

# ============================================================================
# Collaboration / permission / function listing
# ============================================================================
function Get-JlCollaborations {
    $resp = Invoke-JlApi GET "/api/fhe-projects?view=$($script:JL_PERM_VIEW)"
    if ($null -eq $resp) { return @() }
    if ($resp.PSObject.Properties.Name -contains 'projects') { return @($resp.projects) }
    return @($resp)
}

function Get-JlPermissionsForJointKey {
    param([Parameter(Mandatory = $true)][string] $JointKeyId)
    $resp = Invoke-JlApi GET "/api/fhe-permissions?view=$($script:JL_PERM_VIEW)&jointKeyId=$JointKeyId"
    if ($null -eq $resp) { return @() }
    if ($resp.PSObject.Properties.Name -contains 'permissions') { return @($resp.permissions) }
    return @($resp)
}

function Get-JlFunctions {
    $resp = Invoke-JlApi GET "/api/fhe-functions"
    if ($null -eq $resp) { return @() }
    if ($resp.PSObject.Properties.Name -contains 'functions') { return @($resp.functions) }
    return @($resp)
}

function Get-JlFunctionsByScheme {
    param([Parameter(Mandatory = $true)][ValidateSet('CKKS', 'BFV')][string] $Scheme)
    return @(Get-JlFunctions | Where-Object { $_.scheme -eq $Scheme })
}

function Get-JlMyDatasetsInProject {
    $resp = Invoke-JlApi GET "/api/fhe-datasets?projectId=$($script:JULENNY_PROJECT_ID)" -AllowFailure
    if ($null -eq $resp) { return @() }
    if ($resp.PSObject.Properties.Name -contains 'datasets') { return @($resp.datasets) }
    return @($resp)
}

# Writes the permission's function definition to the workdir and returns it.
function Update-JlFunctionDef {
    $perm = Get-JlPermission
    $slug = $perm.functionSlug
    $version = $perm.functionVersion
    if ([string]::IsNullOrWhiteSpace($slug)) {
        Stop-JlWithError "Permission $($script:JULENNY_PERMISSION_ID) has no functionSlug."
    }
    $def = Invoke-JlApi GET "/api/fhe-functions/$slug/versions/$version"
    $out = Join-Path $script:JL_WORKDIR 'function-def.json'
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($out, (ConvertTo-Json $def -Depth 30), $utf8NoBom)
    return $def
}

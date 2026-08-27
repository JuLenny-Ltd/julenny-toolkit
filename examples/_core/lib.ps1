# Shared helper library for the _core collaboration driver. PowerShell twin of
# lib.sh, for the Windows scripts path.
#
# Dot-source AFTER the side profile:
#   . "$PSScriptRoot\sides\data-owner.ps1"
#   . "$PSScriptRoot\lib.ps1"
#
# ============================================================================
# PORT STATUS: this library is COMPLETE. Every function lib.sh exposes has a
# twin here, including releaser_flow and viewer_flow with all their output
# layouts (scalar, packed-real-vector, pair-list, binary-indicator, and the
# hash-bucket resolve path).
#
# Still to do elsewhere in the port: the numbered phase scripts, run.ps1, and
# the per-scenario bootstraps.
#
# Deliberately NOT ported: migrate_legacy_workdir_if_needed. It migrates a
# pre-refactor workdir layout that only ever existed on Linux; the Windows
# scripts path is new, so there is nothing to migrate from.
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
# Where _core itself lives. Captured while this file is being dot-sourced, so it
# points at _core rather than at whichever phase script did the dot-sourcing.
# Used to locate recipe\recipe-encode.mjs.
$script:JL_CORE_DIR = $PSScriptRoot

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
# The API key is account-scoped, like the signing key, not collaboration-scoped. It used
# to live only in each collaboration's config.env, so every new collaboration asked for
# it again AND left another copy of a live key on disk. Remembered here once instead.
$script:JL_ACCOUNT_CONFIG = Join-Path $script:JL_ROOT 'account.env'
$script:JL_CURRENT_FILE   = Join-Path $script:JL_ROOT 'CURRENT'

# The scenario's data\ directory, set by the per-side bootstrap. It arrives as an
# environment variable because the bootstrap launches run.ps1 as a child process,
# mirroring how the bash bootstraps export JL_DATA_DIR.
if ($env:JL_DATA_DIR) { $script:JL_DATA_DIR = $env:JL_DATA_DIR }

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
# Does $Object have a property called $Name?
#
# Do NOT write $Object.PSObject.Properties.Name -contains 'x'. When the object has
# ZERO properties - an API returning {} - member enumeration on the empty property
# collection cannot find 'Name', and StrictMode turns that into a TERMINATING
# error. The guard written to be safe becomes the crash, and it only fires on a
# first run, when nothing has been declared yet.
# POST a hand-built multipart body.
#
# Windows PowerShell 5.1 mangles a byte[] passed to Invoke-RestMethod -Body when
# -ContentType is set: the array goes through string encoding and every non-ASCII
# byte is corrupted, so the server sees a body it cannot parse ("Failed to parse
# body as FormData") and returns 500. Proven by sending byte-identical bodies two
# ways: curl got 201, Invoke-RestMethod -Body got 500.
#
# -InFile sends the bytes verbatim, so write the body out and post the file.
# The server's explanation, not just its status code.
#
# Windows PowerShell 5.1 surfaces only "(402) Payment Required" in
# $_.Exception.Message and leaves the JSON body on the response stream. That body
# is the difference between "your plan has ended" and "storage limit reached",
# which is the whole answer, so read it.
function Get-JlHttpErrorDetail {
    param($ErrorRecord)
    $detail = "$($ErrorRecord.Exception.Message)"
    $body = ''

    # PowerShell has ALREADY consumed the response stream by the time the error
    # record reaches us, so GetResponseStream() reads empty. The body is kept on
    # ErrorDetails.Message instead. Try that first, and fall back to the stream
    # for hosts that populate one and not the other.
    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $body = "$($ErrorRecord.ErrorDetails.Message)"
        }
    } catch { }
    if (-not $body) {
        try {
            $resp = $ErrorRecord.Exception.Response
            if ($resp) {
                $stream = $resp.GetResponseStream()
                if ($stream) {
                    if ($stream.CanSeek) { $stream.Position = 0 }
                    $reader = New-Object System.IO.StreamReader($stream)
                    $body = $reader.ReadToEnd()
                    $reader.Dispose()
                }
            }
        } catch { }
    }
    if ($body) {
        $msg = $body
        try {
            $parsed = $body | ConvertFrom-Json
            if (Test-JlHasProperty $parsed 'error')       { $msg = $parsed.error }
            elseif (Test-JlHasProperty $parsed 'message') { $msg = $parsed.message }
        } catch { }
        $detail = "$detail - $msg"
    }
    return $detail
}

function Invoke-JlMultipartPost {
    param(
        [Parameter(Mandatory = $true)][string] $Uri,
        [Parameter(Mandatory = $true)][byte[]] $Body,
        [Parameter(Mandatory = $true)][string] $Boundary,
        [hashtable] $Headers = @{}
    )
    $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "jl-multipart-$([System.Guid]::NewGuid().ToString('N')).bin")
    try {
        [System.IO.File]::WriteAllBytes($tmp, $Body)
        return Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers `
                   -ContentType "multipart/form-data; boundary=$Boundary" `
                   -InFile $tmp -ErrorAction Stop
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Test-JlHasProperty {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $false }
    foreach ($p in $Object.PSObject.Properties) { if ($p.Name -eq $Name) { return $true } }
    return $false
}

# Number of permissions the platform reports for a collaboration. The API renamed
# this field to grantCount; older builds returned permissionCount. Read either.
function Get-JlGrantCount {
    param($Project)
    foreach ($field in 'grantCount', 'permissionCount') {
        if (Test-JlHasProperty $Project $field) { return [int]("0" + "$($Project.$field)") }
    }
    return 0
}

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

    # Say up front that nothing will appear. A silent prompt with no echo and no
    # confirmation looks like a frozen terminal, and the operator cannot tell
    # whether a paste registered.
    Write-Host "  (input is hidden - paste or type, then press Enter)" -ForegroundColor DarkGray

    $secure = Read-Host $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    # Confirm receipt without revealing the value.
    if ([string]::IsNullOrEmpty($value)) {
        Write-JlWarn "Nothing received. If you pasted, the terminal may not have accepted it - try again."
    } elseif ($value.StartsWith('sk_live_')) {
        Write-JlSuccess "Received $($value.Length) characters, starting 'sk_live_'."
    } else {
        Write-JlInfo "Received $($value.Length) characters."
    }

    return $value
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
    # @(...) around the call: a function returning an empty array unrolls to
    # $null at the call site, and $null.Count throws under Set-StrictMode.
    $collabs = @(Get-JlLocalCollabs)
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

# Fetches the permission out of the active-permissions LIST, filtered to our
# side's view, rather than by id. That is what lib.sh does, and the list
# endpoint is the one that self-heals a permission whose derived fields drifted.
function Get-JlPermission {
    param(
        [string] $PermissionId = '',
        [string] $View = ''
    )
    if (-not $PermissionId) { $PermissionId = $script:JULENNY_PERMISSION_ID }
    if (-not $View)         { $View = $script:JL_PERM_VIEW }

    $resp = Invoke-JlApi GET "/api/fhe-permissions?status=active&view=$View"
    if ($resp -and ((Test-JlHasProperty $resp 'permissions'))) {
        $match = @($resp.permissions | Where-Object { $_.id -eq $PermissionId })
        if ($match.Count -gt 0) { return $match[0] }
    }
    Stop-JlWithError "Permission $PermissionId not found in view=$View."
}

# "dataConsumer" (default) or "dataOwner": which side decrypts the plaintext.
# Mode "both" exists in the platform plan but is deferred (needs transport-key
# infrastructure for blind relay between parties).
function Get-JlResultVisibility {
    $perm = Get-JlPermission
    $vis = ''
    if ($perm -and (Test-JlHasProperty $perm 'resultVisibility')) {
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
    if ((Test-JlHasProperty $resp 'projects')) { return @($resp.projects) }
    return @($resp)
}

function Get-JlPermissionsForJointKey {
    param([Parameter(Mandatory = $true)][string] $JointKeyId)
    $resp = Invoke-JlApi GET "/api/fhe-permissions?view=$($script:JL_PERM_VIEW)&jointKeyId=$JointKeyId"
    if ($null -eq $resp) { return @() }
    if ((Test-JlHasProperty $resp 'permissions')) { return @($resp.permissions) }
    return @($resp)
}

function Get-JlFunctions {
    $resp = Invoke-JlApi GET "/api/functions"
    if ($null -eq $resp) { return @() }
    if ((Test-JlHasProperty $resp 'functions')) { return @($resp.functions) }
    return @($resp)
}

function Get-JlFunctionsByScheme {
    param([Parameter(Mandatory = $true)][ValidateSet('CKKS', 'BFV')][string] $Scheme)
    return @(Get-JlFunctions | Where-Object { $_.scheme -eq $Scheme })
}

function Get-JlMyDatasetsInProject {
    $resp = Invoke-JlApi GET "/api/fhe-datasets?projectId=$($script:JULENNY_PROJECT_ID)" -AllowFailure
    if ($null -eq $resp) { return @() }
    if ((Test-JlHasProperty $resp 'datasets')) { return @($resp.datasets) }
    return @($resp)
}

# ============================================================================
# The offline CLI
# ============================================================================
# Every crypto operation shells out to julenny-toolkit. PowerShell does not fail
# on a native non-zero exit, so $LASTEXITCODE must be checked every time or a
# failed encrypt looks like a success and the wrong bytes get uploaded.
function Invoke-JlCli {
    param(
        [Parameter(Mandatory = $true)][string[]] $CliArgs,
        [switch] $PassThru
    )
    $exe = 'julenny-toolkit'
    if ($env:JULENNY_TOOLKIT_BIN) { $exe = $env:JULENNY_TOOLKIT_BIN }

    $output = & $exe @CliArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        Stop-JlWithError ("julenny-toolkit {0} failed (exit {1}):`n{2}" -f ($CliArgs -join ' '), $LASTEXITCODE, ($output -join "`n"))
    }
    if ($PassThru) { return ($output -join "`n") }
}

# Same, but returns $false instead of exiting. Used where one failure should
# skip an item and carry on rather than end the run.
function Invoke-JlCliAllowFail {
    param([Parameter(Mandatory = $true)][string[]] $CliArgs)
    $exe = 'julenny-toolkit'
    if ($env:JULENNY_TOOLKIT_BIN) { $exe = $env:JULENNY_TOOLKIT_BIN }
    $output = & $exe @CliArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-JlWarn ("julenny-toolkit {0} failed (exit {1}):" -f ($CliArgs -join ' '), $LASTEXITCODE)
        $output | ForEach-Object { Write-Host "    $_" }
        return $false
    }
    return $true
}

# Ed25519 signature as lowercase hex, the form the platform's x-jl-signature
# header expects (the bash side does this with xxd -p).
function Get-JlFileHex {
    param([Parameter(Mandatory = $true)][string] $Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLower()
}

# ============================================================================
# Peer key-share transfer
# ============================================================================
# The platform resolves "peer" from the grant plus our auth; no peer id needed.
function Get-JlPeerKeysetupMessages {
    return Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/keysetup/messages?from=peer" -AllowFailure
}

function Get-JlPeerMessageOfType {
    param([Parameter(Mandatory = $true)][string] $MessageType)
    $resp = Get-JlPeerKeysetupMessages
    if ($null -eq $resp) { return $null }
    if (-not ((Test-JlHasProperty $resp 'messages'))) { return $null }
    foreach ($m in @($resp.messages)) {
        if ($m.messageType -eq $MessageType) { return $m }
    }
    return $null
}

# Fetches the peer's share, whether it came inline or via object storage, and
# writes the raw bytes to disk.
function Save-JlPeerShare {
    param(
        [Parameter(Mandatory = $true)][string] $MessageType,
        [Parameter(Mandatory = $true)][string] $OutPath
    )
    $msg = Get-JlPeerMessageOfType $MessageType
    if ($null -eq $msg) {
        Stop-JlWithError "$($script:JL_PEER_LABEL) has not yet submitted a '$MessageType' share. Tell them to run the previous step."
    }

    $payloadB64 = ''
    if ((Test-JlHasProperty $msg 'payloadB64')) { $payloadB64 = $msg.payloadB64 }
    $downloadUrl = ''
    if ((Test-JlHasProperty $msg 'downloadUrl')) { $downloadUrl = $msg.downloadUrl }

    $parent = Split-Path -Parent $OutPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($payloadB64)) {
        [System.IO.File]::WriteAllBytes($OutPath, [Convert]::FromBase64String($payloadB64))
        Write-JlSuccess "Downloaded peer's $MessageType -> $OutPath (inline)"
    } elseif (-not [string]::IsNullOrWhiteSpace($downloadUrl)) {
        Write-JlInfo "Downloading peer's $MessageType from object storage..."
        try {
            # No api key header: this is a pre-signed object storage URL.
            Invoke-WebRequest -Uri $downloadUrl -OutFile $OutPath -UseBasicParsing -ErrorAction Stop | Out-Null
        } catch {
            Stop-JlWithError "object storage download failed for ${MessageType}: $($_.Exception.Message)"
        }
        $len = (Get-Item -LiteralPath $OutPath).Length
        if ($len -le 0) { Stop-JlWithError "Downloaded file is empty" }
        Write-JlSuccess "Downloaded peer's $MessageType -> $OutPath ($len bytes, via object storage)"
    } else {
        Stop-JlWithError "Peer's '$MessageType' message has neither payloadB64 nor downloadUrl."
    }
}

# Polls until the peer submits the named share. Backoff matches lib.sh so the
# two sides produce comparable logs.
function Wait-JlPeerShare {
    param(
        [Parameter(Mandatory = $true)][string] $MessageType,
        [int] $MaxWaitSeconds = 1800
    )
    $elapsed = 0
    $delay = 5
    Write-JlInfo "Waiting for $($script:JL_PEER_LABEL) to submit '$MessageType'..."
    while ($elapsed -lt $MaxWaitSeconds) {
        if ($null -ne (Get-JlPeerMessageOfType $MessageType)) {
            Write-JlSuccess "$($script:JL_PEER_LABEL) submitted '$MessageType'."
            return
        }
        Start-Sleep -Seconds $delay
        $elapsed += $delay
        if     ($elapsed -lt 10)  { $delay = 5 }
        elseif ($elapsed -lt 30)  { $delay = 10 }
        elseif ($elapsed -lt 60)  { $delay = 15 }
        elseif ($elapsed -lt 180) { $delay = 30 }
        else                      { $delay = 60 }
        Write-Host ("  (still waiting, {0}s elapsed)" -f $elapsed)
    }
    Stop-JlWithError "Timed out after ${MaxWaitSeconds}s waiting for $($script:JL_PEER_LABEL) to submit '$MessageType'."
}

# ============================================================================
# Envelope signing and upload
# ============================================================================
if (-not (Get-Variable -Name JL_INLINE_THRESHOLD_BYTES -Scope Script -ErrorAction SilentlyContinue)) {
    if ($env:JL_INLINE_THRESHOLD_BYTES) {
        $script:JL_INLINE_THRESHOLD_BYTES = [int64] $env:JL_INLINE_THRESHOLD_BYTES
    } else {
        $script:JL_INLINE_THRESHOLD_BYTES = 15MB
    }
}

function Request-JlUploadUrl {
    param([Parameter(Mandatory = $true)][int] $Round)
    $resp = Invoke-JlApi POST "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/keysetup/messages/upload-url" `
                         -Body @{ round = $Round }
    $url = ''
    $key = ''
    if ($resp) {
        if ((Test-JlHasProperty $resp 'uploadUrl')) { $url = $resp.uploadUrl }
        if ((Test-JlHasProperty $resp 'objectKey')) { $key = $resp.objectKey }
    }
    if ([string]::IsNullOrWhiteSpace($url) -or [string]::IsNullOrWhiteSpace($key)) {
        Stop-JlWithError "Failed to obtain upload URL for round $Round."
    }
    return @{ UploadUrl = $url; ObjectKey = $key }
}

# Signs a payload into an envelope and posts it. Small payloads are embedded in
# the envelope; large ones go to object storage first and the envelope carries a
# reference. The size split matches lib.sh so both sides behave identically.
function Publish-JlEnvelope {
    param(
        [Parameter(Mandatory = $true)][string] $BinPath,
        [Parameter(Mandatory = $true)][int]    $Round,
        [Parameter(Mandatory = $true)][string] $MessageType
    )
    $jsonPath  = Join-Path $script:JL_ENV_DIR "$MessageType.json"
    $sizeBytes = (Get-Item -LiteralPath $BinPath).Length

    if ($sizeBytes -lt $script:JL_INLINE_THRESHOLD_BYTES) {
        Write-JlInfo "Wrapping $MessageType (round $Round, inline, $sizeBytes bytes)"
        Invoke-JlCli @(
            'crypto', 'wrap-envelope',
            '--payload',       $BinPath,
            '--secret-key',    $script:JULENNY_SIGNING_SECRET,
            '--output',        $jsonPath,
            '--permission-id', $script:JULENNY_PERMISSION_ID,
            '--round',         "$Round",
            '--message-type',  $MessageType
        )
    } else {
        Write-JlInfo "Wrapping $MessageType (round $Round, object storage-mediated, $sizeBytes bytes)"
        $target = Request-JlUploadUrl $Round

        Write-JlInfo "  Uploading payload to object storage ($($target.ObjectKey))..."
        try {
            # -InFile streams the raw bytes. Passing -Body with file contents
            # would re-encode them and corrupt the payload.
            Invoke-WebRequest -Method PUT -Uri $target.UploadUrl `
                              -InFile $BinPath -ContentType 'application/octet-stream' `
                              -UseBasicParsing -ErrorAction Stop | Out-Null
        } catch {
            Stop-JlWithError "object storage PUT failed: $($_.Exception.Message)"
        }
        Write-JlSuccess "  Uploaded to object storage"

        Invoke-JlCli @(
            'crypto', 'wrap-envelope',
            '--object-key',    $target.ObjectKey,
            '--size-bytes',    "$sizeBytes",
            '--secret-key',    $script:JULENNY_SIGNING_SECRET,
            '--output',        $jsonPath,
            '--permission-id', $script:JULENNY_PERMISSION_ID,
            '--round',         "$Round",
            '--message-type',  $MessageType
        )
    }

    Write-JlInfo "Posting envelope to /keysetup/messages..."
    $uri = $script:JULENNY_API_BASE + "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/keysetup/messages"
    try {
        # -InFile posts the signed envelope exactly as the CLI wrote it. Parsing
        # and re-serializing could reorder keys and invalidate the signature.
        $resp = Invoke-RestMethod -Method POST -Uri $uri `
                                  -Headers @{ 'x-api-key' = $script:JULENNY_API_KEY } `
                                  -InFile $jsonPath -ContentType 'application/json' -ErrorAction Stop
        if ($resp -and ((Test-JlHasProperty $resp 'message'))) {
            Write-JlSuccess "Uploaded ${MessageType}: $($resp.message)"
        } else {
            Write-JlSuccess "Uploaded $MessageType"
        }
    } catch {
        # A keysetup that is already complete is not an error: the peer may have
        # finalized between our check and this post. Same tolerance as lib.sh.
        $body = ''
        try {
            $r = $_.Exception.Response
            if ($r) { $body = (New-Object System.IO.StreamReader($r.GetResponseStream())).ReadToEnd() }
        } catch { }
        if ($body -match 'in state .?complete|already complete|cannot accept messages') {
            Write-JlInfo "$MessageType not needed: keysetup already complete."
        } else {
            Stop-JlWithError "Upload of $MessageType failed: $($_.Exception.Message) $body"
        }
    }
}

# Writes the permission's function definition to the workdir and returns it.
function Update-JlFunctionDef {
    $perm = Get-JlPermission
    $slug = $perm.functionSlug
    $version = $perm.functionVersion
    if ([string]::IsNullOrWhiteSpace($slug)) {
        Stop-JlWithError "Permission $($script:JULENNY_PERMISSION_ID) has no functionSlug."
    }
    # /api/functions/<slug>/<version>/definition is the route the platform serves, and
    # the same one the bash library and the grant-creation path below already use.
    $def = Invoke-JlApi GET "/api/functions/$slug/$version/definition"
    if (-not (Test-JlHasProperty $def 'slug') -or -not (Test-JlHasProperty $def 'inputs')) {
        Stop-JlWithError "Platform response for $slug v$version does not look like a function definition."
    }
    $out = Join-Path $script:JL_WORKDIR 'function-def.json'
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($out, (ConvertTo-Json $def -Depth 30), $utf8NoBom)
    return $def
}

# ============================================================================
# Creating collaborations and permissions
# ============================================================================
function New-JlCollaboration {
    param(
        [Parameter(Mandatory = $true)][string] $PartnerCollaborationId,
        [Parameter(Mandatory = $true)][string] $Name,
        [string] $Description = 'Created from the JuLenny example scripts.'
    )
    $resp = Invoke-JlApi POST "/api/fhe-projects" -Body @{
        partnerCompanyId = $PartnerCollaborationId
        name             = $Name
        description      = $Description
    }
    $newId = ''
    if ($resp) {
        if ((Test-JlHasProperty $resp 'project') -and $resp.project) { $newId = $resp.project.id }
        elseif ((Test-JlHasProperty $resp 'id'))                     { $newId = $resp.id }
    }
    if ([string]::IsNullOrWhiteSpace($newId)) {
        Stop-JlWithError "Collaboration creation succeeded but no id was returned."
    }
    return $newId
}

# resultVisibility is "dataConsumer" (default) or "dataOwner". Mode "both" is
# deferred (needs transport-key infrastructure).
function New-JlPermission {
    param(
        [Parameter(Mandatory = $true)][string] $ProjectId,
        [Parameter(Mandatory = $true)][string] $FunctionSlug,
        [Parameter(Mandatory = $true)][string] $FunctionVersion,
        [Parameter(Mandatory = $true)][string] $ConsumerCollaborationId,
        [int]    $AllowedExecutions = 100,
        [ValidateSet('dataConsumer', 'dataOwner')][string] $ResultVisibility = 'dataConsumer',
        [string] $ExpirationDate = ''
    )
    $body = @{
        projectId             = $ProjectId
        fheFunction           = $FunctionSlug
        functionVersion       = $FunctionVersion
        dataConsumerCompanyId = $ConsumerCollaborationId
        allowedExecutions     = $AllowedExecutions
        resultVisibility      = $ResultVisibility
        grantType             = 'external'
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpirationDate)) {
        $body['expirationDate'] = $ExpirationDate
    }

    $resp = Invoke-JlApi POST "/api/fhe-permissions" -Body $body
    $newId = ''
    if ($resp) {
        if     ((Test-JlHasProperty $resp 'permission') -and $resp.permission) { $newId = $resp.permission.id }
        elseif ((Test-JlHasProperty $resp 'id'))                               { $newId = $resp.id }
        elseif ((Test-JlHasProperty $resp 'permissionId'))                     { $newId = $resp.permissionId }
    }
    if ([string]::IsNullOrWhiteSpace($newId)) {
        Stop-JlWithError "Permission creation succeeded but no id was returned."
    }
    return $newId
}

# ============================================================================
# Rotation-key augmentation (phase 4.5)
# ============================================================================
# Drives the post-keysetup augmentation when the function-def's requiredEvalKeys
# includes "rotation". Identical contract and polling cadence on both sides;
# only the protocol role differs.

function Get-JlFunctionDefObject {
    param([string] $Path = '')
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path $script:JL_WORKDIR 'function-def.json'
    }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

# The legacy default includes both keys. A function that omits "sum" (e.g.
# decision-tree v2) skips the sum contribution/combine/upload entirely, which
# avoids generating an oversized eval-sum key.
function Get-JlRequiredEvalKeys {
    param([string] $Path = '')
    $def = Get-JlFunctionDefObject $Path
    if ($null -eq $def) { return @('relinearization', 'sum') }
    if (-not ((Test-JlHasProperty $def 'requiredEvalKeys')) -or $null -eq $def.requiredEvalKeys) {
        return @('relinearization', 'sum')
    }
    return @($def.requiredEvalKeys)
}

function Test-JlFunctionRequiresRotationKeys {
    param([string] $Path = '')
    return ((Get-JlRequiredEvalKeys $Path) -contains 'rotation')
}

function Test-JlFunctionRequiresSumKeys {
    param([string] $Path = '')
    return ((Get-JlRequiredEvalKeys $Path) -contains 'sum')
}

# True if the function-def declares a "relinearization" eval key. Additive-only
# functions (federated-average) declare requiredEvalKeys: [], and for those the whole
# relin exchange - rounds 1, 2 and the final combine - must be skipped. The platform
# knows this and goes straight to awaiting-finalization, so a script that waits for
# relin-round1-continue waits forever.
function Test-JlFunctionRequiresRelinKeys {
    param([string] $Path = '')
    return ((Get-JlRequiredEvalKeys $Path) -contains 'relinearization')
}

function Get-JlPendingRotationKeysetup {
    $state = Get-JlKeysetupState
    if ($null -eq $state) { return $null }
    if (-not ((Test-JlHasProperty $state 'pendingRotationKeySetup'))) { return $null }
    return $state.pendingRotationKeySetup
}

function Get-JlPendingRotationIndicesCsv {
    $prks = Get-JlPendingRotationKeysetup
    if ($null -eq $prks) { return '' }
    if (-not ((Test-JlHasProperty $prks 'indices')) -or $null -eq $prks.indices) { return '' }
    return (@($prks.indices) -join ',')
}

function Get-JlRotationStatus {
    $prks = Get-JlPendingRotationKeysetup
    if ($null -eq $prks) { return 'absent' }
    if (-not ((Test-JlHasProperty $prks 'status')) -or [string]::IsNullOrWhiteSpace($prks.status)) {
        return 'absent'
    }
    return $prks.status
}

function Wait-JlPendingRotationIndices {
    param(
        [string] $Description = 'platform to derive rotation indices',
        [int]    $MaxWaitSeconds = 600
    )
    $elapsed = 0
    $delay = 5
    Write-JlInfo "Waiting for $Description..."
    while ($elapsed -lt $MaxWaitSeconds) {
        $prks = $null
        try { $prks = Get-JlPendingRotationKeysetup } catch { $prks = $null }
        if ($null -ne $prks) {
            $n = 0
            if (((Test-JlHasProperty $prks 'indices')) -and $null -ne $prks.indices) {
                $n = @($prks.indices).Count
            }
            if ($n -gt 0) {
                Write-JlSuccess "Platform derived $n rotation indices."
                return
            }
            $status = ''
            if ((Test-JlHasProperty $prks 'status')) { $status = $prks.status }
            if ($status -eq 'complete') {
                Write-JlInfo "Platform derived an empty index set and transitioned to complete."
                Write-JlInfo "No rotation keys needed for this execution."
                return
            }
        }
        Start-Sleep -Seconds $delay
        $elapsed += $delay
        if     ($elapsed -lt 30) { $delay = 5 }
        elseif ($elapsed -lt 60) { $delay = 10 }
        else                     { $delay = 15 }
        Write-Host ("  (still waiting, {0}s elapsed)" -f $elapsed)
    }
    Stop-JlWithError "Timed out after ${MaxWaitSeconds}s waiting for $Description."
}

function Wait-JlRotationStatus {
    param(
        [Parameter(Mandatory = $true)][string] $TargetStatus,
        [int] $MaxWaitSeconds = 1800
    )
    $elapsed = 0
    $delay = 10
    Write-JlInfo "Waiting for rotation keysetup status: $TargetStatus"
    while ($elapsed -lt $MaxWaitSeconds) {
        $current = 'absent'
        try { $current = Get-JlRotationStatus } catch { $current = 'absent' }
        if ($current -eq $TargetStatus) {
            Write-JlSuccess "Rotation keysetup status is now '$TargetStatus'."
            return
        }
        Start-Sleep -Seconds $delay
        $elapsed += $delay
        if     ($elapsed -lt 60)  { $delay = 10 }
        elseif ($elapsed -lt 180) { $delay = 20 }
        else                      { $delay = 60 }
        Write-Host ("  (status={0}, {1}s elapsed)" -f $current, $elapsed)
    }
    Stop-JlWithError "Timed out after ${MaxWaitSeconds}s waiting for rotation status '$TargetStatus'."
}

# Rotation rounds sit at the end of the round sequence. When a rotation keysetup
# is pending, the last three rounds are its own, so the base is totalRounds - 3.
function Get-JlRotationRoundOffset {
    param([Parameter(Mandatory = $true)][ValidateSet('round1', 'round1-continue', 'combine')][string] $Kind)

    $state = Get-JlKeysetupState
    $total = 0
    if ($state -and ((Test-JlHasProperty $state 'totalRounds')) -and $state.totalRounds) {
        $total = [int] $state.totalRounds
    }
    $prks = $null
    if ($state -and ((Test-JlHasProperty $state 'pendingRotationKeySetup'))) {
        $prks = $state.pendingRotationKeySetup
    }

    if ($null -eq $prks) { $base = $total } else { $base = $total - 3 }

    switch ($Kind) {
        'round1'          { return $base + 1 }
        'round1-continue' { return $base + 2 }
        'combine'         { return $base + 3 }
    }
}

# ============================================================================
# Dataset upload
# ============================================================================
# Windows PowerShell 5.1 has no -Form parameter (that is 6.1+), so the
# multipart body is assembled by hand as a byte array. This MUST stay bytes
# end to end: building it as a string would run the payload through .NET string
# encoding and corrupt any non-UTF8 byte, which is every ciphertext file.
function New-JlMultipartBody {
    param(
        [Parameter(Mandatory = $true)][string]    $FilePath,
        [Parameter(Mandatory = $true)][hashtable] $Fields,
        [Parameter(Mandatory = $true)][string]    $Boundary,
        [string] $FileFieldName = 'file'
    )
    $LF = "`r`n"
    $enc = New-Object System.Text.UTF8Encoding($false)
    $ms  = New-Object System.IO.MemoryStream

    function Write-Text {
        param([string] $Text)
        $b = $enc.GetBytes($Text)
        $ms.Write($b, 0, $b.Length)
    }

    $fileName = [System.IO.Path]::GetFileName($FilePath)
    Write-Text "--$Boundary$LF"
    Write-Text "Content-Disposition: form-data; name=`"$FileFieldName`"; filename=`"$fileName`"$LF"
    Write-Text "Content-Type: application/octet-stream$LF$LF"

    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $ms.Write($fileBytes, 0, $fileBytes.Length)
    Write-Text $LF

    foreach ($k in $Fields.Keys) {
        Write-Text "--$Boundary$LF"
        Write-Text "Content-Disposition: form-data; name=`"$k`"$LF$LF"
        Write-Text ("{0}{1}" -f $Fields[$k], $LF)
    }
    Write-Text "--$Boundary--$LF"

    $bytes = $ms.ToArray()
    $ms.Dispose()
    return $bytes
}

# Uploads a dataset. Small files go in one multipart shot; larger ones use the
# signed-URL flow (upload-url -> PUT -> confirm) so the bytes bypass the API
# body cap. Kind is "plaintext" (raw input) or "ciphertext" (encrypted bundle).
# Returns the new dataset id.
function Send-JlDataset {
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [Parameter(Mandatory = $true)][string] $DatasetName,
        [ValidateSet('plaintext', 'ciphertext')][string] $Kind = 'plaintext'
    )
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        Stop-JlWithError "Send-JlDataset: file not found: $FilePath"
    }
    $sizeBytes = (Get-Item -LiteralPath $FilePath).Length

    if ($sizeBytes -lt $script:JL_INLINE_THRESHOLD_BYTES) {
        Write-JlInfo ("Uploading {0} {1} as '{2}' (single-shot, {3} bytes)..." -f $Kind.ToUpper(), $FilePath, $DatasetName, $sizeBytes)

        $boundary = [System.Guid]::NewGuid().ToString()
        $body = New-JlMultipartBody -FilePath $FilePath -Boundary $boundary -Fields @{
            name = $DatasetName
            kind = $Kind
        }
        $uri = "$($script:JULENNY_API_BASE)/api/fhe-data-upload?permissionId=$($script:JULENNY_PERMISSION_ID)"
        try {
            $resp = Invoke-JlMultipartPost -Uri $uri -Body $body -Boundary $boundary `
                        -Headers @{ 'x-api-key' = $script:JULENNY_API_KEY }
        } catch {
            Stop-JlWithError "Dataset upload failed: $(Get-JlHttpErrorDetail $_)"
        }
        $id = ''
        if ($resp -and ((Test-JlHasProperty $resp 'datasetId'))) { $id = $resp.datasetId }
        if ([string]::IsNullOrWhiteSpace($id)) {
            Stop-JlWithError "Dataset upload succeeded but no datasetId was returned."
        }
        return $id
    }

    Write-JlInfo ("Uploading {0} {1} as '{2}' via signed URL ({3} bytes, exceeds inline cap)..." -f $Kind.ToUpper(), $FilePath, $DatasetName, $sizeBytes)
    $urlResp = Invoke-JlApi POST "/api/fhe-data-upload/upload-url" -Body @{
        name         = $DatasetName
        permissionId = $script:JULENNY_PERMISSION_ID
    }
    $upUrl = ''
    $id = ''
    if ($urlResp) {
        if ((Test-JlHasProperty $urlResp 'uploadUrl')) { $upUrl = $urlResp.uploadUrl }
        if ((Test-JlHasProperty $urlResp 'datasetId')) { $id    = $urlResp.datasetId }
    }
    if ([string]::IsNullOrWhiteSpace($upUrl) -or [string]::IsNullOrWhiteSpace($id)) {
        Stop-JlWithError "upload-url did not return both an uploadUrl and a datasetId."
    }

    try {
        Invoke-WebRequest -Method PUT -Uri $upUrl -InFile $FilePath `
                          -ContentType 'application/octet-stream' `
                          -UseBasicParsing -ErrorAction Stop | Out-Null
    } catch {
        Stop-JlWithError "object storage PUT failed: $($_.Exception.Message)"
    }

    $confirm = Invoke-JlApi POST "/api/fhe-data-upload/confirm" -Body @{
        datasetId     = $id
        name          = $DatasetName
        kind          = $Kind
        fileName      = [System.IO.Path]::GetFileName($FilePath)
        permissionId  = $script:JULENNY_PERMISSION_ID
        retentionDays = 90
    }
    $confirmedId = ''
    if ($confirm -and ((Test-JlHasProperty $confirm 'datasetId'))) {
        $confirmedId = $confirm.datasetId
    }
    if ([string]::IsNullOrWhiteSpace($confirmedId)) {
        Stop-JlWithError "Upload confirm succeeded but no datasetId was returned."
    }
    return $confirmedId
}

# True when EVERY input the function-def declares has a datasetId registered via
# /preferred-datasets. Gates execution: if the peer has not finished their
# 04-encrypt, the platform rejects the trigger, so it is nicer to gate here and
# let watch mode poll cleanly.
function Test-JlAllRequiredInputsDeclared {
    param([string] $FunctionDefPath = '')
    $def = Get-JlFunctionDefObject $FunctionDefPath
    if ($null -eq $def) { return $false }
    if (-not ((Test-JlHasProperty $def 'inputs')) -or $null -eq $def.inputs) { return $false }

    $resp = Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/preferred-datasets" -AllowFailure
    if ($null -eq $resp) { return $false }

    foreach ($input in @($def.inputs)) {
        $name = $input.name
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if (-not ((Test-JlHasProperty $resp $name))) { return $false }
        $entry = $resp.$name
        if ($null -eq $entry) { return $false }
        if (-not ((Test-JlHasProperty $entry 'datasetId'))) { return $false }
        if ([string]::IsNullOrWhiteSpace($entry.datasetId)) { return $false }
    }
    return $true
}

# ============================================================================
# Session setup (phase 0)
# ============================================================================
# Function-agnostic: the function is picked from the platform's live list at run
# time rather than hardcoded, which is why one implementation backs every
# scenario. Both sides share this; the differences are which permissions each
# side can see and whether it may create one.

function Select-JlFunction {
    # LockScheme pins the list to one scheme instead of asking. A permission added to an
    # EXISTING collaboration must match that collaboration's joint key: there is one joint
    # key per collaboration, so a BFV function inside a CKKS collaboration would need a
    # second joint key and break the keysetup reuse the whole flow depends on. Offering
    # the choice there is offering a way to break it.
    param(
        [string] $Prompt = 'Pick a function',
        [ValidateSet('CKKS', 'BFV', '')]
        [string] $LockScheme = ''
    )

    if ($LockScheme) {
        $funcs = @(Get-JlFunctionsByScheme $LockScheme)
        $schemeLabel = $LockScheme
    } else {
        Write-Host ""
        Write-Host "Which scheme should the function use?"
        Write-Host "  1) CKKS  (real-valued analytics)"
        Write-Host "  2) BFV   (exact-integer functions)"
        Write-Host "  3) Any"
        $schemeChoice = Read-JlValue "Choose (1-3)" '1'
        switch ($schemeChoice) {
            '1' { $funcs = @(Get-JlFunctionsByScheme 'CKKS'); $schemeLabel = 'CKKS' }
            '2' { $funcs = @(Get-JlFunctionsByScheme 'BFV');  $schemeLabel = 'BFV' }
            '3' { $funcs = @(Get-JlFunctions);                $schemeLabel = 'any' }
            default { Stop-JlWithError "Invalid choice: $schemeChoice" }
        }
    }
    if ($funcs.Count -eq 0) { Stop-JlWithError "No functions found for scheme '$schemeLabel'." }

    Write-Host ""
    Write-JlInfo "Functions available (scheme=$schemeLabel):"
    for ($i = 0; $i -lt $funcs.Count; $i++) {
        # Trim to the last whole word and say it was trimmed. A hard cut at 80 stops
        # mid-word, which reads like the description itself is broken.
        $desc = "$($funcs[$i].description)"
        if ($desc.Length -gt 80) { $desc = ($desc.Substring(0, 77) -replace '\s+\S*$', '') + '...' }
        Write-Host ("  [{0}] {1} v{2}  |  scheme: {3}  |  {4}" -f `
            ($i + 1), $funcs[$i].slug, $funcs[$i].version, $funcs[$i].scheme, $desc)
    }
    Write-Host ""

    if ($funcs.Count -eq 1) {
        Write-JlInfo "Only one function; selecting [1]."
        return $funcs[0]
    }
    $pick = Read-JlValue "$Prompt (1-$($funcs.Count))" '1'
    $n = 0
    if (-not [int]::TryParse($pick, [ref] $n) -or $n -lt 1 -or $n -gt $funcs.Count) {
        Stop-JlWithError "Invalid choice: $pick"
    }
    return $funcs[$n - 1]
}

function Invoke-JlInitSession {
    param(
        # Only the data owner can create a permission under an existing
        # collaboration; the consumer must wait for one to be granted.
        [switch] $CanCreatePermission
    )

    Write-JlStep "JuLenny collaboration setup ($($script:JL_OUR_LABEL): $($script:JL_ROLE_LABEL))"

    # -------- API connection --------
    # An inherited JULENNY_API_BASE is honoured so a run can be pointed at a
    # staging host, but it is announced rather than applied silently: a stale
    # value sends every call to the wrong host, and the only symptom is an empty
    # collaboration list, which reads as "you have no collaborations".
    if ($env:JULENNY_API_BASE) {
        $script:JULENNY_API_BASE = $env:JULENNY_API_BASE
    } else {
        $script:JULENNY_API_BASE = 'https://julenny.net'
    }
    if ($script:JULENNY_API_BASE -ne 'https://julenny.net') {
        Write-JlWarn "Using a non-default platform host from JULENNY_API_BASE:"
        Write-JlWarn "    $($script:JULENNY_API_BASE)"
        Write-JlWarn "Clear JULENNY_API_BASE to use https://julenny.net."
    }

    # A key already in the environment wins, so the operator can supply it
    # without an interactive paste. Terminals vary in how they treat a pasted
    # secret at a hidden prompt, and this is the route a scripted run would use.
    $rememberedKey = ''
    if (Test-Path -LiteralPath $script:JL_ACCOUNT_CONFIG) {
        foreach ($line in (Get-Content -LiteralPath $script:JL_ACCOUNT_CONFIG)) {
            if ($line -match '^\s*JULENNY_API_KEY\s*=\s*"?([^"]*)"?\s*$') { $rememberedKey = $Matches[1] }
        }
    }

    if ($env:JULENNY_API_KEY) {
        $script:JULENNY_API_KEY = $env:JULENNY_API_KEY
        Write-JlInfo "Using JULENNY_API_KEY from the environment ($($script:JULENNY_API_KEY.Length) characters)."
    } elseif ($rememberedKey) {
        $script:JULENNY_API_KEY = $rememberedKey
        Write-JlInfo "Using the API key remembered for this machine ($($rememberedKey.Length) characters)."
        Write-JlInfo "Delete $($script:JL_ACCOUNT_CONFIG) to be asked again."
    } else {
        $script:JULENNY_API_KEY = Read-JlSecret "$($script:JL_OUR_LABEL)'s API key (starts with sk_live_)"
        if (-not (Test-Path -LiteralPath $script:JL_ROOT)) {
            New-Item -ItemType Directory -Path $script:JL_ROOT -Force | Out-Null
        }
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($script:JL_ACCOUNT_CONFIG,
            "# JuLenny account-scoped settings. Delete this file to be asked again.`r`n" +
            "JULENNY_API_KEY=`"$($script:JULENNY_API_KEY)`"`r`n", $utf8NoBom)
        Write-JlInfo "Remembered for future runs: $($script:JL_ACCOUNT_CONFIG) (delete it to be asked again)"
    }
    if (-not $script:JULENNY_API_KEY.StartsWith('sk_live_')) {
        Stop-JlWithError "API key must start with sk_live_"
    }
    Write-JlInfo "Platform: $($script:JULENNY_API_BASE)"

    if ($script:JULENNY_OUR_SIDE -eq 'data-owner') { $myRoleName = 'dataOwner' } else { $myRoleName = 'dataConsumer' }

    # -------- Pick or create a collaboration --------
    Write-JlStep "Fetching your collaborations..."
    $all = @(Get-JlCollaborations)

    # Primary signal is the platform's yourPermissionRoles array; permissionCount
    # is the fallback. permissionCount is already role-scoped by the view, so >0
    # means "I hold at least one permission of my role here". Filtering on
    # project ownership instead wrongly hides collabs the other party created.
    $mine = @($all | Where-Object {
        $roles = @()
        if ((Test-JlHasProperty $_ 'yourPermissionRoles') -and $_.yourPermissionRoles) {
            $roles = @($_.yourPermissionRoles)
        }
        ($roles -contains $myRoleName) -or ((Get-JlGrantCount $_) -gt 0)
    } | Sort-Object createdAt -Descending)

    Write-Host ""
    if ($mine.Count -gt 0) {
        Write-JlInfo "Active collaborations where you're the $myRoleName (newest first):"
        for ($i = 0; $i -lt $mine.Count; $i++) {
            # Identify the peer by collaboration id, not by company name. These scripts
            # authenticate with an API key, and the API does not give company names to
            # API keys - that is deliberate, so that an agent driving these steps never
            # learns who you are working with. The collaboration id is the public handle
            # the two sides already exchanged to set this up.
            $peer = $mine[$i].partnerCollaborationId
            if (-not $peer) { $peer = $mine[$i].ownerCollaborationId }
            if (-not $peer) { $peer = '?' }
            $created = "$($mine[$i].createdAt)"
            if ($created.Length -gt 10) { $created = $created.Substring(0, 10) }
            Write-Host ("  [{0}] {1}  |  peer: {2}  |  {3} permission(s)  |  keysetup: {4}  |  created {5}  |  id: {6}" -f `
                ($i + 1), $mine[$i].name, $peer, (Get-JlGrantCount $mine[$i]), $mine[$i].keysetupState, $created, $mine[$i].id)
        }
    } else {
        Write-JlInfo "No active collaborations where you're the $myRoleName."
    }
    Write-Host "  n) Create a NEW collaboration + permission via the API"
    if (-not $CanCreatePermission) {
        Write-Host "     (uncommon on this side - usually the data owner initiates. Useful for single-machine smoke tests.)"
    }
    Write-Host ""

    if ($mine.Count -eq 0 -and -not $CanCreatePermission) {
        # Consumer side: do NOT default into creating one. The data owner creates
        # the collaboration here, so "none found" nearly always means they have
        # not created it yet, or this machine is pointed at the wrong account or
        # host - not that a new collaboration is wanted. Auto-selecting 'n'
        # silently created a duplicate the owner could not see, leaving the
        # operator waiting on a peer with nothing to answer.
        Write-JlWarn "No collaborations found where you're the $myRoleName."
        Write-JlWarn "In the normal flow $($script:JL_PEER_LABEL) creates the collaboration and grants you a permission."
        Write-JlWarn "If you expected one here, check that this API key belongs to the account"
        Write-JlWarn "$($script:JL_PEER_LABEL) invited, and that the platform host printed above is right."
        Write-Host ""
        $createNew = Read-JlValue "Create a NEW collaboration anyway? (y/N)" 'N'
        if ($createNew -match '^[Yy]') {
            $projectChoice = 'n'
        } else {
            Write-JlInfo "Nothing to do until $($script:JL_PEER_LABEL) creates the collaboration. Exiting."
            exit 0
        }
    } elseif ($mine.Count -eq 0) {
        $projectChoice = 'n'
        Write-JlInfo "No existing collaborations; defaulting to 'n' (create new)."
    } else {
        $projectChoice = Read-JlValue "Pick a collaboration (1-$($mine.Count), or n)" '1'
    }

    $projectId = ''
    $permId = ''
    $jointKeyId = ''

    if ($projectChoice -match '^[Nn]$') {
        Write-JlStep "Creating a new collaboration + permission via API"
        if (-not $CanCreatePermission) {
            Write-JlWarn "Heads up: in the normal two-party flow the data owner creates the collaboration."
            Write-JlWarn "Use this path only for single-machine smoke tests where you drive both sides."
            Write-Host ""
        }

        $fn = Select-JlFunction
        $fnSlug = $fn.slug
        $fnVersion = $fn.version

        # The operator types the PEER's Collaboration ID (XXXX-XXXX, shown on
        # their Company page). It goes straight to the API, which resolves it
        # internally: the toolkit never handles a raw company id.
        Write-Host ""
        Write-JlInfo "The partner company must already exist on the platform."
        Write-JlInfo "Ask $($script:JL_PEER_LABEL) for their Collaboration ID (format XXXX-XXXX,"
        Write-JlInfo "visible on their Company page in the JuLenny web UI)."
        $partnerId = Read-JlValue "Partner ($($script:JL_PEER_LABEL)) Collaboration ID (XXXX-XXXX)"
        if (-not $partnerId) { Stop-JlWithError "Partner Collaboration ID is required." }

        $defaultName = "$($script:JL_OUR_LABEL) x $($script:JL_PEER_LABEL) ($fnSlug, $(Get-Date -Format 'yyyy-MM-dd'))"
        $collabName = Read-JlValue "Collaboration name" $defaultName

        Write-JlStep "Creating collaboration via POST /api/fhe-projects..."
        $projectId = New-JlCollaboration -PartnerCollaborationId $partnerId -Name $collabName
        Write-JlSuccess "Collaboration created: $projectId"

        $allowed = Read-JlValue "How many executions should this permission allow?" '10'
        $visibility = 'dataConsumer'
        if ($CanCreatePermission) {
            Write-Host ""
            Write-Host "Who should see the plaintext result?"
            Write-Host "  1) The data consumer ($($script:JL_PEER_LABEL))  [default]"
            Write-Host "  2) The data owner ($($script:JL_OUR_LABEL))"
            $visChoice = Read-JlValue "Choose (1-2)" '1'
            if ($visChoice -eq '2') { $visibility = 'dataOwner' }
        }

        Write-JlStep "Creating permission via POST /api/fhe-permissions..."
        $permId = New-JlPermission -ProjectId $projectId -FunctionSlug $fnSlug `
                                   -FunctionVersion $fnVersion -ConsumerCollaborationId $partnerId `
                                   -AllowedExecutions ([int] $allowed) -ResultVisibility $visibility
        Write-JlSuccess "Permission created: $permId  ($fnSlug v$fnVersion)"

    } else {
        $n = 0
        if (-not [int]::TryParse($projectChoice, [ref] $n) -or $n -lt 1 -or $n -gt $mine.Count) {
            Stop-JlWithError "Invalid choice: $projectChoice"
        }
        $project = $mine[$n - 1]
        $projectId = $project.id
        if ((Test-JlHasProperty $project 'jointKeyId')) { $jointKeyId = $project.jointKeyId }
        Write-JlSuccess "Selected collaboration: $($project.name) ($projectId)"

        $perms = @(Get-JlPermissionsForJointKey $projectId)
        Write-Host ""
        if ($perms.Count -gt 0) {
            Write-JlInfo "Permissions under this collaboration:"
            for ($i = 0; $i -lt $perms.Count; $i++) {
                Write-Host ("  [{0}] {1}  |  {2} v{3}  |  keysetup: {4}" -f `
                    ($i + 1), $perms[$i].id, $perms[$i].fheFunction, $perms[$i].functionVersion, $perms[$i].keysetupState)
            }
        } else {
            Write-JlInfo "No permissions found under this collaboration."
        }
        if ($CanCreatePermission) { Write-Host "  n) Create a NEW permission via the API" }
        Write-Host ""

        if ($perms.Count -eq 0 -and -not $CanCreatePermission) {
            Stop-JlWithError "No permissions here yet. Ask $($script:JL_PEER_LABEL) (the data owner) to add one."
        }

        $default = '1'
        if ($perms.Count -eq 0) { $default = 'n' }
        $permChoice = Read-JlValue "Pick a permission (1-$($perms.Count)$(if ($CanCreatePermission) { ', or n' }))" $default

        if ($permChoice -match '^[Nn]$') {
            if (-not $CanCreatePermission) {
                Stop-JlWithError "Only the data owner can create a permission."
            }
            # One joint key per collaboration, so a new permission must use the same scheme
            # as the permissions already here. Infer it from an existing one rather than
            # asking; only fall back to the prompt if there is nothing to read it from.
            $lockScheme = ''
            if ($perms.Count -gt 0 -and (Test-JlHasProperty $perms[0] 'cryptoContextSpec')) {
                $existingSpec = "$($perms[0].cryptoContextSpec)"
                if ($existingSpec -like 'ckks-*') { $lockScheme = 'CKKS' }
                elseif ($existingSpec -like 'bfv-*') { $lockScheme = 'BFV' }
                if ($lockScheme) {
                    Write-JlInfo "This collaboration's joint key is $lockScheme ($existingSpec); a new"
                    Write-JlInfo "permission must use the same scheme, so only $lockScheme functions are offered."
                }
            }
            if (-not $lockScheme) {
                Write-JlWarn "Could not infer this collaboration's scheme from its permissions."
            }
            $fn = Select-JlFunction -LockScheme $lockScheme
            # The partner is already known: this permission goes under a collaboration that
            # was set up with them, and the project carries their collaboration id. Asking
            # again invites a typo that would point the permission at the wrong company.
            # Only fall back to a prompt if the project somehow has no partner recorded.
            $partnerId = ''
            if ((Test-JlHasProperty $project 'partnerCollaborationId')) { $partnerId = "$($project.partnerCollaborationId)" }
            if ($partnerId) {
                Write-JlInfo "Partner ($($script:JL_PEER_LABEL)) Collaboration ID: $partnerId"
            } else {
                $partnerId = Read-JlValue "Partner ($($script:JL_PEER_LABEL)) Collaboration ID (XXXX-XXXX)"
            }
            if (-not $partnerId) { Stop-JlWithError "Partner Collaboration ID is required." }
            $allowed = Read-JlValue "How many executions should this permission allow?" '10'
            Write-Host ""
            Write-Host "Who should see the plaintext result?"
            Write-Host "  1) The data consumer ($($script:JL_PEER_LABEL))  [default]"
            Write-Host "  2) The data owner ($($script:JL_OUR_LABEL))"
            $visChoice = Read-JlValue "Choose (1-2)" '1'
            $visibility = 'dataConsumer'
            if ($visChoice -eq '2') { $visibility = 'dataOwner' }

            $permId = New-JlPermission -ProjectId $projectId -FunctionSlug $fn.slug `
                                       -FunctionVersion $fn.version -ConsumerCollaborationId $partnerId `
                                       -AllowedExecutions ([int] $allowed) -ResultVisibility $visibility
            Write-JlSuccess "Permission created: $permId"
        } else {
            $n = 0
            if (-not [int]::TryParse($permChoice, [ref] $n) -or $n -lt 1 -or $n -gt $perms.Count) {
                Stop-JlWithError "Invalid choice: $permChoice"
            }
            $permId = $perms[$n - 1].id
            if ((Test-JlHasProperty $perms[$n - 1] 'jointKeyId')) { $jointKeyId = $perms[$n - 1].jointKeyId }
            Write-JlSuccess "Selected permission: $permId"
        }
    }

    $script:JULENNY_PERMISSION_ID = $permId

    # -------- Resolve the joint key and activate the per-collab workdir --------
    if (-not $jointKeyId) {
        $perm = Get-JlPermission -PermissionId $permId
        if ($perm -and ((Test-JlHasProperty $perm 'jointKeyId'))) { $jointKeyId = $perm.jointKeyId }
    }
    if (-not $jointKeyId) {
        Stop-JlWithError "Could not resolve a jointKeyId for permission $permId."
    }
    Set-JlActiveJointKey $jointKeyId
    Write-JlSuccess "Workdir: $($script:JL_WORKDIR)"

    # -------- Re-fetch the permission for its derived fields --------
    $permObj = Get-JlPermission -PermissionId $permId
    $fnSlug    = $permObj.fheFunction
    $fnVersion = $permObj.functionVersion
    $ctxSpec   = $permObj.cryptoContextSpec
    $visibility = 'dataConsumer'
    if ((Test-JlHasProperty $permObj 'resultVisibility') -and $permObj.resultVisibility) {
        $visibility = $permObj.resultVisibility
    }
    $peerCollab = ''
    if ((Test-JlHasProperty $permObj $script:JL_PEER_COLLAB_FIELD)) {
        $peerCollab = $permObj.$($script:JL_PEER_COLLAB_FIELD)
    }

    Write-JlSuccess "Permission resolved: $permId  ($fnSlug v$fnVersion)"
    Write-JlInfo "  $($script:JL_OUR_LABEL) is:  $($script:JL_ROLE_LABEL)"
    if ($peerCollab) {
        Write-JlInfo "  $($script:JL_PEER_LABEL) (peer): collab $peerCollab"
    }
    Write-JlInfo "  Result is visible to: $visibility"

    # -------- Function definition --------
    Write-JlStep "Fetching function definition from platform..."
    $fnDef = Invoke-JlApi GET "/api/functions/$fnSlug/$fnVersion/definition"
    $fnDefPath = Join-Path $script:JL_WORKDIR 'function-def.json'
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($fnDefPath, (ConvertTo-Json $fnDef -Depth 30), $utf8NoBom)
    Write-JlSuccess "Function definition saved: $fnDefPath ($fnSlug v$fnVersion)"

    $scheme = ''
    if ((Test-JlHasProperty $fnDef 'scheme')) { $scheme = $fnDef.scheme }

    # -------- Signing keypair --------
    # Account-scoped and scheme-agnostic: generated once per machine and reused
    # across every collaboration.
    if (-not (Test-Path -LiteralPath $script:JL_SIGNING_DIR)) {
        New-Item -ItemType Directory -Force -Path $script:JL_SIGNING_DIR | Out-Null
    }
    if (-not (Test-Path -LiteralPath $script:JL_SIGNING_SECRET)) {
        Write-JlInfo "Generating signing keypair..."
        Invoke-JlCli @(
            'crypto', 'signing-keygen',
            '--output-secret', $script:JL_SIGNING_SECRET,
            '--output-public', $script:JL_SIGNING_PUBLIC
        )
        Write-JlSuccess "Signing keypair created."
    } else {
        Write-JlInfo "Reusing existing signing keypair at $($script:JL_SIGNING_SECRET)."
    }

    # -------- Register the signing public key --------
    Write-JlStep "Registering $($script:JL_OUR_LABEL)'s signing public key with the platform..."
    $pubHex = Get-JlFileHex $script:JL_SIGNING_PUBLIC
    if ($pubHex.Length -ne 64) {
        Stop-JlWithError "Signing public key hex is $($pubHex.Length) chars, expected 64."
    }
    Invoke-JlApi POST "/api/companies/me/fhe-public-keys" -Body @{
        cryptoContextSpec   = $ctxSpec
        signingPublicKeyHex = $pubHex
    } | Out-Null
    Write-JlSuccess "Signing public key registered for crypto context: $ctxSpec"

    # -------- Default input file --------
    $inputCsv = ''
    if ($script:JL_DATA_DIR -and (Test-Path -LiteralPath $script:JL_DATA_DIR)) {
        $first = @(Get-ChildItem -LiteralPath $script:JL_DATA_DIR -File | Sort-Object Name)
        if ($first.Count -gt 0) { $inputCsv = $first[0].FullName }
    }

    # -------- Write config.env --------
    # Same KEY="value" format lib.sh reads, so the file is identical on both
    # platforms. Written fresh here rather than appended.
    $lines = @(
        "# JuLenny session config for $($script:JL_OUR_LABEL) ($($script:JL_ROLE_LABEL)).",
        "JULENNY_API_BASE=`"$($script:JULENNY_API_BASE)`"",
        "JULENNY_API_KEY=`"$($script:JULENNY_API_KEY)`"",
        "JULENNY_PROJECT_ID=`"$projectId`"",
        "JULENNY_JOINT_KEY_ID=`"$jointKeyId`"",
        "JULENNY_PERMISSION_ID=`"$permId`"",
        "JULENNY_OUR_SIDE=`"$($script:JULENNY_OUR_SIDE)`"",
        "JULENNY_ROLE=`"$($script:JL_ROLE_DIR)`"",
        "JULENNY_RESULT_VISIBILITY=`"$visibility`"",
        "JULENNY_SCHEME=`"$scheme`"",
        "JULENNY_CRYPTO_CONTEXT_SPEC=`"$ctxSpec`"",
        "JULENNY_INPUT_CSV=`"$($inputCsv -replace '\\', '\\')`"",
        "JULENNY_SIGNING_SECRET=`"$($script:JL_SIGNING_SECRET -replace '\\', '\\')`"",
        "JULENNY_SIGNING_PUBLIC=`"$($script:JL_SIGNING_PUBLIC -replace '\\', '\\')`""
    )
    [System.IO.File]::WriteAllText($script:JL_CONFIG, (($lines -join "`n") + "`n"), $utf8NoBom)
    Write-JlSuccess "Session config written to $($script:JL_CONFIG)"

    Write-Host ""
    Write-JlInfo "Next step (on this machine):"
    Write-Host "  run.ps1                # one-command driver"
    Write-Host "  01-keysetup-1.ps1      # or run the numbered scripts in order"
}

# ============================================================================
# Dataset encryption and upload (phase 4)
# ============================================================================
# One implementation for both sides; the caller passes its platform role. Each
# input is handled per the function-def's declared encoding and layout, which is
# what lets one script serve every scenario.

function Set-JlJsonMapEntry {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Key,
        [Parameter(Mandatory = $true)] $Value
    )
    $map = @{}
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        foreach ($p in $existing.PSObject.Properties) { $map[$p.Name] = $p.Value }
    }
    $map[$Key] = $Value
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, (ConvertTo-Json $map -Depth 10), $utf8NoBom)
}

function Invoke-JlEncryptAndUploadInputs {
    param([Parameter(Mandatory = $true)][ValidateSet('dataOwner', 'queryAnalyst')][string] $MyRole)

    $functionDefPath = Join-Path $script:JL_WORKDIR 'function-def.json'
    $pickFile        = Join-Path $script:JL_WORKDIR 'my_dataset_picks.json'
    $csvMapFile      = Join-Path $script:JL_WORKDIR 'dataset_csv_map.json'
    $ptSidecar       = Join-Path $script:JL_WORKDIR 'my_plaintext_paths.json'

    $def = Get-JlFunctionDefObject $functionDefPath
    if ($null -eq $def) {
        Stop-JlWithError "Function-def not found at $functionDefPath. Re-run 00-init.ps1."
    }

    Write-JlStep "$($script:JL_OUR_LABEL): pick datasets for $MyRole inputs"

    $myInputs = @()
    if ((Test-JlHasProperty $def 'inputs') -and $def.inputs) {
        $myInputs = @($def.inputs | Where-Object { $_.role -eq $MyRole })
    }
    if ($myInputs.Count -eq 0) {
        Write-JlInfo "Function declares no $MyRole inputs. Nothing to upload here."
        return
    }
    Write-JlInfo "Function requires $($myInputs.Count) $MyRole input(s)."

    # -------- Joint public key, only needed if some input is encrypted --------
    $jointPk = ''
    $hasCiphertextInput = $false
    foreach ($inp in $myInputs) {
        $enc = "$($inp.encoding)"
        $lay = "$($inp.layout)"
        if ((-not $enc.StartsWith('plaintext-')) -or ($lay -eq 'encrypted-bundle')) {
            $hasCiphertextInput = $true
            break
        }
    }
    if ($hasCiphertextInput) {
        foreach ($cand in @((Join-Path $script:JL_KEYS_DIR 'joint_public_key.bin'),
                            (Join-Path $script:JL_PEER_DIR 'joint-pk.bin'))) {
            if (Test-Path -LiteralPath $cand) { $jointPk = $cand; break }
        }
        if (-not $jointPk) {
            Write-JlInfo "Fetching joint public key from platform..."
            $perm = Get-JlPermission
            $jointKeyId = ''
            if ($perm -and ((Test-JlHasProperty $perm 'jointKeyId'))) { $jointKeyId = $perm.jointKeyId }
            if ([string]::IsNullOrWhiteSpace($jointKeyId)) {
                Stop-JlWithError "Permission has no jointKeyId. Keysetup may not be complete."
            }
            $jointPk = Join-Path $script:JL_KEYS_DIR 'joint_public_key.bin'
            Save-JlApiFile -Path "/api/fhe-joint-keys/$jointKeyId/public-key" -OutFile $jointPk
            Write-JlSuccess "Joint pk downloaded -> $jointPk"
        }
    }

    # -------- Per-input loop --------
    $picks = @{}
    foreach ($inp in $myInputs) {
        $inputName = $inp.name
        $inputEnc  = "$($inp.encoding)"
        $inputLay  = "$($inp.layout)"
        $isBundle    = ($inputLay -eq 'encrypted-bundle')
        $isPlaintext = ($inputEnc.StartsWith('plaintext-') -and -not $isBundle)

        Write-Host ""
        Write-Host "============================================================"
        if ($isBundle) {
            Write-Host " INPUT '$inputName' (encrypted bundle via recipe, role: $MyRole)"
        } elseif ($isPlaintext) {
            Write-Host " INPUT '$inputName' (PLAINTEXT, role: $MyRole)"
        } else {
            Write-Host " INPUT '$inputName' (ciphertext, role: $MyRole)"
        }
        Write-Host "============================================================"

        # Offer datasets already uploaded under this collaboration.
        $existing = @(Get-JlMyDatasetsInProject)
        $pickedId = ''
        if ($existing.Count -gt 0) {
            Write-JlInfo "Existing dataset(s) in this project:"
            for ($i = 0; $i -lt $existing.Count; $i++) {
                $created = '?'
                if ((Test-JlHasProperty $existing[$i] 'createdAt') -and $existing[$i].createdAt) {
                    $created = "$($existing[$i].createdAt)".Substring(0, [Math]::Min(10, "$($existing[$i].createdAt)".Length))
                }
                Write-Host ("  {0}) {1}  (id: {2}, uploaded {3})" -f ($i + 1), $existing[$i].name, $existing[$i].id, $created)
            }
            Write-Host "  u) Upload a NEW dataset"
            Write-Host ""

            $defaultPick = '1'
            if ($env:JULENNY_NEW_TEST -eq '1') { $defaultPick = 'u' }
            $choice = Read-JlValue "Pick for '$inputName' (1-$($existing.Count), or u)" $defaultPick

            if ($choice -notmatch '^[Uu]$') {
                $n = 0
                if (-not [int]::TryParse($choice, [ref] $n) -or $n -lt 1 -or $n -gt $existing.Count) {
                    Stop-JlWithError "Invalid choice: '$choice' (must be 1-$($existing.Count) or 'u')"
                }
                $pickedId = $existing[$n - 1].id
                Write-JlSuccess "Selected existing '$($existing[$n - 1].name)' ($pickedId) for '$inputName'."
            }
        }

        if (-not $pickedId) {
            $default = ''
            if ($script:JULENNY_INPUT_CSV) { $default = $script:JULENNY_INPUT_CSV }
            $inputFile = Select-JlDataFile "Pick the file for input '$inputName'" $default

            if ($inputFile -ne $default) { Set-JlConfigValue 'JULENNY_INPUT_CSV' $inputFile }

            $datasetName = Read-JlValue "Display name for the uploaded dataset" `
                                        "$($script:JL_OUR_LABEL) $inputName ($(Get-Date -Format 'yyyy-MM-dd'))"

            $base = [System.IO.Path]::GetFileName($inputFile)

            if ($isBundle) {
                # recipe-encode (cleartext) -> encrypt under the joint key -> upload
                if (-not $jointPk) { Stop-JlWithError "encrypted-bundle input needs the joint public key, but none was fetched." }
                if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
                    Stop-JlWithError "node is required to run the encodingRecipe executor (_core/recipe/recipe-encode.mjs)."
                }
                Write-Host ""
                Write-Host "============================================================"
                Write-Host " ENCODING + ENCRYPTING BUNDLE FOR '$inputName': $inputFile"
                Write-Host "============================================================"

                $bundleInput = Join-Path $script:JL_KEYS_DIR "$base.$inputName.bundle-input.json"
                $recipe = Join-Path $script:JL_CORE_DIR 'recipe\recipe-encode.mjs'
                if (-not (Test-Path -LiteralPath $recipe)) {
                    Stop-JlWithError "Recipe executor not found at $recipe"
                }
                & node $recipe $functionDefPath $inputName $inputFile $bundleInput
                if ($LASTEXITCODE -ne 0) { Stop-JlWithError "recipe executor failed for '$inputName'." }

                $bundleBin = Join-Path $script:JL_KEYS_DIR "$base.$inputName.bundle.bin"
                Invoke-JlCli @(
                    'crypto', 'encrypt',
                    '--function-def',      $functionDefPath,
                    '--input-name',        $inputName,
                    '--input',             $bundleInput,
                    '--joint-public-key',  $jointPk,
                    '--output',            $bundleBin
                )
                Write-JlSuccess "Encrypted bundle: $bundleBin ($((Get-Item -LiteralPath $bundleBin).Length) bytes)"
                $pickedId = Send-JlDataset -FilePath $bundleBin -DatasetName $datasetName -Kind 'ciphertext'
                Write-JlSuccess "Uploaded encrypted bundle '$datasetName' ($pickedId)."

            } elseif ($isPlaintext) {
                Write-Host ""
                Write-Host "============================================================"
                Write-Host " UPLOADING PLAINTEXT FILE FOR '$inputName': $inputFile"
                Write-Host "    encoding=$inputEnc, $((Get-Item -LiteralPath $inputFile).Length) bytes"
                Write-Host "============================================================"
                $pickedId = Send-JlDataset -FilePath $inputFile -DatasetName $datasetName -Kind 'plaintext'
                Write-JlSuccess "Uploaded plaintext '$datasetName' ($pickedId)."

                # Sidecar: phase 4.5 re-derives rotation indices from these files
                # to cross-check the platform, and needs the dataset id too.
                Set-JlJsonMapEntry -Path $ptSidecar -Key $inputName `
                                   -Value ([ordered]@{ path = $inputFile; datasetId = $pickedId })

            } else {
                Write-Host ""
                Write-Host "============================================================"
                Write-Host " ENCRYPTING FILE FOR '$inputName': $inputFile"
                Write-Host "    encoding=$inputEnc, $((Get-Item -LiteralPath $inputFile).Length) bytes"
                Write-Host "============================================================"

                $ciphertext = Join-Path $script:JL_KEYS_DIR "$base.$inputName.enc.bin"
                Invoke-JlCli @(
                    'crypto', 'encrypt',
                    '--input',            $inputFile,
                    '--joint-public-key', $jointPk,
                    '--output',           $ciphertext,
                    '--function-def',     $functionDefPath,
                    '--input-name',       $inputName
                )
                Write-JlSuccess "Encrypted: $ciphertext ($((Get-Item -LiteralPath $ciphertext).Length) bytes)"

                $pickedId = Send-JlDataset -FilePath $ciphertext -DatasetName $datasetName -Kind 'ciphertext'
                Write-JlSuccess "Uploaded as '$datasetName' ($pickedId)."

                # Remember which cleartext file produced this dataset, so the
                # viewer flow can resolve indicator slots back to record names
                # without asking. Written on BOTH sides: with resultVisibility
                # dataOwner the owner is the viewer and needs it too. (The bash
                # version only writes this on the consumer side.)
                Set-JlJsonMapEntry -Path $csvMapFile -Key $pickedId -Value $inputFile
                Write-JlInfo "Mapped dataset $pickedId -> $inputFile in $csvMapFile."
            }
        }

        Write-JlInfo "Declaring '$inputName' = $pickedId on the platform..."
        Invoke-JlApi PUT "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/preferred-datasets/$inputName" `
                     -Body @{ datasetId = $pickedId } | Out-Null
        Write-JlSuccess "Platform now knows: $inputName -> $pickedId."

        $picks[$inputName] = $pickedId
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($pickFile, (ConvertTo-Json $picks -Depth 5), $utf8NoBom)

    Write-Host ""
    Write-JlSuccess "$($script:JL_OUR_LABEL)'s dataset picks for this execution:"
    foreach ($k in $picks.Keys) { Write-Host ("   {0} -> {1}" -f $k, $picks[$k]) }
    Write-JlInfo "Saved to $pickFile (local to this machine)."
}

# ============================================================================
# Keysetup finalization (phase 3)
# ============================================================================
# lead/03 and main/03 are 95% identical in bash. Here the shared work lives in
# one function and the two scripts just call it, so the combines cannot drift
# apart between sides.
#
# CRITICAL: the combines always pass share-a = the LEAD's share and
# share-b = the MAIN's share, on BOTH machines. The ordering is by role, not by
# "mine first". Both sides must produce byte-identical keys, because the
# platform compares their SHA-256 hashes to decide the keysetup is sound.

function Request-JlFinalKeyUploadUrl {
    param([Parameter(Mandatory = $true)][string] $KeyType)
    $resp = Invoke-JlApi POST "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/keysetup/final-keys/upload-url" `
                         -Body @{ keyType = $KeyType }
    $url = ''
    $key = ''
    if ($resp) {
        if ((Test-JlHasProperty $resp 'uploadUrl')) { $url = $resp.uploadUrl }
        if ((Test-JlHasProperty $resp 'objectKey')) { $key = $resp.objectKey }
    }
    if ([string]::IsNullOrWhiteSpace($url) -or [string]::IsNullOrWhiteSpace($key)) {
        Stop-JlWithError "upload-url for $KeyType did not return both an uploadUrl and an objectKey."
    }
    return @{ UploadUrl = $url; ObjectKey = $key }
}

function Send-JlBlobToStorage {
    param(
        [Parameter(Mandatory = $true)][string] $Url,
        [Parameter(Mandatory = $true)][string] $Path
    )
    try {
        Invoke-WebRequest -Method PUT -Uri $Url -InFile $Path `
            -ContentType 'application/octet-stream' -UseBasicParsing -ErrorAction Stop | Out-Null
    } catch {
        Stop-JlWithError "object storage PUT failed for ${Path}: $($_.Exception.Message)"
    }
}

# Lowercase hex, matching sha256sum. Get-FileHash returns uppercase, and the
# platform compares these strings against the peer's.
function Get-JlSha256 {
    param([Parameter(Mandatory = $true)][string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

function Invoke-JlFinalizeKeysetup {
    Write-JlStep "$($script:JL_OUR_LABEL): finalize joint keysetup"

    # Idempotence marker, per permission. When a new permission is created under
    # an existing complete joint key the crypto is already done locally, but the
    # finalKeys envelope still has to be POSTed against the NEW permission id.
    $marker = Join-Path $script:JL_WORKDIR "finalkeys_submitted_$($script:JULENNY_PERMISSION_ID)"
    if (Test-Path -LiteralPath $marker) {
        Write-JlInfo "Final keys already submitted for permission $($script:JULENNY_PERMISSION_ID)."
        Write-JlInfo "(Remove $marker and rerun if you need to re-submit.)"
        return
    }

    # If the platform already considers this complete, there is nothing to do
    # even if this machine never held the intermediates (joint key set up
    # elsewhere and reused here). Detect that BEFORE requiring local files.
    $precheck = Invoke-JlApi POST "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/keysetup/final-keys/upload-url" `
                             -Body @{ keyType = 'joint_public_key' } -AllowFailure
    if ($null -eq $precheck) {
        $state = Get-JlKeysetupState
        if ($state -and ((Test-JlHasProperty $state 'state')) -and $state.state -eq 'complete') {
            Write-JlInfo "Final keys already registered for this permission (keysetup complete). Skipping finalize."
            New-Item -ItemType File -Path $marker -Force | Out-Null
            return
        }
    }

    $needsSum   = Test-JlFunctionRequiresSumKeys
    $needsRelin = Test-JlFunctionRequiresRelinKeys

    # Role decides which share is "a" and which is "b"; side decides which of
    # them is local and which came from the peer.
    $iAmLead = ($script:JL_ROLE_DIR -eq 'lead')
    if ($iAmLead) {
        $leadR2  = Join-Path $script:JL_KEYS_DIR 'lead-relin-r2.bin'
        $mainR2  = Join-Path $script:JL_PEER_DIR 'main-relin-r2.bin'
        $leadSum = Join-Path $script:JL_KEYS_DIR 'lead-sum-r1.bin'
        $mainSum = Join-Path $script:JL_PEER_DIR 'main-sum-r1.bin'
        $peerR2  = $mainR2
        $peerSum = $mainSum
        $mineR2  = $leadR2
        $mineSum = $leadSum
        $peerSumMessageType = 'sum-round1-continue'
    } else {
        $leadR2  = Join-Path $script:JL_PEER_DIR 'lead-relin-r2.bin'
        $mainR2  = Join-Path $script:JL_KEYS_DIR 'main-relin-r2.bin'
        $leadSum = Join-Path $script:JL_PEER_DIR 'lead-sum-r1.bin'
        $mainSum = Join-Path $script:JL_KEYS_DIR 'main-sum-r1.bin'
        $peerR2  = $leadR2
        $peerSum = $leadSum
        $mineR2  = $mainR2
        $mineSum = $mainSum
        $peerSumMessageType = 'sum-round1'
    }

    $combinedR1 = Join-Path $script:JL_KEYS_DIR 'combined-relin-r1.bin'
    # The round-2 intermediates are only needed to PRODUCE the final relin key. When a new
    # permission reuses an existing joint key, the final key is already on disk and the
    # combine below is skipped, so demanding the intermediates here refuses a case that
    # works perfectly well. Only insist on them when there is a combine still to do.
    $finalRelinPath = Join-Path $script:JL_KEYS_DIR 'final_relin_key.bin'
    if ($needsRelin -and -not (Test-Path -LiteralPath $finalRelinPath)) {
        if (-not (Test-Path -LiteralPath $mineR2))     { Stop-JlWithError "Missing $mineR2. Did 02-keysetup-2.ps1 run?" }
        if (-not (Test-Path -LiteralPath $combinedR1)) { Stop-JlWithError "Missing $combinedR1. Did 02-keysetup-2.ps1 run?" }
    }
    # Same reasoning as the relin intermediates above: sum-round-1 is only needed to
    # PRODUCE the final sum key, so a reused joint key that already has it needs nothing.
    $finalSumPath = Join-Path $script:JL_KEYS_DIR 'final_sum_key.bin'
    if ($needsSum -and -not (Test-Path -LiteralPath $finalSumPath) -and -not (Test-Path -LiteralPath $mineSum)) {
        Stop-JlWithError "Missing $mineSum. Did 01-keysetup-1.ps1 run?"
    }

    # The joint pk lands in different places depending on the side and on which
    # steps ran; check both.
    $jointPk = ''
    foreach ($cand in @((Join-Path $script:JL_KEYS_DIR 'joint_public_key.bin'),
                        (Join-Path $script:JL_PEER_DIR 'joint-pk.bin'))) {
        if (Test-Path -LiteralPath $cand) { $jointPk = $cand; break }
    }
    # Normally the lead picks the joint pk up during bundle 2. An additive-only function
    # has no bundle 2, so fetch the peer's pk-share here instead: for the lead, the
    # consumer's pk-share IS the joint public key.
    if (-not $jointPk -and $iAmLead) {
        $cand = Join-Path $script:JL_PEER_DIR 'joint-pk.bin'
        Write-JlInfo "Fetching the joint public key from $($script:JL_PEER_LABEL)'s pk-share..."
        Wait-JlPeerShare 'pk-share'
        Save-JlPeerShare -MessageType 'pk-share' -OutPath $cand
        if (Test-Path -LiteralPath $cand) { $jointPk = $cand }
    }
    if (-not $jointPk) { Stop-JlWithError "Cannot find the joint public key on disk." }

    # -------- 1. Fetch the peer's round-2 (and sum) shares --------
    # Skip if already present: a reused-joint-key permission has no fresh peer
    # upload for THIS permission, but the original bytes are still correct.
    if ($needsRelin) {
        if (-not (Test-Path -LiteralPath $peerR2)) {
            Write-JlInfo "Waiting for $($script:JL_PEER_LABEL)'s relin-round2 contribution..."
            Wait-JlPeerShare 'relin-round2'
            Save-JlPeerShare -MessageType 'relin-round2' -OutPath $peerR2
        } else {
            Write-JlInfo "Reusing existing peer share: $peerR2"
        }
    }
    if ($needsSum) {
        if (-not (Test-Path -LiteralPath $peerSum)) {
            Write-JlInfo "Waiting for $($script:JL_PEER_LABEL)'s $peerSumMessageType contribution..."
            Wait-JlPeerShare $peerSumMessageType
            Save-JlPeerShare -MessageType $peerSumMessageType -OutPath $peerSum
        } else {
            Write-JlInfo "Reusing existing peer share: $peerSum"
        }
    }

    # -------- 2. Final combines (deterministic; identical on both sides) --------
    $finalRelin = Join-Path $script:JL_KEYS_DIR 'final_relin_key.bin'
    $finalSum   = Join-Path $script:JL_KEYS_DIR 'final_sum_key.bin'

    if ($needsRelin) {
        if (-not (Test-Path -LiteralPath $finalRelin)) {
            Write-JlInfo "Combining round-2 relin shares -> final relin key..."
            Invoke-JlCli @(
                'crypto', 'relin-combine',
                '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
                '--round', '2',
                '--share-a',     $leadR2,
                '--share-b',     $mainR2,
                '--combined-r1', $combinedR1,
                '--output',      $finalRelin
            )
            Write-JlSuccess "Final relin key: $finalRelin ($((Get-Item -LiteralPath $finalRelin).Length) bytes)"
        } else {
            Write-JlInfo "Reusing existing final relin key: $finalRelin"
        }
    } else {
        Write-JlInfo "Function does not require a relinearization key; no relin combine."
    }

    if ($needsSum) {
        if (-not (Test-Path -LiteralPath $finalSum)) {
            Write-JlInfo "Combining sum-round-1 shares -> final sum key..."
            Invoke-JlCli @(
                'crypto', 'sum-combine',
                '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
                '--share-a',  $leadSum,
                '--share-b',  $mainSum,
                '--joint-pk', $jointPk,
                '--output',   $finalSum
            )
            Write-JlSuccess "Final sum key: $finalSum ($((Get-Item -LiteralPath $finalSum).Length) bytes)"
        } else {
            Write-JlInfo "Reusing existing final sum key: $finalSum"
        }
    }

    Write-JlInfo "Joint public key: $jointPk ($((Get-Item -LiteralPath $jointPk).Length) bytes)"

    # -------- 3. Hashes (the cross-party byte-equality check) --------
    $jointPkSha = Get-JlSha256 $jointPk
    $relinSha   = ''
    if ($needsRelin) { $relinSha = Get-JlSha256 $finalRelin }
    $sumSha     = ''
    if ($needsSum) { $sumSha = Get-JlSha256 $finalSum }

    Write-JlInfo "Hashes computed."
    Write-JlInfo "  joint_public_key: $jointPkSha"
    if ($needsRelin) { Write-JlInfo "  joint_relin_key:  $relinSha" }
    if ($needsSum) { Write-JlInfo "  eval_sum_key:     $sumSha" }

    # -------- 4. Upload URLs, then PUT each blob --------
    Write-JlInfo "Requesting upload URLs..."
    $jpkTarget = Request-JlFinalKeyUploadUrl 'joint_public_key'
    $relTarget = $null
    if ($needsRelin) { $relTarget = Request-JlFinalKeyUploadUrl 'joint_relin_key' }
    $sumTarget = $null
    if ($needsSum) { $sumTarget = Request-JlFinalKeyUploadUrl 'eval_sum_key' }

    Write-JlInfo "Uploading the final keys to object storage..."
    Send-JlBlobToStorage -Url $jpkTarget.UploadUrl -Path $jointPk
    Write-JlSuccess "  joint_public_key -> $($jpkTarget.ObjectKey)"
    if ($needsRelin) {
        Send-JlBlobToStorage -Url $relTarget.UploadUrl -Path $finalRelin
        Write-JlSuccess "  joint_relin_key  -> $($relTarget.ObjectKey)"
    }
    if ($needsSum) {
        Send-JlBlobToStorage -Url $sumTarget.UploadUrl -Path $finalSum
        Write-JlSuccess "  eval_sum_key     -> $($sumTarget.ObjectKey)"
    }

    # -------- 5. Build the to-sign JSON --------
    # Ordered dictionaries throughout: this document gets signed, so its shape
    # should not depend on hashtable enumeration order. The sum entry comes
    # first when present, matching the bash version.
    $toSign    = Join-Path $script:JL_ENV_DIR 'final-keys-to-sign.json'
    $signedOut = Join-Path $script:JL_ENV_DIR 'final-keys-signed.json'
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

    $keys = @()
    if ($needsSum) {
        $keys += [ordered]@{ keyType = 'eval_sum_key'; objectKey = $sumTarget.ObjectKey; sha256Hex = $sumSha }
    }
    $keys += [ordered]@{ keyType = 'joint_public_key'; objectKey = $jpkTarget.ObjectKey; sha256Hex = $jointPkSha }
    if ($needsRelin) {
        $keys += [ordered]@{ keyType = 'joint_relin_key';  objectKey = $relTarget.ObjectKey; sha256Hex = $relinSha }
    }

    $doc = [ordered]@{
        keys         = $keys
        permissionId = $script:JULENNY_PERMISSION_ID
        timestamp    = $timestamp
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($toSign, (ConvertTo-Json $doc -Depth 10), $utf8NoBom)
    Write-JlSuccess "To-sign JSON: $toSign"

    # -------- 6. Sign it offline --------
    Write-JlInfo "Signing the envelope (offline)..."
    Invoke-JlCli @(
        'crypto', 'wrap-final-keys-envelope',
        '--to-sign',    $toSign,
        '--secret-key', $script:JULENNY_SIGNING_SECRET,
        '--output',     $signedOut
    )
    Write-JlSuccess "Signed envelope: $signedOut"

    # -------- 7. POST it --------
    Write-JlInfo "POSTing signed envelope to /keysetup/final-keys..."
    $resp = $null
    try {
        $resp = Invoke-RestMethod -Method POST `
            -Uri "$($script:JULENNY_API_BASE)/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/keysetup/final-keys" `
            -Headers @{ 'x-api-key' = $script:JULENNY_API_KEY } `
            -InFile $signedOut -ContentType 'application/json' -ErrorAction Stop
    } catch {
        Stop-JlWithError "Submission failed: $($_.Exception.Message)"
    }

    # -------- 8. Report --------
    $state = ''
    if ($resp) {
        # grantState is what the API returns today; the other two are older names.
        # Matching none of them used to fall through to the "unexpected state"
        # branch, which skipped the completion marker and stalled a run whose
        # submission had actually succeeded.
        foreach ($field in 'grantState', 'permissionState', 'state') {
            if ((Test-JlHasProperty $resp $field)) { $state = $resp.$field; break }
        }
    }
    $msg = ''
    if ($resp -and ((Test-JlHasProperty $resp 'message'))) { $msg = $resp.message }

    Write-Host ""
    switch -Regex ($state) {
        '^(active|complete)$' {
            Write-JlSuccess "Keysetup is COMPLETE. Permission is active."
            if ($msg) { Write-JlSuccess "  Server: $msg" }
            New-Item -ItemType File -Path $marker -Force | Out-Null
            Write-Host ""
            Write-JlInfo "Next step (on this machine): 04-encrypt.ps1"
        }
        '^(awaiting-peer-submission|awaiting-finalization)$' {
            Write-JlInfo "Your submission is in. Waiting for $($script:JL_PEER_LABEL) to run their finalize."
            if ($msg) { Write-JlInfo "  Server: $msg" }
            New-Item -ItemType File -Path $marker -Force | Out-Null
            Write-Host ""
            Write-JlInfo "Tell $($script:JL_PEER_LABEL) to run 03-finalize-keysetup on their machine."
        }
        default {
            Write-JlWarn "Unexpected response state: '$state'"
            Write-Host ($resp | ConvertTo-Json -Depth 10)
        }
    }
}

# ============================================================================
# Result-visibility flows: releaser and viewer
# ============================================================================
# These do the threshold-decrypt work. Which one this side runs depends on
# resultVisibility (see Test-JlAmViewer / Test-JlAmReleaser):
#
#   releaser  polls for an awaiting-release execution, downloads the encrypted
#             result, produces this side's partial decryption using its keysetup
#             role (lead or main), signs it and uploads it. Never sees plaintext.
#
#   viewer    polls for a released execution, downloads the encrypted result and
#             the peer's partial, produces its own partial, combines both, and
#             renders the answer per the function-def's output.layout.
#
# Same code on both sides; the only side-specific piece is the path to the local
# FHE secret share, passed in (the owner and consumer filenames differ).

function Get-JlExecutionsInState {
    param([Parameter(Mandatory = $true)][string] $State)
    $resp = Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/executions?state=$State" -AllowFailure
    if ($null -eq $resp) { return @() }
    if (-not ((Test-JlHasProperty $resp 'executions'))) { return @() }
    return @($resp.executions)
}

function Invoke-JlReleaserFlow {
    param([Parameter(Mandatory = $true)][string] $MySecret)

    if (-not (Test-Path -LiteralPath $MySecret)) {
        Stop-JlWithError "Missing FHE secret share at $MySecret. Did keysetup complete on this machine?"
    }

    Write-JlStep "Releaser flow: partial-decrypt and upload (resultVisibility: $(Get-JlResultVisibility))"

    # There can be MORE THAN ONE awaiting-release execution: an older one whose
    # result is unusable cannot be released and sits in the queue until the
    # platform cancels it. Try every one and skip failures, so a stuck execution
    # does not block releasing the current cycle's run.
    Write-JlInfo "Polling for awaiting-release executions on permission $($script:JULENNY_PERMISSION_ID)..."
    $elapsed = 0
    $delay = 5
    $skip = @{}
    $released = 0
    $failed = 0

    $leadFlag = @()
    if ($script:JULENNY_ROLE -eq 'lead') { $leadFlag = @('--lead') }

    while ($true) {
        $execIds = @(Get-JlExecutionsInState 'awaiting-release' | ForEach-Object { $_.id } | Where-Object { $_ })
        $pending = @($execIds | Where-Object { -not $skip.ContainsKey($_) })

        if ($pending.Count -gt 0) {
            Write-JlInfo "Attempting $($pending.Count) awaiting-release execution(s)..."
            foreach ($execId in $pending) {
                Write-Host ""
                Write-JlInfo "Releasing execution $execId..."
                $resultBin  = Join-Path $script:JL_KEYS_DIR "result-$execId.bin"
                $partialBin = Join-Path $script:JL_KEYS_DIR "releaser-partial-$execId.bin"
                $sigBin     = Join-Path $script:JL_KEYS_DIR "releaser-partial-$execId.sig"

                # Download the encrypted result.
                $ok = $true
                try {
                    Invoke-WebRequest -Uri "$($script:JULENNY_API_BASE)/api/executions/$execId/result" `
                        -Headers @{ 'x-api-key' = $script:JULENNY_API_KEY } `
                        -OutFile $resultBin -UseBasicParsing -ErrorAction Stop | Out-Null
                } catch { $ok = $false }
                if ((-not $ok) -or (-not (Test-Path -LiteralPath $resultBin)) -or ((Get-Item -LiteralPath $resultBin).Length -le 0)) {
                    Write-JlWarn "Could not download the result for $execId. Skipping it."
                    Remove-Item -LiteralPath $resultBin -Force -ErrorAction SilentlyContinue
                    $skip[$execId] = $true
                    $failed++
                    continue
                }
                Write-JlSuccess "Encrypted result: $resultBin ($((Get-Item -LiteralPath $resultBin).Length) bytes)"

                # Partial-decrypt with our keysetup role. JULENNY_ROLE is fixed at
                # keysetup time and is independent of resultVisibility. A result
                # produced under a foreign crypto context aborts the CLI; that is
                # per-execution, not fatal, so skip and carry on.
                Write-JlInfo "Producing partial decryption (keysetup role: $($script:JULENNY_ROLE))..."
                $cliArgs = @(
                    'crypto', 'partial-decrypt',
                    '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
                    '--input',        $resultBin,
                    '--secret-key',   $MySecret,
                    '--output',       $partialBin
                ) + $leadFlag
                if (-not (Invoke-JlCliAllowFail $cliArgs)) {
                    Write-JlWarn "partial-decrypt FAILED for execution $execId (see above)."
                    Write-JlWarn "  Skipping it. It stays awaiting-release; ask the platform side to"
                    Write-JlWarn "  cancel/fail it if its result is known to be unusable."
                    $skip[$execId] = $true
                    $failed++
                    continue
                }
                Write-JlSuccess "Partial decrypt: $partialBin ($((Get-Item -LiteralPath $partialBin).Length) bytes)"

                # Sign the partial bytes.
                Write-JlInfo "Signing the partial decrypt with the registered signing key..."
                Invoke-JlCli @(
                    'crypto', 'sign',
                    '--input',      $partialBin,
                    '--secret-key', $script:JULENNY_SIGNING_SECRET,
                    '--output',     $sigBin
                )
                $sigHex = Get-JlFileHex $sigBin
                if ($sigHex.Length -ne 128) {
                    Stop-JlWithError "Signature is $($sigHex.Length) hex chars, expected 128."
                }

                # Upload as multipart, with the signature in a header.
                Write-JlInfo "Uploading partial decrypt to platform..."
                $boundary = [System.Guid]::NewGuid().ToString()
                $body = New-JlMultipartBody -FilePath $partialBin -Boundary $boundary -Fields @{}
                $state = ''
                try {
                    $resp = Invoke-JlMultipartPost `
                        -Uri "$($script:JULENNY_API_BASE)/api/executions/$execId/partial-decrypt" `
                        -Body $body -Boundary $boundary `
                        -Headers @{ 'x-api-key' = $script:JULENNY_API_KEY; 'x-jl-signature' = $sigHex }
                    if ($resp -and ((Test-JlHasProperty $resp 'state'))) { $state = $resp.state }
                } catch {
                    Write-JlWarn "Upload failed for ${execId}: $($_.Exception.Message)"
                }

                if ($state -eq 'released') {
                    Write-JlSuccess "Released. Execution state: $state."
                    $released++
                } else {
                    Write-JlWarn "Upload may have failed for $execId (state: '$state')."
                    $skip[$execId] = $true
                    $failed++
                }
            }
            if ($released -gt 0) { break }
            # Every pending execution failed and is now skipped. Keep polling for
            # a NEW one rather than giving up.
        }

        if ($execIds.Count -gt 0) {
            Write-Host ("  (only unreleasable execution(s) in the queue [{0}]; waiting for a new one, {1}s elapsed)" -f ($execIds -join ' '), $elapsed)
        } else {
            Write-Host ("  (no awaiting-release execution yet, {0}s elapsed)" -f $elapsed)
        }

        Start-Sleep -Seconds $delay
        $elapsed += $delay
        if     ($elapsed -gt 60) { $delay = 15 }
        elseif ($elapsed -gt 30) { $delay = 10 }
        if ($elapsed -gt 1800) {
            Stop-JlWithError "Timed out after 30 min waiting for a releasable execution. Has the viewer side triggered?"
        }
    }

    Write-Host ""
    Write-JlSuccess "Released $released execution(s)."
    if ($failed -gt 0) {
        Write-JlWarn "$failed execution(s) could NOT be released and remain awaiting-release"
        Write-JlWarn "  until the platform cancels them."
    }

    Write-Host ""
    Write-JlInfo "Next step:"
    Write-Host "  The viewer side can now run their decrypt script to combine partials and"
    Write-Host "  reveal the plaintext answer."
}

# Downloads a URL to a file and returns the HTTP status, without throwing, so
# the caller can tell 403 (not released yet) from a real failure.
function Save-JlExecutionFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $OutFile
    )
    try {
        $r = Invoke-WebRequest -Uri "$($script:JULENNY_API_BASE)$Path" `
                -Headers @{ 'x-api-key' = $script:JULENNY_API_KEY } `
                -OutFile $OutFile -UseBasicParsing -PassThru -ErrorAction Stop
        return [int] $r.StatusCode
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int] $_.Exception.Response.StatusCode }
        return $code
    }
}

# Slot indices of the meaningful values, numerically sorted.
#
# The field name depends on the scheme. The whole-number path (BFV) writes
# nonZeroValues; the decimal path (CKKS) writes significantValues, because CKKS
# leaves every empty slot at about 1e-14 and "non-zero" would mean all of them.
# Reading only nonZeroValues made every CKKS function look like it returned
# nothing, whatever it had actually computed.
function Get-JlResultSlotMap {
    param([Parameter(Mandatory = $true)] $CombineJson)
    foreach ($field in 'significantValues', 'nonZeroValues') {
        if (((Test-JlHasProperty $CombineJson $field)) -and
            ($null -ne $CombineJson.$field)) { return $CombineJson.$field }
    }
    return $null
}

function Get-JlNonZeroSlots {
    param([Parameter(Mandatory = $true)] $CombineJson)
    $map = Get-JlResultSlotMap $CombineJson
    if ($null -eq $map) { return @() }
    return @($map.PSObject.Properties.Name | Sort-Object { [int] $_ })
}

function Invoke-JlViewerFlow {
    param([Parameter(Mandatory = $true)][string] $MySecret)

    if (-not (Test-Path -LiteralPath $MySecret)) {
        Stop-JlWithError "Missing FHE secret share at $MySecret. Did keysetup complete on this machine?"
    }

    Write-JlStep "Viewer flow: combine partials and reveal the plaintext (resultVisibility: $(Get-JlResultVisibility))"

    # If THIS machine just triggered an execution, 05-run-query persisted its id.
    # Wait for that specific execution rather than offering older released ones:
    # decrypting a stale execution is an easy mistake to make.
    $lastExecFile = Join-Path $script:JL_WORKDIR 'last_exec_id'
    $wantExec = ''
    if (Test-Path -LiteralPath $lastExecFile) {
        $wantExec = ([System.IO.File]::ReadAllText($lastExecFile)).Trim()
    }

    $elapsed = 0
    $delay = 5
    $execId = ''
    $execWhen = ''
    $released = @()

    if ($wantExec) {
        Write-JlInfo "Waiting for this cycle's execution ($wantExec) to be released..."
    } else {
        Write-JlInfo "Polling for released executions on permission $($script:JULENNY_PERMISSION_ID)..."
    }

    while ($true) {
        if ($wantExec) {
            $doc = Invoke-JlApi GET "/api/executions/$wantExec" -AllowFailure
            $state = 'unknown'
            if ($doc -and ((Test-JlHasProperty $doc 'state'))) { $state = $doc.state }

            if ($state -eq 'released') {
                $execId = $wantExec
                $execWhen = 'unknown date'
                if ((Test-JlHasProperty $doc 'releasedAt') -and $doc.releasedAt) { $execWhen = $doc.releasedAt }
                elseif ((Test-JlHasProperty $doc 'triggeredAt') -and $doc.triggeredAt) { $execWhen = $doc.triggeredAt }
                Remove-Item -LiteralPath $lastExecFile -Force -ErrorAction SilentlyContinue
                Write-JlSuccess "This cycle's execution is released: $execId ($execWhen)"
                break
            } elseif ($state -eq 'failed') {
                Write-JlWarn "Execution $wantExec failed; falling back to the released-executions picker."
                Remove-Item -LiteralPath $lastExecFile -Force -ErrorAction SilentlyContinue
                $wantExec = ''
                continue
            } else {
                Write-Host ("  (execution {0} is '{1}', waiting for release, {2}s elapsed)" -f $wantExec, $state, $elapsed)
            }
        } else {
            $released = @(Get-JlExecutionsInState 'released')
            if ($released.Count -gt 0) { break }
            Write-Host ("  (no released execution yet, {0}s elapsed)" -f $elapsed)
        }

        Start-Sleep -Seconds $delay
        $elapsed += $delay
        if     ($elapsed -gt 60) { $delay = 15 }
        elseif ($elapsed -gt 30) { $delay = 10 }
        if ($elapsed -gt 1800) {
            Stop-JlWithError "Timed out after 30 min waiting for a released execution. Has the releaser run their script?"
        }
    }

    if (-not $execId) {
        while ($true) {
            if ($released.Count -eq 1) {
                $execId = $released[0].id
                $execWhen = 'unknown date'
                if ((Test-JlHasProperty $released[0] 'releasedAt') -and $released[0].releasedAt) { $execWhen = $released[0].releasedAt }
                Write-JlSuccess "Single released execution: $execId ($execWhen)"
                break
            }
            Write-JlInfo "Found $($released.Count) released executions (newest first):"
            for ($i = 0; $i -lt $released.Count; $i++) {
                $when = 'unknown date'
                if ((Test-JlHasProperty $released[$i] 'releasedAt') -and $released[$i].releasedAt) { $when = $released[$i].releasedAt }
                Write-Host ("  {0}) {1}  ({2})" -f ($i + 1), $released[$i].id, $when)
            }
            $choice = Read-JlValue "Pick an execution (1-$($released.Count), or r to refresh)" '1'
            if ($choice -match '^[Rr]$') {
                Write-JlInfo "Refreshing the released-executions list..."
                $released = @(Get-JlExecutionsInState 'released')
                continue
            }
            $n = 0
            if (-not [int]::TryParse($choice, [ref] $n) -or $n -lt 1 -or $n -gt $released.Count) {
                Stop-JlWithError "Invalid choice: $choice (must be between 1 and $($released.Count), or r)"
            }
            $execId = $released[$n - 1].id
            $execWhen = 'unknown date'
            if ((Test-JlHasProperty $released[$n - 1] 'releasedAt') -and $released[$n - 1].releasedAt) { $execWhen = $released[$n - 1].releasedAt }
            Write-JlSuccess "Selected: $execId ($execWhen)"
            break
        }
    }

    $resultBin      = Join-Path $script:JL_KEYS_DIR "result-$execId.bin"
    $peerPartialBin = Join-Path $script:JL_KEYS_DIR "peer-partial-$execId.bin"
    $myPartialBin   = Join-Path $script:JL_KEYS_DIR "my-partial-$execId.bin"

    Write-JlInfo "Downloading encrypted result from platform..."
    $code = Save-JlExecutionFile "/api/executions/$execId/result" $resultBin
    if ($code -eq 403) {
        Remove-Item -LiteralPath $resultBin -Force -ErrorAction SilentlyContinue
        Stop-JlWithError "Platform says the result isn't released yet. Has the releaser side run their script?"
    } elseif ($code -ne 200) {
        Remove-Item -LiteralPath $resultBin -Force -ErrorAction SilentlyContinue
        Stop-JlWithError "Platform returned HTTP $code when downloading the result. Cannot proceed."
    }
    if ((Get-Item -LiteralPath $resultBin).Length -le 0) { Stop-JlWithError "Result file is empty." }
    Write-JlSuccess "Encrypted result: $resultBin ($((Get-Item -LiteralPath $resultBin).Length) bytes)"

    Write-JlInfo "Downloading peer's partial decrypt..."
    $code = Save-JlExecutionFile "/api/executions/$execId/partial" $peerPartialBin
    if ($code -ne 200) {
        Remove-Item -LiteralPath $peerPartialBin -Force -ErrorAction SilentlyContinue
        Stop-JlWithError "Platform returned HTTP $code for the peer's partial. Releaser may not have uploaded yet."
    }
    if ((Get-Item -LiteralPath $peerPartialBin).Length -le 0) { Stop-JlWithError "Peer's partial is empty." }
    Write-JlSuccess "Peer's partial: $peerPartialBin ($((Get-Item -LiteralPath $peerPartialBin).Length) bytes)"

    Write-JlInfo "Producing this side's local partial decryption (keysetup role: $($script:JULENNY_ROLE))..."
    $leadFlag = @()
    if ($script:JULENNY_ROLE -eq 'lead') { $leadFlag = @('--lead') }
    Invoke-JlCli (@(
        'crypto', 'partial-decrypt',
        '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
        '--input',        $resultBin,
        '--secret-key',   $MySecret,
        '--output',       $myPartialBin
    ) + $leadFlag)
    Write-JlSuccess "Our partial: $myPartialBin"

    # ---- combine and render, driven by the function-def's output.layout ----
    $functionDefPath = Join-Path $script:JL_WORKDIR 'function-def.json'
    $def = Get-JlFunctionDefObject $functionDefPath

    $outputLayout = 'scalar'
    if ($def -and ((Test-JlHasProperty $def 'output')) -and $def.output -and
        ((Test-JlHasProperty $def.output 'layout')) -and $def.output.layout) {
        $outputLayout = $def.output.layout
    }

    $weightInputs = 0
    if ($def -and ((Test-JlHasProperty $def 'inputs')) -and $def.inputs) {
        $weightInputs = @($def.inputs | Where-Object { $_.schema -eq 'weight-vector' }).Count
    }

    Write-JlStep "Decrypting the answer (combining both partials)..."

    # Weight-vector functions (federated-average) produce REAL-valued slots.
    # Integer rounding would destroy them, so combine with --real and skip the
    # indicator-style analysis entirely.
    if ($weightInputs -gt 0) {
        $nSlots = 0
        if ($script:JULENNY_SHOW_SLOTS) { $nSlots = [int] $script:JULENNY_SHOW_SLOTS }
        if ($nSlots -le 0 -and $script:JULENNY_INPUT_CSV -and (Test-Path -LiteralPath $script:JULENNY_INPUT_CSV)) {
            $nSlots = @([System.IO.File]::ReadAllLines($script:JULENNY_INPUT_CSV)).Count
        }
        if ($nSlots -le 0) { $nSlots = 16 }

        Invoke-JlCli @(
            'crypto', 'combine',
            '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
            '--partials',     $peerPartialBin, $myPartialBin,
            '--real', '--show-slots', "$nSlots"
        )
        Write-Host ""
        Write-JlSuccess "Decryption complete. The combined (averaged) vector is shown above."
        Write-Host ""
        Write-JlInfo "Showing the first $nSlots slots. To see more: re-run 'julenny-toolkit crypto combine'"
        Write-JlInfo "with a larger --show-slots, or set JULENNY_SHOW_SLOTS and re-run this script."
        return
    }

    $combineRaw = Invoke-JlCli @(
        'crypto', 'combine',
        '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
        '--partials',     $peerPartialBin, $myPartialBin,
        '--non-zero', '--json'
    ) -PassThru
    $combine = $combineRaw | ConvertFrom-Json

    $nonZero    = [int] $combine.nonZeroSlots
    $totalSlots = [int] $combine.totalSlots
    Write-JlInfo "Combined plaintext: $nonZero non-zero slot(s) out of $totalSlots."
    Write-JlInfo "Function output layout: $outputLayout"

    switch -Regex ($outputLayout) {

        '^(scalar|scalar-int)$' {
            $answer = ''
            if ((Test-JlHasProperty $combine 'answer')) { $answer = $combine.answer }
            Write-Host ""
            if (-not [string]::IsNullOrWhiteSpace("$answer")) {
                Write-JlSuccess "Answer: $answer"
            } else {
                Write-JlWarn "Output is declared '$outputLayout' but combine didn't report a uniform answer."
                Write-JlWarn "Raw non-zero slot positions and values:"
                foreach ($s in (Get-JlNonZeroSlots $combine)) {
                    Write-Host ("    [{0}] = {1}" -f $s, (Get-JlResultSlotMap $combine).$s)
                }
            }
        }

        '^packed-real-vector$' {
            # Real-valued score vector (decision-tree per-class scores). Show the
            # slot values; the predicted class is the argmax. NOT an indicator
            # vector, so do not resolve slots against a dataset.
            $nShow = 8
            if ($script:JULENNY_SHOW_SLOTS) { $nShow = [int] $script:JULENNY_SHOW_SLOTS }
            Write-Host ""
            Invoke-JlCli @(
                'crypto', 'combine',
                '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
                '--partials',     $peerPartialBin, $myPartialBin,
                '--real', '--show-slots', "$nShow"
            )
            Write-Host ""
            Write-JlSuccess "Decryption complete. The real-valued result vector is shown above (predicted class = argmax)."
        }

        '^(packed-int-vector|indicator-hash)$' {
            if ($script:JULENNY_OUR_SIDE -eq 'data-owner') { $myRole = 'dataOwner' } else { $myRole = 'queryAnalyst' }

            $inputName = ''
            if ($def -and $def.inputs) {
                $mine = @($def.inputs | Where-Object {
                    $_.role -eq $myRole -and -not ("$($_.encoding)").StartsWith('plaintext')
                })
                if ($mine.Count -gt 0) { $inputName = $mine[0].name }
            }
            if (-not $inputName -and $script:JULENNY_INPUT_NAME) { $inputName = $script:JULENNY_INPUT_NAME }

            $pairInput = ''
            if ($def -and $def.inputs) {
                $pairs = @($def.inputs | Where-Object { "$($_.layout)" -eq 'pair-list' })
                if ($pairs.Count -gt 0) { $pairInput = $pairs[0].name }
            }

            $isBinaryIndicator = $false
            if ($def -and $def.inputs -and $inputName) {
                $isBinaryIndicator = @($def.inputs | Where-Object {
                    $_.name -eq $inputName -and $_.schema -eq 'binary-indicator'
                }).Count -gt 0
            }

            if ($pairInput) {
                # Rule-pair functions: the output slot index is the ROW NUMBER in
                # the pair-list input (0-based, blank lines skipped). Hash-based
                # resolve-indicator does not apply; print the matched rows.
                Write-Host ""
                if ($nonZero -eq 0) {
                    Write-JlSuccess "Answer: 0 matches. (No rule pair was satisfied by both sides.)"
                } else {
                    $pairFile = ''
                    $mapFile = Join-Path $script:JL_WORKDIR 'my_plaintext_paths.json'
                    if (Test-Path -LiteralPath $mapFile) {
                        $map = Get-Content -LiteralPath $mapFile -Raw | ConvertFrom-Json
                        if ((Test-JlHasProperty $map $pairInput)) { $pairFile = $map.$pairInput.path }
                    }
                    if (-not $pairFile -or -not (Test-Path -LiteralPath $pairFile)) {
                        $pairFile = Select-JlDataFile "File with the '$pairInput' rows used for this run"
                    }
                    Write-JlInfo "Pair list: $pairFile"
                    $rows = @([System.IO.File]::ReadAllLines($pairFile) | Where-Object { $_.Trim() -ne '' })
                    Write-JlSuccess "Matched rule pairs (satisfied by BOTH sides):"
                    foreach ($s in (Get-JlNonZeroSlots $combine)) {
                        $idx = [int] $s
                        if ($idx -lt $rows.Count) {
                            Write-Host ("    pair {0}: {1}" -f $idx, $rows[$idx])
                        } else {
                            Write-JlWarn ("    pair {0}: index beyond the pair list ({1} rows) - wrong file?" -f $idx, $rows.Count)
                        }
                    }
                }
            } elseif ($isBinaryIndicator) {
                # negotiation-matrix family: slots are GRID POSITIONS in the
                # agreed term grid, not hash buckets, so resolve-indicator does
                # not apply. Print positions directly.
                Write-Host ""
                if ($nonZero -eq 0) {
                    Write-JlSuccess "Answer: 0 matches. (No grid position was accepted by both sides.)"
                } else {
                    Write-JlSuccess "Both sides accepted these grid positions:"
                    foreach ($s in (Get-JlNonZeroSlots $combine)) {
                        Write-Host ("    position {0}  (slot value {1})" -f $s, (Get-JlResultSlotMap $combine).$s)
                    }
                    Write-JlInfo "Map positions back to contract terms with your grid file (comment lines excluded)."
                }
            } elseif ($nonZero -eq 0) {
                Write-Host ""
                Write-JlSuccess "Answer: 0 matches.  (No slots overlapped; the two datasets are disjoint.)"
            } elseif ($null -eq $def) {
                Write-JlWarn "No function-def at $functionDefPath; cannot resolve indicator slots."
                foreach ($s in (Get-JlNonZeroSlots $combine)) {
                    Write-Host ("    [{0}] = {1}" -f $s, (Get-JlResultSlotMap $combine).$s)
                }
            } elseif (-not $inputName) {
                Write-JlWarn "Could not determine this side's indicator input from the function-def."
                Write-JlWarn "Set JULENNY_INPUT_NAME to your indicator input and re-run to resolve names."
                foreach ($s in (Get-JlNonZeroSlots $combine)) {
                    Write-Host ("    [{0}] = {1}" -f $s, (Get-JlResultSlotMap $combine).$s)
                }
            } else {
                # Resolve hash-bucket positions back to record names against THIS
                # side's own dataset CSV.
                $execDoc = Invoke-JlApi GET "/api/executions/$execId" -AllowFailure

                # /execute maps inputDatasetIds positionally to the function-def's
                # .inputs[] order, so the dataset behind OUR indicator input sits
                # at that input's index. Scanning for "any dataset of ours" picked
                # the wrong one when this side owned several inputs.
                $names = @($def.inputs | ForEach-Object { $_.name })
                $inputIdx = [Array]::IndexOf($names, $inputName)
                $myDsetId = ''
                if ($inputIdx -ge 0 -and $execDoc -and ((Test-JlHasProperty $execDoc 'inputDatasetIds'))) {
                    $ids = @($execDoc.inputDatasetIds)
                    if ($inputIdx -lt $ids.Count) { $myDsetId = $ids[$inputIdx] }
                }

                $myDsetName = ''
                if ($myDsetId) {
                    $mine = @(Get-JlMyDatasetsInProject | Where-Object { $_.id -eq $myDsetId })
                    if ($mine.Count -gt 0) { $myDsetName = $mine[0].name }
                    Write-JlInfo "Your dataset for this execution: '$myDsetName' ($myDsetId)"
                }

                $csvMapFile = Join-Path $script:JL_WORKDIR 'dataset_csv_map.json'
                $inputCsv = ''
                if ($myDsetId -and (Test-Path -LiteralPath $csvMapFile)) {
                    $csvMap = Get-Content -LiteralPath $csvMapFile -Raw | ConvertFrom-Json
                    if ((Test-JlHasProperty $csvMap $myDsetId)) { $inputCsv = $csvMap.$myDsetId }
                }

                if ($inputCsv -and (Test-Path -LiteralPath $inputCsv)) {
                    Write-JlInfo "Originating CSV (from dataset map): $inputCsv"
                } else {
                    if ($inputCsv) {
                        Write-JlWarn "Map says the CSV was $inputCsv but that file no longer exists."
                    } elseif ($myDsetId) {
                        Write-JlWarn "No CSV mapping for dataset $myDsetId. The CSV you provide MUST"
                        Write-JlWarn "  be the EXACT one that was encrypted to create this dataset."
                    }
                    $default = ''
                    if ($script:JULENNY_INPUT_CSV) { $default = $script:JULENNY_INPUT_CSV }
                    $inputCsv = Select-JlDataFile "Originating CSV for dataset '$myDsetName'" $default

                    if ($myDsetId) {
                        $existing = @{}
                        if (Test-Path -LiteralPath $csvMapFile) {
                            $tmp = Get-Content -LiteralPath $csvMapFile -Raw | ConvertFrom-Json
                            foreach ($p in $tmp.PSObject.Properties) { $existing[$p.Name] = $p.Value }
                        }
                        $existing[$myDsetId] = $inputCsv
                        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
                        [System.IO.File]::WriteAllText($csvMapFile, (ConvertTo-Json $existing -Depth 5), $utf8NoBom)
                        Write-JlInfo "Mapped dataset $myDsetId -> $inputCsv in $csvMapFile."
                    }
                }

                $slotsCsv = (Get-JlNonZeroSlots $combine) -join ','
                Write-Host ""
                Write-JlStep "Resolving $nonZero non-zero slot(s) against $inputCsv..."
                Invoke-JlCli @(
                    'crypto', 'resolve-indicator',
                    '--context-spec', $script:JULENNY_CRYPTO_CONTEXT_SPEC,
                    '--slots',        $slotsCsv,
                    '--input',        $inputCsv,
                    '--function-def', $functionDefPath,
                    '--input-name',   $inputName
                )
            }
        }

        default {
            Write-JlWarn "Unknown output.layout '$outputLayout'. Showing raw combine output."
            Write-Host $combineRaw
        }
    }

    Write-Host ""
    Write-JlSuccess "Decryption complete. The plaintext answer is shown above."
    Write-Host ""
    Write-JlInfo "If the answer is what you expected: keysetup, encryption, computation, and decryption all worked end-to-end."
}

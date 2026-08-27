# Data-consumer: trigger the execution and wait for it to finish.
#
# Confirms every function input has a declared dataset, gets a cost estimate,
# lets the operator pick an engine and confirm the spend, triggers, then polls
# until the platform is waiting on the other side's release.
#
# PowerShell twin of 05-run-query.sh.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. "$here\..\sides\data-consumer.ps1"
. "$here\..\lib.ps1"
Import-JlSession

$functionDefPath = Join-Path $script:JL_WORKDIR 'function-def.json'
$def = Get-JlFunctionDefObject $functionDefPath
if ($null -eq $def) {
    Stop-JlWithError "Function-def not found at $functionDefPath. Re-run 00-init.ps1."
}

Write-JlStep "$($script:JL_OUR_LABEL): trigger the execution"

# -------- Confirm every input has a declared dataset --------
Write-JlInfo "Fetching declared dataset picks from the platform..."
$declared = Invoke-JlApi GET "/api/fhe-permissions/$($script:JULENNY_PERMISSION_ID)/preferred-datasets"

$inputNames = @($def.inputs | ForEach-Object { $_.name })
$missing = @()
foreach ($name in $inputNames) {
    $id = ''
    if ($declared -and ((Test-JlHasProperty $declared $name)) -and $declared.$name) {
        $id = $declared.$name.datasetId
    }
    if ([string]::IsNullOrWhiteSpace($id)) { $missing += $name }
}
if ($missing.Count -gt 0) {
    Write-JlWarn "Function inputs without a declared pick yet: $($missing -join ', ')"
    Write-JlWarn "Ask the responsible side to run their 04-encrypt for those inputs."
    Stop-JlWithError "Cannot proceed."
}

Write-Host ""
Write-Host "============================================================"
Write-Host " DECLARED DATASET PICKS FOR THIS EXECUTION:"
foreach ($name in $inputNames) {
    $entry = $declared.$name
    $when = '?'
    if ((Test-JlHasProperty $entry 'declaredAt') -and $entry.declaredAt) { $when = $entry.declaredAt }
    Write-Host "   ${name}:"
    Write-Host "       datasetId   = $($entry.datasetId)"
    Write-Host "       declaredAt  = $when"
}
Write-Host "============================================================"

# CRITICAL: /estimate and /execute map inputDatasetIds to function inputs BY
# POSITION, in the function-def's .inputs[] order. Build the array in exactly
# that order. The declared-picks object's key order is arbitrary, so deriving
# the array from it directly would send ciphertexts into the wrong slots (e.g.
# plaintext rule_pairs landing in left_indicator).
$inputIds = @($inputNames | ForEach-Object { $declared.$_.datasetId })

# Both /estimate and /execute return "No remaining executions." once this
# permission's allowedExecutions are spent. Rather than dying, offer to re-check
# after the data owner tops up the SAME permission (that increments the existing
# grant: no new keysetup, no new permission).
function Test-JlNoExecutions {
    param([string] $Message)
    return ("$Message" -like '*No remaining executions*')
}

function Confirm-JlRecheckOrStop {
    Write-Host ""
    Write-JlWarn "This permission has no remaining executions left."
    $perm = Get-JlPermission
    if ($perm -and ((Test-JlHasProperty $perm 'allowedExecutions')) -and $perm.allowedExecutions) {
        Write-JlInfo "  (executions granted so far: $($perm.allowedExecutions), remaining: 0)"
    }
    Write-JlInfo "Ask $($script:JL_PEER_LABEL) (the data owner) to add more executions to this"
    Write-JlInfo "permission ($($script:JULENNY_PERMISSION_ID)). It tops up the existing grant -"
    Write-JlInfo "no new keysetup and no new permission needed."
    Write-Host ""
    $more = Read-JlValue "Have they added more? Re-check now? (y/N)" 'N'
    if ($more -match '^[Yy]') {
        Write-JlInfo "Re-checking with the platform..."
        return $true
    }
    Write-JlInfo "No executions added. Stopping. Re-run this script once $($script:JL_PEER_LABEL) grants more."
    exit 0
}

$execId = ''
while (-not $execId) {
    $chosenEngine = ''
    $quoteToken = ''

    Write-Host ""
    Write-JlInfo "Estimating execution cost..."
    # Engine-agnostic estimate: .options[] comes back already filtered to the
    # engines THIS account may actually run (GPU only if the plan allows it),
    # each with its own cost and quoteToken. That is what drives the menu, not
    # the function-def's supportedEngines, which is only what it could use in
    # theory.
    $est = Invoke-JlApi POST "/api/grants/$($script:JULENNY_PERMISSION_ID)/estimate" `
                        -Body @{ inputDatasetIds = $inputIds } -AllowFailure

    $options = @()
    if ($est -and ((Test-JlHasProperty $est 'options')) -and $est.options) {
        $options = @($est.options)
    }

    if ($options.Count -ge 1) {
        $optIdx = 0
        if ($options.Count -gt 1) {
            Write-Host ""
            Write-Host "This function can run on more than one engine available to you:"
            for ($i = 0; $i -lt $options.Count; $i++) {
                $e = $options[$i].engine
                switch ($e) {
                    'openfhe-cpu'       { $label = 'CPU (OpenFHE)' }
                    'fideslib-ckks-gpu' { $label = 'GPU (FIDESlib, L4)' }
                    default             { $label = "$e" }
                }
                Write-Host ("   [{0}] {1,-18} {2,-18} ~{3} CR (P90: {4} CR)" -f `
                    ($i + 1), $e, $label, $options[$i].costP50Credits, $options[$i].costP90Credits)
            }
            $engPick = Read-JlValue "Choose engine (1-$($options.Count))" '1'
            $n = 0
            if ([int]::TryParse($engPick, [ref] $n) -and $n -ge 1 -and $n -le $options.Count) {
                $optIdx = $n - 1
            }
        }

        $chosenEngine = $options[$optIdx].engine
        $quoteToken   = $options[$optIdx].quoteToken
        $costP50      = $options[$optIdx].costP50Credits
        $costP90      = $options[$optIdx].costP90Credits

        $bal = '?'; $avail = '?'; $held = '?'
        if ((Test-JlHasProperty $est 'balance') -and $est.balance) {
            if ((Test-JlHasProperty $est.balance 'credits'))     { $bal   = $est.balance.credits }
            if ((Test-JlHasProperty $est.balance 'available'))   { $avail = $est.balance.available }
            if ((Test-JlHasProperty $est.balance 'heldCredits')) { $held  = $est.balance.heldCredits }
        }

        Write-Host ""
        Write-Host "   Engine:         $chosenEngine"
        Write-Host "   Estimated cost: $costP50 CR (P90: $costP90 CR)"
        Write-Host "   Credit balance: $bal CR (available: $avail, held: $held)"
        Write-Host ""
        $proceed = Read-JlValue "Proceed with execution? (Y/n)" 'Y'
        if ($proceed -notmatch '^[Yy]') {
            Write-JlInfo "Execution cancelled. No credits were held."
            exit 0
        }
    } else {
        $estErr = ''
        if ($est -and ((Test-JlHasProperty $est 'error'))) { $estErr = $est.error }
        if (Test-JlNoExecutions $estErr) {
            Confirm-JlRecheckOrStop | Out-Null
            continue
        }
        Write-JlWarn "Cost estimate unavailable; the platform will auto-reserve credits at trigger time."
    }

    Write-Host ""
    Write-JlInfo "Triggering execution on permission $($script:JULENNY_PERMISSION_ID)..."
    $body = @{}
    if ($quoteToken) {
        $body['inputDatasetIds'] = $inputIds
        $body['quoteToken']      = $quoteToken
    }
    if ($chosenEngine) { $body['engine'] = $chosenEngine }

    $resp = $null
    $errMsg = ''
    try {
        $resp = Invoke-RestMethod -Method POST `
            -Uri "$($script:JULENNY_API_BASE)/api/grants/$($script:JULENNY_PERMISSION_ID)/execute" `
            -Headers @{ 'x-api-key' = $script:JULENNY_API_KEY } `
            -Body (ConvertTo-Json $body -Depth 10 -Compress) `
            -ContentType 'application/json' -ErrorAction Stop
    } catch {
        $errMsg = $_.Exception.Message
        try {
            $r = $_.Exception.Response
            if ($r) { $errMsg = (New-Object System.IO.StreamReader($r.GetResponseStream())).ReadToEnd() }
        } catch { }
    }

    if ($resp -and ((Test-JlHasProperty $resp 'error')) -and $resp.error) {
        $errMsg = $resp.error
        $resp = $null
    }

    if (-not $resp) {
        if (Test-JlNoExecutions $errMsg) {
            Confirm-JlRecheckOrStop | Out-Null
            continue
        }
        # The quote is a price lock with a 5 minute life, and the clock starts when
        # the estimate is fetched, not when the operator answers. Thinking time, or a
        # phone call, should not cost the run: go back and re-quote instead of dying.
        if ($errMsg -like '*Quote token has expired*') {
            Write-Host ""
            Write-JlWarn "That quote expired while you were deciding (they last 5 minutes)."
            Write-JlWarn "Fetching a fresh estimate. Nothing has been charged or held."
            continue
        }
        Write-JlErr "/execute rejected the trigger:"
        Write-JlErr "  $errMsg"
        if ($errMsg -like '*has not declared*') {
            Write-JlErr ""
            Write-JlErr "That input still needs its owner to run 04-encrypt. Once they do,"
            Write-JlErr "this script can be rerun without changes."
        }
        if ($errMsg -match 'redit|uote') {
            Write-JlErr ""
            Write-JlErr "Looks credit related: the balance may be insufficient."
        }
        Stop-JlWithError "Cannot proceed."
    }

    if ((Test-JlHasProperty $resp 'executionId')) { $execId = $resp.executionId }
    if (-not $execId) { Stop-JlWithError "No executionId returned." }
}

Write-JlSuccess "Execution triggered. ID: $execId"

# Persist this cycle's execution id so the viewer flow (06-decrypt) waits for
# THIS execution rather than offering older released ones.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $script:JL_WORKDIR 'last_exec_id'), $execId, $utf8NoBom)

# -------- Poll until the computation is done --------
Write-JlInfo "Polling for execution to complete..."
$elapsed = 0
$delay = 5
while ($true) {
    $doc = Invoke-JlApi GET "/api/executions/$execId" -AllowFailure
    $state = 'unknown'
    if ($doc -and ((Test-JlHasProperty $doc 'state')) -and $doc.state) { $state = $doc.state }

    $done = $false
    switch ($state) {
        'queued'    { Write-Host ("  state: {0} ({1}s elapsed)" -f $state, $elapsed) }
        'computing' { Write-Host ("  state: {0} ({1}s elapsed)" -f $state, $elapsed) }
        'awaiting-release' {
            Write-JlSuccess "Computation done. Awaiting $($script:JL_PEER_LABEL)'s partial-decrypt release."
            $done = $true
        }
        'released' {
            # Their releaser was watching and released between our polls.
            Write-JlSuccess "Computation done and already released by $($script:JL_PEER_LABEL)."
            $done = $true
        }
        'succeeded' {
            Write-JlSuccess "Computation done (internal permission; result directly available)."
            $done = $true
        }
        'failed' {
            Write-JlErr "Execution failed. Full execution doc:"
            Write-Host ($doc | ConvertTo-Json -Depth 10)
            Stop-JlWithError "See above for failureReason / error."
        }
        default { Write-JlWarn "Unexpected state: $state" }
    }
    if ($done) { break }

    Start-Sleep -Seconds $delay
    $elapsed += $delay
    if     ($elapsed -gt 60) { $delay = 15 }
    elseif ($elapsed -gt 30) { $delay = 10 }
    if ($elapsed -gt 1800) { Stop-JlWithError "Timed out after 30 min." }
}

Write-Host ""
Write-JlInfo "Next step: $($script:JL_PEER_LABEL) runs their end-of-cycle (release); then run 06-decrypt.ps1 here."

function New-Folder {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FolderPath
    )
    if (-not (Test-Path -Path $FolderPath)) {New-Item -Path $FolderPath -ItemType Directory -Force > $null}
}

function Write-RepairLog {
    [CmdletBinding(DefaultParameterSetName = 'FullEntry')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [string]$Message = "",

        [Parameter(Mandatory = $true)]
        [string]$Component,

        [Parameter(Mandatory = $false)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter(Mandatory = $false)]
        [datetime]$Time,

        [Parameter(ParameterSetName = 'Start')]
        [switch]$StartLogEntry,

        [Parameter(ParameterSetName = 'Add')]
        [switch]$AddLogEntryData,

        [Parameter(ParameterSetName = 'End')]
        [switch]$EndLogEntry
    )

    $callerLine   = $MyInvocation.ScriptLineNumber
    $callerScript = Split-Path -Path $MyInvocation.ScriptName -Leaf
    if ([string]::IsNullOrWhiteSpace($callerScript)) { $callerScript = "Interactive" }
    $resolvedSource = if ([string]::IsNullOrWhiteSpace($Source)) {
        "${callerScript}:${callerLine}"
    } else {
        "${callerScript}:${callerLine}($Source)"
    }

    $timestamp   = if ($Time) { $Time } else { Get-Date }
    $dateStr     = $timestamp.ToString("MM-dd-yyyy")
    $timeStr     = $timestamp.ToString("HH:mm:ss.fff")
    $tzOffset    = (Get-TimeZone).BaseUtcOffset.TotalMinutes
    $tzFormatted = if ($tzOffset -ge 0) { "+{0:000}" -f $tzOffset } else { "-{0:000}" -f [math]::Abs($tzOffset) }
    $threadId    = [System.Diagnostics.Process]::GetCurrentProcess().Id

    $statePath = "$LogPath.state"
    $logDir    = [System.IO.Path]::GetDirectoryName($LogPath)
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

    # The master log is a contended file: a CMTrace viewer, antivirus / search-indexer scans, or the OS
    # lagging to release the handle right after the previous append can all briefly lock it. Append with
    # retry and NEVER throw - a dropped log line must never abort the actual repair. -Encoding UTF8 skips
    # the BOM-detection read that Add-Content does by default, which is the open that fails on a
    # transiently held file (the same hardening Write-StepLogEntry already uses for step logs).
    $appendLog = {
        param($path, $value)
        for ($i = 0; $i -lt 10; $i++) {
            try { Add-Content -Path $path -Value $value -Encoding UTF8 -ErrorAction Stop; return } catch { Start-Sleep -Milliseconds 200 }
        }
        Write-Warning "Repair-System: a log entry could not be written to '$(Split-Path $path -Leaf)' after retries; continuing."
    }
    # Reads the open-entry state file, tolerating a transient lock or corrupt content (returns $null).
    $readState = {
        param($sp)
        for ($i = 0; $i -lt 10; $i++) {
            try { return (Get-Content $sp -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { Start-Sleep -Milliseconds 200 }
        }
        return $null
    }

    function Close-UnclosedEntry {
        if (Test-Path $statePath) {
            $state = & $readState $statePath
            Remove-Item $statePath -Force -ErrorAction SilentlyContinue
            if ($null -eq $state) { return }
            $autoCloseTime = [datetime]::Parse($state.Time)
            $dateAuto = $autoCloseTime.ToString("MM-dd-yyyy")
            $timeAuto = $autoCloseTime.ToString("HH:mm:ss.fff")
            $tzAuto   = if ($tzOffset -ge 0) { "+{0:000}" -f $tzOffset } else { "-{0:000}" -f [math]::Abs($tzOffset) }
            & $appendLog $state.LogPath "]LOG]!><time=""$timeAuto$tzAuto"" date=""$dateAuto"" component=""$($state.Component)"" context=""autoClosedByFollowingEntry"" type=""1"" thread=""$threadId"" file=""$resolvedSource"">"
        }
    }

    if ($StartLogEntry -and $EndLogEntry) {
        Close-UnclosedEntry
        & $appendLog $LogPath "<![LOG[$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""1"" thread=""$threadId"" file=""$resolvedSource"">"
        return
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Start' {
            Close-UnclosedEntry
            if ($null -eq $Message) { $Message = "LogEntry:" }
            & $appendLog $LogPath "<![LOG[$Message"
            @{ Component = $Component; Source = $resolvedSource; LogPath = $LogPath; Time = $timestamp.ToString("o") } |
                ConvertTo-Json -Compress | Out-File -FilePath $statePath -Encoding UTF8 -Force
        }
        'Add' {
            if ($Message) { & $appendLog $LogPath $Message }
        }
        'End' {
            if ($null -eq $Message) { $Message = "" }
            $state = $null
            if (Test-Path $statePath) {
                $state = & $readState $statePath
                Remove-Item $statePath -Force -ErrorAction SilentlyContinue
            }
            if ($null -ne $state) {
                & $appendLog $state.LogPath "$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$($state.Component)"" context="""" type=""1"" thread=""$threadId"" file=""$($state.Source)"">"
            } else {
                & $appendLog $LogPath "$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""1"" thread=""$threadId"" file=""$resolvedSource"">"
            }
        }
        default {
            Close-UnclosedEntry
            & $appendLog $LogPath "<![LOG[$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""1"" thread=""$threadId"" file=""$resolvedSource"">"
        }
    }
}

function Start-LogAppendJob {
    param(
        [Parameter(Mandatory=$true)]  [string]$StepLogPath,
        [Parameter(Mandatory=$true)]  [string]$MasterLogPath,
        [Parameter(Mandatory=$true)]  [string]$StepName,
        [Parameter(Mandatory=$false)] [string]$Component = "Repair-System",
        [switch]$Sync
    )
    $appendBlock = {
        param($stepLogPath, $masterLogPath, $stepName, $component)
        $maxWaitSec = 120; $waited = 0
        while (-not (Test-Path $stepLogPath) -and $waited -lt $maxWaitSec) {
            Start-Sleep -Seconds 5; $waited += 5
        }
        if (-not (Test-Path $stepLogPath)) { return }
        $content = Get-Content $stepLogPath -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($content)) { return }
        # Collapse repeated progress lines (DISM bar / SFC verification) to only the last one.
        # Split on \r\n, \n, or bare \r (SFC uses \r-only for in-place progress updates).
        # Blank lines that appear between progress lines are suppressed; the first blank line
        # after the last progress line is restored as a separator before the result text.
        $lines    = $content -split '\r?\n|\r'
        $filtered = [System.Collections.Generic.List[string]]::new()
        $pending  = $null
        foreach ($line in $lines) {
            if ($line -match '^\[=.*%|^Verification \d+% complete') {
                $pending = $line
            } elseif ([string]::IsNullOrWhiteSpace($line) -and $null -ne $pending) {
                # blank line while a progress line is pending — skip, it is between progress lines
            } else {
                if ($null -ne $pending) {
                    $filtered.Add($pending)
                    $filtered.Add("")   # blank separator before result text
                    $pending = $null
                }
                $filtered.Add($line)
            }
        }
        if ($null -ne $pending) { $filtered.Add($pending) }
        $content = $filtered -join "`n"
        $ts      = Get-Date
        $timeStr = $ts.ToString("HH:mm:ss.fff")
        $dateStr = $ts.ToString("MM-dd-yyyy")
        $tzOffset = (Get-TimeZone).BaseUtcOffset.TotalMinutes
        $tzFmt   = if ($tzOffset -ge 0) { "+{0:000}" -f $tzOffset } else { "-{0:000}" -f [math]::Abs($tzOffset) }
        $tid     = [System.Diagnostics.Process]::GetCurrentProcess().Id
        # Same contended-file hardening as Write-RepairLog: retry, and -Encoding UTF8 to skip the
        # BOM-detection read that fails on a transiently locked file (also keeps the master log a
        # single uniform encoding).
        $appendMaster = {
            param($mp, $v)
            for ($k = 0; $k -lt 10; $k++) {
                try { Add-Content -Path $mp -Value $v -Encoding UTF8 -ErrorAction Stop; return } catch { Start-Sleep -Milliseconds 200 }
            }
        }
        & $appendMaster $masterLogPath "<![LOG[--- $stepName log ---"
        & $appendMaster $masterLogPath $content
        & $appendMaster $masterLogPath "--- end $stepName log ---]LOG]!><time=""$timeStr$tzFmt"" date=""$dateStr"" component=""$component"" context="""" type=""1"" thread=""$tid"" file=""LogAppendJob"">"
    }
    if ($Sync) {
        & $appendBlock $StepLogPath $MasterLogPath $StepName $Component
    } else {
        return Start-Job -ScriptBlock $appendBlock -ArgumentList $StepLogPath, $MasterLogPath, $StepName, $Component
    }
}

function Write-StepLogEntry {
    # Append $Value to a step log with retry. Uses -Encoding UTF8 to skip the BOM-detection
    # read that Add-Content normally performs — that read fails while the process redirect
    # FileStream is still held open. Retries up to 10x / 2s. Falls back to Write-Warning.
    param([string]$Path, [string]$Value, [switch]$Silent)
    for ($i = 0; $i -lt 10; $i++) {
        try {
            Add-Content -Path $Path -Value $Value -Encoding UTF8 -ErrorAction Stop
            return
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $Silent) {
        Write-Warning "Step log '$(Split-Path $Path -Leaf)' could not be written. Entry: $Value"
    }
}

<#
Single source of truth for Repair-System's exit code: position -> step name/label.
Used both when building the composite code and when decoding it via -AnalyzeExitCode.

The detailed exit code is a length-prefixed sequence of per-step fields whose position is the
step's identity AND its execution order. When a new step is inserted mid-sequence, every later
step shifts down a position - so a code produced by an OLDER build must be decoded against the
layout that produced it, or its fields get the wrong labels. RepairSystemStepLayouts keeps every
historical layout keyed by its field count; the current layout is the one with the most fields.
ConvertFrom / Get-RepairSystemStepAnalysis pick the layout by how many fields the code actually
carries, so historical codes keep their correct labels while new codes reflect the current order.
#>
$script:RepairSystemStepLayouts = @{
    # Legacy layout (builds up to v1.9): WMI Repository Repair did not exist yet.
    10 = [ordered]@{
        0 = @{ Key = 'Startup';                   Label = 'Startup / Pre-Flight Checks' }
        1 = @{ Key = 'DISMScanHealth';            Label = 'DISM /Online /Cleanup-Image /ScanHealth' }
        2 = @{ Key = 'DISMRestoreHealth';         Label = 'DISM /Online /Cleanup-Image /RestoreHealth' }
        3 = @{ Key = 'DISMAnalyzeComponentStore'; Label = 'DISM /Online /Cleanup-Image /AnalyzeComponentStore' }
        4 = @{ Key = 'DISMComponentCleanup';      Label = 'DISM /Online /Cleanup-Image /StartComponentCleanup' }
        5 = @{ Key = 'SFC';                       Label = 'SFC /scannow' }
        6 = @{ Key = 'SCCMCleanup';               Label = 'Content Cache Cleanup (ConfigMgr / Adaptiva / Intune / WU)' }
        7 = @{ Key = 'WindowsUpdateCleanup';      Label = 'Windows Update Cleanup' }
        8 = @{ Key = 'RepairCCM';                 Label = 'CCM Client Repair' }
        9 = @{ Key = 'ZipLogs';                   Label = 'Zip CBS/DISM Logs' }
    }
    # Current layout (v1.10+): WMI Repository Repair inserted at position 6 - it runs right after
    # SFC and before the WMI-dependent Content Cache Cleanup and CCM Repair steps, so those act on
    # a repaired store. Positions 7-10 are the former 6-9 shifted down by one.
    11 = [ordered]@{
        0  = @{ Key = 'Startup';                   Label = 'Startup / Pre-Flight Checks' }
        1  = @{ Key = 'DISMScanHealth';            Label = 'DISM /Online /Cleanup-Image /ScanHealth' }
        2  = @{ Key = 'DISMRestoreHealth';         Label = 'DISM /Online /Cleanup-Image /RestoreHealth' }
        3  = @{ Key = 'DISMAnalyzeComponentStore'; Label = 'DISM /Online /Cleanup-Image /AnalyzeComponentStore' }
        4  = @{ Key = 'DISMComponentCleanup';      Label = 'DISM /Online /Cleanup-Image /StartComponentCleanup' }
        5  = @{ Key = 'SFC';                       Label = 'SFC /scannow' }
        6  = @{ Key = 'WMIRepair';                 Label = 'WMI Repository Repair' }
        7  = @{ Key = 'SCCMCleanup';               Label = 'Content Cache Cleanup (ConfigMgr / Adaptiva / Intune / WU)' }
        8  = @{ Key = 'WindowsUpdateCleanup';      Label = 'Windows Update Cleanup' }
        9  = @{ Key = 'RepairCCM';                 Label = 'CCM Client Repair' }
        10 = @{ Key = 'ZipLogs';                   Label = 'Zip CBS/DISM Logs' }
    }
}
# The current (widest) layout - what ConvertTo encodes against and what live runs report/analyse.
$script:RepairSystemSteps = $script:RepairSystemStepLayouts[11]

function Get-RepairSystemStepLayout {
    <#
    Selects the step layout that matches a decoded code's field count: 10 -> legacy, 11 -> current.
    An unrecognised count (a partial or foreign string) falls back to the current layout for
    best-effort labelling; Get-RepairSystemStepAnalysis tolerates positions with no mapped step.
    #>
    param([Parameter(Mandatory=$true)][int]$FieldCount)
    if ($script:RepairSystemStepLayouts.ContainsKey($FieldCount)) {
        return $script:RepairSystemStepLayouts[$FieldCount]
    }
    return $script:RepairSystemSteps
}

<#
Well-known integer codes per step (by Key), plus a 'Generic' fallback used by every step.
Anything not listed here falls back to a generic "tool-specific result code" message.
#>
$script:RepairSystemKnownCodes = @{
    Generic = @{
        '0'          = 'Success, or the step was not requested. Without the original run context this cannot be distinguished: a step that was never requested (e.g. -noDism, -noSfc, or component cleanup not included) keeps its initial value of 0, indistinguishable here from a step that ran and succeeded. A step skipped for a known reason instead carries its own code - not necessary (-4) or connection lost (5) - so those never appear as 0.'
        '1'          = 'The step failed. See the step''s log file for details.'
        '5'          = 'Skipped - the remote connection was lost before this step could run.'
        '87'         = 'DISM: The parameter is incorrect (ERROR_INVALID_PARAMETER).'
        '1726'       = 'DISM: The remote procedure call failed.'
        '3010'       = 'DISM/SFC: Success, but a restart is required to finish applying changes.'
        '-2' = 'Repair-System terminated the process because it exceeded its maximum allowed run time (timeout). Restarting the device and running the step again is recommended.'
        '-3' = 'The process ended almost immediately, well before Repair-System killed it for a timeout. It was most likely closed by something else (e.g. Task Manager, a crash, a forced shutdown) before it could finish, so its own exit code could not be trusted and was not used.'
        '-4' = 'The step was requested but did not run because it was not necessary (for DISM RestoreHealth, ScanHealth reported no corruption; for DISM StartComponentCleanup, AnalyzeComponentStore did not recommend a cleanup) or because a required prior step did not complete. No changes were made, and this is not an error.'
    }
    Startup = @{
        '0' = 'Startup completed successfully.'
        '1' = 'Invalid -ComputerName format.'
        '2' = 'Remote computer unreachable (ping failed).'
        '3' = 'Unable to establish a WinRM/remote PowerShell session.'
        '4' = 'Connection to the remote device was lost during execution.'
        '5' = 'Not running with administrative privileges.'
        '6' = 'Error reading or writing the configuration file.'
        '7' = 'Conflicting parameters were supplied (e.g. -IncludeComponentCleanup with -noDism).'
    }
    WMIRepair = @{
        '0' = 'WMI repository is consistent, or was inconsistent and successfully salvaged (verified consistent afterwards).'
        '1' = 'WMI repository repair failed - still inconsistent after salvage, or the verify/salvage could not complete. See the step log; a manual "winmgmt /resetrepository" may be required (not attempted in this non-destructive step).'
    }
}

<#
Out-of-band sentinel values used in place of a process's own (untrustworthy) exit code when
Repair-System knows the raw exit code can't be trusted - either because Repair-System itself
killed the process for exceeding its time budget, or because the process disappeared
implausibly fast for the kind of operation it was running, which is a strong sign it was
closed by something other than Repair-System. Chosen deliberately out near the top of the
uint32 range so they can't be confused with a real Win32/DISM/SFC exit code.
#>
$script:RepairSystemProcessSentinel = @{
    TimedOut             = -2 # 0xFFFFFFFE / 4294967294 as uint32
    TerminatedExternally = -3 # 0xFFFFFFFD / 4294967293 as uint32
}

# Below this, a finished process is assumed to have had a real chance to do its job; below it,
# an unforced NON-ZERO exit is treated as suspicious (a clean exit code 0 is always trusted -
# see Get-RepairSystemProcessResult). DISM/SFC repairs realistically take much longer than this,
# but read-only steps such as AnalyzeComponentStore can legitimately finish in seconds, which is
# exactly why a fast SUCCESS must never be mistaken for an external termination.
$script:RepairSystemMinPlausibleDurationSeconds = 30

# Out-of-band value recorded for a step that WAS requested but deliberately did not run because
# a precondition was not met (DISM RestoreHealth when ScanHealth finds no corruption, DISM
# StartComponentCleanup when AnalyzeComponentStore recommends none, or a conditional step whose
# prerequisite step failed). Distinct from 0 - which for a requested step would read as a genuine
# success - so "requested but not executed" is never misreported as "ran and succeeded". Sits in
# the same reserved top-of-uint32 band as the process sentinels and is treated as a non-problem
# by Get-RepairSystemExitCodeSeverity.
$script:RepairSystemNotExecutedCode = -4 # 0xFFFFFFFC / 4294967292 as uint32

function Get-RepairSystemProcessResult {
    <#
    Translates a finished process's raw exit code into the value Repair-System actually trusts
    for that step. A raw exit code alone can't distinguish "finished the job" from "got
    terminated by something else" (Task Manager, a crash, a forced shutdown) - both look
    identical to .NET: HasExited = true, some ExitCode. So instead of trusting it blindly: if
    Repair-System itself killed the process for exceeding its time budget, return the
    dedicated TimedOut sentinel; if the process disappeared implausibly fast without
    Repair-System killing it, return the dedicated TerminatedExternally sentinel; otherwise
    trust the process's own exit code.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory=$true)]
        [datetime]$StartTime,

        [Parameter(Mandatory=$false)]
        [switch]$KilledByTimeout
    )
    # Use literal values so this function remains self-contained when shipped to a remote
    # session via New-RemoteFunctionScriptBlock (script-scope variables don't cross the wire).
    if ($KilledByTimeout) { return -2 }   # $script:RepairSystemProcessSentinel.TimedOut

    # A process ended by something other than Repair-System (Task Manager, taskkill /F, a crash,
    # a forced shutdown) is torn down via TerminateProcess and cannot report a clean result -
    # DISM and SFC only return exit code 0 when they actually finished their work. So a 0 exit is
    # trustworthy no matter how quickly it arrived, and must be believed here: some steps (notably
    # AnalyzeComponentStore) legitimately complete in well under the plausibility window below, and
    # treating that fast success as an external termination is precisely the bug this guards against.
    if ($Process.ExitCode -eq 0) { return 0 }

    # Only a NON-ZERO exit that arrived implausibly fast is suspicious: too quick for a real
    # scan/repair to have run and failed on its own, so its exit code can't be trusted.
    $minDur = if ($null -ne $script:RepairSystemMinPlausibleDurationSeconds) { $script:RepairSystemMinPlausibleDurationSeconds } else { 30 }
    if (((Get-Date) - $StartTime).TotalSeconds -lt $minDur) {
        return -3   # $script:RepairSystemProcessSentinel.TerminatedExternally
    }

    return $Process.ExitCode
}

function ConvertTo-RepairSystemExitCode {
    <#
    Renders each step's real return value (not a lossy category) as a length-prefixed hex
    field - one hex digit (0-8) saying how many hex digits follow, then those digits ('0'
    alone means the value is 0) - concatenated in fixed position order. No delimiters are
    needed because the length prefix marks where each field ends, and a fully successful run
    collapses to a string of 10 '0' characters instead of 80 hex characters.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [int[]]$Codes
    )
    $sb = [System.Text.StringBuilder]::new()
    foreach ($code in $Codes) {
        # [uint32] is a checked cast and throws on negative input; reinterpret the raw
        # bytes instead so e.g. -1 becomes 0xFFFFFFFF rather than an exception.
        $value = [BitConverter]::ToUInt32([BitConverter]::GetBytes($code), 0)
        if ($value -eq 0) {
            [void]$sb.Append('0')
        } else {
            $hex = '{0:X}' -f $value
            [void]$sb.Append([string]$hex.Length)
            [void]$sb.Append($hex)
        }
    }
    return $sb.ToString()
}

function ConvertFrom-RepairSystemExitCode {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Code
    )
    $Code = $Code.Trim()
    if ([string]::IsNullOrEmpty($Code)) {
        return [PSCustomObject]@{
            IsValid = $false
            Error   = "An empty string is not a valid Repair-System exit code."
            Values  = $null
        }
    }
    # The field count is NOT fixed: a code carries one field per step that existed in the build that
    # produced it (10 for legacy builds, 11 for current). Parse every field the string actually holds
    # and let the caller pick the matching step layout by the resulting count - this is what keeps a
    # historical code decoding correctly after a new step is inserted ahead of the old trailing ones.
    # Signed Int32 so the out-of-band sentinels round-trip back to the small negatives they were
    # stored as (-2/-3/-4) instead of surfacing as their unwieldy uint32 form (4294967294/93/92).
    # This makes ConvertFrom the true inverse of ConvertTo, which takes a signed [int[]].
    $values = [System.Collections.Generic.List[int]]::new()
    $pos = 0
    $i = 0

    while ($pos -lt $Code.Length) {
        $lengthChar = $Code[$pos]
        if ($lengthChar -notmatch '^[0-8]$') {
            return [PSCustomObject]@{
                IsValid = $false
                Error   = "'$Code' is not a valid Repair-System exit code: invalid length marker '$lengthChar' at position $pos (expected 0-8)."
                Values  = $null
            }
        }
        $len = [int]"$lengthChar"
        $pos++

        if ($len -eq 0) {
            $values.Add(0)
            $i++
            continue
        }

        if ($pos + $len -gt $Code.Length) {
            return [PSCustomObject]@{
                IsValid = $false
                Error   = "'$Code' is not a valid Repair-System exit code: truncated value for step $i (expected $len hex digit(s))."
                Values  = $null
            }
        }

        $hexChunk = $Code.Substring($pos, $len)
        if ($hexChunk -notmatch '^[0-9A-Fa-f]+$') {
            return [PSCustomObject]@{
                IsValid = $false
                Error   = "'$Code' is not a valid Repair-System exit code: '$hexChunk' is not valid hexadecimal (step $i)."
                Values  = $null
            }
        }

        # ToInt32 (not ToUInt32) so an 8-hex-digit field with the high bit set decodes to its
        # signed value (e.g. FFFFFFFC -> -4), the inverse of how ConvertTo encoded it.
        $values.Add([Convert]::ToInt32($hexChunk, 16))
        $pos += $len
        $i++
    }

    return [PSCustomObject]@{
        IsValid = $true
        Error   = $null
        Values  = @($values)
    }
}

function Get-RepairSystemExitCodeSeverity {
    <#
    Boils the detailed per-step codes down to a single conventional process exit code:
    0 = full success, 2 = startup/fatal error (nothing ran), 1 = anything else that
    reported a problem (including a mid-run connection loss, which is degraded/partial
    rather than a complete failure to start). The "requested but not executed" sentinel
    (-4) is a non-problem outcome (the step simply was not necessary) and does not count.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [int[]]$Codes
    )
    if (($Codes | Where-Object { $_ -ne 0 -and $_ -ne -4 }).Count -eq 0) { return 0 }
    if ($Codes[0] -in 1,2,3,5,6,7) { return 2 }
    return 1
}

function Get-RepairSystemStepAnalysis {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Code
    )
    $parsed = ConvertFrom-RepairSystemExitCode -Code $Code
    if (-not $parsed.IsValid) { return $null }
    # Decode against the layout that matches the code's field count, so a legacy (10-field) code
    # gets the pre-WMI labels and a current (11-field) code gets WMI at position 6.
    $stepMap = Get-RepairSystemStepLayout -FieldCount $parsed.Values.Count
    $steps = [System.Collections.Generic.List[PSCustomObject]]::new()
    for ($i = 0; $i -lt $parsed.Values.Count; $i++) {
        $step      = $stepMap[$i]
        $value     = $parsed.Values[$i]
        $valueKey  = $value.ToString()
        $stepKey   = if ($null -ne $step) { $step.Key }   else { $null }
        $stepLabel = if ($null -ne $step) { $step.Label } else { "Unknown step $i" }
        $description = if ($null -ne $stepKey -and $script:RepairSystemKnownCodes.ContainsKey($stepKey) -and $script:RepairSystemKnownCodes[$stepKey].ContainsKey($valueKey)) {
            $script:RepairSystemKnownCodes[$stepKey][$valueKey]
        } elseif ($script:RepairSystemKnownCodes.Generic.ContainsKey($valueKey)) {
            $script:RepairSystemKnownCodes.Generic[$valueKey]
        } else {
            "Tool-specific result code (0x{0:X8} / {0}). See the step's log file for details." -f $value
        }
        $steps.Add([PSCustomObject]@{
            Position    = $i
            Label       = $stepLabel
            Value       = $value
            Description = $description
        })
    }
    return $steps.ToArray()
}

function Set-RepairSystemExitCode {
    <#
    Single point where Repair-System's exit code is finalized: the full, lossless detail
    goes to the console and is returned as the DetailedExitCode property of the result object,
    while $global:LASTEXITCODE - the value scripts/CI/batch actually branch on - stays a
    conventional single digit.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [int[]]$Codes,
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = '',
        [Parameter(Mandatory=$false)]
        [string]$LogPath = '',
        [Parameter(Mandatory=$false)]
        [bool[]]$RequestedSteps = $null
    )
    $detailedCode = ConvertTo-RepairSystemExitCode -Codes $Codes
    $severity     = Get-RepairSystemExitCodeSeverity -Codes $Codes
    $global:LASTEXITCODE = $severity
    Write-Host "Detailed Exit Code: $detailedCode"
    $actions  = $null
    $analysis = Get-RepairSystemStepAnalysis -Code $detailedCode
    if ($null -ne $RequestedSteps -and $RequestedSteps.Count -ge 9) {
        $actions = [PSCustomObject]@{
            DISMScanHealth            = $RequestedSteps[1]
            DISMRestoreHealth         = $RequestedSteps[2]
            DISMAnalyzeComponentStore = $RequestedSteps[3]
            DISMComponentCleanup      = $RequestedSteps[4]
            SFC                       = $RequestedSteps[5]
            WMIRepair                 = $RequestedSteps[6]
            SCCMCleanup               = $RequestedSteps[7]
            WindowsUpdateCleanup      = $RequestedSteps[8]
            RepairCCM                 = $RequestedSteps[9]
        }
        if ($null -ne $analysis) {
            $analysis = foreach ($step in $analysis) {
                $isReq = $RequestedSteps[$step.Position]
                $val   = $step.Value
                $status = if (-not $isReq -and $val -eq 0) {
                    'Not requested'
                } elseif ($val -eq 0) {
                    'Success'
                } elseif ($val -eq 3010) {
                    'Success (restart required)'
                } elseif ($val -eq -4) {
                    'Skipped (not needed)'
                } elseif ($val -eq 5) {
                    'Skipped (connection lost)'
                } elseif ($val -eq -2) {
                    'Timed out'
                } elseif ($val -eq -3) {
                    'Terminated externally'
                } else {
                    $step.Description
                }
                [PSCustomObject]@{
                    Position = $step.Position
                    Label    = $step.Label
                    Value    = $val
                    Status   = $status
                }
            }
        }
    }
    $result = [PSCustomObject]@{
        ExitCode         = $severity
        DetailedExitCode = $detailedCode
        ComputerName     = if ($ComputerName) { $ComputerName } else { $env:COMPUTERNAME }
        LogPath          = if ($LogPath) { $LogPath } else { $null }
        Actions          = $actions
        Analysis         = $analysis
    }
    $result.PSObject.TypeNames.Insert(0, 'RepairSystem.Result')
    $global:RepairSystemResult = $result
    $result
}

function Write-RepairSystemExitCodeAnalysis {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Code
    )

    $parsed = ConvertFrom-RepairSystemExitCode -Code $Code
    if (-not $parsed.IsValid) {
        Write-Error $parsed.Error
        $global:LASTEXITCODE = 1
        return
    }
    $global:LASTEXITCODE = 0

    $isFullSuccess = ($parsed.Values | Where-Object { $_ -ne 0 -and $_ -ne -4 }).Count -eq 0
    Write-Host "Repair-System Exit Code Analysis for: $Code"
    Write-Host $(if ($isFullSuccess) { "Overall: SUCCESS - no errors reported by any step.`r`n" } else { "Overall: One or more steps reported an error or warning.`r`n" })

    foreach ($step in (Get-RepairSystemStepAnalysis -Code $Code)) {
        Write-Host "[$($step.Position)] $($step.Label)"
        Write-Host "`tValue: 0x$('{0:X8}' -f $step.Value) ($($step.Value))"
        Write-Host "`t$($step.Description)`r`n"
    }
}

function New-RemoteFunctionScriptBlock {
    <#
    Invoke-Command -ScriptBlock ${function:Name} only ships that single function's body to the
    remote session, so helper functions it depends on (eg. Stop-ServiceSafely) are otherwise
    undefined there. This bundles the helper definitions together with the entry point into one
    script block, so the helper stays defined in a single place but still works when shipped remotely.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$FunctionName,

        [Parameter(Mandatory=$true)]
        [string]$EntryPoint
    )

    $scriptText = ""
    foreach ($name in $FunctionName) {
        $scriptText += "function $name {`n" + (Get-Item "function:$name").ScriptBlock.ToString() + "`n}`n"
    }
    $scriptText += "$EntryPoint @args"
    return [scriptblock]::Create($scriptText)
}

function Invoke-RemoteStep {
    <#
    Runs one remote repair step via Invoke-Command. If the step fails with a remoting
    error, retries the connection for up to $ReconnectTimeoutSec seconds. If the machine
    comes back online the interrupted step is marked failed but remaining steps continue.
    If not, ConnectionLost is set so every later call becomes a no-op.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$InvokeParams,

        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$false)]
        [object[]]$ArgumentList = @(),

        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [string]$StepName,

        [Parameter(Mandatory=$true)]
        [ref]$ConnectionLost,

        [Parameter(Mandatory=$false)]
        [int]$ReconnectTimeoutSec = 90
    )

    if ($ConnectionLost.Value) {
        return $null
    }

    try {
        $stepResult = Invoke-Command @InvokeParams -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        return $stepResult
    } catch {
        $stepError = $_
        Write-Warning "Connection to '$ComputerName' interrupted during '$StepName'. Retrying for up to $ReconnectTimeoutSec seconds..."

        $deadline = (Get-Date).AddSeconds($ReconnectTimeoutSec)
        $reconnected = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 10
            try {
                Invoke-Command @InvokeParams -ScriptBlock { $true } -ErrorAction Stop | Out-Null
                $reconnected = $true
                break
            } catch { }
        }

        if ($reconnected) {
            Write-Warning "Reconnected to '$ComputerName'. Step '$StepName' did not complete - marking as failed and continuing."
            return 1
        }

        $ConnectionLost.Value = $true
        Write-Error "Lost connection to '$ComputerName' while performing '$StepName'. Skipping remaining repair steps.`r`n$stepError"
        return $null
    }
}

function Invoke-SFC {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$sfcLog,

        [Parameter(Mandatory = $true, Position=1)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout = 1.0,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=3)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}
    # get directory path from $sfcLog
    $sfcLogDir = Split-Path -Path $sfcLog -Parent
    $sfcErrorLog = Join-Path -Path $sfcLogDir -ChildPath "SFC_Error.log"
    $SfcMaxDurationVal = 20 * $ChangeTimeout
    if (-not $Quiet) { Write-Host "executing SFC (up to $SfcMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))" }
        try{
            $SfcMaxDuration = New-TimeSpan -Minutes $SfcMaxDurationVal
            $process = Start-Process -FilePath "sfc" -ArgumentList "/scannow" -RedirectStandardOutput $sfcLog -RedirectStandardError $sfcErrorLog -NoNewWindow -PassThru
            $SfcStartTime = Get-Date
            $sfcKilledByTimeout = $false

            # Monitor the process
            while (-not $process.HasExited) {
                Start-Sleep -Seconds 5

                $elapsed = (Get-Date) - $SfcStartTime
                if ($elapsed -gt $SfcMaxDuration) {
                    $sfcStucknotify = "Sfc.exe has been running for more than $($SfcMaxDuration.TotalMinutes) minutes. Stopping it..."
                    Write-Warning $sfcStucknotify
                    $sfcKilledByTimeout = $true
                    try {
                        $process.Kill()
                        [void]$process.WaitForExit(30000); $process.WaitForExit()
                        Write-StepLogEntry $sfcLog "!!`t`t> $sfcStucknotify"
                        $sfcStuckTerminate = "Sfc.exe terminated."
                        Write-StepLogEntry $sfcLog "!!`t`t> $sfcStuckTerminate"
                        Write-Warning $sfcStuckTerminate
                    } catch {
                        $sfcStuckTerminateFail = "Failed to terminate Sfc.exe: $_"
                        Write-StepLogEntry $sfcLog "!!`t`t> $sfcStuckTerminateFail" -Silent
                        Write-Warning $sfcStuckTerminateFail
                    }
                    break
                }
            }
            $process.WaitForExit()
            $sfcExitCode = Get-RepairSystemProcessResult -Process $process -StartTime $SfcStartTime -KilledByTimeout:$sfcKilledByTimeout
            # $sfcExitCode is captured above, before this log cleanup: right after a timeout kill a
            # log handle may still be held, so reading it can throw - keep that out of the outer
            # catch so a cleanup hiccup can't overwrite the step result (e.g. a -2 timeout as a 1).
            try {
                $logContent = Get-Content $sfcLog -Raw
                $logContent = $logContent -replace '[^\x00-\x7F]', ''
                $logContent = $logContent -replace [char]0
                Set-Content $sfcLog -Value $logContent

                $errorLogContent = Get-Content $sfcErrorLog -Raw
                $errorLogContent = $errorLogContent -replace '[^\x00-\x7F]', ''
                $errorLogContent = $errorLogContent -replace [char]0
                Write-StepLogEntry $sfcLog "`r`n`r`n// Start Error-Log:`r`n$errorLogContent`r`n// End Error-Log"
                Remove-Item -Path $sfcErrorLog -Force -ErrorAction SilentlyContinue
            } catch {
                Write-StepLogEntry $sfcLog "!!`t`t> Post-run log handling failed (step result preserved): $_" -Silent
            }
            return $sfcExitCode
        } catch {
            $errorMessage = "An error occurred while performing SFC: `r`n$_"
            Write-Error $errorMessage
            Add-Content -Path $sfcLog -Value $errorMessage
            return 1
        }
}

function Invoke-DISMScan {
    param (
        [CmdletBinding()]
        [Parameter(Mandatory=$true, Position=0)]
        [string]$dismScanLog,

        [Parameter(Mandatory = $true, Position=1)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout = 1.0,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=3)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}
    $dismScanLogDir = Split-Path -Path $dismScanLog -Parent
    $dismErrorLog = Join-Path -Path $dismScanLogDir -ChildPath "DISM_Error.log"
    $DismMaxDurationVal = 15 * $ChangeTimeout
    if (-not $Quiet) { Write-Host "executing DISM/ScanHealth (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))" }
    try{
        $DismMaxDuration = New-TimeSpan -Minutes $DismMaxDurationVal
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/Cleanup-Image", "/Scanhealth" -RedirectStandardOutput $dismScanLog -RedirectStandardError $dismErrorLog -NoNewWindow -PassThru
        $DismStartTime = Get-Date
        $dismKilledByTimeout = $false

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $DismStartTime
            if ($elapsed -gt $DismMaxDuration) {
                $dismStucknotify = "Dism.exe has been running for more than $($DismMaxDuration.TotalMinutes) minutes. Stopping it..."
                Write-Warning $dismStucknotify
                $dismKilledByTimeout = $true
                try {
                    $process.Kill()
                    Get-Process -Name "DismHost" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    [void]$process.WaitForExit(30000); $process.WaitForExit()
                    Write-StepLogEntry $dismScanLog "!!`t`t> $dismStucknotify"
                    $dismStuckTerminate = "Dism.exe terminated."
                    Write-StepLogEntry $dismScanLog "!!`t`t> $dismStuckTerminate"
                    Write-Warning $dismStuckTerminate
                } catch {
                    $dismStuckTerminateFail = "Failed to terminate Dism.exe: $_"
                    Write-StepLogEntry $dismScanLog "!!`t`t> $dismStuckTerminateFail" -Silent
                    Write-Warning $dismStuckTerminateFail
                }
                break
            }
        }

        $process.WaitForExit()
        $dismResult = Get-RepairSystemProcessResult -Process $process -StartTime $DismStartTime -KilledByTimeout:$dismKilledByTimeout
        # Capture the result before the log cleanup below: right after a timeout kill the error-log
        # handle may still be held, so reading it can throw - and that must not fall through to the
        # outer catch and overwrite the step result (e.g. turn a -2 timeout into a generic 1).
        try {
            $dismLogContent = Get-Content $dismErrorLog -Raw
            Write-StepLogEntry $dismScanLog "`r`n`r`n// Start Error-Log:`r`n$dismLogContent`r`n// End Error-Log"
            Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue
        } catch {
            Write-StepLogEntry $dismScanLog "!!`t`t> Post-run error-log handling failed (step result preserved): $_" -Silent
        }
        return $dismResult
    } catch {
        $errorMessage = "An error occurred while performing DISM ScanHealth: `r`n$_"
        Write-Error $errorMessage
        Add-Content -Path $dismScanLog -Value $errorMessage
        return 1
    }
}

function Get-DISMScanResult {
    param(
        [Parameter(Mandatory=$true)]
        [String]$dismScanLog
    )
    $lines=Get-Content -Path $dismScanLog
    $ScanResultData=$lines[-1..-($lines.Count)]
    foreach ($line in $ScanResultData) {
        if ($line -match 'The component store is repairable.') {
            return 1
        } elseif ($line -match 'No component store corruption detected.') {
            return 0

        }
    }
    return 1
}

function Invoke-DISMRestore {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$dismRestoreLog,

        [Parameter(Mandatory = $true, Position=1)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout = 1.0,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=3)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}
    $dismLogDir = Split-Path -Path $dismRestoreLog -Parent
    $dismErrorLog = Join-Path -Path $dismLogDir -ChildPath "DISM_Error.log"

    $DismMaxDurationVal = 40 * $ChangeTimeout
    if (-not $Quiet) { Write-Host "executing DISM/RestoreHealth (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))" }
    try{
        $DismMaxDuration = New-TimeSpan -Minutes $DismMaxDurationVal
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/Cleanup-Image", "/RestoreHealth" -RedirectStandardOutput $dismRestoreLog -RedirectStandardError $dismErrorLog -NoNewWindow -PassThru
        $DismStartTime = Get-Date
        $dismKilledByTimeout = $false

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $DismStartTime
            if ($elapsed -gt $DismMaxDuration) {
                $dismStucknotify = "Dism.exe has been running for more than $($DismMaxDuration.TotalMinutes) minutes. Stopping it..."
                Write-Warning $dismStucknotify
                $dismKilledByTimeout = $true
                try {
                    $process.Kill()
                    Get-Process -Name "DismHost" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    [void]$process.WaitForExit(30000); $process.WaitForExit()
                    Write-StepLogEntry $dismRestoreLog "!!`t`t> $dismStucknotify"
                    $dismStuckTerminate = "Dism.exe terminated."
                    Write-StepLogEntry $dismRestoreLog "!!`t`t> $dismStuckTerminate"
                    Write-Warning $dismStuckTerminate
                } catch {
                    $dismStuckTerminateFail = "Failed to terminate Dism.exe: $_"
                    Write-StepLogEntry $dismRestoreLog "!!`t`t> $dismStuckTerminateFail" -Silent
                    Write-Warning $dismStuckTerminateFail
                }
                break
            }
        }

        $process.WaitForExit()
        $dismResult = Get-RepairSystemProcessResult -Process $process -StartTime $DismStartTime -KilledByTimeout:$dismKilledByTimeout
        # Capture the result before the log cleanup below: right after a timeout kill the error-log
        # handle may still be held, so reading it can throw - and that must not fall through to the
        # outer catch and overwrite the step result (e.g. turn a -2 timeout into a generic 1).
        try {
            $dismLogContent = Get-Content $dismErrorLog -Raw
            Write-StepLogEntry $dismRestoreLog "`r`n`r`n// Start Error-Log:`r`n$dismLogContent`r`n// End Error-Log"
            Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue
        } catch {
            Write-StepLogEntry $dismRestoreLog "!!`t`t> Post-run error-log handling failed (step result preserved): $_" -Silent
        }
        return $dismResult
    } catch {
        $errorMessage = "An error occurred while performing DISM RestoreHealth: `r`n$_"
        Write-Error $errorMessage
        Add-Content -Path $dismRestoreLog -Value $errorMessage
        return 1
    }
}

function Invoke-DISMAnalyzeComponentStore {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$analyzeComponentLog,

        [Parameter(Mandatory = $true, Position=1)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout = 1.0,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=3)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}
    $DismLogDir = Split-Path -Path $analyzeComponentLog -Parent
    $DismErrorLog = Join-Path -Path $DismLogDir -ChildPath "DISM_Error.log"

    $DismMaxDurationVal = 5 * $ChangeTimeout
    if (-not $Quiet) { Write-Host "executing DISM Analyze Component Store (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))" }
    try{
        $DismMaxDuration = New-TimeSpan -Minutes $DismMaxDurationVal
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/Cleanup-Image", "/AnalyzeComponentStore" -RedirectStandardOutput $analyzeComponentLog -RedirectStandardError $DismErrorLog -NoNewWindow -PassThru
        $DismStartTime = Get-Date
        $dismKilledByTimeout = $false

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $DismStartTime
            if ($elapsed -gt $DismMaxDuration) {
                $dismStucknotify = "Dism.exe has been running for more than $($DismMaxDuration.TotalMinutes) minutes. Stopping it..."
                Write-Warning $dismStucknotify
                $dismKilledByTimeout = $true
                try {
                    $process.Kill()
                    Get-Process -Name "DismHost" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    [void]$process.WaitForExit(30000); $process.WaitForExit()
                    Write-StepLogEntry $analyzeComponentLog "!!`t`t> $dismStucknotify"
                    $dismStuckTerminate = "Dism.exe terminated."
                    Write-StepLogEntry $analyzeComponentLog "!!`t`t> $dismStuckTerminate"
                    Write-Warning $dismStuckTerminate
                } catch {
                    $dismStuckTerminateFail = "Failed to terminate Dism.exe: $_"
                    Write-StepLogEntry $analyzeComponentLog "!!`t`t> $dismStuckTerminateFail" -Silent
                    Write-Warning $dismStuckTerminateFail
                }
                break
            }
        }
        $process.WaitForExit()
        $dismResult = Get-RepairSystemProcessResult -Process $process -StartTime $DismStartTime -KilledByTimeout:$dismKilledByTimeout
        # AnalyzeComponentStore returns a NON-ZERO exit code (e.g. 1) precisely when it recommends
        # cleanup ("Component Store Cleanup Recommended : Yes") - a normal, successful outcome, not a
        # failure. Left alone, that fast (well under the plausibility window) non-zero-but-clean finish
        # is misread by Get-RepairSystemProcessResult as -3 (terminated externally), which in the caller
        # also suppresses the StartComponentCleanup step. DISM writes the verdict line only after the
        # scan has finished, so a self-completed analysis that produced a Yes/No verdict is a success:
        # normalise it to 0 and let Get-DISMAnalyzeComponentStoreResult (log-parsed) drive the cleanup
        # decision. A timeout kill (-2) or a genuine failure with no verdict line is left untouched.
        if (-not $dismKilledByTimeout -and $dismResult -ne 0) {
            try {
                $analyzeOutput = Get-Content -Path $analyzeComponentLog -Raw -ErrorAction Stop
                if ($analyzeOutput -match 'Component Store Cleanup Recommended\s*:\s*(Yes|No)') { $dismResult = 0 }
            } catch { }
        }
        # Capture the result before the log cleanup below: right after a timeout kill the error-log
        # handle may still be held, so reading it can throw - and that must not fall through to the
        # outer catch and overwrite the step result (e.g. turn a -2 timeout into a generic 1).
        try {
            $dismLogContent = Get-Content $dismErrorLog -Raw
            Write-StepLogEntry $analyzeComponentLog "`r`n`r`n// Start Error-Log:`r`n$dismLogContent`r`n// End Error-Log"
            Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue
        } catch {
            Write-StepLogEntry $analyzeComponentLog "!!`t`t> Post-run error-log handling failed (step result preserved): $_" -Silent
        }
        return $dismResult
    } catch {
        $errorMessage = "An error occurred while performing DISM AnalyzeComponentStore: `r`n$_"
        Write-Error $errorMessage
        Add-Content -Path $analyzeComponentLog -Value $errorMessage
        return 1
    }
}

function Get-DISMAnalyzeComponentStoreResult {
    param (
        [Parameter(Mandatory=$true)]
        [String]$analyzeComponentLog
    )

    $lines = Get-Content -Path $analyzeComponentLog
    $analyzeComponentLogData = $lines[-1..-($lines.Count)]
    foreach ($line in $analyzeComponentLogData) {
        if ($line -match 'Component Store Cleanup Recommended : Yes') {
            return $true
        } elseif ($line -match 'Component Store Cleanup Recommended : No') {
            return $false
        }
    }
    return $true
}

function Invoke-DISMComponentStoreCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$componentCleanupLog,

        [Parameter(Mandatory = $true, Position=1)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout = 1.0,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=3)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}
    $dismLogDir = Split-Path -Path $componentCleanupLog -Parent
    $DismErrorLog = Join-Path -Path $dismLogDir -ChildPath "DISM_Error.log"
    $DismMaxDurationVal = 20 * $ChangeTimeout
    if (-not $Quiet) { Write-Host "executing DISM Component Store Cleanup (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))" }
    try{
        $DismMaxDuration = New-TimeSpan -Minutes $DismMaxDurationVal
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/Cleanup-Image", "/StartComponentCleanup" -RedirectStandardOutput $componentCleanupLog -RedirectStandardError $DismErrorLog -NoNewWindow -PassThru
        $DismStartTime = Get-Date
        $dismKilledByTimeout = $false

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $DismStartTime
            if ($elapsed -gt $DismMaxDuration) {
                $dismStucknotify = "Dism.exe has been running for more than $($DismMaxDuration.TotalMinutes) minutes. Stopping it..."
                Write-Warning $dismStucknotify
                $dismKilledByTimeout = $true
                try {
                    $process.Kill()
                    Get-Process -Name "DismHost" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    [void]$process.WaitForExit(30000); $process.WaitForExit()
                    Write-StepLogEntry $componentCleanupLog "!!`t`t> $dismStucknotify"
                    $dismStuckTerminate = "Dism.exe terminated."
                    Write-StepLogEntry $componentCleanupLog "!!`t`t> $dismStuckTerminate"
                    Write-Warning $dismStuckTerminate
                } catch {
                    $dismStuckTerminateFail = "Failed to terminate Dism.exe: $_"
                    Write-StepLogEntry $componentCleanupLog "!!`t`t> $dismStuckTerminateFail" -Silent
                    Write-Warning $dismStuckTerminateFail
                }
                break
            }
        }

        $process.WaitForExit()
        $dismResult = Get-RepairSystemProcessResult -Process $process -StartTime $DismStartTime -KilledByTimeout:$dismKilledByTimeout
        # Capture the result before the log cleanup below: right after a timeout kill the error-log
        # handle may still be held, so reading it can throw - and that must not fall through to the
        # outer catch and overwrite the step result (e.g. turn a -2 timeout into a generic 1).
        try {
            $dismLogContent = Get-Content $dismErrorLog -Raw
            Write-StepLogEntry $componentCleanupLog "`r`n`r`n// Start Error-Log:`r`n$dismLogContent`r`n// End Error-Log"
            Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue
        } catch {
            Write-StepLogEntry $componentCleanupLog "!!`t`t> Post-run error-log handling failed (step result preserved): $_" -Silent
        }
        return $dismResult
    } catch {
        $message = "An error occurred while performing Component Store Cleanup: `r`n$_"
        Write-Error $message
        Add-Content -Path $componentCleanupLog -Value $message
    }
}

function Invoke-ContentCacheCleanup {
    <#
    Clears the content/download caches of the software-distribution systems present on the device -
    ConfigMgr (ccmcache), Windows Update (SoftwareDistribution\Download), Adaptiva OneSite
    (<drive>:\AdaptivaCache) and the Intune Management Extension (IMECache + Content staging). Each
    location is auto-detected; systems that are not installed are skipped. Whatever a running agent
    holds open is cleared best-effort now and the remainder is scheduled for deletion on the next
    reboot (via Remove-PathReliable), so the step returns 3010 ("restart required") when anything was
    deferred, otherwise 0. Self-contained apart from Remove-PathReliable, so it can be shipped remotely.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$cacheCleanupLog,

        [Parameter(Mandatory=$true, Position=1)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}

    if (-not $Quiet) { Write-Host "executing Content Cache Cleanup" }

    # Resolve the Windows directory from the OS itself - $env:windir can be empty in a stripped
    # environment, and an empty base is exactly how a cleanup can end up deleting from a drive root.
    # The result is validated, paths are only built from a validated base, and every deletion target
    # is re-checked below, so an empty/garbage value can never reach a delete.
    $winDir = [Environment]::GetFolderPath('Windows')
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:windir }
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:SystemRoot }
    $winDirValid = (-not [string]::IsNullOrWhiteSpace($winDir)) -and ($winDir -match '^[A-Za-z]:\\[^\\]') -and (Test-Path -LiteralPath $winDir -PathType Container)

    # Per-step log writer (captures the log path so it is safe to call from anywhere in the function).
    $log = {
        param($m)
        try { Add-Content -Path $cacheCleanupLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - $m" -ErrorAction SilentlyContinue } catch {}
    }.GetNewClosure()

    # A cache path is only safe to clear if it is absolute, at least one level below a drive root, not
    # the Windows directory or System32, and it exists. No folder-name requirement - a relocated cache
    # can be custom-named (e.g. D:\SCCMCache). An empty/garbage value fails the first checks, so it can
    # never become a root-level delete.
    $isSafeCache = {
        param($p, $win)
        if ([string]::IsNullOrWhiteSpace($p)) { return $false }
        $n = $p.TrimEnd('\')
        if ($n -notmatch '^[A-Za-z]:\\[^\\]+') { return $false }
        if (-not [string]::IsNullOrWhiteSpace($win)) {
            $w = $win.TrimEnd('\')
            if (($n -ieq $w) -or ($n -ieq ((Join-Path $w 'System32').TrimEnd('\')))) { return $false }
        }
        return (Test-Path -LiteralPath $n -PathType Container)
    }

    # Clears a validated folder's CONTENTS via Remove-PathReliable: deletes what is free right now and
    # schedules anything still locked for deletion at the next reboot. Returns $true if anything was
    # deferred to reboot.
    $clearContents = {
        param($folder)
        $deferred = $false
        Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $r = Remove-PathReliable -Path $_.FullName
            if ($r -and $r.Scheduled) { $deferred = $true }
        }
        return $deferred
    }

    # -----------------------------------------------------------------------------------------------
    # Detect each system's cache location(s). Absent systems yield nothing and are simply skipped.
    # -----------------------------------------------------------------------------------------------

    # ConfigMgr ccmcache (relocatable). The WMI CacheConfig class can come back empty even on a healthy
    # client, so try several sources in order and take the first trusted, non-empty path: WMI ->
    # UIResourceMgr COM (what Software Center reads) -> registry CacheConfig -> default under Windows.
    $ccmLoc = $null
    try { $ccmLoc = (Get-CimInstance -Namespace 'root\ccm\SoftMgmtAgent' -ClassName CacheConfig -ErrorAction Stop | Select-Object -First 1).Location } catch { $ccmLoc = $null }
    if ([string]::IsNullOrWhiteSpace($ccmLoc)) {
        try {
            $ui = New-Object -ComObject UIResource.UIResourceMgr
            $ccmLoc = $ui.GetCacheInfo().Location
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($ui)
        } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($ccmLoc)) {
        $ccmLoc = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\CacheConfig' -Name Location -ErrorAction SilentlyContinue).Location
    }
    if ([string]::IsNullOrWhiteSpace($ccmLoc) -and $winDirValid) { $ccmLoc = Join-Path $winDir 'ccmcache' }
    $ccmPaths = @(); if (-not [string]::IsNullOrWhiteSpace($ccmLoc)) { $ccmPaths = @($ccmLoc) }

    # Windows Update download cache - built only from the validated Windows directory.
    $wuPaths = @(); if ($winDirValid) { $wuPaths = @((Join-Path $winDir 'SoftwareDistribution\Download')) }

    # Adaptiva OneSite content cache. Content sits directly under <drive>:\AdaptivaCache (no \Client
    # subfolder). Relocatable via the registry value 'cache.folder' ('na' = use the default), which
    # lives somewhere under the HKLM\SOFTWARE\Adaptiva hive. Only touched when the Adaptiva client is
    # present, so a stray AdaptivaCache folder on a non-Adaptiva box is never cleared.
    $adaptivaPaths = @()
    $adaptivaPresent = ($null -ne (Get-Service -Name 'AdaptivaClient' -ErrorAction SilentlyContinue)) -or (Test-Path 'HKLM:\SOFTWARE\Adaptiva')
    if ($adaptivaPresent) {
        $cacheFolder = $null
        try {
            Get-ChildItem 'HKLM:\SOFTWARE\Adaptiva' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $v = (Get-ItemProperty -LiteralPath $_.PSPath -Name 'cache.folder' -ErrorAction SilentlyContinue).'cache.folder'
                if (-not [string]::IsNullOrWhiteSpace($v)) { $cacheFolder = [string]$v }
            }
        } catch { }
        if ((-not [string]::IsNullOrWhiteSpace($cacheFolder)) -and ($cacheFolder.Trim().ToLower() -ne 'na')) {
            $adaptivaPaths = @($cacheFolder.Trim())
        } else {
            $adaptivaPaths = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { Join-Path $_.RootDirectory.FullName 'AdaptivaCache' })
        }
    }

    # Intune Management Extension (Company Portal / Win32) staging + IMECache. IME normally self-cleans
    # on success but leaves residue on failure/locks. IMECache is under Windows; the Content staging
    # folders are under the IME install (Program Files (x86) on 64-bit, Program Files on 32-bit).
    $intunePaths = @()
    if ($winDirValid) { $intunePaths += (Join-Path $winDir 'IMECache') }
    $imeBases = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    foreach ($base in $imeBases) {
        $imeContent = Join-Path $base 'Microsoft Intune Management Extension\Content'
        if (Test-Path -LiteralPath $imeContent -PathType Container) {
            foreach ($sub in @('Incoming','Staging','Staged')) { $intunePaths += (Join-Path $imeContent $sub) }
        }
    }

    # -----------------------------------------------------------------------------------------------
    # Clear every detected, trusted cache location; defer whatever is locked to the next reboot.
    # -----------------------------------------------------------------------------------------------
    $providers = @(
        @{ Name = 'ConfigMgr (ccmcache)';                          Paths = $ccmPaths }
        @{ Name = 'Windows Update (SoftwareDistribution\Download)'; Paths = $wuPaths }
        @{ Name = 'Adaptiva OneSite (AdaptivaCache)';              Paths = $adaptivaPaths }
        @{ Name = 'Intune Management Extension (IMECache/Content)'; Paths = $intunePaths }
    )

    $anyDeferred = $false
    foreach ($prov in $providers) {
        $cleaned = New-Object System.Collections.Generic.List[string]
        foreach ($p in @($prov.Paths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
            if (& $isSafeCache $p $winDir) {
                $deferred = & $clearContents $p
                if ($deferred) { $anyDeferred = $true }
                if ($deferred) { $cleaned.Add("$p (locked items deferred to reboot)") } else { $cleaned.Add($p) }
            } else {
                & $log "$($prov.Name): skipped '$p' (not found or path could not be trusted)."
            }
        }
        if ($cleaned.Count -gt 0) { & $log "$($prov.Name): cleaned $($cleaned -join '; ')" }
        else { & $log "$($prov.Name): nothing to clean (not installed or no cache present)." }
    }

    if ($anyDeferred) { return 3010 } else { return 0 }
}

function Stop-ServiceSafely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string[]]$ServiceName,

        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 10
    )

    $services = Get-Service -ErrorAction SilentlyContinue -Name $ServiceName
    if (-not $services) { return }

    # Stop-Service can hang indefinitely waiting on the SCM (eg. TrustedInstaller),
    # so request the stop without waiting and enforce our own timeout below.
    $services | Stop-Service -Force:$Force -NoWait -ErrorAction SilentlyContinue

    $waitStart = Get-Date
    $stillRunning = $null
    do {
        Start-Sleep -Seconds 1
        $stillRunning = Get-Service -ErrorAction SilentlyContinue -Name $ServiceName | Where-Object { $_.Status -ne 'Stopped' }
    } while ($stillRunning -and ((Get-Date) - $waitStart).TotalSeconds -lt $TimeoutSeconds)

    foreach ($svc in $stillRunning) {
        $svcStuckMsg = "Service '$($svc.Name)' did not stop within $TimeoutSeconds seconds. Stopping its process forcefully..."
        Write-Warning $svcStuckMsg
        try {
            $svcProcessId = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction Stop).ProcessId
            if ($svcProcessId -and $svcProcessId -ne 0) {
                Stop-Process -Id $svcProcessId -Force -ErrorAction Stop
                Write-Verbose "Process (PID $svcProcessId) backing service '$($svc.Name)' was forcefully stopped."
            }
        } catch {
            Write-Warning "Failed to forcefully stop process for service '$($svc.Name)': $_"
        }
    }
}

function Remove-PathReliable {
    <#
    Deletes a file or directory as completely as possible right now (native, no external binary,
    long-path safe via the \\?\ prefix), then schedules whatever is still locked for deletion at the
    next reboot through the Session Manager's PendingFileRenameOperations - which are processed
    before any service starts, so a handle held right now no longer matters. Returns an object with
    Deleted / Scheduled / Error. Self-contained so it survives being shipped to a remote session.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    $result = [PSCustomObject]@{ Path = $Path; Deleted = $false; Scheduled = $false; Error = $null }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        $result.Deleted = $true
        return $result
    }

    # 0) Safety guard: refuse anything that isn't at least two levels below a drive root (e.g.
    #    C:\Windows\SoftwareDistribution). This is the last line of defence against an empty/garbage
    #    caller value - it stops both the immediate delete AND the reboot-time
    #    PendingFileRenameOperations from ever targeting a drive root or a top-level system folder.
    $checkPath  = if ($Path -like '\\?\*') { $Path.Substring(4) } else { $Path }
    $checkPath  = $checkPath.TrimEnd('\')
    $winDirNorm = ([Environment]::GetFolderPath('Windows')).TrimEnd('\')
    $sys32Norm  = ([Environment]::GetFolderPath('System')).TrimEnd('\')
    if (($checkPath -notmatch '^[A-Za-z]:\\[^\\]+\\[^\\]') -or
        ($winDirNorm -and ($checkPath -ieq $winDirNorm)) -or
        ($sys32Norm  -and ($checkPath -ieq $sys32Norm))) {
        $result.Error = "Refused: '$Path' is not a safe deletion target (drive root, Windows directory, or System32)."
        return $result
    }

    # 1) Best-effort immediate delete - removes everything not locked. The \\?\ prefix covers
    #    >260-char paths, and -LiteralPath avoids the '?' in the prefix being treated as a wildcard.
    $prefixed = if ($Path -like '\\?\*') { $Path } else { "\\?\$Path" }
    Remove-Item -LiteralPath $prefixed -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $Path)) {
        $result.Deleted = $true
        return $result
    }

    # 2) Whatever survived is locked - schedule the remainder for deletion at next boot. Enumeration
    #    works on a locked tree (only deletion is blocked); order deepest-first so each directory is
    #    empty by the time its own entry is processed.
    try {
        $targets = New-Object System.Collections.Generic.List[string]
        @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue) |
            Sort-Object { $_.FullName.Length } -Descending |
            ForEach-Object { $targets.Add($_.FullName) }
        $targets.Add($Path)

        $smKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $pending = New-Object System.Collections.Generic.List[string]
        $current = (Get-ItemProperty -Path $smKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($current) { $pending.AddRange([string[]]$current) }
        foreach ($t in $targets) {
            $pending.Add('\??\' + $t)   # NT-namespace source path to remove
            $pending.Add('')            # empty destination => delete on boot
        }
        Set-ItemProperty -Path $smKey -Name PendingFileRenameOperations -Value $pending.ToArray() -Type MultiString
        $result.Scheduled = $true
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Test-DataStoreHealth {
    <#
    Health gate for the Windows Update DataStore (an ESE/JET database). Returns 'Keep' when
    DataStore.edb is - or can be made - consistent, or 'Wipe' when it can't be trusted. Sequence:
    esentutl /mh (shutdown state) -> /r soft recovery -> /p hard repair -> then a /g integrity pass
    with a /p retry. All repairs run without prompting: a DataStore this damaged has already lost its
    history, so there is nothing left to protect. Requires the update services to be stopped first.
    Self-contained for remote execution.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath,
        [Parameter(Mandatory=$true)]
        [string]$WinDir
    )
    $log  = { param($m) Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - DataStore: $m" -ErrorAction SilentlyContinue }
    if ([string]::IsNullOrWhiteSpace($WinDir) -or -not (Test-Path -LiteralPath $WinDir -PathType Container)) {
        & $log 'Windows directory not provided or invalid - cannot assess DataStore.'; return 'Wipe'
    }
    $dataStoreDir = Join-Path $WinDir 'SoftwareDistribution\DataStore'
    $edb  = Join-Path $dataStoreDir 'DataStore.edb'
    $logs = Join-Path $dataStoreDir 'Logs'

    if (-not (Test-Path -LiteralPath $edb)) { & $log 'DataStore.edb not present - nothing to preserve.'; return 'Wipe' }

    $isClean  = { (( & esentutl.exe /mh "$edb" 2>&1 | Out-String) -match 'State:\s*Clean Shutdown') }
    $isIntact = { & esentutl.exe /g "$edb" 2>&1 | Out-Null; ($LASTEXITCODE -eq 0) }

    # --- shutdown state + logical recovery --------------------------------------------------------
    if (& $isClean) {
        & $log '/mh: Clean Shutdown.'
    } else {
        & $log '/mh: Dirty Shutdown - attempting soft recovery (/r).'
        & esentutl.exe /r edb /l"$logs" /s"$logs" /d"$dataStoreDir" 2>&1 | Out-Null
        if (& $isClean) {
            & $log 'Soft recovery (/r) succeeded.'
        } else {
            & $log 'Still dirty - attempting hard repair (/p).'
            & esentutl.exe /p "$edb" 2>&1 | Out-Null
            if (& $isClean) {
                & $log 'Hard repair (/p) succeeded.'
            } else {
                & $log 'Recovery failed - DataStore will be wiped (skipping /g).'
                return 'Wipe'
            }
        }
    }

    # --- deep integrity ---------------------------------------------------------------------------
    & $log 'Running deep integrity check (/g)...'
    if (& $isIntact) { & $log '/g: integrity OK - keeping DataStore.'; return 'Keep' }
    & $log '/g: integrity failed - attempting hard repair (/p).'
    & esentutl.exe /p "$edb" 2>&1 | Out-Null
    if (& $isIntact) { & $log '/g: OK after repair - keeping DataStore.'; return 'Keep' }
    & $log '/g: still failing after repair - DataStore will be wiped.'
    return 'Wipe'
}

function Invoke-WULegacyRepair {
    <#
    Legacy, invasive Windows Update repair actions kept out of the default path: re-registers the
    update-related COM DLLs, resets the Winsock catalog, and rewrites the security descriptors on the
    wuauserv/bits services. Only reached after an explicit, already-confirmed -IncludeLegacyRepair
    opt-in. The Winsock reset requires a reboot to take effect. Self-contained for remote execution.
    #>
    param([Parameter(Mandatory=$true)][string]$LogPath)
    $log = { param($m) Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - Legacy: $m" -ErrorAction SilentlyContinue }

    $dlls = @(
        'atl.dll','urlmon.dll','mshtml.dll','shdocvw.dll','browseui.dll','jscript.dll','vbscript.dll',
        'scrrun.dll','msxml.dll','msxml3.dll','msxml6.dll','actxprxy.dll','softpub.dll','wintrust.dll',
        'dssenh.dll','rsaenh.dll','gpkcsp.dll','sccbase.dll','slbcsp.dll','cryptdlg.dll','oleaut32.dll',
        'ole32.dll','shell32.dll','initpki.dll','wuapi.dll','wuaueng.dll','wups.dll','wups2.dll',
        'wuwebv.dll','wucltux.dll','muweb.dll','qmgr.dll','qmgrprxy.dll'
    ) | Select-Object -Unique
    foreach ($d in $dlls) {
        Start-Process -FilePath 'regsvr32.exe' -ArgumentList '/s', $d -Wait -NoNewWindow -ErrorAction SilentlyContinue
    }
    & $log "Re-registered update DLLs (missing ones skipped): $($dlls -join ', ')."

    & netsh winsock reset 2>&1 | Out-Null
    & $log 'Reset Winsock catalog (effective after reboot).'

    # Well-known default service security descriptors.
    $sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)'
    foreach ($svc in @('wuauserv','bits')) { & sc.exe sdset $svc $sddl 2>&1 | Out-Null }
    & $log 'Reset security descriptors on wuauserv and bits.'
}

function Invoke-WindowsUpdateCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$updateCleanupLog,

        [Parameter(Mandatory = $true, Position=1)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout = 1.0,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=3)]
        [switch]$VerboseArg,

        # Force-wipe the DataStore even when it is healthy (loses update history).
        [Parameter(Mandatory=$false, Position=4)]
        [bool]$ResetUpdateHistory = $false,

        # Already-confirmed decision to run the legacy repair (confirmation happens in the caller).
        [Parameter(Mandatory=$false, Position=5)]
        [bool]$DoLegacyRepair = $false
    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}
    $log = { param($m) Add-Content -Path $updateCleanupLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - $m" -ErrorAction SilentlyContinue }
    $deferred = $false   # any deletion scheduled for reboot
    $failed   = $false

    Write-Host "Starting Windows Update Cleanup..."

    # Update Medic + Update Orchestrator + Delivery Optimization are stopped FIRST so they can't
    # resurrect the update services we stop next. They are trigger-started, so they are left out of
    # the restart list - Windows starts them again on demand.
    $servicesStop  = @("waasmedicsvc","usosvc","dosvc","wuauserv","bits","cryptsvc","appidsvc","msiserver","trustedinstaller","ccmexec","smstsmgr")
    $servicesStart = @("bits","wuauserv","cryptsvc","appidsvc","msiserver","trustedinstaller","ccmexec","smstsmgr")

    Stop-ServiceSafely -ServiceName $servicesStop -Force
    if ($Null -ne (Get-Process CcmExec  -ea SilentlyContinue)) { Get-Process CcmExec  | Stop-Process -Force -ErrorAction SilentlyContinue }
    if ($Null -ne (Get-Process TSManager -ea SilentlyContinue)) { Get-Process TSManager | Stop-Process -Force -ErrorAction SilentlyContinue }

    # Resolve the Windows directory from the OS (robust against an empty $env:windir) and validate it
    # before ANY path is built from it - an empty base is how a cleanup ends up deleting from a drive
    # root. Remove-PathReliable adds a second guard, but paths are only built here when valid.
    $winDir = [Environment]::GetFolderPath('Windows')
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:windir }
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:SystemRoot }
    $winDirValid = (-not [string]::IsNullOrWhiteSpace($winDir)) -and ($winDir -match '^[A-Za-z]:\\[^\\]') -and (Test-Path -LiteralPath $winDir -PathType Container)
    if (-not $winDirValid) {
        Write-Warning "Windows directory could not be resolved; skipping SoftwareDistribution and catroot2 reset."
        & $log 'CRITICAL: Windows directory could not be resolved; skipping SoftwareDistribution and catroot2 reset.'
        $failed = $true
    }
    $sdPath   = if ($winDirValid) { Join-Path $winDir 'SoftwareDistribution' } else { $null }
    $dsPath   = if ($winDirValid) { Join-Path $winDir 'SoftwareDistribution\DataStore' } else { $null }
    $catroot2 = if ($winDirValid) { Join-Path $winDir 'System32\catroot2' } else { $null }

    # --- SoftwareDistribution: keep update history when the DataStore is healthy, else full wipe ---
    if ($sdPath -and (Test-Path -LiteralPath $sdPath)) {
        $keepDataStore = $false
        if ($ResetUpdateHistory) {
            & $log 'SoftwareDistribution: -ResetUpdateHistory set - wiping the DataStore as well.'
        } else {
            $verdict = Test-DataStoreHealth -LogPath $updateCleanupLog -WinDir $winDir
            $keepDataStore = ($verdict -eq 'Keep') -and (Test-Path -LiteralPath $dsPath)
            & $log "SoftwareDistribution: DataStore verdict = $verdict (keep history: $keepDataStore)."
        }

        if ($keepDataStore) {
            Write-Host "Clearing SoftwareDistribution (keeping update history)..."
            foreach ($child in (Get-ChildItem -LiteralPath $sdPath -Force -ErrorAction SilentlyContinue)) {
                if ($child.Name -ieq 'DataStore') { continue }
                $r = Remove-PathReliable -Path $child.FullName
                if ($r.Scheduled) { $deferred = $true }
                if ($r.Error)     { & $log "SoftwareDistribution\$($child.Name): $($r.Error)" }
            }
        } else {
            Write-Host "Resetting SoftwareDistribution..."
            $r = Remove-PathReliable -Path $sdPath
            if ($r.Scheduled) { $deferred = $true }
            if ($r.Error)     { & $log "SoftwareDistribution: $($r.Error)"; $failed = $true }
        }
    } else {
        & $log 'SoftwareDistribution not present - nothing to reset.'
    }

    # Delivery Optimization jobs (cleared by the built-in troubleshooter's reset too).
    $doJobs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Jobs'
    if (Test-Path -Path $doJobs) { Remove-Item -Path $doJobs -Recurse -Force -ErrorAction SilentlyContinue }

    # --- catroot2: reset outright (cryptsvc rebuilds it; no history to preserve) -------------------
    if ($catroot2 -and (Test-Path -LiteralPath $catroot2)) {
        Write-Host "Resetting catroot2..."
        $r = Remove-PathReliable -Path $catroot2
        if ($r.Scheduled) { $deferred = $true }
        if ($r.Error)     { & $log "catroot2: $($r.Error)"; $failed = $true }
    }

    # --- BITS transfer queue: drop stuck transfers by clearing qmgr* ------------------------------
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if ([string]::IsNullOrWhiteSpace($programData)) { $programData = $env:ALLUSERSPROFILE }
    $bitsQueue = if (-not [string]::IsNullOrWhiteSpace($programData)) { Join-Path $programData 'Microsoft\Network\Downloader' } else { $null }
    if ($bitsQueue -and (Test-Path -LiteralPath $bitsQueue)) {
        Write-Host "Clearing BITS transfer queue..."
        foreach ($q in (Get-ChildItem -LiteralPath $bitsQueue -Filter 'qmgr*' -Force -ErrorAction SilentlyContinue)) {
            $r = Remove-PathReliable -Path $q.FullName
            if ($r.Scheduled) { $deferred = $true }
            if ($r.Error)     { & $log "BITS queue $($q.Name): $($r.Error)" }
        }
    }

    # --- sweep any leftover *.bak folders from older versions of this tool -------------------------
    if ($winDirValid) {
        foreach ($stale in (Get-ChildItem -LiteralPath $winDir -Filter 'SoftwareDistribution.bak*' -Directory -Force -ErrorAction SilentlyContinue)) {
            $r = Remove-PathReliable -Path $stale.FullName
            if ($r.Scheduled) { $deferred = $true }
        }
    }
    if ($catroot2) {
        foreach ($stale in @("$catroot2.bak")) {
            if (Test-Path -LiteralPath $stale) {
                $r = Remove-PathReliable -Path $stale
                if ($r.Scheduled) { $deferred = $true }
            }
        }
    }

    # --- optional legacy component repair (already confirmed by the caller) ------------------------
    if ($DoLegacyRepair) {
        Write-Host "Performing legacy Windows Update component repair..."
        Invoke-WULegacyRepair -LogPath $updateCleanupLog
        $deferred = $true   # Winsock reset needs a reboot to fully apply
    }

    # --- restart services -------------------------------------------------------------------------
    Get-Service -ErrorAction SilentlyContinue $servicesStart | Start-Service -ErrorAction SilentlyContinue

    $summary = if ($failed) { 'Windows Update Cleanup completed with errors - review the log.' }
               elseif ($deferred) { 'Windows Update Cleanup complete; some locked items are scheduled for removal on the next reboot.' }
               else { 'Windows Update Cleanup successful.' }
    Write-Host $summary
    & $log $summary

    if ($failed)   { return 1 }
    if ($deferred) { return 3010 }   # success, restart required
    return 0
}

function Repair-CCM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$localTempPath,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$RepairCCMLog,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=3)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}

    if ($Quiet) {
        $PSCmdlet.MyInvocation.BoundParameters['Verbose']=$false
    }

    function Write-RepairCCMLog {
        param([string]$Message)
        Add-Content -Path $RepairCCMLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - INFO:`r`n`t$Message"
    }

    # Resolve the Windows directory from the OS (robust against an empty $env:windir), with a
    # last-resort default; used only to LOCATE the CCM client and its logs (no deletions here).
    $winDir = [Environment]::GetFolderPath('Windows')
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:windir }
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:SystemRoot }
    if ([string]::IsNullOrWhiteSpace($winDir) -or -not (Test-Path -LiteralPath $winDir -PathType Container)) { $winDir = 'C:\Windows' }

    $ccmrepairexe = Join-Path $winDir 'CCM\ccmrepair.exe'
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"

    # A cache path is only safe to clear if it is absolute, below a drive root, not the Windows
    # directory or System32, and exists (no folder-name requirement - a relocated cache can be
    # custom-named). Guards against an empty/garbage value becoming a root-level delete.
    $isSafeCache = {
        param($p, $win)
        if ([string]::IsNullOrWhiteSpace($p)) { return $false }
        $n = $p.TrimEnd('\')
        if ($n -notmatch '^[A-Za-z]:\\[^\\]+') { return $false }
        $w = $win.TrimEnd('\')
        if (($n -ieq $w) -or ($n -ieq ((Join-Path $w 'System32').TrimEnd('\')))) { return $false }
        return (Test-Path -LiteralPath $n -PathType Container)
    }

    if (-not (Test-Path $ccmrepairexe)) {
        Write-Host "CCMRepair executable not found."
        Write-RepairCCMLog "CCMRepair executable not found at $ccmrepairexe."
        return 1
    }

    try {
        # Restart SCCM Client Service
        if (-not $Quiet) { Write-Host "Restarting SCCM Service..." }
        Write-RepairCCMLog "Restarting SCCM Service..."

        $stopProcessErrors = $null
        Stop-Process -Name SCClient,CcmExec -Force -ErrorAction SilentlyContinue -ErrorVariable stopProcessErrors
        foreach ($stopProcessError in $stopProcessErrors) {
            Write-RepairCCMLog "ERROR: Failed to stop process: $stopProcessError"
        }

        # If the client is not registered in WMI (root\ccm unreachable), re-register its WMI classes
        # by recompiling the client MOFs - a broken WMI store otherwise blocks detection and repair.
        # Done here with CcmExec stopped, before the service is restarted.
        $ccmDir   = Split-Path $ccmrepairexe -Parent
        $ccmWmiOk = try { [bool](Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Client -ErrorAction Stop) } catch { $false }
        if (-not $ccmWmiOk) {
            if (-not $Quiet) { Write-Host "CCM is not registered in WMI; re-registering client MOFs..." }
            Write-RepairCCMLog "CCM not registered in WMI (root\ccm unreachable). Re-registering WMI classes via mofcomp from '$ccmDir'..."
            if (Test-Path -LiteralPath $ccmDir -PathType Container) {
                $mofcomp = Join-Path $winDir 'System32\wbem\mofcomp.exe'
                Get-ChildItem -LiteralPath $ccmDir -Filter '*.mof' -File -ErrorAction SilentlyContinue | ForEach-Object {
                    & $mofcomp $_.FullName 2>&1 | Out-Null
                }
                $ccmWmiOk = try { [bool](Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Client -ErrorAction Stop) } catch { $false }
                Write-RepairCCMLog "WMI re-registration attempted; root\ccm accessible now: $ccmWmiOk."
            } else {
                Write-RepairCCMLog "CCM directory '$ccmDir' not found; cannot re-register WMI classes."
            }
        } else {
            Write-RepairCCMLog "CCM is registered in WMI (root\ccm accessible)."
        }

        $restartServiceErrors = $null
        Restart-Service CcmExec -Force -ErrorAction SilentlyContinue -ErrorVariable restartServiceErrors
        foreach ($restartServiceError in $restartServiceErrors) {
            Write-RepairCCMLog "ERROR: Failed to restart service CcmExec: $restartServiceError"
        }

        Start-Sleep -Seconds 10

        # Run SCCM Client Repair
        if (-not $Quiet) { Write-Host "Starting CCMRepair... This may take a while (~30min)." }
        Write-RepairCCMLog "Starting CCMRepair..."
        # Run with an enforced ceiling so a hung ccmrepair can't block the whole repair run.
        $ccmRepairMaxMinutes = 45
        $ccmProc  = Start-Process -FilePath $ccmrepairexe -PassThru -NoNewWindow -ErrorAction Stop
        $ccmStart = Get-Date
        while (-not $ccmProc.HasExited) {
            Start-Sleep -Seconds 15
            if (((Get-Date) - $ccmStart).TotalMinutes -gt $ccmRepairMaxMinutes) {
                Write-Warning "CCMRepair exceeded $ccmRepairMaxMinutes minutes; terminating it."
                Write-RepairCCMLog "CCMRepair exceeded $ccmRepairMaxMinutes minutes; terminating it."
                try { $ccmProc.Kill(); $ccmProc.WaitForExit(30000) } catch {}
                break
            }
        }
        $ccmProc.WaitForExit()
        Write-RepairCCMLog "CCMRepair process finished."

        # Print Repair Result
        $ccmSetupLogFolder = Join-Path $winDir 'ccmsetup\Logs'
        $ccmsetupLogFile="ccmsetup.log"
        if (Test-Path "$ccmSetupLogFolder\$ccmsetupLogFile") {
            $logLines = Get-Content -Path "$ccmSetupLogFolder\$ccmsetupLogFile" -Tail 3
            foreach ($line in $logLines) {
                if ($line -match "<!\[LOG\[(.*?)\]LOG\]!>") {
                    $logMessage = $matches[1]
                    # only print if logmessage starts with "CcmSetup is exiting with return code"
                    if ($logMessage -like "CcmSetup is exiting with return code*" -or $logMessage -like "CcmSetup failed with error code*") {
                        Write-Host "Log Message: $logMessage"
                        Write-RepairCCMLog "ccmsetup.log result: $logMessage"
                    }
                }
            }
            # copy logfile to localtemppath
            Copy-Item -Path "$ccmSetupLogFolder\$ccmsetupLogFile" -Destination $localTempPath -Force
            if ( Test-Path "$localTempPath\$ccmsetupLogFile") {
                Rename-Item -Path "$localTempPath\$ccmsetupLogFile" -NewName "CCMSetup_$timestamp.log" -Force
                Write-RepairCCMLog "Copied $ccmsetupLogFile to $localTempPath as CCMSetup_$timestamp.log."
            } else {
                Write-Host "CCMSetup log file not found in the expected Temp location."
                Write-RepairCCMLog "CCMSetup log file not found in the expected Temp location ($localTempPath)."
            }
        } else {
            Write-Host "CCMSetup log file not found."
            Write-RepairCCMLog "CCMSetup log file not found at $ccmSetupLogFolder\$ccmsetupLogFile."
        }

        # Clear SCCM Cache
        if (-not $Quiet) { Write-Host "Clearing SCCM Cache..." }
        Write-RepairCCMLog "Clearing SCCM Cache..."
        # ConfigMgr client cache (relocatable). The WMI CacheConfig class can come back empty even on a
        # healthy client, so try WMI -> UIResourceMgr COM (what Software Center reads) -> registry
        # CacheConfig -> default under Windows, and take the first trusted, non-empty path. Cleared only
        # if it passes the safety guard.
        $ccmCachePath = $null
        try { $ccmCachePath = (Get-CimInstance -Namespace 'root\ccm\SoftMgmtAgent' -ClassName CacheConfig -ErrorAction Stop | Select-Object -First 1).Location } catch { $ccmCachePath = $null }
        if ([string]::IsNullOrWhiteSpace($ccmCachePath)) {
            try {
                $ccmUi = New-Object -ComObject UIResource.UIResourceMgr
                $ccmCachePath = $ccmUi.GetCacheInfo().Location
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($ccmUi)
            } catch { }
        }
        if ([string]::IsNullOrWhiteSpace($ccmCachePath)) {
            $ccmCachePath = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\CacheConfig' -Name Location -ErrorAction SilentlyContinue).Location
        }
        if ([string]::IsNullOrWhiteSpace($ccmCachePath)) { $ccmCachePath = Join-Path $winDir 'ccmcache' }
        if (& $isSafeCache $ccmCachePath $winDir) {
            Get-ChildItem -LiteralPath $ccmCachePath -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -LiteralPath "\\?\$($_.FullName)" -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-RepairCCMLog "SCCM Cache cleared ($ccmCachePath)."
        } else {
            Write-RepairCCMLog "SCCM Cache folder not found or its path could not be trusted ('$ccmCachePath'). No need to clear."
        }

        # Trigger SCCM Cycles
        if (-not $Quiet) { Write-Host "Triggering SCCM Client Actions..." }
        Write-RepairCCMLog "Triggering SCCM Client Actions..."
        $SCCMActions = @{
            "Hardware Inventory Cycle"                     = "{00000000-0000-0000-0000-000000000001}"
            "Software Inventory Cycle"                     = "{00000000-0000-0000-0000-000000000002}"
            "Discovery Data Collection Cycle"               = "{00000000-0000-0000-0000-000000000003}"
            "File Collection Cycle"                         = "{00000000-0000-0000-0000-000000000010}"
            "Machine Policy Retrieval & Evaluation Cycle"   = "{00000000-0000-0000-0000-000000000021}"
            "Software Metering Usage Report Cycle"          = "{00000000-0000-0000-0000-000000000031}"
            "Windows Installer Source List Update Cycle"    = "{00000000-0000-0000-0000-000000000032}"
            "Software Updates Scan Cycle"                   = "{00000000-0000-0000-0000-000000000113}"
            "Software Updates Deployment Evaluation Cycle"  = "{00000000-0000-0000-0000-000000000108}"
            "Application Deployment Evaluation Cycle"       = "{00000000-0000-0000-0000-000000000121}"
        }

        foreach ($Action in $SCCMActions.GetEnumerator()) {
            Write-Host "  - $($Action.Key)"
            Write-RepairCCMLog "Triggering: $($Action.Key)..."
            try {
                Invoke-WmiMethod -Namespace "root\ccm" -Class SMS_Client -Name TriggerSchedule -ArgumentList $Action.Value -ErrorAction Stop | Out-Null
                Write-RepairCCMLog "  - OK: $($Action.Key)"
            } catch {
                Write-RepairCCMLog "  - ERROR triggering '$($Action.Key)': $_"
            }
        }
        Write-Host "All SCCM Client Actions triggered."
        Write-RepairCCMLog "All SCCM Client Actions triggered."
    } catch {
        $errorMessage = "Failed to repair CCM: $_"
        Write-Error $errorMessage
        Write-RepairCCMLog "ERROR: $errorMessage"
        return 2
    }
    return 0
}

function Repair-WMIRepository {
    <#
    Non-destructive WMI repository check + repair, run as a Repair-System step (position 6, after SFC
    and before the WMI-dependent Content Cache Cleanup and CCM Repair steps). Verifies the repository
    with 'winmgmt /verifyrepository'; if it reports inconsistent, runs 'winmgmt /salvagerepository'
    and re-verifies. It deliberately never runs '/resetrepository', which is destructive and can break
    third-party WMI providers (SCCM, AV, monitoring). Self-contained so it can be shipped to a remote
    session via ${function:Repair-WMIRepository}. Returns 0 (consistent or successfully salvaged) or
    1 (still inconsistent / could not complete).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$WMIRepairLog,

        [Parameter(Mandatory=$true, Position=1)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$VerboseArg
    )
    if ($VerboseArg) { $PSCmdlet.MyInvocation.BoundParameters['Verbose'] = $true }
    if ($Quiet)      { $PSCmdlet.MyInvocation.BoundParameters['Verbose'] = $false }

    function Write-WMIRepairLog {
        param([string]$Message)
        Add-Content -Path $WMIRepairLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - INFO:`r`n`t$Message"
    }

    # winmgmt sets a NON-ZERO exit code when the repository is inconsistent and 0 when consistent - a
    # locale-independent signal, unlike the (localised) verdict text, so the EXIT CODE drives the
    # decision and the text is only captured for the log. winmgmt.exe is a service stub, though: it
    # does NOT expose its exit code through Start-Process -PassThru (the ExitCode comes back empty even
    # after WaitForExit) - only the call operator ($LASTEXITCODE) or -Wait capture it. Run it in a
    # background job so the call operator gets the real code while Wait-Job still enforces a hard
    # timeout against a wedged WMI service. Returns @{ ExitCode; Output; TimedOut }.
    $invokeWinmgmt = {
        param([string]$WinmgmtArg, [int]$TimeoutSec)
        $winDir = [Environment]::GetFolderPath('Windows')
        if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:SystemRoot }
        if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = 'C:\Windows' }
        $winmgmt = Join-Path $winDir 'System32\wbem\winmgmt.exe'
        $job = Start-Job -ScriptBlock {
            param($exe, $a)
            $o = & $exe $a 2>&1 | Out-String
            [PSCustomObject]@{ Code = $LASTEXITCODE; Out = $o }
        } -ArgumentList $winmgmt, $WinmgmtArg
        if (Wait-Job $job -Timeout $TimeoutSec) {
            $r = Receive-Job $job
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            $code = $r.Code
            if ($null -eq $code) { $code = 0 }
            return @{ ExitCode = [int]$code; Output = ([string]$r.Out).Trim(); TimedOut = $false }
        } else {
            Stop-Job  $job -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return @{ ExitCode = -2; Output = 'winmgmt timed out'; TimedOut = $true }
        }
    }

    try {
        if (-not $Quiet) { Write-Host "Verifying WMI repository (winmgmt /verifyrepository)..." }
        Write-WMIRepairLog "Verifying WMI repository (winmgmt /verifyrepository)..."
        $verify = & $invokeWinmgmt '/verifyrepository' 60
        Write-WMIRepairLog "verifyrepository exit=$($verify.ExitCode); output:`r`n`t$($verify.Output)"

        if ($verify.TimedOut) {
            Write-Warning "WMI /verifyrepository timed out; the WMI service may be wedged."
            Write-WMIRepairLog "verifyrepository timed out. Aborting WMI repair (non-destructive step)."
            return 1
        }

        if ($verify.ExitCode -eq 0) {
            if (-not $Quiet) { Write-Host "WMI repository is consistent; no repair needed." }
            Write-WMIRepairLog "WMI repository is consistent (verify exit 0); no repair needed."
            return 0
        }

        if (-not $Quiet) { Write-Host "WMI repository is inconsistent; salvaging (winmgmt /salvagerepository)..." }
        Write-WMIRepairLog "WMI repository reported inconsistent (verify exit $($verify.ExitCode)). Running winmgmt /salvagerepository..."
        $salvage = & $invokeWinmgmt '/salvagerepository' 300
        Write-WMIRepairLog "salvagerepository exit=$($salvage.ExitCode); output:`r`n`t$($salvage.Output)"
        if ($salvage.TimedOut) {
            Write-Warning "WMI /salvagerepository timed out; the WMI service may be wedged."
            Write-WMIRepairLog "salvagerepository timed out. WMI repository still needs attention."
            return 1
        }

        # The salvage command's own exit code is not conclusive; re-verify to confirm consistency.
        if (-not $Quiet) { Write-Host "Re-verifying WMI repository after salvage..." }
        Write-WMIRepairLog "Re-verifying WMI repository after salvage..."
        $reverify = & $invokeWinmgmt '/verifyrepository' 60
        Write-WMIRepairLog "post-salvage verifyrepository exit=$($reverify.ExitCode); output:`r`n`t$($reverify.Output)"

        if (-not $reverify.TimedOut -and $reverify.ExitCode -eq 0) {
            if (-not $Quiet) { Write-Host "WMI repository salvaged; now consistent." }
            Write-WMIRepairLog "WMI repository salvaged successfully; re-verify reports consistent."
            return 0
        }

        Write-Warning "WMI repository is still inconsistent after salvage."
        Write-WMIRepairLog "WMI repository still inconsistent after salvage. A manual 'winmgmt /resetrepository' may be required; not attempted (non-destructive step)."
        return 1
    } catch {
        $err = "An error occurred during WMI repository repair:`r`n$_"
        Write-Warning $err
        Write-WMIRepairLog "ERROR: $err"
        return 1
    }
}

function Start-ZipFileCreation {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$localTempPath,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$zipFile,

        [Parameter(Mandatory=$true, Position=2)]
        [string]$zipErrorLog,

        [Parameter(Mandatory=$true, Position=3)]
        [switch]$noDism
    )

    try {
        $winDir = [Environment]::GetFolderPath('Windows')
        if ([string]::IsNullOrWhiteSpace($winDir) -or -not (Test-Path -LiteralPath $winDir -PathType Container)) { $winDir = if ($env:windir) { $env:windir } else { 'C:\Windows' } }
        $cbsLog = Join-Path $winDir 'Logs\CBS\CBS.log'
        $dismLog = Join-Path $winDir 'Logs\dism\dism.log'
        $filesToZip = @()

        # Copy CBS.log to the temporary directory if it exists
        if (Test-Path $cbsLog) {
            Copy-Item -Path $cbsLog -Destination $localtempPath
            $filesToZip += (Join-Path -Path $localtempPath -ChildPath "CBS.log")
        }

        # Copy DISM.log to the temporary directory if it exists and the noDism flag is not set
        if (-not $noDism) {
            if (Test-Path $dismLog) {
                Copy-Item -Path $dismLog -Destination $localtempPath
                $filesToZip += (Join-Path -Path $localtempPath -ChildPath "dism.log")
            }
        }

        # Delete existing zip file if it exists
        if (Test-Path $zipFile) {
            Remove-Item -Path $zipFile -Force
        }

        # Create a new zip file
        if ($filesToZip.Count -gt 0) {
            Compress-Archive -Path $filesToZip -DestinationPath $zipFile -Force
        }

        # Remove the copied logs from the temporary directory
        foreach ($file in $filesToZip) {
            if (Test-Path $file) {
                Remove-Item -Path $file -Force
            }
        }
    } catch {
        $errorMessage = "An error occurred while creating the zip file: $_"
        Add-Content -Path $zipErrorLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - ERROR:`r`n$errorMessage"
        Write-Error $message
        return 1
    }
    return 0
}

function Test-DismSfcStepIncomplete {
    <#
    Decides whether a DISM or SFC step that actually RAN failed to truly complete - and therefore
    warrants a reboot re-run. Returns $true when: the step was timed out (-2) or terminated
    externally (-3); its captured log is missing or empty (it never really started); its log lacks
    the tool's completion marker (killed mid-run); or the log reports a reboot-pending / could-not-
    repair condition. The log is read from the path given (a UNC path for a remote target).
    #>
    param(
        [Parameter(Mandatory=$true)] [int]$ResultCode,
        [Parameter(Mandatory=$true)] [string]$LogPath,
        [Parameter(Mandatory=$true)] [ValidateSet('SFC','DISM')] [string]$Kind
    )
    if ($ResultCode -eq -4) { return $false }          # requested-but-not-executed: did not run, fine
    if ($ResultCode -eq -2 -or $ResultCode -eq -3) { return $true }   # timed out / terminated externally

    $content = if (Test-Path -LiteralPath $LogPath) { Get-Content -LiteralPath $LogPath -Raw -ErrorAction SilentlyContinue } else { $null }
    if ([string]::IsNullOrWhiteSpace($content)) { return $true }      # empty / could not start

    if ($content -match 'system repair pending|unable to fix some of them|could not perform the requested operation') { return $true }

    $completed = if ($Kind -eq 'SFC') {
        ($content -match 'Windows Resource Protection') -and
        ($content -match 'did not find any integrity violations|successfully repaired them|found corrupt files|Verification 100% complete')
    } else {
        $content -match 'The operation completed successfully|No component store corruption detected|The component store is repairable|Component Store Cleanup Recommended'
    }
    return (-not $completed)
}

function Invoke-DismSfcRebootRepair {
    <#
    Entry point for the scheduled reboot re-run. Runs at next boot as SYSTEM. Re-runs the full
    conditional DISM + SFC flow (ScanHealth -> RestoreHealth if repairable -> AnalyzeComponentStore ->
    StartComponentCleanup if recommended -> SFC) and writes a CMTrace Repair-System log next to itself.
    FAIL-SAFE: it deletes its own scheduled task FIRST, so it runs at most once even if it hangs or the
    machine reboots mid-repair, and it never schedules another run. Self-contained for bundling into a
    stand-alone script.
    #>
    param(
        [Parameter(Mandatory=$true)]  [string]$RepairFolder,
        [Parameter(Mandatory=$true)]  [string]$TaskName,
        [Parameter(Mandatory=$true)]  [string]$SelfScriptPath,
        [Parameter(Mandatory=$false)] [decimal]$ChangeTimeout = 1.0
    )
    # --- fail-safe: remove our own task before doing anything, so this can only ever run once -------
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop }
    catch { try { & schtasks.exe /Delete /TN $TaskName /F 2>&1 | Out-Null } catch {} }

    New-Folder -FolderPath $RepairFolder
    $pc  = $env:COMPUTERNAME
    $ts  = (Get-Date).ToString('yyyy-MM-dd_HH-mm')
    $masterLog = Join-Path $RepairFolder "SystemRepair_${pc}_${ts}_reboot-rerun.log"

    Write-RepairLog -Message "Repair-System reboot re-run started (DISM/SFC);" -Component "RebootRerun" -LogPath $masterLog -StartLogEntry
    Write-RepairLog -Message "Target: $pc; Reason: a DISM/SFC step did not complete during the previous run; single automatic attempt;" -Component "RebootRerun" -LogPath $masterLog -EndLogEntry

    $scanLog    = Join-Path $RepairFolder "${ts}_DISM_scanHealth.log"
    $restoreLog = Join-Path $RepairFolder "${ts}_DISM_restoreHealth.log"
    $analyzeLog = Join-Path $RepairFolder "${ts}_DISM_analyze-component.log"
    $cleanupLog = Join-Path $RepairFolder "${ts}_DISM_componentStore-cleanup.log"
    $sfcLog     = Join-Path $RepairFolder "${ts}_sfc-scannow.log"

    $scanExit = [int]((Invoke-DISMScan $scanLog $ChangeTimeout $false $false) | Select-Object -Last 1)
    Write-RepairLog -Message "DISM ScanHealth completed; ExitCode=$scanExit;" -Component "DISM-ScanHealth" -LogPath $masterLog
    Start-LogAppendJob -StepLogPath $scanLog -MasterLogPath $masterLog -StepName "DISM-ScanHealth" -Component "DISM-ScanHealth" -Sync

    if ($scanExit -eq 0 -and (Get-DISMScanResult -dismScanLog $scanLog) -eq 1) {
        $restoreExit = [int]((Invoke-DISMRestore $restoreLog $ChangeTimeout $false $false) | Select-Object -Last 1)
        Write-RepairLog -Message "DISM RestoreHealth completed; ExitCode=$restoreExit;" -Component "DISM-RestoreHealth" -LogPath $masterLog
        Start-LogAppendJob -StepLogPath $restoreLog -MasterLogPath $masterLog -StepName "DISM-RestoreHealth" -Component "DISM-RestoreHealth" -Sync
    }

    $analyzeExit = [int]((Invoke-DISMAnalyzeComponentStore $analyzeLog $ChangeTimeout $false $false) | Select-Object -Last 1)
    Write-RepairLog -Message "DISM AnalyzeComponentStore completed; ExitCode=$analyzeExit;" -Component "DISM-Analyze" -LogPath $masterLog
    Start-LogAppendJob -StepLogPath $analyzeLog -MasterLogPath $masterLog -StepName "DISM-AnalyzeComponentStore" -Component "DISM-Analyze" -Sync

    if ($analyzeExit -eq 0 -and (Get-DISMAnalyzeComponentStoreResult -analyzeComponentLog $analyzeLog)) {
        $cleanupExit = [int]((Invoke-DISMComponentStoreCleanup $cleanupLog $ChangeTimeout $false $false) | Select-Object -Last 1)
        Write-RepairLog -Message "DISM ComponentStoreCleanup completed; ExitCode=$cleanupExit;" -Component "DISM-ComponentCleanup" -LogPath $masterLog
        Start-LogAppendJob -StepLogPath $cleanupLog -MasterLogPath $masterLog -StepName "DISM-ComponentStoreCleanup" -Component "DISM-ComponentCleanup" -Sync
    }

    $sfcExit = [int]((Invoke-SFC $sfcLog $ChangeTimeout $false $false) | Select-Object -Last 1)
    Write-RepairLog -Message "SFC /scannow completed; ExitCode=$sfcExit;" -Component "SFC" -LogPath $masterLog
    Start-LogAppendJob -StepLogPath $sfcLog -MasterLogPath $masterLog -StepName "SFC" -Component "SFC" -Sync

    Write-RepairLog -Message "Repair-System reboot re-run completed;" -Component "RebootRerun" -LogPath $masterLog -StartLogEntry
    Write-RepairLog -Message "No further re-runs are scheduled (single attempt by design). Log: $masterLog;" -Component "RebootRerun" -LogPath $masterLog -EndLogEntry

    # self-cleanup: the per-step logs were embedded into the master log above (same as the main
    # Repair-System run, which deletes them after embedding), so remove them and the generated
    # script - only the master reboot-rerun log stays.
    foreach ($stepLog in @($scanLog, $restoreLog, $analyzeLog, $cleanupLog, $sfcLog)) {
        try { if (Test-Path -LiteralPath $stepLog) { Remove-Item -LiteralPath $stepLog -Force -ErrorAction SilentlyContinue } } catch {}
    }
    try { if (Test-Path -LiteralPath $SelfScriptPath) { Remove-Item -LiteralPath $SelfScriptPath -Force -ErrorAction SilentlyContinue } } catch {}
}

function Register-RebootRepairTask {
    <#
    Writes a self-contained re-run script to the target (bundling the DISM/SFC workers plus
    Invoke-DismSfcRebootRepair) and registers a one-shot AtStartup SYSTEM scheduled task that runs it
    after the next reboot. For a remote target the script is written and the task registered ON the
    target via Invoke-Command; the re-run then runs purely locally at boot. Returns the paths used, or
    $null on failure (registration failure is never fatal to the calling run).
    #>
    param(
        [Parameter(Mandatory=$true)]  [decimal]$ChangeTimeout,
        [Parameter(Mandatory=$false)] [hashtable]$InvokeParams = @{},
        [Parameter(Mandatory=$false)] [switch]$Remote
    )
    $repairFolder = 'C:\_IT-RebootRepair'
    $scriptPath   = Join-Path $repairFolder 'RepairSystem-RebootRerun.ps1'
    $taskName     = 'RepairSystem-RebootRerun'

    # Bundle the worker functions + the orchestrator into one script, then append the entry call.
    $bundle = @('New-Folder','Write-RepairLog','Start-LogAppendJob','Write-StepLogEntry',
                'Get-RepairSystemProcessResult','Invoke-DISMScan','Get-DISMScanResult','Invoke-DISMRestore',
                'Invoke-DISMAnalyzeComponentStore','Get-DISMAnalyzeComponentStoreResult',
                'Invoke-DISMComponentStoreCleanup','Invoke-SFC','Invoke-DismSfcRebootRepair')
    $scriptText = "# Auto-generated by Repair-System; single-shot DISM/SFC reboot re-run. Safe to delete.`r`n"
    foreach ($n in $bundle) { $scriptText += "function $n {`r`n" + (Get-Item "function:$n").ScriptBlock.ToString() + "`r`n}`r`n" }
    $scriptText += "`r`nInvoke-DismSfcRebootRepair -RepairFolder '$repairFolder' -TaskName '$taskName' -SelfScriptPath '$scriptPath' -ChangeTimeout $ChangeTimeout`r`n"

    $register = {
        param($repairFolder, $scriptPath, $taskName, $scriptText)
        if (-not (Test-Path -LiteralPath $repairFolder)) { New-Item -ItemType Directory -Path $repairFolder -Force | Out-Null }
        Set-Content -LiteralPath $scriptPath -Value $scriptText -Encoding UTF8 -Force
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        $trigger   = New-ScheduledTaskTrigger -AtStartup
        $trigger.Delay = 'PT2M'   # let the servicing stack settle before DISM runs
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 3)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    }

    try {
        if ($Remote) {
            Invoke-Command @InvokeParams -ScriptBlock $register -ArgumentList $repairFolder, $scriptPath, $taskName, $scriptText -ErrorAction Stop
        } else {
            & $register $repairFolder $scriptPath $taskName $scriptText
        }
        return [PSCustomObject]@{ Folder = $repairFolder; Script = $scriptPath; Task = $taskName }
    } catch {
        Write-Warning "Could not register the reboot re-run task on the target: $_"
        return $null
    }
}

function Repair-RemoteSystem {
    [CmdletBinding()]
    param (
        # Define parameters if needed
    )

    # Throw a specific error indicating that the cmdlet is deprecated
    throw "> This CmdLet is deprecated. Please use 'Repair-System' instead.`r`n "
}

function Repair-LocalSystem {
    [CmdletBinding()]
    param (
        # Define parameters if needed
    )

    # Throw a specific error indicating that the cmdlet is deprecated
    throw "> This CmdLet is deprecated. Please use 'Repair-System' instead.`r`n "
}

function Repair-System {
    <#
    .SYNOPSIS
    Repairs the system by running SFC and DISM commands locally or on a remote computer.

    .DESCRIPTION
    This function performs a series of system repair commands locally or on a remote computer. It first checks the availability of the remote machine by pinging it.
    Then, depending on the options specified, it executes `sfc /scannow` and  `DISM` commands to scan and repair the Windows image.

    Optional steps clean up the Windows Component Store, reset the Windows Update client (history-preserving), clear the content/download caches of the installed software-distribution systems (ConfigMgr / Adaptiva / Intune / Windows Update), and repair the ConfigMgr client. If a DISM/SFC step does not complete, a one-shot repair is scheduled to re-run the full DISM + SFC pass once after the next reboot (unless `-NoRebootRepair` is specified).

    Progress and status are printed to the local console. Step outputs are written to temporary log files, then consolidated into a single master repair log (`SystemRepair_<PC>_<date>.log`) in CMTrace-compatible format; individual step log files are removed after embedding. On remote runs, the master log and a CBS/DISM system log archive are transferred to the local machine.

    .PARAMETER ComputerName
    The hostname or IP address of the remote computer where the system repair will be performed.

    .PARAMETER remoteShareDrive
    The ShareDrive of the Remote-Device on which Windows is installed. If non is provided, Default-Value 'C$' will be used
    The Command `Repair-System -ComputerName SomeDevice -remoteShareDrive D$` will result in Network-Path `\\SomeDevice\D$\`

    .PARAMETER noSfc
    When specified, the `SCF /SCANNOW` command is skipped.

    .PARAMETER noDism
    When specified, the `DISM` commands are skipped.

    .PARAMETER Quiet
    Suppresses console output on the local machine. The output is logged to files on the remote machine instead.

    .PARAMETER IncludeComponentCleanup
    When specified, performs `DISM /Online /Cleanup-Image /AnalyzeComponentStore` and, if recommended, performs `DISM /Online /Cleanup-Image /StartComponentCleanup`.

    .PARAMETER ContentCacheCleanup
    When specified, clears the content/download caches of every software-distribution system detected on
    the device: ConfigMgr (ccmcache), Windows Update (SoftwareDistribution\Download), Adaptiva OneSite
    (<drive>:\AdaptivaCache) and the Intune Management Extension (IMECache + Content staging). Each cache
    location is auto-detected; systems that are not installed are skipped. Items locked by a running
    agent are cleared best-effort now and the remainder is scheduled for removal on the next reboot, in
    which case the step reports 3010 ("restart required"). The alias -sccmCleanup is accepted for
    backwards compatibility (it now performs this broader cleanup).

    .PARAMETER WindowsUpdateCleanup
    When specified, resets the Windows Update client: stops the update services, clears the SoftwareDistribution
    folder (keeping the update history / DataStore when it is healthy - see -ResetUpdateHistory), resets catroot2,
    and clears the BITS transfer queue. Anything held open by a process is scheduled for removal on the next reboot.
    If any item is deferred to reboot, the step reports code 3010 ("Success (restart required)").

    .PARAMETER ChangeTimeout
    Multiplicator
    Use decimal value to change when DISM/SFC and Windows Update Diagnostics will timeout (value `-ChangeTimeout 2` will double the time, `-ChangeTimeout 0.5` will half it).
    Range = 0.25 - 10.0

    .PARAMETER KeepLogs
    When specified, individual step log files are retained alongside the master log instead of being deleted after their content is embedded. On remote runs, step logs remain on the remote device and the full set (step logs + master log) is transferred to the Client.

    .PARAMETER init
    When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
    When specified, no other Parameter will be executed (other provided Parameters will be ignored). This will retun 0 if the Config-File was created successfully, or already exists.

    Configuration-File Template:
    ```
    ShareDrive=C$                                       # ShareDrive-Letter of the Remote-Device on which Windows is installed
    TempDirName=_IT-temp                                # Name of the temporary Directory on the Remote-Device
    FinalDestinationPath=C:\remote-Files                # Path where the Logs and Files will be copied to on the executing Client
    ```

    .PARAMETER Credentials
    Specifies the user credentials to use for the remote Connection to Remote Computers.

    If Get-Credential is used, to obtain the credentials interactively, and it throws an error without prompting, please use Get-CredentialObject from the CredentialHandler Module of the Module-Suite (https://github.com/halatsWol/PowerShell-Tools)

    .PARAMETER RepairCCM
    When specified, the CCMRepair.exe will be executed. This will also copy the ccmsetup.log to the local Temp-Path.

    .PARAMETER RepairWMI
    When specified, the WMI repository is checked with "winmgmt /verifyrepository" and, if it reports inconsistent,
    repaired non-destructively with "winmgmt /salvagerepository" followed by a re-verify. It never runs the destructive
    "/resetrepository". This step runs before the WMI-dependent Content Cache Cleanup and CCM Repair steps so those act
    on a repaired store.

    .PARAMETER ResetUpdateHistory
    Only meaningful with -WindowsUpdateCleanup. By default the Windows Update history (the DataStore database) is
    kept when it passes an integrity check and only rebuilt if it is corrupt. When -ResetUpdateHistory is specified,
    the DataStore is always wiped and rebuilt, discarding the update history.

    .PARAMETER IncludeLegacyRepair
    Only meaningful with -WindowsUpdateCleanup. Additionally performs invasive legacy repairs: re-registering the
    Windows Update COM DLLs, resetting the Winsock catalog, and rewriting the security descriptors of the
    wuauserv/bits services. These can affect networking and require a reboot. In an interactive session this prompts
    for confirmation; combine with -Force to skip the prompt (required to run it in a non-interactive session).

    .PARAMETER Force
    Skips the confirmation prompt for -IncludeLegacyRepair (and is required to run legacy repair non-interactively).

    .PARAMETER NoRebootRepair
    By default, if any DISM/SFC step does not complete during the run (it timed out, was terminated, produced an
    empty/incomplete log, or reported a reboot-pending/could-not-repair state), a one-shot scheduled task is
    registered on the target that re-runs the full DISM + SFC pass once after the next reboot and writes its own
    Repair-System log under C:\_IT-RebootRepair. The task deletes itself before running (single attempt, no loop).
    Specify -NoRebootRepair to disable this automatic reboot re-run.

    .PARAMETER AnalyzeExitCode
    Decodes a previously produced Repair-System exit code (see Exit-Codes in .NOTES) into a human-readable, per-step breakdown.
    Cannot be combined with any other parameter, and never performs any repair actions (no SFC/DISM/SCCM/etc. is executed).

    .OUTPUTS
    RepairSystem.Result
    A PSCustomObject with TypeName 'RepairSystem.Result'. Suppressed from default display; access via assignment,
    inline property access, or $global:RepairSystemResult after the run.

        ExitCode         [int]    Conventional exit code: 0 = success, 1 = partial/step failure, 2 = fatal/startup error.
        DetailedExitCode [string] Full per-step lossless hex string (e.g. "0000000000").
        ComputerName     [string] Target device the repair ran on.
        LogPath          [string] Full path to the master repair log. $null for early-exit (pre-log) failures.
        Actions          [PSCustomObject] Which steps were requested: DISMScanHealth, DISMRestoreHealth,
                                          DISMAnalyzeComponentStore, DISMComponentCleanup, SFC, SCCMCleanup,
                                          WindowsUpdateCleanup, RepairCCM — each a [bool]. (SCCMCleanup
                                          reflects the -ContentCacheCleanup step; the property name is kept
                                          for backwards compatibility.)
        Analysis         [PSCustomObject[]] Per-step breakdown: Position, Label, Value, Status.
                                            Status is one of: Success, Not requested, Skipped (not needed),
                                            Skipped (connection lost), Success (restart required), Timed out,
                                            Terminated externally, or the step's known-code description for
                                            other failures.

    Not emitted by -AnalyzeExitCode (that mode writes to the host and returns nothing).

    .EXAMPLE
    Repair-System -AnalyzeExitCode "0000000000"

    Decodes the given exit code ("0000000000" = every step succeeded/was not requested) and prints a description of each step's result. Runs standalone; performs no repair actions.

    .EXAMPLE
    $r = Repair-System -noSfc
    $r.Actions
    $r.Analysis | Format-Table

    Assigns the result object and inspects which steps were requested and their per-step status.

    .EXAMPLE
    (Repair-System -ComputerName SomeDevice).DetailedExitCode

    Runs a remote repair and retrieves the detailed exit code inline.

    .EXAMPLE
    Repair-System
    $RepairSystemResult.Analysis | Where-Object { $_.Status -ne 'Not requested' } | Format-Table

    Accesses the last result via the module global after running without assignment.

    .EXAMPLE
    Repair-System -ComputerName <remote-device>

    Runs the `sfc /scannow` and `DISM` commands on the remote computer `<remote-device>`. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-System

    Runs the `sfc /scannow` and `DISM` commands on the local computer. Minimal Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-System -ComputerName SomeDevice -remoteShareDrive D$

    Will connect to `\\SomeDevice\D$\`. This can be used if the SystemRoot (installation of Windows) is either not on Drive C:,
    or if the Share-Drive has a different Name (eg access via `\\SomeDevice\C\` instead of C$)

    .EXAMPLE
    Repair-System <remote-device> -noDism

    Runs only the `sfc /scannow` command on the remote computer `<remote-device>`. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-System -ComputerName <remote-device> -Quiet

    Runs the `sfc /scannow` and `DISM` commands on the remote computer `<remote-device>`. Outputs are logged to files but not shown on the console.

    .EXAMPLE
    Repair-System <remote-device> -IncludeComponentCleanup

    Analyses the Component Store and removes old Data which is not required anymore. Cannot be used with '-noDism'

    .EXAMPLE
    Repair-System -ComputerName <remote-device> -WindowsUpdateCleanup

    Resets the Windows Update client on `<remote-device>`: stops the update services, clears SoftwareDistribution (keeping the update history when the DataStore is healthy), resets catroot2, and clears the BITS transfer queue. Items locked by a running process are deferred to the next reboot, in which case the step reports 3010. Add `-ResetUpdateHistory` to also discard the history, or `-IncludeLegacyRepair -Force` to run the invasive legacy repairs non-interactively.

    .EXAMPLE
    Repair-System -ComputerName <remote-device> -ContentCacheCleanup

    Clears the content/download caches of every distribution system detected on `<remote-device>` - ConfigMgr (ccmcache), Windows Update (SoftwareDistribution\Download), Adaptiva OneSite (<drive>:\AdaptivaCache) and the Intune Management Extension (IMECache + Content staging). Absent systems are skipped, and locked items are deferred to the next reboot (the step then reports 3010). The alias `-sccmCleanup` behaves identically.

    .LINK
    https://github.com/halatsWol/PowerShell-Tools

    .LINK
	https://www.kMarflow.com/

    .NOTES
    This script is provided as-is and is not supported by Microsoft. Use it at your own risk.
    WinRM must be enabled and configured on the remote computer for this script to work. Using IP addresses may require additional configuration.
    Using this script may require administrative privileges on the remote computer.
    In a Domain, powershell can be executed locally as the user wich has the necessary permissions on the remote computer.

    WARNING:
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT PERMISSION OR AUTHORIZATION.
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT UNDERSTANDING THE CONSEQUENCES.
    NEVER RUN SCRIPTS FROM UNTRUSTED SOURCES WITHOUT REVIEWING AND UNDERSTANDING THE CODE.
    DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING. IT MAY CAUSE DATA LOSS OR SYSTEM INSTABILITY.


    Exit-Codes:
    $global:LASTEXITCODE - the value scripts/CI/batch should branch on - is a conventional
    single digit:
        0 = full success (every step succeeded or was not requested)
        1 = the run completed (possibly only partially, e.g. a mid-run connection loss) but
            one or more steps reported a problem
        2 = a startup/fatal error meant no repair steps ran at all (bad parameters, target
            unreachable, WinRM failure, not elevated, config error, conflicting parameters)

    The full, lossless detail behind that digit is printed to the console as "Detailed Exit Code:
    <code>" and returned as the DetailedExitCode property of the result object. The last result
    object is also stored in $global:RepairSystemResult for post-run access without assignment.

    The detailed code is made up of one field per step, concatenated in a fixed position order
    (no reordering/sorting, no delimiters). Each field starts with a single hex digit (0-8)
    giving the number of hex digits that follow ('0' alone means the step's value is 0); the
    digits that follow (if any) are the step's real return value (DISM/SFC's own exit code, or
    the step's own small result code) rendered as hex, so no detail is lost. Because the length
    prefix marks where each field ends, no separators are needed and a fully successful run
    collapses to "0000000000" (ten '0' characters) instead of a long fixed-width string. Run
    `Repair-System -AnalyzeExitCode <code>` to get a human-readable breakdown of a previously
    produced detailed code; this mode never performs any repair actions and cannot be combined
    with any other parameter.

    The step positions follow the order the steps actually run in (DISM before SFC):
    Position 0: Startup (parameter/network/WinRM/elevation/config errors), or a connection-lost code if the remote connection was lost mid-execution
    Position 1: DISM ScanHealth
    Position 2: DISM RestoreHealth
    Position 3: DISM AnalyzeComponentStore
    Position 4: DISM StartComponentCleanup
    Position 5: SFC /scannow
    Position 6: WMI Repository Repair
    Position 7: Content Cache Cleanup (ConfigMgr / Adaptiva / Intune / Windows Update)
    Position 8: Windows Update Cleanup
    Position 9: Repair CCM
    Position 10: Zip CBS/DISM Logs

    For the DISM and SFC steps (Positions 1-5) specifically, a raw process exit code is only
    trusted if it is either a clean success or the process had a fair chance to run. A clean exit
    (code 0) is always trusted, however quickly it arrives - some steps (e.g. AnalyzeComponentStore)
    legitimately finish in seconds. If Repair-System itself killed the process for exceeding its
    time budget, that field instead reads -2 (a dedicated out-of-band "timed out" value, distinct
    from any real DISM/SFC exit code). If the process exited on its own with a NON-ZERO code in
    well under 30 seconds - implausibly fast for a real scan/repair to have failed legitimately -
    that field instead reads -3 ("likely terminated externally, e.g. via Task Manager - its own
    exit code could not be trusted").

    Except for Position 0, the detailed exit code field is the return value of the corresponding
    command. If a step was requested but deliberately did not run because it was not necessary
    (RestoreHealth when ScanHealth finds no corruption; StartComponentCleanup when
    AnalyzeComponentStore recommends none) or because a prerequisite step did not complete, the
    field reads -4 ("requested but not executed" - reported as "Skipped (not needed)", not counted
    as a failure). If a step was not requested at all, or was not reached because the remote
    connection was lost, the field is 0. Only a startup failure causes an immediate exit; all
    other step failures are recorded but do not interrupt the remaining steps.

    These three out-of-band values (-2, -3, -4) are shown as their small signed numbers in the
    result object's Analysis and in -AnalyzeExitCode output; inside the packed DetailedExitCode
    string they are the 32-bit two's-complement hex fields FFFFFFFE, FFFFFFFD and FFFFFFFC.

    Author: Wolfram Halatschek
    E-Mail: dev@kMarflow.com
    Date: 2026-08-15
    #>

    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true, ParameterSetName='Default')]
        [string]$ComputerName,

        [Parameter(Mandatory=$false,Position=0, ParameterSetName='Default')]
        [string]$remoteShareDrive,

        [Parameter(Mandatory = $false, ParameterSetName='Default')]
        [switch]$noSfc,

        [Parameter(Mandatory = $false, ParameterSetName='Default')]
        [switch]$noDism,

        [Parameter(Mandatory = $false, ParameterSetName='Default')]
        [switch]$Quiet,

        [Parameter(Mandatory = $false, ParameterSetName='Default')]
        [switch]$IncludeComponentCleanup,

        [Parameter(Mandatory = $false, ParameterSetName='Default')]
        [switch]$WindowsUpdateCleanup,

        [Parameter(Mandatory = $false, ParameterSetName='Default')]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout = 1.0,

        [Parameter(Mandatory = $false, ParameterSetName='Default')]
        [Alias('sccmCleanup')]
        [switch]$ContentCacheCleanup,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$KeepLogs,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$init,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [PSCredential] $Credentials,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$RepairCCM,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$RepairWMI,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$ResetUpdateHistory,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$IncludeLegacyRepair,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$Force,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$NoRebootRepair,

        [Parameter(Mandatory=$true, ParameterSetName='Analyze')]
        [string]$AnalyzeExitCode

    )

    if ($PSCmdlet.ParameterSetName -eq 'Analyze') {
        Write-RepairSystemExitCodeAnalysis -Code $AnalyzeExitCode
        return
    }

    [int[]]$ExitCode = 0,0,0,0,0,0,0,0,0,0,0 #Startup, DISM Scan, DISM Restore, Analyze Component, Component Cleanup, SFC, WMI Repository Repair, Content Cache Cleanup, Windows Update Cleanup, Repair CCM, Zip CBS/DISM Logs

    $ComputerName = $ComputerName.Trim()
    $targetDevice   = $env:COMPUTERNAME
    $requestedSteps = @(
        $true,                                        # [0] Startup - always
        (-not $noDism),                               # [1] DISM ScanHealth
        (-not $noDism),                               # [2] DISM RestoreHealth
        (-not $noDism),                               # [3] DISM AnalyzeComponentStore
        (-not $noDism -and $IncludeComponentCleanup), # [4] DISM ComponentCleanup
        (-not $noSfc),                                # [5] SFC
        $RepairWMI.IsPresent,                         # [6] WMI Repository Repair
        $ContentCacheCleanup.IsPresent,               # [7] Content Cache Cleanup
        $WindowsUpdateCleanup.IsPresent,              # [8] WU Cleanup
        $RepairCCM.IsPresent,                         # [9] CCM Repair
        (-not $noSfc -or -not $noDism)                # [10] Zip Logs
    )
    if ($ComputerName -and ($ComputerName -notmatch '^(([a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$')) {
        Write-Error "Invalid ComputerName format: '$ComputerName'.`r`nValid Windows hostnames must:
        - Only contain letters (A-Z, a-z), numbers (0-9), hyphens (-), underscores (_), and dots (.)
        - Not contain spaces or special characters
        - Not start or end with a hyphen or dot
        - Each label (separated by dots) must be 1-63 characters
        - The full name must be 1-255 characters
        - Alternatively, a valid IPv4 address (e.g. 192.168.1.1) is allowed."
        $ExitCode[0]=1
        Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
        return
    }

    $confFile="$PSScriptRoot\RepairSystem.conf"
    $tempFolder="_IT-temp"
    $FinalDestinationPath = "$env:SystemDrive\remote-Files"
    $ShareDrive="C$"
    if($init){
        # create in Module-Path a ReparSystem.conf file
        if(-not (Test-Path $confFile)){
            try {
                New-Item -Path $confFile -ItemType File -Force
                Add-Content -Path $confFile -Value "ShareDrive=$ShareDrive"
                Add-Content -Path $confFile -Value "TempDirName=$TempDirName"
                Add-Content -Path $confFile -Value "FinalDestinationPath=$FinalDestinationPath"
            } catch {
                Write-Error "Error creating Config-File. Please check if the Module-Path is writable`r`n `r`n$_"
                $global:LASTEXITCODE = 1
                return
            }
        } else {
            Write-Warning "Config-File already exists. If you want to reset the Config-File, please delete it manually"
        }
        $global:LASTEXITCODE = 0
        return
    }

    $remote=$false
    $remoteConnectionLost=$false
    $shareDrivePath=""
    $remoteTempPath=""
    # check if verbose param is set in command execution
    $VerboseOption = if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) { $true } else { $false }
    $invokeParams =@{}

    if($ComputerName -ne "" -and $ComputerName -ne $env:COMPUTERNAME -and $ComputerName -ne "localhost"){
        $remote=$true
        $targetDevice = $ComputerName
    }

    if (-not $remote) {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ( -not $isElevated ) {
            $("") ; Write-Warning "`r`nThis script must be run with administrative privileges. Please restart the script in an elevated PowerShell session.`r`n"
            Pause ; $("")
            $ExitCode[0]=5
            Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
            return
        }
    } else {
        $invokeParams.ComputerName = $ComputerName
        if ($Credentials) {
            $invokeParams.Credential = $Credentials
        }
    }

    # Validation to ensure -IncludeComponentCleanup is not used with -noDism
    if ($noDism -and $IncludeComponentCleanup) {
        Write-Error "The parameter -IncludeComponentCleanup cannot be used in combination with -noDism."
        $ExitCode[0]=7
        Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
        return
    }

    # Resolve the legacy-repair opt-in once, up front - so we never prompt in the middle of a long
    # run, and so a remote target is authorized here on the local console. -Force skips the prompt;
    # a non-interactive session without -Force skips legacy repair rather than blocking on a prompt.
    $legacyRepairConfirmed = $false
    if ($WindowsUpdateCleanup -and $IncludeLegacyRepair) {
        if ($Force) {
            $legacyRepairConfirmed = $true
        } elseif ([Environment]::UserInteractive) {
            Write-Warning "-IncludeLegacyRepair runs invasive legacy repairs on ${targetDevice}: re-registering Windows Update DLLs, resetting the Winsock catalog, and rewriting the wuauserv/bits service security descriptors. These can affect networking and require a reboot."
            $answer = Read-Host "Type 'YES' to proceed with legacy repair (anything else skips it)"
            $legacyRepairConfirmed = ($answer -eq 'YES')
            if (-not $legacyRepairConfirmed) { Write-Warning "Legacy Windows Update repair skipped." }
        } else {
            Write-Warning "-IncludeLegacyRepair requires -Force in a non-interactive session; skipping legacy repair."
        }
    }

    # Set up paths and file names for logging
    $currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")


    if (Test-Path $confFile) {
        $confData = Get-Content -Path $confFile
        foreach ($line in $confData) {
            if ($line -match 'ShareDrive=(.*)') {
                $shareDrive = $Matches[1]
            } elseif ($line -match 'TempDirName=(.*)') {
                $tempFolder = $Matches[1]
            } elseif ($line -match 'FinalDestinationPath=(.*)') {
                $finalDestinationPath = $Matches[1]
            } else {
                Write-Warning "Invalid line in config file $confFile : `t$line`r`n`tAllowed Variables: ShareDrive, TempDirName, FinalDestinationPath"
                $ExitCode[0]=6
                Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
                return
            }
        }
    }

    if($remote){
        # Ping the remote computer to check availability. -Quiet returns $true/$false for a normal
        # unreachable host, but name-resolution failures still throw with -ErrorAction Stop - catch
        # those and treat them as unreachable rather than letting the exception escape.
        try {
            $pingResult = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction Stop
        } catch {
            $pingResult = $false
        }

        if (-not $pingResult) {
            Write-Error "Unable to reach $ComputerName. Please check the Device-Name or the network connection to the remote Device."
            $ExitCode[0]=2
            Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
            return
        }

        if($remoteShareDrive -ne ""){
            $shareDrive=$remoteShareDrive
        }
        $shareDrivePath="\\$ComputerName\$shareDrive"
        $remoteTempPath = "$shareDrivePath\$tempFolder"
    }


    $localTempPath="C:\$tempFolder"
    $FinalDestinationPath="$FinalDestinationPath\$ComputerName"
    $dismScanLog = ""
    $dismRestoreLog = ""
    $analyzeComponentLog = ""
    $componentCleanupLog = ""

    New-Folder -FolderPath $finalDestinationPath

    if($remote){
        # Check if the remote computer is reachable via WinRM
        $winRMexit = ""
        try{
            Invoke-Command @invokeParams -ScriptBlock {
                Write-Host "Connected to $env:COMPUTERNAME"
            } -Verbose:$VerboseOption -ErrorAction Stop
        } catch {
            $winRMexit = "Unable to establish a remote PowerShell session to $ComputerName. Please check the WinRM configuration.`r`n `r`n `r`nError: $_"
            Write-Error $winRMexit
            Add-Content -Path "$finalDestinationPath\remoteConnectError_$currentDateTime.log" -Value "[$currentDateTime] - ERROR:`r`n$winRMexit"
            $ExitCode[0]=3
            Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
            return
        }
    }

    if ($remote) {
        Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:New-Folder} -ArgumentList @($localTempPath) -ComputerName $ComputerName -StepName 'Creating remote temp folder' -ConnectionLost ([ref]$remoteConnectionLost) | Out-Null
    } else {
        New-Folder -FolderPath $localTempPath
    }

    $masterLogPath = if ($remote) {
        "$finalDestinationPath\SystemRepair_${ComputerName}_${currentDateTime}.log"
    } else {
        "$localTempPath\SystemRepair_$($env:COMPUTERNAME)_${currentDateTime}.log"
    }
    $logAppendJobs = [System.Collections.Generic.List[System.Management.Automation.Job]]::new()
    $stepLogPaths  = [System.Collections.Generic.List[string]]::new()

    # Deletes a step log immediately after it is no longer needed.
    # Local+KeepLogs=false  → remove local file.
    # Remote+KeepLogs=false → remove from remote via UNC.
    # KeepLogs=true         → skip now; remote copies are removed from $finalDestinationPath at the end.
    $removeStepLog = {
        param([string]$Path)
        if ([string]::IsNullOrEmpty($Path) -or $KeepLogs) { return }
        Remove-Item -Path $(if ($remote) { "$remoteTempPath\$(Split-Path $Path -Leaf)" } else { $Path }) `
                    -Force -ErrorAction SilentlyContinue
    }

    Write-RepairLog -Message "Repair-System started;" -Component "RepairSystem" -LogPath $masterLogPath -StartLogEntry
    Write-RepairLog -Message "Target: $(if ($remote) { $ComputerName } else { $env:COMPUTERNAME }); Remote: $remote;" -Component "RepairSystem" -LogPath $masterLogPath -AddLogEntryData
    Write-RepairLog -Message "SFC: $(if ($noSfc) { 'skip' } else { 'run' }); DISM: $(if ($noDism) { 'skip' } else { 'run' }); ComponentCleanup: $IncludeComponentCleanup; RepairWMI: $RepairWMI; ContentCacheCleanup: $ContentCacheCleanup; WUCleanup: $WindowsUpdateCleanup; RepairCCM: $RepairCCM; Timeout: ${ChangeTimeout}x;" -Component "RepairSystem" -LogPath $masterLogPath -EndLogEntry

    # Tracks whether any DISM/SFC step that ran did not truly complete (timed out, killed, empty or
    # incomplete log, or reboot-pending) - which triggers the one-shot reboot re-run below.
    $needsRebootRerun = $false
    $rebootRerunScheduled = $false

    if (-not $noDism -and -not $remoteConnectionLost) {
        $dismScanLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_DISM_scanHealth.log"
        $dismScanResult=0
        Write-RepairLog -Message "Starting DISM ScanHealth..." -Component "DISM-ScanHealth" -LogPath $masterLogPath
        if($remote){
            $dismScanBlock = New-RemoteFunctionScriptBlock -FunctionName @('Write-StepLogEntry', 'Get-RepairSystemProcessResult', 'Invoke-DISMScan') -EntryPoint 'Invoke-DISMScan'
            $dismScanResult = Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock $dismScanBlock -ArgumentList @($dismScanLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'DISM ScanHealth' -ConnectionLost ([ref]$remoteConnectionLost)
        } else { $dismScanResult=Invoke-DISMScan $dismScanLog $ChangeTimeout $Quiet $VerboseOption}

        if (-not $remoteConnectionLost) {
            $dismScanResult = [int]($dismScanResult | Select-Object -Last 1)
            $ExitCode[1]=$dismScanResult
            $dismScanResultString = $dismScanResult.ToString()
        } else { $ExitCode[1]=5 }
        Write-RepairLog -Message "DISM ScanHealth completed; ExitCode=$($ExitCode[1]);" -Component "DISM-ScanHealth" -LogPath $masterLogPath
        Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $dismScanLog -Leaf)" } else { $dismScanLog }) -MasterLogPath $masterLogPath -StepName "DISM-ScanHealth" -Component "DISM-ScanHealth" -Sync
        $needsRebootRerun = $needsRebootRerun -or (Test-DismSfcStepIncomplete -ResultCode $ExitCode[1] -LogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $dismScanLog -Leaf)" } else { $dismScanLog }) -Kind 'DISM')

        if (-not $remoteConnectionLost) {

            $dismRestoreLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_DISM_restoreHealth.log"
            if ($dismScanResultString -eq 0) {
                $dismScanExit=1
                $dismRestoreExit=0
                if($remote){
                    $dismScanExit=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Get-DISMScanResult} -ArgumentList @($dismScanLog) -ComputerName $ComputerName -StepName 'DISM ScanHealth result check' -ConnectionLost ([ref]$remoteConnectionLost)
                } else { $dismScanExit=Get-DISMScanResult -dismScanLog $dismScanLog}
                if (-not $remoteConnectionLost -and $dismScanExit -eq 1) {

                    Write-RepairLog -Message "Starting DISM RestoreHealth..." -Component "DISM-RestoreHealth" -LogPath $masterLogPath
                    if ($remote) {
                        $dismRestoreBlock = New-RemoteFunctionScriptBlock -FunctionName @('Write-StepLogEntry', 'Get-RepairSystemProcessResult', 'Invoke-DISMRestore') -EntryPoint 'Invoke-DISMRestore'
                        $dismRestoreExit=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock $dismRestoreBlock -ArgumentList @($dismRestoreLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'DISM RestoreHealth' -ConnectionLost ([ref]$remoteConnectionLost)
                    } else { $dismRestoreExit=Invoke-DISMRestore $dismRestoreLog $ChangeTimeout $Quiet $VerboseOption }
                    if (-not $remoteConnectionLost) { $ExitCode[2]=$dismRestoreExit } else { $ExitCode[2]=5 }
                    Write-RepairLog -Message "DISM RestoreHealth completed; ExitCode=$($ExitCode[2]);" -Component "DISM-RestoreHealth" -LogPath $masterLogPath
                    Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $dismRestoreLog -Leaf)" } else { $dismRestoreLog }) -MasterLogPath $masterLogPath -StepName "DISM-RestoreHealth" -Component "DISM-RestoreHealth" -Sync
                    $needsRebootRerun = $needsRebootRerun -or (Test-DismSfcStepIncomplete -ResultCode $ExitCode[2] -LogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $dismRestoreLog -Leaf)" } else { $dismRestoreLog }) -Kind 'DISM')
                } elseif (-not $remoteConnectionLost) {
                    # ScanHealth reported a healthy store, so RestoreHealth was not necessary. Record
                    # the requested-but-not-executed sentinel so a step that never ran is not
                    # misreported as a successful repair.
                    $ExitCode[2]=$script:RepairSystemNotExecutedCode
                    Write-RepairLog -Message "DISM RestoreHealth not required (no corruption detected); marked as not executed." -Component "DISM-RestoreHealth" -LogPath $masterLogPath
                }
            } else {
                # ScanHealth itself returned an unexpected exit code, so RestoreHealth was not run.
                if (-not $remoteConnectionLost) { $ExitCode[2]=$script:RepairSystemNotExecutedCode }
                $message = "DISM ScanHealth returned an unexpected exit code ($dismScanResultString) on $ComputerName. Please review the logs."
                Write-Verbose $message
                if ($remote) {
                    Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock {
                        param ($logPath, $logMessage)
                        Add-Content -Path $logPath -Value $logMessage
                    } -ArgumentList @($dismRestoreLog, $message) -ComputerName $ComputerName -StepName 'Logging DISM ScanHealth result' -ConnectionLost ([ref]$remoteConnectionLost) | Out-Null
                } else {
                    Add-Content -Path $dismRestoreLog -Value $message
                    Write-Output $message
                }
            }
            & $removeStepLog $dismScanLog;    $stepLogPaths.Add($dismScanLog)
            & $removeStepLog $dismRestoreLog; $stepLogPaths.Add($dismRestoreLog)
            if (-not $remoteConnectionLost -and $IncludeComponentCleanup) {
                $analyzeComponentLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_DISM_analyze-component.log"
                $analyzeExit=0
                Write-RepairLog -Message "Starting DISM AnalyzeComponentStore..." -Component "DISM-Analyze" -LogPath $masterLogPath
                if ($remote) {
                    $analyzeBlock = New-RemoteFunctionScriptBlock -FunctionName @('Write-StepLogEntry', 'Get-RepairSystemProcessResult', 'Invoke-DISMAnalyzeComponentStore') -EntryPoint 'Invoke-DISMAnalyzeComponentStore'
                    $analyzeExit = Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock $analyzeBlock -ArgumentList @($analyzeComponentLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'DISM AnalyzeComponentStore' -ConnectionLost ([ref]$remoteConnectionLost)
                } else { $analyzeExit = Invoke-DISMAnalyzeComponentStore $analyzeComponentLog $ChangeTimeout $Quiet $VerboseOption }

                if ($remoteConnectionLost) { $ExitCode[3]=5 }

                if (-not $remoteConnectionLost) {
                    $analyzeExit  = [int]($analyzeExit | Select-Object -Last 1)
                    $ExitCode[3]  = $analyzeExit
                    Write-RepairLog -Message "DISM AnalyzeComponentStore completed; ExitCode=$($ExitCode[3]);" -Component "DISM-Analyze" -LogPath $masterLogPath
                    Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $analyzeComponentLog -Leaf)" } else { $analyzeComponentLog }) -MasterLogPath $masterLogPath -StepName "DISM-AnalyzeComponentStore" -Component "DISM-Analyze" -Sync
                    $needsRebootRerun = $needsRebootRerun -or (Test-DismSfcStepIncomplete -ResultCode $ExitCode[3] -LogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $analyzeComponentLog -Leaf)" } else { $analyzeComponentLog }) -Kind 'DISM')

                    # Check the output and perform cleanup if recommended
                    $message = ""
                    $componentCleanupLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_DISM_componentStore-cleanup.log"
                    if ($analyzeExit -eq 0 -or $analyzeExit -eq "") {
                        $analyzeResult=$true
                        if ($remote) {
                            $analyzeResult=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Get-DISMAnalyzeComponentStoreResult} -ArgumentList @($analyzeComponentLog) -ComputerName $ComputerName -StepName 'DISM AnalyzeComponentStore result check' -ConnectionLost ([ref]$remoteConnectionLost)
                        } else { $analyzeResult=Get-DISMAnalyzeComponentStoreResult -analyzeComponentLog $analyzeComponentLog }
                        $componentCleanupExit=0
                        if (-not $remoteConnectionLost -and $analyzeResult) {

                            Write-RepairLog -Message "Starting DISM ComponentStoreCleanup..." -Component "DISM-ComponentCleanup" -LogPath $masterLogPath
                            if ($remote) {
                                $componentCleanupBlock = New-RemoteFunctionScriptBlock -FunctionName @('Write-StepLogEntry', 'Get-RepairSystemProcessResult', 'Invoke-DISMComponentStoreCleanup') -EntryPoint 'Invoke-DISMComponentStoreCleanup'
                                $componentCleanupExit=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock $componentCleanupBlock -ArgumentList @($componentCleanupLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'DISM Component Store Cleanup' -ConnectionLost ([ref]$remoteConnectionLost)
                            } else { $componentCleanupExit=Invoke-DISMComponentStoreCleanup $componentCleanupLog $ChangeTimeout $Quiet $VerboseOption }
                        } elseif (-not $remoteConnectionLost) {
                            # AnalyzeComponentStore recommended no cleanup, so the step did not run.
                            # Flag it as requested-but-not-executed rather than leaving 0 (success).
                            $componentCleanupExit=$script:RepairSystemNotExecutedCode
                            $message = "No component store cleanup was needed on $ComputerName."
                            if($remote) {
                                Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock {
                                    param ($logPath, $logMessage)
                                    Add-Content -Path $logPath -Value $logMessage
                                } -ArgumentList @($componentCleanupLog, $message) -ComputerName $ComputerName -StepName 'Logging Component Store Cleanup result' -ConnectionLost ([ref]$remoteConnectionLost) | Out-Null
                            } else {
                                Write-Verbose $message
                                Add-Content -Path $componentCleanupLog -Value $message
                            }
                        }

                        if (-not $remoteConnectionLost) { $ExitCode[4]=$componentCleanupExit } else { $ExitCode[4]=5 }
                        if ($analyzeResult) {
                            Write-RepairLog -Message "DISM ComponentStoreCleanup completed; ExitCode=$($ExitCode[4]);" -Component "DISM-ComponentCleanup" -LogPath $masterLogPath
                            Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $componentCleanupLog -Leaf)" } else { $componentCleanupLog }) -MasterLogPath $masterLogPath -StepName "DISM-ComponentStoreCleanup" -Component "DISM-ComponentCleanup" -Sync
                            $needsRebootRerun = $needsRebootRerun -or (Test-DismSfcStepIncomplete -ResultCode $ExitCode[4] -LogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $componentCleanupLog -Leaf)" } else { $componentCleanupLog }) -Kind 'DISM')
                        }
                    } else {
                        # AnalyzeComponentStore did not complete cleanly, so cleanup could not run.
                        if (-not $remoteConnectionLost) { $ExitCode[4]=$script:RepairSystemNotExecutedCode }
                        $message = "DISM AnalyzeComponentStore returned an unexpected exit code ($analyzeExit) on $ComputerName. Please review the logs."
                        Write-Verbose $message
                        Add-Content -Path $componentCleanupLog -Value $message
                    }
                    & $removeStepLog $analyzeComponentLog;  $stepLogPaths.Add($analyzeComponentLog)
                    & $removeStepLog $componentCleanupLog;  $stepLogPaths.Add($componentCleanupLog)
                }
            }
        }
    }

    if(-not $noSfc -and -not $remoteConnectionLost){
        $sfcLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_sfc-scannow.log"
        $sfcExitCode=0
        Write-RepairLog -Message "Starting SFC /scannow..." -Component "SFC" -LogPath $masterLogPath
        if($remote){
            $sfcBlock = New-RemoteFunctionScriptBlock -FunctionName @('Write-StepLogEntry', 'Get-RepairSystemProcessResult', 'Invoke-SFC') -EntryPoint 'Invoke-SFC'
            $sfcExitCode= Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock $sfcBlock -ArgumentList @($sfcLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'SFC /scannow' -ConnectionLost ([ref]$remoteConnectionLost)
        } else {$sfcExitCode=Invoke-SFC $sfcLog $ChangeTimeout $Quiet $VerboseOption}
        if (-not $remoteConnectionLost) { $ExitCode[5]=[int]($sfcExitCode | Select-Object -Last 1) } else { $ExitCode[5]=5 }
        Write-RepairLog -Message "SFC /scannow completed; ExitCode=$($ExitCode[5]);" -Component "SFC" -LogPath $masterLogPath
        Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $sfcLog -Leaf)" } else { $sfcLog }) -MasterLogPath $masterLogPath -StepName "SFC" -Component "SFC" -Sync
        $needsRebootRerun = $needsRebootRerun -or (Test-DismSfcStepIncomplete -ResultCode $ExitCode[5] -LogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $sfcLog -Leaf)" } else { $sfcLog }) -Kind 'SFC')
        & $removeStepLog $sfcLog; $stepLogPaths.Add($sfcLog)
    }

    # If any DISM/SFC step that ran did not complete cleanly, schedule a single automatic repair to
    # run after the next reboot (default on; suppressed by -NoRebootRepair). Only when DISM was in
    # play - the re-run performs the full DISM + SFC pass.
    if ($needsRebootRerun -and -not $NoRebootRepair -and -not $noDism -and -not $remoteConnectionLost) {
        Write-RepairLog -Message "A DISM/SFC step did not complete cleanly; scheduling a one-shot reboot re-run..." -Component "RebootRerun" -LogPath $masterLogPath
        $rebootTask = Register-RebootRepairTask -ChangeTimeout $ChangeTimeout -InvokeParams $invokeParams -Remote:$remote
        if ($null -ne $rebootTask) {
            $rebootRerunScheduled = $true
            Write-RepairLog -Message "Reboot re-run scheduled as task '$($rebootTask.Task)' on $targetDevice; its log will be written under $($rebootTask.Folder) after the next restart." -Component "RebootRerun" -LogPath $masterLogPath
        } else {
            Write-RepairLog -Message "Reboot re-run could NOT be scheduled (task registration failed); a manual re-run after restart is recommended." -Component "RebootRerun" -LogPath $masterLogPath
        }
    }

    $zipJob      = $null
    $zipFile     = $null
    $zipErrorLog = $null
    if ((-not $noSfc -or -not $noDism) -and -not $remoteConnectionLost) {
        $zipFile     = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_CBS-DISM_sys-logs.zip"
        $zipErrorLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_CBS-DISM_zip-errors.log"
        Write-RepairLog -Message "Starting CBS/DISM log zip in background (after last SFC/DISM step)..." -Component "ZipLogs" -LogPath $masterLogPath
        try {
            if ($remote) {
                $zipJob = Invoke-Command @invokeParams -ScriptBlock ${function:Start-ZipFileCreation} -ArgumentList @($localTempPath, $zipFile, $zipErrorLog, $noDism) -AsJob
            } else {
                $zipJob = Start-Job -ScriptBlock ${function:Start-ZipFileCreation} -ArgumentList @($localTempPath, $zipFile, $zipErrorLog, $noDism)
            }
        } catch {
            Write-RepairLog -Message "Failed to start zip background job: $_" -Component "ZipLogs" -LogPath $masterLogPath
        }
    }

    # WMI Repository Repair runs BEFORE the WMI-dependent Content Cache Cleanup and CCM Repair steps
    # so those act on a repaired store. Its exit-code field is position 6 (see RepairSystemStepLayouts).
    if ($RepairWMI -and -not $remoteConnectionLost) {
        $wmiRepairLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_WMI_repository-repair.log"
        $wmiRepairResult=0
        Write-RepairLog -Message "Starting WMI Repository Repair (verify + salvage)..." -Component "WMIRepair" -LogPath $masterLogPath
        if ($remote) {
            $wmiRepairResult=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Repair-WMIRepository} -ArgumentList @($wmiRepairLog, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'WMI Repository Repair' -ConnectionLost ([ref]$remoteConnectionLost)
        } else { $wmiRepairResult=Repair-WMIRepository $wmiRepairLog $Quiet $VerboseOption }

        if (-not $remoteConnectionLost) { $ExitCode[6]=[int]($wmiRepairResult | Select-Object -Last 1) } else { $ExitCode[6]=5 }
        Write-RepairLog -Message "WMI Repository Repair completed; ExitCode=$($ExitCode[6]);" -Component "WMIRepair" -LogPath $masterLogPath
        Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $wmiRepairLog -Leaf)" } else { $wmiRepairLog }) -MasterLogPath $masterLogPath -StepName "WMI-RepositoryRepair" -Component "WMIRepair" -Sync
        & $removeStepLog $wmiRepairLog; $stepLogPaths.Add($wmiRepairLog)
    }

    if ($ContentCacheCleanup -and -not $remoteConnectionLost) {
        $cacheCleanupLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_ContentCache_cleanup.log"
        $cacheCleanupResult=0
        Write-RepairLog -Message "Starting Content Cache Cleanup (ConfigMgr / Adaptiva / Intune / Windows Update)..." -Component "ContentCacheCleanup" -LogPath $masterLogPath
        if ($remote) {
            $cacheCleanupBlock = New-RemoteFunctionScriptBlock -FunctionName @('Remove-PathReliable', 'Invoke-ContentCacheCleanup') -EntryPoint 'Invoke-ContentCacheCleanup'
            $cacheCleanupResult=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock $cacheCleanupBlock -ArgumentList @($cacheCleanupLog, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'Content Cache Cleanup' -ConnectionLost ([ref]$remoteConnectionLost)
        } else { $cacheCleanupResult=Invoke-ContentCacheCleanup $cacheCleanupLog $Quiet $VerboseOption }

        if (-not $remoteConnectionLost) {
            $cacheCleanupResult = [int]($cacheCleanupResult | Select-Object -Last 1)
            $ExitCode[7]=$cacheCleanupResult
            if ($cacheCleanupResult -eq 3010) {
                Write-Warning "`r`nContent Cache Cleanup on $targetDevice scheduled some locked cache items for removal on the next reboot. Please restart the device to finish."
            }
        } else { $ExitCode[7]=5 }
        Write-RepairLog -Message "Content Cache Cleanup completed; ExitCode=$($ExitCode[7]);" -Component "ContentCacheCleanup" -LogPath $masterLogPath
        Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $cacheCleanupLog -Leaf)" } else { $cacheCleanupLog }) -MasterLogPath $masterLogPath -StepName "ContentCache-Cleanup" -Component "ContentCacheCleanup" -Sync
        & $removeStepLog $cacheCleanupLog; $stepLogPaths.Add($cacheCleanupLog)
    }

    if ($WindowsUpdateCleanup -and -not $remoteConnectionLost) {
        $updateCleanupLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_WinUpdt-BITS_reset-cleanup.log"
        $updateCleanupExit=0
        Write-RepairLog -Message "Starting Windows Update Cleanup..." -Component "WUCleanup" -LogPath $masterLogPath
        if ($remote) {
            $updateCleanupBlock = New-RemoteFunctionScriptBlock -FunctionName @('Stop-ServiceSafely', 'Remove-PathReliable', 'Test-DataStoreHealth', 'Invoke-WULegacyRepair', 'Invoke-WindowsUpdateCleanup') -EntryPoint 'Invoke-WindowsUpdateCleanup'
            $updateCleanupExit=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock $updateCleanupBlock -ArgumentList @($updateCleanupLog, $ChangeTimeout, $Quiet, $VerboseOption, ([bool]$ResetUpdateHistory), $legacyRepairConfirmed) -ComputerName $ComputerName -StepName 'Windows Update Cleanup' -ConnectionLost ([ref]$remoteConnectionLost)
        } else { $updateCleanupExit=Invoke-WindowsUpdateCleanup $updateCleanupLog $ChangeTimeout $Quiet $VerboseOption ([bool]$ResetUpdateHistory) $legacyRepairConfirmed }

        if (-not $remoteConnectionLost) {
            $updateCleanupExit = [int]($updateCleanupExit | Select-Object -Last 1)
            if ($updateCleanupExit -eq 3010) {
                Write-Warning "`r`nWindows Update Cleanup on $targetDevice scheduled some locked items for removal on the next reboot. Please restart the device to finish."
            } elseif ($updateCleanupExit -ne 0) {
                Write-Error "`r`nAn error occurred while performing Windows Update Cleanup on $targetDevice. Please review the logs.`r`n`tA Restart of the Device is Adviced! Please try again afterwards"
            }
            $ExitCode[8]=$updateCleanupExit
        } else { $ExitCode[8]=5 }
        Write-RepairLog -Message "Windows Update Cleanup completed; ExitCode=$($ExitCode[8]);" -Component "WUCleanup" -LogPath $masterLogPath
        Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $updateCleanupLog -Leaf)" } else { $updateCleanupLog }) -MasterLogPath $masterLogPath -StepName "WindowsUpdate-Cleanup" -Component "WUCleanup" -Sync
        & $removeStepLog $updateCleanupLog; $stepLogPaths.Add($updateCleanupLog)
    }

    if ($RepairCCM -and -not $remoteConnectionLost) {
        $repairCCMLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_CCM_repair.log"
        $repairCCMResult=0
        Write-RepairLog -Message "Starting CCM Client Repair..." -Component "RepairCCM" -LogPath $masterLogPath
        if ($remote) {
            $repairCCMResult=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Repair-CCM} -ArgumentList @($localTempPath, $repairCCMLog, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'CCM Repair' -ConnectionLost ([ref]$remoteConnectionLost)
        } else { $repairCCMResult=Repair-CCM $localTempPath $repairCCMLog $Quiet $VerboseOption }

        if (-not $remoteConnectionLost) { $ExitCode[9]=$repairCCMResult } else { $ExitCode[9]=5 }
        Write-RepairLog -Message "CCM Repair completed; ExitCode=$($ExitCode[9]);" -Component "RepairCCM" -LogPath $masterLogPath
        Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $repairCCMLog -Leaf)" } else { $repairCCMLog }) -MasterLogPath $masterLogPath -StepName "CCM-Repair" -Component "RepairCCM" -Sync
        & $removeStepLog $repairCCMLog; $stepLogPaths.Add($repairCCMLog)
        if ($remote) {
            # Fetch CCMSetup_*.log to local immediately — stored next to the repair log, not embedded
            $logAppendJobs.Add((Start-Job -ScriptBlock {
                param($srcDir, $dst, $maxSec)
                $waited = 0
                while ($waited -lt $maxSec) {
                    $f = Get-Item "$srcDir\CCMSetup_*.log" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($f) { Copy-Item -Path $f.FullName -Destination $dst -Force -ErrorAction SilentlyContinue; return }
                    Start-Sleep -Seconds 5; $waited += 5
                }
            } -ArgumentList $remoteTempPath, $finalDestinationPath, 120))
        }
    }


    # Wait for background CBS/DISM zip job (started after last SFC/DISM step)
    if ($null -ne $zipJob) {
        Write-RepairLog -Message "Waiting for CBS/DISM zip background job..." -Component "ZipLogs" -LogPath $masterLogPath
        try {
            $zipJobDone = $zipJob | Wait-Job -Timeout 300
            $zipErrorCode = if ($null -ne $zipJobDone -and $zipJobDone.State -eq 'Completed') {
                $result = Receive-Job -Job $zipJob -ErrorAction SilentlyContinue
                if ($null -ne $result) { [int]($result | Select-Object -Last 1) } else { 0 }
            } else { 1 }
            $zipJob | Remove-Job -Force -ErrorAction SilentlyContinue
        } catch {
            Write-RepairLog -Message "Error waiting for zip background job: $_" -Component "ZipLogs" -LogPath $masterLogPath
            $zipErrorCode = 1
        }
        if ($remote -and $zipErrorCode -eq 0) {
            try {
                $zipCopySession = New-PSSession @invokeParams -ErrorAction Stop
                Copy-Item -Path $zipFile -Destination $finalDestinationPath -Force -FromSession $zipCopySession -ErrorAction SilentlyContinue
                Remove-PSSession $zipCopySession -ErrorAction SilentlyContinue
            } catch {
                Write-RepairLog -Message "Failed to copy zip to local immediately: $_" -Component "ZipLogs" -LogPath $masterLogPath
            }
        }
        if (-not $remoteConnectionLost) { $ExitCode[10]=$zipErrorCode } else { $ExitCode[10]=5 }
    } elseif ($remoteConnectionLost) {
        $ExitCode[10]=5
    } else {
        $ExitCode[10]=0
    }
    Write-RepairLog -Message "CBS/DISM zip step completed; ExitCode=$($ExitCode[10]);" -Component "ZipLogs" -LogPath $masterLogPath

    # Wait for all background log-append / fetch jobs BEFORE the bulk copy so that jobs
    # reading from remote UNC paths finish before -KeepLogs deletion can remove those files.
    if ($logAppendJobs.Count -gt 0) {
        Write-RepairLog -Message "Waiting for log-append background jobs ($($logAppendJobs.Count))..." -Component "RepairSystem" -LogPath $masterLogPath
        $logAppendJobs | Wait-Job -Timeout 120 | Out-Null
        $logAppendJobs | Remove-Job -Force -ErrorAction SilentlyContinue
    }

    if($remote) {$path=$finalDestinationPath} else {$path=$localTempPath}
    $extmsg= "`r`nSystem-Repair performed.`r`n`r`nIf Errors Occurred, or SFC/DISM/WindowsUpdate Cleanup and Diagnostics Jobs were Terminated due to Timeout, please restart the system and run once more."
    if ($rebootRerunScheduled) {
        $extmsg += "`r`n`r`n[INFO]`tOne or more DISM/SFC steps did not complete. A one-time repair has been scheduled to run automatically after the next restart of $targetDevice; its log will be saved on that machine under C:\_IT-RebootRepair\ (kept separate from the temp folder so cleanup will not remove it)."
    }
    $extmsglLogP ="`r`nLog-Files can be found on this Machine under '$path'`r`nRepair log: $masterLogPath"
    $extmsgrLogP ="`r`n`tThe Log-Data can be found on the Remote Device on $remoteTempPath"
    if ($remote){
        if ($remoteConnectionLost) {
            $extmsg+= "`r`n[WARNING]`tConnection to $ComputerName was lost during the repair process. Log files could not be copied from the remote device."
        } else {
            if (-not (Test-Path -Path $finalDestinationPath)) {
                New-Item -Path $finalDestinationPath -ItemType Directory -Force
            }
            try{
                $Session = New-PSSession @invokeParams
                Copy-Item -Path "$localTempPath\*" -Destination $finalDestinationPath -Recurse -Force -FromSession $Session

                # Clear remote _temp folder if copy was successful

                if(-not $KeepLogs){
                    Invoke-Command @invokeParams -ScriptBlock {
                        Remove-Item -Path "$using:localTempPath" -Recurse -Force
                    } -Verbose:$VerboseOption
                    $extmsg+= $extmsglLogP
                } else {
                    # KeepLogs=true: keep step logs on the remote device.
                    # Delete the copies that landed in $finalDestinationPath — content is already in master log.
                    $stepLogPaths | ForEach-Object {
                        Remove-Item -Path "$finalDestinationPath\$(Split-Path $_ -Leaf)" -Force -ErrorAction SilentlyContinue
                    }
                    $extmsg+= $extmsgrLogP
                }
            } catch {
                $message = "An error occurred while copying the log files from $ComputerName."
                Write-Error $message
                $extmsg+= $extmsgrLogP+"`r`n[ERROR]`r`t$_"
            }
        }
    } else {
        $extmsg+= $extmsglLogP
    }

    if ($remoteConnectionLost) {
        if ($ExitCode[0] -eq 0) { $ExitCode[0] = 4 }
        $extmsg += "`r`n[WARNING]`tRemaining repair steps were skipped because the connection to $ComputerName was lost."
        Write-RepairLog -Message "Connection to $ComputerName was lost during execution; ExitCode[0] set to $($ExitCode[0])." -Component "RepairSystem" -LogPath $masterLogPath
    }

    Write-RepairLog -Message "Repair-System completed;" -Component "RepairSystem" -LogPath $masterLogPath -StartLogEntry
    Write-RepairLog -Message "Target: $(if ($remote) { $ComputerName } else { $env:COMPUTERNAME }); Remote: $remote;" -Component "RepairSystem" -LogPath $masterLogPath -AddLogEntryData
    Write-RepairLog -Message "DetailedExitCode: $(ConvertTo-RepairSystemExitCode -Codes $ExitCode); Severity: $(Get-RepairSystemExitCodeSeverity -Codes $ExitCode);" -Component "RepairSystem" -LogPath $masterLogPath -AddLogEntryData
    Write-RepairLog -Message "Log: $masterLogPath;" -Component "RepairSystem" -LogPath $masterLogPath -EndLogEntry

    Start-Sleep -Seconds 1
    if (-not $Quiet) { Write-Host $extmsg }
    Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -LogPath $masterLogPath -RequestedSteps $requestedSteps
}
Export-ModuleMember -Function Repair-System, Repair-LocalSystem, Repair-RemoteSystem

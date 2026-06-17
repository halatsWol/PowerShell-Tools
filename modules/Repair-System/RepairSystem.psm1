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

    function Close-UnclosedEntry {
        if (Test-Path $statePath) {
            $state = Get-Content $statePath -Raw | ConvertFrom-Json
            Remove-Item $statePath -Force
            $autoCloseTime = [datetime]::Parse($state.Time)
            $dateAuto = $autoCloseTime.ToString("MM-dd-yyyy")
            $timeAuto = $autoCloseTime.ToString("HH:mm:ss.fff")
            $tzAuto   = if ($tzOffset -ge 0) { "+{0:000}" -f $tzOffset } else { "-{0:000}" -f [math]::Abs($tzOffset) }
            Add-Content -Path $state.LogPath -Value "]LOG]!><time=""$timeAuto$tzAuto"" date=""$dateAuto"" component=""$($state.Component)"" context=""autoClosedByFollowingEntry"" type=""1"" thread=""$threadId"" file=""$resolvedSource"">"
        }
    }

    if ($StartLogEntry -and $EndLogEntry) {
        Close-UnclosedEntry
        Add-Content -Path $LogPath -Value "<![LOG[$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""1"" thread=""$threadId"" file=""$resolvedSource"">"
        return
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Start' {
            Close-UnclosedEntry
            if ($null -eq $Message) { $Message = "LogEntry:" }
            Add-Content -Path $LogPath -Value "<![LOG[$Message"
            @{ Component = $Component; Source = $resolvedSource; LogPath = $LogPath; Time = $timestamp.ToString("o") } |
                ConvertTo-Json -Compress | Out-File -FilePath $statePath -Encoding UTF8 -Force
        }
        'Add' {
            if ($Message) { Add-Content -Path $LogPath -Value $Message }
        }
        'End' {
            if ($null -eq $Message) { $Message = "" }
            if (Test-Path $statePath) {
                $state = Get-Content $statePath -Raw | ConvertFrom-Json
                Remove-Item $statePath -Force
                Add-Content -Path $state.LogPath -Value "$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$($state.Component)"" context="""" type=""1"" thread=""$threadId"" file=""$($state.Source)"">"
            } else {
                Add-Content -Path $LogPath -Value "$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""1"" thread=""$threadId"" file=""$resolvedSource"">"
            }
        }
        default {
            Close-UnclosedEntry
            Add-Content -Path $LogPath -Value "<![LOG[$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""1"" thread=""$threadId"" file=""$resolvedSource"">"
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
        Add-Content -Path $masterLogPath -Value "<![LOG[--- $stepName log ---"
        Add-Content -Path $masterLogPath -Value $content
        Add-Content -Path $masterLogPath -Value "--- end $stepName log ---]LOG]!><time=""$timeStr$tzFmt"" date=""$dateStr"" component=""$component"" context="""" type=""1"" thread=""$tid"" file=""LogAppendJob"">"
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
#>
$script:RepairSystemSteps = [ordered]@{
    0 = @{ Key = 'Startup';                   Label = 'Startup / Pre-Flight Checks' }
    1 = @{ Key = 'SFC';                       Label = 'SFC /scannow' }
    2 = @{ Key = 'DISMScanHealth';            Label = 'DISM /Online /Cleanup-Image /ScanHealth' }
    3 = @{ Key = 'DISMRestoreHealth';         Label = 'DISM /Online /Cleanup-Image /RestoreHealth' }
    4 = @{ Key = 'DISMAnalyzeComponentStore'; Label = 'DISM /Online /Cleanup-Image /AnalyzeComponentStore' }
    5 = @{ Key = 'DISMComponentCleanup';      Label = 'DISM /Online /Cleanup-Image /StartComponentCleanup' }
    6 = @{ Key = 'SCCMCleanup';               Label = 'SCCM Cache / SoftwareDistribution Cleanup' }
    7 = @{ Key = 'WindowsUpdateCleanup';      Label = 'Windows Update Cleanup' }
    8 = @{ Key = 'RepairCCM';                 Label = 'CCM Client Repair' }
    9 = @{ Key = 'ZipLogs';                   Label = 'Zip CBS/DISM Logs' }
}

<#
Well-known integer codes per step (by Key), plus a 'Generic' fallback used by every step.
Anything not listed here falls back to a generic "tool-specific result code" message.
#>
$script:RepairSystemKnownCodes = @{
    Generic = @{
        '0'          = 'Success, not requested, or skipped. Without the original run context, it cannot be determined whether this step ran and succeeded, or was not executed (not requested, not applicable, or skipped due to a prior failure or connection loss).'
        '1'          = 'The step failed. See the step''s log file for details.'
        '5'          = 'Skipped - the remote connection was lost before this step could run.'
        '87'         = 'DISM: The parameter is incorrect (ERROR_INVALID_PARAMETER).'
        '1726'       = 'DISM: The remote procedure call failed.'
        '3010'       = 'DISM/SFC: Success, but a restart is required to finish applying changes.'
        '4294967294' = 'Repair-System terminated the process because it exceeded its maximum allowed run time (timeout). Restarting the device and running the step again is recommended.'
        '4294967293' = 'The process ended almost immediately, well before Repair-System killed it for a timeout. It was most likely closed by something else (e.g. Task Manager, a crash, a forced shutdown) before it could finish, so its own exit code could not be trusted and was not used.'
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
# an unforced exit is treated as suspicious. DISM/SFC scans realistically take much longer than
# this, so a legitimate sub-30-second completion is not expected in normal use.
$script:RepairSystemMinPlausibleDurationSeconds = 30

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
    if ($KilledByTimeout) { return $script:RepairSystemProcessSentinel.TimedOut }

    if (((Get-Date) - $StartTime).TotalSeconds -lt $script:RepairSystemMinPlausibleDurationSeconds) {
        return $script:RepairSystemProcessSentinel.TerminatedExternally
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
    $stepCount = $script:RepairSystemSteps.Count
    $values = [System.Collections.Generic.List[uint32]]::new()
    $pos = 0

    for ($i = 0; $i -lt $stepCount; $i++) {
        if ($pos -ge $Code.Length) {
            return [PSCustomObject]@{
                IsValid = $false
                Error   = "'$Code' is not a valid Repair-System exit code: ran out of characters while reading step $i of $stepCount."
                Values  = $null
            }
        }

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
            $values.Add([uint32]0)
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

        $values.Add([Convert]::ToUInt32($hexChunk, 16))
        $pos += $len
    }

    if ($pos -ne $Code.Length) {
        return [PSCustomObject]@{
            IsValid = $false
            Error   = "'$Code' is not a valid Repair-System exit code: $($Code.Length - $pos) unexpected trailing character(s)."
            Values  = $null
        }
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
    rather than a complete failure to start).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [int[]]$Codes
    )
    if (($Codes | Where-Object { $_ -ne 0 }).Count -eq 0) { return 0 }
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
    $steps = [System.Collections.Generic.List[PSCustomObject]]::new()
    for ($i = 0; $i -lt $parsed.Values.Count; $i++) {
        $step     = $script:RepairSystemSteps[$i]
        $value    = $parsed.Values[$i]
        $valueKey = $value.ToString()
        $description = if ($script:RepairSystemKnownCodes.ContainsKey($step.Key) -and $script:RepairSystemKnownCodes[$step.Key].ContainsKey($valueKey)) {
            $script:RepairSystemKnownCodes[$step.Key][$valueKey]
        } elseif ($script:RepairSystemKnownCodes.Generic.ContainsKey($valueKey)) {
            $script:RepairSystemKnownCodes.Generic[$valueKey]
        } else {
            "Tool-specific result code (0x{0:X8} / {0}). See the step's log file for details." -f $value
        }
        $steps.Add([PSCustomObject]@{
            Position    = $i
            Label       = $step.Label
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
            SFC                       = $RequestedSteps[1]
            DISMScanHealth            = $RequestedSteps[2]
            DISMRestoreHealth         = $RequestedSteps[3]
            DISMAnalyzeComponentStore = $RequestedSteps[4]
            DISMComponentCleanup      = $RequestedSteps[5]
            SCCMCleanup               = $RequestedSteps[6]
            WindowsUpdateCleanup      = $RequestedSteps[7]
            RepairCCM                 = $RequestedSteps[8]
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
                } elseif ($val -eq 5) {
                    'Skipped (connection lost)'
                } elseif ($val -eq [uint32](-2)) {
                    'Timed out'
                } elseif ($val -eq [uint32](-3)) {
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

    $isFullSuccess = ($parsed.Values | Where-Object { $_ -ne 0 }).Count -eq 0
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
    Runs one remote repair step via Invoke-Command. Once a step fails to reach the remote
    device, ConnectionLost is set so every later call into this function becomes a no-op,
    instead of every remaining step also throwing its own remoting error.
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
        [ref]$ConnectionLost
    )

    if ($ConnectionLost.Value) {
        return $null
    }

    try {
        return Invoke-Command @InvokeParams -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
    } catch {
        $ConnectionLost.Value = $true
        Write-Error "Lost connection to '$ComputerName' while performing '$StepName'. Skipping remaining repair steps.`r`n$_"
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
    Write-Host "executing SFC (up to $SfcMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
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
                        $process.WaitForExit(30000); $process.WaitForExit()
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
            $logContent = Get-Content $sfcLog -Raw
            $logContent = $logContent -replace '[^\x00-\x7F]', ''
            $logContent = $logContent -replace [char]0
            Set-Content $sfcLog -Value $logContent

            $errorLogContent = Get-Content $sfcErrorLog -Raw
            $errorLogContent = $errorLogContent -replace '[^\x00-\x7F]', ''
            $errorLogContent = $errorLogContent -replace [char]0
            Write-StepLogEntry $sfcLog "`r`n`r`n// Start Error-Log:`r`n$errorLogContent`r`n// End Error-Log"
            Remove-Item -Path $sfcErrorLog -Force -ErrorAction SilentlyContinue
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
    Write-Host "executing DISM/ScanHealth (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
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
                    $process.WaitForExit(30000); $process.WaitForExit()
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
        $dismLogContent = Get-Content $dismErrorLog -Raw
        Write-StepLogEntry $dismScanLog "`r`n`r`n// Start Error-Log:`r`n$dismLogContent`r`n// End Error-Log"
        Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue

        return (Get-RepairSystemProcessResult -Process $process -StartTime $DismStartTime -KilledByTimeout:$dismKilledByTimeout)
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
    Write-Host "executing DISM/RestoreHealth (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
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
                    $process.WaitForExit(30000); $process.WaitForExit()
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
        $dismLogContent = Get-Content $dismErrorLog -Raw
        Write-StepLogEntry $dismRestoreLog "`r`n`r`n// Start Error-Log:`r`n$dismLogContent`r`n// End Error-Log"
        Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue

        return (Get-RepairSystemProcessResult -Process $process -StartTime $DismStartTime -KilledByTimeout:$dismKilledByTimeout)
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
    Write-Host "executing DISM Analyze Component Store (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
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
                    $process.WaitForExit(30000); $process.WaitForExit()
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
        $dismLogContent = Get-Content $dismErrorLog -Raw
        Write-StepLogEntry $analyzeComponentLog "`r`n`r`n// Start Error-Log:`r`n$dismLogContent`r`n// End Error-Log"
        Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue

        return (Get-RepairSystemProcessResult -Process $process -StartTime $DismStartTime -KilledByTimeout:$dismKilledByTimeout)
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
    Write-Host "executing DISM Component Store Cleanup (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
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
                    $process.WaitForExit(30000); $process.WaitForExit()
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
        $dismLogContent = Get-Content $dismErrorLog -Raw
        Write-StepLogEntry $componentCleanupLog "`r`n`r`n// Start Error-Log:`r`n$dismLogContent`r`n// End Error-Log"
        Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue

        return (Get-RepairSystemProcessResult -Process $process -StartTime $DismStartTime -KilledByTimeout:$dismKilledByTimeout)
    } catch {
        $message = "An error occurred while performing Component Store Cleanup: `r`n$_"
        Write-Error $message
        Add-Content -Path $componentCleanupLog -Value $message
    }
}

function Invoke-SCCMCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$sccmCleanupLog,

        [Parameter(Mandatory=$true, Position=1)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}

    Write-Host "executing SCCM Cleanup"
    $returnVal=0
    if (Test-Path -Path "C:\Windows\ccmcache") {
        try{
            Remove-Item -Path "\\?\C:\Windows\ccmcache\*" -Recurse -Force
            Add-Content -Path $sccmCleanupLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - INFO:`r`n`tC:\Windows\ccmcache\ cleaned`r`n"
            $returnVal = 0
        } catch {
            $errorMessage = "An error occurred while performing SCCM Cleanup: `r`n$_"
            Write-Error $errorMessage
            Add-Content -Path $sccmCleanupLog -Value $errorMessage
            $returnVal = 1
        }
    } else {
        $msg = "CCM Cache folder does not exist. No need to delete."
        Write-Verbose $msg
        Add-Content -Path $sccmCleanupLog -Value $msg
        $returnVal = 0
    }

    if (Test-Path -Path "C:\Windows\SoftwareDistribution\Download") {
        try{
            Remove-Item -Path "\\?\C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force
            Add-Content -Path $sccmCleanupLog -Value "`r`n[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - INFO:`r`n`tC:\Windows\SoftwareDistribution\Download\ cleaned`r`n"
            $returnVal = 0
        } catch {
            $errorMessage = "An error occurred while Cleaning SoftwareDistribution\Download: `r`n$_"
            Write-Error $errorMessage
            Add-Content -Path $sccmCleanupLog -Value $errorMessage
            $returnVal = 1
        }
    } else {
        $msg = "SoftwareDistribution\Download folder does not exist. No need to delete."
        Write-Verbose $msg
        Add-Content -Path $sccmCleanupLog -Value $msg
        $returnVal = 0
    }
    return $returnVal
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
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}

    Write-Host "Starting Windows Update Cleanup..."
    $servicesStart=@("bits","wuauserv","appidsvc","cryptsvc","msiserver","trustedinstaller","ccmexec","smstsmgr")
    $servicesStop=@("wuauserv","bits","appidsvc","cryptsvc","msiserver","trustedinstaller","ccmexec","smstsmgr")
    $softwareDistributionPath = "C:\Windows\SoftwareDistribution"
    $catroot2Path = "C:\Windows\system32\catroot2"
    $softwareDistributionBackupPath = "$softwareDistributionPath.bak"
    $catroot2BackupPath = "$catroot2Path.bak"
    $softDist = $false
    $softDistErr=""
    $cat2= $false
    $cat2Err=""
    Stop-ServiceSafely -ServiceName $servicesStop
    if ($Null -ne (Get-Process CcmExec -ea SilentlyContinue)) {Get-Process CcmExec | Stop-Process -Force}
    if ($Null -ne (Get-Process TSManager -ea SilentlyContinue)) {Get-Process TSManager| Stop-Process -Force}
    if (Test-Path -Path $softwareDistributionBackupPath) {
        Write-Verbose "Backup directory exists. Deleting $softwareDistributionBackupPath..."
        try{
            Remove-Item -Path "\\?\$softwareDistributionBackupPath" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            $softDistErr= "Error deleting SoftwareDistribution backup folder: `r`n$_"
            Add-Content -Path $updateCleanupLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - ERROR:`r`n`t$softDistErr"
            Write-Error $softDistErr
            Get-Service -ErrorAction SilentlyContinue $servicesStart | Start-Service
            return 2
        }
    } else {
        Write-Verbose "Backup directory does not exist. No need to delete."
    }
    Stop-ServiceSafely -ServiceName $servicesStop -Force
    if ($Null -ne (Get-Process CcmExec -ea SilentlyContinue)) {Get-Process CcmExec | Stop-Process -Force}
    if ($Null -ne (Get-Process TSManager -ea SilentlyContinue)) {Get-Process TSManager| Stop-Process -Force}
    if (Test-Path -Path $softwareDistributionPath) {
        try{
            Rename-Item -Force -Path $softwareDistributionPath -NewName SoftwareDistribution.bak -ErrorAction Continue
            $softDist = $true
        } catch {
            $softDistErr= "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - INFO:`r`n`tError renaming SoftwareDistribution folder: `r`n$_"
            Add-Content -Path $updateCleanupLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - ERROR:`r`n`t$softDistErr"
            Write-Error $softDistErr
            Get-Service -ErrorAction SilentlyContinue $servicesStart | Start-Service
            return 1
        }
    }
    if (Test-Path -Path $catroot2BackupPath) {
        Write-Verbose "Backup directory exists. Deleting $catroot2BackupPath..."
        try{
            Remove-Item -Path "\\?\$catroot2BackupPath" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            $cat2Err= "Error deleting catroot2 backup folder: `r`n$_"
            Add-Content -Path $updateCleanupLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - ERROR:`r`n`t$cat2Err"
            Write-Error $cat2Err
            Get-Service -ErrorAction SilentlyContinue $servicesStart | Start-Service
            return 2
        }
    } else {
        Write-Verbose "Backup directory does not exist. No need to delete."
    }
    Stop-ServiceSafely -ServiceName $servicesStop -Force
    if ($Null -ne (Get-Process CcmExec -ea SilentlyContinue)) {Get-Process CcmExec | Stop-Process -Force}
    if ($Null -ne (Get-Process TSManager -ea SilentlyContinue)) {Get-Process TSManager| Stop-Process -Force}
    if (Test-Path -Path $catroot2Path) {
        try{
            Rename-Item -Force -Path $catroot2Path -NewName catroot2.bak -ErrorAction Continue
            $cat2 = $true
        } catch {
            $cat2Err= "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - ERROR:`r`n`tError renaming catroot2 folder: `r`n$_"
            Add-Content -Path $updateCleanupLog -Value "$cat2Err"
            Write-Error $cat2Err
            Get-Service -ErrorAction SilentlyContinue $servicesStart | Start-Service
            return 1
        }
    } else {
        Write-Verbose "catroot2 folder does not exist. No need to rename."
    }
    Get-Service -ErrorAction SilentlyContinue $servicesStart | Start-Service


    Write-Host "Starting Diagnostics..."
    $winDiagMsg="[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - INFO:`r`n`tStarting Diagnostics:"
    Add-Content -Path $updateCleanupLog -Value "$winDiagMsg"
    Write-Verbose $winDiagMsg
    $updtDiagMsg="`t`tWindows Update Troubleshooting..."
    $bitsDiagMsg="`t`tBITS Troubleshooting..."
    try {
        $DiagMaxDurationVal = 15 * $ChangeTimeout
        $DiagMaxDuration = New-TimeSpan -Minutes $DiagMaxDurationVal
        Add-Content -Path $updateCleanupLog -Value "$updtDiagMsg"
        Write-Host "Starting Windows Update Troubleshooting... (up to $DiagMaxDurationVal min, Start: $(Get-Date -Format "HH:mm"))"
        $job = Start-Job -ScriptBlock {
            Get-TroubleshootingPack -Path 'C:\Windows\diagnostics\system\WindowsUpdate' | Invoke-TroubleshootingPack -Unattended
        }
        $startTime = Get-Date

        while ($job.State -eq 'Running') {
            Start-Sleep -Seconds 5
            if ((Get-Date) - $startTime -gt $DiagMaxDuration) {
                Write-Warning "Diagnostics timed out after $DiagMaxDurationVal minutes."
                Stop-Job -Job $job
            }
        }
        $jobResult = Receive-Job -Job $job -Wait
        # write job result to log
        Add-Content -Path $updateCleanupLog -Value "`t`tDiag Job-State: $($job.State)Result: $jobResult"
        Remove-Job -Job $job
    }
    catch {
        $updtTrblShootErr="ERROR:`r`n$_"
        Add-Content -Path $updateCleanupLog -Value "$updtTrblShootErr"
        Write-Error $updtTrblShootErr
    }
    try {
        $DiagMaxDurationVal = 10 * $ChangeTimeout
        $DiagMaxDuration = New-TimeSpan -Minutes $DiagMaxDurationVal
        Add-Content -Path $updateCleanupLog -Value "$bitsDiagMsg"
        Write-Host "Starting BITS Troubleshooting... (up to $DiagMaxDurationVal min, Start: $(Get-Date -Format "HH:mm"))"
        $job = Start-Job -ScriptBlock {
            Get-TroubleshootingPack -Path 'C:\Windows\diagnostics\system\BITS' | Invoke-TroubleshootingPack -Unattended
        }
        $startTime = Get-Date

        while ($job.State -eq 'Running') {
            Start-Sleep -Seconds 5
            if ((Get-Date) - $startTime -gt $DiagMaxDuration) {
                Write-Warning "Diagnostics timed out after $DiagMaxDurationVal minutes."
                Stop-Job -Job $job
            }
        }
        $jobResult = Receive-Job -Job $job -Wait
        # write job result to log
        Add-Content -Path $updateCleanupLog -Value "`t`tDiag Job-State: $($job.State)Result: $jobResult"
        Remove-Job -Job $job

    }
    catch {
        $bitsTrblShootErr="`t`tERROR:`r`n$_"
        Add-Content -Path $updateCleanupLog -Value "$bitsTrblShootErr"
        Write-Error $bitsTrblShootErr
    }


    $successMessage = "Windows Update Cleanup successful."
    if($softDist){
        $successMessage += "`r`n[SUCCESS]`tSoftwareDistribution folder has been renamed."
    } else {
        $successMessage += "`r`n[STATUS]`tRenaming SoftwareDistribution: folder does not exist or is currently used by another process.`r`n`t`tThis may be because it has been renamed before."
        if($softDistErr -ne ""){$successMessage += "`r`n[ERROR]`t$softDistErr"}
    }
    if($cat2){
        $successMessage += "`r`n[SUCCESS]`tcatroot2 folder has been renamed."
    }else {
        $successMessage += "`r`n[STATUS]`tRenaming catroot2: folder does not exist or is currently used by another process.`r`n`t`tThis may be because it has been renamed before."
        if($cat2Err -ne ""){$successMessage += "`r`n[ERROR]`t$cat2Err"}
    }
    Write-Verbose $successMessage
    Add-Content -Path $updateCleanupLog -Value "[$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss.fff')] - INFO:`r`n`t$successMessage"
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

    $ccmrepairexe="C:\Windows\CCM\ccmrepair.exe"
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"

    if (-not (Test-Path $ccmrepairexe)) {
        Write-Host "CCMRepair executable not found."
        Write-RepairCCMLog "CCMRepair executable not found at $ccmrepairexe."
        return 1
    }

    try {
        # Restart SCCM Client Service
        Write-Host "Restarting SCCM Service..."
        Write-RepairCCMLog "Restarting SCCM Service..."

        $stopProcessErrors = $null
        Stop-Process -Name SCClient,CcmExec -Force -ErrorAction SilentlyContinue -ErrorVariable stopProcessErrors
        foreach ($stopProcessError in $stopProcessErrors) {
            Write-RepairCCMLog "ERROR: Failed to stop process: $stopProcessError"
        }

        $restartServiceErrors = $null
        Restart-Service CcmExec -Force -ErrorAction SilentlyContinue -ErrorVariable restartServiceErrors
        foreach ($restartServiceError in $restartServiceErrors) {
            Write-RepairCCMLog "ERROR: Failed to restart service CcmExec: $restartServiceError"
        }

        Start-Sleep -Seconds 10

        # Run SCCM Client Repair
        Write-Host "Starting CCMRepair... This may take a while (~30min)."
        Write-RepairCCMLog "Starting CCMRepair..."
        Start-Process -FilePath $ccmrepairexe -Wait -ErrorAction Stop -NoNewWindow
        Write-RepairCCMLog "CCMRepair process finished."

        # Print Repair Result
        $ccmSetupLogFolder = "C:\Windows\ccmsetup\Logs"
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
        Write-Host "Clearing SCCM Cache..."
        Write-RepairCCMLog "Clearing SCCM Cache..."
        $CachePath = "C:\Windows\ccmcache\*"
        if (Test-Path $CachePath) {
            Remove-Item $CachePath -Recurse -Force -ErrorAction SilentlyContinue
            Write-RepairCCMLog "SCCM Cache cleared."
        } else {
            Write-RepairCCMLog "SCCM Cache folder does not exist. No need to clear."
        }

        # Trigger SCCM Cycles
        Write-Host "Triggering SCCM Client Actions..."
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
        $cbsLog = "C:\Windows\Logs\CBS\CBS.log"
        $dismLog = "C:\Windows\Logs\dism\dism.log"
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

    Progress and status are printed to the local console. Step outputs are written to temporary log files, then consolidated into a single master repair log (`SystemRepair_<PC>_<date>.log`) in CMTrace-compatible format; individual step log files are removed after embedding. On remote runs, the master log and a CBS/DISM system log archive are transferred to the local machine.

    .PARAMETER ComputerName
    The hostname or IP address of the remote computer where the system repair will be performed.

    .PARAMETER remoteShareDrive
    The ShareDrive of the Remote-Device on which Windows is installed. If non is provided, Default-Value 'C$' will be used
    The Command `Repair-RemoteSystem -ComputerName SomeDevice -remoteShareDrive D$` will result in Network-Path `\\SomeDevice\D$\`

    .PARAMETER noSfc
    When specified, the `SCF /SCANNOW` command is skipped.

    .PARAMETER noDism
    When specified, the `DISM` commands are skipped.

    .PARAMETER Quiet
    Suppresses console output on the local machine. The output is logged to files on the remote machine instead.

    .PARAMETER IncludeComponentCleanup
    When specified, performs `DISM /Online /Cleanup-Image /AnalyzeComponentStore` and, if recommended, performs `DISM /Online /Cleanup-Image /StartComponentCleanup`.

    .PARAMETER sccmCleanup
    When specified, deletes the contents of the CCMCache folder and SoftwareDistribution\Download folder.

    .PARAMETER WindowsUpdateCleanup
    When specified, performs Windows Update Cleanup by renaming the SoftwareDistribution and catroot2 folders.
    This will also run the Windows Update and BITS Troubleshooting Packs.

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
        Actions          [PSCustomObject] Which steps were requested: SFC, DISMScanHealth, DISMRestoreHealth,
                                          DISMAnalyzeComponentStore, DISMComponentCleanup, SCCMCleanup,
                                          WindowsUpdateCleanup, RepairCCM — each a [bool].
        Analysis         [PSCustomObject[]] Per-step breakdown: Position, Label, Value, Status.
                                            Status is one of: Success, Not requested, Skipped (connection lost),
                                            Success (restart required), Timed out, Terminated externally, or the
                                            step's known-code description for other failures.

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
    Repair-RemoteSystem <remote-device> -WindowsUpdateCleanup

    stops the Windows Update and related Services, renames the SoftwareDistribution and catroot2 folders, and restarts the services.

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

    The step positions are as follows:
    Position 0: Startup (parameter/network/WinRM/elevation/config errors), or a connection-lost code if the remote connection was lost mid-execution
    Position 1: SFC /scannow
    Position 2: DISM ScanHealth
    Position 3: DISM RestoreHealth
    Position 4: DISM AnalyzeComponentStore
    Position 5: DISM StartComponentCleanup
    Position 6: SCCM Cleanup
    Position 7: Windows Update Cleanup
    Position 8: Repair CCM
    Position 9: Zip CBS/DISM Logs

    For the SFC and DISM steps (Positions 1-5) specifically, a raw process exit code is only
    trusted if the process actually had a fair chance to run. If Repair-System itself killed
    the process for exceeding its time budget, that field instead reads 4294967294 (a
    dedicated out-of-band "timed out" value, distinct from any real SFC/DISM exit code). If the
    process disappeared in well under 30 seconds without Repair-System killing it - implausibly
    fast for a real scan/repair - that field instead reads 4294967293 ("likely terminated
    externally, e.g. via Task Manager - its own exit code could not be trusted").

    Except for Position 0, the detailed exit code field is the return value of the corresponding
    command. If the command was not executed (skipped, or not reached because the remote
    connection was lost), the field is 0. Only a startup failure causes an immediate exit;
    all other step failures are recorded but do not interrupt the remaining steps.

    Author: Wolfram Halatschek
    E-Mail: dev@kMarflow.com
    Date: 2026-06-17
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
        [switch]$sccmCleanup,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$KeepLogs,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$init,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [PSCredential] $Credentials,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
        [switch]$RepairCCM,

        [Parameter(Mandatory=$true, ParameterSetName='Analyze')]
        [string]$AnalyzeExitCode

    )

    if ($PSCmdlet.ParameterSetName -eq 'Analyze') {
        Write-RepairSystemExitCodeAnalysis -Code $AnalyzeExitCode
        return
    }

    $ExitCode = @(0,0,0,0,0,0,0,0,0,0) #Startup, SFC, DISM Scan, DISM Restore, Analyze Component, Component Cleanup, SCCM Cleanup, Windows Update Cleanup, Repair CCM, Zip CBS/DISM Logs

    $ComputerName = $ComputerName.Trim()
    $targetDevice   = $env:COMPUTERNAME
    $requestedSteps = @(
        $true,                                        # [0] Startup - always
        (-not $noSfc),                                # [1] SFC
        (-not $noDism),                               # [2] DISM ScanHealth
        (-not $noDism),                               # [3] DISM RestoreHealth
        (-not $noDism),                               # [4] DISM AnalyzeComponentStore
        (-not $noDism -and $IncludeComponentCleanup), # [5] DISM ComponentCleanup
        $sccmCleanup.IsPresent,                       # [6] SCCM Cleanup
        $WindowsUpdateCleanup.IsPresent,              # [7] WU Cleanup
        $RepairCCM.IsPresent,                         # [8] CCM Repair
        (-not $noSfc -or -not $noDism)                # [9] Zip Logs
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
        break
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
        # Ping the remote computer to check availability
        $pingResult = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction Stop

        if (-not $pingResult) {
            Write-Error "Unable to reach $ComputerName. Please check the Device-Name or the network connection to the remote Device."
            $ExitCode[0]=2
            Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
            break
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
            break
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
    Write-RepairLog -Message "SFC: $(if ($noSfc) { 'skip' } else { 'run' }); DISM: $(if ($noDism) { 'skip' } else { 'run' }); ComponentCleanup: $IncludeComponentCleanup; SCCMCleanup: $sccmCleanup; WUCleanup: $WindowsUpdateCleanup; RepairCCM: $RepairCCM; Timeout: ${ChangeTimeout}x;" -Component "RepairSystem" -LogPath $masterLogPath -EndLogEntry

    if (-not $noDism -and -not $remoteConnectionLost) {
        $dismScanLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_DISM_scanHealth.log"
        $dismScanResult=0
        Write-RepairLog -Message "Starting DISM ScanHealth..." -Component "DISM-ScanHealth" -LogPath $masterLogPath
        if($remote){
            $dismScanResult = Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Invoke-DISMScan} -ArgumentList @($dismScanLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'DISM ScanHealth' -ConnectionLost ([ref]$remoteConnectionLost)
        } else { $dismScanResult=Invoke-DISMScan $dismScanLog $ChangeTimeout $Quiet $VerboseOption}

        if (-not $remoteConnectionLost) {
            $dismScanResult = [int]($dismScanResult | Select-Object -First 1)
            $ExitCode[2]=$dismScanResult
            $dismScanResultString = $dismScanResult.ToString()
        } else { $ExitCode[2]=5 }
        Write-RepairLog -Message "DISM ScanHealth completed; ExitCode=$($ExitCode[2]);" -Component "DISM-ScanHealth" -LogPath $masterLogPath
        Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $dismScanLog -Leaf)" } else { $dismScanLog }) -MasterLogPath $masterLogPath -StepName "DISM-ScanHealth" -Component "DISM-ScanHealth" -Sync

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
                        $dismRestoreExit=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Invoke-DISMRestore} -ArgumentList @($dismRestoreLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'DISM RestoreHealth' -ConnectionLost ([ref]$remoteConnectionLost)
                    } else { $dismRestoreExit=Invoke-DISMRestore $dismRestoreLog $ChangeTimeout $Quiet $VerboseOption }
                    if (-not $remoteConnectionLost) { $ExitCode[3]=$dismRestoreExit } else { $ExitCode[3]=5 }
                    Write-RepairLog -Message "DISM RestoreHealth completed; ExitCode=$($ExitCode[3]);" -Component "DISM-RestoreHealth" -LogPath $masterLogPath
                    Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $dismRestoreLog -Leaf)" } else { $dismRestoreLog }) -MasterLogPath $masterLogPath -StepName "DISM-RestoreHealth" -Component "DISM-RestoreHealth" -Sync
                }
            } else {
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
                    $analyzeExit = Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Invoke-DISMAnalyzeComponentStore} -ArgumentList @($analyzeComponentLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'DISM AnalyzeComponentStore' -ConnectionLost ([ref]$remoteConnectionLost)
                } else { $analyzeExit = Invoke-DISMAnalyzeComponentStore $analyzeComponentLog $ChangeTimeout $Quiet $VerboseOption }

                if ($remoteConnectionLost) { $ExitCode[4]=5 }

                if (-not $remoteConnectionLost) {
                    $analyzeExit  = [int]($analyzeExit | Select-Object -Last 1)
                    $ExitCode[4]  = $analyzeExit
                    Write-RepairLog -Message "DISM AnalyzeComponentStore completed; ExitCode=$($ExitCode[4]);" -Component "DISM-Analyze" -LogPath $masterLogPath
                    Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $analyzeComponentLog -Leaf)" } else { $analyzeComponentLog }) -MasterLogPath $masterLogPath -StepName "DISM-AnalyzeComponentStore" -Component "DISM-Analyze" -Sync

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
                                $componentCleanupExit=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Invoke-DISMComponentStoreCleanup} -ArgumentList @($componentCleanupLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'DISM Component Store Cleanup' -ConnectionLost ([ref]$remoteConnectionLost)
                            } else { $componentCleanupExit=Invoke-DISMComponentStoreCleanup $componentCleanupLog $ChangeTimeout $Quiet $VerboseOption }
                        } elseif (-not $remoteConnectionLost) {
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

                        if (-not $remoteConnectionLost) { $ExitCode[5]=$componentCleanupExit } else { $ExitCode[5]=5 }
                        if ($analyzeResult) {
                            Write-RepairLog -Message "DISM ComponentStoreCleanup completed; ExitCode=$($ExitCode[5]);" -Component "DISM-ComponentCleanup" -LogPath $masterLogPath
                            Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $componentCleanupLog -Leaf)" } else { $componentCleanupLog }) -MasterLogPath $masterLogPath -StepName "DISM-ComponentStoreCleanup" -Component "DISM-ComponentCleanup" -Sync
                        }
                    } else {
                        $message = "DISM AnalyzeComponentStore returned an unexpected exit code ($analyzeResult) on $ComputerName. Please review the logs."
                        Write-Output $message
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
            $sfcExitCode= Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Invoke-SFC} -ArgumentList @($sfcLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'SFC /scannow' -ConnectionLost ([ref]$remoteConnectionLost)
        } else {$sfcExitCode=Invoke-SFC $sfcLog $ChangeTimeout $Quiet $VerboseOption}
        if (-not $remoteConnectionLost) { $ExitCode[1]=[int]($sfcExitCode | Select-Object -Last 1) } else { $ExitCode[1]=5 }
        Write-RepairLog -Message "SFC /scannow completed; ExitCode=$($ExitCode[1]);" -Component "SFC" -LogPath $masterLogPath
        Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $sfcLog -Leaf)" } else { $sfcLog }) -MasterLogPath $masterLogPath -StepName "SFC" -Component "SFC" -Sync
        & $removeStepLog $sfcLog; $stepLogPaths.Add($sfcLog)
    }

    $zipJob      = $null
    $zipFetchJob = $null
    $zipFile     = $null
    $zipErrorLog = $null
    if ((-not $noSfc -or -not $noDism) -and -not $remoteConnectionLost) {
        $zipFile     = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_CBS-DISM_sys-logs.zip"
        $zipErrorLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_CBS-DISM_zip-errors.log"
        Write-RepairLog -Message "Starting CBS/DISM log zip in background (after last SFC/DISM step)..." -Component "ZipLogs" -LogPath $masterLogPath
        try {
            if ($remote) {
                $zipJob = Invoke-Command @invokeParams -ScriptBlock ${function:Start-ZipFileCreation} -ArgumentList @($localTempPath, $zipFile, $zipErrorLog, $noDism) -AsJob
                # Immediately start a fetch job: polls the UNC path and copies the zip to
                # $finalDestinationPath as soon as it appears there — overlaps SCCM/WU/CCM steps.
                $remoteZipUncPath = "$remoteTempPath\$(Split-Path $zipFile -Leaf)"
                $zipFetchJob = Start-Job -ScriptBlock {
                    param($src, $dst, $maxSec)
                    $waited = 0
                    while (-not (Test-Path $src) -and $waited -lt $maxSec) {
                        Start-Sleep -Seconds 5; $waited += 5
                    }
                    if (Test-Path $src) {
                        Copy-Item -Path $src -Destination $dst -Force -ErrorAction SilentlyContinue
                        return 0
                    }
                    return 1
                } -ArgumentList $remoteZipUncPath, $finalDestinationPath, 600
            } else {
                $zipJob = Start-Job -ScriptBlock ${function:Start-ZipFileCreation} -ArgumentList @($localTempPath, $zipFile, $zipErrorLog, $noDism)
            }
        } catch {
            Write-RepairLog -Message "Failed to start zip background job: $_" -Component "ZipLogs" -LogPath $masterLogPath
        }
    }

    if ($sccmCleanup -and -not $remoteConnectionLost) {
        $sccmCleanupLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_SCCM_cleanup.log"
        $sccmCleanupResult=0
        Write-RepairLog -Message "Starting SCCM Cache / SoftwareDistribution Cleanup..." -Component "SCCMCleanup" -LogPath $masterLogPath
        if ($remote) {
            $sccmCleanupResult=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock ${function:Invoke-SCCMCleanup} -ArgumentList @($sccmCleanupLog, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'SCCM Cleanup' -ConnectionLost ([ref]$remoteConnectionLost)
        } else { $sccmCleanupResult=Invoke-SCCMCleanup $sccmCleanupLog $Quiet $VerboseOption }

        if (-not $remoteConnectionLost) { $ExitCode[6]=$sccmCleanupResult } else { $ExitCode[6]=5 }
        Write-RepairLog -Message "SCCM Cleanup completed; ExitCode=$($ExitCode[6]);" -Component "SCCMCleanup" -LogPath $masterLogPath
        Start-LogAppendJob -StepLogPath $(if ($remote) { "$remoteTempPath\$(Split-Path $sccmCleanupLog -Leaf)" } else { $sccmCleanupLog }) -MasterLogPath $masterLogPath -StepName "SCCM-Cleanup" -Component "SCCMCleanup" -Sync
        & $removeStepLog $sccmCleanupLog; $stepLogPaths.Add($sccmCleanupLog)
    }

    if ($WindowsUpdateCleanup -and -not $remoteConnectionLost) {
        $updateCleanupLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_WinUpdt-BITS_reset-cleanup.log"
        $updateCleanupExit=0
        Write-RepairLog -Message "Starting Windows Update Cleanup..." -Component "WUCleanup" -LogPath $masterLogPath
        if ($remote) {
            $updateCleanupBlock = New-RemoteFunctionScriptBlock -FunctionName @('Stop-ServiceSafely', 'Invoke-WindowsUpdateCleanup') -EntryPoint 'Invoke-WindowsUpdateCleanup'
            $updateCleanupExit=Invoke-RemoteStep -InvokeParams $invokeParams -ScriptBlock $updateCleanupBlock -ArgumentList @($updateCleanupLog, $ChangeTimeout, $Quiet, $VerboseOption) -ComputerName $ComputerName -StepName 'Windows Update Cleanup' -ConnectionLost ([ref]$remoteConnectionLost)
        } else { $updateCleanupExit=Invoke-WindowsUpdateCleanup  $updateCleanupLog $ChangeTimeout $Quiet $VerboseOption }

        if (-not $remoteConnectionLost) {
            if($updateCleanupExit -ne 0){
                Write-Error "`r`nAn error occurred while performing Windows Update Cleanup on $ComputerName. Please review the logs.`r`n`tA Restart of the Device is Adviced! Please try again afterwards"
            }
            $ExitCode[7]=$updateCleanupExit
        } else { $ExitCode[7]=5 }
        Write-RepairLog -Message "Windows Update Cleanup completed; ExitCode=$($ExitCode[7]);" -Component "WUCleanup" -LogPath $masterLogPath
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

        if (-not $remoteConnectionLost) { $ExitCode[8]=$repairCCMResult } else { $ExitCode[8]=5 }
        Write-RepairLog -Message "CCM Repair completed; ExitCode=$($ExitCode[8]);" -Component "RepairCCM" -LogPath $masterLogPath
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
        if ($null -ne $zipFetchJob) {
            # Zip is confirmed done on remote; fetch job should finish very shortly
            $zipFetchJob | Wait-Job -Timeout 120 | Out-Null
            $zipFetchJob | Remove-Job -Force -ErrorAction SilentlyContinue
        }
        if (-not $remoteConnectionLost) { $ExitCode[9]=$zipErrorCode } else { $ExitCode[9]=5 }
    } elseif ($remoteConnectionLost) {
        $ExitCode[9]=5
    } else {
        $ExitCode[9]=0
    }
    Write-RepairLog -Message "CBS/DISM zip step completed; ExitCode=$($ExitCode[9]);" -Component "ZipLogs" -LogPath $masterLogPath

    # Wait for all background log-append / fetch jobs BEFORE the bulk copy so that jobs
    # reading from remote UNC paths finish before -KeepLogs deletion can remove those files.
    if ($logAppendJobs.Count -gt 0) {
        Write-RepairLog -Message "Waiting for log-append background jobs ($($logAppendJobs.Count))..." -Component "RepairSystem" -LogPath $masterLogPath
        $logAppendJobs | Wait-Job -Timeout 120 | Out-Null
        $logAppendJobs | Remove-Job -Force -ErrorAction SilentlyContinue
    }

    if($remote) {$path=$finalDestinationPath} else {$path=$localTempPath}
    $extmsg= "`r`nSystem-Repair performed.`r`n`r`nIf Errors Occurred, or SFC/DISM/WindowsUpdate Cleanup and Diagnostics Jobs were Terminated due to Timeout, please restart the system and run once more."
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
    Write-Host $extmsg
    Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -LogPath $masterLogPath -RequestedSteps $requestedSteps
}
Export-ModuleMember -Function Repair-System, Repair-LocalSystem, Repair-RemoteSystem

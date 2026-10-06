function New-Folder {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FolderPath
    )
    if (-not (Test-Path -Path $FolderPath)) {New-Item -Path $FolderPath -ItemType Directory -Force > $null}
}

function New-SecureDirectory {
    <#
        Creates a directory only SYSTEM and Administrators can modify, with the ACL
        applied at creation so there is no window in which it is open. A folder made
        directly under C:\ otherwise inherits Modify for Authenticated Users - and the
        deferred task runs as SYSTEM.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$UsersRead
    )
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rights = @{ 'S-1-5-18' = 'FullControl'; 'S-1-5-32-544' = 'FullControl' }
    if ($UsersRead) { $rights['S-1-5-32-545'] = 'ReadAndExecute' }
    foreach ($sid in $rights.Keys) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier $sid), $rights[$sid], 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop -WhatIf:$false | Out-Null
    }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($Path), $acl)
    } else {
        [void][System.IO.Directory]::CreateDirectory($Path, $acl)
    }
}

function Write-CMTraceLog {
    <#
    Appends one CMTrace-format entry. Identical in TempDataCleanup, Repair-System, removeUserProfile and
    AutoDeskCleanRemove; anything tool-specific lives in wrappers that call this. A multi-line message
    stays a single entry, and CMTrace delimiters inside it are escaped so an embedded log cannot split
    it. A briefly locked file (open viewer, AV scan) is retried and the function never throws - a lost
    log line must not abort the caller. Wrappers pass their own $MyInvocation as -Caller, so file= names
    the real call site. Self-contained so it survives being shipped to a remote session or script.
    #>
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$Component,

        [Parameter(Mandatory=$true, Position=2)]
        [string]$LogPath,

        [Parameter(Position=3)]
        [ValidateSet('Info','Warning','Error')]
        [string]$Severity = 'Info',

        [System.Management.Automation.InvocationInfo]$Caller
    )
    if (-not $Caller) { $Caller = $MyInvocation }
    $type    = @{ Info = 1; Warning = 2; Error = 3 }[$Severity]
    $now     = Get-Date
    $offset  = [TimeZoneInfo]::Local.GetUtcOffset($now).TotalMinutes
    $source  = if ($Caller.ScriptName) { Split-Path -Path $Caller.ScriptName -Leaf } else {
        # Shipped scriptblock without a file: name the nearest named function that made the call.
        $stack = @(Get-PSCallStack)
        $i = 0
        while ($i -lt $stack.Count -and -not [object]::ReferenceEquals($stack[$i].InvocationInfo, $Caller)) { $i++ }
        $named = @($stack | Select-Object -Skip ($i + 1) | Where-Object { $_.FunctionName -ne '<ScriptBlock>' })
        if ($named.Count -gt 0) { $named[0].FunctionName } else { '<ScriptBlock>' }
    }
    $escaped = $Message -replace '<!\[LOG\[', '&lt;![LOG[' -replace '\]LOG\]!>', ']LOG]!&gt;'
    $entry   = '<![LOG[{0}]LOG]!><time="{1}{2:+000;-000}" date="{3}" component="{4}" context="" type="{5}" thread="{6}" file="{7}:{8}">' -f
        $escaped, $now.ToString('HH:mm:ss.fff'), $offset, $now.ToString('MM-dd-yyyy'), $Component, $type, $PID, $source, $Caller.ScriptLineNumber

    # -Encoding UTF8 skips the BOM-detection read Add-Content otherwise does, which is the open that
    # fails on a transiently held file. -WhatIf:$false keeps logging active in a -WhatIf run.
    for ($i = 0; $i -lt 10; $i++) {
        try {
            Add-Content -LiteralPath $LogPath -Value $entry -Encoding UTF8 -ErrorAction Stop -WhatIf:$false
            return
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    Write-Warning "A log entry could not be written to '$LogPath'; continuing."
}

function Add-RepairStepLog {
    <#
    Embeds a finished step's own log (its content, read from the target by the caller) into the master
    log as one CMTrace entry. Repeated progress lines (DISM bar / SFC verification) are collapsed to the
    last one.
    #>
    param(
        [AllowEmptyString()] [AllowNull()] [string]$Content,
        [Parameter(Mandatory=$true)]  [string]$MasterLogPath,
        [Parameter(Mandatory=$true)]  [string]$StepName,
        [Parameter(Mandatory=$false)] [string]$Component = "RepairSystem"
    )
    if ([string]::IsNullOrWhiteSpace($Content)) { return }
    # The step's own entries (Write-CMTraceLog in the step log) become plain 'time [severity] message'
    # lines, so the embedded block reads like the tool output around it.
    $content = [regex]::Replace($Content, '(?s)<!\[LOG\[(.*?)\]LOG\]!><time="([\d:.]+)[^"]*"[^>]*?type="(\d)"[^>]*>', {
        param($m)
        $level = @{ '2' = ' [Warning]'; '3' = ' [Error]' }[$m.Groups[3].Value]
        "$($m.Groups[2].Value)$level $($m.Groups[1].Value)"
    })
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
    Write-CMTraceLog -Message ("--- $StepName log ---`n" + ($filtered -join "`n") + "`n--- end $StepName log ---") -Component $Component -LogPath $MasterLogPath -Caller $MyInvocation
}

function Write-StepLogLine {
    # One entry in a step's own log on the target; bundled with Write-CMTraceLog into every step that
    # keeps one. Add-RepairStepLog folds the step log into the master log afterwards.
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [Parameter(Mandatory=$true)] [AllowEmptyString()] [string]$Message,
        [Parameter(Mandatory=$true)] [string]$Component,
        [ValidateSet('Info','Warning','Error')] [string]$Severity = 'Info'
    )
    Write-CMTraceLog -Message $Message -Component $Component -LogPath $Path -Severity $Severity -Caller $MyInvocation
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
# Set while a -Quiet run is in progress, so remote steps can be silenced on the device as well.
$script:RepairSystemQuietRun = $false

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
        '0'          = 'Success, or the step was not requested. Without the original run context this cannot be distinguished: a step that was never requested (e.g. -noDism, -noSfc, or component cleanup not included) keeps its initial value of 0, indistinguishable here from a step that ran and succeeded. A step skipped for a known reason instead carries its own code - not necessary (-4), postponed (-5) or connection lost (5) - so those never appear as 0.'
        '1'          = 'The step failed. See the step''s log file for details.'
        '5'          = 'Skipped - the remote connection was lost before this step could run.'
        '87'         = 'DISM: The parameter is incorrect (ERROR_INVALID_PARAMETER).'
        '1726'       = 'DISM: The remote procedure call failed.'
        '3010'       = 'DISM/SFC: Success, but a restart is required to finish applying changes.'
        '-2' = 'Repair-System terminated the process because it exceeded its maximum allowed run time (timeout). Restarting the device and running the step again is recommended.'
        '-3' = 'The process ended almost immediately, well before Repair-System killed it for a timeout. It was most likely closed by something else (e.g. Task Manager, a crash, a forced shutdown) before it could finish, so its own exit code could not be trusted and was not used.'
        '-4' = 'The step was requested but did not run because it was not necessary (for DISM StartComponentCleanup, AnalyzeComponentStore did not recommend a cleanup) or because a required prior step did not complete. No changes were made, and this is not an error.'
        '-5' = 'The step was needed but postponed because a restart is pending (for DISM StartComponentCleanup, AnalyzeComponentStore recommended a cleanup but reported that a restart is required first). Restart the device and run Repair-System again.'
    }
    Startup = @{
        '0' = 'Startup completed successfully.'
        '1' = 'Invalid -ComputerName format.'
        '2' = 'Remote computer unreachable (no PowerShell session could be opened and ping failed).'
        '3' = 'Unable to establish a WinRM/remote PowerShell session.'
        '4' = 'Connection to the remote device was lost during execution.'
        '5' = 'Not running with administrative privileges.'
        '6' = 'Error reading or writing the configuration file.'
        '7' = 'Conflicting parameters were supplied (e.g. -IncludeComponentCleanup with -noDism).'
    }
    DISMScanHealth = @{
        '0' = 'ScanHealth is no longer run - RestoreHealth (position 2) scans the image itself and repairs only what it finds - so current builds always report 0 here. In codes from older builds, 0 meant success or not requested.'
    }
    WindowsUpdateCleanup = @{
        '3010' = 'Success, but a restart is required: locked items are deleted at the next boot. Also reported when an update or MSI installation was still running after the wait - then no service was stopped and the whole reset runs at the next boot.'
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
# a precondition was not met (DISM StartComponentCleanup when AnalyzeComponentStore recommends none, or a conditional step whose
# prerequisite step failed). Distinct from 0 - which for a requested step would read as a genuine
# success - so "requested but not executed" is never misreported as "ran and succeeded". Sits in
# the same reserved top-of-uint32 band as the process sentinels and is treated as a non-problem
# by Get-RepairSystemExitCodeSeverity.
$script:RepairSystemNotExecutedCode = -4 # 0xFFFFFFFC / 4294967292 as uint32

# Recorded for a step that is needed but was held back because a restart is pending (DISM
# StartComponentCleanup when AnalyzeComponentStore recommends a cleanup but returns 3010). Unlike
# -4 it needs action: restart and run again.
$script:RepairSystemPostponedCode = -5 # 0xFFFFFFFB / 4294967291 as uint32

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
    # stored as (-2/-3/-4/-5) instead of surfacing as their unwieldy uint32 form (4294967294/93/92/91).
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
        [bool[]]$RequestedSteps,
        # Steps that were started; only consulted after a lost connection (startup field 4).
        [Parameter(Mandatory=$false)]
        [bool[]]$AttemptedSteps
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
                } elseif ($val -eq 0 -and $Codes[0] -eq 4 -and $null -ne $AttemptedSteps -and -not $AttemptedSteps[$step.Position]) {
                    'Not run (connection lost)'
                } elseif ($val -eq 0) {
                    'Success'
                } elseif ($val -eq 3010) {
                    'Success (restart required)'
                } elseif ($val -eq -4) {
                    'Skipped (not needed)'
                } elseif ($val -eq -5) {
                    'Postponed (restart required)'
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
    remote session, so helper functions it depends on (eg. Remove-PathReliable) are otherwise
    undefined there. This bundles the helper definitions together with the entry point into one
    script block, so the helper stays defined in a single place but still works when shipped. The
    block takes one hashtable (-ArgumentList $params) and splats it onto the entry point.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$FunctionName,

        [Parameter(Mandatory=$true)]
        [string]$EntryPoint
    )

    $scriptText = "param(`$Params)`n"
    foreach ($name in $FunctionName) {
        $scriptText += "function $name {`n" + (Get-Item "function:$name").ScriptBlock.ToString() + "`n}`n"
    }
    $scriptText += "$EntryPoint @Params"
    return [scriptblock]::Create($scriptText)
}

function Invoke-RepairStep {
    <#
    Runs one step on the target: in the run's PSSession for a remote device, in-process for the local
    one, so every step takes the same code path. Errors the step itself reports are shown and its
    return value is kept. Only a broken session counts as a lost connection: the session is reopened
    for up to $ReconnectTimeoutSec seconds - if that works the interrupted step is marked failed (1)
    and the run continues, otherwise $Target.Lost is set and every later call returns $null.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Target,

        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [object[]]$ArgumentList = @(),

        [Parameter(Mandatory=$true)]
        [string]$StepName,

        [int]$ReconnectTimeoutSec = 90
    )
    if ($Target.Lost) { return $null }
    # A step that throws fails only itself (1); without the catch it would end the whole run. On PS 5.1
    # a throw in the session also arrives here as a terminating RemoteException.
    if (-not $Target.Session) {
        try { return Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList }
        catch { Write-Error "'$StepName' failed: $_"; return 1 }
    }

    # A remote step's host output and warnings reach the local console directly, past any redirection
    # by the caller, so a quiet run silences them on the device itself.
    if ($Target.Quiet) { $ScriptBlock = [scriptblock]::Create("& {`n$ScriptBlock`n} @args 6>`$null 3>`$null") }
    $result = $null
    try {
        $result = Invoke-Command -Session $Target.Session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    } catch {
        if ($Target.Session.State -eq 'Opened') { Write-Error "'$StepName' failed: $_"; return 1 }
    }
    if ($Target.Session.State -eq 'Opened') { return $result }

    Write-Warning "Connection to '$($Target.ComputerName)' interrupted during '$StepName'. Retrying for up to $ReconnectTimeoutSec seconds..."
    Remove-PSSession -Session $Target.Session -ErrorAction SilentlyContinue
    $sessionParams = $Target.SessionParams
    $deadline = (Get-Date).AddSeconds($ReconnectTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 10
        try {
            $Target.Session = New-PSSession @sessionParams -ErrorAction Stop
            Write-Warning "Reconnected to '$($Target.ComputerName)'. Step '$StepName' did not complete - marking as failed and continuing."
            return 1
        } catch { }
    }
    $Target.Lost = $true
    Write-Error "Lost connection to '$($Target.ComputerName)' while performing '$StepName'. Skipping remaining repair steps."
    return $null
}
function Invoke-RepairTool {
    <#
    Runs one DISM/SFC operation with its output captured to the step log and a hard time limit, and
    returns the result Repair-System trusts for it (see Get-RepairSystemProcessResult). stderr goes to
    <step log>_stderr.log: an empty capture is deleted (queued for the next reboot if a killed process
    still holds it), a non-empty one is kept as its own file. Self-contained apart from
    Write-CMTraceLog, Get-RepairSystemProcessResult, Remove-PathReliable and Register-PendingDelete.
    #>
    param(
        [Parameter(Mandatory=$true)] [string]$Name,
        [Parameter(Mandatory=$true)] [string]$FilePath,
        [Parameter(Mandatory=$true)] [string[]]$ArgumentList,
        [Parameter(Mandatory=$true)] [string]$LogPath,
        [Parameter(Mandatory=$true)] [decimal]$MaxMinutes,
        # SFC writes UTF-16 with embedded NULs; normalise its captures to plain text.
        [switch]$AsciiOutput
    )
    $errLog = $LogPath -replace '\.log$', '_stderr.log'
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -RedirectStandardOutput $LogPath -RedirectStandardError $errLog -NoNewWindow -PassThru
        $null = $process.Handle   # keeps ExitCode readable after exit (empty on PS 5.1 otherwise)
        $startTime = Get-Date
        $killedByTimeout = -not $process.WaitForExit([int]($MaxMinutes * 60000))
        if ($killedByTimeout) {
            $stuck = "$Name has been running for more than $MaxMinutes minutes. Stopping it..."
            Write-Warning $stuck
            try {
                # Only the DismHost.exe children of this run, never other servicing on the machine.
                $children = @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId=$($process.Id)" -ErrorAction SilentlyContinue)
                $process.Kill()
                $children | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
                [void]$process.WaitForExit(30000)
                # Written only now: the step log is held by the process's output redirect until it exits.
                Write-CMTraceLog "$stuck $Name terminated." $Name $LogPath Warning
                Write-Warning "$Name terminated."
            } catch {
                Write-CMTraceLog "$stuck Failed to terminate ${Name}: $_" $Name $LogPath Error
                Write-Warning "Failed to terminate ${Name}: $_"
            }
        }
        $result = Get-RepairSystemProcessResult -Process $process -StartTime $startTime -KilledByTimeout:$killedByTimeout
    } catch {
        $message = "An error occurred while running ${Name}:`r`n$_"
        Write-Error $message
        Write-CMTraceLog $message $Name $LogPath Error
        return 1
    }

    # Post-run handling must never overwrite the step result (eg. turn a -2 timeout into a 1): right
    # after a timeout kill a handle may still be held, so every read here is allowed to fail.
    try {
        if ($AsciiOutput) {
            foreach ($file in $LogPath, $errLog) {
                $text = if (Test-Path -LiteralPath $file) { Get-Content -LiteralPath $file -Raw -ErrorAction Stop }
                if ($null -ne $text) { Set-Content -LiteralPath $file -Value (($text -replace '[^\x00-\x7F]', '') -replace [char]0) -ErrorAction Stop }
            }
        }
    } catch {
        Write-CMTraceLog "Post-run log handling failed (step result preserved): $_" $Name $LogPath Warning
    }
    $errItem = Get-Item -LiteralPath $errLog -ErrorAction SilentlyContinue
    if ($errItem) {
        $isEmpty = $errItem.Length -eq 0
        if (-not $isEmpty -and $errItem.Length -lt 4096) {
            try { $isEmpty = [string]::IsNullOrWhiteSpace((Get-Content -LiteralPath $errLog -Raw -ErrorAction Stop)) } catch { }
        }
        if ($isEmpty -and (Remove-PathReliable -Path $errLog).Scheduled) {
            Write-CMTraceLog "Empty stderr capture '$($errItem.Name)' is locked; queued for deletion on the next restart." $Name $LogPath
        }
    }
    return $result
}

function Invoke-SFC {
    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$true)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout
    )
    $maxMinutes = 20 * $ChangeTimeout
    $start = Get-Date
    Write-Host "executing SFC (up to $maxMinutes min, Start $(Get-Date -Format 'HH:mm' -Date $start))"
    $result = Invoke-RepairTool -Name 'Sfc.exe' -FilePath 'sfc' -ArgumentList '/scannow' -LogPath $LogPath -MaxMinutes $maxMinutes -AsciiOutput
    Write-CMTraceLog (Get-SfcCbsSummary -Since $start) 'Sfc.exe' $LogPath
    $result
}

function Get-SfcCbsSummary {
    <#
    Language-neutral SFC verdict: sfc's console text is localised and it exits 0 even when it could not
    repair, but the [SR] entries it writes to CBS.log are neither. Returns one fixed line for the step
    log, which Test-DismSfcStepIncomplete reads. CBS.log is rotated to CbsPersist_*.log (compressed to
    .cab later) when it grows too large, possibly in the middle of the scan, so the persisted parts
    written since the start are read first. Self-contained for remote shipping.
    #>
    param([Parameter(Mandatory=$true)] [datetime]$Since)
    $cbsDir       = Join-Path $env:windir 'Logs\CBS'
    $sinceStamp   = $Since.AddSeconds(-2).ToString('yyyy-MM-dd HH:mm:ss')
    $finished     = $false
    $repaired     = @{}
    $unrepairable = @{}
    $expandDir    = Join-Path $env:TEMP "RepairSystem-Cbs-$([guid]::NewGuid().ToString('N'))"
    try {
        $persisted = @(Get-ChildItem -LiteralPath $cbsDir -Filter 'CbsPersist_*' -File -ErrorAction SilentlyContinue |
                       Where-Object { $_.LastWriteTime -ge $Since.AddSeconds(-2) -and $_.Extension -in '.log', '.cab' } | Sort-Object Name)
        $files = foreach ($file in $persisted) {
            if ($file.Extension -eq '.log') { $file.FullName; continue }
            # expand.exe names a single-file cab's content after the cab, so every file extracted counts
            $target = Join-Path $expandDir $file.BaseName
            $null = New-Item -ItemType Directory -Path $target -Force
            & (Join-Path $env:windir 'System32\expand.exe') "-F:*" $file.FullName $target 2>&1 | Out-Null
            Get-ChildItem -LiteralPath $target -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
        }
        $files = @($files) + (Join-Path $cbsDir 'CBS.log')
        foreach ($path in $files) {
            # CBS.log is held open by TrustedInstaller, so share everything.
            $reader = New-Object System.IO.StreamReader (New-Object System.IO.FileStream $path, 'Open', 'Read', 'ReadWrite, Delete')
            try {
                while ($null -ne ($line = $reader.ReadLine())) {
                    if ($line.IndexOf('[SR] ') -lt 0 -or $line.Length -lt 19 -or [string]::CompareOrdinal($line.Substring(0, 19), $sinceStamp) -lt 0) { continue }
                    # the final batch's "Repair complete" is the only one per run
                    if ($line -match '\[SR\] Repair complete') { $finished = $true }
                    elseif ($line -match '\[SR\] Repairing file (.+) from store') { $repaired[(Split-Path $Matches[1] -Leaf)] = $true }
                    elseif ($line -match '\[SR\] Could not reproject corrupted file ([^;]+)') { $unrepairable[(Split-Path $Matches[1] -Leaf)] = $true }
                    elseif ($line -match "\[SR\] Cannot repair member file \[l:\d+\]'([^']+)'") { $unrepairable[$Matches[1]] = $true }
                }
            } finally { $reader.Dispose() }
        }
    } catch {
        return "Repair-System SFC result (CBS.log): not available - $($_.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $expandDir) { Remove-Item -LiteralPath $expandDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $result = "Repair-System SFC result (CBS.log): Finished=$finished; Repaired=$($repaired.Count); Unrepairable=$($unrepairable.Count)"
    if ($unrepairable.Count) { $result += " ($(@($unrepairable.Keys) -join ', '))" }
    $result
}

function Invoke-DISMRestore {
    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$true)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout
    )
    $maxMinutes = 40 * $ChangeTimeout
    Write-Host "executing DISM/RestoreHealth (up to $maxMinutes min, Start $(Get-Date -Format 'HH:mm'))"
    Invoke-RepairTool -Name 'Dism.exe' -FilePath 'dism.exe' -ArgumentList '/online', '/Cleanup-Image', '/RestoreHealth', '/NoRestart', '/English' -LogPath $LogPath -MaxMinutes $maxMinutes
}

function Invoke-DISMAnalyzeComponentStore {
    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$true)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout
    )
    $maxMinutes = 5 * $ChangeTimeout
    Write-Host "executing DISM Analyze Component Store (up to $maxMinutes min, Start $(Get-Date -Format 'HH:mm'))"
    Invoke-RepairTool -Name 'Dism.exe' -FilePath 'dism.exe' -ArgumentList '/online', '/Cleanup-Image', '/AnalyzeComponentStore', '/NoRestart', '/English' -LogPath $LogPath -MaxMinutes $maxMinutes
}

function Get-DISMAnalyzeComponentStoreResult {
    # $true = cleanup recommended (or the verdict is unknown), $false = not recommended.
    param([AllowEmptyString()][AllowNull()][string]$Content)
    return ($Content -notmatch 'Component Store Cleanup Recommended\s*:\s*No')
}

function Invoke-DISMComponentStoreCleanup {
    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$true)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout
    )
    $maxMinutes = 20 * $ChangeTimeout
    Write-Host "executing DISM Component Store Cleanup (up to $maxMinutes min, Start $(Get-Date -Format 'HH:mm'))"
    Invoke-RepairTool -Name 'Dism.exe' -FilePath 'dism.exe' -ArgumentList '/online', '/Cleanup-Image', '/StartComponentCleanup', '/NoRestart', '/English' -LogPath $LogPath -MaxMinutes $maxMinutes
}

function Get-CleanupBasePath {
    <#
    Resolves the OS folders every cleanup target is built from, on the machine being cleaned. A base is
    only accepted if it is absolute, below a drive root and exists; otherwise it is $null and callers
    skip the targets depending on it. An empty variable or failed lookup therefore never turns into a
    path at or near a drive root. Self-contained so it survives being shipped to a remote session.
    #>
    $firstValid = {
        foreach ($candidate in $args) {
            if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
            $candidate = ([string]$candidate).TrimEnd('\')
            if (($candidate -match '^[A-Za-z]:\\[^\\]') -and (Test-Path -LiteralPath $candidate -PathType Container)) {
                return $candidate
            }
        }
    }

    $windows  = & $firstValid ([Environment]::GetFolderPath('Windows')) $env:windir $env:SystemRoot
    $drive    = if ($windows) { Split-Path -Path $windows -Qualifier }
    $profiles = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory -ErrorAction SilentlyContinue).ProfilesDirectory

    @{
        ComputerName = $env:COMPUTERNAME
        Windows     = $windows
        SystemDrive = $drive
        ProgramData = & $firstValid ([Environment]::GetFolderPath('CommonApplicationData')) $env:ProgramData
        Profiles    = & $firstValid $profiles $(if ($drive) { "$drive\Users" })
    }
}

function Get-CCMCachePath {
    <#
    Location of the ConfigMgr client cache (relocatable). The WMI CacheConfig class can come back empty
    even on a healthy client, so this tries WMI -> UIResourceMgr COM (what Software Center reads) ->
    registry CacheConfig -> the default under Windows and returns the first non-empty value. The result
    is not validated - check it with Test-SafeCachePath before clearing it. Self-contained so it
    survives being shipped to a remote session.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Bases
    )
    $location = $null
    try { $location = (Get-CimInstance -Namespace 'root\ccm\SoftMgmtAgent' -ClassName CacheConfig -ErrorAction Stop | Select-Object -First 1).Location } catch { }
    if ([string]::IsNullOrWhiteSpace($location)) {
        try {
            $ui = New-Object -ComObject UIResource.UIResourceMgr
            $location = $ui.GetCacheInfo().Location
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($ui)
        } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($location)) {
        $location = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\CacheConfig' -Name Location -ErrorAction SilentlyContinue).Location
    }
    if ([string]::IsNullOrWhiteSpace($location) -and $Bases.Windows) { $location = Join-Path $Bases.Windows 'ccmcache' }
    return $location
}

function Test-SafeCachePath {
    <#
    A cache location comes from WMI/COM/registry, so a misconfigured value must never empty a key
    system folder: the path has to be absolute, at least one level below a drive root and existing, and
    must not be the Windows directory (or System32, SysWOW64, WinSxS, servicing, Installer,
    SoftwareDistribution below it), Program Files, ProgramData, the profiles directory or anything
    inside a user profile. No folder-name requirement: a relocated cache can be custom-named
    (D:\SCCMCache). Self-contained so it survives being shipped to a remote session.
    #>
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $normalized = $Path.TrimEnd('\')
    if ($normalized -notmatch '^[A-Za-z]:\\[^\\]+') { return $false }
    $protected = @(
        $env:ProgramFiles, ${env:ProgramFiles(x86)}, $Bases.ProgramData, $Bases.Profiles
        if ($Bases.Windows) {
            $Bases.Windows
            foreach ($sub in 'System32', 'SysWOW64', 'WinSxS', 'servicing', 'Installer', 'SoftwareDistribution') { Join-Path $Bases.Windows $sub }
        }
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.TrimEnd('\') }
    if ($protected -contains $normalized) { return $false }
    if ($Bases.Profiles -and $normalized.StartsWith($Bases.Profiles.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    return (Test-Path -LiteralPath $normalized -PathType Container)
}

function Invoke-ContentCacheCleanup {
    <#
    Clears the content/download caches of the software-distribution systems present on the device -
    ConfigMgr (ccmcache), Windows Update (SoftwareDistribution\Download), Adaptiva OneSite
    (<drive>:\AdaptivaCache) and the Intune Management Extension (IMECache + Content staging). Each
    location is auto-detected; systems that are not installed are skipped, and a location is only
    cleared after Test-SafeCachePath accepted it. Whatever a running agent holds open is cleared
    best-effort now and the remainder is scheduled for deletion on the next reboot (via
    Clear-FolderContentsReliable).
    Returns $true when anything was deferred to the next reboot. Identical in TempDataCleanup and
    Repair-System; self-contained apart from Get-CCMCachePath, Test-SafeCachePath and the bundled helpers,
    so it can be shipped to a remote session.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases,

        [string]$Component = 'ContentCache',

        # set when a Windows Update reset of the same run clears all of SoftwareDistribution anyway
        [switch]$SkipWindowsUpdate,

        [string]$TranscriptPath
    )
    if ($TranscriptPath) { Start-Transcript -Path $TranscriptPath -Append | Out-Null }

    $log = @{ LogPath = $LogPath; Component = $Component }
    Write-CMTraceLog @log 'Content cache cleanup (ConfigMgr / Windows Update / Adaptiva / Intune)'

    # -----------------------------------------------------------------------------------------------
    # Detect each system's cache location(s). Absent systems yield nothing and are simply skipped;
    # paths are only built from the validated base folders.
    # -----------------------------------------------------------------------------------------------
    $ccmLocation = Get-CCMCachePath -Bases $Bases
    $ccmPaths    = @(if (-not [string]::IsNullOrWhiteSpace($ccmLocation)) { $ccmLocation })
    $wuPaths     = @(if ($Bases.Windows) { Join-Path $Bases.Windows 'SoftwareDistribution\Download' })

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
    $intunePaths = @(if ($Bases.Windows) { Join-Path $Bases.Windows 'IMECache' })
    $imeBases = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    foreach ($base in $imeBases) {
        $imeContent = Join-Path $base 'Microsoft Intune Management Extension\Content'
        if (Test-Path -LiteralPath $imeContent -PathType Container) {
            foreach ($sub in @('Incoming','Staging','Staged')) { $intunePaths += (Join-Path $imeContent $sub) }
        }
    }

    $providers = @(
        @{ Name = 'ConfigMgr (ccmcache)';                          Paths = $ccmPaths }
        @{ Name = 'Windows Update (SoftwareDistribution\Download)'; Paths = $wuPaths; WindowsUpdate = $true }
        @{ Name = 'Adaptiva OneSite (AdaptivaCache)';              Paths = $adaptivaPaths }
        @{ Name = 'Intune Management Extension (IMECache/Content)'; Paths = $intunePaths }
    )

    # -----------------------------------------------------------------------------------------------
    # Clear every detected, trusted cache location; defer whatever is locked to the next reboot.
    # -----------------------------------------------------------------------------------------------
    $anyDeferred = $false
    foreach ($prov in $providers) {
        if ($prov.WindowsUpdate -and $SkipWindowsUpdate) {
            Write-CMTraceLog @log "$($prov.Name): left to the Windows Update cleanup step."
            continue
        }
        $cleaned = New-Object System.Collections.Generic.List[string]
        $skipped = New-Object System.Collections.Generic.List[string]
        $left    = New-Object System.Collections.Generic.List[string]
        foreach ($p in @($prov.Paths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
            if (-not (Test-SafeCachePath -Path $p -Bases $Bases)) {
                $skipped.Add("'$p'")
                continue
            }
            if ($prov.WindowsUpdate) {
                $wu = Clear-WindowsUpdateDownload -Folder $p
                if ($wu.Skipped) { $left.Add("$p ($($wu.Skipped))"); continue }
                if ($wu.Postponed) { $anyDeferred = $true; $cleaned.Add("$p (queued for the next boot: $($wu.Postponed))"); continue }
                $deferred = $wu.Deferred
            } else {
                $deferred = Clear-FolderContentsReliable -Folder $p
            }
            if ($deferred) {
                $anyDeferred = $true
                $cleaned.Add("$p (locked items deferred to reboot)")
            } else {
                $cleaned.Add($p)
            }
        }
        $parts = @()
        if ($cleaned.Count -gt 0) { $parts += "cleaned $($cleaned -join '; ')" }
        if ($left.Count -gt 0)    { $parts += "left untouched $($left -join '; ')" }
        if ($skipped.Count -gt 0) { $parts += "skipped $($skipped -join ', ') (not found or path could not be trusted)" }
        if ($parts.Count -eq 0)   { $parts += 'nothing to clean (not installed or no cache present)' }
        $result = "$($prov.Name): $($parts -join '; ')."
        Write-CMTraceLog @log $result
    }

    if ($anyDeferred) { Write-CMTraceLog @log 'One or more locked cache items were scheduled for deletion on the next reboot (restart required).' -Severity Warning }
    if ($TranscriptPath) { Stop-Transcript | Out-Null }
    return $anyDeferred
}
function Invoke-ContentCacheCleanupStep {
    # Step entry point: Repair-System records step results as exit codes, the shared cleanup returns a bool.
    param(
        [Parameter(Mandatory=$true)] [string]$LogPath,
        [Parameter(Mandatory=$true)] [hashtable]$Bases,
        [switch]$SkipWindowsUpdate
    )
    Write-Host "executing Content Cache Cleanup"
    if (Invoke-ContentCacheCleanup -LogPath $LogPath -Bases $Bases -Component 'ContentCacheCleanup' -SkipWindowsUpdate:$SkipWindowsUpdate) { 3010 } else { 0 }
}

function Clear-WindowsUpdateDownload {
    <#
    Empties SoftwareDistribution\Download the way Microsoft's Windows Update reset does: wuauserv and
    BITS hold and recreate files there, so both are force-stopped first - an interrupted download is
    simply fetched again - and afterwards only those that were running are started again. A service
    that ignores the stop is killed only when it runs alone in its process; a shared svchost would take
    other services with it, so its files are left to the next reboot instead. An installation in
    progress (TiWorker.exe) is never interrupted - that can leave the component store inconsistent - but
    waited for up to $WaitMinutes; if it is still running then, the folder's contents are queued for
    deletion at the next boot instead, which runs before Windows Update starts and after the
    installation has finished. Returns Deferred (anything queued for the next reboot), Postponed (why
    the whole folder waits for the reboot) and Skipped (why nothing could be done). Self-contained apart
    from Clear-FolderContentsReliable and Register-PendingDelete.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Folder,
        [int]$WaitMinutes = 10
    )
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    while ((Get-Process -Name 'TiWorker' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 5 }
    if (Get-Process -Name 'TiWorker' -ErrorAction SilentlyContinue) {
        $reason = "an update was still being installed (TiWorker.exe) after $WaitMinutes minutes"
        $items  = @(Get-ChildItem -LiteralPath $Folder -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        if ($items.Count -eq 0) { return [pscustomobject]@{ Deferred = $false; Postponed = $null; Skipped = $null } }
        try {
            $null = Register-PendingDelete -Path $items
            return [pscustomobject]@{ Deferred = $true; Postponed = $reason; Skipped = $null }
        } catch {
            return [pscustomobject]@{ Deferred = $false; Postponed = $null; Skipped = "$reason, and queueing it for the next boot failed: $($_.Exception.Message)" }
        }
    }

    $names   = 'wuauserv', 'bits'
    $running = @(Get-Service -Name $names -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' })
    $running | Stop-Service -Force -NoWait -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and @(Get-Service -Name $names -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' }).Count) {
        Start-Sleep -Milliseconds 500
    }
    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.Name -and $_.ProcessId })) {
        $sharing = @(Get-CimInstance -ClassName Win32_Service -Filter "ProcessId=$($service.ProcessId)" -ErrorAction SilentlyContinue).Count
        if ($sharing -eq 1) { Stop-Process -Id $service.ProcessId -Force -ErrorAction SilentlyContinue }
    }
    $deferred = $false
    try { $deferred = [bool](Clear-FolderContentsReliable -Folder $Folder) }
    finally { $running | Start-Service -ErrorAction SilentlyContinue }
    [pscustomobject]@{ Deferred = $deferred; Postponed = $null; Skipped = $null }
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

    # A service that ignores the stop is killed only when it runs alone in its process: a shared svchost
    # would take every other service in it down too. Its files are then left to the next reboot.
    foreach ($svc in $stillRunning) {
        try {
            $svcProcessId = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction Stop).ProcessId
            if (-not $svcProcessId) { continue }
            $sharing = @(Get-CimInstance -ClassName Win32_Service -Filter "ProcessId=$svcProcessId" -ErrorAction Stop | Where-Object { $_.Name -ne $svc.Name })
            if ($sharing.Count -gt 0) {
                Write-Warning "Service '$($svc.Name)' did not stop within $TimeoutSeconds seconds; its process also hosts $($sharing.Name -join ', '), so it is left running."
                continue
            }
            Write-Warning "Service '$($svc.Name)' did not stop within $TimeoutSeconds seconds. Stopping its process forcefully..."
            Stop-Process -Id $svcProcessId -Force -ErrorAction Stop
            Write-Verbose "Process (PID $svcProcessId) backing service '$($svc.Name)' was forcefully stopped."
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

    -BestEffort stops after the immediate delete: locked items are neither scheduled for reboot nor
    reported as an error. Used for user-profile temp, where boot-time deletion of a locked user file
    (eg. an open browser's cache) is not wanted.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [switch]$BestEffort
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

    # -BestEffort: stop here - do not schedule locked items for reboot.
    if ($BestEffort) { return $result }

    # 2) Whatever survived is locked - schedule the remainder for deletion at next boot.
    try {
        $null = Register-PendingDelete -Path $Path
        $result.Scheduled = $true
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Register-PendingDelete {
    <#
    Queues paths for deletion at the next boot via the Session Manager's PendingFileRenameOperations,
    which runs before anything can load them again. A directory is expanded to its contents
    deepest-first (enumerated through \\?\, so locked trees and paths over 260 characters work), so each
    directory is empty by the time its own entry is processed. Entries Windows already had pending are
    kept and paths already queued are not added twice; the value is read and written once per call, so
    pass all locked items together. Returns the paths it added. A drive root or top-level folder is
    never queued: such a path is reported by throwing once everything else is queued. Identical in
    TempDataCleanup, Repair-System and AutoDeskCleanRemove; self-contained for remote shipping.
    #>
    param([Parameter(Mandatory=$true)][string[]]$Path)
    $smKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $pending = New-Object System.Collections.Generic.List[string]
    $queued  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $current = @((Get-ItemProperty -Path $smKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations | Where-Object { $null -ne $_ })
    $pending.AddRange([string[]]$current)
    # entries are source/destination pairs; an empty destination means 'delete'
    for ($i = 0; $i + 1 -lt $current.Count; $i += 2) {
        if ($current[$i + 1] -eq '') { [void]$queued.Add($current[$i]) }
    }

    $added   = New-Object System.Collections.Generic.List[string]
    $refused = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Path) {
        $root = $item -replace '^\\\\\?\\', ''
        if ($root -notmatch '^[A-Za-z]:\\[^\\]+\\[^\\]') { $refused.Add($item); continue }
        $targets = @(Get-ChildItem -LiteralPath "\\?\$root" -Recurse -Force -ErrorAction SilentlyContinue |
                     ForEach-Object { $_.FullName.Substring(4) } |
                     Sort-Object { $_.Length } -Descending) + $root
        foreach ($target in $targets) {
            if ($queued.Add("\??\$target")) {
                $pending.Add("\??\$target")
                $pending.Add('')
                $added.Add($target)
            }
        }
    }
    if ($added.Count -gt 0) {
        Set-ItemProperty -Path $smKey -Name PendingFileRenameOperations -Value $pending.ToArray() -Type MultiString -ErrorAction Stop
    }
    if ($refused.Count -gt 0) { throw "Refused to schedule $($refused -join ', ') for deletion: not a safe target." }
    $added.ToArray()
}

function Clear-FolderContentsReliable {
    <#
    Deletes the CONTENTS of a folder (the folder itself is kept, matching temp-cleanup behaviour) by
    routing every child through Remove-PathReliable. Whatever is still locked is queued for deletion at
    the next reboot in one go; -BestEffort skips that (used for user-profile temp). Returns $true if
    anything was deferred to the next reboot.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Folder,

        [switch]$BestEffort
    )
    if (-not (Test-Path -LiteralPath $Folder)) { return $false }
    # Refused items carry an Error and are never queued; only genuinely locked ones are collected.
    $locked = @(Get-ChildItem -LiteralPath $Folder -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $r = Remove-PathReliable -Path $_.FullName -BestEffort
        if (-not $r.Deleted -and -not $r.Error) { $_.FullName }
    })
    if ($BestEffort -or $locked.Count -eq 0) { return $false }
    try {
        $null = Register-PendingDelete -Path $locked
        return $true
    } catch {
        return $false
    }
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
    $log = { param($m, $s = 'Info') Write-StepLogLine $LogPath "DataStore: $m" 'WUCleanup' $s }
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
                & $log 'Recovery failed - DataStore will be wiped (skipping /g).' Warning
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
    & $log '/g: still failing after repair - DataStore will be wiped.' Warning
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
    $log = { param($m, $s = 'Info') Write-StepLogLine $LogPath "Legacy: $m" 'WUCleanup' $s }

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
    param(
        [Parameter(Mandatory=$true)]
        [string]$updateCleanupLog,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases,

        # Force-wipe the DataStore even when it is healthy (loses update history).
        [bool]$ResetUpdateHistory = $false,

        # Already-confirmed decision to run the legacy repair (confirmation happens in the caller).
        [bool]$DoLegacyRepair = $false,

        # How long an installation in progress is waited for before the reset is queued for the next boot.
        [int]$WaitMinutes = 10
    )
    $log = { param($m, $s = 'Info') Write-StepLogLine $updateCleanupLog $m 'WUCleanup' $s }
    $deferred = $false   # any deletion scheduled for reboot
    $failed   = $false

    Write-Host "Starting Windows Update Cleanup..."

    # A running task sequence drives Windows Update itself and would interfere with the reset, so it is stopped.
    $taskSequence = @(Get-Process -Name 'TSManager' -ErrorAction SilentlyContinue)
    if ($taskSequence) {
        $taskSequence | Stop-Process -Force -ErrorAction SilentlyContinue
        $m = if (Get-Process -Name 'TSManager' -ErrorAction SilentlyContinue) { 'A ConfigMgr task sequence (TSManager.exe) is running and could not be stopped.' }
             else { 'A running ConfigMgr task sequence (TSManager.exe) was stopped.' }
        Write-Warning $m
        & $log $m Warning
    }

    # Paths are only built from the validated Windows directory (see Get-CleanupBasePath) - an empty
    # base is how a cleanup ends up deleting from a drive root. Remove-PathReliable adds a second guard.
    $winDir = $Bases.Windows
    $winDirValid = -not [string]::IsNullOrWhiteSpace($winDir)
    if (-not $winDirValid) {
        Write-Warning "Windows directory could not be resolved; skipping SoftwareDistribution and catroot2 reset."
        & $log 'Windows directory could not be resolved; skipping SoftwareDistribution and catroot2 reset.' Error
        $failed = $true
    }
    $sdPath    = if ($winDirValid) { Join-Path $winDir 'SoftwareDistribution' } else { $null }
    $dsPath    = if ($winDirValid) { Join-Path $winDir 'SoftwareDistribution\DataStore' } else { $null }
    $catroot2  = if ($winDirValid) { Join-Path $winDir 'System32\catroot2' } else { $null }
    $bitsQueue = if ($Bases.ProgramData) { Join-Path $Bases.ProgramData 'Microsoft\Network\Downloader' } else { $null }

    # Stopping cryptsvc or the update services under a running servicing or MSI installation can leave
    # it half-applied, so wait for it; if it outlasts the wait, the files are reset at the next boot,
    # before any of these services start.
    $installActivity = {
        if (Get-Process -Name 'TiWorker' -ErrorAction SilentlyContinue) { return 'an update is being installed (TiWorker.exe)' }
        try { ([System.Threading.Mutex]::OpenExisting('Global\_MSIExecute')).Dispose(); return 'an MSI installation is running' }
        catch {
            if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.InnerException -is [System.UnauthorizedAccessException]) { return 'an MSI installation is running' }
        }
        $null
    }
    $activity = & $installActivity
    if ($activity) {
        Write-Host "Waiting up to $WaitMinutes minutes: $activity..."
        & $log "Waiting up to $WaitMinutes minutes: $activity."
        $deadline = (Get-Date).AddMinutes($WaitMinutes)
        while ($activity -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 5; $activity = & $installActivity }
    }
    if ($activity) {
        $items = @()
        if ($sdPath -and (Test-Path -LiteralPath $sdPath)) {
            $items += @(Get-ChildItem -LiteralPath $sdPath -Force -ErrorAction SilentlyContinue |
                        Where-Object { $ResetUpdateHistory -or $_.Name -ine 'DataStore' } | ForEach-Object { $_.FullName })
        }
        if ($catroot2 -and (Test-Path -LiteralPath $catroot2)) { $items += $catroot2 }
        if ($bitsQueue -and (Test-Path -LiteralPath $bitsQueue)) {
            $items += @(Get-ChildItem -LiteralPath $bitsQueue -Filter 'qmgr*' -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        }
        try { if ($items) { $null = Register-PendingDelete -Path $items } }
        catch {
            $m = "Still $activity after $WaitMinutes minutes, and queueing the reset for the next boot failed: $($_.Exception.Message)"
            Write-Warning $m
            & $log $m Error
            return 1
        }
        $kept = if ($ResetUpdateHistory) { '' } else { ', keeping the update history' }
        $m = "Still $activity after $WaitMinutes minutes; no service was stopped. SoftwareDistribution$kept, catroot2 and the BITS queue are reset at the next boot instead."
        Write-Warning $m
        & $log $m Warning
        if ($DoLegacyRepair) {
            & $log 'The legacy repair was not run; run Repair-System -WindowsUpdateCleanup -IncludeLegacyRepair again after the restart.' Warning
            Write-Warning 'The legacy repair was not run; run it again after the restart.'
        }
        return 3010
    }

    # The update services Microsoft's reset stops. Update Medic, Orchestrator and Delivery Optimization
    # go first so they can't restart the others. Only services that were running are started again,
    # including dependents that Stop-Service -Force takes down with them.
    $servicesStop = @('waasmedicsvc', 'usosvc', 'dosvc', 'wuauserv', 'bits', 'cryptsvc', 'appidsvc')
    $stopped = @(Get-Service -Name $servicesStop -ErrorAction SilentlyContinue | ForEach-Object { $_; $_.DependentServices } |
                 Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name -Unique)
    Stop-ServiceSafely -ServiceName $servicesStop -Force

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
            # Locked children are collected and queued for reboot in one PendingFileRenameOperations write.
            $locked = @(foreach ($child in (Get-ChildItem -LiteralPath $sdPath -Force -ErrorAction SilentlyContinue)) {
                if ($child.Name -ieq 'DataStore') { continue }
                $r = Remove-PathReliable -Path $child.FullName -BestEffort
                if ($r.Error) { & $log "SoftwareDistribution\$($child.Name): $($r.Error)" }
                elseif (-not $r.Deleted) { $child.FullName }
            })
            if ($locked) {
                try { $null = Register-PendingDelete -Path $locked; $deferred = $true }
                catch { & $log "SoftwareDistribution: locked items could not be queued for reboot: $_" Warning }
            }
        } else {
            Write-Host "Resetting SoftwareDistribution..."
            $r = Remove-PathReliable -Path $sdPath
            if ($r.Scheduled) { $deferred = $true }
            if ($r.Error)     { & $log "SoftwareDistribution: $($r.Error)" Error; $failed = $true }
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
        if ($r.Error)     { & $log "catroot2: $($r.Error)" Error; $failed = $true }
    }

    # --- BITS transfer queue: drop stuck transfers by clearing qmgr* ------------------------------
    if ($bitsQueue -and (Test-Path -LiteralPath $bitsQueue)) {
        Write-Host "Clearing BITS transfer queue..."
        $locked = @(foreach ($q in (Get-ChildItem -LiteralPath $bitsQueue -Filter 'qmgr*' -Force -ErrorAction SilentlyContinue)) {
            $r = Remove-PathReliable -Path $q.FullName -BestEffort
            if ($r.Error) { & $log "BITS queue $($q.Name): $($r.Error)" }
            elseif (-not $r.Deleted) { $q.FullName }
        })
        if ($locked) {
            try { $null = Register-PendingDelete -Path $locked; $deferred = $true }
            catch { & $log "BITS queue: locked files could not be queued for reboot: $_" Warning }
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
    if ($stopped) {
        Get-Service -Name $stopped -ErrorAction SilentlyContinue | Start-Service -ErrorAction SilentlyContinue
        $notRestarted = @(Get-Service -Name $stopped -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Running' } | ForEach-Object { $_.Name })
        if ($notRestarted) { & $log "Not running again after the cleanup: $($notRestarted -join ', ')." Warning }
    }

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
    param(
        [Parameter(Mandatory=$true)]
        [string]$RepairCCMLog,

        # Where the copy of ccmsetup.log is stored, next to the step log.
        [Parameter(Mandatory=$true)]
        [string]$CCMSetupLogCopy,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases
    )

    $log = { param($m, $s = 'Info') Write-StepLogLine $RepairCCMLog $m 'RepairCCM' $s }

    if (-not $Bases.Windows) {
        Write-Host "Windows directory could not be resolved; CCM repair skipped."
        & $log "Windows directory could not be resolved; the CCM client cannot be located." Error
        return 1
    }
    $winDir = $Bases.Windows
    $ccmrepairexe = Join-Path $winDir 'CCM\ccmrepair.exe'

    if (-not (Test-Path $ccmrepairexe)) {
        Write-Host "CCMRepair executable not found."
        & $log "CCMRepair executable not found at $ccmrepairexe." Error
        return 1
    }

    try {
        # Restart SCCM Client Service
        Write-Host "Restarting SCCM Service..."
        & $log "Restarting SCCM Service..."

        $stopProcessErrors = $null
        Stop-Process -Name SCClient,CcmExec -Force -ErrorAction SilentlyContinue -ErrorVariable stopProcessErrors
        foreach ($stopProcessError in $stopProcessErrors) {
            & $log "Failed to stop process: $stopProcessError" Error
        }

        # If the client is not registered in WMI (root\ccm unreachable), re-register its WMI classes
        # by recompiling the client MOFs - a broken WMI store otherwise blocks detection and repair.
        # Done here with CcmExec stopped, before the service is restarted.
        $ccmDir   = Split-Path $ccmrepairexe -Parent
        $ccmWmiOk = try { [bool](Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Client -ErrorAction Stop) } catch { $false }
        if (-not $ccmWmiOk) {
            Write-Host "CCM is not registered in WMI; re-registering client MOFs..."
            & $log "CCM not registered in WMI (root\ccm unreachable). Re-registering WMI classes via mofcomp from '$ccmDir'..."
            if (Test-Path -LiteralPath $ccmDir -PathType Container) {
                $mofcomp = Join-Path $winDir 'System32\wbem\mofcomp.exe'
                Get-ChildItem -LiteralPath $ccmDir -Filter '*.mof' -File -ErrorAction SilentlyContinue | ForEach-Object {
                    & $mofcomp $_.FullName 2>&1 | Out-Null
                }
                $ccmWmiOk = try { [bool](Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Client -ErrorAction Stop) } catch { $false }
                & $log "WMI re-registration attempted; root\ccm accessible now: $ccmWmiOk."
            } else {
                & $log "CCM directory '$ccmDir' not found; cannot re-register WMI classes." Warning
            }
        } else {
            & $log "CCM is registered in WMI (root\ccm accessible)."
        }

        $restartServiceErrors = $null
        Restart-Service CcmExec -Force -ErrorAction SilentlyContinue -ErrorVariable restartServiceErrors
        foreach ($restartServiceError in $restartServiceErrors) {
            & $log "Failed to restart service CcmExec: $restartServiceError" Error
        }

        Start-Sleep -Seconds 10

        # Run SCCM Client Repair
        Write-Host "Starting CCMRepair... This may take a while (~30min)."
        & $log "Starting CCMRepair..."
        # Run with an enforced ceiling so a hung ccmrepair can't block the whole repair run.
        $ccmRepairMaxMinutes = 45
        $ccmProc = Start-Process -FilePath $ccmrepairexe -PassThru -NoNewWindow -ErrorAction Stop
        if ($ccmProc.WaitForExit($ccmRepairMaxMinutes * 60000)) {
            & $log "CCMRepair process finished."
        } else {
            Write-Warning "CCMRepair exceeded $ccmRepairMaxMinutes minutes; terminating it."
            & $log "CCMRepair exceeded $ccmRepairMaxMinutes minutes; terminating it."
            try { $ccmProc.Kill(); [void]$ccmProc.WaitForExit(30000) } catch { }
        }

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
                        & $log "ccmsetup.log result: $logMessage"
                    }
                }
            }
            try {
                Copy-Item -LiteralPath "$ccmSetupLogFolder\$ccmsetupLogFile" -Destination $CCMSetupLogCopy -Force -ErrorAction Stop
                & $log "Copied $ccmsetupLogFile to $CCMSetupLogCopy."
            } catch {
                Write-Host "CCMSetup log file could not be copied."
                & $log "CCMSetup log file could not be copied to ${CCMSetupLogCopy}: $_" Warning
            }
        } else {
            Write-Host "CCMSetup log file not found."
            & $log "CCMSetup log file not found at $ccmSetupLogFolder\$ccmsetupLogFile."
        }

        # Clear SCCM Cache
        Write-Host "Clearing SCCM Cache..."
        & $log "Clearing SCCM Cache..."
        $ccmCachePath = Get-CCMCachePath -Bases $Bases
        if (Test-SafeCachePath -Path $ccmCachePath -Bases $Bases) {
            Clear-FolderContentsReliable -Folder $ccmCachePath -BestEffort | Out-Null
            & $log "SCCM Cache cleared ($ccmCachePath)."
        } else {
            & $log "SCCM Cache folder not found or its path could not be trusted ('$ccmCachePath'). No need to clear."
        }

        # Trigger SCCM Cycles
        Write-Host "Triggering SCCM Client Actions..."
        & $log "Triggering SCCM Client Actions..."
        $SCCMActions = [ordered]@{
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

        $failedActions = 0
        foreach ($Action in $SCCMActions.GetEnumerator()) {
            Write-Host "  - $($Action.Key)"
            & $log "Triggering: $($Action.Key)..."
            try {
                Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{ sScheduleID = $Action.Value } -ErrorAction Stop | Out-Null
                & $log "  - OK: $($Action.Key)"
            } catch {
                $failedActions++
                & $log "  - triggering '$($Action.Key)' failed: $_" Error
            }
        }
        $triggerSummary = if ($failedActions -eq 0) { "All SCCM Client Actions triggered." }
                          else { "Triggered $($SCCMActions.Count - $failedActions) of $($SCCMActions.Count) SCCM Client Actions; $failedActions failed (see log)." }
        Write-Host $triggerSummary
        & $log $triggerSummary
    } catch {
        $errorMessage = "Failed to repair CCM: $_"
        Write-Error $errorMessage
        & $log $errorMessage Error
        return 1
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
    session. Returns 0 (consistent or successfully salvaged) or 1 (still inconsistent / could not
    complete).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$WMIRepairLog,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases
    )

    $log = { param($m, $s = 'Info') Write-StepLogLine $WMIRepairLog $m 'WMIRepair' $s }

    # winmgmt sets a NON-ZERO exit code when the repository is inconsistent and 0 when consistent - a
    # locale-independent signal, unlike the (localised) verdict text, so the EXIT CODE drives the
    # decision and the text is only captured for the log. The time limit guards against a wedged WMI
    # service. Returns @{ ExitCode; Output; TimedOut }.
    $invokeWinmgmt = {
        param([string]$WinmgmtArg, [int]$TimeoutSec)
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo -ArgumentList (Join-Path $Bases.Windows 'System32\wbem\winmgmt.exe'), $WinmgmtArg
        $startInfo.UseShellExecute        = $false
        $startInfo.CreateNoWindow         = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError  = $true
        $process = [System.Diagnostics.Process]::Start($startInfo)
        # both streams are read asynchronously so a full pipe can't stall the process
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSec * 1000)) {
            try { $process.Kill() } catch { }
            return @{ ExitCode = -2; Output = 'winmgmt timed out'; TimedOut = $true }
        }
        @{ ExitCode = $process.ExitCode; Output = ($stdout.Result + $stderr.Result).Trim(); TimedOut = $false }
    }

    if (-not $Bases.Windows) {
        & $log "Windows directory could not be resolved; winmgmt cannot be located." Error
        return 1
    }

    try {
        Write-Host "Verifying WMI repository (winmgmt /verifyrepository)..."
        & $log "Verifying WMI repository (winmgmt /verifyrepository)..."
        $verify = & $invokeWinmgmt '/verifyrepository' 60
        & $log "verifyrepository exit=$($verify.ExitCode); output:`r`n`t$($verify.Output)"

        if ($verify.TimedOut) {
            Write-Warning "WMI /verifyrepository timed out; the WMI service may be wedged."
            & $log "verifyrepository timed out. Aborting WMI repair (non-destructive step)."
            return 1
        }

        if ($verify.ExitCode -eq 0) {
            Write-Host "WMI repository is consistent; no repair needed."
            & $log "WMI repository is consistent (verify exit 0); no repair needed."
            return 0
        }

        Write-Host "WMI repository is inconsistent; salvaging (winmgmt /salvagerepository)..."
        & $log "WMI repository reported inconsistent (verify exit $($verify.ExitCode)). Running winmgmt /salvagerepository..."
        $salvage = & $invokeWinmgmt '/salvagerepository' 300
        & $log "salvagerepository exit=$($salvage.ExitCode); output:`r`n`t$($salvage.Output)"
        if ($salvage.TimedOut) {
            Write-Warning "WMI /salvagerepository timed out; the WMI service may be wedged."
            & $log "salvagerepository timed out. WMI repository still needs attention."
            return 1
        }

        # The salvage command's own exit code is not conclusive; re-verify to confirm consistency.
        Write-Host "Re-verifying WMI repository after salvage..."
        & $log "Re-verifying WMI repository after salvage..."
        $reverify = & $invokeWinmgmt '/verifyrepository' 60
        & $log "post-salvage verifyrepository exit=$($reverify.ExitCode); output:`r`n`t$($reverify.Output)"

        if (-not $reverify.TimedOut -and $reverify.ExitCode -eq 0) {
            Write-Host "WMI repository salvaged; now consistent."
            & $log "WMI repository salvaged successfully; re-verify reports consistent."
            return 0
        }

        Write-Warning "WMI repository is still inconsistent after salvage."
        & $log "WMI repository still inconsistent after salvage. A manual 'winmgmt /resetrepository' may be required; not attempted (non-destructive step)."
        return 1
    } catch {
        $err = "An error occurred during WMI repository repair:`r`n$_"
        Write-Warning $err
        & $log $err Error
        return 1
    }
}

function Start-ZipFileCreation {
    <#
    Zips the CBS (and, unless -noDism, the DISM) system log into $ZipFile. The logs are copied into
    the temp folder first because the live files stay open; the copies are deleted afterwards (queued
    for the next reboot if still locked). A failure is written to $ZipErrorLog. Self-contained apart
    from Write-CMTraceLog, Remove-PathReliable and Register-PendingDelete, so it can run as a
    background job on the target.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$TempPath,

        [Parameter(Mandatory=$true)]
        [string]$ZipFile,

        [Parameter(Mandatory=$true)]
        [string]$ZipErrorLog,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases,

        [switch]$noDism
    )
    $filesToZip = @()
    try {
        if (-not $Bases.Windows) { throw "the Windows directory could not be resolved" }
        $sources = @(Join-Path $Bases.Windows 'Logs\CBS\CBS.log')
        if (-not $noDism) { $sources += Join-Path $Bases.Windows 'Logs\dism\dism.log' }
        foreach ($source in $sources) {
            if (Test-Path -LiteralPath $source) {
                Copy-Item -LiteralPath $source -Destination $TempPath -Force -ErrorAction Stop
                $filesToZip += Join-Path $TempPath (Split-Path $source -Leaf)
            }
        }
        if ($filesToZip.Count -gt 0) {
            Compress-Archive -LiteralPath $filesToZip -DestinationPath $ZipFile -Force -ErrorAction Stop
        }
        $exitCode = 0
    } catch {
        $errorMessage = "An error occurred while creating the zip file: $_"
        Write-CMTraceLog $errorMessage 'ZipCreation' $ZipErrorLog Error
        Write-Error $errorMessage
        $exitCode = 1
    }
    foreach ($file in $filesToZip) { $null = Remove-PathReliable -Path $file }
    return $exitCode
}

function Test-DismSfcStepIncomplete {
    <#
    Decides whether a DISM or SFC step that actually RAN failed to truly complete - and therefore
    warrants a reboot re-run. Returns $true when: the step was timed out (-2) or terminated
    externally (-3); its captured log is missing or empty (it never really started); its log lacks
    the tool's completion marker (killed mid-run); or the log reports a reboot-pending / could-not-
    repair condition. DISM runs with /English; for SFC the CBS.log summary line written by
    Invoke-SFC decides, the English console text is only a fallback when CBS.log was unreadable.
    #>
    param(
        [Parameter(Mandatory=$true)] [int]$ResultCode,
        [AllowEmptyString()] [AllowNull()] [string]$Content,
        [Parameter(Mandatory=$true)] [ValidateSet('SFC','DISM')] [string]$Kind
    )
    if ($ResultCode -eq -4) { return $false }          # requested-but-not-executed: did not run, fine
    if ($ResultCode -eq -2 -or $ResultCode -eq -3) { return $true }   # timed out / terminated externally
    if ([string]::IsNullOrWhiteSpace($Content)) { return $true }      # empty / could not start

    if ($Kind -eq 'SFC' -and $Content -match 'Repair-System SFC result \(CBS\.log\): Finished=(\w+); Repaired=\d+; Unrepairable=(\d+)') {
        return ($Matches[1] -ne 'True' -or [int]$Matches[2] -gt 0)
    }
    if ($Content -match 'system repair pending|unable to fix some of them|could not perform the requested operation') { return $true }

    $completed = if ($Kind -eq 'SFC') {
        ($Content -match 'Windows Resource Protection') -and
        ($Content -match 'did not find any integrity violations|successfully repaired them|found corrupt files|Verification 100% complete')
    } else {
        $Content -match 'The operation completed successfully|No component store corruption detected|The component store is repairable|Component Store Cleanup Recommended'
    }
    return (-not $completed)
}

function Invoke-DismSfcRebootRepair {
    <#
    Entry point for the scheduled reboot re-run. Runs at next boot as SYSTEM. Re-runs the full
    conditional DISM + SFC flow (RestoreHealth -> AnalyzeComponentStore ->
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

    if (-not (Test-Path -LiteralPath $RepairFolder)) { New-SecureDirectory -Path $RepairFolder -UsersRead }
    $pc        = $env:COMPUTERNAME
    $runPrefix = Join-Path $RepairFolder "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')_${pc}_RepairSystem"
    $masterLog = "${runPrefix}_RebootRerun.log"
    $stepLogs  = [System.Collections.Generic.List[string]]::new()

    Write-CMTraceLog -Message "Repair-System reboot re-run started (DISM/SFC);`r`nTarget: $pc; Reason: a DISM/SFC step did not complete during the previous run; single automatic attempt;" -Component "RebootRerun" -LogPath $masterLog

    # Runs one DISM/SFC step, embeds its log and returns its result code and log content.
    $runStep = {
        param($worker, $component, $stepName)
        $stepLog = "${runPrefix}_$component.log"
        $stepLogs.Add($stepLog)
        $exitCode = [int]((& $worker -LogPath $stepLog -ChangeTimeout $ChangeTimeout) | Select-Object -Last 1)
        $content = Get-Content -LiteralPath $stepLog -Raw -ErrorAction SilentlyContinue
        Write-CMTraceLog -Message "$stepName completed; ExitCode=$exitCode;" -Component $component -LogPath $masterLog
        Add-RepairStepLog -Content $content -MasterLogPath $masterLog -StepName $component -Component $component
        $errLog = $stepLog -replace '\.log$', '_stderr.log'
        if ((Test-Path -LiteralPath $errLog) -and (Get-Item -LiteralPath $errLog).Length -gt 0) {
            Write-CMTraceLog -Message "$stepName wrote to stderr: $errLog" -Component $component -LogPath $masterLog -Severity Warning
        }
        @{ ExitCode = $exitCode; Content = $content }
    }

    $null = & $runStep 'Invoke-DISMRestore' 'DISM-RestoreHealth' 'DISM RestoreHealth'
    $analyze = & $runStep 'Invoke-DISMAnalyzeComponentStore' 'DISM-Analyze' 'DISM AnalyzeComponentStore'
    if ($analyze.ExitCode -eq 0 -and (Get-DISMAnalyzeComponentStoreResult -Content $analyze.Content)) {
        $null = & $runStep 'Invoke-DISMComponentStoreCleanup' 'DISM-ComponentCleanup' 'DISM ComponentStoreCleanup'
    } elseif ($analyze.ExitCode -eq 3010 -and (Get-DISMAnalyzeComponentStoreResult -Content $analyze.Content)) {
        Write-CMTraceLog -Message "A component store cleanup is recommended, but a restart is pending; StartComponentCleanup postponed. Restart $pc and run Repair-System -IncludeComponentCleanup." -Component "DISM-ComponentCleanup" -LogPath $masterLog -Severity Warning
    }
    $null = & $runStep 'Invoke-SFC' 'SFC' 'SFC /scannow'

    Write-CMTraceLog -Message "Repair-System reboot re-run completed;`r`nNo further re-runs are scheduled (single attempt by design). Log: $masterLog;" -Component "RebootRerun" -LogPath $masterLog

    # self-cleanup: the step logs are embedded in the master log, so remove them and the generated
    # script's folder (queued for the next reboot if locked) - the master log and any non-empty stderr stay.
    foreach ($file in @($stepLogs) + (Split-Path -Path $SelfScriptPath -Parent)) {
        if ((Remove-PathReliable -Path $file).Scheduled) {
            Write-CMTraceLog -Message "$file is locked; queued for deletion on the next restart." -Component "RebootRerun" -LogPath $masterLog
        }
    }
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
        [Parameter(Mandatory=$true)] [decimal]$ChangeTimeout,
        [Parameter(Mandatory=$true)] [hashtable]$Target
    )
    $taskName = 'RepairSystem-RebootRerun'

    # Bundle the worker functions + the orchestrator into one script, then append the entry call. The
    # log folder and the script's own path are resolved on the target when it runs.
    $bundle = @('New-SecureDirectory','Write-CMTraceLog','Add-RepairStepLog',
                'Get-RepairSystemProcessResult','Remove-PathReliable','Register-PendingDelete','Invoke-RepairTool',
                'Invoke-DISMRestore',
                'Invoke-DISMAnalyzeComponentStore','Get-DISMAnalyzeComponentStoreResult',
                'Invoke-DISMComponentStoreCleanup','Get-SfcCbsSummary','Invoke-SFC','Invoke-DismSfcRebootRepair')
    $scriptText = "# Auto-generated by Repair-System; single-shot DISM/SFC reboot re-run. Safe to delete.`r`n"
    foreach ($n in $bundle) { $scriptText += "function $n {`r`n" + (Get-Item "function:$n").ScriptBlock.ToString() + "`r`n}`r`n" }
    $scriptText += "`r`nInvoke-DismSfcRebootRepair -RepairFolder `"`$env:SystemDrive\_IT-RebootRepair`" -TaskName '$taskName' -SelfScriptPath `$PSCommandPath -ChangeTimeout $ChangeTimeout`r`n"

    $install = New-RemoteFunctionScriptBlock -FunctionName 'New-SecureDirectory', 'Install-RebootRepairTask' -EntryPoint 'Install-RebootRepairTask'
    $params  = @{ ScriptText = $scriptText; TaskName = $taskName }
    try {
        if ($Target.Session) {
            return Invoke-Command -Session $Target.Session -ScriptBlock $install -ArgumentList $params -ErrorAction Stop
        }
        return & $install $params
    } catch {
        Write-Warning "Could not register the reboot re-run task on the target: $_"
        return $null
    }
}

function Install-RebootRepairTask {
    <#
    Runs on the target: writes the re-run script and registers the task that runs it as SYSTEM at the
    next boot. Every folder SYSTEM uses must be writable by SYSTEM and Administrators only, or any user
    could plant code or redirect its writes:
    - the script goes into a fresh folder under ProgramData; Directory.Delete removes a planted junction
      itself instead of following it, and fails safe on a folder the user locked against Administrators
    - the logs stay where earlier runs put them, readable by users; an existing folder is refused if it is
      a junction and otherwise gets Administrators as owner and the restricted ACL back
    #>
    param(
        [Parameter(Mandatory=$true)] [string]$ScriptText,
        [Parameter(Mandatory=$true)] [string]$TaskName
    )
    $ErrorActionPreference = 'Stop'   # a failed registration must reach the caller's catch, locally too
    $workDir   = Join-Path $env:ProgramData 'RepairSystem-RebootRerun'
    $logFolder = "$env:SystemDrive\_IT-RebootRepair"

    if (-not (Test-Path -LiteralPath $logFolder)) {
        New-SecureDirectory -Path $logFolder -UsersRead
    } else {
        if ((Get-Item -LiteralPath $logFolder -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "$logFolder is a junction or symbolic link; remove it and run Repair-System again."
        }
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @('S-1-5-32-545', 'ReadAndExecute'))) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                (New-Object System.Security.Principal.SecurityIdentifier $rule[0]), $rule[1], 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $logFolder -AclObject $acl
    }

    if (Test-Path -LiteralPath $workDir) { [System.IO.Directory]::Delete($workDir, $true) }
    New-SecureDirectory -Path $workDir
    $scriptPath = Join-Path $workDir 'RepairSystem-RebootRerun.ps1'
    Set-Content -LiteralPath $scriptPath -Value $ScriptText -Encoding UTF8 -Force
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT1M'   # let the servicing stack settle before DISM runs
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 3)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    [PSCustomObject]@{ Folder = $logFolder; Script = $scriptPath; Task = $TaskName }
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
    This function performs a series of system repair commands locally or on a remote computer. A remote computer is reached through a single PowerShell remoting session (WinRM) that is used for every step; no administrative file share is needed.
    Then, depending on the options specified, it executes `sfc /scannow` and  `DISM` commands to scan and repair the Windows image.

    Optional steps clean up the Windows Component Store, reset the Windows Update client (history-preserving), clear the content/download caches of the installed software-distribution systems (ConfigMgr / Adaptiva / Intune / Windows Update), and repair the ConfigMgr client. If a DISM/SFC step does not complete, a one-shot repair is scheduled to re-run the full DISM + SFC pass once after the next reboot (unless `-NoRebootRepair` is specified).

    Progress and status are printed to the local console. Step outputs are written to temporary log files on the device, then consolidated into a single repair log (`<yyyy-MM-dd_HH-mm-ss>_<PC>_RepairSystem.log`) in CMTrace-compatible format; individual step log files (`..._RepairSystem_<Step>.log`) are removed after embedding. Output a DISM/SFC step writes to stderr is kept as `..._RepairSystem_<Step>_stderr.log` (an empty capture is removed). On remote runs the repair log is written on the local machine, and the CBS/DISM system log archive (`..._RepairSystem_CBS-DISM.zip`), its error log if zipping failed, the ccmsetup.log copy and any stderr captures are copied from the device; only the files of this run are removed from the device. The run ends with a summary of the outcome: success, steps that need a restart, steps that did not complete (and whether a re-run after restart was scheduled), and steps that reported errors. With -Verbose, each step's console and verbose output is also recorded in `..._RepairSystem_Verbose.log` on the device, which is copied back like the other files of the run.

    .PARAMETER ComputerName
    The hostname or IP address of the remote computer where the system repair will be performed. Accepts pipeline input; several computers are repaired one after another, each returning its own result object.

    .PARAMETER remoteShareDrive
    No longer used: logs are read and copied through the PowerShell remoting session, not through an administrative share. Still accepted so existing commands keep working.

    .PARAMETER noSfc
    When specified, the `SCF /SCANNOW` command is skipped.

    .PARAMETER noDism
    When specified, the `DISM` commands are skipped.

    .PARAMETER Quiet
    Suppresses all console output (progress, warnings, the summary and the detailed exit code line); only errors and the result object remain, eg. for scheduled or scripted runs. Everything is still written to the repair log. The confirmation prompt of -IncludeLegacyRepair is still shown; use -Force to bypass it.

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
    Only the services Microsoft's Windows Update reset stops are stopped, and only those that were running are
    started again. An update or MSI installation in progress is waited for up to 10 minutes; if it is still running
    then, no service is stopped and the reset is carried out at the next boot instead (3010; -IncludeLegacyRepair is
    then not run). A running ConfigMgr task sequence (TSManager.exe) is stopped first.

    .PARAMETER ChangeTimeout
    Multiplicator
    Use decimal value to change when the DISM/SFC steps will timeout (value `-ChangeTimeout 2` will double the time, `-ChangeTimeout 0.5` will half it).
    Range = 0.25 - 10.0

    .PARAMETER KeepLogs
    When specified, individual step log files are retained alongside the repair log instead of being deleted after their content is embedded. On remote runs, the files of this run stay on the remote device and are also copied to the Client.

    .PARAMETER init
    When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
    When specified, no other Parameter will be executed (other provided Parameters will be ignored). This will retun 0 if the Config-File was created successfully, or already exists.

    Configuration-File Template:
    ```
    TempDirName=_IT-temp                                # Name of the temporary Directory on the target device (below its system drive); a single folder name
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
    Repair-System log under <SystemDrive>\_IT-RebootRepair. The task deletes itself before running (single attempt, no loop).
    The task's script lives in <ProgramData>\RepairSystem-RebootRerun; both folders are writable by SYSTEM and
    Administrators only.
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
                                          DISMAnalyzeComponentStore, DISMComponentCleanup, SFC, WMIRepair,
                                          SCCMCleanup, WindowsUpdateCleanup, RepairCCM — each a [bool]. (SCCMCleanup
                                          reflects the -ContentCacheCleanup step; the property name is kept
                                          for backwards compatibility.)
        Analysis         [PSCustomObject[]] Per-step breakdown: Position, Label, Value, Status.
                                            Status is one of: Success, Not requested, Not run (connection lost), Skipped (not needed),
                                            Postponed (restart required), Skipped (connection lost), Success (restart required), Timed out,
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
    Position 1: DISM ScanHealth (no longer run - RestoreHealth scans the image itself; always 0)
    Position 2: DISM RestoreHealth
    Position 3: DISM AnalyzeComponentStore
    Position 4: DISM StartComponentCleanup
    Position 5: SFC /scannow
    Position 6: WMI Repository Repair
    Position 7: Content Cache Cleanup (ConfigMgr / Adaptiva / Intune / Windows Update)
    Position 8: Windows Update Cleanup
    Position 9: Repair CCM
    Position 10: Zip CBS/DISM Logs

    For the DISM and SFC steps (Positions 2-5) specifically, a raw process exit code is only
    trusted if it is either a clean success or the process had a fair chance to run. A clean exit
    (code 0) is always trusted, however quickly it arrives - some steps (e.g. AnalyzeComponentStore)
    legitimately finish in seconds. If Repair-System itself killed the process for exceeding its
    time budget, that field instead reads -2 (a dedicated out-of-band "timed out" value, distinct
    from any real DISM/SFC exit code). If the process exited on its own with a NON-ZERO code in
    well under 30 seconds - implausibly fast for a real scan/repair to have failed legitimately -
    that field instead reads -3 ("likely terminated externally, e.g. via Task Manager - its own
    exit code could not be trusted"). AnalyzeComponentStore returns 0 for a finished analysis
    (whether or not it recommends a cleanup) and 3010 when a restart is pending.

    Except for Position 0, the detailed exit code field is the return value of the corresponding
    command. If a step was requested but deliberately did not run because it was not necessary
    (StartComponentCleanup when
    AnalyzeComponentStore recommends none) or because a prerequisite step did not complete, the
    field reads -4 ("requested but not executed" - reported as "Skipped (not needed)", not counted
    as a failure). If StartComponentCleanup is recommended but AnalyzeComponentStore reports a
    pending restart (3010), the cleanup is postponed and the field reads -5 ("Postponed (restart
    required)"): restart the device and run Repair-System -IncludeComponentCleanup again. If a
    step was not requested at all, or was not reached because the remote connection was lost,
    the field is 0. Only a startup failure causes an immediate exit; all other step failures are
    recorded but do not interrupt the remaining steps.

    These out-of-band values (-2, -3, -4, -5) are shown as their small signed numbers in the
    result object's Analysis and in -AnalyzeExitCode output; inside the packed DetailedExitCode
    string they are the 32-bit two's-complement hex fields FFFFFFFE, FFFFFFFD, FFFFFFFC and
    FFFFFFFB.

    Author: Wolfram Halatschek
    E-Mail: dev@kMarflow.com
    Date: 2026-10-06
    #>

    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true, ParameterSetName='Default')]
        [string]$ComputerName,

        [Parameter(Mandatory=$false, ParameterSetName='Default')]
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

    process {
        # -Quiet: run the same repair once more with host output and warnings redirected away, so every
        # step (local or remote) stays silent; errors and the result object remain.
        if ($Quiet) {
            $forward = @{}
            foreach ($key in $PSBoundParameters.Keys) { $forward[$key] = $PSBoundParameters[$key] }
            $forward.Remove('Quiet')
            # Errors are re-raised from this call so they point at the caller's command line.
            $script:RepairSystemQuietRun = $true
            try {
                Repair-System @forward 6>$null 3>$null 2>&1 | ForEach-Object {
                    if ($_ -is [System.Management.Automation.ErrorRecord]) {
                        $PSCmdlet.WriteError((New-Object System.Management.Automation.ErrorRecord $_.Exception, $_.FullyQualifiedErrorId, $_.CategoryInfo.Category, $_.TargetObject))
                    } else {
                        $_
                    }
                }
            } finally {
                $script:RepairSystemQuietRun = $false
            }
            return
        }

        if ($PSCmdlet.ParameterSetName -eq 'Analyze') {
            Write-RepairSystemExitCodeAnalysis -Code $AnalyzeExitCode
            return
        }

        [int[]]$ExitCode = 0,0,0,0,0,0,0,0,0,0,0 #Startup, DISM Scan, DISM Restore, Analyze Component, Component Cleanup, SFC, WMI Repository Repair, Content Cache Cleanup, Windows Update Cleanup, Repair CCM, Zip CBS/DISM Logs

        $ComputerName = $ComputerName.Trim()
        $targetDevice   = $env:COMPUTERNAME
        $requestedSteps = @(
            $true,                                        # [0] Startup - always
            $false,                                       # [1] DISM ScanHealth - no longer run: RestoreHealth scans itself
            (-not $noDism),                               # [2] DISM RestoreHealth
            (-not $noDism -and $IncludeComponentCleanup), # [3] DISM AnalyzeComponentStore
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
        if($init){
            if(-not (Test-Path $confFile)){
                try {
                    Set-Content -Path $confFile -Value "TempDirName=$tempFolder","FinalDestinationPath=$FinalDestinationPath" -ErrorAction Stop
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

        $remote = $ComputerName -ne "" -and $ComputerName -ne $env:COMPUTERNAME -and $ComputerName -ne "localhost"
        if ($remote) { $targetDevice = $ComputerName }

        if (-not $remote) {
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Write-Error "Repair-System must be run with administrative privileges. Please restart it in an elevated PowerShell session."
                $ExitCode[0]=5
                Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
                return
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

        if (Test-Path $confFile) {
            # Blank lines, '#' comment lines and trailing ' # comments' are ignored.
            $configError = $null
            foreach ($line in Get-Content -Path $confFile) {
                $line = ($line -replace '(^|\s)#.*$', '').Trim()
                if (-not $line) { continue }
                $key, $value = $line -split '=', 2
                $value = "$value".Trim()
                switch ($key.Trim()) {
                    'TempDirName'          { $tempFolder = $value }
                    'FinalDestinationPath' { $finalDestinationPath = $value }
                    'ShareDrive'           { }   # no longer used (logs are read through the session); accepted so older Config-Files keep working
                    default { $configError = "Invalid line in config file $confFile : `t$line`r`n`tAllowed Variables: TempDirName, FinalDestinationPath" }
                }
                if ($configError) { break }
            }
            # TempDirName becomes <SystemDrive>\<TempDirName> on the target, so anything but a single plain
            # folder name could point the temp folder (and its cleanup) at the drive root.
            if (-not $configError -and (($tempFolder -notmatch '^[^\\/:*?"<>|]+$') -or ($tempFolder -match '^\.+$'))) {
                $configError = "Invalid TempDirName '$tempFolder' in config file $confFile : a single folder name is required."
            }
            if (-not $configError -and [string]::IsNullOrWhiteSpace($finalDestinationPath)) {
                $configError = "FinalDestinationPath in config file $confFile must not be empty."
            }
            if ($configError) {
                Write-Warning $configError
                $ExitCode[0]=6
                Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
                return
            }
        }

        $runStamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
        # Everything on the device runs through $target: in one PSSession for a remote device, in-process
        # for the local one (see Invoke-RepairStep).
        $target = @{ ComputerName = $targetDevice; Session = $null; SessionParams = $null; Lost = $false; Quiet = [bool]$script:RepairSystemQuietRun }
        if ($remote) {
            $target.SessionParams = @{ ComputerName = $ComputerName; SessionOption = (New-PSSessionOption -OpenTimeout 30000) }
            if ($Credentials) { $target.SessionParams.Credential = $Credentials }
            $sessionParams = $target.SessionParams
            try {
                $target.Session = New-PSSession @sessionParams -ErrorAction Stop
            } catch {
                # Opening the session is the real reachability test (ICMP can be blocked while WinRM is open);
                # a ping only tells an unreachable device (2) from one without working remoting (3).
                $reachable = try { Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction Stop } catch { $false }
                if (-not $reachable) {
                    Write-Error "Unable to reach $ComputerName. Please check the Device-Name or the network connection to the remote Device."
                    $ExitCode[0]=2
                } else {
                    $winRMexit = "Unable to establish a remote PowerShell session to $ComputerName. Please check the WinRM configuration.`r`n`r`nError: $_"
                    Write-Error $winRMexit
                    $connectErrorFolder = Join-Path $FinalDestinationPath $ComputerName
                    New-Folder -FolderPath $connectErrorFolder
                    Write-CMTraceLog $winRMexit 'Connect' (Join-Path $connectErrorFolder "${runStamp}_${ComputerName}_RepairSystem_ConnectError.log") Error
                    $ExitCode[0]=3
                }
                Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -RequestedSteps $requestedSteps
                return
            }
        }

        try {
            # Every path on the device is built from base folders resolved and validated there, and named
            # after the device itself (also for an IP target).
            $bases = Invoke-RepairStep -Target $target -StepName 'Preparing the device' -ArgumentList @{} -ScriptBlock (New-RemoteFunctionScriptBlock -FunctionName 'Get-CleanupBasePath' -EntryPoint 'Get-CleanupBasePath')
            if ($bases -isnot [hashtable]) { $bases = @{} }
            $deviceName  = if ($bases.ComputerName) { $bases.ComputerName } else { $targetDevice }
            $tempPath    = "$(if ($bases.SystemDrive) { $bases.SystemDrive } else { 'C:' })\$tempFolder"
            $runPrefix   = "$tempPath\${runStamp}_${deviceName}_RepairSystem"
            # A remote run keeps its repair log on this machine, so it survives a lost connection.
            $localFolder = if ($remote) { Join-Path $FinalDestinationPath $ComputerName } else { $tempPath }
            New-Folder -FolderPath $localFolder
            $masterLogPath = Join-Path $localFolder "${runStamp}_${deviceName}_RepairSystem.log"
            # This run's own files on the device that are copied back at the end (step logs only with -KeepLogs).
            $runFiles = [System.Collections.Generic.List[string]]::new()
            # -Verbose records each step's console and verbose output in a transcript next to the step logs.
            $verboseLog = if ($VerbosePreference -eq 'Continue') { "${runPrefix}_Verbose.log" }
            if ($verboseLog) { $runFiles.Add($verboseLog) }

            # Light-weight calls (reads, deletes, the zip job) never reconnect: a broken session is left to
            # the next step, which reconnects or marks the connection as lost.
            $onTarget = {
                param([scriptblock]$ScriptBlock, [object[]]$ArgumentList)
                if ($target.Lost) { return }
                if (-not $target.Session) { return Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList }
                if ($target.Quiet) { $ScriptBlock = [scriptblock]::Create("& {`n$ScriptBlock`n} @args 6>`$null 3>`$null") }
            if ($target.Session.State -eq 'Opened') { Invoke-Command -Session $target.Session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList }
            }
            $null = & $onTarget (New-RemoteFunctionScriptBlock -FunctionName 'New-Folder' -EntryPoint 'New-Folder') @{ FolderPath = $tempPath }
            $removeBlock = New-RemoteFunctionScriptBlock -FunctionName 'Remove-PathReliable', 'Register-PendingDelete' -EntryPoint 'Remove-PathReliable'
            $removeOnTarget = {
                param([string]$Path)
                $r = & $onTarget $removeBlock @{ Path = $Path }
                if ($r.Scheduled) {
                    Write-CMTraceLog -Message "$Path is locked; queued for deletion on the next restart." -Component "RepairSystem" -LogPath $masterLogPath
                } elseif ($r.Error) {
                    Write-CMTraceLog -Message "$Path could not be deleted: $($r.Error)" -Component "RepairSystem" -LogPath $masterLogPath -Severity Warning
                }
            }

            # Runs one step on the device, records its result code, embeds its log into the repair log and
            # returns the log content. A non-empty stderr capture is kept and copied back; the step log is
            # deleted after embedding unless -KeepLogs.
            $toolHelpers = 'Write-CMTraceLog', 'Get-RepairSystemProcessResult', 'Remove-PathReliable', 'Register-PendingDelete', 'Invoke-RepairTool'
            $runStep = {
                param([int]$Position, [string]$Component, [string]$Label, [string[]]$Functions, [hashtable]$Params, [string]$LogPath)
                Write-CMTraceLog -Message "Starting $Label..." -Component $Component -LogPath $masterLogPath
                $attempted[$Position] = $true
                $block  = New-RemoteFunctionScriptBlock -FunctionName $Functions -EntryPoint $Functions[-1]
                if ($verboseLog) {
                    $block = [scriptblock]::Create("`$VerbosePreference = 'Continue'`nStart-Transcript -LiteralPath '$verboseLog' -Append | Out-Null`ntry { & {`n$block`n} @args } finally { Stop-Transcript | Out-Null }")
                }
                $result = Invoke-RepairStep -Target $target -ScriptBlock $block -ArgumentList $Params -StepName $Label
                # A step that ends without a result code must not read as success ([int]$null is 0).
                $last = $result | Select-Object -Last 1
                $ExitCode[$Position] = if ($target.Lost) { 5 } elseif ($last -is [int]) { $last } else { 1 }
                if (-not $target.Lost -and $last -isnot [int]) {
                    Write-CMTraceLog -Message "$Label returned no result code; recorded as failed." -Component $Component -LogPath $masterLogPath -Severity Warning
                }
                $stepSeverity = if ($ExitCode[$Position] -in 0, 3010, $script:RepairSystemNotExecutedCode) { 'Info' } else { 'Warning' }
                Write-CMTraceLog -Message "$Label completed; ExitCode=$($ExitCode[$Position]);" -Component $Component -LogPath $masterLogPath -Severity $stepSeverity
                $logs = & $onTarget {
                    param($log)
                    $err = $log -replace '\.log$', '_stderr.log'
                    [PSCustomObject]@{
                        Log    = $(if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue })
                        Stderr = $(if (Test-Path -LiteralPath $err) { Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue })
                    }
                } @($LogPath)
                Add-RepairStepLog -Content $logs.Log -MasterLogPath $masterLogPath -StepName $Component -Component $Component
                if (-not [string]::IsNullOrWhiteSpace($logs.Stderr)) {
                    $errLog = $LogPath -replace '\.log$', '_stderr.log'
                    $runFiles.Add($errLog)
                    Write-CMTraceLog -Message "$Label wrote to stderr: $errLog" -Component $Component -LogPath $masterLogPath -Severity Warning
                }
                if ($KeepLogs) { $runFiles.Add($LogPath) } elseif ($null -ne $logs) { & $removeOnTarget $LogPath }
                $logs.Log
            }

            Write-CMTraceLog -Message ("Repair-System started;`r`n" +
                "Target: $deviceName; Remote: $remote;`r`n" +
                "SFC: $(if ($noSfc) { 'skip' } else { 'run' }); DISM: $(if ($noDism) { 'skip' } else { 'run' }); ComponentCleanup: $IncludeComponentCleanup; RepairWMI: $RepairWMI; ContentCacheCleanup: $ContentCacheCleanup; WUCleanup: $WindowsUpdateCleanup; RepairCCM: $RepairCCM; Timeout: ${ChangeTimeout}x;") -Component "RepairSystem" -LogPath $masterLogPath

            # DISM/SFC steps that ran but did not truly complete (timed out, killed, empty or incomplete log,
            # or reboot-pending) - they trigger the one-shot reboot re-run below.
            $incompleteSteps = [System.Collections.Generic.List[string]]::new()
            # Steps that were actually started - after a lost connection, a requested step with value 0 that
            # was never started is reported as not run rather than as a success.
            $attempted = [bool[]]::new($ExitCode.Count)
            $checkComplete = {
                param([int]$Position, [string]$Content, [string]$Kind)
                if (-not $target.Lost -and (Test-DismSfcStepIncomplete -ResultCode $ExitCode[$Position] -Content $Content -Kind $Kind)) {
                    $incompleteSteps.Add($script:RepairSystemSteps[$Position].Label)
                }
            }
            $toolParams = { param($component) @{ LogPath = "${runPrefix}_$component.log"; ChangeTimeout = $ChangeTimeout } }

            if (-not $noDism -and -not $target.Lost) {
                # RestoreHealth scans the image itself and repairs only what it finds, so a separate
                # ScanHealth first would only scan a damaged image twice.
                $p = & $toolParams 'DISM-RestoreHealth'
                $restoreContent = & $runStep 2 'DISM-RestoreHealth' 'DISM RestoreHealth' ($toolHelpers + 'Invoke-DISMRestore') $p $p.LogPath
                & $checkComplete 2 $restoreContent 'DISM'

                if (-not $target.Lost -and $IncludeComponentCleanup) {
                    $p = & $toolParams 'DISM-Analyze'
                    $analyzeContent = & $runStep 3 'DISM-Analyze' 'DISM AnalyzeComponentStore' ($toolHelpers + 'Invoke-DISMAnalyzeComponentStore') $p $p.LogPath
                    & $checkComplete 3 $analyzeContent 'DISM'
                    if (-not $target.Lost) {
                        if ($ExitCode[3] -notin 0, 3010) {
                            $ExitCode[4] = $script:RepairSystemNotExecutedCode
                            Write-CMTraceLog -Message "DISM AnalyzeComponentStore returned an unexpected exit code ($($ExitCode[3])); StartComponentCleanup was not run. Please review the logs." -Component "DISM-ComponentCleanup" -LogPath $masterLogPath -Severity Warning
                        } elseif ($ExitCode[3] -eq 3010 -and (Get-DISMAnalyzeComponentStoreResult -Content $analyzeContent)) {
                            # 3010: servicing operations are pending a restart; cleaning the store now would work on a stale state.
                            $ExitCode[4] = $script:RepairSystemPostponedCode
                            Write-CMTraceLog -Message "A component store cleanup is recommended, but a restart is pending; StartComponentCleanup postponed until after the restart." -Component "DISM-ComponentCleanup" -LogPath $masterLogPath -Severity Warning
                        } elseif ($ExitCode[3] -eq 0 -and (Get-DISMAnalyzeComponentStoreResult -Content $analyzeContent)) {
                            $p = & $toolParams 'DISM-ComponentCleanup'
                            $cleanupContent = & $runStep 4 'DISM-ComponentCleanup' 'DISM ComponentStoreCleanup' ($toolHelpers + 'Invoke-DISMComponentStoreCleanup') $p $p.LogPath
                            & $checkComplete 4 $cleanupContent 'DISM'
                        } else {
                            $ExitCode[4] = $script:RepairSystemNotExecutedCode
                            Write-CMTraceLog -Message "No component store cleanup was needed; StartComponentCleanup marked as not executed." -Component "DISM-ComponentCleanup" -LogPath $masterLogPath
                        }
                    }
                }
            }

            if (-not $noSfc -and -not $target.Lost) {
                $p = & $toolParams 'SFC'
                $sfcContent = & $runStep 5 'SFC' 'SFC /scannow' ($toolHelpers + 'Get-SfcCbsSummary' + 'Invoke-SFC') $p $p.LogPath
                & $checkComplete 5 $sfcContent 'SFC'
            }

            # If any DISM/SFC step that ran did not complete cleanly, schedule a single automatic repair to
            # run after the next reboot (default on; suppressed by -NoRebootRepair). Only when DISM was in
            # play - the re-run performs the full DISM + SFC pass.
            $rebootRerunScheduled = $false
            if ($incompleteSteps.Count -gt 0 -and -not $NoRebootRepair -and -not $noDism -and -not $target.Lost) {
                Write-CMTraceLog -Message "A DISM/SFC step did not complete cleanly; scheduling a one-shot reboot re-run..." -Component "RebootRerun" -LogPath $masterLogPath
                $rebootTask = Register-RebootRepairTask -ChangeTimeout $ChangeTimeout -Target $target
                if ($null -ne $rebootTask) {
                    $rebootRerunScheduled = $true
                    Write-CMTraceLog -Message "Reboot re-run scheduled as task '$($rebootTask.Task)' on $deviceName; its log will be written under $($rebootTask.Folder) after the next restart." -Component "RebootRerun" -LogPath $masterLogPath
                } else {
                    Write-CMTraceLog -Message "Reboot re-run could NOT be scheduled (task registration failed); a manual re-run after restart is recommended." -Component "RebootRerun" -LogPath $masterLogPath -Severity Warning
                }
            }

            # The CBS/DISM zip runs as a background job on the device while the remaining steps run.
            $zipJobId = $null
            if ((-not $noSfc -or -not $noDism) -and -not $target.Lost) {
                $zipFile     = "${runPrefix}_CBS-DISM.zip"
                $zipErrorLog = "${runPrefix}_CBS-DISM_zip-errors.log"
                $runFiles.Add($zipFile)
                $runFiles.Add($zipErrorLog)
                Write-CMTraceLog -Message "Starting CBS/DISM log zip in background (after last SFC/DISM step)..." -Component "ZipLogs" -LogPath $masterLogPath
                $zipText = (New-RemoteFunctionScriptBlock -FunctionName 'Write-CMTraceLog', 'Remove-PathReliable', 'Register-PendingDelete', 'Start-ZipFileCreation' -EntryPoint 'Start-ZipFileCreation').ToString()
                $attempted[10] = $true
                try {
                    $zipJobId = & $onTarget {
                        param($text, $params)
                        (Start-Job -ScriptBlock ([scriptblock]::Create($text)) -ArgumentList $params -ErrorAction Stop).Id
                    } @($zipText, @{ TempPath = $tempPath; ZipFile = $zipFile; ZipErrorLog = $zipErrorLog; Bases = $bases; noDism = [bool]$noDism })
                } catch {
                    Write-CMTraceLog -Message "Failed to start zip background job: $_" -Component "ZipLogs" -LogPath $masterLogPath -Severity Warning
                }
            }

            # WMI Repository Repair runs BEFORE the WMI-dependent Content Cache Cleanup and CCM Repair steps
            # so those act on a repaired store. Its exit-code field is position 6 (see RepairSystemStepLayouts).
            if ($RepairWMI -and -not $target.Lost) {
                $log = "${runPrefix}_WMIRepair.log"
                $null = & $runStep 6 'WMIRepair' 'WMI Repository Repair' @('Write-CMTraceLog', 'Write-StepLogLine', 'Repair-WMIRepository') @{ WMIRepairLog = $log; Bases = $bases } $log
            }

            if ($ContentCacheCleanup -and -not $target.Lost) {
                $log = "${runPrefix}_ContentCacheCleanup.log"
                $null = & $runStep 7 'ContentCacheCleanup' 'Content Cache Cleanup' @('Write-CMTraceLog', 'Remove-PathReliable', 'Register-PendingDelete', 'Clear-FolderContentsReliable', 'Clear-WindowsUpdateDownload', 'Get-CCMCachePath', 'Test-SafeCachePath', 'Invoke-ContentCacheCleanup', 'Invoke-ContentCacheCleanupStep') @{ LogPath = $log; Bases = $bases; SkipWindowsUpdate = [bool]$WindowsUpdateCleanup } $log
                if ($ExitCode[7] -eq 3010) {
                    Write-Warning "`r`nContent Cache Cleanup on $deviceName scheduled some locked cache items for removal on the next reboot. Please restart the device to finish."
                }
            }

            if ($WindowsUpdateCleanup -and -not $target.Lost) {
                $log = "${runPrefix}_WUCleanup.log"
                $wuParams = @{ updateCleanupLog = $log; Bases = $bases; ResetUpdateHistory = [bool]$ResetUpdateHistory; DoLegacyRepair = $legacyRepairConfirmed }
                $null = & $runStep 8 'WUCleanup' 'Windows Update Cleanup' @('Write-CMTraceLog', 'Write-StepLogLine', 'Stop-ServiceSafely', 'Remove-PathReliable', 'Register-PendingDelete', 'Test-DataStoreHealth', 'Invoke-WULegacyRepair', 'Invoke-WindowsUpdateCleanup') $wuParams $log
                if ($ExitCode[8] -eq 3010) {
                    Write-Warning "`r`nWindows Update Cleanup on $deviceName scheduled some locked items for removal on the next reboot. Please restart the device to finish."
                } elseif ($ExitCode[8] -notin 0, 5) {
                    Write-Error "`r`nAn error occurred while performing Windows Update Cleanup on $deviceName. Please review the logs.`r`n`tA restart of the device is advised. Please try again afterwards."
                }
            }

            if ($RepairCCM -and -not $target.Lost) {
                $log = "${runPrefix}_RepairCCM.log"
                $ccmSetupCopy = "${runPrefix}_ccmsetup.log"
                $runFiles.Add($ccmSetupCopy)
                $null = & $runStep 9 'RepairCCM' 'CCM Repair' @('Write-CMTraceLog', 'Write-StepLogLine', 'Remove-PathReliable', 'Register-PendingDelete', 'Clear-FolderContentsReliable', 'Get-CCMCachePath', 'Test-SafeCachePath', 'Repair-CCM') @{ RepairCCMLog = $log; CCMSetupLogCopy = $ccmSetupCopy; Bases = $bases } $log
            }

            if ($null -ne $zipJobId -and -not $target.Lost) {
                Write-CMTraceLog -Message "Waiting for CBS/DISM zip background job..." -Component "ZipLogs" -LogPath $masterLogPath
                $zipResult = & $onTarget {
                    param($id)
                    $job = Get-Job -Id $id -ErrorAction SilentlyContinue
                    if (-not $job) { return 'no job' }
                    if (-not (Wait-Job -Job $job -Timeout 300)) { Stop-Job -Job $job; Remove-Job -Job $job -Force; return 'timed out after 300 seconds' }
                    $out = Receive-Job -Job $job -ErrorAction SilentlyContinue | Select-Object -Last 1
                    Remove-Job -Job $job -Force
                    if ($out -is [int]) { $out } else { 'no result code' }
                } @($zipJobId)
                if ($zipResult -is [int]) {
                    $ExitCode[10] = $zipResult
                } else {
                    $ExitCode[10] = 1
                    Write-CMTraceLog -Message "CBS/DISM zip job did not finish ($(if ($zipResult) { $zipResult } else { 'connection to the device was lost' }))." -Component "ZipLogs" -LogPath $masterLogPath -Severity Warning
                }
            }
            if ($target.Lost -and ((-not $noSfc) -or (-not $noDism))) { $ExitCode[10] = 5 }
            Write-CMTraceLog -Message "CBS/DISM zip step completed; ExitCode=$($ExitCode[10]);" -Component "ZipLogs" -LogPath $masterLogPath

            # Remote: copy this run's own files back; only those are removed, the temp folder may be in use
            # by other tools (it is removed only if this leaves it empty).
            $notCopied = @()
            if ($remote -and -not $target.Lost) {
                $existing = @(& $onTarget { param($files) $files | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } } @(,@($runFiles)))
                foreach ($file in $existing) {
                    try {
                        Copy-Item -LiteralPath $file -Destination $localFolder -FromSession $target.Session -Force -ErrorAction Stop
                        if (-not $KeepLogs) { & $removeOnTarget $file }
                    } catch {
                        $notCopied += $file
                        Write-CMTraceLog -Message "$file could not be copied from ${deviceName}: $_" -Component "RepairSystem" -LogPath $masterLogPath -Severity Warning
                    }
                }
                if (-not $KeepLogs) {
                    $null = & $onTarget { param($p) if (-not (Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } } @($tempPath)
                }
            }

            if ($target.Lost -and $ExitCode[0] -eq 0) { $ExitCode[0] = 4 }

            # Outcome-driven summary: printed and written as the final log entry.
            $summary = [System.Collections.Generic.List[object]]::new()
            $problemSteps = [System.Collections.Generic.List[string]]::new()
            $restartSteps = [System.Collections.Generic.List[string]]::new()
            $postponedSteps = [System.Collections.Generic.List[string]]::new()
            for ($i = 1; $i -lt $ExitCode.Count; $i++) {
                $label = $script:RepairSystemSteps[$i].Label
                if ($ExitCode[$i] -eq 3010) { $restartSteps.Add($label) }
                elseif ($ExitCode[$i] -eq $script:RepairSystemPostponedCode) { $postponedSteps.Add($label) }
                elseif (($ExitCode[$i] -notin 0, 5, $script:RepairSystemNotExecutedCode) -and ($incompleteSteps -notcontains $label)) { $problemSteps.Add($label) }
            }
            if ($target.Lost) {
                $summary.Add(@('Warning', "Connection to $ComputerName was lost during the repair; the remaining steps were skipped and the log files on the device could not be copied (they remain under $tempPath)."))
            }
            if ($incompleteSteps.Count -gt 0) {
                $notCompleted = "Did not complete: $($incompleteSteps -join ', ')."
                if ($rebootRerunScheduled) {
                    $summary.Add(@('Info', "$notCompleted A one-time repair will run automatically after the next restart of $deviceName; its log is saved there under $($rebootTask.Folder)\."))
                } else {
                    $reason = if ($NoRebootRepair) { 'disabled by -NoRebootRepair' }
                              elseif ($noDism) { 'the automatic re-run only covers runs that include DISM' }
                              elseif ($target.Lost) { "the connection to $ComputerName was lost" }
                              else { 'the scheduled task could not be registered' }
                    $summary.Add(@('Warning', "$notCompleted No automatic re-run was scheduled ($reason). Restart $deviceName and run Repair-System again."))
                }
            }
            if ($problemSteps.Count -gt 0) {
                $summary.Add(@('Warning', "Completed with errors in: $($problemSteps -join ', '). See the repair log for details."))
            }
            if ($restartSteps.Count -gt 0) {
                $summary.Add(@('Info', "Restart $deviceName to finish pending changes ($($restartSteps -join ', '))."))
            }
            if ($postponedSteps.Count -gt 0) {
                $summary.Add(@('Warning', "Postponed because a restart is pending: $($postponedSteps -join ', '). Restart $deviceName and run Repair-System -IncludeComponentCleanup again."))
            }
            if ($summary.Count -eq 0) {
                $summary.Add(@('Info', "System repair completed successfully on $deviceName."))
            }
            $logInfo = "Repair log: $masterLogPath"
            if ($remote -and -not $target.Lost) {
                $logInfo += "`r`nLog files of this run were copied to $localFolder"
                if ($KeepLogs) { $logInfo += "; they are also kept on the device under $tempPath" }
                if ($notCopied) { $logInfo += "`r`nNot copied (left on the device): $($notCopied -join ', ')" }
            } elseif (-not $remote) {
                $logInfo += "`r`nLog files of this run are in $tempPath"
            }
            $summary.Add(@('Info', $logInfo))

            foreach ($line in $summary) {
                if ($line[0] -eq 'Warning') { Write-Warning $line[1] } else { Write-Host $line[1] }
            }

            $finalSeverity = Get-RepairSystemExitCodeSeverity -Codes $ExitCode
            Write-CMTraceLog -Message ("Repair-System completed;`r`n" +
                "Target: $deviceName; Remote: $remote;`r`n" +
                "DetailedExitCode: $(ConvertTo-RepairSystemExitCode -Codes $ExitCode); Severity: $finalSeverity;`r`n" +
                (($summary | ForEach-Object { $_[1] }) -join "`r`n")) -Component "RepairSystem" -LogPath $masterLogPath -Severity $(if ($finalSeverity -eq 0) { 'Info' } elseif ($finalSeverity -eq 1) { 'Warning' } else { 'Error' })

            Set-RepairSystemExitCode -Codes $ExitCode -ComputerName $targetDevice -LogPath $masterLogPath -RequestedSteps $requestedSteps -AttemptedSteps $attempted
        } finally {
            if ($target.Session) { Remove-PSSession -Session $target.Session -ErrorAction SilentlyContinue }
        }
    }
}
Export-ModuleMember -Function Repair-System, Repair-LocalSystem, Repair-RemoteSystem

<#
.SYNOPSIS
    Cleanly uninstalls all Autodesk products from a system, including the residue
    that Autodesk's own uninstallers leave behind.

.DESCRIPTION
    Removes Autodesk software in stages, and finishes the work that cannot be done
    while Windows is running by scheduling a one-shot task for the next boot.

    What it does, in order:

      1. Stops Autodesk services, then Autodesk processes. Services are disabled
         first so the Service Control Manager cannot restart them; a service that
         ignores SERVICE_CONTROL_STOP has its hosting process terminated by PID.
      2. Walks C:\ProgramData\Autodesk\Uninstallers, ordering Object Enablers
         first, then updates/service packs, then base products, and uninstalls each
         MSI package via msiexec.
      3. Runs the shared-component removers (ODIS, Access, Licensing, Identity
         Manager) and their uninstall helpers.
      4. Sweeps services and processes a SECOND time - uninstallers routinely
         restart their own services, and anything running holds file handles that
         would make the deletion below fail.
      5. Deletes Autodesk folders under Program Files, ProgramData and every user
         profile, and removes Autodesk registry keys from HKLM and every loaded
         user hive.
      6. Removes Autodesk entries from the Uninstall and Installer\Products hives.
      7. Sweeps C:\ProgramData\Autodesk again - the uninstall helpers in step 3
         recreate part of it (IDSDK) as they remove themselves. Only the
         Uninstallers folder is kept, deliberately.
      8. Queues anything still locked into PendingFileRenameOperations and
         registers a one-shot SYSTEM task that, at next boot, unregisters the
         Autodesk COM/shell extensions, cleans the per-user registry keys -
         including for users who never sign in - and sweeps ProgramData once more.

    Step 8 exists because AcSignCore16.dll (Autodesk Signature Core) is registered
    as a shell extension under hundreds of CLSIDs. explorer.exe loads it at every
    logon and it recreates HKCU\SOFTWARE\Autodesk, and because Explorer holds the
    file open it can never be deleted while Windows is running. Doing that work at
    boot, before any logon, is the only way to break the cycle.

    Logging is CMTrace-compatible. The live run and the deferred boot-time phase
    write paired files that share a timestamp:
        ADSK_CleanUninstall_<timestamp>.log
        ADSK_CleanUninstall_Deferred_<timestamp>.log

.PARAMETER LogPath
    Directory for all logs. MSI logs are written to <LogPath>\MSILogs.
    Defaults to C:\_ADSK_CleanUninstall. The script aborts if it cannot be created.

.PARAMETER LogLevel
    Verbosity threshold. Defaults to Verbose, which reproduces the historical
    output in full, including the complete MSI logs inlined into the main log.

        None    - no file logging
        Error   - errors only
        Warning - warnings and errors
        Info    - normal flow; MSI logs inlined only on failure
        Verbose - everything, including full MSI logs   (default)
        Debug   - everything plus extra diagnostic detail

    The level also drives the CMTrace severity column, so errors show in red.

.PARAMETER Unattended
    Suppresses every prompt and the completion toast. Required for Intune, SCCM or
    any headless execution - without it the script waits at Pause/Read-Host.

.PARAMETER NoRestart
    Never offers to restart, even in an interactive session. Takes precedence over
    -ForceRestart if both are supplied.

.PARAMETER ForceRestart
    Restarts the computer as soon as the run completes, without asking. Useful in
    unattended deployment so the deferred boot-time cleanup finishes immediately
    rather than waiting for the user's next restart.

.EXAMPLE
    PS> .\AutoDeskCleanRemove.ps1

    Interactive run with default logging to C:\_ADSK_CleanUninstall.

.EXAMPLE
    PS> .\AutoDeskCleanRemove.ps1 -WhatIf

    Dry run. Reports every uninstall, deletion, registry removal and the deferred
    task it would create, and changes nothing.

.EXAMPLE
    PS> .\AutoDeskCleanRemove.ps1 -Unattended -ForceRestart

    Unattended removal for a deployment tool, restarting immediately so the
    boot-time cleanup completes without waiting for the user.

.EXAMPLE
    PS> .\AutoDeskCleanRemove.ps1 -LogPath 'D:\Logs\ADSK' -LogLevel Info

    Logs to a custom directory and omits the inlined MSI logs except on failure,
    producing a much smaller main log.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    None. Progress is written to the host, detail to the CMTrace logs under
    -LogPath, and the outcome is reported through the exit code:

        0     Completed with no unresolved failures
        1     Not elevated, the log directory could not be created, or one or
              more packages failed to uninstall AND are still registered
        3010  Completed successfully; a restart is required to finish

    Packages that report a failure but are no longer registered by the end of the
    run are logged as resolved and do not affect the exit code. Autodesk Genuine
    Service, for instance, returns 1604 from its own checkUninstall action while
    other products are still installed, and is removed successfully afterwards.

.NOTES
    Author:   Halatschek Wolfram
    Date:     2026-08-09
    Version:  3.0
    Requires: Administrative privileges, Windows PowerShell 5.1 or later.

    A restart is required to complete removal - the deferred task does its work at
    the next boot. One run plus one restart is normally sufficient; running the
    script a second time afterwards remains a safe way to confirm nothing is left.

    Warning:  This script is provided "as is" without any warranty of any kind.

        !!    The Author of this script is not responsible for any data loss or
              system damage caused by the use of this script. Use at your own risk.

              This removes per-user Autodesk data for EVERY profile on the machine,
              including customisations under AppData\Roaming\Autodesk. Use -WhatIf
              first if you are unsure what will be removed.

              Autodesk Fusion must be uninstalled MANUALLY BEFOREHAND. It is not an
              MSI/ODIS product, so this script cannot uninstall it - but it does
              delete AppData\Local\Autodesk, which is where Fusion lives, without
              running Fusion's uninstaller. Running this with Fusion still installed
              leaves a corrupted, half-removed Fusion behind.

              If any errors occur that you wish to report to the Author, please
              open an issue on https://github.com/halatsWol/PowerShell-Tools

.LINK
    https://github.com/halatsWol/PowerShell-Tools

.LINK
    https://github.com/halatsWol/PowerShell-Tools/blob/main/scripts/AutoDeskCleanRemove.ps1
#>

# SupportsShouldProcess gives -WhatIf and -Confirm. ConfirmImpact is deliberately
# left at the default: 'High' would prompt for every one of the hundreds of
# destructive operations below, which would make a normal run unusable.
[CmdletBinding(SupportsShouldProcess)]
param(
    # Root directory for logs. MSI logs are written to <LogPath>\MSILogs.
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = "C:\_ADSK_CleanUninstall",

    # Verbosity threshold. 'Verbose' (the default) reproduces the historical
    # output in full, including the complete MSI logs embedded in the main log.
    #   None    - no file logging
    #   Error   - errors only
    #   Warning - warnings and errors
    #   Info    - normal flow; MSI logs embedded only on failure
    #   Verbose - everything, including full MSI logs           (DEFAULT)
    #   Debug   - everything plus extra diagnostic detail
    [ValidateSet('None','Error','Warning','Info','Verbose','Debug')]
    [string]$LogLevel = 'Verbose',

    # Suppress every prompt and the toast notification. Required for Intune/SCCM
    # and any headless run; without it Pause/Read-Host block forever.
    [switch]$Unattended,

    # Never offer to restart at the end, even interactively.
    [switch]$NoRestart,

    # Restart automatically when the run finishes, without asking. Intended for
    # unattended deployment, where the deferred boot-time cleanup should complete
    # immediately rather than waiting for the user's next restart.
    [switch]$ForceRestart
)

# $PSSenderInfo alone does not detect a headless local session (e.g. a service or
# remote-exec context), which is why AppActivate could throw at the very end.
$script:Interactive = (-not $Unattended) -and (-not $PSSenderInfo) -and [Environment]::UserInteractive

# Conflicting intents: prefer the safer one rather than guessing.
if ($ForceRestart -and $NoRestart) {
    Write-Warning "-ForceRestart and -NoRestart were both specified; -NoRestart wins and the computer will not be restarted."
    $ForceRestart = $false
}

# $PSCmdlet is only bound at script scope, so capture it for use inside functions.
$script:Cmdlet = $PSCmdlet

function Test-ShouldProcess {
    <#
        Wrapper so nested functions can take part in -WhatIf / -Confirm. Returns
        $true when the action should actually be performed; under -WhatIf it
        returns $false and PowerShell prints the "What if:" line automatically.
    #>
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Action
    )
    if ($null -eq $script:Cmdlet) { return $true }
    return $script:Cmdlet.ShouldProcess($Target, $Action)
}

function Wait-ForUser {
    if ($script:Interactive) { Pause }
}

# Pre-load CimCmdlets. Otherwise it autoloads mid-run and its alias registrations
# emit a dozen spurious "What if: Set Alias" lines. Import-Module does not support
# -WhatIf, so the preference is suppressed around the call instead.
$previousWhatIfPreference = $WhatIfPreference
$WhatIfPreference = $false
Import-Module CimCmdlets -ErrorAction SilentlyContinue
$WhatIfPreference = $previousWhatIfPreference

$script:LogLevel = $LogLevel
$MainLogPath = $LogPath
$MsiLogPath  = Join-Path -Path $LogPath -ChildPath 'MSILogs'
try {
    if (-not (Test-Path -LiteralPath $MainLogPath)) {
        New-Item -ItemType Directory -Path $MainLogPath -Force -ErrorAction Stop -WhatIf:$false | Out-Null
    }
    if (-not (Test-Path -LiteralPath $MsiLogPath)) {
        New-Item -ItemType Directory -Path $MsiLogPath -Force -ErrorAction Stop -WhatIf:$false | Out-Null
    }
} catch {
    Write-Warning "Cannot create log directory '$MainLogPath': $($_.Exception.Message)"
    exit 1
}
$MainLogPathFileName="ADSK_CleanUninstall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
$MainLogFile = Join-Path -Path $MainLogPath -ChildPath $MainLogPathFileName

# Outcome tracking - drives the script's real exit code instead of a hardcoded 0
# holds PSCustomObjects (ProductCode/ExitCode/Label) so failures can be re-verified
# against the registry at the end - a List[string] would silently stringify them
$script:FailedPackages = New-Object System.Collections.Generic.List[object]
$script:RebootRequired = $false
$script:ExitCode       = 0

# Files that could not be deleted because something holds them open (in practice
# shell-extension DLLs that explorer.exe has loaded). Collected here and scheduled
# for deletion at next boot in a single registry write.
$script:PendingDeletePaths = New-Object System.Collections.Generic.List[string]
# Cumulative count across every Set-PendingFileDeletes call. The list above is
# emptied on each write so a later call cannot re-queue what is already pending,
# so it can no longer be used to answer "was anything scheduled at all?".
$script:PendingDeleteTotal = 0

# C:\ProgramData\Autodesk is kept ONLY for its Uninstallers folder; everything else
# under it is residue.
$script:AdskProgramDataPath = 'C:\ProgramData\Autodesk'
$script:AdskProgramDataKeep = Join-Path -Path $script:AdskProgramDataPath -ChildPath 'Uninstallers'

function Get-AdskProgramDataResidue {
    <#
        Everything under C:\ProgramData\Autodesk except the Uninstallers folder.
    #>
    if (-not (Test-Path -LiteralPath $script:AdskProgramDataPath)) { return @() }
    return @(Get-ChildItem -LiteralPath $script:AdskProgramDataPath -Force -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -ne $script:AdskProgramDataKeep })
}

function Remove-AdskProgramDataResidue {
    <#
        Deletes that residue and returns whatever survived.

        Called a SECOND time after the shared-component uninstall helpers have run:
        AdskIdentityManager and message_router recreate IDSDK while uninstalling
        themselves, so the earlier pass - which necessarily runs before them - always
        leaves it behind.
    #>
    $survivors = New-Object System.Collections.Generic.List[string]
    foreach ($residueItem in (Get-AdskProgramDataResidue)) {
        if (-not (Test-ShouldProcess -Target $residueItem.FullName -Action 'Delete folder recursively')) { continue }
        Write-Log -Message "Deleting ProgramData residue $($residueItem.FullName)" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Remove-Item -LiteralPath $residueItem.FullName -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $residueItem.FullName) { $survivors.Add($residueItem.FullName) }
    }
    return $survivors.ToArray()
}

function Set-PendingFileDeletes {
    <#
        Queues $script:PendingDeletePaths into PendingFileRenameOperations so the
        Session Manager removes them very early at next boot, before anything can
        load them again. A "\??\<path>" entry followed by an empty string means
        delete. Existing entries Windows already had pending are preserved.

        Returns the paths it scheduled and empties the list, so it can be called
        again later in the run for items found after the first pass without
        re-queuing everything from the first one.
    #>
    if ($script:PendingDeletePaths.Count -eq 0) { return @() }
    if (-not (Test-ShouldProcess -Target "$($script:PendingDeletePaths.Count) locked item(s)" -Action 'Schedule deletion at next boot (PendingFileRenameOperations)')) { return @() }
    $sessionMgr = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $entries = New-Object System.Collections.Generic.List[string]
    $existing = (Get-ItemProperty -Path $sessionMgr -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    foreach ($existingEntry in @($existing)) {
        if ($null -ne $existingEntry) { $entries.Add([string]$existingEntry) }
    }
    foreach ($pendingPath in $script:PendingDeletePaths) {
        $entries.Add("\??\$pendingPath")
        $entries.Add("")
    }
    Set-ItemProperty -Path $sessionMgr -Name PendingFileRenameOperations `
                     -Value ([string[]]$entries.ToArray()) -Type MultiString -ErrorAction Stop
    $scheduledPaths = $script:PendingDeletePaths.ToArray()
    $script:PendingDeletePaths.Clear()
    $script:PendingDeleteTotal += $scheduledPaths.Count
    return $scheduledPaths
}

function Register-AdskDeferredCleanup {
    <#
        Registers a one-shot SYSTEM task that finishes the cleanup at next boot.

        Why deferred rather than done here: AcSignCore16.dll is registered under
        hundreds of CLSIDs as a shell extension, and explorer.exe keeps it loaded
        for the life of the session. Removing those registrations from under a
        running shell stalls shutdown, and any per-user Autodesk key deleted now
        is simply rewritten by that still-loaded DLL.

        At next boot, by the time this task runs:
          - PendingFileRenameOperations has already deleted the DLLs
          - no user has logged on, so nothing can reload them
          - every user hive is UNLOADED and can be cleaned offline, which also
            reaches users who never sign in - something the live run cannot do,
            since Get-ChildItem HKU:\ only ever sees loaded hives.
    #>
    param([Parameter(Mandatory)][string]$WorkDir)

    if (-not (Test-ShouldProcess -Target 'ADSK-DeferredCleanup (SYSTEM task at startup)' -Action 'Register one-shot deferred cleanup')) { return $null }

    $deferredScript = Join-Path -Path $WorkDir -ChildPath 'ADSK-DeferredCleanup.ps1'
    # Same naming convention and timestamp as the main log, so the two halves of one
    # cleanup operation pair up: ADSK_CleanUninstall_<ts>.log / ..._Deferred_<ts>.log
    $deferredLog    = $MainLogFile -replace 'ADSK_CleanUninstall_', 'ADSK_CleanUninstall_Deferred_'
    # Marker proving this task already ran, so it can never fire twice
    $deferredDone    = Join-Path -Path $WorkDir -ChildPath 'ADSK-DeferredCleanup.done'
    # Attempt counter, written before any work, so a hung/killed run is still detected
    $deferredAttempt = Join-Path -Path $WorkDir -ChildPath 'ADSK-DeferredCleanup.attempt'
    # Scheduling time, used to count boots since registration
    $deferredScheduledAt = (Get-Date).ToString('o')

    # single-quoted here-string: nothing below is expanded by THIS script
    $deferredBody = @'
$deferredLogPath     = '__LOGPATH__'
$deferredDoneFile    = '__SENTINEL__'
$deferredAttemptFile = '__ATTEMPTFILE__'
$deferredScheduledAt = [datetime]::Parse('__SCHEDULEDAT__')
$deferredTaskName    = 'ADSK-DeferredCleanup'

# CMTrace-format writer, matching the main log so both open in CMTrace.exe
function Write-DeferredLog {
    param([string]$Message, [ValidateSet('Info','Warning','Error')][string]$Level = 'Info')
    $cmType = switch ($Level) { 'Error' { 3 } 'Warning' { 2 } default { 1 } }
    $now = Get-Date
    $tz  = (Get-TimeZone).BaseUtcOffset.TotalMinutes
    $tzf = if ($tz -ge 0) { "+{0:000}" -f $tz } else { "-{0:000}" -f [math]::Abs($tz) }
    $line = "<![LOG[$Message]LOG]!><time=""$($now.ToString('HH:mm:ss.fff'))$tzf"" date=""$($now.ToString('MM-dd-yyyy'))"" component=""AutoDeskCleanRemove-Deferred"" context="""" type=""$cmType"" thread=""$PID"" file=""ADSK-DeferredCleanup.ps1"">"
    foreach ($attempt in 1..10) {
        try { Add-Content -Path $deferredLogPath -Value $line -ErrorAction Stop; return } catch { Start-Sleep -Milliseconds 100 }
    }
}

function Remove-DeferredCleanup {
    # Belt and braces: mark done FIRST, then unregister, then self-delete. If any of
    # these fail the marker still exists, so the next boot exits immediately.
    try { New-Item -Path $deferredDoneFile -ItemType File -Force -ErrorAction Stop | Out-Null } catch { }
    try { Unregister-ScheduledTask -TaskName $deferredTaskName -Confirm:$false -ErrorAction Stop } catch {
        try { & schtasks.exe /delete /tn $deferredTaskName /f 2>&1 | Out-Null } catch { }
    }
    try { Remove-Item -LiteralPath $deferredAttemptFile -Force -ErrorAction SilentlyContinue } catch { }
    try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction Stop } catch { }
}

# Record this script's own source as the first entry, before anything else runs and
# before any guard can exit. The script deletes itself as its last act, so without
# this the log is the only survivor and there is no way to audit what it actually
# did. Same convention as the MSI logs inlined into the main log: one entry, the
# content wrapped in braces.
try {
    $deferredSelfSource = Get-Content -LiteralPath $PSCommandPath -Raw -ErrorAction Stop
    # This source contains the CMTrace delimiters themselves - Write-DeferredLog above
    # builds "<![LOG[...]LOG]!>" - and an embedded "]LOG]!>" would close THIS entry
    # early, so CMTrace would split the dump into bogus entries dated 01/01/1601.
    # Escape both delimiters; the text stays readable and is obviously not doctored.
    $deferredSelfEscaped = $deferredSelfSource -replace '<!\[LOG\[', '&lt;![LOG[' -replace '\]LOG\]!>', ']LOG]!&gt;'
    Write-DeferredLog "Deferred cleanup script source ($PSCommandPath) - CMTrace delimiters escaped as &lt; / &gt; so this stays one entry:`r`n{`r`n$deferredSelfEscaped`r`n}"
} catch {
    Write-DeferredLog "Could not read own source for the log: $($_.Exception.Message)" -Level Warning
}

# GUARD 1 - completion marker. Set in the finally block of a previous run, so it
# means "already finished, cleanly or with a handled error".
if (Test-Path -LiteralPath $deferredDoneFile) {
    Write-DeferredLog "Deferred cleanup already completed previously; removing the task and exiting." -Level Warning
    Remove-DeferredCleanup
    exit 0
}

# GUARD 1a - attempt counter, written BEFORE any work is done. Covers the case the
# finally block cannot: the script hanging or being killed mid-run, so it never
# marked itself done. A second sighting means it already had its chance.
$deferredAttempt = 1
try {
    if (Test-Path -LiteralPath $deferredAttemptFile) {
        $previous = [int]((Get-Content -LiteralPath $deferredAttemptFile -Raw -ErrorAction Stop).Trim())
        $deferredAttempt = $previous + 1
    }
} catch { $deferredAttempt = 2 }   # unreadable counter -> assume this is a retry
try { Set-Content -LiteralPath $deferredAttemptFile -Value $deferredAttempt -Force -ErrorAction Stop } catch { }
if ($deferredAttempt -gt 1) {
    Write-DeferredLog "This is attempt $deferredAttempt; a previous run started but did not finish. Removing the task rather than retrying indefinitely." -Level Warning
    Remove-DeferredCleanup
    exit 0
}

# GUARD 1b - boots since the task was scheduled. Independent of any file we write,
# so it still holds if the counter above could not be persisted. Event 6005 ("Event
# log service was started") fires once per boot; the task is AtStartup, so on its
# legitimate first run exactly ONE boot has occurred since scheduling.
try {
    $bootsSinceScheduled = @(Get-WinEvent -FilterHashtable @{
        LogName = 'System'; Id = 6005; StartTime = $deferredScheduledAt
    } -ErrorAction Stop).Count
    if ($bootsSinceScheduled -gt 1) {
        Write-DeferredLog "$bootsSinceScheduled boots have occurred since scheduling; this task should already have run. Removing it." -Level Warning
        Remove-DeferredCleanup
        exit 0
    }
    Write-DeferredLog "Boots since scheduling: $bootsSinceScheduled (expected 1)."
} catch {
    Write-DeferredLog "Could not count boots since scheduling: $($_.Exception.Message)" -Level Warning
}

# GUARD 2 - everything below runs inside try/finally, so the task and script are
# removed even if the body throws. Without this, a failure part-way through would
# leave the task registered and it would fire on EVERY subsequent boot.
try {

Write-DeferredLog "Deferred Autodesk cleanup started (running as $env:USERNAME)."

# --- 1. unregister Autodesk COM / shell extensions -------------------------
$clsidRemoved = 0
foreach ($clsidRoot in @('HKLM\SOFTWARE\Classes\CLSID','HKLM\SOFTWARE\Classes\WOW6432Node\CLSID')) {
    foreach ($regLine in (& reg.exe query $clsidRoot /s /f "Autodesk" /d 2>$null)) {
        if ($regLine -match '^HKEY_LOCAL_MACHINE\\(SOFTWARE\\Classes\\(?:WOW6432Node\\)?CLSID\\\{[^}]+\})\\InprocServer32\s*$') {
            $clsidKey = "HKLM:\$($Matches[1])"
            $inprocDll = (Get-ItemProperty -Path (Join-Path $clsidKey 'InprocServer32') -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
            if ($inprocDll -match '\\Autodesk|^Autodesk\.') {
                Remove-Item -Path $clsidKey -Recurse -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path -Path $clsidKey)) { $clsidRemoved++ }
            }
        }
    }
}
Write-DeferredLog "Unregistered $clsidRemoved Autodesk CLSID(s)."

# --- 2. clean every user hive offline (loaded hives do not exist yet) -------
$keysRemoved = 0
foreach ($userDir in Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue) {
    $ntUser = Join-Path $userDir.FullName 'NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $ntUser)) { continue }
    $mount = "adskdef_$($userDir.Name)"
    & reg.exe load "HKU\$mount" $ntUser 2>&1 | Out-Null
    $hiveWasMounted = ($LASTEXITCODE -eq 0)
    if ($hiveWasMounted) {
        $hiveRoot = "Registry::HKEY_USERS\$mount"
    } else {
        # reg load fails when the hive is ALREADY loaded, i.e. the user was signed
        # in before this task ran (auto-logon can beat an AtStartup trigger). Clean
        # the live hive instead - by now the shell extension DLL is already deleted,
        # so nothing can write the key back.
        $userSid = $null
        try {
            $userSid = (New-Object System.Security.Principal.NTAccount($userDir.Name)).Translate(
                           [System.Security.Principal.SecurityIdentifier]).Value
        } catch { }
        if ($userSid -and (Test-Path -Path "Registry::HKEY_USERS\$userSid")) {
            $hiveRoot = "Registry::HKEY_USERS\$userSid"
            Write-DeferredLog "Hive for $($userDir.Name) already loaded; cleaning it live at $userSid."
        } else {
            Write-DeferredLog "Could not access hive for $($userDir.Name); skipped."
            continue
        }
    }
    foreach ($suffix in 'SOFTWARE\Autodesk','SOFTWARE\WOW6432Node\Autodesk') {
        $hivePath = "$hiveRoot\$suffix"
        if (Test-Path -Path $hivePath) {
            Remove-Item -Path $hivePath -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path -Path $hivePath)) {
                $keysRemoved++
                Write-DeferredLog "Removed $suffix for user $($userDir.Name)."
            } else {
                Write-DeferredLog "FAILED to remove $suffix for user $($userDir.Name)."
            }
        }
    }
    if ($hiveWasMounted) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 500
        foreach ($unloadTry in 1..5) {
            & reg.exe unload "HKU\$mount" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { break }
            [gc]::Collect(); Start-Sleep -Seconds 1
        }
    }
}
Write-DeferredLog "Removed $keysRemoved per-user Autodesk key(s)."

# --- 3. remove folders that are now unlocked -------------------------------
foreach ($folder in @('C:\Program Files\Autodesk','C:\Program Files\Common Files\Autodesk',
                      'C:\Program Files\Common Files\Autodesk Shared','C:\Program Files (x86)\Autodesk',
                      'C:\Program Files (x86)\Common Files\Autodesk Shared','C:\Autodesk')) {
    if (Test-Path -LiteralPath $folder) {
        Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
        $state = if (Test-Path -LiteralPath $folder) { 'still present' } else { 'removed' }
        Write-DeferredLog "Folder ${folder}: $state"
    }
}

# --- 4. ProgramData residue, keeping only the Uninstallers folder ----------
# The live run sweeps this twice, but the uninstall helpers recreate parts of it
# (IDSDK) and anything still held open then could not be deleted. Nothing is
# running yet at this point, so this is the last and cleanest chance.
$programDataPath = 'C:\ProgramData\Autodesk'
$programDataKeep = Join-Path $programDataPath 'Uninstallers'
if (Test-Path -LiteralPath $programDataPath) {
    foreach ($residueItem in @(Get-ChildItem -LiteralPath $programDataPath -Force -ErrorAction SilentlyContinue |
                               Where-Object { $_.FullName -ne $programDataKeep })) {
        Remove-Item -LiteralPath $residueItem.FullName -Recurse -Force -ErrorAction SilentlyContinue
        $state = if (Test-Path -LiteralPath $residueItem.FullName) { 'still present' } else { 'removed' }
        Write-DeferredLog "ProgramData residue $($residueItem.FullName): $state"
    }
}

Write-DeferredLog "Deferred Autodesk cleanup finished."

} catch {
    Write-DeferredLog "[ERROR] Deferred cleanup failed: $($_.Exception.Message)" -Level Error
    Write-DeferredLog "[ERROR] $($_.InvocationInfo.PositionMessage)" -Level Error
} finally {
    # ALWAYS runs - success, failure, or a terminating error part-way through
    Write-DeferredLog "Removing the deferred cleanup task and script."
    Remove-DeferredCleanup
}
'@ -replace '__LOGPATH__', $deferredLog `
   -replace '__SENTINEL__', $deferredDone `
   -replace '__ATTEMPTFILE__', $deferredAttempt `
   -replace '__SCHEDULEDAT__', $deferredScheduledAt

    Set-Content -LiteralPath $deferredScript -Value $deferredBody -Encoding UTF8 -Force

    # stale state from an earlier cleanup would make the new task exit immediately
    Remove-Item -LiteralPath $deferredDone -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $deferredAttempt -Force -ErrorAction SilentlyContinue

    $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$deferredScript`""
    $taskTrigger   = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # GUARD 3 - bounded runtime, never retried, never concurrent. Even if the script
    # somehow failed to remove itself, the task cannot pile up or run forever.
    $taskSettings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
                        -MultipleInstances IgnoreNew -RestartCount 0 `
                        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable:$false
    # -Force replaces any existing task of the same name, so repeated runs never stack
    Register-ScheduledTask -TaskName 'ADSK-DeferredCleanup' -Action $taskAction -Trigger $taskTrigger `
                           -Principal $taskPrincipal -Settings $taskSettings `
                           -Description 'One-shot Autodesk cleanup; removes itself after running.' `
                           -Force -ErrorAction Stop | Out-Null
    return $deferredScript
}

# Verbosity ranks. A message is written when its rank <= the configured threshold.
$script:LogLevelRank = @{ 'None' = 0; 'Error' = 1; 'Warning' = 2; 'Info' = 3; 'Verbose' = 4; 'Debug' = 5 }

function Write-Log {
    [CmdletBinding(DefaultParameterSetName = 'FullEntry')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [string]$Message = "",

        [Parameter(Mandatory = $true)]
        [string]$Component,

        [Parameter(Mandatory = $false)]
        [string]$Source,

        # Full path to the log FILE (the script-level -LogPath is a directory)
        [Parameter(Mandatory = $true)]
        [string]$LogFile,

        [Parameter(Mandatory = $false)]
        [datetime]$Time,

        # Severity of THIS message. Filtered against $script:LogLevel, and also
        # drives the CMTrace type field (1 = info, 2 = warning, 3 = error).
        [Parameter(Mandatory = $false)]
        [ValidateSet('Error','Warning','Info','Verbose','Debug')]
        [string]$Level = 'Info',

        [Parameter(ParameterSetName = 'Start')]
        [switch]$StartLogEntry,

        [Parameter(ParameterSetName = 'Add')]
        [switch]$AddLogEntryData,

        [Parameter(ParameterSetName = 'End')]
        [switch]$EndLogEntry
    )

    $threshold = $script:LogLevelRank[$script:LogLevel]
    if ($null -eq $threshold) { $threshold = $script:LogLevelRank['Verbose'] }
    $suppress = $script:LogLevelRank[$Level] -gt $threshold
    $cmType = switch ($Level) { 'Error' { 3 } 'Warning' { 2 } default { 1 } }

    # Auto-detect Source if not provided
    $callerLine = $MyInvocation.ScriptLineNumber
    $scriptName = Split-Path -Path $MyInvocation.ScriptName -Leaf
    if ([string]::IsNullOrWhiteSpace($scriptName)) { $scriptName = "Interactive" }
    $Source = if ([string]::IsNullOrWhiteSpace($Source)) {
        "${scriptName}:${callerLine}"
    } else {
        "${scriptName}:${callerLine}($Source)"
    }

    # Setup time values
    $timestamp = if ($Time) { $Time } else { Get-Date }
    $dateStr = $timestamp.ToString("MM-dd-yyyy")
    $timeStr = $timestamp.ToString("HH:mm:ss.fff")
    $tzOffset = (Get-TimeZone).BaseUtcOffset.TotalMinutes
    $tzFormatted = if ($tzOffset -ge 0) { "+{0:000}" -f $tzOffset } else { "-{0:000}" -f [math]::Abs($tzOffset) }
    $processId = [System.Diagnostics.Process]::GetCurrentProcess().Id

    $statePath = "$LogFile.state"
    $logDir = [System.IO.Path]::GetDirectoryName($LogFile)
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force -WhatIf:$false | Out-Null
    }

    # Add-Content has no retry of its own; under contention it throws and the
    # line is lost silently. Retry briefly, and say so if the line is dropped.
    function Add-LogLine {
        param([string]$Path, [string]$Value)
        foreach ($attempt in 1..10) {
            try { Add-Content -Path $Path -Value $Value -ErrorAction Stop -WhatIf:$false; return }
            catch { Start-Sleep -Milliseconds 100 }
        }
        Write-Warning "Log line lost (file locked after 10 attempts): $Value"
    }

    function Close-UnclosedLog {
        if (Test-Path $statePath) {
            $state = Get-Content $statePath -Raw | ConvertFrom-Json
            Remove-Item $statePath -Force
            # never emit a closer for an entry whose opener was suppressed
            if (-not $state.Suppressed) {
                $autocloseTime = [datetime]::Parse($state.Time)
                $dateAuto = $autocloseTime.ToString("MM-dd-yyyy")
                $timeAuto = $autocloseTime.ToString("HH:mm:ss.fff")
                $tzAuto = if ($tzOffset -ge 0) { "+{0:000}" -f $tzOffset } else { "-{0:000}" -f [math]::Abs($tzOffset) }
                $autoClose = "]LOG]!><time=""$timeAuto$tzAuto"" date=""$dateAuto"" component=""$($state.Component)"" context=""autoClosedLogEntryByFollowingLog"" type=""$($state.Type)"" thread=""$processId"" file=""$Source"">"
                Add-LogLine -Path $state.LogFile -Value $autoClose
            }
        }
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Start' {
            Close-UnclosedLog
            if ([string]::IsNullOrEmpty($Message)) { $Message = "LogEntry:" }
            if (-not $suppress) { Add-LogLine -Path $LogFile -Value "<![LOG[$Message" }

            # the opener's level decides the whole entry; Add/End honour this flag
            $state = @{
                Component  = $Component
                Source     = $Source
                LogFile    = $LogFile
                Time       = $timestamp.ToString("o")
                Suppressed = $suppress
                Type       = $cmType
            }
            $state | ConvertTo-Json -Compress | Out-File -FilePath $statePath -Encoding UTF8 -Force -WhatIf:$false
        }

        'Add' {
            # body text inside an already-open envelope - safe to drop individually
            if (-not $suppress -and $Message) {
                Add-LogLine -Path $LogFile -Value $Message
            }
        }

        'End' {
            if (Test-Path $statePath) {
                $state = Get-Content $statePath -Raw | ConvertFrom-Json
                Remove-Item $statePath -Force
                if (-not $state.Suppressed) {
                    $line = "$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$($state.Component)"" context="""" type=""$($state.Type)"" thread=""$processId"" file=""$($state.Source)"">"
                    Add-LogLine -Path $state.LogFile -Value $line
                }
            }
            elseif (-not $suppress) {
                $line = "$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""$cmType"" thread=""$processId"" file=""$Source"">"
                Add-LogLine -Path $LogFile -Value $line
            }
        }

        default {
            Close-UnclosedLog
            if (-not $suppress) {
                $line = "<![LOG[$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""$cmType"" thread=""$processId"" file=""$Source"">"
                Add-LogLine -Path $LogFile -Value $line
            }
        }
    }
}



# Anchored so unrelated software is not force-killed (the old unanchored "Inventor"
# matched e.g. InventoryAgent). ADP* included: ADPClientService holds cer.dll and was
# never matched by the old ADSK-only pattern.
$script:AdskProcNamePattern = '^(Autodesk|Adsk|ADP|AutoCAD|acad|cer_service|dwgviewr|message_router|AdODIS|senddmp)|^Inventor(Server)?$'

function Get-AdskServices {
    # Name is matched too: ADPSvc has no "Autodesk" in its DisplayName
    @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match 'Autodesk' -or $_.DisplayName -match 'ADSK' -or $_.Name -match '^(Autodesk|Adsk|ADP)'
    })
}

function Get-AdskProcesses {
    @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -match $script:AdskProcNamePattern -or $_.Description -match 'Autodesk'
    })
}

function Stop-AdskServiceHard {
    <#
        Stop a service and PROVE it stopped.

        Stop-Service blocks on the SCM and then gives up quietly when a service does
        not answer SERVICE_CONTROL_STOP - that is what "Waiting for service ... to
        stop" means. The hosting process survives, keeps its file handles, and the
        folder deletion later fails. So: disable it (the SCM must not restart it),
        request the stop without blocking, poll for the result, and if it is still
        running terminate the hosting process by PID and confirm.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutSeconds = 30
    )
    $result = [ordered]@{ Name = $Name; Stopped = $false; Killed = $false; Message = '' }

    if (-not (Test-ShouldProcess -Target "service $Name" -Action 'Disable and stop')) {
        $result.Message = 'skipped (WhatIf)'
        return [pscustomobject]$result
    }

    # disable first so the SCM cannot bring it straight back
    & sc.exe config $Name start= disabled 2>&1 | Out-Null

    # capture the PID BEFORE stopping - it reads 0 once the service reports stopped
    $servicePid = 0
    try { $servicePid = [int](Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop).ProcessId } catch { }

    # non-blocking stop request; Stop-Service would hang on an unresponsive service
    & sc.exe stop $Name 2>&1 | Out-Null

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $svc -or $svc.Status -eq 'Stopped') { $result.Stopped = $true; break }
    } while ((Get-Date) -lt $deadline)

    if (-not $result.Stopped -and $servicePid -gt 0) {
        try {
            Stop-Process -Id $servicePid -Force -ErrorAction Stop
            $result.Killed = $true
            Start-Sleep -Seconds 2
            $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if ($null -eq $svc -or $svc.Status -eq 'Stopped') { $result.Stopped = $true }
            $result.Message = "did not answer SERVICE_CONTROL_STOP after ${TimeoutSeconds}s; terminated hosting process PID $servicePid"
        } catch {
            $result.Message = "stop timed out and PID $servicePid could not be terminated: $($_.Exception.Message)"
        }
    } elseif (-not $result.Stopped) {
        $result.Message = "stop timed out after ${TimeoutSeconds}s and no hosting PID was available"
    }
    [pscustomobject]$result
}

function Invoke-AdskServiceAndProcessSweep {
    <#
        Stop every Autodesk service, then kill every Autodesk process, verifying both.

        Called more than once. Uninstallers routinely start their own services again
        on the way out, and anything still running at deletion time holds handles that
        make the folder removal fail - so this runs again immediately before the
        filesystem cleanup rather than only at the start.
    #>
    param([string]$Phase = 'initial')

    Write-Log -Message "Autodesk service/process sweep ($Phase):" -StartLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile

    $services = Get-AdskServices
    if ($services.Count -eq 0) {
        Write-Log -Message "  no Autodesk services present" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    } else {
        Write-Log -Message "  found $($services.Count) service(s): $(($services | Select-Object -ExpandProperty Name) -join ', ')" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        foreach ($svc in $services) {
            $stopResult = Stop-AdskServiceHard -Name $svc.Name
            if ($stopResult.Stopped -and -not $stopResult.Killed) {
                Write-Log -Message "  stopped service $($svc.Name)" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            } elseif ($stopResult.Stopped -and $stopResult.Killed) {
                Write-Log -Message "  service $($svc.Name): $($stopResult.Message)" -Level Warning -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                Write-Warning "Service $($svc.Name) ignored the stop request; its process was terminated."
            } elseif ($WhatIfPreference) {
                # nothing was attempted, so this is not a failure worth reporting
                Write-Log -Message "  (WhatIf) would disable and stop service $($svc.Name)" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            } else {
                Write-Log -Message "  [ERROR] service $($svc.Name) still running: $($stopResult.Message)" -Level Error -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                Write-Warning "Service $($svc.Name) could not be stopped: $($stopResult.Message)"
            }
        }
    }

    # processes AFTER services, so the SCM cannot respawn what we kill
    $remaining = Get-AdskProcesses
    if ($remaining.Count -gt 0) {
        Write-Log -Message "  found $($remaining.Count) process(es): $(($remaining | Select-Object -ExpandProperty ProcessName -Unique) -join ', ')" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    foreach ($pass in 1..3) {
        if ($remaining.Count -eq 0) { break }
        foreach ($proc in $remaining) {
            if (-not (Test-ShouldProcess -Target "$($proc.ProcessName) (PID $($proc.Id))" -Action 'Terminate process')) { continue }
            try { Stop-Process -InputObject $proc -Force -ErrorAction Stop }
            catch {
                Write-Log -Message "  [ERROR] could not stop $($proc.ProcessName) (PID $($proc.Id)) on pass ${pass}: $($_.Exception.Message)" -Level Error -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            }
        }
        if ($WhatIfPreference) { break }
        Start-Sleep -Seconds 2
        $remaining = Get-AdskProcesses
    }
    if ($remaining.Count -gt 0 -and $WhatIfPreference) {
        # -WhatIf killed nothing, so "still running" is expected and not a finding
        Write-Log -Message "  (WhatIf) would terminate $($remaining.Count) process(es)" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    } elseif ($remaining.Count -gt 0) {
        $stillRunning = ($remaining | Select-Object -ExpandProperty ProcessName -Unique) -join ', '
        Write-Log -Message "  [ERROR] still running after 3 passes: $stillRunning" -Level Error -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Write-Warning "Still running after 3 attempts: $stillRunning. These hold file handles; a reboot and second run will be required."
    } else {
        Write-Log -Message "  no Autodesk processes remain" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }

    Write-Log -Message "Sweep ($Phase) complete." -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    return $remaining.Count
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ( -not $isElevated ) {
    Write-Log -Message "Script must be run with administrative privileges." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    $("") ; Write-Warning "`r`nThis script must be run with administrative privileges. Please restart the script in an elevated PowerShell session.`r`n"
    Wait-ForUser ; $("")
    Write-Log -Message "Exiting Uninstall-Script with Exit Code 1" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    exit 1
} else {
    Write-Log -Message "Starting AutoDeskCleanRemove.ps1;" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -StartLogEntry
    Write-Log -Message "Script Version: 3.0;" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -AddLogEntryData
    Write-Log -Message "Author: Halatschek Wolfram;`r`nScript-Source: 'https://github.com/halatsWol/PowerShell-Tools/blob/main/scripts/AutoDeskCleanRemove.ps1';" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -EndLogEntry
    Write-Log -Message "Script started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -StartLogEntry
    Write-Log -Message "Hostname: $($env:COMPUTERNAME);" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -AddLogEntryData
    Write-Log -Message "User: $($env:USERNAME);" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -EndLogEntry
    Write-Host "`r`nThis script will remove all Autodesk products from your system."
    Write-Host "Please ensure that you have closed all Autodesk applications before proceeding."
    # Fusion is not an MSI/ODIS product - it has no folder under
    # C:\ProgramData\Autodesk\Uninstallers, so nothing here uninstalls it. Its payload
    # under %LOCALAPPDATA%\Autodesk\webdeploy is nevertheless deleted along with the
    # rest of AppData\Local\Autodesk, while its per-user uninstall entry (HKCU, which
    # this script does not clean) survives. The result is a half-removed install, so
    # this has to be a warning rather than a note.
    Write-Warning "Autodesk Fusion is NOT uninstalled by this script - but it WILL be corrupted by it.`r`nFusion installs per-user under %LOCALAPPDATA%\Autodesk\webdeploy. This script deletes that folder without ever running Fusion's own uninstaller, which leaves the program files gone while Fusion still appears in Apps & Features.`r`nIf Fusion is installed, stop now and uninstall it manually first."
    Write-Warning "Please note that this may prompt OneDrive regarding the deletion of files. This is to be expected.`r`nMultiple Windows may appear, please do not close them manually.`r`nThe script will close them automatically after the uninstallation process."
    Wait-ForUser
    Write-Host "`r`n`r`nStarting Autodesk Clean Uninstall...`r`nThis may take a while, please be patient...`r`n"
    # Services first, then processes - killing a service's process only makes the SCM
    # restart it. Each stop is verified, and a service that ignores SERVICE_CONTROL_STOP
    # has its hosting process terminated (see Stop-AdskServiceHard).
    $null = Invoke-AdskServiceAndProcessSweep -Phase 'initial'
    # Stop all Autodesk Tasks
    Write-Log -Message "Stopping all Autodesk tasks:" -StartLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    # Get-CimInstance, not Get-WmiObject: the latter is removed in PowerShell 6+
    $tasks = @(Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE Name LIKE '%Autodesk%' OR Name LIKE '%ADSK%' OR Name LIKE '%ADP%'" -ErrorAction SilentlyContinue)
    if ($tasks.Count -eq 0) {
        Write-Log -Message "No Autodesk tasks found." -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    } else {
        foreach ($task in $tasks) {
            Write-Log -Message "Stopping Autodesk task: $($task.Name) (PID: $($task.ProcessId))" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            # the process may already have exited during the phases above - that is a
            # success, not an error, so do not report it as one
            $taskProc = Get-Process -Id $task.ProcessId -ErrorAction SilentlyContinue
            if ($null -eq $taskProc) {
                Write-Log -Message "Task $($task.Name) (PID: $($task.ProcessId)) had already exited." -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            } else {
                try {
                    Stop-Process -InputObject $taskProc -Force -ErrorAction Stop
                } catch {
                    Write-Log -Message "[ERROR] Failed to terminate process $($task.Name) (PID: $($task.ProcessId)): $($_.Exception.Message)" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                    Write-Warning "Failed to terminate process $($task.Name) (PID: $($task.ProcessId)): $($_.Exception.Message)"
                }
            }
        }
        Write-Log -Message "All Autodesk tasks have been stopped." -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }

    # Transform GUID to Installer format: {GUID} -> GUID packed
    function Convert-GuidToInstallerKey {
        param (
            [Parameter(Mandatory)]
            [string]$guid
        )
        $guid = $guid.Trim('{}')
        $parts = $guid -split '-'
        function Get-ReverseOrder($hex) {
            $hex=[string]$hex
            $charArray = $hex.ToCharArray()
            [Array]::Reverse($charArray)
            return -join $charArray
        }
        # Rearrange according to MSI installer registry format
        $ProductCode = ""
        $ProductCode += [String](Get-ReverseOrder($parts[0])) + [String](Get-ReverseOrder($parts[1])) + [String](Get-ReverseOrder($parts[2]))
        #split $parts[3] into parts of 2 characters each
        $ProductCode += [String](($parts[3] -split '(.{2})' | ForEach-Object { [String](Get-ReverseOrder($_)) }) -join '')
        $ProductCode += [String](($parts[4] -split '(.{2})' | ForEach-Object { [String](Get-ReverseOrder($_)) }) -join '')
        return $ProductCode.ToUpper()
    }

    # Is this ProductCode still registered with Windows Installer?
    # msiexec /x works from the product code alone, so the cached local package
    # is only diagnostic - it must not gate whether the uninstall runs.
    function Test-MsiProductInstalled {
        param (
            [Parameter(Mandatory)]
            [string]$ProductCode
        )
        foreach ($base in @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")) {
            if (Test-Path (Join-Path -Path $base -ChildPath $ProductCode)) { return $true }
        }
        $installerKey = Convert-GuidToInstallerKey $ProductCode
        foreach ($base in @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products",
            "HKLM:\SOFTWARE\Classes\Installer\Products",
            "HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Products")) {
            if (Test-Path (Join-Path -Path $base -ChildPath $installerKey)) { return $true }
        }
        return $false
    }

    function Get-MsiLocalPackagePath {
        param (
            [Parameter(Mandatory)]
            [string]$ProductCode
        )

        # check if guid is in registry uninstall keys
        $uninstallRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        $uninstallRegPathWow6432 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        $GuidRegPath = Join-Path -Path $uninstallRegPath -ChildPath $ProductCode
        if (-not (Test-Path $GuidRegPath)) {
            $GuidRegPath = Join-Path -Path $uninstallRegPathWow6432 -ChildPath $ProductCode
            if (-not (Test-Path $GuidRegPath)) {
                $GuidRegPath = $null
            }
        }

        if ($null -ne $GuidRegPath) {
            $InstallSourceProp = Get-ItemProperty -Path $GuidRegPath -Name InstallSource -ErrorAction SilentlyContinue
            if ($null -ne $InstallSourceProp -and -not [string]::IsNullOrWhiteSpace($InstallSourceProp.InstallSource)) {
                $InstallSourceMsi = Get-ChildItem -Path (Join-Path -Path $InstallSourceProp.InstallSource -ChildPath '*.msi') -ErrorAction SilentlyContinue |
                                    Select-Object -First 1
                if ($null -ne $InstallSourceMsi) {
                    return $InstallSourceMsi.FullName
                }
            }

        }

        # If not found in uninstall keys, try to find it in the Installer Products registry
        $installerKey = Convert-GuidToInstallerKey $ProductCode
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$installerKey\InstallProperties"
        if (-not (Test-Path $regPath)) {
            $regPath = "HKLM:\SOFTWARE\Classes\Installer\Products\$installerKey"
            if (-not (Test-Path $regPath)) {
                $regPath = "HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Products\$installerKey"
            }

            if (Test-Path $regPath) {
                # SourceList is a SUBKEY, not a value; LastUsedSource lives inside it
                $sourceListPath = Join-Path -Path $regPath -ChildPath "SourceList"
                if (Test-Path $sourceListPath) {
                    $localPackageSource = (Get-ItemProperty -Path $sourceListPath -Name LastUsedSource -ErrorAction SilentlyContinue).LastUsedSource
                    # prefix letter varies: n = network/local, u = URL, m = media
                    if ($localPackageSource -match "^[a-z];\d+;(.+)$" -and (Test-Path $matches[1])) {
                        return $matches[1]
                    }
                }
                return $null
            } else {
                return $null
            }
        } else {
            $localPackageSource = Get-ItemProperty -Path $regPath -Name LocalPackage -ErrorAction SilentlyContinue
            $localPackageSource = $localPackageSource.LocalPackage
            # check if $localPackagePath not null or empty, or if path exists
            if ( -not [string]::IsNullOrEmpty($localPackageSource) -and (Test-Path $localPackageSource)  ) {
                return $localPackageSource
            } else {
                return $null
            }
        }
    }

    $UninstallersPath="C:\ProgramData\Autodesk\Uninstallers"
    $UninstallHelperBundleData="bundle_data.xml"

    # get folders in the Uninstallers path
    $UninstallersFolders = Get-ChildItem -Path $UninstallersPath -Directory -ea SilentlyContinue | Where-Object { $_.Name -ne "metadata" -and $_.Name -ne "Autodesk Access" -and $_.Name -ne "Autodesk Genuine Service" -and $_.Name -ne "Autodesk Installer" -and $_.Name -ne "Autodesk Identity Manager" -and $_.Name -ne "Autodesk Identity Manager Component" }
    $productsSorted = New-Object System.Collections.Generic.List[System.Object]
    # put folders with Object Enabler in the ProductsSorted array
    foreach ($folder in $UninstallersFolders) {
        $folderName = $folder.Name
        if ($folderName -match "Enabler") {
            $productsSorted.Add($folder)
            # remove the folder from the UninstallersFolders array
            $UninstallersFolders = $UninstallersFolders | Where-Object { $_.Name -ne $folderName }
        }
    }

    # put update folders (such as containing "2024.0.1","SP0.1","Update" etc ) in the ProductsSorted array
    foreach ($folder in $UninstallersFolders) {
        $folderName = $folder.Name
        if ($folderName -match "Update|SP\d+(\.\d+)?|20\d{2}\.\d+(\.\d+)?") {
            $productsSorted.Add($folder)
            # remove the folder from the UninstallersFolders array
            $UninstallersFolders = $UninstallersFolders | Where-Object { $_.Name -ne $folderName }
        }
    }

    # add remainders
    foreach ($folder in $UninstallersFolders) {
        $folderName = $folder.Name
        $productsSorted.Add($folder)
        $UninstallersFolders = $UninstallersFolders | Where-Object { $_.Name -ne $folderName }
    }
    $productsSorted.Add($UninstallersFolders)


    $GlobalProgressPercentage = 0
    $TotalUninstallProgressPercentage = 0
    $InstallDirTotalProgressPercentage = 0
    $RegistryTotalProgressPercentage = 0
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
    $folderPercentage = 99 / ($productsSorted.Count+9)
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage  -Id 1
    foreach ($folder in $productsSorted) {
        if ($null -ne $folder) {
            $folderName = $folder.Name
            $UninstallHelperBundleDataPath = Join-Path -Path $folder.FullName -ChildPath $UninstallHelperBundleData
            if (Test-Path -Path $UninstallHelperBundleDataPath) {
                # a malformed bundle_data.xml must not abort the whole run
                try {
                    $xmlContent = [xml](Get-Content -Path $UninstallHelperBundleDataPath -Raw -ErrorAction Stop)
                } catch {
                    Write-Log -Message "[ERROR] Failed to parse ${UninstallHelperBundleDataPath}: $($_.Exception.Message)" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                    Write-Warning "Failed to parse bundle data for $folderName. Skipping this product."
                    $TotalUninstallProgressPercentage += $folderPercentage
                    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
                    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
                    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
                    continue
                }
                $allPackages = @()
                $bundleNodes = $xmlContent.SelectNodes('//bundleData')
                foreach ($bundle in $bundleNodes) {
                    $packageNodes = $bundle.SelectNodes('.//m_packages')
                    foreach ($packageGroup in $packageNodes) {
                        foreach ($item in $packageGroup.item) {
                            $obj = [PSCustomObject]@{
                                bundleName      = $bundleNodes.m_displayName
                                bundleUPI2      = $bundleNodes.m_bundleUPI2
                                packageType     = $item.m_packageType
                                productCode     = $item.m_productCode
                            }
                            $allPackages += $obj
                        }
                    }
                }

                # Output all parsed items
                if ($allPackages.Count -gt 0) {
                    $packagePercentage = $folderPercentage / $allPackages.Count
                    foreach ($package in $allPackages) {
                        if ([int]$package.packageType -eq 0) {
                            $productCode = $package.productCode
                            if ($productCode) {
                                Write-Log -Message "Processing package: $($package.bundleName) - Product Code: $productCode" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                if (-not (Test-ShouldProcess -Target "MSI product $productCode" -Action 'Uninstall')) {
                                    # -WhatIf: report and move on
                                } elseif (Test-MsiProductInstalled -ProductCode $productCode) {
                                    # informational only - a missing cached package must not skip the uninstall
                                    $localPackagePath = Get-MsiLocalPackagePath -ProductCode $productCode
                                    if ($null -ne $localPackagePath) {
                                        Write-Log -Message "Cached local package for ${productCode}: $localPackagePath" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                    } else {
                                        Write-Log -Message "No cached local package found for $productCode; uninstalling by product code." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                    }
                                    $MsiLogFileName = "Uninstall_$($productCode)_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
                                    $MsiLogFullPath = Join-Path -Path $MsiLogPath -ChildPath $MsiLogFileName
                                    Write-Log -Message "msiexec /x $productCode /qn /norestart REBOOT=ReallySuppress" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                    $msiProc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x `"$productCode`" /qn /norestart REBOOT=ReallySuppress /l*v `"$MsiLogFullPath`"" -Wait -PassThru
                                    $msiExit = $msiProc.ExitCode
                                    $msiFailed = $false
                                    switch ($msiExit) {
                                        0    { Write-Log -Message "Uninstalled $productCode successfully (exit 0)." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile }
                                        1605 { Write-Log -Message "Product $productCode was not installed (exit 1605)." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile }
                                        3010 { $script:RebootRequired = $true
                                               Write-Log -Message "Uninstalled $productCode; reboot required (exit 3010)." -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile }
                                        1641 { $script:RebootRequired = $true
                                               Write-Log -Message "Uninstalled $productCode; reboot suppressed (exit 1641)." -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile }
                                        default {
                                               $msiFailed = $true
                                               $script:FailedPackages.Add([pscustomobject]@{ ProductCode = $productCode; ExitCode = $msiExit; Label = '' })
                                               Write-Log -Message "[ERROR] msiexec returned $msiExit for $productCode" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                               Write-Warning "Failed to uninstall $productCode (msiexec exit $msiExit)."
                                        }
                                    }
                                    if (Test-Path $MsiLogFullPath) {
                                        $MsiLogContent = Get-Content -Path $MsiLogFullPath -ErrorAction SilentlyContinue
                                        if ($null -ne $MsiLogContent) {
                                            # Full MSI log at Verbose (the historical default), wrapped in a real
                                            # entry so -AddLogEntryData has an envelope instead of emitting raw lines
                                            Write-Log -Message "MSI Log for Product Code: $productCode" -Level Verbose -StartLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                            Write-Log -Message "{`r`n$($MsiLogContent -join "`r`n")`r`n}" -Level Verbose -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                            Write-Log -Message "" -Level Verbose -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                            # keep failure diagnostics even when the full log is filtered out
                                            if ($msiFailed) {
                                                $msiTail = $MsiLogContent | Select-String -Pattern 'Return value 3|MainEngineThread is returning|Error \d{4}' | Select-Object -Last 20
                                                if ($msiTail) {
                                                    Write-Log -Message "[ERROR] MSI failure detail for ${productCode}:`r`n$($msiTail -join "`r`n")" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                                }
                                            }
                                        } else {
                                            Write-Log -Message "MSI Log file is empty for Product Code: $productCode" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                        }
                                        Remove-Item -Path $MsiLogFullPath -Force -ErrorAction SilentlyContinue
                                    } else {
                                        Write-Log -Message "MSI Log file not found for Product Code: $productCode" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                    }
                                } else {
                                    Write-Log -Message "Product Code $productCode is not registered with Windows Installer; skipping." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                                }
                            }
                        }
                        $TotalUninstallProgressPercentage += $packagePercentage
                        Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
                        $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
                        Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
                    }
                } else {
                    Write-Log -Message "No packages found in bundle data for $folderName" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                    $TotalUninstallProgressPercentage += $folderPercentage
                    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
                    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
                    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
                }
            } else {
                Write-Log -Message "Uninstall Helper bundle data not found for $folderName" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                $TotalUninstallProgressPercentage += $folderPercentage
                Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
                $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
                Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
            }
        } else {
            $TotalUninstallProgressPercentage += $folderPercentage
            Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
            $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
            Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
        }
    }

    $AdODISPath = "C:\Program Files\Autodesk\AdODIS\V1\RemoveODIS.exe"
    if ((Test-Path -Path $AdODISPath) -and (Test-ShouldProcess -Target $AdODISPath -Action 'Remove Autodesk ODIS')) {
        Write-Log -Message "Removing Autodesk ODIS..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Start-Process -FilePath $AdODISPath -ArgumentList "--mode unattended" -Wait
    } else {
        Write-Log -Message "Autodesk ODIS Remover not found at $AdODISPath" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Remove Autodesk Access
    $AdskAccessPath = "C:\Program Files\Autodesk\AdODIS\V1\Access\RemoveAccess.exe"
    if ((Test-Path -Path $AdskAccessPath) -and (Test-ShouldProcess -Target $AdskAccessPath -Action 'Remove Autodesk Access')) {
        Write-Log -Message "Removing Autodesk Access..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Start-Process -FilePath $AdskAccessPath -ArgumentList "--mode unattended" -Wait
    } else {
        Write-Log -Message "Autodesk Access Remover not found at $AdskAccessPath" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # run Autodesk Access uninstall helper
    $AdskAccessUninstHelper = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Access\AdskUninstallHelper.exe"
    if (( Test-Path -Path $AdskAccessUninstHelper ) -and (Test-ShouldProcess -Target $AdskAccessUninstHelper -Action 'Run Autodesk Access uninstall helper')) {
        Write-Log -Message "Running Autodesk Access uninstall helper..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Start-Process -FilePath $AdskAccessUninstHelper -Wait
    } else {
        Write-Log -Message "Autodesk Access uninstall helper not found at $AdskAccessUninstHelper" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Remove Autodesk Licensing
    $AdskLicensingPath = "C:\Program Files (x86)\Common Files\Autodesk Shared\AdskLicensing\uninstall.exe"
    if ((Test-Path -Path $AdskLicensingPath) -and (Test-ShouldProcess -Target $AdskLicensingPath -Action 'Remove Autodesk Licensing')) {
        Write-Log -Message "Removing Autodesk Licensing..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Start-Process -FilePath $AdskLicensingPath -ArgumentList "--mode unattended" -Wait
    } else {
        Write-Log -Message "Autodesk Licensing Remover not found at $AdskLicensingPath" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Remove Autodesk Identity Manager
    $AdskIdentityManagerPath = "C:\Program Files\Autodesk\AdskIdentityManager\uninstall.exe"
    if ((Test-Path -Path $AdskIdentityManagerPath) -and (Test-ShouldProcess -Target $AdskIdentityManagerPath -Action 'Remove Autodesk Identity Manager')) {
        Write-Log -Message "Removing Autodesk Identity Manager..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Start-Process -FilePath $AdskIdentityManagerPath -ArgumentList "--mode unattended" -Wait
    } else {
        Write-Log -Message "Autodesk Identity Manager Remover not found at $AdskIdentityManagerPath" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Remove in C:\ProgramData\FLEXnet the files starting with adsk
    $flexnetPath = "C:\ProgramData\FLEXnet"
    if ( Test-Path -Path $flexnetPath) {
        Write-Log -Message "Removing Autodesk FLEXnet files..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        $flexnetFiles = Get-ChildItem -Path $flexnetPath -File -Recurse -ea SilentlyContinue | Where-Object { $_.Name -match "^adsk" }
        foreach ($file in $flexnetFiles) {
            try {
                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
            } catch {
                Write-Log -Message "[ERROR] Failed to remove $($file.FullName): $($_.Exception.Message)" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            }
        }
    }
    $TotalUninstallProgressPercentage += 1
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0


    # Second sweep, immediately before the destructive filesystem phase. The
    # uninstallers above routinely start their own services again on the way out
    # (Autodesk Access and the licensing agent both do), and anything running here
    # holds file handles that make the deletion below fail silently.
    $AdskStillRunning = Invoke-AdskServiceAndProcessSweep -Phase 'pre-deletion'
    if ($AdskStillRunning -gt 0) {
        Write-Log -Message "[ERROR] $AdskStillRunning Autodesk process(es) still running going into folder deletion; expect locked files." -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }

    Write-Log -Message "Deleting Autodesk folders..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    $autodeskFoldersGlobal = @(
        "C:\Program Files\Autodesk",
        "C:\Program Files\Common Files\Autodesk",
        "C:\Program Files\Common Files\Autodesk Shared",
        "C:\Program Files (x86)\Autodesk",
        "C:\Program Files (x86)\Common Files\Autodesk Shared"
    )
    $autodeskFoldersUser = @(
        "AppData\Local\Autodesk",
        "AppData\Roaming\Autodesk"
    )
    $autodeskFoldersAll = New-Object System.Collections.Generic.List[System.Object]
    foreach ($folder in $autodeskFoldersGlobal) {
        if (Test-Path -Path $folder) {
            $autodeskFoldersAll.Add($folder)
        }
    }

    $UserDirs= Get-ChildItem -Path "C:\Users\" -Directory -ea SilentlyContinue
    foreach ($UserDir in $UserDirs) {
        foreach ($folder in $autodeskFoldersUser) {
            # test first, same as the global list - otherwise absent paths skew the progress denominator
            $UserFolderPath = Join-Path -Path $UserDir.FullName -ChildPath $folder
            if (Test-Path -Path $UserFolderPath) {
                $autodeskFoldersAll.Add($UserFolderPath)
            }
        }
    }

	$programDataPath = "C:\ProgramData\Autodesk"
	$excludePath     = Join-Path -Path $programDataPath -ChildPath Uninstallers
	if (Test-Path $programDataPath) {
    Get-ChildItem -Path $programDataPath -Force |
        Where-Object { $_.FullName -ne $excludePath } |
        ForEach-Object {
            $autodeskFoldersAll.Add($_.FullName)
        }
	}

    if ($autodeskFoldersAll.Count -eq 0) {
        $InstallDirPercentage = 0
        $InstallDirTotalProgressPercentage = 100
        Write-Log -Message "No Autodesk folders present to delete." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Write-Progress -Activity "Post Uninstall: FileSystem Cleanup" -Status "100% Complete:" -PercentComplete 100 -Id 2
    } else {
        $InstallDirPercentage = 100 / $autodeskFoldersAll.Count
    }
    foreach ($folder in $autodeskFoldersAll) {
        if ((Test-Path -Path $folder) -and (Test-ShouldProcess -Target $folder -Action 'Delete folder recursively')) {
            Write-Log -Message "Deleting folder $folder" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            # Deliberately NOT -ErrorAction Stop: that aborts the recursive delete at
            # the first locked/ACL-protected file and leaves the rest behind. Collect
            # the errors instead, so best-effort deletion is kept AND failures are visible.
            $delErrors = $null
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable delErrors
            foreach ($delError in $delErrors) {
                Write-Log -Message "[ERROR] Failed to delete an item under ${folder}: $($delError.Exception.Message)" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            }
            if (Test-Path -Path $folder) {
                Write-Log -Message "[ERROR] Folder still present after delete attempt: $folder" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                Write-Warning "Could not fully delete $folder ($($delErrors.Count) item(s) failed)."
            }
        }
        $InstallDirTotalProgressPercentage += $InstallDirPercentage
        Write-Progress -Activity "Post Uninstall: FileSystem Cleanup" -Status "$([math]::Round($InstallDirTotalProgressPercentage, 2))% Complete:" -PercentComplete $InstallDirTotalProgressPercentage -Id 2
        $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
        Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
    }
    # Anything that survived the deletion above is held open by a running process.
    # Schedule it for removal at next boot, before anything can reload it.
    foreach ($folder in $autodeskFoldersAll) {
        if (-not (Test-Path -Path $folder)) { continue }
        foreach ($leftoverFile in @(Get-ChildItem -LiteralPath $folder -Recurse -Force -File -ErrorAction SilentlyContinue)) {
            $script:PendingDeletePaths.Add($leftoverFile.FullName)
        }
        # directories deepest-first, so each is empty by the time it is processed
        foreach ($leftoverDir in @(Get-ChildItem -LiteralPath $folder -Recurse -Force -Directory -ErrorAction SilentlyContinue |
                                   Sort-Object { $_.FullName.Length } -Descending)) {
            $script:PendingDeletePaths.Add($leftoverDir.FullName)
        }
        $script:PendingDeletePaths.Add($folder)
    }
    if ($script:PendingDeletePaths.Count -gt 0) {
        try {
            # returns the paths it scheduled AND empties the list, so read the result
            # rather than $script:PendingDeletePaths, which is empty by now
            $scheduledPaths = @(Set-PendingFileDeletes)
            if ($scheduledPaths.Count -gt 0) {
                $script:RebootRequired = $true
                Write-Log -Message "Scheduled $($scheduledPaths.Count) locked item(s) for deletion at next boot." -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -StartLogEntry
                Write-Log -Message ($scheduledPaths -join "`r`n") -Level Verbose -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                Write-Log -Message "" -Level Warning -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                Write-Host "$($scheduledPaths.Count) locked item(s) will be removed on the next restart." -ForegroundColor Yellow
            }
        } catch {
            Write-Log -Message "[ERROR] Failed to schedule pending file deletes: $($_.Exception.Message)" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            Write-Warning "Could not schedule locked files for deletion at next boot: $($_.Exception.Message)"
        }
    }

    # NOTE: the HKLM/HKU Autodesk key cleanup runs after the Genuine Service and
    # uninstall-helper block below, so no uninstaller can write keys back afterwards.

    # uninstall Autodesk Genuine Service
    Stop-Service -Name "GenuineService" -Force -ErrorAction SilentlyContinue
    # Win32_Product forces an MSI consistency check on EVERY installed product on the
    # machine - slow, and known to trigger unrelated repairs. Read the uninstall hive.
    $adskGenuineServiceGUID = $null
    foreach ($GenuineBase in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                               "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")) {
        $GenuineHit = Get-ChildItem -Path $GenuineBase -ErrorAction SilentlyContinue | Where-Object {
            (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName -like 'Autodesk Genuine Service*'
        } | Select-Object -First 1
        if ($GenuineHit) { $adskGenuineServiceGUID = $GenuineHit.PSChildName; break }
    }
    if ($adskGenuineServiceGUID) {
        $MsiLogFileName = "MSIUninstall_adskGenuineService_$($adskGenuineServiceGUID)__$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
        $MsiLogFullPath = Join-Path -Path $MsiLogPath -ChildPath $MsiLogFileName
        Write-Log -Message "Uninstalling Autodesk Genuine Service with GUID: $adskGenuineServiceGUID" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        $gsProc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $adskGenuineServiceGUID /qn /norestart REBOOT=ReallySuppress /l*v `"$MsiLogFullPath`"" -Wait -PassThru
        $gsExit = $gsProc.ExitCode
        switch ($gsExit) {
            0    { Write-Log -Message "Uninstalled Autodesk Genuine Service successfully (exit 0)." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile }
            1605 { Write-Log -Message "Autodesk Genuine Service was not installed (exit 1605)." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile }
            3010 { $script:RebootRequired = $true
                   Write-Log -Message "Uninstalled Autodesk Genuine Service; reboot required (exit 3010)." -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile }
            default {
                   $script:FailedPackages.Add([pscustomobject]@{ ProductCode = $adskGenuineServiceGUID; ExitCode = $gsExit; Label = 'Autodesk Genuine Service' })
                   Write-Log -Message "[ERROR] msiexec returned $gsExit for Autodesk Genuine Service $adskGenuineServiceGUID" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                   Write-Warning "Failed to uninstall Autodesk Genuine Service (msiexec exit $gsExit)."
            }
        }
        if (Test-Path $MsiLogFullPath) {
            $MsiLogContent = Get-Content -Path $MsiLogFullPath -ErrorAction SilentlyContinue
            if ($null -ne $MsiLogContent) {
                Write-Log -Message "MSI Log for Autodesk Genuine Service: $adskGenuineServiceGUID" -Level Verbose -StartLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                Write-Log -Message "{`r`n$($MsiLogContent -join "`r`n")`r`n}" -Level Verbose -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                Write-Log -Message "" -Level Verbose -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            } else {
                Write-Log -Message "MSI Log file is empty for Autodesk Genuine Service: $adskGenuineServiceGUID" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            }
            Remove-Item -Path $MsiLogFullPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log -Message "MSI Log file not found for Autodesk Genuine Service: $adskGenuineServiceGUID" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        }
    } else {
        Write-Log -Message "Autodesk Genuine Service not found." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Running Uninstall Helper for Genuine Service
    $adskGenuineServicePath = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Genuine Service\AdskUninstallHelper.exe"
    if ((Test-Path -Path $adskGenuineServicePath) -and (Test-ShouldProcess -Target $adskGenuineServicePath -Action 'Run Genuine Service uninstall helper')) {
        Write-Log -Message "Running Uninstall Helper for Autodesk Genuine Service..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Start-Process -FilePath $adskGenuineServicePath -Wait -NoNewWindow -ea SilentlyContinue
        Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log -Message "Autodesk Genuine Service Uninstall Helper not found at $adskGenuineServicePath" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Running Uninstall Helper for Autodesk Identity Manager Component
    $adskIdentityManagerComponentPath = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Identity Manager Component\AdskUninstallHelper.exe"
    if ((Test-Path -Path $adskIdentityManagerComponentPath) -and (Test-ShouldProcess -Target $adskIdentityManagerComponentPath -Action 'Run Identity Manager Component helper')) {
        Write-Log -Message "Running Uninstall Helper for Autodesk Identity Manager Component..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Start-Process -FilePath $adskIdentityManagerComponentPath -Wait -NoNewWindow -ea SilentlyContinue
        Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log -Message "Autodesk Identity Manager Component Uninstall Helper not found at $adskIdentityManagerComponentPath" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Running Uninstall Helper for Autodesk Installer
    $adskInstallerPath = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Installer\AdskUninstallHelper.exe"
    if ((Test-Path -Path $adskInstallerPath) -and (Test-ShouldProcess -Target $adskInstallerPath -Action 'Run Autodesk Installer helper')) {
        Write-Log -Message "Running Uninstall Helper for Autodesk Installer..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Start-Process -FilePath $adskInstallerPath -Wait -NoNewWindow -ea SilentlyContinue
        Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log -Message "Autodesk Installer Uninstall Helper not found at $adskInstallerPath" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # ---- second C:\ProgramData\Autodesk sweep ----
    # The uninstall helpers above recreate parts of it as they remove themselves -
    # IDSDK in particular, written by AdskIdentityManager/message_router - so the
    # sweep in the folder-deletion phase runs too early to catch them. Everything
    # except the Uninstallers folder goes; whatever is still locked is queued for
    # next boot, and the deferred task sweeps this path again for good measure.
    Write-Log -Message "Re-checking $script:AdskProgramDataPath for residue recreated by the uninstall helpers..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -StartLogEntry
    $programDataSurvivors = @(Remove-AdskProgramDataResidue)
    if ($programDataSurvivors.Count -eq 0) {
        Write-Log -Message "No residue left under $script:AdskProgramDataPath (Uninstallers kept by design)." -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    } else {
        Write-Log -Message "$($programDataSurvivors.Count) item(s) still locked; scheduling for deletion at next boot." -Level Warning -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        foreach ($survivor in $programDataSurvivors) {
            foreach ($leftoverFile in @(Get-ChildItem -LiteralPath $survivor -Recurse -Force -File -ErrorAction SilentlyContinue)) {
                $script:PendingDeletePaths.Add($leftoverFile.FullName)
            }
            # directories deepest-first, so each is empty by the time it is processed
            foreach ($leftoverDir in @(Get-ChildItem -LiteralPath $survivor -Recurse -Force -Directory -ErrorAction SilentlyContinue |
                                       Sort-Object { $_.FullName.Length } -Descending)) {
                $script:PendingDeletePaths.Add($leftoverDir.FullName)
            }
            $script:PendingDeletePaths.Add($survivor)
        }
        try {
            $lateScheduled = @(Set-PendingFileDeletes)
            if ($lateScheduled.Count -gt 0) {
                $script:RebootRequired = $true
                Write-Log -Message ($lateScheduled -join "`r`n") -Level Verbose -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            }
        } catch {
            Write-Log -Message "[ERROR] Failed to schedule ProgramData residue for deletion: $($_.Exception.Message)" -Level Error -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        }
        Write-Log -Message "" -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }

    # ---- HKLM / per-user Autodesk key cleanup ----
    # Runs HERE, after every uninstaller has finished, so nothing can write
    # HKCU\SOFTWARE\Autodesk back after we have cleaned it.
    $autodeskRegistryKeys = @(
        "HKLM:\SOFTWARE\Autodesk",
        "HKLM:\SOFTWARE\WOW6432Node\Autodesk"
    )
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS > $null
    }
    $userProfiles = @(Get-ChildItem "HKU:\" | Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notmatch "_Classes" })

    $userRegSuffixes = @("SOFTWARE\Autodesk", "SOFTWARE\WOW6432Node\Autodesk")
    $RegistryHklmHkuPercentage = 25/3 / ($autodeskRegistryKeys.Count + ($userProfiles.Count * $userRegSuffixes.Count))
    Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
    foreach ($key in $autodeskRegistryKeys) {
        if ((Test-Path -Path $key) -and (Test-ShouldProcess -Target $key -Action 'Delete registry key')) {
            Write-Log -Message "Deleting registry key $key" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        }
        $RegistryTotalProgressPercentage += $RegistryHklmHkuPercentage
        Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
        $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
        Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
    }

    foreach ($userProfile in $userProfiles) {
        foreach ($userRegSuffix in $userRegSuffixes) {
            # PSChildName is the bare SID - without the "HKU:\" prefix Test-Path
            # resolves against the current (filesystem) location and never matches
            $autodeskKey = "HKU:\$($userProfile.PSChildName)\$userRegSuffix"
            if ((Test-Path -Path $autodeskKey) -and (Test-ShouldProcess -Target $autodeskKey -Action 'Delete registry key')) {
                Write-Log -Message "Deleting registry key $autodeskKey" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                Remove-Item -Path $autodeskKey -Recurse -Force -ErrorAction SilentlyContinue
            }
            $RegistryTotalProgressPercentage += $RegistryHklmHkuPercentage
            Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
            $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
            Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
        }
    }
    Remove-PSDrive -Name HKU -ErrorAction SilentlyContinue

    # delete Autodesk registry keys
    Write-Log -Message "Deleting Autodesk Install/Uninstall registry keys..." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    $autodeskRegistryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\Classes\Installer\Products",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Products",
        # InstallProperties actually lives here, not under Classes\Installer\Products;
        # this hive was never cleaned by the original sweep
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    )


    $RegistryMainLocationsPercentage = 275/3 / $autodeskRegistryKeys.Count
    Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
    foreach ($key in $autodeskRegistryKeys) {
        if (Test-Path -Path $key) {
            $subkeys = @(Get-ChildItem -Path $key -ErrorAction SilentlyContinue)
            if ($subkeys.Count -eq 0) {
                $RegistryTotalProgressPercentage += $RegistryMainLocationsPercentage
                Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
                $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
                Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
                continue
            }
            $RegistrySubKeyPercentage = $RegistryMainLocationsPercentage / $subkeys.Count
            foreach ($subkey in $subkeys) {
                $subkeyPath = Join-Path -Path $key -ChildPath $subkey.PSChildName
                $shouldRemove = $false
                # For Uninstall keys, check main properties
                if ($key -like "*Uninstall*") {
                    $props = Get-ItemProperty -Path $subkeyPath -ErrorAction SilentlyContinue
                    # UninstallString/InstallLocation/DisplayIcon start with a path or
                    # "MsiExec.exe", never the literal "Autodesk" - matching "^Autodesk"
                    # on them was dead code. Match the path segment instead.
                    if (
                        $null -ne $props -and
                        (
                            $props.DisplayName     -match "^Autodesk" -or
                            $props.Publisher       -match "^Autodesk" -or
                            $props.InstallLocation -match "\\Autodesk" -or
                            $props.DisplayIcon     -match "\\Autodesk"
                        )
                    ) {
                        $shouldRemove = $true
                    }
                }
                # For Installer/Products, check InstallProperties subkey
                if (-not $shouldRemove -and $key -like "*Products*") {
                    $props = Get-ItemProperty -Path $subkeyPath -ErrorAction SilentlyContinue
                    if ( $null -ne $props -and $props.ProductName -match "^Autodesk" ) {
                        $shouldRemove = $true
                    } else {
                        $installPropsPath = Join-Path -Path $subkeyPath -ChildPath "InstallProperties"
                        if (Test-Path $installPropsPath) {
                            $props = Get-ItemProperty -Path $installPropsPath -ErrorAction SilentlyContinue
                            if (
                                $null -ne $props -and
                                (
                                    $props.DisplayName     -match "^Autodesk" -or
                                    $props.Publisher       -match "^Autodesk" -or
                                    $props.ProductName     -match "^Autodesk" -or
                                    $props.InstallLocation -match "\\Autodesk" -or
                                    $props.DisplayIcon     -match "\\Autodesk"
                                )
                            ) {
                                $shouldRemove = $true
                            }
                        }
                    }
                }
                if ($shouldRemove -and (Test-ShouldProcess -Target $subkeyPath -Action 'Delete registry key')) {
                    Remove-Item -Path $subkeyPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "Removed registry key $subkeyPath" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                }
                $RegistryTotalProgressPercentage += $RegistrySubKeyPercentage
                Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
                $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
                Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
            }
        } else {
            $RegistryTotalProgressPercentage += $RegistryMainLocationsPercentage
            Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
            $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
            Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
        }
    }
    # Defer the COM/shell-extension removal and the final per-user key cleanup to a
    # one-shot SYSTEM task at next boot. Doing either now would stall shutdown (the
    # registrations belong to a DLL explorer.exe still has loaded) and the key would
    # simply be rewritten by that DLL before the session ends.
    # PendingDeleteTotal, not PendingDeletePaths: the list is emptied on each write,
    # so it is zero after a successful schedule. The list itself still matters under
    # -WhatIf, where nothing was written but paths were collected.
    $adskCleanupPending = ($script:PendingDeleteTotal -gt 0) -or ($script:PendingDeletePaths.Count -gt 0)
    if (-not $adskCleanupPending) {
        foreach ($residualFolder in @('C:\Program Files\Autodesk','C:\Program Files\Common Files\Autodesk',
                                      'C:\Program Files\Common Files\Autodesk Shared','C:\Program Files (x86)\Autodesk',
                                      'C:\Program Files (x86)\Common Files\Autodesk Shared','C:\Autodesk')) {
            if (Test-Path -LiteralPath $residualFolder) { $adskCleanupPending = $true; break }
        }
    }
    # Residue under ProgramData alone is reason enough to run the deferred task
    if (-not $adskCleanupPending -and (Get-AdskProgramDataResidue).Count -gt 0) { $adskCleanupPending = $true }
    if ($adskCleanupPending) {
        try {
            $deferredScriptPath = Register-AdskDeferredCleanup -WorkDir $MainLogPath
            $script:RebootRequired = $true
            Write-Log -Message "Registered one-shot deferred cleanup task 'ADSK-DeferredCleanup' -> $deferredScriptPath" -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            Write-Host "Remaining Autodesk COM registrations and per-user keys will be removed on the next restart." -ForegroundColor Yellow
        } catch {
            Write-Log -Message "[ERROR] Failed to register the deferred cleanup task: $($_.Exception.Message)" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            Write-Warning "Could not register the deferred cleanup task: $($_.Exception.Message)"
        }
    }

    # only remove the MSI log directory if it is a real directory, not a redirect
    $MsiLogDirItem = Get-Item -LiteralPath $MsiLogPath -Force -ErrorAction SilentlyContinue
    if ($MsiLogDirItem -and -not ($MsiLogDirItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Remove-Item -Path $MsiLogPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # A package can report a failure and still be gone by the end. Autodesk's Genuine
    # Service returns 1604 from its own checkUninstall custom action while other
    # products are still installed, and the dedicated step above then removes it
    # successfully. Re-check every recorded failure against the registry so the exit
    # code reflects the final state, not a transient refusal - otherwise a deployment
    # tool marks a clean uninstall as failed.
    $script:UnresolvedFailures = New-Object System.Collections.Generic.List[string]
    $resolvedFailures = New-Object System.Collections.Generic.List[string]
    foreach ($failedPackage in $script:FailedPackages) {
        $failureText = (("$($failedPackage.Label) $($failedPackage.ProductCode)").Trim() + " (msiexec exit $($failedPackage.ExitCode))")
        $stillRegistered = $true
        try { $stillRegistered = Test-MsiProductInstalled -ProductCode $failedPackage.ProductCode } catch { $stillRegistered = $true }
        if ($stillRegistered) { $script:UnresolvedFailures.Add($failureText) } else { $resolvedFailures.Add($failureText) }
    }
    if ($resolvedFailures.Count -gt 0) {
        Write-Log -Message "$($resolvedFailures.Count) package(s) reported a failure but are no longer registered; treating as resolved:" -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -StartLogEntry
        Write-Log -Message ($resolvedFailures -join "`r`n") -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -AddLogEntryData
        Write-Log -Message "" -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -EndLogEntry
    }

    if ($script:UnresolvedFailures.Count -gt 0) {
        $script:ExitCode = 1
        Write-Log -Message "Autodesk products uninstallation completed with $($script:UnresolvedFailures.Count) unresolved failure(s)." -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -StartLogEntry
        Write-Log -Message ($script:UnresolvedFailures -join "`r`n") -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -AddLogEntryData
        Write-Log -Message "" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -EndLogEntry
        Write-Warning "$($script:UnresolvedFailures.Count) package(s) failed to uninstall and are still registered. See $MainLogFile"
    } elseif ($script:RebootRequired) {
        $script:ExitCode = 3010
        Write-Log -Message "Autodesk products uninstallation completed; reboot required (Exit Code 3010)." -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    } else {
        $script:ExitCode = 0
        Write-Log -Message "Autodesk products uninstallation completed with Exit Code 0." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }

    if ($script:Interactive) {
        # Notify the user
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $notification = New-Object System.Windows.Forms.NotifyIcon
        $notification.Icon = [System.Drawing.SystemIcons]::Information
        $notification.BalloonTipTitle = "Autodesk Uninstall Completed..."
        $notification.BalloonTipText = "Please follow the instruction in the PowerShell-Window."
        $notification.Visible = $true
        $notification.ShowBalloonTip(30000)
        # Activate the PS Window to notify the user
        Add-Type -AssemblyName Microsoft.VisualBasic
        # AppActivate throws "Process was not found" when there is no window to
        # activate; never let a cosmetic notification emit an error at the end
        try { [Microsoft.VisualBasic.Interaction]::AppActivate($PID) } catch { }
    }

    if ($script:UnresolvedFailures.Count -gt 0) {
        Write-Host "`r`nAutodesk removal finished with $($script:UnresolvedFailures.Count) unresolved failure(s):" -ForegroundColor Red
        $script:UnresolvedFailures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-Host "A complete Log has been generated at $MainLogFile" -ForegroundColor Red
    } else {
        Write-Host "`r`nAutodesk products have been uninstalled successfully.`r`nA complete Log has been generated at $MainLogFile" -ForegroundColor Green
    }
    # Always ask for a restart, even when nothing is left pending. The sweep stops and
    # disables unrelated services and kills processes that hold Autodesk handles
    # (Software Center and the ConfigMgr agent among them); only a reboot brings them
    # all back in a known-good state.
    Write-Host "Please restart your computer to complete the uninstallation process." -ForegroundColor Yellow
    # The deferred boot-time task now does the work that used to require a second full
    # run, so point at it rather than asking the user to run the script again.
    if ($deferredScriptPath) {
        $deferredLogFile = $MainLogFile -replace 'ADSK_CleanUninstall_', 'ADSK_CleanUninstall_Deferred_'
        Write-Host "The remaining cleanup runs automatically during that restart, before anyone logs on," -ForegroundColor Yellow
        Write-Host "then removes itself. It logs to $deferredLogFile" -ForegroundColor Yellow
    }
    Wait-ForUser
    if ($script:Interactive -and $notification) { $notification.Dispose() }

    # -ForceRestart: restart without asking, whether interactive or not. Checked
    # before the interactive branch so it works in unattended deployments, where
    # the deferred boot-time cleanup should complete straight away.
    if ($ForceRestart) {
        Write-Log -Message "-ForceRestart specified: restarting the computer now." -Level Warning -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        Write-Host "`r`nRestarting now (-ForceRestart)..." -ForegroundColor Yellow
        if (Test-ShouldProcess -Target $env:COMPUTERNAME -Action 'Restart computer') {
            Restart-Computer -Force
        }
        exit $script:ExitCode
    }

    if (-not $script:Interactive -or $NoRestart) {
        # The restart requirement is already reported above, for every path.
        Write-Log -Message "Non-interactive or -NoRestart: skipping the restart prompt." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        exit $script:ExitCode
    }
    Read-Host -Prompt "`r`nWould you like to restart your computer now? (Y/N)" | ForEach-Object {
        if ($_ -eq "y") {
            Write-Log -Message "Restarting the computer as per user request." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            if (Test-ShouldProcess -Target $env:COMPUTERNAME -Action 'Restart computer') {
                Restart-Computer -Force
            }
        } elseif($_ -eq "n") {
            Write-Log -Message "User chose not to restart the computer." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            Write-Host "Please restart your computer manually to complete the uninstallation process."
        } else {
            Write-Log -Message "Unknown response from user regarding restart: $_. Skipping restart." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            Write-Host "Unknown Response. Please restart your computer manually to complete the uninstallation process."
        }
    }

    exit $script:ExitCode
}


#####################################################################################
# Script Name:  AutoDeskCleanRemove.ps1
# Description:  This script is used to cleanly uninstall all Autodesk products
#               from a system.
#
# Author:       Halatschek Wolfram
# Date:         2025-05-20
# Version:      2.0
# Notes:        This script requires administrative privileges to run.
#
# Usage:        Run this script in an elevated PowerShell session.
#               PS> cd <path to script>
#               PS> .\AutoDeskCleanRemove.ps1
#
#               Please restart your computer after running this Script and run it
#               again to ensure all Autodesk residuals are removed.
#
#
# Warning:      This script is provided "as is" without any warranty of any kind.
#
#       !!      The Author of this script is not responsible for any data loss or
#               system damage caused by the use of this script. Use at your own risk.
#
#               If any Errors occur you wish to report to the Author, please open an
#               issue on https://github.com/halatsWol/PowerShell-Tools
#####################################################################################

[CmdletBinding()]
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
    [switch]$NoRestart
)

# $PSSenderInfo alone does not detect a headless local session (e.g. a service or
# remote-exec context), which is why AppActivate could throw at the very end.
$script:Interactive = (-not $Unattended) -and (-not $PSSenderInfo) -and [Environment]::UserInteractive

function Wait-ForUser {
    if ($script:Interactive) { Pause }
}

$script:LogLevel = $LogLevel
$MainLogPath = $LogPath
$MsiLogPath  = Join-Path -Path $LogPath -ChildPath 'MSILogs'
try {
    if (-not (Test-Path -LiteralPath $MainLogPath)) {
        New-Item -ItemType Directory -Path $MainLogPath -Force -ErrorAction Stop | Out-Null
    }
    if (-not (Test-Path -LiteralPath $MsiLogPath)) {
        New-Item -ItemType Directory -Path $MsiLogPath -Force -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Warning "Cannot create log directory '$MainLogPath': $($_.Exception.Message)"
    exit 1
}
$MainLogPathFileName="ADSK_CleanUninstall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
$MainLogFile = Join-Path -Path $MainLogPath -ChildPath $MainLogPathFileName

# Outcome tracking - drives the script's real exit code instead of a hardcoded 0
$script:FailedPackages = New-Object System.Collections.Generic.List[string]
$script:RebootRequired = $false
$script:ExitCode       = 0

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
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Add-Content has no retry of its own; under contention it throws and the
    # line is lost silently. Retry briefly, and say so if the line is dropped.
    function Add-LogLine {
        param([string]$Path, [string]$Value)
        foreach ($attempt in 1..10) {
            try { Add-Content -Path $Path -Value $Value -ErrorAction Stop; return }
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
            $state | ConvertTo-Json -Compress | Out-File -FilePath $statePath -Encoding UTF8 -Force
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
    Write-Log -Message "Script Version: 2.0;" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -AddLogEntryData
    Write-Log -Message "Author: Halatschek Wolfram;`r`nScript-Source: 'https://github.com/halatsWol/PowerShell-Tools/blob/main/scripts/AutoDeskCleanRemove.ps1';" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -EndLogEntry
    Write-Log -Message "Script started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -StartLogEntry
    Write-Log -Message "Hostname: $($env:COMPUTERNAME);" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -AddLogEntryData
    Write-Log -Message "User: $($env:USERNAME);" -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -EndLogEntry
    Write-Host "`r`nThis script will remove all Autodesk products from your system."
    Write-Host "Please ensure that you have closed all Autodesk applications before proceeding."
    Write-Host "This script has not been tested with Fusion 360. If you have Fusion 360 installed, please uninstall it manually before running this script."
    Write-Warning "Please note that this may prompt OneDrive regarding the deletion of files. This is to be expected.`r`nMultiple Windows may appear, please do not close them manually.`r`nThe script will close them automatically after the uninstallation process."
    Wait-ForUser
    Write-Host "`r`n`r`nStarting Autodesk Clean Uninstall...`r`nThis may take a while, please be patient...`r`n"
    # Stop all Autodesk SERVICES FIRST. Order matters: killing a service's process only
    # makes the SCM restart it, which is why AdskAccessService, AdskLicensingService,
    # ADPClientService et al survived three kill passes and kept holding the file
    # handles that then broke the folder deletion further down.
    Write-Log -Message "Stopping all Autodesk services:" -StartLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    # Stop-Service emits nothing without -PassThru, so enumerate first and stop separately.
    # Name is matched too: ADPClientService has no "Autodesk" in its DisplayName.
    $AdskServices = @(Get-Service | Where-Object {
        $_.DisplayName -match "Autodesk" -or $_.DisplayName -match "ADSK" -or $_.Name -match "^(Autodesk|Adsk|ADP)"
    })
    if (-not $AdskServices) {
        Write-Log -Message "`r`nNo Autodesk services found." -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    } else {
        $ServiceInfo = $AdskServices | Select-Object DisplayName, Name, Status | ConvertTo-Json -Depth 2
        Write-Log -Message "Found Autodesk services:`r`n{$ServiceInfo}" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        foreach ($AdskService in $AdskServices) {
            # disable before stopping, otherwise the SCM restarts it moments later
            try { Set-Service -Name $AdskService.Name -StartupType Disabled -ErrorAction Stop } catch {
                Write-Log -Message "[ERROR] Failed to disable service $($AdskService.Name): $($_.Exception.Message)" -Level Error -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            }
            try { Stop-Service -InputObject $AdskService -Force -ErrorAction Stop } catch {
                Write-Log -Message "[ERROR] Failed to stop Autodesk service $($AdskService.Name): $($_.Exception.Message)" -Level Error -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                Write-Warning "Failed to stop Autodesk service $($AdskService.Name). This may require a second run of the script, after a reboot."
            }
        }
        Write-Log -Message "Autodesk services have been stopped." -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }

    # Stop all Autodesk processes (AFTER the services, so nothing respawns them)
    Write-Log -Message "Stopping all Autodesk processes:" -StartLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    # Anchored to the start of ProcessName so unrelated software is not force-killed
    # (the old unanchored "Inventor" would match e.g. InventoryAgent). ADP* added:
    # ADPClientService holds cer.dll and was never matched by the old ADSK pattern.
    $script:AdskProcNamePattern = '^(Autodesk|Adsk|ADP|AutoCAD|acad|cer_service|dwgviewr|message_router|AdODIS|senddmp)|^Inventor(Server)?$'
    $AdskProcesses = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -match $script:AdskProcNamePattern -or $_.Description -match 'Autodesk'
    })
    if ($AdskProcesses.Count -eq 0) {
        Write-Log -Message "`r`nNo Autodesk processes found." -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    } else {
        $ProcessInfo = $AdskProcesses | Select-Object Name, Id | ConvertTo-Json -Depth 2
        Write-Log -Message "Found Autodesk processes:`r`n{$ProcessInfo}" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile

        # Some Autodesk components respawn after being killed (AdskAccessService does),
        # so verify and retry instead of assuming one pass is enough. Per-process, NOT
        # a pipeline: with -ErrorAction Stop one un-killable process would abort the
        # pipeline and leave the rest running, holding handles that break deletion later.
        $AdskRemaining = $AdskProcesses
        foreach ($AdskKillPass in 1..3) {
            foreach ($AdskProcess in $AdskRemaining) {
                try {
                    Stop-Process -InputObject $AdskProcess -Force -ErrorAction Stop
                } catch {
                    Write-Log -Message "[ERROR] Failed to stop process $($AdskProcess.ProcessName) (PID $($AdskProcess.Id)) on pass ${AdskKillPass}: $($_.Exception.Message)" -Level Error -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
                }
            }
            Start-Sleep -Seconds 2
            $AdskRemaining = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $_.ProcessName -match $script:AdskProcNamePattern -or $_.Description -match 'Autodesk'
            })
            if ($AdskRemaining.Count -eq 0) { break }
            Write-Log -Message "$($AdskRemaining.Count) Autodesk process(es) still running after pass $AdskKillPass; retrying." -Level Warning -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        }
        if ($AdskRemaining.Count -gt 0) {
            $StillRunning = ($AdskRemaining | Select-Object -ExpandProperty ProcessName -Unique) -join ', '
            Write-Log -Message "[ERROR] Autodesk process(es) still running after 3 passes: $StillRunning" -Level Error -AddLogEntryData -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            Write-Warning "Still running after 3 attempts: $StillRunning. These hold file handles; a reboot and second run will be required."
        }
        Write-Log -Message "Autodesk processes have been stopped." -EndLogEntry -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
    }
    # (the Autodesk service shutdown now runs BEFORE the process kill, above)
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
                                if (Test-MsiProductInstalled -ProductCode $productCode) {
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
                                               $script:FailedPackages.Add("$productCode (msiexec exit $msiExit)")
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
    if (Test-Path -Path $AdODISPath) {
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
    if (Test-Path -Path $AdskAccessPath) {
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
    if ( Test-Path -Path $AdskAccessUninstHelper ) {
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
    if (Test-Path -Path $AdskLicensingPath) {
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
    if (Test-Path -Path $AdskIdentityManagerPath) {
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
        if (Test-Path -Path $folder) {
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
                   $script:FailedPackages.Add("Autodesk Genuine Service $adskGenuineServiceGUID (msiexec exit $gsExit)")
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
    if (Test-Path -Path $adskGenuineServicePath) {
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
    if (Test-Path -Path $adskIdentityManagerComponentPath) {
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
    if (Test-Path -Path $adskInstallerPath) {
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
        if (Test-Path -Path $key) {
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
            if (Test-Path -Path $autodeskKey) {
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
                if ($shouldRemove) {
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
    # only remove the MSI log directory if it is a real directory, not a redirect
    $MsiLogDirItem = Get-Item -LiteralPath $MsiLogPath -Force -ErrorAction SilentlyContinue
    if ($MsiLogDirItem -and -not ($MsiLogDirItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Remove-Item -Path $MsiLogPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($script:FailedPackages.Count -gt 0) {
        $script:ExitCode = 1
        Write-Log -Message "Autodesk products uninstallation completed with $($script:FailedPackages.Count) failure(s)." -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -StartLogEntry
        Write-Log -Message ($script:FailedPackages -join "`r`n") -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -AddLogEntryData
        Write-Log -Message "" -Level Error -Component "AutoDeskCleanRemove" -LogFile $MainLogFile -EndLogEntry
        Write-Warning "$($script:FailedPackages.Count) package(s) failed to uninstall. See $MainLogFile"
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

    if ($script:FailedPackages.Count -gt 0) {
        Write-Host "`r`nAutodesk removal finished with $($script:FailedPackages.Count) failure(s):" -ForegroundColor Red
        $script:FailedPackages | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-Host "A complete Log has been generated at $MainLogFile" -ForegroundColor Red
    } else {
        Write-Host "`r`nAutodesk products have been uninstalled successfully.`r`nA complete Log has been generated at $MainLogFile" -ForegroundColor Green
    }
    Write-Host "Please restart your computer to complete the uninstallation process." -ForegroundColor Yellow
    Write-Host "It is recommended to run this script a second time after the restart to ensure all Autodesk products are removed." -ForegroundColor Yellow
    Wait-ForUser
    if ($script:Interactive -and $notification) { $notification.Dispose() }
    if (-not $script:Interactive -or $NoRestart) {
        Write-Log -Message "Non-interactive or -NoRestart: skipping the restart prompt." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
        if ($script:RebootRequired) {
            Write-Host "A restart is required to complete the uninstallation process." -ForegroundColor Yellow
        }
        exit $script:ExitCode
    }
    Read-Host -Prompt "`r`nWould you like to restart your computer now? (Y/N)" | ForEach-Object {
        if ($_ -eq "y") {
            Write-Log -Message "Restarting the computer as per user request." -Component "AutoDeskCleanRemove" -LogFile $MainLogFile
            Restart-Computer -Force
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


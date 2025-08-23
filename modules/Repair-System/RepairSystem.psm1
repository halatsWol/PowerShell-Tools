function New-Folder {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FolderPath
    )
    if (-not (Test-Path -Path $FolderPath)) {New-Item -Path $FolderPath -ItemType Directory -Force > $null}
}

function Invoke-SFC {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$sfcLog,

        [Parameter(Mandatory=$true, Position=1)]
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}
    # get directory path from $sfcLog
    $sfcLogDir = Split-Path -Path $sfcLog -Parent
    $sfcErrorLog = Join-Path -Path $sfcLogDir -ChildPath "SFC_Error.log"
    $SfcMaxDurationVal = 20
    Write-Host "executing SFC (up to $SfcMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
        try{
            $SfcMaxDuration = New-TimeSpan -Minutes $SfcMaxDurationVal
            $process = Start-Process -FilePath "sfc" -ArgumentList "/scannow" -RedirectStandardOutput $sfcLog -RedirectStandardError $sfcErrorLog -NoNewWindow -PassThru
            $SfcStartTime = Get-Date

            # Monitor the process
            while (-not $process.HasExited) {
                Start-Sleep -Seconds 5

                $elapsed = (Get-Date) - $SfcStartTime
                if ($elapsed -gt $SfcMaxDuration) {
                    $sfcStucknotify = "Sfc.exe has been running for more than $($SfcMaxDuration.TotalMinutes) minutes. Stopping it..."
                    Add-Content -Path $sfcLog -Value "!!`t`t> $sfcStucknotify"
                    Write-Warning $sfcStucknotify
                    try {
                        $process.Kill()
                        $sfcStuckTerminate = "Sfc.exe terminated."
                        Add-Content -Path $sfcLog -Value "!!`t`t> $sfcStuckTerminate"
                        Write-Warning $sfcStuckTerminate
                    } catch {
                        $sfcStuckTerminateFail = "Failed to terminate Sfc.exe: $_"
                        Add-Content -Path $sfcLog -Value "!!`t`t> $sfcStuckTerminateFail"
                        Write-Warning $sfcStuckTerminateFail
                    }
                    break
                }
            }

            $sfcExitCode=$process.ExitCode
            $logContent = Get-Content $sfcLog -Raw
            $logContent = $logContent -replace '[^\x00-\x7F]', ''
            $logContent = $logContent -replace [char]0
            Set-Content $sfcLog -Value $logContent

            $errorLogContent = Get-Content $sfcErrorLog -Raw
            $errorLogContent = $errorLogContent -replace '[^\x00-\x7F]', ''
            $errorLogContent = $errorLogContent -replace [char]0
            Add-Content -Path $sfcLog -Value "`r`n`r`nSFC Error Output:`r`n"
            Add-Content $sfcLog -Value $errorLogContent
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
    $DismMaxDurationVal = 15
    Write-Host "executing DISM/ScanHealth (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
    try{
        $DismMaxDuration = New-TimeSpan -Minutes $DismMaxDurationVal
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/Cleanup-Image", "/Scanhealth" -RedirectStandardOutput $dismScanLog -RedirectStandardError $dismErrorLog -NoNewWindow -Wait -PassThru
        $DismStartTime = Get-Date

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $DismStartTime
            if ($elapsed -gt $DismMaxDuration) {
                $dismStucknotify = "Dism.exe has been running for more than $($DismMaxDuration.TotalMinutes) minutes. Stopping it..."
                Add-Content -Path $dismScanLog -Value "!!`t`t> $dismStucknotify"
                Write-Warning $dismStucknotify
                try {
                    $process.Kill()
                    $dismStuckTerminate = "Dism.exe terminated."
                    Add-Content -Path $dismScanLog -Value "!!`t`t> $dismStuckTerminate"
                    Write-Warning $dismStuckTerminate
                } catch {
                    $dismStuckTerminateFail = "Failed to terminate Dism.exe: $_"
                    Add-Content -Path $dismScanLog -Value "!!`t`t> $dismStuckTerminateFail"
                    Write-Warning $dismStuckTerminateFail
                }
                break
            }
        }
        return $process.ExitCode

        $dismLogContent = Get-Content $dismErrorLog -Raw
        Add-Content -Path $dismScanLog -Value "`r`n`r`nDISM Error Output:`r`n$dismLogContent"
        Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue
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

    $DismMaxDurationVal = 40
    Write-Host "executing DISM/RestoreHealth (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
    try{
        $DismMaxDuration = New-TimeSpan -Minutes $DismMaxDurationVal
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/Cleanup-Image", "/RestoreHealth" -RedirectStandardOutput $dismRestoreLog -RedirectStandardError $dismErrorLog -NoNewWindow -Wait -PassThru
        $DismStartTime = Get-Date

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $DismStartTime
            if ($elapsed -gt $DismMaxDuration) {
                $dismStucknotify = "Dism.exe has been running for more than $($DismMaxDuration.TotalMinutes) minutes. Stopping it..."
                Add-Content -Path $dismRestoreLog -Value "!!`t`t> $dismStucknotify"
                Write-Warning $dismStucknotify
                try {
                    $process.Kill()
                    $dismStuckTerminate = "Dism.exe terminated."
                    Add-Content -Path $dismRestoreLog -Value "!!`t`t> $dismStuckTerminate"
                    Write-Warning $dismStuckTerminate
                } catch {
                    $dismStuckTerminateFail = "Failed to terminate Dism.exe: $_"
                    Add-Content -Path $dismRestoreLog -Value "!!`t`t> $dismStuckTerminateFail"
                    Write-Warning $dismStuckTerminateFail
                }
                break
            }
        }
        return $process.ExitCode

        $dismLogContent = Get-Content $dismErrorLog -Raw
        Add-Content -Path $dismRestoreLog -Value "`r`n`r`nDISM Error Output:`r`n$dismLogContent"
        Remove-Item -Path $dismErrorLog -Force-ErrorAction SilentlyContinue
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

    $DismMaxDurationVal = 5
    Write-Host "executing DISM Analyze Component Store (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
    try{
        $DismMaxDuration = New-TimeSpan -Minutes $DismMaxDurationVal
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/Cleanup-Image", "/AnalyzeComponentStore" -RedirectStandardOutput $analyzeComponentLog -RedirectStandardError $DismErrorLog -NoNewWindow -Wait -PassThru
        $DismStartTime = Get-Date

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $DismStartTime
            if ($elapsed -gt $DismMaxDuration) {
                $dismStucknotify = "Dism.exe has been running for more than $($DismMaxDuration.TotalMinutes) minutes. Stopping it..."
                Add-Content -Path $analyzeComponentLog -Value "!!`t`t> $dismStucknotify"
                Write-Warning $dismStucknotify
                try {
                    $process.Kill()
                    $dismStuckTerminate = "Dism.exe terminated."
                    Add-Content -Path $analyzeComponentLog -Value "!!`t`t> $dismStuckTerminate"
                    Write-Warning $dismStuckTerminate
                } catch {
                    $dismStuckTerminateFail = "Failed to terminate Dism.exe: $_"
                    Add-Content -Path $analyzeComponentLog -Value "!!`t`t> $dismStuckTerminateFail"
                    Write-Warning $dismStuckTerminateFail
                }
                break
            }
        }
        return $process.ExitCode
        $dismLogContent = Get-Content $dismErrorLog -Raw
        Add-Content -Path $analyzeComponentLog -Value "`r`n`r`nDISM Error Output:`r`n$dismLogContent"
        Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue
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
    $DismMaxDurationVal = 20
    Write-Host "executing DISM Component Store Cleanup (up to $DismMaxDurationVal min, Start $(Get-Date -Format "HH:mm"))"
    try{
        $DismMaxDuration = New-TimeSpan -Minutes $DismMaxDurationVal
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/Cleanup-Image", "/StartComponentCleanup" -RedirectStandardOutput $componentCleanupLog -RedirectStandardError $DismErrorLog -NoNewWindow -Wait -PassThru
        $DismStartTime = Get-Date

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $DismStartTime
            if ($elapsed -gt $DismMaxDuration) {
                $dismStucknotify = "Dism.exe has been running for more than $($DismMaxDuration.TotalMinutes) minutes. Stopping it..."
                Add-Content -Path $componentCleanupLog -Value "!!`t`t> $dismStucknotify"
                Write-Warning $dismStucknotify
                try {
                    $process.Kill()
                    $dismStuckTerminate = "Dism.exe terminated."
                    Add-Content -Path $componentCleanupLog -Value "!!`t`t> $dismStuckTerminate"
                    Write-Warning $dismStuckTerminate
                } catch {
                    $dismStuckTerminateFail = "Failed to terminate Dism.exe: $_"
                    Add-Content -Path $componentCleanupLog -Value "!!`t`t> $dismStuckTerminateFail"
                    Write-Warning $dismStuckTerminateFail
                }
                break
            }
        }
        return $process.ExitCode

        $dismLogContent = Get-Content $dismErrorLog -Raw
        Add-Content -Path $componentCleanupLog -Value "`r`n`r`nDISM Error Output:`r`n$dismLogContent"
        Remove-Item -Path $dismErrorLog -Force -ErrorAction SilentlyContinue
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
    Get-Service -ErrorAction SilentlyContinue $servicesStop | Stop-Service
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
    Get-Service -ErrorAction SilentlyContinue $servicesStop | Stop-Service -force
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
    Get-Service -ErrorAction SilentlyContinue $servicesStop | Stop-Service -force
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
        $DiagMaxDurationVal = 15
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
        $DiagMaxDurationVal = 10
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
        [switch]$Quiet,

        [Parameter(Mandatory=$true, Position=2)]
        [switch]$VerboseArg

    )
    if ($VerboseArg) {$PSCmdlet.MyInvocation.BoundParameters['Verbose']=$true}

    if ($Quiet) {
        $PSCmdlet.MyInvocation.BoundParameters['Verbose']=$false
    }

    $ccmrepairexe="C:\Windows\CCM\ccmrepair.exe"
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    if ( Test-Path $ccmrepairexe) {
        $ccmSetupLogFolder = "C:\Windows\ccmsetup\Logs"
        $ccmsetupLogFile="ccmsetup.log"
        # start $ccmrepairexe do not open new window and route output in current shell
        try {
            Write-Host "Starting CCMRepair... This may take a while (~30min)."
            Start-Process -FilePath $ccmrepairexe -Wait -ErrorAction Stop -NoNewWindow
            if (Test-Path $ccmsetupLogFolder\$ccmsetupLogFile) {
                $logLines = Get-Content -Path $ccmsetupLogFolder\$ccmsetupLogFile -Tail 3
                foreach ($line in $logLines) {
                    if ($line -match "<!\[LOG\[(.*?)\]LOG\]!>") {
                        $logMessage = $matches[1]
                        # only print if logmessage starts with "CcmSetup is exiting with return code"
                        if ($logMessage -like "CcmSetup is exiting with return code*" -or $logMessage -like "CcmSetup failed with error code*") {
                            Write-Host "Log Message: $logMessage"
                        }
                    }
                }
                # copy logfile to localtemppath
                Copy-Item -Path "$ccmsetupLogFolder\$ccmsetupLogFile" -Destination $localTempPath -Force
                if ( Test-Path "$localTempPath\$ccmsetupLogFile") {
                    Rename-Item -Path "$localTempPath\$ccmsetupLogFile" -NewName "CCMSetup_$timestamp.log" -Force
                } else {
                    Write-Host "CCMSetup log file not found in the expected Temp location."
                }
            } else {
                Write-Host "CCMSetup log file not found."
            }
        } catch {
            Write-Error "Failed to start $ccmrepairexe : $_"
        }

    } else {
        Write-Host "CCMRepair executable not found."
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

    The results are logged both on the remote machine and optionally shown on the local console. Logs and relevant system files are then transferred to the local machine.

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
    When specified, log files will be kept on the remote Device, but still be copied to the Client

    .PARAMETER noCopy
    When specified, log files will not be copied to the Client. this will automatically use '-KeepLogs'

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
    Repair-System Module returns an exit code that can be used to determine the success or failure of the script.
    0 if the script was executed successfully. Any other value indicates an error.
    The exit code is a string of 8 digits, each representing the exit code of a specific step in the script.
    The exit codes possitions are as follows:
    Position 0: Startup (Synthax Error, Network Error, WinRM Error)
    Position 1: SFC
    Position 2: DISM Scan Health
    Position 3: Dism Restore Healt
    Position 4: Dism Analyse Component Store
    Position 5: Dism Component Cleanup
    Position 6: SCCM Cleanup
    Position 7: Windows Update Cleanup
    Position 8: Zip CBS/DISM Logs


    Except for Position 0, the exit code is the return value of the corresponding command.
    If the command was not executed, the exit code is 0.
    Furthermore only if startup fails, the Repair-System will quit and return the exit code.
    All other errors will not interrupt the script.



    Author: Wolfram Halatschek
    E-Mail: dev@kMarflow.com
    Date: 2025-08-23
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [ValidatePattern('^(([a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$')]
        [string]$ComputerName,

        [Parameter(Mandatory=$false,Position=0)]
        [string]$remoteShareDrive,

        [Parameter(Mandatory = $false)]
        [switch]$noSfc,

        [Parameter(Mandatory = $false)]
        [switch]$noDism,

        [Parameter(Mandatory = $false)]
        [switch]$Quiet,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeComponentCleanup,

        [Parameter(Mandatory = $false)]
        [switch]$WindowsUpdateCleanup,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0.25,10.0)]
        [decimal]$ChangeTimeout = 1.0,

        [Parameter(Mandatory = $false)]
        [switch]$sccmCleanup,

        [Parameter(Mandatory=$false)]
        [switch]$KeepLogs,

        [Parameter(Mandatory=$false)]
        [switch]$noCopy,

        [Parameter(Mandatory=$false)]
        [switch]$init,

        [Parameter(Mandatory=$false)]
        [PSCredential] $Credentials,

        [Parameter(Mandatory=$false)]
        [switch]$RepairCCM

    )

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

    $ExitCode=0,0,0,0,0,0,0,0,0 #Startup, SFC, DISM Scan, DISM Restore, Analyze Component, Component Cleanup, SCCM Cleanup, Windows Update Cleanup, Zip CBS/DISM Logs
    $remote=$false
    $shareDrivePath=""
    $remoteTempPath=""
    # check if verbose param is set in command execution
    $VerboseOption = if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) { $true } else { $false }
    $invokeParams =@{}

    if($ComputerName -ne "" -and $ComputerName -ne $env:COMPUTERNAME -and $ComputerName -ne "localhost"){
        $remote=$true

    }

    if (-not $remote) {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ( -not $isElevated ) {
            $("") ; Write-Warning "`r`nThis script must be run with administrative privileges. Please restart the script in an elevated PowerShell session.`r`n"
            Pause ; $("")
            $global:LASTEXITCODE=1
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
        $ExitCode[0]=1
        $exitCode=$exitCode | Sort-Object {$_} -Descending
        $exitCode = $exitCode -join ""
        $global:LASTEXITCODE = $ExitCode
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
                $global:LASTEXITCODE = 1
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
            $exitCode=$exitCode | Sort-Object {$_} -Descending
            $exitCode = $exitCode -join ""
            $global:LASTEXITCODE = $ExitCode
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
            $exitCode=$exitCode | Sort-Object {$_} -Descending
            $exitCode = $exitCode -join ""
            $global:LASTEXITCODE = $ExitCode
            break
        }
    }

    if ($remote) {
        Invoke-Command @invokeParams -ScriptBlock ${function:New-Folder} -ArgumentList $localTempPath
    } else {
        New-Folder -FolderPath $localTempPath
    }

    if (-not $noDism) {
        $dismScanLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_DISM_scanHealth.log"
        $dismScanResult=0
        if($remote){
            $dismScanResult = Invoke-Command @invokeParams -ScriptBlock ${function:Invoke-DISMScan} -ArgumentList $dismScanLog, $ChangeTimeout, $Quiet, $VerboseOption
        } else { $dismScanResult=Invoke-DISMScan $dismScanLog $ChangeTimeout $Quiet $VerboseOption}
        $dismScanResult = [int]($dismScanResult | Select-Object -First 1)
        $ExitCode[2]=$dismScanResult
        $dismScanResultString = $dismScanResult.ToString()

        $dismRestoreLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_DISM_restoreHealth.log"
        if ($dismScanResultString -eq 0) {
            $dismScanExit=1
            $dismRestoreExit=0
            if($remote){
                $dismScanExit=Invoke-Command @invokeParams -ScriptBlock ${function:Get-DISMScanResult} -ArgumentList $dismScanLog
            } else { $dismScanExit=Get-DISMScanResult -dismScanLog $dismScanLog}
            if ($dismScanExit -eq 1) {

                if ($remote) {
                    $dismRestoreExit=Invoke-Command @invokeParams -ScriptBlock ${function:Invoke-DISMRestore} -ArgumentList $dismRestoreLog, $ChangeTimeout, $Quiet, $VerboseOption
                } else { $dismRestoreExit=Invoke-DISMRestore $dismRestoreLog $ChangeTimeout $Quiet $VerboseOption }
                $ExitCode[3]=$dismRestoreExit
            }
        } else {
            $message = "DISM ScanHealth returned an unexpected exit code ($dismScanResultString) on $ComputerName. Please review the logs."
            Write-Verbose $message
            if ($remote) {
                Invoke-Command @invokeParams -ScriptBlock {
                    param ($logPath, $logMessage)
                    Add-Content -Path $logPath -Value $logMessage
                }  -Verbose:$VerboseOption -ArgumentList $dismRestoreLog, $message
            } else {
                Add-Content -Path $dismRestoreLog -Value $message
                Write-Output $message
            }
        }
        if ($IncludeComponentCleanup) {
            $analyzeComponentLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_DISM_analyze-component.log"
            $analyzeExit=0
            if ($remote) {
                $analyzeExit = Invoke-Command @invokeParams -ScriptBlock ${function:Invoke-DISMAnalyzeComponentStore} -ArgumentList $analyzeComponentLog, $ChangeTimeout, $Quiet, $VerboseOption
            } else { $analyzeExit = Invoke-DISMAnalyzeComponentStore $analyzeComponentLog $ChangeTimeout $Quiet $VerboseOption }
            $ExitCode[4]=$analyzeExit

            # Check the output and perform cleanup if recommended
            $message = ""
            $componentCleanupLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_DISM_componentStore-cleanup.log"
            if ($analyzeExit -eq 0 -or $analyzeExit -eq "") {
                $analyzeResult=$true
                if ($remote) {
                    $analyzeResult=Invoke-Command @invokeParams -ScriptBlock ${function:Get-DISMAnalyzeComponentStoreResult} -ArgumentList $analyzeComponentLog
                } else { $analyzeResult=Get-DISMAnalyzeComponentStoreResult -analyzeComponentLog $analyzeComponentLog }
                $componentCleanupExit=0
                if ($analyzeResult) {

                    if ($remote) {
                        $componentCleanupExit=Invoke-Command @invokeParams -ScriptBlock ${function:Invoke-DISMComponentStoreCleanup} -ArgumentList $componentCleanupLog, $ChangeTimeout, $Quiet, $VerboseOption
                    } else { $componentCleanupExit=Invoke-DISMComponentStoreCleanup $componentCleanupLog $ChangeTimeout $Quiet $VerboseOption }
                } else {
                    $message = "No component store cleanup was needed on $ComputerName."
                    if($remote) {
                        Invoke-Command @invokeParams -ScriptBlock {
                            param ($logPath, $logMessage)
                            Add-Content -Path $logPath -Value $logMessage
                        }  -Verbose:$VerboseOption -ArgumentList $componentCleanupLog, $message
                    } else {
                        Write-Verbose $message
                        Add-Content -Path $componentCleanupLog -Value $message
                    }
                }

                $ExitCode[5]=$componentCleanupExit
            } else {
                $message = "DISM AnalyzeComponentStore returned an unexpected exit code ($analyzeResult) on $ComputerName. Please review the logs."
                Write-Output $message
                Add-Content -Path $componentCleanupLog -Value $message
            }
        }
    }

    if(-not $noSfc){
        $sfcLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_sfc-scannow.log"
        $sfcExitCode=0
        if($remote){
            $sfcExitCode= Invoke-Command @invokeParams -ScriptBlock ${function:Invoke-SFC} -ArgumentList $sfcLog, $ChangeTimeout, $Quiet, $VerboseOption
        } else {$sfcExitCode=Invoke-SFC $sfcLog $ChangeTimeout $Quiet $VerboseOption}
        $ExitCode[1]=$sfcExitCode
    }


    if ($sccmCleanup) {
        $sccmCleanupLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_SCCM_cleanup.log"
        $sccmCleanupResult=0
        if ($remote) {
            $sccmCleanupResult=Invoke-Command @invokeParams -ScriptBlock ${function:Invoke-SCCMCleanup} -ArgumentList $sccmCleanupLog, $Quiet, $VerboseOption
        } else { $sccmCleanupResult=Invoke-SCCMCleanup $sccmCleanupLog $Quiet $VerboseOption }

        $ExitCode[6]=$sccmCleanupResult
    }

    if ($WindowsUpdateCleanup) {,
        $updateCleanupLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_WinUpdt-BITS_reset-cleanup.log"
        $updateCleanupExit=0
        if ($remote) {
            $updateCleanupExit=Invoke-Command @invokeParams -ScriptBlock ${function:Invoke-WindowsUpdateCleanup} -ArgumentList $updateCleanupLog, $ChangeTimeout, $Quiet, $VerboseOption
        } else { $updateCleanupExit=Invoke-WindowsUpdateCleanup  $updateCleanupLog $ChangeTimeout $Quiet $VerboseOption }

        if($updateCleanupExit -ne 0){
            Write-Error "`r`nAn error occurred while performing Windows Update Cleanup on $ComputerName. Please review the logs.`r`n`tA Restart of the Device is Adviced! Please try again afterwards"
        }
        $ExitCode[7]=$updateCleanupExit
    }

    if ($RepairCCM) {
        if ($remote) {
            Invoke-Command @invokeParams -ScriptBlock ${function:Repair-CCM} -ArgumentList $localTempPath, $Quiet, $VerboseOption
        } else { Repair-CCM $localTempPath $Quiet $VerboseOption }
    }


    # Zip CBS.log and DISM.log
    if (-not $noSfc -or -not $noDism) {
        $zipFile = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_CBS-DISM_sys-logs.zip"
        $zipErrorLog = "$localTempPath\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_CBS-DISM_zip-errors.log"
        $zipErrorCode=0
        if ($remote) {
            $zipErrorCode=Invoke-Command @invokeParams -ScriptBlock ${function:Start-ZipFileCreation} -ArgumentList $localTempPath, $zipFile, $zipErrorLog, $noDism
        } else {
            $zipErrorCode=Start-ZipFileCreation $localTempPath $zipFile $zipErrorLog $noDism
        }

        $ExitCode[8]=$zipErrorCode
    } else {
        $ExitCode[8]=0
    }

    if($remote) {$path=$finalDestinationPath} else {$path=$localTempPath}
    $extmsg= "`r`nSystem-Repair performed. If Errors Occurred, or SFC/DISM/WindowsUpdate Cleanup and Diagnostics Jobs were Terminated due to Timeout, please restart the system and run once more."
    $extmsglLogP ="`r`nLog-Files can be found on this Machine under '$path'"
    $extmsgrLogP ="`r`n`tThe Log-Data can be found on the Remote Device on $remoteTempPath"
    if (-not $noCopy){
        if ($remote){
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
                    $extmsg+= $extmsgrLogP
                }
            } catch {
                $message = "An error occurred while copying the log files from $ComputerName."
                Write-Error $message
                $extmsg+= $extmsgrLogP+"`r`n[ERROR]`r`t$_"
            }
        }
    } else {
        $extmsg+= $extmsgrLogP
    }

    Start-Sleep -Seconds 1
    Write-Host $extmsg
    $exitCode=$exitCode | Sort-Object {$_} -Descending
    $exitCode = $exitCode -join ""
    $global:LASTEXITCODE = $ExitCode
}
Export-ModuleMember -Function Repair-System, Repair-LocalSystem, Repair-RemoteSystem

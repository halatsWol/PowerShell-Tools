function Repair-RemoteSystem {
    <#
    .SYNOPSIS
    Repairs the system by running SFC and DISM commands on a remote computer.

    .DESCRIPTION
    This function performs a series of system repair commands on a remote computer. It first checks the availability of the remote machine by pinging it.
    Then, depending on the options specified, it executes `sfc /scannow` and  `DISM` commands to scan and repair the Windows image.

    The results are logged both on the remote machine and optionally shown on the local console. Logs and relevant system files are then transferred to the local machine.

    .PARAMETER ComputerName
    The hostname or IP address of the remote computer where the system repair will be performed.

    .PARAMETER sfcOnly
    When specified, only the `sfc /scannow` command is executed. The `DISM` commands are skipped.

    .PARAMETER Quiet
    Suppresses console output on the local machine. The output is logged to files on the remote machine instead.

    .PARAMETER IncludeComponentCleanup
    When specified, performs `DISM /Online /Cleanup-Image /AnalyzeComponentStore` and, if recommended, performs `DISM /Online /Cleanup-Image /StartComponentCleanup`.

    .PARAMETER WindowsUpdateCleanup
    When specified, performs Windows Update Cleanup by renaming the SoftwareDistribution and catroot2 folders.

    .EXAMPLE
    Repair-RemoteSystem -ComputerName <remote-device>

    Runs the `sfc /scannow` and `DISM` commands on the remote computer `<remote-device>`. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-RemoteSystem <remote-device> -sfcOnly

    Runs only the `sfc /scannow` command on the remote computer `<remote-device>`. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-RemoteSystem <remote-device> -Quiet

    Runs the `sfc /scannow` and `DISM` commands on the remote computer `<remote-device>`. Outputs are logged to files but not shown on the console.

    .EXAMPLE
    Repair-RemoteSystem <remote-device> -IncludeComponentCleanup

    Analyses the Component Store and removes old Data which is not required anymore. Cannot be used with '-sfcOnly'

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




    Author: Wolfram Halatschek
    E-Mail: halatschek.wolfram@gmail.com
    Date: 2024-08-15
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [ValidatePattern('^(([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false, Position=1)]
        [switch]$sfcOnly,

        [Parameter(Mandatory = $false, Position=2)]
        [switch]$Quiet,

        [Parameter(Mandatory = $false, Position=3)]
        [switch]$IncludeComponentCleanup,

        [Parameter(Mandatory = $false, Position=4)]
        [switch]$WindowsUpdateCleanup

    )

    # check if verbose param is set in command execution
    $VerboseOption = if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) { $true } else { $false }


    # Validation to ensure -IncludeComponentCleanup is not used with -sfcOnly
    if ($sfcOnly -and $IncludeComponentCleanup) {
        Write-Error "The parameter -IncludeComponentCleanup cannot be used in combination with -sfcOnly."
        return 1
    }

    # Ping the remote computer to check availability
    $pingResult = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet

    if (-not $pingResult) {
        Write-Host "Unable to reach $ComputerName. Please check the network connection."
        return 2
    }



    # Set up paths and file names for logging
    $currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
    $remoteTempPath = "\\$ComputerName\C$\_temp"
    $localTempPath = "C:\remote-Files\$ComputerName"
    $sfcLog = "$remoteTempPath\sfc-scannow_$currentDateTime.log"
    $dismScanLog = "$remoteTempPath\dism-scan_$currentDateTime.log"
    $dismRestoreLog = "$remoteTempPath\dism-restore_$currentDateTime.log"
    $analyzeComponentLog = "$remoteTempPath\analyze-component_$currentDateTime.log"
    $componentCleanupLog = "$remoteTempPath\component-cleanup_$currentDateTime.log"
    $zipFile = "$remoteTempPath\cbsDism-logs_$ComputerName_$currentDateTime.zip"
    $zipErrorLog = "$remoteTempPath\zip-errors_$currentDateTime.log"
    $updateCleanupLog = "$remoteTempPath\update-cleanup_$currentDateTime.log"
    $ExitCode=0,0,0,0,0,0,0,0 #Startup, SFC, DISM Scan, DISM Restore, Analyze Component, Component Cleanup, Windows Update Cleanup, Zip CBS/DISM Logs

    try{
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-Process | Out-Null
        } -Verbose:$VerboseOption
    } catch {
        $winRMexit = "Unable to establish a remote PowerShell session to $ComputerName. Please check the WinRM configuration."
        Write-Host $winRMexit
        if (-not (Test-Path -Path $localTempPath)) {
            New-Item -Path $localTempPath -ItemType Directory -Force
        }
        Add-Content -Path "$localTempPath\remoteConnectError_$currentDateTime.log" -Value "[$currentDateTime] - ERROR:`r`n$winRMexit"
        return 3
    }

    if (-not (Test-Path -Path $remoteTempPath)) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-Item -Path "C:\_temp" -ItemType Directory -Force
        } -Verbose:$VerboseOption
    }

    # Execute sfc /scannow
    $sfcExitCode= Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Write-Verbose "executing SFC"
        if ($using:Quiet) {
            sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } > $using:sfcLog 2>&1
        } else {
            sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } | Tee-Object -FilePath $using:sfcLog
        }
        $sfcExitCode=$LASTEXITCODE
        $logContent = Get-Content $using:sfcLog -Raw
        $logContent = $logContent -replace [char]0
        Set-Content $using:sfcLog -Value $logContent
        return $sfcExitCode
    } -Verbose:$VerboseOption
    $ExitCode[1]=$sfcExitCode

    if (-not $sfcOnly) {
        # Execute dism /online /Cleanup-Image /Scanhealth
        $dismScanResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "executing DISM/ScanHealth"
            if ($using:Quiet) {
                dism /online /Cleanup-Image /Scanhealth > $using:dismScanLog 2>&1
            } else {
                dism /online /Cleanup-Image /Scanhealth | Tee-Object -FilePath $using:dismScanLog
            }
            return $LASTEXITCODE
        } -Verbose:$VerboseOption
        $dismScanResult = [int]($dismScanResult | Select-Object -First 1)
        $ExitCode[2]=$dismScanResult
        $dismScanResultString = $dismScanResult.ToString()



        # Explicitly check the exit code to decide on RestoreHealth
        if ($dismScanResultString -eq 0) {
            # Component store is repairable, proceed with RestoreHealth
            $dismRestoreExit=Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $ScanResult = Get-Content -Path $using:dismScanLog | Select-Object -Reverse | ForEach-Object {
                    if ($_ -match 'The component store is repairable.') {
                        return 1
                    } elseif ($_ -match 'No component store corruption detected.') {
                        return 0
                    }
                }
                if ($ScanResult -eq 1) {
                    Write-Verbose "executing DISM/RestoreHealth"
                    Clear-Content -Path $using:dismRestoreLog
                    if ($using:Quiet) {
                        dism /online /Cleanup-Image /RestoreHealth > $using:dismRestoreLog 2>&1
                    } else {
                        dism /online /Cleanup-Image /RestoreHealth | Tee-Object -FilePath $using:dismRestoreLog
                    }
                    return $LASTEXITCODE
                }
            } -Verbose:$VerboseOption
            $ExitCode[3]=$dismRestoreExit
        } else {
            $message = "DISM ScanHealth returned an unexpected exit code ($dismScanResultString) on $ComputerName. Please review the logs."
            Write-Verbose $message
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param ($logPath, $logMessage)
                Add-Content -Path $logPath -Value $logMessage
            }  -Verbose:$VerboseOption -ArgumentList $dismRestoreLog, $message
        }

        if ($IncludeComponentCleanup) {
            # Perform DISM /Online /Cleanup-Image /AnalyzeComponentStore
            $analyzeExit = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                if ($using:Quiet) {
                    dism /Online /Cleanup-Image /AnalyzeComponentStore > $using:analyzeComponentLog 2>&1
                } else {
                    dism /Online /Cleanup-Image /AnalyzeComponentStore | Tee-Object -FilePath $using:analyzeComponentLog
                }
                return $LASTEXITCODE
            } -Verbose:$VerboseOption
            $ExitCode[4]=$analyzeExit


            # Check the output and perform cleanup if recommended
            $message = ""
            if ($analyzeExit -eq 0 ) {
                $componentCleanupExit=Invoke-Command -ComputerName $ComputerName -ScriptBlock {

                    $analyzeResult = Get-Content -Path $using:analyzeComponentLog | Select-Object -Reverse | ForEach-Object {
                            if ($_ -match 'Component Store Cleanup Recommended : Yes') {
                                return 1
                            } elseif ($_ -match 'Component Store Cleanup Recommended : No') {
                                return 0
                            }
                        }


                    if ($analyzeResult -eq 1) {
                        if ($using:Quiet) {
                            dism /Online /Cleanup-Image /StartComponentCleanup > $using:componentCleanupLog 2>&1
                        } else {
                            dism /Online /Cleanup-Image /StartComponentCleanup | Tee-Object -FilePath $using:componentCleanupLog
                        }
                        $message = "Component store cleanup was performed on $using:ComputerName."
                        Write-Verbose $message
                        Add-Content -Path $using:componentCleanupLog -Value $message
                    } else {
                        $message = "No component store cleanup was needed on $using:ComputerName."
                        Write-Verbose $message
                        Add-Content -Path $using:componentCleanupLog -Value $message
                    }
                } -Verbose:$VerboseOption
                $ExitCode[5]=$componentCleanupExit
            } else {
                $message = "DISM AnalyzeComponentStore returned an unexpected exit code ($analyzeResult) on $using:ComputerName. Please review the logs."
                Write-Output $message
                Add-Content -Path $componentCleanupLog -Value $message
            }
        }

        if ($WindowsUpdateCleanup) {
            $message = "Starting Windows Update Cleanup"
            Write-Verbose $message
            $updateCleanupExit=Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                try {
                    $softwareDistributionPath = "$Env:systemroot\SoftwareDistribution"
                    $catroot2Path = "$Env:systemroot\system32\catroot2"
                    $softwareDistributionBackupPath = "$softwareDistributionPath.bak"
                    $catroot2BackupPath = "$catroot2Path.bak"
                    stop-service wuauserv
                    stop-service bits
                    stop-service appidsvc
                    stop-service cryptsvc
                    if (Test-Path -Path $softwareDistributionBackupPath) {
                        Write-Verbose "Backup directory exists. Deleting $softwareDistributionBackupPath..."
                        Remove-Item -Path $softwareDistributionBackupPath -Recurse -Force -Verbose
                    } else {
                        Write-Verbose "Backup directory does not exist. No need to delete."
                    }
                    Rename-Item -Path $softwareDistributionPath -NewName SoftwareDistribution.bak
                    if (Test-Path -Path $catroot2BackupPath) {
                        Write-Verbose "Backup directory exists. Deleting $catroot2BackupPath..."
                        Remove-Item -Path $catroot2BackupPath -Recurse -Force -Verbose
                    } else {
                        Write-Verbose "Backup directory does not exist. No need to delete."
                    }
                    Rename-Item -Path $catroot2Path -NewName catroot2.bak
                    start-service bits
                    start-service wuauserv
                    start-service appidsvc
                    start-service cryptsvc
                    $successMessage = "Windows Update Cleanup successfully.`r`nSoftwareDistribution and catroot2 folders have been renamed."
                    Write-Verbose $errorMessage
                    Add-Content -Path $using:updateCleanupLog -Value "[$using:currentDateTime] - INFO:`r`n$successMessage"
                } catch {
                    $errorMessage = "An error occurred while performing Windows Update Cleanup: $_"
                    Write-Output $errorMessage
                    Add-Content -Path $using:updateCleanupLog -Value "[$using:currentDateTime] - ERROR:`r`n$errorMessage"
                    return 1
                }
            } -Verbose:$VerboseOption
            $ExitCode[6]=$updateCleanupExit
        }
    }



    # Zip CBS.log and DISM.log
    $zipErrorCode= Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        try {
            $cbsLog = "$env:windir\Logs\CBS\CBS.log"
            $dismLog = "$env:windir\Logs\dism\dism.log"
            $tempPath = "$using:remoteTempPath"
            $filesToZip = @()

            # Copy CBS.log to the temporary directory if it exists
            if (Test-Path $cbsLog) {
                Copy-Item -Path $cbsLog -Destination $tempPath
                $filesToZip += (Join-Path -Path $tempPath -ChildPath "CBS.log")
            }

            # Copy DISM.log to the temporary directory if it exists and the sfcOnly flag is not set
            if (-not $using:sfcOnly) {
                if (Test-Path $dismLog) {
                    Copy-Item -Path $dismLog -Destination $tempPath
                    $filesToZip += (Join-Path -Path $tempPath -ChildPath "dism.log")
                }
            }

            # Delete existing zip file if it exists
            if (Test-Path $using:zipFile) {
                Remove-Item -Path $using:zipFile -Force
            }

            # Create a new zip file
            if ($filesToZip.Count -gt 0) {
                Compress-Archive -Path $filesToZip -DestinationPath $using:zipFile -Force
            }

            # Remove the copied logs from the temporary directory
            foreach ($file in $filesToZip) {
                if (Test-Path $file) {
                    Remove-Item -Path $file -Force
                }
            }
        } catch {
            $errorMessage = "An error occurred while creating the zip file: $_"
            Write-Output $message
            Add-Content -Path $using:zipErrorLog -Value "[$using:currentDateTime] - ERROR:`r`n$errorMessage"
            return 1
        }
        return 0
    } -Verbose:$VerboseOption
    $ExitCode[7]=$zipErrorCode

    # Copy log files to local machine
    if (-not (Test-Path -Path $localTempPath)) {
        New-Item -Path $localTempPath -ItemType Directory -Force
    }
    Copy-Item -Path "\\$ComputerName\C$\_temp\*" -Destination $localTempPath -Recurse -Force

    # Clear remote _temp folder if copy was successful
    if ($?) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Remove-Item -Path "C:\_temp\*" -Recurse -Force
        } -Verbose:$VerboseOption
    }



    Write-Host "System-Repair on $ComputerName successfully performed.`r`nLog-Files can be found on this Machine under '$localTempPath'"
    $exitCode=$exitCode | Sort-Object {$_} -Descending
    $exitCode = $exitCode -join ""
    $global:LASTEXITCODE = $ExitCode
}

function Repair-LocalSystem {

 <#
    .SYNOPSIS
    Repairs the system by running SFC and DISM commands on the local computer.

    .DESCRIPTION
    This function performs a series of system repair commands on the local computer. It first checks the availability of the machine by pinging it.
    Then, depending on the options specified, it executes `sfc /scannow` and  `DISM` commands to scan and repair the Windows image.

    The results are logged both on the machine and optionally shown on the local console. Logs and relevant system files are then transferred to the %HomeDrive%\Repair-System Directory.


    .PARAMETER sfcOnly
    When specified, only the `sfc /scannow` command is executed. The `DISM` commands are skipped.

    .PARAMETER Quiet
    Suppresses console output on the local machine. The output is always logged to files on the local machine instead.

    .PARAMETER IncludeComponentCleanup
    When specified, performs `DISM /Online /Cleanup-Image /AnalyzeComponentStore` and, if recommended, performs `DISM /Online /Cleanup-Image /StartComponentCleanup`.

    .PARAMETER WindowsUpdateCleanup
    When specified, performs Windows Update Cleanup by renaming the SoftwareDistribution and catroot2 folders.

    .EXAMPLE
    Repair-LocalSystem

    Runs the `sfc /scannow` and `DISM` commands on the  computer. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-LocalSystem -sfcOnly

    Runs only the `sfc /scannow` command on the  computer. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-LocalSystem -Quiet

    Runs the `sfc /scannow` and `DISM` commands on the  computer. Outputs are logged to files but not shown on the console.

    .EXAMPLE
    Repair-LocalSystem -IncludeComponentCleanup

    Analyses the Component Store and removes old Data which is not required anymore. Cannot be used with '-sfcOnly'

    .EXAMPLE
    Repair-LocalSystem -WindowsUpdateCleanup
    stops the Windows Update and related Services, renames the SoftwareDistribution and catroot2 folders, and restarts the services.

    .NOTES
    This script is provided as-is and is not supported by Microsoft. Use it at your own risk.
    Using this script may require administrative privileges on the local computer.

    WARNING:
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT PERMISSION OR AUTHORIZATION.
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT UNDERSTANDING THE CONSEQUENCES.
    NEVER RUN SCRIPTS FROM UNTRUSTED SOURCES WITHOUT REVIEWING AND UNDERSTANDING THE CODE.
    DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING. IT MAY CAUSE DATA LOSS OR SYSTEM INSTABILITY.




    Author: Wolfram Halatschek
    E-Mail: halatschek.wolfram@gmail.com
    Date: 2024-08-1
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position=0)]
        [switch]$sfcOnly,

        [Parameter(Mandatory = $false, Position=1)]
        [switch]$Quiet,

        [Parameter(Mandatory = $false, Position=2)]
        [switch]$IncludeComponentCleanup,

        [Parameter(Mandatory = $false, Position=3)]
        [switch]$WindowsUpdateCleanup
    )


    # Validation to ensure -IncludeComponentCleanup is not used with -sfcOnly
    if ($sfcOnly -and $IncludeComponentCleanup) {
        Write-Error "The parameter -IncludeComponentCleanup cannot be used in combination with -sfcOnly."
        return 1
    }
    # Set up paths and file names for logging
    $currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
    $TempPath = "$env:HOMEDRIVE\_temp"
    $logPath = "C:\Repair-System\"
    $sfcLog = "$TempPath\sfc-scannow_$currentDateTime.log"
    $dismScanLog = "$TempPath\dism-scan_$currentDateTime.log"
    $dismRestoreLog = "$TempPath\dism-restore_$currentDateTime.log"
    $analyzeComponentLog = "$TempPath\analyze-component_$currentDateTime.log"
    $componentCleanupLog = "$TempPath\component-cleanup_$currentDateTime.log"
    $updateCleanupLog = "$TempPath\update-cleanup_$currentDateTime.log"
    $zipFile = "$TempPath\cbsDism-logs_$currentDateTime.zip"
    $zipErrorLog = "$TempPath\zip-errors_$currentDateTime.log"
    $ExitCode=0,0,0,0,0,0,0,0 #Startup, SFC, DISM Scan, DISM Restore, Analyze Component, Component Cleanup, Windows Update Cleanup, Zip CBS/DISM Logs

    # Execute sfc /scannow

    Write-Verbose "executing SFC"
    if ($Quiet) {
        sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } > $sfcLog 2>&1
    } else {
        sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } | Tee-Object -FilePath $sfcLog
    }
    $ExitCode[1]=$LASTEXITCODE
    $logContent = Get-Content $sfcLog -Raw
    $logContent = $logContent -replace [char]0
    Set-Content $sfcLog -Value $logContent

    if (-not $sfcOnly) {
        # Execute dism /online /Cleanup-Image /Scanhealth
        $dismScanResult = {
            Write-Verbose "executing DISM/ScanHealth"
            if ($Quiet) {
                dism /online /Cleanup-Image /Scanhealth > $dismScanLog 2>&1
            } else {
                dism /online /Cleanup-Image /Scanhealth | Tee-Object -FilePath $dismScanLog
            }
            $ExitCode[2]=$LASTEXITCODE
            return $LASTEXITCODE
        }

        # Explicitly check the exit code to decide on RestoreHealth
        $message = ""
        if ($dismScanResult -eq 0) {
            $ScanResult = Get-Content -Path $using:dismScanLog | Select-Object -Reverse | ForEach-Object {
                if ($_ -match 'The component store is repairable.') {
                    return 1
                } elseif ($_ -match 'No component store corruption detected.') {
                    return 0
                }
            }
            if ($ScanResult -eq 1) {
                Write-Verbose "executing DISM/RestoreHealth"
                Clear-Content -Path $using:dismRestoreLog
                if ($using:Quiet) {
                    dism /online /Cleanup-Image /RestoreHealth > $dismRestoreLog 2>&1
                } else {
                    dism /online /Cleanup-Image /RestoreHealth | Tee-Object -FilePath $dismRestoreLog
                }
                $ExitCode[3]=$LASTEXITCODE
            }
        } else {
            $message = "DISM ScanHealth returned an unexpected exit code ($dismScanResult). Please review the logs."

        }
        if($message -ne ""){
            Write-Verbose $message
            Add-Content -Path $dismRestoreLog -Value $message
        }

        if ($IncludeComponentCleanup) {
            # Perform DISM /Online /Cleanup-Image /AnalyzeComponentStore
            $analyzeExit =  {
                if ($using:Quiet) {
                    dism /Online /Cleanup-Image /AnalyzeComponentStore > $analyzeComponentLog 2>&1
                } else {
                    dism /Online /Cleanup-Image /AnalyzeComponentStore | Tee-Object -FilePath $analyzeComponentLog
                }
                $ExitCode[4]=$LASTEXITCODE
                return $LASTEXITCODE
            }

            $analyzeResult ={
                $match = Get-Content -Path $analyzeComponentLog | Select-Object -Reverse | ForEach-Object {
                    if ($_ -match 'Component Store Cleanup Recommended : Yes') {
                        return 1
                    } elseif ($_ -match 'Component Store Cleanup Recommended : No') {
                        return 0
                    }
                }
                return $match
            }

            # Check the output and perform cleanup if recommended
            $message = ""
            if ($analyzeExit -eq 0 -and $analyzeResult -eq 1) {

                $cleanupRecommended = Select-String -Path $componentCleanupLog -Pattern "Component store cleanup recommended"
                if ($cleanupRecommended) {
                    if ($Quiet) {
                        dism /Online /Cleanup-Image /StartComponentCleanup > $componentCleanupLog 2>&1
                    } else {
                        dism /Online /Cleanup-Image /StartComponentCleanup | Tee-Object -FilePath $componentCleanupLog
                    }
                    $ExitCode[5]=$LASTEXITCODE
                    $message = "Component store cleanup was performed."
                } elseif ($analyzeExit -eq 0 -and $analyzeResult -eq 0) {
                    $message = "No Component store cleanup recommended."
                } else { $message = "DISM AnalyzeComponentStore returned an unexpected exit code ($analyzeResult). Please review the logs."}


            } else { $message = "DISM AnalyzeComponentStore returned an unexpected exit code ($analyzeResult) on $ComputerName. Please review the logs."}
            if($message -ne ""){
                Write-Verbose $message
                Add-Content -Path $componentCleanupLog -Value $message
            }
        }

        if ($WindowsUpdateCleanup) {
            $message = "Starting Windows Update Cleanup"
            Write-Verbose $message
            $successMessage=""
            try {
                $softwareDistributionPath = "$Env:systemroot\SoftwareDistribution"
                $catroot2Path = "$Env:systemroot\system32\catroot2"
                $softwareDistributionBackupPath = "$softwareDistributionPath.bak"
                $catroot2BackupPath = "$catroot2Path.bak"
                stop-service wuauserv
                stop-service bits
                stop-service appidsvc
                stop-service cryptsvc
                if (Test-Path -Path $softwareDistributionBackupPath) {
                    Write-Verbose "Backup directory exists. Deleting $softwareDistributionBackupPath..."
                    Remove-Item -Path $softwareDistributionBackupPath -Recurse -Force -Verbose
                } else {
                    Write-Verbose "Backup directory does not exist. No need to delete."
                }
                Rename-Item -Path $softwareDistributionPath -NewName SoftwareDistribution.bak
                if (Test-Path -Path $catroot2BackupPath) {
                    Write-Verbose "Backup directory exists. Deleting $catroot2BackupPath..."
                    Remove-Item -Path $catroot2BackupPath -Recurse -Force -Verbose
                } else {
                    Write-Verbose "Backup directory does not exist. No need to delete."
                }
                Rename-Item -Path $catroot2Path -NewName catroot2.bak
                start-service bits
                start-service wuauserv
                start-service appidsvc
                start-service cryptsvc
                $ExitCode[6]=$LASTEXITCODE
                $successMessage = "Windows Update Cleanup successfully.`r`nSoftwareDistribution and catroot2 folders have been renamed."
                Write-Verbose $errorMessage
                Add-Content -Path $updateCleanupLog -Value "[$currentDateTime] - INFO:`r`n$successMessage"

            } catch {
                $successMessage = "An error occurred while performing Windows Update Cleanup: $_"
                Write-Output $errorMessage
                Add-Content -Path $updateCleanupLog -Value "[$currentDateTime] - ERROR:`r`n$errorMessage"
                $ExitCode[6]=1

            }

        }

        return
    }


    $zipErrorCode= {
        try {
            $cbsLog = "$env:windir\Logs\CBS\CBS.log"
            $dismLog = "$env:windir\Logs\dism\dism.log"

            $filesToZip = @()

            # Copy CBS.log to the temporary directory if it exists
            if (Test-Path $cbsLog) {
                Copy-Item -Path $cbsLog -Destination $TempPath
                $filesToZip += (Join-Path -Path $TempPath -ChildPath "CBS.log")
            }

            # Copy DISM.log to the temporary directory if it exists and the sfcOnly flag is not set
            if (-not $using:sfcOnly) {
                if (Test-Path $dismLog) {
                    Copy-Item -Path $dismLog -Destination $TempPath
                    $filesToZip += (Join-Path -Path $TempPath -ChildPath "dism.log")
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
            Write-Output $message
            Add-Content -Path $zipErrorLog -Value "[$currentDateTime] - ERROR:`r`n$errorMessage"
            return 1
        }
        return 0
    }
    $ExitCode[7]=$zipErrorCode


    # Copy log files to local machine
    if (-not (Test-Path -Path $logPath)) {
        New-Item -Path $logPath -ItemType Directory -Force
    }
    Copy-Item -Path "$TempPath\*" -Destination $logPath -Recurse -Force

    # Clear remote _temp folder if copy was successful
    if ($?) {
        Remove-Item -Path "$TempPath\*" -Recurse -Force
    }



    Write-Host "Local System-Repair successfully performed.`r`nLog-Files can be found on this Machine under '$logPath'"

    $exitCode=$exitCode | Sort-Object {$_} -Descending
    $exitCode = $exitCode -join ""
    $global:LASTEXITCODE = $ExitCode
}


Export-ModuleMember -Function Repair-RemoteSystem, Repair-LocalSystem

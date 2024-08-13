# Define the Repair-System module

function Repair-System {
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

    .EXAMPLE
    Repair-System -ComputerName <remote-device>

    Runs the `sfc /scannow` and `DISM` commands on the remote computer `<remote-device>`. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-System <remote-device> -sfcOnly

    Runs only the `sfc /scannow` command on the remote computer `<remote-device>`. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-System <remote-device> -Quiet

    Runs the `sfc /scannow` and `DISM` commands on the remote computer `<remote-device>`. Outputs are logged to files but not shown on the console.

    .EXAMPLE
    Repair-System <remote-device> -IncludeComponentCleanup

    Analyses the Component Store and removes old Data which is not required anymore. Cannot be used with '-sfcOnly'

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
    Date: 2024-08-12
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
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
    $localTempPath = "C:\remoteFiles\$ComputerName"
    $sfcLog = "$remoteTempPath\sfc-scannow_$currentDateTime.log"
    $dismScanLog = "$remoteTempPath\dism-scan_$currentDateTime.log"
    $dismRestoreLog = "$remoteTempPath\dism-restore_$currentDateTime.log"
    $analyzeComponentLog = "$remoteTempPath\analyze-component_$currentDateTime.log"
    $componentCleanupLog = "$remoteTempPath\component-cleanup_$currentDateTime.log"
    $zipFile = "$remoteTempPath\logs_$ComputerName_$currentDateTime.zip"
    $zipErrorLog = "$remoteTempPath\zip-errors_$currentDateTime.log"
    $updateCleanupLog = "$remoteTempPath\update-cleanup_$currentDateTime.log"


    if (-not (Test-Path -Path $remoteTempPath)) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-Item -Path "C:\_temp" -ItemType Directory -Force
        }
    }

    # Execute sfc /scannow
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Write-Verbose "executing SFC"
        if ($using:Quiet) {
            sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } > $using:sfcLog 2>&1
            $logContent = Get-Content $using:sfcLog -Raw
            $logContent = $logContent -replace [char]0
            Set-Content $using:sfcLog -Value $logContent
        } else {
            sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } | Tee-Object -FilePath $using:sfcLog
            $logContent = Get-Content $using:sfcLog -Raw
            $logContent = $logContent -replace [char]0
            Set-Content $using:sfcLog -Value $logContent
        }
    }

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
        }

        # Explicitly check the exit code to decide on RestoreHealth
        if ($dismScanResult -eq 0) {
            # Component store is repairable, proceed with RestoreHealth
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                Write-Verbose "executing DISM/RestoreHealth"
                if ($using:Quiet) {
                    dism /online /Cleanup-Image /RestoreHealth > $using:dismRestoreLog 2>&1
                } else {
                    dism /online /Cleanup-Image /RestoreHealth | Tee-Object -FilePath $using:dismRestoreLog
                }
            }
        } elseif ($dismScanResult -eq 2) {
            $message = "The component store is healthy on $ComputerName. No repairs needed."
            Write-Verbose $message
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param ($logPath, $logMessage)
                Add-Content -Path $logPath -Value $logMessage
            } -ArgumentList $dismRestoreLog, $message
        } else {
            $message = "DISM ScanHealth returned an unexpected exit code ($dismScanResult) on $ComputerName. Please review the logs."
            Write-Verbose $message
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param ($logPath, $logMessage)
                Add-Content -Path $logPath -Value $logMessage
            } -ArgumentList $dismRestoreLog, $message
        }

        if ($IncludeComponentCleanup) {
            # Perform DISM /Online /Cleanup-Image /AnalyzeComponentStore
            $analyzeResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                if ($using:Quiet) {
                    dism /Online /Cleanup-Image /AnalyzeComponentStore > $using:analyzeComponentLog 2>&1
                } else {
                    dism /Online /Cleanup-Image /AnalyzeComponentStore | Tee-Object -FilePath $using:analyzeComponentLog
                }
                return $LASTEXITCODE
            }

            # Check the output and perform cleanup if recommended
            if ($analyzeResult -eq 0) {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $cleanupRecommended = Select-String -Path $using:componentCleanupLog -Pattern "Component store cleanup recommended"
                    if ($cleanupRecommended) {
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
                }
            } else {
                $message = "DISM AnalyzeComponentStore returned an unexpected exit code ($analyzeResult) on $ComputerName. Please review the logs."
                Write-Output $message
                Add-Content -Path $componentCleanupLog -Value $message
            }
        }

        if ($WindowsUpdateCleanup) {
            $message = "Starting Windows Update Cleanup"
            Write-Verbose $message
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
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
            }
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
                Copy-Item -Path $cbsLog -Destination $tempPath -Verbose
                $filesToZip += (Join-Path -Path $tempPath -ChildPath "CBS.log")
            }

            # Copy DISM.log to the temporary directory if it exists and the sfcOnly flag is not set
            if (-not $using:sfcOnly) {
                if (Test-Path $dismLog) {
                    Copy-Item -Path $dismLog -Destination $tempPath -Verbose
                    $filesToZip += (Join-Path -Path $tempPath -ChildPath "dism.log")
                }
            }

            # Delete existing zip file if it exists
            if (Test-Path $using:zipFile) {
                Remove-Item -Path $using:zipFile -Force -Verbose
            }

            # Create a new zip file
            if ($filesToZip.Count -gt 0) {
                Compress-Archive -Path $filesToZip -DestinationPath $using:zipFile -Force -Verbose
            }

            # Remove the copied logs from the temporary directory
            foreach ($file in $filesToZip) {
                if (Test-Path $file) {
                    Remove-Item -Path $file -Force -Verbose
                }
            }
        } catch {
            $errorMessage = "An error occurred while creating the zip file: $_"
            Write-Output $message
            Add-Content -Path $using:zipErrorLog -Value "[$using:currentDateTime] - ERROR:`r`n$errorMessage"
            return 1
        }
        return 0
    }


    # Copy log files to local machine
    if (-not (Test-Path -Path $localTempPath)) {
        New-Item -Path $localTempPath -ItemType Directory -Force
    }
    Copy-Item -Path "\\$ComputerName\C$\_temp\*" -Destination $localTempPath -Recurse -Force

    # Clear remote _temp folder if copy was successful
    if ($?) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Remove-Item -Path "C:\_temp\*" -Recurse -Force
        }
    }



    return $zipErrorCode
}

Export-ModuleMember -Function Repair-System

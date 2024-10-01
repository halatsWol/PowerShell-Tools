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

    .PARAMETER KeepLogs
    When specified, log files will be kept on the remote Device, but still be copied to the Client

    .PARAMETER noCopy
    When specified, log files will not be copied to the Client. this will automatically use '-KeepLogs'

    .EXAMPLE
    Repair-RemoteSystem -ComputerName <remote-device>

    Runs the `sfc /scannow` and `DISM` commands on the remote computer `<remote-device>`. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-RemoteSystem -ComputerName SomeDevice -remoteShareDrive D$

    Will connect to `\\SomeDevice\D$\`. This can be used if the SystemRoot (installation of Windows) is either not on Drive C:,
    or if the Share-Drive has a different Name (eg access via `\\SomeDevice\C\` instead of C$)

    .EXAMPLE
    Repair-RemoteSystem <remote-device> -noDism

    Runs only the `sfc /scannow` command on the remote computer `<remote-device>`. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-RemoteSystem <remote-device> -Quiet

    Runs the `sfc /scannow` and `DISM` commands on the remote computer `<remote-device>`. Outputs are logged to files but not shown on the console.

    .EXAMPLE
    Repair-RemoteSystem <remote-device> -IncludeComponentCleanup

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
    E-Mail: halatschek.wolfram@gmail.com
    Date: 2024-10-01
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
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
        [switch]$sccmCleanup,

        [Parameter(Mandatory=$false)]
        [switch]$KeepLogs,

        [Parameter(Mandatory=$false)]
        [switch]$noCopy

    )
    $ExitCode=0,0,0,0,0,0,0,0,0 #Startup, SFC, DISM Scan, DISM Restore, Analyze Component, Component Cleanup, SCCM Cleanup, Windows Update Cleanup, Zip CBS/DISM Logs

    # check if verbose param is set in command execution
    $VerboseOption = if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) { $true } else { $false }

    # Validation to ensure -IncludeComponentCleanup is not used with -noDism
    if ($noDism -and $IncludeComponentCleanup) {
        Write-Error "The parameter -IncludeComponentCleanup cannot be used in combination with -noDism."
        $ExitCode[0]=1
        $exitCode=$exitCode | Sort-Object {$_} -Descending
        $exitCode = $exitCode -join ""
        $global:LASTEXITCODE = $ExitCode
        break
    }

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


    $shareDrive="C$"
    if($remoteShareDrive -ne ""){
        $shareDrive=$remoteShareDrive
    }
    $shareDrivePath="\\$ComputerName\$shareDrive"
    # Set up paths and file names for logging
    $currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
    $remoteTempPath = "$shareDrivePath\_temp"
    $localTempPath = "C:\remote-Files\$ComputerName"
    $sfcLog = "$remoteTempPath\sfc-scannow_$currentDateTime.log"
    $dismScanLog = "$remoteTempPath\dism-scan_$currentDateTime.log"
    $dismRestoreLog = "$remoteTempPath\dism-restore_$currentDateTime.log"
    $analyzeComponentLog = "$remoteTempPath\analyze-component_$currentDateTime.log"
    $componentCleanupLog = "$remoteTempPath\component-cleanup_$currentDateTime.log"
    $zipFile = "$remoteTempPath\cbsDism-logs_$currentDateTime.zip"
    $zipErrorLog = "$remoteTempPath\zip-errors_$currentDateTime.log"
    $updateCleanupLog = "$remoteTempPath\update-cleanup_$currentDateTime.log"
    $sccmCleanupLog = "$remoteTempPath\sccm-cleanup_$currentDateTime.log"

    try{
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-Process | Out-Null
        } -Verbose:$VerboseOption -ErrorAction Stop
    } catch {
        $winRMexit = "Unable to establish a remote PowerShell session to $ComputerName. Please check the WinRM configuration.`r`n `r`n `r`nError: $_"
        Write-Error $winRMexit
        if (-not (Test-Path -Path $localTempPath)) {
            New-Item -Path $localTempPath -ItemType Directory -Force
        }
        Add-Content -Path "$localTempPath\remoteConnectError_$currentDateTime.log" -Value "[$currentDateTime] - ERROR:`r`n$winRMexit"
        $ExitCode[0]=3
        $exitCode=$exitCode | Sort-Object {$_} -Descending
        $exitCode = $exitCode -join ""
        $global:LASTEXITCODE = $ExitCode
        break
    }

    try{
        Test-Path "$shareDrivePath\Windows"
    } catch {
        $errmsg="[$using:currentDateTime] - ERROR:`tNo Windows Directory found on Remote Device`r`nTested:`t'$shareDrivePath\Windows'"
        $errmsg+="`r`nPlease check if The ShareDrive '$shareDrivePath' exists and is accessible!"
        Write-Error $errmsg
        if (-not (Test-Path -Path $localTempPath)) {
            New-Item -Path $localTempPath -ItemType Directory -Force
        }
        Add-Content -Path "$localTempPath\remoteConnectError_$currentDateTime.log" -Value "[$currentDateTime] - ERROR:`r`n$errmsg"
        $ExitCode[0]=4
        $exitCode=$exitCode | Sort-Object {$_} -Descending
        $exitCode = $exitCode -join ""
        $global:LASTEXITCODE = $ExitCode
        break
    }

    if (-not (Test-Path -Path $remoteTempPath)) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-Item -Path "C:\_temp" -ItemType Directory -Force
        } -Verbose:$VerboseOption
    }

    if(-not $noSfc){
        # Execute sfc /scannow
            $sfcExitCode= Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "executing SFC"
            try{
                if ($using:Quiet) {
                    sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } > $using:sfcLog 2>&1
                } else {
                    sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } | Tee-Object -FilePath $using:sfcLog -OutBuffer 1
                }
                $sfcExitCode=$LASTEXITCODE
                $logContent = Get-Content $using:sfcLog -Raw
                $logContent = $logContent -replace [char]0
                Set-Content $using:sfcLog -Value $logContent
                return $sfcExitCode
            } catch {
                $errorMessage = "An error occurred while performing SFC: `r`n$_"
                Write-Error $errorMessage
                Add-Content -Path $using:sfcLog -Value $errorMessage
                return 1
            }
        } -Verbose:$VerboseOption
        $ExitCode[1]=$sfcExitCode
    }

    if (-not $noDism) {
        # Execute dism /online /Cleanup-Image /Scanhealth
        $dismScanResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "executing DISM/ScanHealth"
            try{
                if ($using:Quiet) {
                    dism /online /Cleanup-Image /Scanhealth > $using:dismScanLog 2>&1
                } else {
                    dism /online /Cleanup-Image /Scanhealth | Tee-Object -FilePath $using:dismScanLog
                }
                return $LASTEXITCODE
            } catch {
                $errorMessage = "An error occurred while performing DISM ScanHealth: `r`n$_"
                Write-Error $errorMessage
                Add-Content -Path $using:dismScanLog -Value $errorMessage
                return 1
            }
        } -Verbose:$VerboseOption
        $dismScanResult = [int]($dismScanResult | Select-Object -First 1)
        $ExitCode[2]=$dismScanResult
        $dismScanResultString = $dismScanResult.ToString()



        # Explicitly check the exit code to decide on RestoreHealth
        if ($dismScanResultString -eq 0) {
            # Component store is repairable, proceed with RestoreHealth
            $dismRestoreExit=Invoke-Command -ComputerName $ComputerName -ScriptBlock {

                $ScanResult = 1
                $lines=Get-Content -Path $using:dismScanLog
                $ScanResultData=$lines[-1..-($lines.Count)]
                foreach ($line in $ScanResultData) {
                    if ($line -match 'The component store is repairable.') {
                        break
                    } elseif ($line -match 'No component store corruption detected.') {
                        $ScanResult=0
                        break
                    }
                }
                if ($ScanResult -eq 1) {
                    Write-Verbose "executing DISM/RestoreHealth"
                    try{
                        if ($using:Quiet) {
                            dism /online /Cleanup-Image /RestoreHealth > $using:dismRestoreLog 2>&1
                        } else {
                            dism /online /Cleanup-Image /RestoreHealth | Tee-Object -FilePath $using:dismRestoreLog
                        }
                        return $LASTEXITCODE
                    } catch {
                        $errorMessage = "An error occurred while performing DISM RestoreHealth: `r`n$_"
                        Write-Error $errorMessage
                        Add-Content -Path $using:dismRestoreLog -Value $errorMessage
                        return 1
                    }
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
                try{
                    if ($using:Quiet) {
                        dism /Online /Cleanup-Image /AnalyzeComponentStore > $using:analyzeComponentLog 2>&1
                    } else {
                        dism /Online /Cleanup-Image /AnalyzeComponentStore | Tee-Object -FilePath $using:analyzeComponentLog
                    }
                    return $LASTEXITCODE
                } catch {
                    $errorMessage = "An error occurred while performing DISM AnalyzeComponentStore: `r`n$_"
                    Write-Error $errorMessage
                    Add-Content -Path $using:analyzeComponentLog -Value $errorMessage
                    return 1
                }
            } -Verbose:$VerboseOption
            $ExitCode[4]=$analyzeExit


            # Check the output and perform cleanup if recommended
            $message = ""
            if ($analyzeExit -eq 0 -or $analyzeExit -eq "") {
                $componentCleanupExit=Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $lines = Get-Content -Path $using:analyzeComponentLog
                    $analyzeComponentLogData = $lines[-1..-($lines.Count)]
                    $analyzeResult = 0
                    foreach ($line in $analyzeComponentLogData) {
                        if ($line -match 'Component Store Cleanup Recommended : Yes') {
                            $analyzeResult= 1
                            break
                        } elseif ($line -match 'Component Store Cleanup Recommended : No') {
                            $analyzeResult= 0
                            break
                        }
                    }


                    if ($analyzeResult -eq 1) {
                        try{
                            if ($using:Quiet) {
                                dism /Online /Cleanup-Image /StartComponentCleanup > $using:componentCleanupLog 2>&1
                            } else {
                                dism /Online /Cleanup-Image /StartComponentCleanup | Tee-Object -FilePath $using:componentCleanupLog
                            }
                            $message = "Component store cleanup was performed on $using:ComputerName."
                            Write-Verbose $message
                            Add-Content -Path $using:componentCleanupLog -Value $message
                        } catch {
                            $message = "An error occurred while performing Component Store Cleanup: `r`n$_"
                            Write-Error $message
                            Add-Content -Path $using:componentCleanupLog -Value $message
                        }
                    } else {
                        $message = "No component store cleanup was needed on $using:ComputerName."
                        Write-Verbose $message
                        Add-Content -Path $using:componentCleanupLog -Value $message
                    }
                } -Verbose:$VerboseOption
                $ExitCode[5]=$componentCleanupExit
            } else {
                $message = "DISM AnalyzeComponentStore returned an unexpected exit code ($analyzeResult) on $ComputerName. Please review the logs."
                Write-Output $message
                Add-Content -Path $componentCleanupLog -Value $message
            }
        }


    }

    if ($sccmCleanup) {
        $sccmCleanupResult=Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "executing SCCM Cleanup"
            if (Test-Path -Path "$env:windir\ccmcache") {
                try{
                    Remove-Item -Path "$env:windir\ccmcache\*" -Recurse -Force
                    return 0
                } catch {
                    $errorMessage = "An error occurred while performing SCCM Cleanup: `r`n$_"
                    Write-Error $errorMessage
                    Add-Content -Path $using:sccmCleanupLog -Value $errorMessage
                    return 1
                }
            } else {
                $msg = "CCM Cache folder does not exist. No need to delete."
                Write-Verbose $msg
                Add-Content -Path $using:sccmCleanupLog -Value $msg
                return 0
            }

            if (Test-Path -Path "$env:windir\SoftwareDistribution\Download") {
                try{
                    Remove-Item -Path "$env:windir\SoftwareDistribution\Download\*" -Recurse -Force
                    return 0
                } catch {
                    $errorMessage = "An error occurred while Cleaning SoftwareDistribution\Download: `r`n$_"
                    Write-Error $errorMessage
                    Add-Content -Path $using:sccmCleanupLog -Value $errorMessage
                    return 1
                }
            } else {
                $msg = "SoftwareDistribution\Download folder does not exist. No need to delete."
                Write-Verbose $msg
                Add-Content -Path $using:sccmCleanupLog -Value $msg
                return 0
            }
        } -Verbose:$VerboseOption
        $ExitCode[6]=$sccmCleanupResult

    }

    if ($WindowsUpdateCleanup) {
        $servicesStart=@("bits","wuauserv","appidsvc","cryptsvc","msiserver")
        $updateCleanupExit=Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                Write-Host "Starting Windows Update Cleanup..."
                $softwareDistributionPath = "$Env:systemroot\SoftwareDistribution"
                $catroot2Path = "$Env:systemroot\system32\catroot2"
                $softwareDistributionBackupPath = "$softwareDistributionPath.bak"
                $catroot2BackupPath = "$catroot2Path.bak"
                $softDist = $false
                $softDistErr=""
                $cat2= $false
                $cat2Err=""
                stop-service @("wuauserv","bits","appidsvc","cryptsvc","msiserver")
                if (Test-Path -Path $softwareDistributionBackupPath) {
                    Write-Verbose "Backup directory exists. Deleting $softwareDistributionBackupPath..."
                    try{
                        Remove-Item -Path $softwareDistributionBackupPath -Recurse -Force
                    } catch {
                        $softDistErr= "Error deleting SoftwareDistribution backup folder: `r`n$_"
                        Add-Content -Path $using:updateCleanupLog -Value "[$using:currentDateTime] - ERROR:`r`n`t$softDistErr"
                        Write-Error $softDistErr
                        start-service $servicesStart
                        return 2
                    }
                } else {
                    Write-Verbose "Backup directory does not exist. No need to delete."
                }
                if (Test-Path -Path $softwareDistributionPath) {
                    try{
                        Rename-Item -Path $softwareDistributionPath -NewName SoftwareDistribution.bak
                        $softDist = $true
                    } catch {
                        $softDistErr= "[$using:currentDateTime] - INFO:`r`n`tError renaming SoftwareDistribution folder: `r`n$_"
                        Add-Content -Path $using:updateCleanupLog -Value "[$using:currentDateTime] - ERROR:`r`n`t$softDistErr"
                        Write-Error $softDistErr
                        start-service $servicesStart
                        return 1
                    }
                }
                if (Test-Path -Path $catroot2BackupPath) {
                    Write-Verbose "Backup directory exists. Deleting $catroot2BackupPath..."
                    try{
                        Remove-Item -Path $catroot2BackupPath -Recurse -Force
                    } catch {
                        $cat2Err= "Error deleting catroot2 backup folder: `r`n$_"
                        Add-Content -Path $using:updateCleanupLog -Value "[$using:currentDateTime] - ERROR:`r`n`t$cat2Err"
                        Write-Error $cat2Err
                        start-service $servicesStart
                        return 2
                    }
                } else {
                    Write-Verbose "Backup directory does not exist. No need to delete."
                }
                if (Test-Path -Path $catroot2Path) {
                    try{
                        Rename-Item -Path $catroot2Path -NewName catroot2.bak
                        $cat2 = $true
                    } catch {
                        $cat2Err= "[$using:currentDateTime] - ERROR:`r`n`tError renaming catroot2 folder: `r`n$_"
                        Add-Content -Path $using:updateCleanupLog -Value "[$using:currentDateTime] - ERROR:`r`n`t$cat2Err"
                        Write-Error $cat2Err
                        start-service $servicesStart
                        return 1
                    }
                } else {
                    Write-Verbose "catroot2 folder does not exist. No need to rename."
                }
                start-service $servicesStart
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
                Add-Content -Path $using:updateCleanupLog -Value "[$using:currentDateTime] - INFO:`r`n`t$successMessage"
            } catch {
                $errorMessage = "An error occurred while performing Windows Update Cleanup: `r`n$_"
                Add-Content -Path $using:updateCleanupLog -Value "[$using:currentDateTime] - ERROR:`r`n`t$errorMessage"
                Write-Error $errorMessage
                return 1
            }
        } -Verbose:$VerboseOption
        if($updateCleanupExit -ne 0){
            Write-Error "`r`nAn error occurred while performing Windows Update Cleanup on $ComputerName. Please review the logs.`r`n`tA Restart of the Device is Adviced! Please try again afterwards"
        }
        $ExitCode[7]=$updateCleanupExit
    }



    # Zip CBS.log and DISM.log
    if (-not $noSfc -or -not $noDism) {
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

                # Copy DISM.log to the temporary directory if it exists and the noDism flag is not set
                if (-not $using:noDism) {
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
                Add-Content -Path $using:zipErrorLog -Value "[$using:currentDateTime] - ERROR:`r`n$errorMessage"
                Write-Error $message
                return 1
            }
            return 0
        } -Verbose:$VerboseOption
        $ExitCode[8]=$zipErrorCode
    } else {
        $ExitCode[8]=0
    }


    $extmsg= "`r`nSystem-Repair on $ComputerName successfully performed."
    $extmsglLogP ="`r`nLog-Files can be found on this Machine under '$localTempPath'"
    $extmsgrLogP ="`r`n`tThe Log-Data can be found on the Remote Device on $remoteTempPath"
    # Copy log files to local machine
    if (-not $noCopy){
        if (-not (Test-Path -Path $localTempPath)) {
            New-Item -Path $localTempPath -ItemType Directory -Force
        }
        Copy-Item -Path "\\$ComputerName\C$\_temp\*" -Destination $localTempPath -Recurse -Force

        # Clear remote _temp folder if copy was successful

        if ($?) {
            if(-not $KeepLogs){
                Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    Remove-Item -Path "C:\_temp\*" -Recurse -Force
                } -Verbose:$VerboseOption
                $extmsg+= $extmsglLogP
            } else {
                $extmsg+= $extmsgrLogP
            }
        } else {
            $message = "An error occurred while copying the log files from $ComputerName."
            Write-Error $message
            $extmsg+= $extmsgrLogP+"`r`n[ERROR]`r`t$_"
        }
    } else {
        $extmsg+= $extmsgrLogP
    }
    Start-Sleep -Seconds 2
    Write-Host $extmsg
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

    .PARAMETER noSfc
    When specified, the `SCF /SCANNOW` command is skipped.

    .PARAMETER noDism
    When specified, the `DISM` commands are skipped.

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
    Repair-LocalSystem -noDism

    Runs only the `sfc /scannow` command on the  computer. Outputs are shown on the console and logged to files.

    .EXAMPLE
    Repair-LocalSystem -Quiet

    Runs the `sfc /scannow` and `DISM` commands on the  computer. Outputs are logged to files but not shown on the console.

    .EXAMPLE
    Repair-LocalSystem -IncludeComponentCleanup

    Analyses the Component Store and removes old Data which is not required anymore. Cannot be used with '-noDism'

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


    Exit-Codes:
    Repair-System Module returns an exit code that can be used to determine the success or failure of the script.
    0 if the script was executed successfully. Any other value indicates an error.
    The exit code is a string of 8 digits, each representing the exit code of a specific step in the script.
    The exit codes possitions are as follows:
    Position 0: Startup (Synthax Error)
    Position 1: SFC
    Position 2: DISM Scan Health
    Position 3: Dism Restore Healt
    Position 4: Dism Analyse Component Store
    Position 5: Dism Component Cleanup
    Position 6: Windows Update Cleanup
    Position 7: Zip CBS/DISM Logs

    Except for Position 0, the exit code is the return value of the corresponding command.
    If the command was not executed, the exit code is 0.
    Furthermore only if startup fails, the Repair-System will quit and return the exit code.
    All other errors will not interrupt the script.


    Author: Wolfram Halatschek
    E-Mail: halatschek.wolfram@gmail.com
    Date: 2024-08-24
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position=0)]
        [switch]$noSfc,

        [Parameter(Mandatory = $false, Position=1)]
        [switch]$noDism,

        [Parameter(Mandatory = $false, Position=2)]
        [switch]$Quiet,

        [Parameter(Mandatory = $false, Position=3)]
        [switch]$IncludeComponentCleanup,

        [Parameter(Mandatory = $false, Position=4)]
        [switch]$WindowsUpdateCleanup
    )

    $ExitCode=0,0,0,0,0,0,0,0 #Startup, SFC, DISM Scan, DISM Restore, Analyze Component, Component Cleanup, Windows Update Cleanup, Zip CBS/DISM Logs

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

    if(-not $noSfc){
        # Execute sfc /scannow

        Write-Verbose "executing SFC"
        try{
            if ($Quiet) {
                sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } > $sfcLog 2>&1
            } else {
                sfc /scannow | Where-Object { $_ -notmatch "^[^\x00-\x7F]" } | Tee-Object -FilePath $sfcLog -OutBuffer 1
            }
            $ExitCode[1]=$LASTEXITCODE
            $logContent = Get-Content $sfcLog -Raw
            $logContent = $logContent -replace [char]0
            Set-Content $sfcLog -Value $logContent
        } catch {
            $errorMessage = "An error occurred while performing SFC: `r`n$_"
            Write-Error $errorMessage
            Add-Content -Path $sfcLog -Value $errorMessage
            $ExitCode[1]=1
        }
    }

    if (-not $noDism) {
        # Execute dism /online /Cleanup-Image /Scanhealth
        Write-Verbose "executing DISM/ScanHealth"
        try{
            if ($Quiet) {
                dism /online /Cleanup-Image /Scanhealth > $dismScanLog 2>&1
            } else {
                dism /online /Cleanup-Image /Scanhealth | Tee-Object -FilePath $dismScanLog
            }
            $ExitCode[2]=$LASTEXITCODE
        } catch {
            $errorMessage = "An error occurred while performing DISM ScanHealth: `r`n$_"
            Write-Error $errorMessage
            Add-Content -Path $dismScanLog -Value $errorMessage
            $ExitCode[2]=1
        }

        # Explicitly check the exit code to decide on RestoreHealth
        $message = ""
        if ($ExitCode[2] -eq 0) {
            $ScanResult = 1
            $lines = Get-Content -Path $dismScanLog
            $ScanResultData=$lines[-1..-($lines.Count)]
            foreach ($line in $ScanResultData) {
                if ($line -match 'The component store is repairable.') {
                    break
                } elseif ($line -match 'No component store corruption detected.') {
                    $ScanResult=0
                    break
                }
            }
            if ($ScanResult -eq 1) {
                Write-Verbose "executing DISM/RestoreHealth"
                try{
                    if ($Quiet) {
                        dism /online /Cleanup-Image /RestoreHealth > $dismRestoreLog 2>&1
                    } else {
                        dism /online /Cleanup-Image /RestoreHealth | Tee-Object -FilePath $dismRestoreLog
                    }
                    $ExitCode[3]=$LASTEXITCODE
                } catch {
                    $errorMessage = "An error occurred while performing DISM RestoreHealth: `r`n$_"
                    Write-Error $errorMessage
                    Add-Content -Path $dismRestoreLog -Value $errorMessage
                    $ExitCode[3]=1
                }
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
            Write-Verbose "executing DISM/AnalyzeComponentStore"
            try{
                if ($Quiet) {
                    dism /Online /Cleanup-Image /AnalyzeComponentStore > $analyzeComponentLog 2>&1
                } else {
                    dism /Online /Cleanup-Image /AnalyzeComponentStore | Tee-Object -FilePath $analyzeComponentLog
                }
                $ExitCode[4]=$LASTEXITCODE
            } catch {
                $errorMessage = "An error occurred while performing DISM AnalyzeComponentStore: `r`n$_"
                Write-Error $errorMessage
                Add-Content -Path $analyzeComponentLog -Value $errorMessage
                $ExitCode[4]=1
            }

            $lines = Get-Content -Path $analyzeComponentLog
            $analyzeComponentLogData = $lines[-1..-($lines.Count)]
            $analyzeResult = 0
            foreach ($line in $analyzeComponentLogData) {
                if ($line -match 'Component Store Cleanup Recommended : Yes') {
                    $analyzeResult= 1
                    break
                } elseif ($line -match 'Component Store Cleanup Recommended : No') {
                    $analyzeResult= 0
                    break
                }
            }


            # Check the output and perform cleanup if recommended
            $message = ""
            if ($ExitCode[4] -eq 0 -and $analyzeResult -eq 1) {
                Write-Verbose "executing DISM/StartComponentCleanup"
                try{
                    if ($Quiet) {
                        dism /Online /Cleanup-Image /StartComponentCleanup > $componentCleanupLog 2>&1
                    } else {
                        dism /Online /Cleanup-Image /StartComponentCleanup | Tee-Object -FilePath $componentCleanupLog
                    }
                    $ExitCode[5]=$LASTEXITCODE
                    $message = "Component store cleanup was performed."
                } catch {
                    $errorMessage = "An error occurred while performing Component Store Cleanup: `r`n$_"
                    Write-Error $errorMessage
                    Add-Content -Path $componentCleanupLog -Value $errorMessage
                    $ExitCode[5]=1
                }


            } elseif ($analyzeExit -eq 0 -and $analyzeResult -eq 0) {
                $message = "No Component store cleanup recommended."
            }else { $message = "DISM AnalyzeComponentStore returned an unexpected exit code ($analyzeResult) on $ComputerName. Please review the logs."}
            if($message -ne ""){
                Write-Verbose $message
                Add-Content -Path $componentCleanupLog -Value $message
            }
        }

    }

    if ($WindowsUpdateCleanup) {
        try {
            Write-Host "Starting Windows Update Cleanup..."
            $softwareDistributionPath = "$Env:systemroot\SoftwareDistribution"
            $catroot2Path = "$Env:systemroot\system32\catroot2"
            $softwareDistributionBackupPath = "$softwareDistributionPath.bak"
            $catroot2BackupPath = "$catroot2Path.bak"
            $softDist = $false
            $softDistErr=""
            $cat2= $false
            $cat2Err=""
            stop-service @("wuauserv","bits","appidsvc","cryptsvc","msiserver")
            if (Test-Path -Path $softwareDistributionBackupPath) {
                Write-Verbose "Backup directory exists. Deleting $softwareDistributionBackupPath..."
                Remove-Item -Path $softwareDistributionBackupPath -Recurse -Force
            } else {
                Write-Verbose "Backup directory does not exist. No need to delete."
            }
            if (Test-Path -Path $softwareDistributionPath) {
                try{
                    Rename-Item -Path $softwareDistributionPath -NewName SoftwareDistribution.bak
                    $softDist = $true
                } catch {
                    $softDistErr= "Error renaming SoftwareDistribution folder: `r`n$_"
                    Write-Verbose $softDistErr
                }
            }
            if (Test-Path -Path $catroot2BackupPath) {
                Write-Verbose "Backup directory exists. Deleting $catroot2BackupPath..."
                Remove-Item -Path $catroot2BackupPath -Recurse -Force
            } else {
                Write-Verbose "Backup directory does not exist. No need to delete."
            }
            if (Test-Path -Path $catroot2Path) {
                try{
                    Rename-Item -Path $catroot2Path -NewName catroot2.bak
                    $cat2 = $true
                } catch {
                    $cat2Err= "Error renaming catroot2 folder: `r`n$_"
                    Write-Verbose $cat2Err
                }
            }
            start-service @("bits","wuauserv","appidsvc","cryptsvc","msiserver")
            $successMessage = "Windows Update Cleanup successfully."
            if($softDist){
                $successMessage += "`r`n[SUCCESS]`tSoftwareDistribution folder has been renamed."
            } else {
                $successMessage += "`r`n[STATUS]`tRenaming SoftwareDistribution: folder does not exist or is currently used by another process.`r`n`t`tThis may be because it has been renamed before."
                if($softDistErr -ne ""){$successMessage += "`r`n[ERROR]`t$softDistErr"}
            }
            if($cat2){
                $successMessage += "`r`ncatroot2 folder has been renamed."
            }else {
                $successMessage += "`r`n[STATUS]`tRenaming catroot2: folder does not exist or is currently used by another process.`r`n`t`tThis may be because it has been renamed before."
                if($cat2Err -ne ""){$successMessage += "`r`n[ERROR]`t$cat2Err"}
            }
            Write-Verbose $successMessage
            Add-Content -Path $updateCleanupLog -Value "[$currentDateTime] - INFO:`r`n`t$successMessage"
        } catch {
            $errorMessage = "An error occurred while performing Windows Update Cleanup: `r`n$_"
            Write-Error $errorMessage
            Add-Content -Path $updateCleanupLog -Value "[$currentDateTime] - ERROR:`r`n`t$errorMessage"
            $ExitCode[6]=1
        }
    }


    if (-not $noSfc -or -not $noDism) {
        try {
            $cbsLog = "$env:windir\Logs\CBS\CBS.log"
            $dismLog = "$env:windir\Logs\dism\dism.log"

            $filesToZip = @()

            # Copy CBS.log to the temporary directory if it exists and the noSfc flag is not set
            if (-not $noSfc) {
                if (Test-Path $cbsLog) {
                    Copy-Item -Path $cbsLog -Destination $TempPath
                    $filesToZip += (Join-Path -Path $TempPath -ChildPath "CBS.log")
                }
            }

            # Copy DISM.log to the temporary directory if it exists and the noDism flag is not set
            if (-not $noDism) {
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
            Write-Error $message
            Add-Content -Path $zipErrorLog -Value "[$currentDateTime] - ERROR:`r`n$errorMessage"
            $ExitCode[7]= 1
        }
    }



    # Copy log files to local machine
    if (-not (Test-Path -Path $logPath)) {
        New-Item -Path $logPath -ItemType Directory -Force
    }
    Copy-Item -Path "$TempPath\*" -Destination $logPath -Recurse -Force

    # Clear remote _temp folder if copy was successful
    if ($?) {
        Remove-Item -Path "$TempPath\*" -Recurse -Force
    }

    Start-Sleep -Seconds 2

    Write-Host "`r`nLocal System-Repair successfully performed.`r`nLog-Files can be found on this Machine under '$logPath'"

    $exitCode=$exitCode | Sort-Object {$_} -Descending
    $exitCode = $exitCode -join ""
    $global:LASTEXITCODE = $ExitCode
}


Export-ModuleMember -Function Repair-RemoteSystem, Repair-LocalSystem,Invoke-WinUpdateCleanup

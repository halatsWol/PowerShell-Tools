function New-Folder {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FolderPath
    )
    if (-not (Test-Path -Path $FolderPath)) {New-Item -Path $FolderPath -ItemType Directory -Force > $null}
}

function Start-UserCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$logfile,

        [Parameter(Mandatory=$true, Position=1)]
        [string[]]$userTempFolders,

        [Parameter(Mandatory=$true, Position=2)]
        [string[]]$userReportingDirs,

        [Parameter(Mandatory=$true, Position=3)]
        [string]$explorerCacheDir,

        [Parameter(Mandatory=$true, Position=4)]
        [string]$localIconCacheDB,

        [Parameter(Mandatory=$true, Position=5)]
        [string]$msTeamsCacheFolder,

        [Parameter(Mandatory=$true, Position=6)]
        [string]$teamsClassicPath,

        [Parameter(Mandatory=$true, Position=7)]
        [switch]$IncludeSystemLogs,

        [Parameter(Mandatory=$true, Position=8)]
        [switch]$IncludeIconCache,

        [Parameter(Mandatory=$true, Position=9)]
        [switch]$IncludeMSTeamsCache,

        [Parameter(Mandatory=$true,Position=10)]
        [switch]$VerboseOption,

        [Parameter(Mandatory=$true,Position=11)]
        [string]$VerboseLogFile

    )

    $V = $PSCmdlet.MyInvocation.BoundParameters.Verbose
    if ($V -or $VerboseOption) {
        $VerboseOption = $true
    } else {
        $VerboseOption = $false
    }
    if($VerboseOption) {
        Start-Transcript -Path $VerboseLogFile -Append
    }
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -Exclude "Public","Default","Default User","All Users" | Select-Object -ExpandProperty Name
    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] User Profile cleanup:"
    foreach ($userProfile in $userProfiles) {
        Add-Content -Path $logfile -Value "`tUser Profile: $userProfile"
        try{
            foreach ($folder in $userTempFolders) {
                $path = Join-Path "C:\Users\$userProfile" $folder
                if (Test-Path $path) {
                    Add-Content -Path $logfile -Value "`t`t> $path"
                    Remove-Item -Path "\\?\$path\*" -Verbose:$VerboseOption -Recurse -Force -ErrorAction SilentlyContinue
                }

            }
            if ($IncludeSystemLogs) {
                foreach ($folder in $userReportingDirs) {
                    $path = Join-Path "C:\Users\$userProfile" $folder
                    if (Test-Path $path) {
                        Add-Content -Path $logfile -Value "`t`t> $path"
                        Remove-Item -Path "\\?\$path\*" -Verbose:$VerboseOption -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            if ($IncludeIconCache) {
                $path = Join-Path "C:\Users\$userProfile" $explorerCacheDir
                Add-Content -Path $logfile -Value "`t`tcleaning Icon & ThumbCache:"
                $pathI = "$path\iconcache*.db"
                $pathT = "$path\thumbcache*.db"
                $pathLI = Join-Path "C:\Users\$userProfile" $localIconCacheDB
                if (Test-Path $path) {
                    Add-Content -Path $logfile -Value "`t`t`t> $pathI"
                    Remove-Item -Path "$pathI" -Verbose:$VerboseOption -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t`t> $pathT"
                    Remove-Item -Path "$pathT" -Verbose:$VerboseOption -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t`t> $pathLI"
                    Remove-Item -Path "$pathLI" -Verbose:$VerboseOption -Force -ErrorAction SilentlyContinue
                }
            }
        }catch{
            Write-Warning "Error while cleaning up $userProfile :`r`n $_"
        }

        if($IncludeMSTeamsCache) {
            Get-Process ms-teams -ErrorAction SilentlyContinue | stop-process -Force 
            $path = Join-Path "C:\Users\$userProfile" $msTeamsCacheFolder
            $bgPath="$path\Microsoft\MSTeams"
            $bgBackupPath="$path\.."
            #move $msTeamsCacheFolder\Microsoft\MSTeams\Backgrounds to $msTeamsCacheFolder
            if (Test-Path "$bgPath\Backgrounds") {
                Add-Content -Path $logfile -Value "`t`t> Backing Up MS-Teams Background-Images"
                Move-Item -Path "$bgPath\Backgrounds" -Destination "$bgBackupPath" -Force -ErrorAction SilentlyContinue
            }
            #cleanup $msTeamsCacheFolder
            $cpath = "$path"
            if (Test-Path $cpath) {
                Add-Content -Path $logfile -Value "`t`t> $cpath"
                Remove-Item -Path "$cpath\*" -Verbose:$VerboseOption -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Add-Content -Path $logfile -Value "`t`t> $cpath (not found)"
            }
            #create bgPath
            if (-not (Test-Path $bgPath)) {
                New-Item -Path $bgPath -ItemType Directory -Force -ErrorAction SilentlyContinue
            }
            if(Test-Path "$bgBackupPath\Backgrounds") {
                Add-Content -Path $logfile -Value "`t`t> Recovering MS-Teams Background-Images"
                Move-Item -Path "$bgBackupPath\Backgrounds" -Destination "$bgPath" -Force -ErrorAction SilentlyContinue
            }
            #cleanup $teamsClassicPath
            $path = Join-Path "C:\Users\$userProfile" $teamsClassicPath
            if (Test-Path $path) {
                Add-Content -Path $logfile -Value "`t`t> $path"
                Remove-Item -Path "$path\*" -Verbose:$VerboseOption -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Add-Content -Path $logfile -Value "`t`t> $path (not found)"
            }
        }

    }
    if($VerboseOption) {
        Stop-Transcript
    }
}

function Start-SystemCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$logfile,

        [Parameter(Mandatory=$true,Position=1)]
        [string[]]$systemTempFolders,

        [Parameter(Mandatory=$true,Position=2)]
        [string[]]$sysReportingDirs,

        [Parameter(Mandatory=$true,Position=3)]
        [string]$ccmCachePath,

        [Parameter(Mandatory=$true,Position=4)]
        [switch]$IncludeSystemData,

        [Parameter(Mandatory=$true,Position=5)]
        [switch]$IncludeSystemLogs,

        [Parameter(Mandatory=$true,Position=6)]
        [switch]$IncludeCCMCache,

        [Parameter(Mandatory=$true,Position=7)]
        [switch]$VerboseOption,

        [Parameter(Mandatory=$true,Position=8)]
        [string]$VerboseLogFile

    )

    $V = $PSCmdlet.MyInvocation.BoundParameters.Verbose
    if ($V -or $VerboseOption) {
        $VerboseOption = $true
    } else {
        $VerboseOption = $false
    }
    if($VerboseOption) {
        Start-Transcript -Path $VerboseLogFile -Append
    }
    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] System cleanup:"

    if($IncludeSystemData) {
        foreach ($folder in $systemTempFolders) {
            if (Test-Path $folder) {
                Add-Content -Path $logfile -Value "`t`t> $folder"
                Remove-Item -Path "\\?\$folder\*" -Verbose:$VerboseOption -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Add-Content -Path $logfile -Value "`t`t> $path (not found)"
            }
        }
        Start-Sleep -Milliseconds 100
    }

    if($IncludeSystemLogs) {
        foreach ($folder in $sysReportingDirs) {
            if (Test-Path $folder) {
                Add-Content -Path $logfile -Value "`t`t> $folder"
                Remove-Item -Path "\\?\$folder\*" -Verbose:$VerboseOption -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Add-Content -Path $logfile -Value "`t`t> $path (not found)"
            }
        }
        Start-Sleep -Milliseconds 100
    }



    if($IncludeCCMCache) {
        if (Test-Path $ccmCachePath) {
            Add-Content -Path $logfile -Value "`t`t> $ccmCachePath"
            Remove-Item -Path "\\?\$ccmCachePath\*" -Verbose:$VerboseOption -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Add-Content -Path $logfile -Value "`t`t> $path (not found)"
        }
        Start-Sleep -Milliseconds 100
    }

    if($VerboseOption) {
        Stop-Transcript
    }
}

function Start-CleanMgr{
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$logfile,

        [Parameter(Mandatory=$true,Position=1)]
        [switch]$LowDisk,

        [Parameter(Mandatory=$true,Position=2)]
        [switch]$VeryLowDisk,

        [Parameter(Mandatory=$true,Position=3)]
        [switch]$ConfirmWarning,

        [Parameter(Mandatory=$true,Position=4)]
        [switch]$AutoClean
    )

    if ($VeryLowDisk -and -not $ConfirmWarning) {
        $confirmation = Read-Host "VeryLowDisk cleanup is selected. This will clean up the system including critical recovery-Files and remove all files in the Recycle Bin. (Selecting N will revert to -LowDisk)`r`nDo you want to continue? ([Y]es/[N]o/exit)"
        $validVal=$false
        while(-not $validVal) {
            $confirmation = $confirmation.ToLower()
            switch ($confirmation) {
                "y" {
                    $VeryLowDisk = $true
                    $validVal=$true
                    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] - VeryLowDisk Warning confirmed"
                }
                "n" {
                    $VeryLowDisk = $false
                    $LowDisk = $true
                    $validVal=$true
                    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] - VeryLowDisk Warning declined, reverting to LowDisk"
                }
                "exit" {
                    Write-Host "Exiting script."
                    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] - VeryLowDisk Warning declined with 'Exit', exiting script"
                    $global:LASTEXITCODE = 1
                    return
                }
                Default { $confirmation = Read-Host "`r`nInvalid input. Repeat the confirmation.`r`nDo you want to continue? ([Y]es/[N]o/exit)" }
            }
        }
    }



    if($LowDisk -or $VeryLowDisk){
        $options = @(
            "Active Setup Temp Folders"
            "D3D Shader Cache",
            "Delivery Optimization Files",
            "Diagnostic Data Viewer database files",
            "Downloaded Program Files",
            "Feedback Hub Archive log files",
            "Internet Cache Files",
            "Temporary Files",
            "Temporary Setup Files",
            "Thumbnail Cache",
            "Offline Pages Files",
            "System error memory dump files",
            "System error minidump files",
            "Old ChkDsk Files",
            "Windows Error Reporting Files"
        )

        $CleanMaxDurationVal=10
        if ($VeryLowDisk) {
            $options += @(
                "Update Cleanup",
                "Device Driver Packages",
                "Windows Defender",
                "Upgrade Discarded Files",
                "Windows ESD installation files",
                "Windows Reset Log Files",
                "Windows Upgrade Log Files",
                "Recycle Bin"
            )
            $CleanMaxDurationVal=20
        }

        $softwareDistributionPath = "C:\Windows\SoftwareDistribution"
        $catroot2Path = "C:\Windows\system32\catroot2"
        $softwareDistributionBackupPath = "$softwareDistributionPath.bak"
        $catroot2BackupPath = "$catroot2Path.bak"
        $softwareDistributionBackupPath2 = "$softwareDistributionPath.old"
        $catroot2BackupPath2 = "$catroot2Path.old"

        if ($VeryLowDisk) {
            Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Cleaning Recycle Bin"
            Remove-Item -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue
            Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Cleaning SoftwareDistribution and Catroot2 Backup folders"
            if (Test-Path $softwareDistributionBackupPath) {
                Add-Content -Path $logfile -Value "`t`t> $softwareDistributionBackupPath"
                Remove-Item -Path "\\?\$softwareDistributionBackupPath" -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $catroot2BackupPath) {
                Add-Content -Path $logfile -Value "`t`t> $catroot2BackupPath"
                Remove-Item -Path "\\?\$catroot2BackupPath" -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $softwareDistributionBackupPath2) {
                Add-Content -Path $logfile -Value "`t`t> $softwareDistributionBackupPath2"
                Remove-Item -Path "\\?\$softwareDistributionBackupPath2" -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $catroot2BackupPath2) {
                Add-Content -Path $logfile -Value "`t`t> $catroot2BackupPath2"
                Remove-Item -Path "\\?\$catroot2BackupPath2" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Starting CleanMgr Cleanup"
        Add-Content -Path $logfile -Value "`t`t> Enabling the following Cleanup options."
        foreach ($option in $options) {
            Add-Content -Path $logfile -Value "`t`t> $option"
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$option" -Name StateFlags0901 -Value 2 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        }

        $CleanMaxDuration = New-TimeSpan -Minutes $CleanMaxDurationVal
        Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Executing CleanMgr"
        Write-Host "Starting CleanMgr.exe,`r`nThis may take a while... (up to $($CleanMaxDuration.TotalMinutes) minutes)"
        # Start CleanMgr.exe with arguments and get the process object
        $process = Start-Process -FilePath "CleanMgr.exe" -ArgumentList '/sagerun:901' -PassThru
        $CleanMgrStartTime = Get-Date

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $CleanMgrStartTime
            if ($elapsed -gt $CleanMaxDuration) {
                $cleanMgrStucknotify = "CleanMgr.exe has been running for more than $($CleanMaxDuration.TotalMinutes) minutes. Stopping it..."
                Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStucknotify"
                Write-Warning $cleanMgrStucknotify
                try {
                    $process.Kill()
                    $cleanMgrStuckTerminate = "CleanMgr.exe terminated."
                    Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStuckTerminate"
                    Write-Warning $cleanMgrStuckTerminate
                } catch {
                    $cleanMgrStuckTerminateFail = "Failed to terminate CleanMgr.exe: $_"
                    Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStuckTerminateFail"
                    Write-Warning $cleanMgrStuckTerminateFail
                }
                break
            }
        }
        Get-Process -Name cleanmgr,dismhost -ErrorAction SilentlyContinue | Wait-Process
        Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] CleanMgr Complete"
        Add-Content -Path $logfile -Value "`t`t> removing CleanMgr Automation-Settings"
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags0901 -ErrorAction SilentlyContinue | Remove-ItemProperty -Name StateFlags0901 -ErrorAction SilentlyContinue | Out-Null

    }

    if($AutoClean -or $VeryLowDisk){
        Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Starting CleanMgr Upgrade-Cleanup"
        $CleanMaxDurationVal = 5
        $CleanMaxDuration = New-TimeSpan -Minutes $CleanMaxDurationVal
        Write-Host "Starting CleanMgr Upgrade-Cleanup,`r`nThis may take a while... (up to $($CleanMaxDuration.TotalMinutes) minutes)"
        Start-Process -FilePath "C:\Windows\System32\cleanmgr.exe" -ArgumentList "/autoclean" -NoNewWindow -Wait -PassThru | Out-Null

        $CleanMgrStartTime = Get-Date
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 10

            $elapsed = (Get-Date) - $CleanMgrStartTime
            if ($elapsed -gt $CleanMaxDuration) {
                $cleanMgrStucknotify = "CleanMgr.exe has been running for more than $($CleanMaxDuration.TotalMinutes) minutes. Stopping it..."
                Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStucknotify"
                Write-Warning $cleanMgrStucknotify
                try {
                    $process.Kill()
                    $cleanMgrStuckTerminate = "CleanMgr.exe terminated."
                    Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStuckTerminate"
                    Write-Warning $cleanMgrStuckTerminate
                } catch {
                    $cleanMgrStuckTerminateFail = "Failed to terminate CleanMgr.exe: $_"
                    Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStuckTerminateFail"
                    Write-Warning $cleanMgrStuckTerminateFail
                }
                break
            }
        }
    }
}


function Invoke-TempDataCleanup {
    <#
    .SYNOPSIS
    Clean up temporary files from user profiles and system folders

    .DESCRIPTION
    This function will clean up temporary files from user profiles and system folders. It can be run on the local computer or on a remote computer.

    .PARAMETER ComputerName
    The name of the computer to run the cleanup on. Use "localhost" for the local computer.
    Accepts multiple computer names as an array. Accepts pipeline input.
    If no computer name is provided, it defaults to "localhost".

    .PARAMETER IncludeSystemData
    If this switch is present, the cleanup will also include system folders.

    .PARAMETER IncludeSystemLogs
    If this switch is present, the cleanup will also include system log files like C:\Windows\Logs\,  C:\Windows\Minidmp\.

    .PARAMETER IncludeCCMCache
    If this switch is present, the cleanup will also include the Configuration Manager cache folder, if it exists.

    .PARAMETER IncludeBrowserData
    If this switch is present, the cleanup will also include browser cache folders.

    .PARAMETER IncludeMSTeamsCache
    If this switch is present, the cleanup will also include Microsoft Teams cache folders.

    .PARAMETER IncludeIconCache
    If this switch is present, the cleanup will also include the User Icon & ThumbCache files.

    .PARAMETER IncludeAllPackages
    If this switch is present, the cleanup will also include the LocalCache folders of all packages in $env:localappdata\Packages.
    This will render IncludeMSTeamsCache irrelevant.

    USE WITH CAUTION! This will Clean Up all LocalCache folders of all packages in $env:localappdata\Packages.

    .PARAMETER LowDisk
    This Switch will Use the CleanMgr to clean up the system. This can be used with all other Switches.
    Please keep in mind that this may take a while to complete.
    Using this Switch will also set the following switches:
    -IncludeSystemData, -IncludeCCMCache, -IncludeIconCache

    Following CleanMgr Settings will be set:
    - D3D Shader Cache
    - Delivery Optimization Files
    - Downloaded Program Files
    - Internet Cache Files
    - Temporary Files
    - Temporary Setup Files
    - Thumbnail Cache
    - Feedback Hub Archive log files
    - Offline Pages Files
    - System error memory dump files
    - System error minidump files
    - Old ChkDsk Files
    - Windows Error Reporting Files


    .PARAMETER VeryLowDisk
    This Switch will Use the CleanMgr to clean up the system . This can be used with all other Switches.
    Please keep in mind that this may take a while to complete.
    Confirmation is required before proceeding with the cleanup (can be bypassed using -ConfirmWarning).
    If the Prompt is denied, the cleanup will fall back to -LowDisk
    Using this Switch will also set the following switches:
    -IncludeSystemData, -IncludeCCMCache, -IncludeIconCache

    This will use the same CleanMgr Settings as -LowDisk, but will also set the following settings:
    - Update Cleanup
    - Device Driver Packages
    - Windows Defender
    - Upgrade Discarded Files
    - Windows ESD installation files
    - Windows Reset Log Files
    - Windows Upgrade Log Files

    Additionally the Recycle Bin will be cleaned up, as well as the SoftwareDistribution and Catroot2 Backup (*.old / *.bak) folders.

    This will also perform -AutoClean

    .PARAMETER ConfirmWarning
    Using this switch will bypass the confirmation prompt of -VeryLowDisk and proceed with the cleanup.

    .PARAMETER AutoClean
    Automatically deletes the files that are left behind after you upgrade Windows. This can be used with all other Switches.
    Using this Switch will also set the following switches:
    -IncludeSystemData, -IncludeCCMCache, -IncludeIconCache

    .PARAMETER init
    When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
    When specified, no other Parameter will be executed (other provided Parameters will be ignored). This will retun 0 if the Config-File was created successfully, or already exists.

    Configuration-File Template:
    ```
    ShareDrive=C$                               # ShareDrive-Letter of the Remote-Device on which Windows is installed
    TempFolder=_IT-temp                         # Name of the temporary Directory on the Remote-Device
    LocalTargetPath=C:\remote-Files             # Path where the Logs and Files will be copied to on the executing Client
    ```


    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01"

    This will clean up temporary files from user profiles on Computer01.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData

    This will clean up temporary files from user profiles and system folders on Computer01.

    .EXAMPLE
    $DeviceList | Invoke-TempDataCleanup -IncludeSystemData

    This will clean up temporary files from user profiles and system folders on all computers in the $DeviceList array.
    ("" and $Null will not default to "localhost" and are skipped if list is longer than 1).

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName dev01,dev02,dev03,""

    This will clean up temporary files from user profiles on dev01, dev02, dev03 and the local computer ("").

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "localhost" -IncludeSystemData -IncludeBrowserData

    This will clean up temporary files including Browser-Cache Data from user profiles and system folders on the local computer.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData -IncludeBrowserData -IncludeMSTeamsCache

    This will clean up temporary files including Browser-Cache Data and Microsoft Teams cache from user profiles and system folders on Computer01.

    .NOTES
    This script is provided as-is and is not supported by Microsoft. Use it at your own risk.
    WinRM must be enabled and configured on the remote computer for this script to work. Using IP addresses may require additional configuration.
    Using this script may require administrative privileges on the remote computer.
    In a Domain, powershell can be executed locally as the user wich has the necessary permissions on the remote computer.


    Further information:
    https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-5.1




    WARNING:
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT PERMISSION OR AUTHORIZATION.
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT UNDERSTANDING THE CONSEQUENCES.
    NEVER RUN SCRIPTS FROM UNTRUSTED SOURCES WITHOUT REVIEWING AND UNDERSTANDING THE CODE.
    DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING. IT MAY CAUSE DATA LOSS OR SYSTEM INSTABILITY.


    Author: Wolfram Halatschek
    E-Mail: wolfram@kMarflow.com
    Date: 2025-06-03
    #>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeSystemData,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeSystemLogs,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeCCMCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeBrowserData,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeMSTeamsCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeIconCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeAllPackages,

        [Parameter(Mandatory=$false)]
        [switch]$init,

        [Parameter(Mandatory=$false)]
        [switch]$LowDisk,

        [Parameter(Mandatory=$false)]
        [switch]$VeryLowDisk,

        [Parameter(Mandatory=$false)]
        [switch]$ConfirmWarning,

        [Parameter(Mandatory=$false)]
        [switch]$AutoClean

    )
    begin {
        $computerList = @()
    }
    process {
        if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
            $computerList += $ComputerName
        }
    }
    end {
        if ($computerList.Count -eq 0) {
            $computerList = @("localhost")
        }

        # check if verbose is enabled
        $VerboseOption = $PSCmdlet.MyInvocation.BoundParameters.Verbose

        $initFree_bytes=""
        $exitFree_bytes=""

        $confFile="$PSScriptRoot\TempDataCleanup.conf"
        if($init){
            $ShareDrive="C$"
            $TempFolder="_IT-temp"
            $LocalTargetPath="C:\remote-Files"

            if(-not (Test-Path $confFile)){
                try {
                    New-Item -Path $confFile -ItemType File -Force
                    Add-Content -Path $confFile -Value "ShareDrive=$ShareDrive"
                    Add-Content -Path $confFile -Value "TempFolder=$TempFolder"
                    Add-Content -Path $confFile -Value "LocalTargetPath=$LocalTargetPath"
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

        $userTempFolders=@(
            "\AppData\Local\Temp",
            "\AppData\Local\Microsoft\Office\16.0\OfficeFileCache",
            "\AppData\Local\Microsoft\Office\15.0\Lync\Tracing",
            "\AppData\Local\Microsoft\Office\16.0\Lync\Tracing",
            "\AppData\Local\Microsoft\EdgeWebView\Cache",
            "\AppData\LocalLow\Sun\Java\Deployment\cache"
        )
        $commonUserPackages=@(
            "\AppData\Local\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.WindowsCamera_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.DiagnosticDataViewer_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe\TempState",
            "\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TempState"
        )
        $allPackagesCacheFolder="\AppData\Local\Packages\*\LocalCache"
        $BrowserData=@(
            # general
            "\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData",
            # Microsoft Internet Explorer
            "\AppData\Local\Microsoft\Windows\INetCache",
            "\AppData\Local\Microsoft\Windows\INetCookies",
            # Microsoft Edge (Chromium)
            "\AppData\Local\Microsoft\Edge\User Data\*\Temp",
            "\AppData\Local\Microsoft\Edge\User Data\*\Cache",
            "\AppData\Local\Microsoft\Edge\User Data\*\Media Cache",
            "\AppData\Local\Microsoft\Edge\User Data\*\Code Cache",
            "\AppData\Local\Microsoft\Edge\User Data\*\GPUCache",
            "\AppData\Local\Microsoft\Edge\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\Microsoft\Edge\User Data\*\Service Worker\ScriptCache",
            # Mozilla Firefox
            "\AppData\Local\Mozilla\Firefox\Profiles\*\cache2",
            "\AppData\Local\Mozilla\Firefox\Profiles\*\storage\default",
            # Google Chrome
            "\AppData\Local\Google\Chrome\User Data\*\Temp",
            "\AppData\Local\Google\Chrome\User Data\*\Cache",
            "\AppData\Local\Google\Chrome\User Data\*\Media Cache",
            "\AppData\Local\Google\Chrome\User Data\*\Code Cache",
            "\AppData\Local\Google\Chrome\User Data\*\GPUCache",
            "\AppData\Local\Google\Chrome\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\Google\Chrome\User Data\*\Service Worker\ScriptCache"
            # Opera
            "\AppData\Local\Opera Software\Opera Stable\Temp",
            "\AppData\Local\Opera Software\Opera Stable\Cache",
            "\AppData\Local\Opera Software\Opera Stable\Media Cache",
            "\AppData\Local\Opera Software\Opera Stable\Code Cache",
            "\AppData\Local\Opera Software\Opera Stable\GPUCache",
            "\AppData\Local\Opera Software\Opera Stable\Service Worker\CacheStorage",
            "\AppData\Local\Opera Software\Opera Stable\Service Worker\ScriptCache",
            # Vivaldi
            "\AppData\Local\Vivaldi\User Data\*\Temp",
            "\AppData\Local\Vivaldi\User Data\*\Cache",
            "\AppData\Local\Vivaldi\User Data\*\Media Cache",
            "\AppData\Local\Vivaldi\User Data\*\Code Cache",
            "\AppData\Local\Vivaldi\User Data\*\GPUCache",
            "\AppData\Local\Vivaldi\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\Vivaldi\User Data\*\Service Worker\ScriptCache"
            # Brave
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Temp",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Cache",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Media Cache",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Code Cache",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\GPUCache",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Service Worker\ScriptCache"
        )

        $explorerCacheDir="\AppData\Local\Microsoft\Windows\Explorer"
        $localIconCacheDB="\AppData\Local\IconCache.db"


        $systemTempFolders=@(
            "C:\Windows\Temp",
            "C:\Windows\Prefetch",
            "C:\Windows\SoftwareDistribution\Download"
        )
        $msTeamsCacheFolder="\AppData\local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache"
        $teamsClassicPath="\AppData\Roaming\Microsoft\Teams"
        $ccmCachePath="C:\Windows\ccmcache"

        $userReportingDirs=@(
            "\AppData\Local\CrashDumps",
            "\Appdata\Local\D3DSCache",
            "\AppData\Local\Microsoft\Windows\WER\ReportQueue",
            "\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
        )

        $sysReportingDirs=@(
            "C:\Windows\Logs",
            "C:\Windows\Minidump",
            "C:\Windows\LiveKernelReports",
            "C:\Windows\System32\LogFiles\WMI",
            "C:\Windows\System32\LogFiles\setupcln",
            "C:\Windows\ServiceProfiles\LocalService\AppData\Local\CrashDumps",
            "C:\Windows\sysWOW64\config\systemprofile\AppData\Local\CrashDumps",
            "C:\Windows\system32\config\systemprofile\AppData\Local\CrashDumps",
            "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache",
            "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
            "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
        )

        $LocalTargetPath = "C:\remote-Files"
        $TempFolder="_IT-temp"
        $ShareDrive="C$"

        if(Test-Path $confFile){
            $confData = Get-Content -Path $confFile
            foreach ($line in $confData) {
                $key, $value = $line -split '=', 2
                if ($key -eq "ShareDrive") {$ShareDrive=$value}
                elseif ($key -eq "TempFolder") {$TempFolder=$value}
                elseif ($key -eq "LocalTargetPath") {$LocalTargetPath=$value}
                else {
                    Write-Warning "Unknown Key in Config-File: $key"
                    $global:LASTEXITCODE = 1
                    return
                }
            }

        }


        if($LowDisk -or $VeryLowDisk){
            $IncludeSystemData=$true
            $IncludeCCMCache=$true
            $IncludeIconCache=$true
        }

        if($IncludeAllPackages){
            $confirmation=Read-Host "Are you sure you want to include ALL Packages in the cleanup?`r`nThis will render IncludeMSTeamsCache irrelevant. Do you want to continue?`r`n(enter [yes] to continue with this option)"
            if($confirmation -ne "yes"){
                $IncludeAllPackages=$false
                Write-Host "Cleanup will not use IncludeAllPackages"
            }
            else{
                $IncludeMSTeamsCache=$false
                Write-Host "Cleanup will use IncludeAllPackages"
            }
        }

        if ($IncludeAllPackages){$userTempFolders=$userTempFolders+$allPackagesCacheFolder}else{$userTempFolders=$userTempFolders+$commonUserPackages}
        if ($IncludeBrowserData){$userTempFolders=$userTempFolders+$BrowserData}


        foreach ( $comp in $computerList ){



            $remote=$false
            $LocalTargetPath = "$LocalTargetPath\$comp"

            $logdir="C:\$TempFolder"
            $logfile="$logdir\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_TempDataCleanup.log"
            $VerboseLogFile="$logdir\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_TempDataCleanup_Verbose.log"

            if (
                    -not [string]::IsNullOrWhiteSpace($comp) -and
                    $comp.ToLower() -ne "localhost" -and
                    $comp.ToUpper() -ne $env:COMPUTERNAME.ToUpper()
                ) {
                $remote=$true
            } else {
                $comp = "localhost"
            }
            if ($remote){
                if (-not (Test-Connection -ComputerName $comp -Count 1 -Quiet)){
                    Write-Host ""
                    Write-Warning "Computer $comp is not reachable`r`n"
                    Write-Host "`r`n-------------------------------"
                    continue
                }

                $initFree_bytes = Invoke-Command -ComputerName $comp -ScriptBlock {
                    (Get-Volume -DriveLetter C).SizeRemaining
                }
                Invoke-Command -ComputerName $comp -ScriptBlock ${function:New-Folder} -ArgumentList $logdir
                Invoke-Command -ComputerName $comp -ScriptBlock {
                    param($logfile, $comp)
                    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Starting Cleanup on $comp"
                } -ArgumentList $logfile, $comp
            } else {
                $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                $isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if ( -not $isElevated ) {
                    $("") ; Write-Warning "`r`nThis script must be run with administrative privileges. Please restart the script in an elevated PowerShell session.`r`n"
                    Pause ; $("")
                    $global:LASTEXITCODE=1
                    return
                }
                $initFree_bytes = (Get-Volume -DriveLetter C).SizeRemaining
                New-Folder -FolderPath $logdir
                Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Starting Cleanup on $comp"
            }

            Write-Host "`r`nCleaning up  $comp`r`n"

            Write-Host "Cleaning up User Data and Cache"
            if ($remote) {
                Invoke-Command -ComputerName $comp -ScriptBlock ${function:Start-UserCleanup} -ArgumentList $logfile, $userTempFolders, $userReportingDirs, $explorerCacheDir, $localIconCacheDB, $msTeamsCacheFolder, $teamsClassicPath, $IncludeSystemLogs, $IncludeIconCache, $IncludeMSTeamsCache, $VerboseOption, $VerboseLogFile
            } else {
                Start-UserCleanup -logfile $logfile -userTempFolders $userTempFolders -userReportingDirs $userReportingDirs -explorerCacheDir $explorerCacheDir -localIconCacheDB $localIconCacheDB -msTeamsCacheFolder $msTeamsCacheFolder -teamsClassicPath $teamsClassicPath -IncludeSystemLogs:$IncludeSystemLogs -IncludeIconCache:$IncludeIconCache -IncludeMSTeamsCache:$IncludeMSTeamsCache -VerboseOption:$VerboseOption -VerboseLogFile $VerboseLogFile
            }


            if( $IncludeSystemData -or $IncludeSystemLogs -or $IncludeCCMCache) {
                Write-Host "Cleaning up System Data and Cache"
                if ($remote) {
                    Invoke-Command -ComputerName $comp -ScriptBlock ${function:Start-SystemCleanup} -ArgumentList $logfile, $systemTempFolders, $sysReportingDirs, $ccmCachePath, $IncludeSystemData, $IncludeSystemLogs, $IncludeCCMCache, $VerboseOption, $VerboseLogFile
                } else {
                    Start-SystemCleanup -logfile $logfile -systemTempFolders $systemTempFolders -sysReportingDirs $sysReportingDirs -ccmCachePath $ccmCachePath -IncludeSystemData:$IncludeSystemData -IncludeSystemLogs:$IncludeSystemLogs -IncludeCCMCache:$IncludeCCMCache -VerboseOption:$VerboseOption -VerboseLogFile:$VerboseLogFile
                }
            }

            if($LowDisk -or $VeryLowDisk -or $AutoClean){
                if ($remote) {
                    Invoke-Command -ComputerName $comp -ScriptBlock ${function:Start-CleanMgr} -ArgumentList $logfile, $LowDisk, $VeryLowDisk, $ConfirmWarning, $AutoClean
                } else {
                    Start-CleanMgr -logfile $logfile -LowDisk:$LowDisk -VeryLowDisk:$VeryLowDisk -ConfirmWarning:$ConfirmWarning -AutoClean:$AutoClean
                }
            }



            if ($remote) {
                $RemoteLogDir="\\$comp\$ShareDrive\$TempFolder"
                New-Folder -FolderPath $localTargetPath
                Copy-Item -Path "$RemoteLogDir\*" -Destination $localTargetPath -Recurse -Force
                if ($?) {

                    Invoke-Command -ComputerName $comp -ScriptBlock {
                        Remove-Item -Path "$using:logdir" -Recurse
                    } -Verbose:$VerboseOption

                } else {
                    Write-Error "An error occurred while copying the log files from $comp."
                }
            }

            if ($remote){
                $exitFree_bytes = Invoke-Command -ComputerName $comp -ScriptBlock {
                    (Get-Volume -DriveLetter C).SizeRemaining
                }
            } else {
                $exitFree_bytes = (Get-Volume -DriveLetter C).SizeRemaining
            }

            $additionalFree = "{0:N2}" -f (($exitFree_bytes - $initFree_bytes)/1GB)
            Write-Host "`r`nAdditional Free Space: $additionalFree GB`r`nTotal Free Space: $("{0:N2}" -f ($exitFree_bytes/1GB)) GB`r`n"
            Write-Host "-------------------------------"
        }
        Write-Host "`r`nCleanUp Complete" -ForegroundColor Green
        Write-Host "Please Restart the Computer to finalize the Cleanup!" -ForegroundColor Yellow
    }
}

Export-ModuleMember -Function Invoke-TempDataCleanup

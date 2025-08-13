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

$MainLogPath = "C:\_ADSK_CleanUninstall\"
$MsiLogPath = "C:\_ADSK_CleanUninstall\MSILogs\"
if (-not (Test-Path $MainLogPath)) {
    New-Item -ItemType Directory -Path $MainLogPath -Force | Out-Null
}
if (-not (Test-Path $MsiLogPath)) {
    New-Item -ItemType Directory -Path $MsiLogPath -Force | Out-Null
}
$MainLogPathFileName="ADSK_CleanUninstall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
$MainLogFile = Join-Path -Path $MainLogPath -ChildPath $MainLogPathFileName

function Write-Log {
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

    # Auto-detect Source if not provided
    $line = $MyInvocation.ScriptLineNumber
    $scriptName = Split-Path -Path $MyInvocation.ScriptName -Leaf

    if ([string]::IsNullOrWhiteSpace($scriptName)) {
        $scriptName = "Interactive"
    }
    $forwarder=$Source
    $Source = "${scriptName}:${line}"
    if ([string]::IsNullOrWhiteSpace($forwarder)) {
        $Source = $Source
    } else {
        $Source = "$Source($forwarder)"
    }


    # Setup time values
    $timestamp = if ($Time) { $Time } else { Get-Date }
    $dateStr = $timestamp.ToString("MM-dd-yyyy")
    $timeStr = $timestamp.ToString("HH:mm:ss.fff")
    $tzOffset = (Get-TimeZone).BaseUtcOffset.TotalMinutes
    $tzFormatted = if ($tzOffset -ge 0) { "+{0:000}" -f $tzOffset } else { "-{0:000}" -f [math]::Abs($tzOffset) }
    $threadId = [System.Diagnostics.Process]::GetCurrentProcess().Id

    $statePath = "$LogPath.state"
    $logDir = [System.IO.Path]::GetDirectoryName($LogPath)
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    function Close-UnclosedLog {
        if (Test-Path $statePath) {
            $state = Get-Content $statePath -Raw | ConvertFrom-Json
            Remove-Item $statePath -Force

            $autocloseTime = [datetime]::Parse($state.Time)
            $dateAuto = $autocloseTime.ToString("MM-dd-yyyy")

            $timeAuto = $autocloseTime.ToString("HH:mm:ss.fff")
            $tzAuto = if ($tzOffset -ge 0) { "+{0:000}" -f $tzOffset } else { "-{0:000}" -f [math]::Abs($tzOffset) }
            $autoClose = "]LOG]!><time=""$timeAuto$tzAuto"" date=""$dateAuto"" component=""$($state.Component)"" context=""autoClosedLogEntryByFollowingLog"" type=""1"" thread=""$threadId"" file=""$Source"">"
            Add-Content -Path $state.LogPath -Value $autoClose
        }
    }

    if ($StartLogEntry -and $EndLogEntry) {
        Close-UnclosedLog
        $line = "<![LOG[$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""1"" thread=""$threadId"" file=""$Source"">"
        Add-Content -Path $LogPath -Value $line
        return
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Start' {
            Close-UnclosedLog
			if ($null -eq $message) {$Message="LogEntry:"}
            $line = "<![LOG[$Message"
            Add-Content -Path $LogPath -Value $line

            $state = @{
                Component = $Component
                Source    = $Source
                LogPath   = $LogPath
                Time      = $timestamp.ToString("o")
            }
            $state | ConvertTo-Json -Compress | Out-File -FilePath $statePath -Encoding UTF8 -Force
        }

        'Add' {
            if ($Message) {
                Add-Content -Path $LogPath -Value $Message
            }
        }

        'End' {
            if ($null -eq $Message ) { $Message = "LogEntry End" }
            if (-not $StartLogEntry -and (Test-Path $statePath)) {
                $state = Get-Content $statePath -Raw | ConvertFrom-Json
                Remove-Item $statePath -Force

                $line = "$message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$($state.Component)"" context="""" type=""1"" thread=""$threadId"" file=""$($state.Source)"">"
                Add-Content -Path $state.LogPath -Value $line
            }
            else {
                $line = "$message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""1"" thread=""$threadId"" file=""$Source"">"
                Add-Content -Path $LogPath -Value $line
                if (Test-Path $statePath) { Remove-Item $statePath -Force }
            }
        }



        default {
            Close-UnclosedLog
            $line = "<![LOG[$Message]LOG]!><time=""$timeStr$tzFormatted"" date=""$dateStr"" component=""$Component"" context="""" type=""1"" thread=""$threadId"" file=""$Source"">"
            Add-Content -Path $LogPath -Value $line
        }
    }
}



$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ( -not $isElevated ) {
    Write-Log -Message "Script must be run with administrative privileges." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    $("") ; Write-Warning "`r`nThis script must be run with administrative privileges. Please restart the script in an elevated PowerShell session.`r`n"
    Pause ; $("")
    Write-Log -Message "Exiting Uninstall-Script with Exit Code 1" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
} else {
    Write-Log -Message "Starting AutoDeskCleanRemove.ps1;" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile -StartLogEntry
    Write-Log -Message "Script Version: 2.0;" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile -AddLogEntryData
    Write-Log -Message "Author: Halatschek Wolfram;`r`nScript-Source: 'https://github.com/halatsWol/PowerShell-Tools/blob/main/scripts/AutoDeskCleanRemove.ps1';" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile -EndLogEntry
    Write-Log -Message "Script started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile -StartLogEntry
    Write-Log -Message "Hostname: $($env:COMPUTERNAME);" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile -AddLogEntryData
    Write-Log -Message "User: $($env:USERNAME);" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile -EndLogEntry
    Write-Host "`r`nThis script will remove all Autodesk products from your system."
    Write-Host "Please ensure that you have closed all Autodesk applications before proceeding."
    Write-Host "This script has not been tested with Fusion 360. If you have Fusion 360 installed, please uninstall it manually before running this script."
    Write-Warning "Please note that this may prompt OneDrive regarding the deletion of files. This is to be expected.`r`nMultiple Windows may appear, please do not close them manually.`r`nThe script will close them automatically after the uninstallation process."
    Pause
    Write-Host "`r`n`r`nStarting Autodesk Clean Uninstall...`r`nThis may take a while, please be patient...`r`n"
    # Stop all Autodesk Services
    Write-Log -Message "Stopping all Autodesk processes:" -StartLogEntry -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    $AdskProcesses = Get-Process | Where-Object { $_.Description -match "Autodesk" -or $_.Description -match "ADSK" -or $_.Description -match "AutoCAD" -or $_.Description -match "Inventor" -or $_.ProcessName -match "cer_service" -or $_.ProcessName -match "Autodesk" -or $_.ProcessName -match "ADSK" -or $_.ProcessName -match "AutoCAD" -or $_.ProcessName -match "Inventor" }
    if ($AdskProcesses.Count -eq 0) {
        Write-Log -Message "`r`nNo Autodesk processes found." -EndLogEntry -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    } else {
        $ProcessInfo = $AdskProcesses | Select-Object Name, Id | ConvertTo-Json -Depth 2
        Write-Log -Message "Found Autodesk processes:`r`n{$ProcessInfo}" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        try{ $AdskProcesses | Stop-Process -Force -ErrorAction SilentlyContinue } catch {
            Write-Log -Message "[ERROR]Failed to stop Autodesk processes: $($_.Exception.Message)" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            Write-Warning "Failed to stop some Autodesk processes. This may require a second run of the Script after a reboot."
        }
        Write-Log -Message "Autodesk processes have been stopped." -EndLogEntry -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    Write-Log -Message "Stopping all Autodesk services:" -StartLogEntry -Component "AutoDeskCleanRemove" -LogPath $MainLogFile

    $AdskServices = Get-Service | Where-Object { $_.DisplayName -match "Autodesk" -or $_.DisplayName -match "ADSK"  } | Stop-Service -Force -ErrorAction SilentlyContinue
    if ($AdskServices.Count -eq 0) {
        Write-Log -Message "`r`nNo Autodesk services found." -EndLogEntry -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    } else {
        $ServiceInfo = $AdskServices | Select-Object DisplayName, Name | ConvertTo-Json -Depth 2
        Write-Log -Message "Found Autodesk services:`r`n{$ServiceInfo}" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        try{ $AdskServices | Stop-Service -Force -ErrorAction SilentlyContinue } catch {
            Write-Log -Message "[ERROR] Failed to stop Autodesk services: $($_.Exception.Message)" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            Write-Warning "Failed to stop some Autodesk services. This may require a second run of the script, after a reboot."
        }
        Write-Log -Message "Autodesk services have been stopped." -EndLogEntry -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    # Stop all Autodesk Tasks
    Write-Log -Message "Stopping all Autodesk tasks:" -StartLogEntry -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    $tasks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name LIKE '%Autodesk%' OR Name LIKE '%ADSK%'"
    if ($tasks.Count -eq 0) {
        Write-Log -Message "No Autodesk tasks found." -EndLogEntry -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    } else {
        foreach ($task in $tasks) {
            Write-Log -Message "Stopping Autodesk task: $($task.Name) (PID: $($task.ProcessId))" -AddLogEntryData -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            try {
                Stop-Process -Id $task.ProcessId -Force -ErrorAction Continue
            } catch {
                Write-Log -Message "[ERROR] Failed to terminate process $($task.Name) (PID: $($task.ProcessId)): $($_.Exception.Message)" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
                Write-Warning "Failed to terminate process $($task.Name) (PID: $($task.ProcessId)): $($_.Exception.Message)"
            }
        }
        Write-Log -Message "All Autodesk tasks have been stopped." -EndLogEntry -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }

    function Get-MsiLocalPackagePath {
        param (
            [Parameter(Mandatory)]
            [string]$ProductCode
        )

        # Transform GUID to Installer format: {GUID} → GUID packed
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
            $InstallSource = Get-ItemProperty -Path $GuidRegPath -Name InstallSource -ErrorAction SilentlyContinue
            if ($null -ne $InstallSource) {
                $InstallSource = Get-Item "$InstallSource.InstallSource\*.msi" -ErrorAction SilentlyContinue
                $InstallSource = $InstallSource.FullName
                if ($null -ne $InstallSource) {
                    return $InstallSource
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
                $localPackageSourceList = Get-ItemProperty -Path $regPath -Name SourceList -ErrorAction SilentlyContinue
                if ($null -ne $localPackageSourceList) {
                    $localPackageSource = $localPackageSourceList.LastUsedSource
                    if ($localPackageSource -match "n;\d+;(.+)") {
                        $localPackagePath = $matches[1]
                        if (Test-Path $localPackagePath) {
                            return $localPackagePath
                        } else {
                            return $null
                        }
                    }
                } else {
                    return $null
                }
                return $localPackage.LocalPackage
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
                $xmlContent = [xml](Get-Content -Path $UninstallHelperBundleDataPath -ErrorAction Stop)
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
                                Write-Log -Message "Processing package: $($package.bundleName) - Product Code: $productCode" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
                                $localPackagePath = Get-MsiLocalPackagePath -ProductCode $productCode
                                if ($null -ne $localPackagePath) {
                                    if (Test-Path $localPackagePath) {
                                        $MsiLogFileName = "Uninstall_$($productCode)_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
                                        $MsiLogFullPath = Join-Path -Path $MsiLogPath -ChildPath $MsiLogFileName
                                        Write-Log -Message "msiexec /x $productCode /qn" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
                                        Start-Process -FilePath "msiexec.exe" -ArgumentList "/x `"$productCode`" /qn /l*x `"$MsiLogFullPath`"" -Wait
                                        if (Test-Path $MsiLogFullPath) {
                                            $MsiLogContent = Get-Content -Path $MsiLogFullPath -ErrorAction SilentlyContinue
                                            if ($null -ne $MsiLogContent) {
                                                Write-Log -Message "MSI Log for Product Code: $productCode`r`n{`r`n$($MsiLogContent -join "`r`n")`r`n}" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile -AddLogEntryData
                                            } else {
                                                Write-Log -Message "MSI Log file is empty for Product Code: $productCode" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
                                            }
                                            Remove-Item -Path $MsiLogFullPath -Force -ErrorAction SilentlyContinue
                                        } else {
                                            Write-Log -Message "MSI Log file not found for Product Code: $productCode" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
                                        }
                                    } else {
                                        Write-Log -Message "Local package path not found for Product Code: $productCode" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
                                    }
                                }
                            }
                        }
                        $TotalUninstallProgressPercentage += $packagePercentage
                        Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
                        $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
                        Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
                    }
                } else {
                    Write-Log -Message "No packages found in bundle data for $folderName" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
                    $TotalUninstallProgressPercentage += $folderPercentage
                    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
                    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
                    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
                }
            } else {
                Write-Log -Message "Uninstall Helper bundle data not found for $folderName" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
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
        Write-Log -Message "Removing Autodesk ODIS..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        Start-Process -FilePath $AdODISPath -ArgumentList "--mode unattended" -Wait
    } else {
        Write-Log -Message "Autodesk ODIS Remover not found at $AdODISPath" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Remove Autodesk Access
    $AdskAccessPath = "C:\Program Files\Autodesk\AdODIS\V1\Access\RemoveAccess.exe"
    if (Test-Path -Path $AdskAccessPath) {
        Write-Log -Message "Removing Autodesk Access..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        Start-Process -FilePath $AdskAccessPath -ArgumentList "--mode unattended" -Wait
    } else {
        Write-Log -Message "Autodesk Access Remover not found at $AdskAccessPath" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # run Autodesk Access uninstall helper
    $AdskAccessUninstHelper = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Access\AdskUninstallHelper.exe"
    if ( Test-Path -Path $AdskAccessUninstHelper ) {
        Write-Log -Message "Running Autodesk Access uninstall helper..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        Start-Process -FilePath $AdskAccessUninstHelper -Wait
    } else {
        Write-Log -Message "Autodesk Access uninstall helper not found at $AdskAccessUninstHelper" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Remove Autodesk Licensing
    $AdskLicensingPath = "C:\Program Files (x86)\Common Files\Autodesk Shared\AdskLicensing\uninstall.exe"
    if (Test-Path -Path $AdskLicensingPath) {
        Write-Log -Message "Removing Autodesk Licensing..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        Start-Process -FilePath $AdskLicensingPath -ArgumentList "--mode unattended" -Wait
    } else {
        Write-Log -Message "Autodesk Licensing Remover not found at $AdskLicensingPath" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Remove Autodesk Identity Manager
    $AdskIdentityManagerPath = "C:\Program Files\Autodesk\AdskIdentityManager\uninstall.exe"
    if (Test-Path -Path $AdskIdentityManagerPath) {
        Write-Log -Message "Removing Autodesk Identity Manager..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        Start-Process -FilePath $AdskIdentityManagerPath -ArgumentList "--mode unattended" -Wait
    } else {
        Write-Log -Message "Autodesk Identity Manager Remover not found at $AdskIdentityManagerPath" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Remove in C:\ProgramData\FLEXnet the files starting with adsk
    $flexnetPath = "C:\ProgramData\FLEXnet"
    if ( Test-Path -Path $flexnetPath) {
        Write-Log -Message "Removing Autodesk FLEXnet files..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        $flexnetFiles = Get-ChildItem -Path $flexnetPath -File -Recurse -ea SilentlyContinue | Where-Object { $_.Name -match "^adsk" }
        foreach ($file in $flexnetFiles) {
            try {
                Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Message "[ERROR] Failed to remove $($file.FullName): $($_.Exception.Message)" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            }
        }
    }
    $TotalUninstallProgressPercentage += 1
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0


    Write-Log -Message "Deleting Autodesk folders..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
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
            $autodeskFoldersAll.Add( $(Join-Path -Path $UserDir.FullName -ChildPath $folder) )
        }
    }

    $InstallDirPercentage = 100 / $autodeskFoldersAll.Count
    foreach ($folder in $autodeskFoldersAll) {
        if (Test-Path -Path $folder) {
            Write-Log -Message "Deleting folder $folder" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        }
        $InstallDirTotalProgressPercentage += $InstallDirPercentage
        Write-Progress -Activity "Post Uninstall: FileSystem Cleanup" -Status "$([math]::Round($InstallDirTotalProgressPercentage, 2))% Complete:" -PercentComplete $InstallDirTotalProgressPercentage -Id 2
        $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
        Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
    }
    $autodeskRegistryKeys = @(
        "HKLM:\SOFTWARE\Autodesk",
        "HKLM:\SOFTWARE\WOW6432Node\Autodesk"
    )
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS > $null
    $userProfiles = Get-ChildItem "HKU:\" | Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notmatch "_Classes" }

    $RegistryHklmHkuPercentage = 25/3 / ($autodeskRegistryKeys.Count + $userProfiles.Count)
    Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
    foreach ($key in $autodeskRegistryKeys) {
        if (Test-Path -Path $key) {
            Write-Log -Message "Deleting registry key $key" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        }
        $RegistryTotalProgressPercentage += $RegistryHklmHkuPercentage
        Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
        $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
        Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
    }



    foreach ($userProfile in $userProfiles) {
        $autodeskKey = "$($userProfile.PSChildName)\SOFTWARE\Autodesk"
        if (Test-Path -Path $autodeskKey) {
            Write-Log -Message "Deleting registry key $autodeskKey" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            Remove-Item -Path $autodeskKey -Recurse -Force -ErrorAction SilentlyContinue
        }
        $RegistryTotalProgressPercentage += $RegistryHklmHkuPercentage
        Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
        $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
        Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0
    }
    Remove-PSDrive -Name HKU -ErrorAction SilentlyContinue

    # uninstall Autodesk Genuine Service
    Stop-Service -Name "GenuineService" -Force -ErrorAction SilentlyContinue
    $adskGenuineSeviceGUID = (Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE 'Autodesk Genuine Service%'").IdentifyingNumber
    if ($adskGenuineSeviceGUID) {
        $MsiLogFileName = "MSIUninstall_adskGenuineService_$($adskGenuineSeviceGUID)__$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
        $MsiLogFullPath = Join-Path -Path $MsiLogPath -ChildPath $MsiLogFileName
        Write-Log -Message "Uninstalling Autodesk Genuine Service with GUID: $adskGenuineSeviceGUID" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $adskGenuineSeviceGUID /qn /l*x `"$MsiLogFullPath`"" -Wait
        if (Test-Path $MsiLogFullPath) {
            $MsiLogContent = Get-Content -Path $MsiLogFullPath -ErrorAction SilentlyContinue
            if ($null -ne $MsiLogContent) {
                Write-Log -Message "MSI Log for Product Code: $productCode`r`n{`r`n$($MsiLogContent -join "`r`n")`r`n}" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile -AddLogEntryData
            } else {
                Write-Log -Message "MSI Log file is empty for Product Code: $productCode" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            }
            Remove-Item -Path $MsiLogFullPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log -Message "MSI Log file not found for Product Code: $productCode" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        }
    } else {
        Write-Log -Message "Autodesk Genuine Service not found." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Running Uninstall Helper for Genuine Service
    $adskGenuineServicePath = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Genuine Service\AdskUninstallHelper.exe"
    if (Test-Path -Path $adskGenuineServicePath) {
        Write-Log -Message "Running Uninstall Helper for Autodesk Genuine Service..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        Start-Process -FilePath $adskGenuineServicePath -Wait -NoNewWindow -ea SilentlyContinue
        Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log -Message "Autodesk Genuine Service Uninstall Helper not found at $adskGenuineServicePath" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Running Uninstall Helper for Autodesk Identity Manager Component
    $adskIdentityManagerComponentPath = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Identity Manager Component\AdskUninstallHelper.exe"
    if (Test-Path -Path $adskIdentityManagerComponentPath) {
        Write-Log -Message "Running Uninstall Helper for Autodesk Identity Manager Component..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        Start-Process -FilePath $adskIdentityManagerComponentPath -Wait -NoNewWindow -ea SilentlyContinue
        Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log -Message "Autodesk Identity Manager Component Uninstall Helper not found at $adskIdentityManagerComponentPath" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # Running Uninstall Helper for Autodesk Installer
    $adskInstallerPath = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Installer\AdskUninstallHelper.exe"
    if (Test-Path -Path $adskInstallerPath) {
        Write-Log -Message "Running Uninstall Helper for Autodesk Installer..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
        Start-Process -FilePath $adskInstallerPath -Wait -NoNewWindow -ea SilentlyContinue
        Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log -Message "Autodesk Installer Uninstall Helper not found at $adskInstallerPath" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    }
    $TotalUninstallProgressPercentage += $folderPercentage
    Write-Progress -Activity "Package Uninstallation" -Status "$([math]::Round($TotalUninstallProgressPercentage, 2))% Complete:" -PercentComplete $TotalUninstallProgressPercentage -Id 1
    $GlobalProgressPercentage = ($TotalUninstallProgressPercentage + $InstallDirTotalProgressPercentage + $RegistryTotalProgressPercentage) / 3
    Write-Progress -Activity "Global Progress" -Status "$([math]::Round($GlobalProgressPercentage, 2))% Complete:" -PercentComplete $GlobalProgressPercentage -Id 0

    # delete Autodesk registry keys
    Write-Log -Message "Deleting Autodesk Install/Uninstall registry keys..." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
    $autodeskRegistryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\Classes\Installer\Products",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Products"
    )


    $RegistryMainLocationsPercentage = 275/3 / $autodeskRegistryKeys.Count
    Write-Progress -Activity "Post Uninstall: Registry Cleanup" -Status "$([math]::Round($RegistryTotalProgressPercentage, 2))% Complete:" -PercentComplete $RegistryTotalProgressPercentage -Id 3
    foreach ($key in $autodeskRegistryKeys) {
        if (Test-Path -Path $key) {
            $subkeys = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
            $RegistrySubKeyPercentage = $RegistryMainLocationsPercentage / $subkeys.Count
            foreach ($subkey in $subkeys) {
                $subkeyPath = Join-Path -Path $key -ChildPath $subkey.PSChildName
                $shouldRemove = $false
                # For Uninstall keys, check main properties
                if ($key -like "*Uninstall*") {
                    $props = Get-ItemProperty -Path $subkeyPath -ErrorAction SilentlyContinue
                    if (
                        $null -ne $props -and
                        (
                            $props.DisplayName -match "^Autodesk" -or
                            $props.UninstallString -match "^Autodesk" -or
                            $props.InstallLocation -match "^Autodesk" -or
                            $props.Publisher -match "^Autodesk" -or
                            $props.DisplayIcon -match "^Autodesk"
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
                                    $props.DisplayName -match "^Autodesk" -or
                                    $props.UninstallString -match "^Autodesk" -or
                                    $props.InstallLocation -match "^Autodesk" -or
                                    $props.Publisher -match "^Autodesk" -or
                                    $props.ProductName -match "^Autodesk"-or
                                    $props.DisplayIcon -match "^Autodesk"
                                )
                            ) {
                                $shouldRemove = $true
                            }
                        }
                    }
                }
                if ($shouldRemove) {
                    Remove-Item -Path $subkeyPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "Removed registry key $subkeyPath" -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
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
    remove-item -Path $MsiLogPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Autodesk products uninstallation completed with Exit Code 0." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile

    if (-not $PSSenderInfo) {
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
        [Microsoft.VisualBasic.Interaction]::AppActivate($PID)
    }

    Write-Host "`r`nAutodesk products have been uninstalled successfully.`r`nA complete Log has been generated at $MainLogFile" -ForegroundColor Green
    Write-Host "Please restart your computer to complete the uninstallation process." -ForegroundColor Yellow
    Write-Host "It is recommended to run this script a second time after the restart to ensure all Autodesk products are removed." -ForegroundColor Yellow
    Pause
    $notification.Dispose()
    Read-Host -Prompt "`r`nWould you like to restart your computer now? (Y/N)" | ForEach-Object {
        if ($_ -eq "y") {
            Write-Log -Message "Restarting the computer as per user request." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            Restart-Computer -Force
        } elseif($_ -eq "n") {
            Write-Log -Message "User chose not to restart the computer." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            Write-Host "Please restart your computer manually to complete the uninstallation process."
        } else {
            Write-Log -Message "Unknown response from user regarding restart: $_. Skipping restart." -Component "AutoDeskCleanRemove" -LogPath $MainLogFile
            Write-Host "Unknown Response. Please restart your computer manually to complete the uninstallation process."
        }
    }
}


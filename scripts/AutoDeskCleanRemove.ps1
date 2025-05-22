#####################################################################################
# Script Name:  AutoDeskCleanRemove.ps1
# Description:  This script is used to cleanly uninstall all Autodesk products
#               from a system.
#
# Author:       Halatschek Wolfram
# Date:         2025-05-20
# Version:      1.0
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

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ( -not $isElevated ) {
    $("") ; Write-Warning "`r`nThis script must be run with administrative privileges. Please restart the script in an elevated PowerShell session.`r`n"
    Pause ; $("")
} else {
    Write-Host "`r`nThis script will remove all Autodesk products from your system."
    Write-Host "Please ensure that you have closed all Autodesk applications before proceeding."
    Write-Host "This script has not been tested with Fusion 360. If you have Fusion 360 installed, please uninstall it manually before running this script."
    Write-Warning "Please note that this may prompt OneDrive regarding the deletion of files. This is to be expected."
    Pause
    # Stop all Autodesk Services
    Get-Process | Where-Object { $_.Description -match "Autodesk" -or $_.Description -match "ADSK" -or $_.Description -match "AutoCAD" -or $_.Description -match "Inventor" } | Stop-Process -Force
    Get-Service | Where-Object { $_.DisplayName -match "Autodesk" -or $_.DisplayName -match "ADSK"  } | Stop-Service -Force -ErrorAction SilentlyContinue
    # Stop all Autodesk Tasks
    $tasks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name LIKE '%Autodesk%' OR Name LIKE '%ADSK%'"
    foreach ($task in $tasks) {
        try {
            Stop-Process -Id $task.ProcessId -Force -ErrorAction Continue
        } catch {
            Write-Warning "Failed to terminate process $($task.Name) (PID: $($task.ProcessId)): $($_.Exception.Message)"
        }
    }

    $UninstallersPath="C:\ProgramData\Autodesk\Uninstallers"
    $UninstallHelperExeName="AdskUninstallHelper.exe"

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

    Write-Host "Running Uninstall Helper for Autodesk products..."
    Write-Warning "Multiple Windows may appear, please do not close them manually.`r`nThe script will close them automatically after the uninstallation process."
    Write-Host "Please wait..."
    Start-Sleep -Seconds 5
    foreach ($folder in $productsSorted) {
        if ($null -ne $folder) {
            $folderName = $folder.Name
            $UninstallHelperExePath = Join-Path -Path $folder.FullName -ChildPath $UninstallHelperExeName
            if (Test-Path -Path $UninstallHelperExePath) {
                Write-Host "Running Uninstall Helper for $folderName"
                Start-Process -FilePath $UninstallHelperExePath -Wait -NoNewWindow -ea SilentlyContinue
                # close all message_router.exe if it is running
                Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            } else {
                Write-Warning "Uninstall Helper not found for $folderName"
            }
        }
    }

    $AdODISPath = "C:\Program Files\Autodesk\AdODIS\V1\RemoveODIS.exe"
    if (Test-Path -Path $AdODISPath) {
        Write-Host "Removing Autodesk ODIS..."
        Start-Process -FilePath $AdODISPath -ArgumentList "--mode unattended" -Wait
    }

    # Remove Autodesk Access
    $AdskAccessPath = "C:\Program Files\Autodesk\AdODIS\V1\Access\RemoveAccess.exe"
    if (Test-Path -Path $AdskAccessPath) {
        Write-Host "Removing Autodesk Access..."
        Start-Process -FilePath $AdskAccessPath -ArgumentList "--mode unattended" -Wait
    }

    # run Autodesk Access uninstall helper
    $AdskAccessUninstHelper = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Access\AdskUninstallHelper.exe"
    if ( Test-Path -Path $AdskAccessUninstHelper ) {
        Write-Host "Running Autodesk Access uninstall helper..."
        Start-Process -FilePath $AdskAccessUninstHelper -Wait
    }

    # Remove Autodesk Licensing
    $AdskLicensingPath = "C:\Program Files (x86)\Common Files\Autodesk Shared\AdskLicensing\uninstall.exe"
    if (Test-Path -Path $AdskLicensingPath) {
        Write-Host "Removing Autodesk Licensing..."
        Start-Process -FilePath $AdskLicensingPath -ArgumentList "--mode unattended" -Wait
    }

    # Remove Autodesk Identity Manager
    $AdskIdentityManagerPath = "C:\Program Files\Autodesk\AdskIdentityManager\uninstall.exe"
    if (Test-Path -Path $AdskIdentityManagerPath) {
        Write-Host "Removing Autodesk Identity Manager..."
        Start-Process -FilePath $AdskIdentityManagerPath -ArgumentList "--mode unattended" -Wait
    }


    # Remove in C:\ProgramData\FLEXnet the files starting with adsk
    $flexnetPath = "C:\ProgramData\FLEXnet"
    if ( Test-Path -Path $flexnetPath) {
        Write-Host "Removing Autodesk FLEXnet files..."
        $flexnetFiles = Get-ChildItem -Path $flexnetPath -File -Recurse -ea SilentlyContinue | Where-Object { $_.Name -match "^adsk" }
        foreach ($file in $flexnetFiles) {
            try {
                Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Failed to remove $($file.FullName): $($_.Exception.Message)"
            }
        }
    }

    Write-Host "Deleting Autodesk folders..."
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
    foreach ($folder in $autodeskFoldersAll) {
        if (Test-Path -Path $folder) {
            Write-Host "Deleting $folder"
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $autodeskRegistryKeys = @(
        "HKLM:\SOFTWARE\Autodesk",
        "HKLM:\SOFTWARE\WOW6432Node\Autodesk"
    )
    foreach ($key in $autodeskRegistryKeys) {
        if (Test-Path -Path $key) {
            Write-Host "Deleting registry key $key"
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS > $null
    $userProfiles = Get-ChildItem "HKU:\" | Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notmatch "_Classes" }
    foreach ($userProfile in $userProfiles) {
        $autodeskKey = "$($userProfile.PSChildName)\SOFTWARE\Autodesk"
        if (Test-Path -Path $autodeskKey) {
            Write-Host "Deleting registry key $autodeskKey"
            Remove-Item -Path $autodeskKey -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-PSDrive -Name HKU -ErrorAction SilentlyContinue

    # uninstall Autodesk Genuine Service
    Stop-Service -Name "GenuineService" -Force -ErrorAction SilentlyContinue
    $adskGenuineSeviceGUID = (Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE 'Autodesk Genuine Service%'").IdentifyingNumber
    if ($adskGenuineSeviceGUID) {
        Write-Host "Uninstalling Autodesk Genuine Service..."
        Write-Host "Uninstalling Autodesk Genuine Service with GUID: $adskGenuineSeviceGUID"
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $adskGenuineSeviceGUID /qn" -Wait
    }

    # Running Uninstall Helper for Genuine Service
    $adskGenuineServicePath = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Genuine Service\AdskUninstallHelper.exe"
    if (Test-Path -Path $adskGenuineServicePath) {
        Write-Host "Running Uninstall Helper for Autodesk Genuine Service..."
        Start-Process -FilePath $adskGenuineServicePath -Wait -NoNewWindow -ea SilentlyContinue
        Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # Running Uninstall Helper for Autodesk Identity Manager Component
    $adskIdentityManagerComponentPath = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Identity Manager Component\AdskUninstallHelper.exe"
    if (Test-Path -Path $adskIdentityManagerComponentPath) {
        Write-Host "Running Uninstall Helper for Autodesk Identity Manager Component..."
        Start-Process -FilePath $adskIdentityManagerComponentPath -Wait -NoNewWindow -ea SilentlyContinue
        Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # Running Uninstall Helper for Autodesk Installer
    $adskInstallerPath = "C:\ProgramData\Autodesk\Uninstallers\Autodesk Installer\AdskUninstallHelper.exe"
    if (Test-Path -Path $adskInstallerPath) {
        Write-Host "Running Uninstall Helper for Autodesk Installer..."
        Start-Process -FilePath $adskInstallerPath -Wait -NoNewWindow -ea SilentlyContinue
        Get-Process -Name "message_router" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # delete Autodesk registry keys
    Write-Host "Deleting Autodesk Install/Uninstall registry keys..."
    $autodeskRegistryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKLM:\SOFTWARE\Classes\Installer\Products"
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Products"
    )

    foreach ($key in $autodeskRegistryKeys) {
        if (Test-Path -Path $key) {
            $subkeys = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
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
                }
            }
        }
    }
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


    Write-Host "`r`n Autodesk products have been uninstalled successfully." -ForegroundColor Green
    Write-Host " Please restart your computer to complete the uninstallation process." -ForegroundColor Yellow
    Write-Host " It is recommended to run this script a second time after the restart to ensure all Autodesk products are removed." -ForegroundColor Yellow
    Pause
    $notification.Dispose()
    Read-Host -Prompt "`r`n Would you like to restart your computer now? (Y/N)" | ForEach-Object {
        if ($_ -eq "y") {
            Restart-Computer -Force
        } elseif($_ -eq "n") {
            Write-Host "Please restart your computer manually to complete the uninstallation process."
        } else {
            Write-Host "Unknown Response. Please restart your computer manually to complete the uninstallation process."
        }
    }
}
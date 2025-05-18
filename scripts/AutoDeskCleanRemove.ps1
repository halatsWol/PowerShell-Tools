#####################################################################################
# SCRIPT NOT YET TESTED!
#
# Script Name:  CleanRemoveADSK.ps1
# Description:  This script is used to cleanly uninstall all Autodesk products
#               from a system.
#
# Author:       Halatschek Wolfram
# Date:         2025-05-18
# Version:      0.9
# Notes:        This script requires administrative privileges to run.
#
# Usage:        Run this script in an elevated PowerShell session.
#               PS> <path to script>\CleanRemoveADSK.ps1
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
    Pause
    Write-Host "`r`n"
    Write-Host "Stopping all Autodesk Services and Processes..."
    # Stop all Autodesk Services
    Get-Process | Where-Object { $_.Description -match "Autodesk" -or $_.Description -match "ADSK" -or $_.Description -match "AutoCAD" -or $_.Description -match "Inventor" } | Stop-Process -Force
    Get-Service | Where-Object { $_.DisplayName -match "Autodesk" -or $_.DisplayName -match "ADSK"  } | Stop-Service -Force -ErrorAction SilentlyContinue
    Get-Process | Where-Object { $_.Description -match "Autodesk" -or $_.Description -match "ADSK" -or $_.Description -match "AutoCAD" -or $_.Description -match "Inventor" } | Stop-Process -Force
    # Stop all Autodesk Tasks
    $tasks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name LIKE '%Autodesk%' OR Name LIKE '%ADSK%'"
    foreach ($task in $tasks) {
        try {
            Stop-Process -Id $task.ProcessId -Force -ErrorAction Continue
        } catch {
        Write-Warning "Failed to terminate process $($task.Name) (PID: $($task.ProcessId)): $($_.Exception.Message)"
    }
    }

    Write-Host "Removing AutoDesk Language Packs..."
    get-Package | Where-Object { $_.name -match "autodesk" -and $_.name -match "Language Pack" } | Uninstall-Package -Force -ErrorAction SilentlyContinue

    $UninstallersPath="C:\ProgramData\Autodesk\Uninstallers"
    $UninstallHelperExeName="AdskUninstallHelper.exe"

    # get folders in the Uninstallers path
    $UninstallersFolders = Get-ChildItem -Path $UninstallersPath -Directory -ea SilentlyContinue | Where-Object { $_.Name -ne "metadata" }

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
    Write-Warning "Multiiple Windows may appear, please do not close them manually."
    Write-Warning "If a Window 'Autodesk Genuine Service' appears, you can simply close it."
    Write-Host "The script will close them automatically after the uninstallation process."
    Write-Host "Please wait..."
    foreach ($folder in $productsSorted) {
        if ($null -ne $folder) {
            $folderName = $folder.Name
            $UninstallHelperExePath = Join-Path -Path $folder.FullName -ChildPath $UninstallHelperExeName
            if (Test-Path -Path $UninstallHelperExePath) {
                Write-Host "Running Uninstall Helper for $folderName"
                Start-Process -FilePath $UninstallHelperExePath -Wait -NoNewWindow -ea SilentlyContinue
            } else {
                Write-Warning "Uninstall Helper not found for $folderName"
            }
        }
    }

    # Uninstall Autodesk products using PowerShell PackageManagement
    Write-Host "Uninstalling remaining Autodesk products using PowerShell PackageManagement..."
    $packages = Get-Package | Where-Object { $_.Name -match "Autodesk" }
    foreach ($package in $packages) {
        # ignore Autodesk Access
        if ($package.Name -ne "Autodesk Access") {
            Write-Host "Uninstalling $($package.Name)"
            try {
                Uninstall-Package -Name $package.Name -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Failed to uninstall $($package.Name): $($_.Exception.Message)"
            }
        }

    }

    # Remove AdODIS
    Write-Host "Removing Autodesk ODIS..."
    $AdODISPath = "C:\Program Files\Autodesk\AdODIS\V1\RemoveODIS.exe"
    if (Test-Path -Path $AdODISPath) {
        Start-Process -FilePath $AdODISPath -Wait
    }
    # Remove Autodesk Licensing
    Write-Host "Removing Autodesk Licensing..."
    $AdskLicensingPath = "C:\Program Files (x86)\Common Files\Autodesk Shared\AdskLicensing\uninstall.exe"
    if (Test-Path -Path $AdskLicensingPath) {
        Start-Process -FilePath $AdskLicensingPath -Wait
    }

    # delete Autodesk folders
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

    # delete Autodesk registry keys
    Write-Host "Deleting Autodesk registry keys..."
    $autodeskRegistryKeys = @(
        "HKLM:\SOFTWARE\Autodesk",
        "HKLM:\SOFTWARE\WOW6432Node\Autodesk",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKLM:\SOFTWARE\Classes\Installer\Products"
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Products"
    )

    foreach ($key in $autodeskRegistryKeys) {
        if ($key -like "*Uninstall*" -or $key -like "*Products*") {
            if (Test-Path -Path $key) {
                $subkeys = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
                foreach ($subkey in $subkeys) {
                    $subkeyPath = Join-Path -Path $key -ChildPath $subkey.PSChildName
                    $shouldRemove = $false

                    # For Uninstall keys, check main properties
                    if ($key -like "*Uninstall*") {
                        $props = Get-ItemProperty -Path $subkeyPath -ErrorAction SilentlyContinue
                        if ($props.DisplayName -match "Autodesk" -or
                            $props.UninstallString -match "Autodesk" -or
                            $props.InstallLocation -match "Autodesk" -or
                            $props.Publisher -match "Autodesk" -or
                            $props.DisplayIcon -match "Autodesk") {
                            $shouldRemove = $true
                        }
                    }

                    # For Installer\Products, check InstallProperties subkey
                    if (-not $shouldRemove -and $key -like "*Products*") {
                        $props = Get-ItemProperty -Path $subkeyPath -ErrorAction SilentlyContinue
                        if ( $props.ProductName -match "Autodesk" ) {
                            $shouldRemove = $true
                        } else {
                            $installPropsPath = Join-Path -Path $subkeyPath -ChildPath "InstallProperties"
                            if (Test-Path $installPropsPath) {
                                $props = Get-ItemProperty -Path $installPropsPath -ErrorAction SilentlyContinue
                                if ($props.DisplayName -match "Autodesk" -or
                                    $props.UninstallString -match "Autodesk" -or
                                    $props.InstallLocation -match "Autodesk" -or
                                    $props.Publisher -match "Autodesk" -or
                                    $props.ProductName -match "Autodesk"-or
                                    $props.DisplayIcon -match "Autodesk") {
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
        } else {
            if (Test-Path -Path $key) {
                Write-Host "Deleting registry key $key"
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Autodesk Access" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Autodesk Desktop App" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Autodesk Sync" -Force -ErrorAction SilentlyContinue

    Write-Host "`r`nAutodesk products have been uninstalled successfully."
    Write-Host "Please restart your computer to complete the uninstallation process."
    Write-Host "It is recommended to run this script again after the restart to ensure all Autodesk products are removed."
    Pause

    Read-Host -Prompt "`r`nWould you like to restart your computer now? (Y/N)" | ForEach-Object {
        if ($_ -match "y") {
            Restart-Computer -Force
        } elseif($_ -match "n") {
            Write-Host "Please restart your computer manually to complete the uninstallation process."
        } else {
            Write-Host "Unknown Response. Please restart your computer manually to complete the uninstallation process."
        }
    }

}
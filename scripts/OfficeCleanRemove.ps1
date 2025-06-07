#####################################################################################
# Script Name:  OfficeCleanRemove.ps1
# Description:  This script is used to cleanly uninstall Microsoft Office 365, 2019
#               and older versions from a system.
#
# Author:       Halatschek Wolfram
# Date:         2025-06-07
# Version:      0.1
# Notes:        This script requires administrative privileges to run.
#
# Usage:        Run this script in an elevated PowerShell session.
#               PS> cd <path to script>
#               PS> .\OfficeCleanRemove.ps1
#
#               Please restart your computer after running this Script and run it
#               again to ensure all MS Office residuals are removed.
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
    Write-Host "`r`nThis script will remove all MS Office products from your system."
    Write-Warning "This script is intended to only be used if the normal uninstallation process fails, as well as Microsoft Support and Recovery Assistant (SaRA/Offscrub)."
    Pause


    $OfficeRegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Office",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office 365",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office 365",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office 2019",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office 2019",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office 2016",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office 2016",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office 2013",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office 2013"
    )

    $fileTypesRegPaths = @(
        # filetype associations
        "HKLM:\SOFTWARE\Classes\Word.",
        "HKLM:\SOFTWARE\Classes\Excel.",
        "HKLM:\SOFTWARE\Classes\PowerPoint.",
        "HKLM:\SOFTWARE\Classes\Outlook.",
        "HKLM:\SOFTWARE\Classes\Access.",
        "HKLM:\SOFTWARE\Classes\Visio.",
        "HKLM:\SOFTWARE\Classes\Publisher.",
        "HKLM:\SOFTWARE\Classes\OneNote.",
        # filetype associations for 32-bit Office on 64-bit Windows
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Word.",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Excel.",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\PowerPoint.",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Outlook.",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Access.",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Visio.",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Publisher.",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\OneNote."
        # filetypes hkey classes root
        "HKCR:\Word.",
        "HKCR:\Excel.",
        "HKCR:\PowerPoint.",
        "HKCR:\Outlook.",
        "HKCR:\Access.",
        "HKCR:\Visio.",
        "HKCR:\Publisher.",
        "HKCR:\OneNote."
    )

    $fileTypesEndingsRegPaths = @(
        # word filetype endings
        "HKCR:\.docx",
        "HKCR:\.docm",
        "HKCR:\.dotx",
        "HKCR:\.dotm",
        "HKCR:\.doc",
        "HKCR:\.dot",
        # excel filetype endings
        "HKCR:\.xlsx",
        "HKCR:\.xlsm",
        "HKCR:\.xltx",
        "HKCR:\.xltm",
        "HKCR:\.xlsb",
        "HKCR:\.xls",
        "HKCR:\.xlt",
        "HKCR:\.csv",
        "HKCR:\.xlam",
        # powerpoint filetype endings
        "HKCR:\.pptx",
        "HKCR:\.pptm",
        "HKCR:\.potx",
        "HKCR:\.potm",
        "HKCR:\.ppsx",
        "HKCR:\.ppsm",
        "HKCR:\.ppt",
        "HKCR:\.pot",
        "HKCR:\.pps",
        "HKCR:\.ppam",
        # outlook filetype endings
        "HKCR:\.msg",
        "HKCR:\.oft",
        "HKCR:\.eml",
        "HKCR:\.pst",
        # access filetype endings
        "HKCR:\.accdb",
        "HKCR:\.accde",
        "HKCR:\.accdr",
        "HKCR:\.accdt",
        # visio filetype endings
        "HKCR:\.vsdx",
        "HKCR:\.vsdm",
        "HKCR:\.vssx",
        "HKCR:\.vssm",
        "HKCR:\.vstx",
        "HKCR:\.vstm",
        "HKCR:\.vsd",
        # publisher filetype endings
        "HKCR:\.pub",
        "HKCR:\.pubx",
        "HKCR:\.pubm",
        "HKCR:\.pubx",
        # onenote filetype endings
        "HKCR:\.one",
        "HKCR:\.onepkg",
        "HKCR:\.onetoc2",
        "HKCR:\.onetmp",
        "HKCR:\.onebin",
        "HKCR:\.onetoc"
    )

    foreach ($regPath in $OfficeRegPaths) {
        if (Test-Path $regPath) {
            Write-Host "Removing registry key: $regPath" -ForegroundColor Yellow
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "Registry key not found: $regPath" -ForegroundColor Green
        }
    }

    foreach ($regPath in $fileTypesRegPaths) {
        Remove-Item -Path "$regPath*" -Recurse -Force -ErrorAction SilentlyContinue
    }

    foreach ($regPath in $fileTypesEndingsRegPaths) {
        Remove-Item -Path "$regPath*" -Recurse -Force -ErrorAction SilentlyContinue
    }


    # "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ search display names
    $uninstallerRegistryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKLM:\SOFTWARE\Classes\Installer\Products"
        "HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Products"
    )

    foreach ($key in $uninstallerRegistryKeys) {
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
                            $props.DisplayName -match "^Office" -or
                            $props.UninstallString -match "^Office" -or
                            $props.InstallLocation -match "^Office" -or
                            $props.Publisher -match "^Office" -or
                            $props.DisplayIcon -match "^Office"
                        )
                    ) {
                        $shouldRemove = $true
                    }
                }
                # For Installer/Products, check InstallProperties subkey
                if (-not $shouldRemove -and $key -like "*Products*") {
                    $props = Get-ItemProperty -Path $subkeyPath -ErrorAction SilentlyContinue
                    if ( $null -ne $props -and $props.ProductName -match "^Office" ) {
                        $shouldRemove = $true
                    } else {
                        $installPropsPath = Join-Path -Path $subkeyPath -ChildPath "InstallProperties"
                        if (Test-Path $installPropsPath) {
                            $props = Get-ItemProperty -Path $installPropsPath -ErrorAction SilentlyContinue
                            if (
                                $null -ne $props -and
                                (
                                    $props.DisplayName -match "^Office" -or
                                    $props.UninstallString -match "^Office" -or
                                    $props.InstallLocation -match "^Office" -or
                                    $props.Publisher -match "^Office" -or
                                    $props.ProductName -match "^Office"-or
                                    $props.DisplayIcon -match "^Office"
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

    # Remove Office-related directories
    $officeDirs = @(
        "$env:ProgramFiles\Microsoft Office*",
        "$env:ProgramFiles(x86)\Microsoft Office*",
        "$env:ProgramData\Microsoft\Office",
        "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun",
        "$env:ProgramFiles(x86)\Common Files\Microsoft Shared\ClickToRun",
        "$env:ProgramData\Microsoft\ClickToRun",
        "$env:ProgramFiles\Common Files\Microsoft Shared\Office*",
        "$env:ProgramFiles(x86)\Common Files\Microsoft Shared\Office*",
        "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\*",
        "$env:ProgramFiles(x86)\Common Files\Microsoft Shared\ClickToRun\*"
    )
    foreach ($dir in $officeDirs) {
        if (Test-Path $dir) {
            Write-Host "Removing directory: $dir" -ForegroundColor Yellow
            Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "Directory not found: $dir" -ForegroundColor Green
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


    Write-Host "`r`n Microsoft Office has been removed successfully." -ForegroundColor Green
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
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
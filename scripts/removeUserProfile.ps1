#####################################################################################
# Script Name:  removeUserProfile.ps1
# Description:  This script removes a user profile from the system and backs up
#               the registry keys associated with the profile. It also exports
#               network drives and printers associated with the user profile.
#
# Author:       Halatschek Wolfram
# Date:         2025-05-01
# Version:      1.0
# Notes:        This script requires administrative privileges to run.
#               The affected User must be logged out before running this script.
#               Please restart the Machine first before use.
#
# Usage:        Run this script in an elevated PowerShell session.
#               PS> <path to script>\removeUserProfile.ps1
#
#               The script will prompt for the username of the profile to be removed.
#               It will then back up the registry keys, export network drives and printers,
#               and rename the user profile folder.
# Logs
# & Backup:     The script will log all actions taken and any errors encountered as well as
#               Backing up all deleted registry keys.
#               The logs and backups will be stored in
#               C:\_IT-ProfileCleanup\<Username>_ProfileCleanup_<Current-Date>\.
#
#               The User-Profile will be renamed at its original location to
#               <Username>-<Current-Date>.old
#
# Warning:      This script deletes user profiles and registry keys. Use with caution.
#               Always test in a safe environment before running in production.
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
    $UserName = Read-Host "Enter the username of the profile to be removed"
    if($UserName -ne "") {
        $currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
        $TempPath = "$env:HOMEDRIVE\_IT-ProfileCleanup\$UserName"+"_ProfileCleanup_$currentDateTime"
        $LogPath = "$TempPath\Logs"
        $cleanupLog = $LogPath+"\cleanupProfileLog_$currentDateTime.log"
        $RegPath = "$TempPath\Registry"
        $profilePath = "$env:HOMEDRIVE\Users\$UserName"
        $profilePathOld = "$env:HOMEDRIVE\Users\$UserName-$currentDateTime.old"
        $regProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $regProfileListPathWOW6432Node = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\ProfileList"
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS > $null
        $netDrivesCMDfile="$TempPath\NetDrives_$UserName.cmd"
        $printerListFile="$TempPath\PrinterList_$UserName.txt"
        $FailedEXPORTS = New-Object System.Collections.Generic.List[System.Object]

        function Write-LogMessage {
            param([string]$message)
            $message = "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss.fff"))] - $message"
            Write-Host $message
            $message | Out-File -FilePath $cleanupLog -Append
        }

        $user = query user| ForEach-Object {
            $_.trim().insert(22,",").insert(42,",").insert(47,",").insert(56,",").insert(68,",") -replace "\s+","" -replace ">" , ""
        } | ConvertFrom-Csv | Where-Object { $_.USERNAME -eq $USERNAME } | Select-Object USERNAME,ID

        if ($user.username -eq $UserName) {
            Write-Error "`r`nUser '$UserName' is still logged in on $env:computername . Please sign out the user before cleaning the profile."
        }
        else{
            New-Item -Path $TempPath,$LogPath,$RegPath -ItemType Directory -Force >$null

            $profileList = Get-ChildItem $regProfileListPath | Get-ItemProperty | Where-Object { $_.ProfileImagePath -eq "C:\Users\$UserName" }
            $profileListId = $profileList.PSChildName
            if( $null -ne $profileListId){
                try{
                    Write-LogMessage "Profile with Username $UserName found in registry"
                    Write-LogMessage "[INFO]`r`n`t`tBacking up Registry - Profile List to $TempPath\Registry"
                    $profileList_SID_PATH = "$regProfileListPath\$profileListId"
                    $profileList_WOW6432Node_SID_PATH = "$regProfileListPathWOW6432Node\$profileListId"
                    $profileList_SID_ITEM = Get-Item -ea SilentlyContinue -Path $profileList_SID_PATH
                    $profileList_WOW6432Node_SID_ITEM = Get-Item -ea SilentlyContinue -Path $profileList_WOW6432Node_SID_PATH
                    $outputFilePathProfileList = "$RegPath\ProfileListBackup_$UserName"+"_$currentDateTime.reg"
                    $outputFilePathProfileListWOW6432Node = "$RegPath\ProfileListBackup-WOW6432Node_$UserName"+"_$currentDateTime.reg"

                    ## EXPORT & DELETE Profile List Registry Keys
                    if (Test-Path $profileList_SID_PATH) {
                        Write-LogMessage "[INFO]`r`n`t`tBacking up Registry - Profile List of $UserName to:`r`n`t`t$outputFilePathProfileList"
                        Start-Process -FilePath "reg.exe" -ArgumentList "export `"$profileList_SID_ITEM`" `"$outputFilePathProfileList`" /y" -NoNewWindow -Wait -RedirectStandardOutput "\NUL"
                        # Check if the export was successful
                        if (Test-Path $outputFilePathProfileList) {
                            Write-LogMessage "Export successful.`r`n`t`tDeleting $profileList_SID_PATH"
                            Remove-Item -Path $profileList_SID_PATH -Force -Recurse
                        } else {
                            Write-LogMessage "[ERROR]`r`n`t`tError occurred while exporting Profile List Key of User '$UserName'. Deletion skipped."
                            $FailedEXPORTS.Add($profileList_SID_PATH)
                        }
                    } else {
                        Write-LogMessage "[WARNING]`r`n`t`tRegistry path $profileList_SID_PATH does not exist"
                    }
                    ## EXPORT & DELETE WOW6432Node Profile List Registry Keys
                    if (Test-Path $profileList_WOW6432Node_SID_PATH) {
                        Write-LogMessage "[INFO]`r`n`t`tBacking up Registry - WOW6432Node Profile List of $UserName to`r`n`t`t$outputFilePathProfileListWOW6432Node"
                        Start-Process -FilePath "reg.exe" -ArgumentList "export `"$profileList_WOW6432Node_SID_ITEM`" `"$outputFilePathProfileListWOW6432Node`" /y" -NoNewWindow -Wait -RedirectStandardOutput "\NUL"
                        # Check if the export was successful
                        if (Test-Path $outputFilePathProfileListWOW6432Node) {
                            Write-LogMessage "Export successful.`r`n`t`tDeleting $profileList_WOW6432Node_SID_PATH"
                            Remove-Item -Path $profileList_WOW6432Node_SID_PATH -Force -Recurse
                        } else {
                            Write-LogMessage "[ERROR]`r`n`t`tError occurred while exporting WOW6432Node Profile List Key of User '$UserName'. Deletion skipped."
                            $FailedEXPORTS.Add($profileList_WOW6432Node_SID_PATH)
                        }
                    } else {
                        Write-LogMessage "[WARNING]`r`n`t`tRegistry path $profileList_WOW6432Node_SID_PATH does not exist"
                    }

                    $HKU_userSID_Path = "HKU:\$profileListId"
                    $UserHiveFile = "$env:HomeDrive\Users\$UserName\NTUSER.DAT"

                    # load user hive
                    if (-not $(Test-Path $HKU_userSID_Path)) {
                        if (Test-Path $UserHiveFile) {
                            Write-LogMessage "[INFO]`r`n`t`tLoading User Hive $HKU_userSID_Path from $UserHiveFile"
                            Start-Process -FilePath "reg.exe" -ArgumentList "load `"HKU\$profileListId`" `"$UserHiveFile`"" -NoNewWindow -Wait -RedirectStandardOutput "\NUL"
                        } else {
                            Write-LogMessage "[ERROR]`r`n`t`tUser Hive File $UserHiveFile does not exist!"
                        }
                    } else {
                        Write-LogMessage "[INFO]`r`n`t`tUser Hive $UserHiveFile already loaded!"
                    }

                    # Continue only if HKU_SID Exists
                    if (Test-Path $HKU_userSID_Path) {
                        # get network drives
                        if (Test-Path "$HKU_userSID_Path\Network") {
                            $drives = Get-ChildItem -Path "$HKU_userSID_Path\Network"
                            Write-LogMessage "[INFO]`r`n`t`tExporting Network Drives to $netDrivesCMDfile"
                            foreach($drive in $drives ){
                                $letter=$drive.PSChildName
                                $remotePath=$drive.GetValue("RemotePath")
                                $netuselet="net use $($letter): '$remotePath' /persistent:yes"
                                Add-Content -Path $netDrivesCMDfile -Value $netuselet
                                Write-LogMessage "`t> $letter`t'$remotePath'"
                            }
                        } else {
                            Write-LogMessage "[INFO]`r`n`t`tNo Network Drives Setup for $UserName"
                        }
                        # get printers
                        if (Test-Path "$HKU_userSID_Path\Printers\ConvertUserDevModesCount\") {
                            $printers = Get-Item -ea SilentlyContinue -Path "$HKU_userSID_Path\Printers\ConvertUserDevModesCount\" | Select-Object Property
                            $defaultPrinters=@("OneNote","OneNote (Desktop)","OneNote for Windows 10","SHRFAX:","Microsoft XPS Document Writer","Microsoft Print to PDF","Fax","Adobe PDF","WinDisc","TIFF Printer","ImagePrinter Pro","NULL")
                            Write-LogMessage "[INFO]`r`n`t`tExporting Printers to $printerListFile"
                            foreach ($printer in $printers.Property) {
                                # Check if the printer is not in the default list and does not contain the computer name
                                if (-not ($defaultPrinters -contains $printer) -and ($printer -notlike "*$env:ComputerName*")) {
                                    # Check if the printer is not redirected
                                    if (-not $($printer -match "\s*\(redirected\s*\d{1,2}\)$")) {
                                        Write-LogMessage "`t`t`t> $printer"
                                        Add-Content -Path $printerListFile -Value $printer
                                    }
                                }
                            }
                        } else {
                            Write-LogMessage "[INFO]`r`n`t`tNo Printers Setup for $UserName"
                        }

                        # Unload user hive
                        Write-LogMessage "[INFO]`r`n`t`tUnloading User Hive $HKU_userSID_Path"
                        Start-Process -FilePath "reg.exe" -ArgumentList "unload `"HKU\$profileListId`"" -NoNewWindow -Wait -RedirectStandardOutput "\NUL"
                        Write-LogMessage "[SUCCESS]`r`n`t`tRegistry Key of ProfileList and HKey_Users - Backup completed"
                    } else {
                        Write-LogMessage "[WARNING]`r`n`t`tRegistry path $HKU_userSID_Path does not exist!`r`n`t`tNo NetworkDrives & Printers exported.`r`n`t`tNo Registry-Key to delete!"
                        Write-LogMessage "[INFO]`r`n`t`tThe abscense of the Registry-Key may be due to the profile being already deleted or not being loaded.`r`n`t`tDepending to System-Configuration, the System may be set up to only load active profiles into HKEY_USERS.`r`n`t`tBy Microsoft Default Configuration, the System only loads active profiles into HKEY_USERS.`r`n`t`tIf the profile is not loaded, the HKU user SID will not be present in the registry.`r`n`r`n`t`tThis data is loaded from the profile folder > NTUSER.DAT.`r`n`t`tIf the ProfileList Key does not exist and/or the User-Folder is deleted/renamed,`r`n`t`tthe Keys will therefore not be present/loaded into the Registry.`r`n"
                        $FailedEXPORTS.Add($HKU_userSID_Path)
                    }

                    # Rename Profile Folder
                    Write-LogMessage "[INFO]`r`n`t`tRenaming Profile Folder $profilePath"
                    try{
                        Rename-Item -Force -Path $profilePath -NewName $profilePathOld
                        Write-LogMessage "[SUCCESS]`r`n`t`tProfile Folder renamed to $profilePathOld"
                    } catch {
                        Write-LogMessage "[ERROR]`r`n`t`tError occurred while deleting profile`r`n$_.Exception.Message"
                    }

                } catch {
                    Write-LogMessage "[ERROR]`r`n`t`tError occurred during profile cleanup"
                    Write-LogMessage "$($_ | Out-String)"
                    break
                }
            } else {
                Write-LogMessage "[WARNING]`r`n`t`tProfile with Username $UserName not found in registry.`r`n`t`tEither the Profile is already deleted or the username mistyped."
            }
            Write-LogMessage "[SUCCESS]`r`n`t`tProfile cleanup completed"
            $endNote = "`r`n`t!!  Any mapped network Drive has been exported to the following file for single-click remapping:`r`n`t`t>   $netDrivesCMDfile`r`n`t`t    (If file is missing, none existed at the moment of Profile-Removal)`r`n`t!!  If existing, Printers will be exported to the following file for reference:`r`n`t`t>   $printerListFile`r`n`r`nLogs & Exports are located in: $tempPath`r`nPlease restart the Device and log in with the User again to create a new Profile.`r`n"
            if ($FailedEXPORTS.Count -gt 0) {
                $FailedEXPORTS = $FailedEXPORTS | ForEach-Object { $_ -replace "HKU:", "HKEY_USERS" }
                Write-LogMessage "[WARNING]`r`n`t`tThe following registry keys could not be Exported and Deleted:`r`n`t`t$([char]0x2022)  $($FailedEXPORTS -join "`r`n`t`t$([char]0x2022)  ")`r`n`r`n`t!!  Please double Check the Paths and, if necessary, Export/Delete them manually before proceeding!$endNote"
            } else {
                Write-LogMessage "[SUCCESS]`r`n`t`tAll Registry-Keys deleted successfully. Profile-Folder renamed successfully.$endNote"
            }
            Remove-PSDrive -Name HKU -Force -ErrorAction SilentlyContinue
            $("`r`nScript Completed.")
            Pause ; $("")
        }
    } else {
        Write-Error "[WARNING]`r`n`t`tUsername cannot be empty"
        break
    }
}
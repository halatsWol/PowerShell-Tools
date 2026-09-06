#####################################################################################
# Script Name:  removeUserProfile.ps1
# Description:  This script removes a user profile from the system and backs up
#               the registry keys associated with the profile. It also exports
#               network drives and printers associated with the user profile.
#
# Author:       Halatschek Wolfram
# Date:         2026-09-06
# Version:      1.1
# Notes:        This script requires administrative privileges to run.
#               The affected User must be logged out before running this script.
#               Please restart the Machine first before use.
#
# Usage:        Run this script in an elevated PowerShell session.
#               PS> <path to script>\removeUserProfile.ps1 [-Delete]
#
#               The script first scans the registry (ProfileList) and C:\Users for
#               existing profiles and lists them, then prompts for the username of the
#               profile to be removed. It will then back up the registry keys, export
#               network drives and printers, and rename the user profile folder.
#
#               By default the profile folder is RENAMED to <Username>-<Date>.old
#               (reversible). Pass -Delete (or type DELETE at the prompt) to permanently
#               delete the profile folder instead (long-path safe, handles paths that
#               exceed the 260-char MAX_PATH limit). Registry keys, network drives and
#               printers are always backed up first, regardless of the chosen method.
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

param(
    # Permanently DELETE the profile folder instead of renaming it to <Username>-<Date>.old
    [switch]$Delete
)

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ( -not $isElevated ) {
    $("") ; Write-Warning "`r`nThis script must be run with administrative privileges. Please restart the script in an elevated PowerShell session.`r`n"
    Pause ; $("")
} else {
    # Scan the registry ProfileList and C:\Users for existing profiles and list them, so the
    # operator can pick a valid username and spot orphaned folders / registry-only entries.
    $profileListScanPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    # Use SystemDrive (always set, e.g. C:) rather than HOMEDRIVE, which can be empty in
    # non-interactive/service sessions and would make the ProfileImagePath match fail.
    $usersRoot = "$env:SystemDrive\Users"
    $builtInFolders = @('Public','Default','Default User','All Users','defaultuser0')
    $profileRows = New-Object System.Collections.Generic.List[System.Object]
    $seenNames = New-Object System.Collections.Generic.List[string]

    Get-ChildItem -LiteralPath $profileListScanPath -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = $_.PSChildName
        $img = (Get-ItemProperty -LiteralPath $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        # Only real interactive user profiles (S-1-5-21-* under \Users); skips SYSTEM/service profiles.
        if ($sid -like 'S-1-5-21-*' -and $img -like "$usersRoot\*") {
            $name = Split-Path $img -Leaf
            $folderExists = Test-Path -LiteralPath $img
            $profileRows.Add([PSCustomObject]@{
                Username     = $name
                InRegistry   = $true
                FolderExists = $folderExists
                Loaded       = Test-Path -LiteralPath "Registry::HKEY_USERS\$sid"
                LastWrite    = if ($folderExists) { (Get-Item -LiteralPath $img).LastWriteTime } else { $null }
                RID          = ($sid -split '-')[-1]
            })
            if (-not $seenNames.Contains($name)) { $seenNames.Add($name) }
        }
    }

    # Folders in C:\Users with no ProfileList entry (orphaned profile folders)
    Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -notin $builtInFolders -and (-not $seenNames.Contains($_.Name)) -and (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0)
    } | ForEach-Object {
        $profileRows.Add([PSCustomObject]@{
            Username     = $_.Name
            InRegistry   = $false
            FolderExists = $true
            Loaded       = $false
            LastWrite    = $_.LastWriteTime
            RID          = ''
        })
    }

    Write-Host ""
    Write-Host "User profiles detected on $env:COMPUTERNAME :" -ForegroundColor Cyan
    if ($profileRows.Count -gt 0) {
        Write-Host (($profileRows | Sort-Object Username | Format-Table Username, InRegistry, FolderExists, Loaded, LastWrite, RID -AutoSize | Out-String).TrimEnd())
        Write-Host "  Legend: InRegistry=False -> orphaned folder (no ProfileList entry); FolderExists=False -> registry entry without a folder." -ForegroundColor DarkGray
    } else {
        Write-Host "  (no non-system user profiles found)" -ForegroundColor DarkGray
    }
    Write-Host ""

    $UserName = Read-Host "Enter the username of the profile to be removed"
    if($UserName -ne "") {
        $currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
        # Anchor on SystemDrive (always set, e.g. C:) rather than HOMEDRIVE, which can be empty in
        # non-interactive/service sessions and would yield drive-relative paths.
        $TempPath = "$env:SystemDrive\_IT-ProfileCleanup\$UserName"+"_ProfileCleanup_$currentDateTime"
        $LogPath = "$TempPath\Logs"
        $cleanupLog = $LogPath+"\cleanupProfileLog_$currentDateTime.log"
        $RegPath = "$TempPath\Registry"
        $profilePath = "$env:SystemDrive\Users\$UserName"
        $profilePathOldName = "$UserName-$currentDateTime.old"
        $profilePathOld = "$env:SystemDrive\Users\$profilePathOldName"
        $regProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $regProfileListPathWOW6432Node = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\ProfileList"
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS > $null
        $netDrivesCMDfile="$TempPath\NetDrives_$UserName.cmd"
        $printerListFile="$TempPath\PrinterList_$UserName.txt"
        $FailedEXPORTS = New-Object System.Collections.Generic.List[System.Object]
        $folderActionSucceeded = $false

        # Removal method: rename to <user>-<date>.old (default, reversible) or permanently delete (opt-in).
        $doDelete = $Delete.IsPresent
        if (-not $doDelete) {
            $methodAnswer = Read-Host "Removal method for '$UserName' - press ENTER to RENAME the profile folder to '$profilePathOldName', or type DELETE to permanently delete it"
            if ($methodAnswer.Trim().ToUpperInvariant() -eq 'DELETE') { $doDelete = $true }
        }
        if ($doDelete) {
            Write-Warning "The profile folder '$profilePath' will be PERMANENTLY DELETED (no .old backup will be kept). Registry keys, network drives and printers are still backed up first."
        }

        function Write-LogMessage {
            param([string]$message)
            $message = "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss.fff"))] - $message"
            Write-Host $message
            $message | Out-File -LiteralPath $cleanupLog -Append
        }

        $user = query user| ForEach-Object {
            $_.trim().insert(22,",").insert(42,",").insert(47,",").insert(56,",").insert(68,",") -replace "\s+","" -replace ">" , ""
        } | ConvertFrom-Csv | Where-Object { $_.USERNAME -eq $USERNAME } | Select-Object USERNAME,ID

        if ($user.username -eq $UserName) {
            Write-Error "`r`nUser '$UserName' is still logged in on $env:computername . Please sign out the user before cleaning the profile."
        }
        else{
            New-Item -Path $TempPath,$LogPath,$RegPath -ItemType Directory -Force >$null

            $profileList = Get-ChildItem -LiteralPath $regProfileListPath | Get-ItemProperty | Where-Object { $_.ProfileImagePath -eq "$usersRoot\$UserName" }
            $profileListId = $profileList.PSChildName
            if( $null -ne $profileListId){
                try{
                    Write-LogMessage "Profile with Username $UserName found in registry"
                    Write-LogMessage "[INFO]`r`n`t`tBacking up Registry - Profile List to $TempPath\Registry"
                    $profileList_SID_PATH = "$regProfileListPath\$profileListId"
                    $profileList_WOW6432Node_SID_PATH = "$regProfileListPathWOW6432Node\$profileListId"
                    $profileList_SID_ITEM = Get-Item -ea SilentlyContinue -LiteralPath $profileList_SID_PATH
                    $profileList_WOW6432Node_SID_ITEM = Get-Item -ea SilentlyContinue -LiteralPath $profileList_WOW6432Node_SID_PATH
                    $outputFilePathProfileList = "$RegPath\ProfileListBackup_$UserName"+"_$currentDateTime.reg"
                    $outputFilePathProfileListWOW6432Node = "$RegPath\ProfileListBackup-WOW6432Node_$UserName"+"_$currentDateTime.reg"

                    ## EXPORT & DELETE Profile List Registry Keys
                    if (Test-Path -LiteralPath $profileList_SID_PATH) {
                        Write-LogMessage "[INFO]`r`n`t`tBacking up Registry - Profile List of $UserName to:`r`n`t`t$outputFilePathProfileList"
                        Start-Process -FilePath "reg.exe" -ArgumentList "export `"$profileList_SID_ITEM`" `"$outputFilePathProfileList`" /y" -NoNewWindow -Wait -RedirectStandardOutput "\NUL"
                        # Check if the export was successful
                        if (Test-Path -LiteralPath $outputFilePathProfileList) {
                            Write-LogMessage "Export successful.`r`n`t`tDeleting $profileList_SID_PATH"
                            Remove-Item -LiteralPath $profileList_SID_PATH -Force -Recurse
                        } else {
                            Write-LogMessage "[ERROR]`r`n`t`tError occurred while exporting Profile List Key of User '$UserName'. Deletion skipped."
                            $FailedEXPORTS.Add($profileList_SID_PATH)
                        }
                    } else {
                        Write-LogMessage "[WARNING]`r`n`t`tRegistry path $profileList_SID_PATH does not exist"
                    }
                    ## EXPORT & DELETE WOW6432Node Profile List Registry Keys
                    if (Test-Path -LiteralPath $profileList_WOW6432Node_SID_PATH) {
                        Write-LogMessage "[INFO]`r`n`t`tBacking up Registry - WOW6432Node Profile List of $UserName to`r`n`t`t$outputFilePathProfileListWOW6432Node"
                        Start-Process -FilePath "reg.exe" -ArgumentList "export `"$profileList_WOW6432Node_SID_ITEM`" `"$outputFilePathProfileListWOW6432Node`" /y" -NoNewWindow -Wait -RedirectStandardOutput "\NUL"
                        # Check if the export was successful
                        if (Test-Path -LiteralPath $outputFilePathProfileListWOW6432Node) {
                            Write-LogMessage "Export successful.`r`n`t`tDeleting $profileList_WOW6432Node_SID_PATH"
                            Remove-Item -LiteralPath $profileList_WOW6432Node_SID_PATH -Force -Recurse
                        } else {
                            Write-LogMessage "[ERROR]`r`n`t`tError occurred while exporting WOW6432Node Profile List Key of User '$UserName'. Deletion skipped."
                            $FailedEXPORTS.Add($profileList_WOW6432Node_SID_PATH)
                        }
                    } else {
                        Write-LogMessage "[WARNING]`r`n`t`tRegistry path $profileList_WOW6432Node_SID_PATH does not exist"
                    }

                    $HKU_userSID_Path = "HKU:\$profileListId"
                    $UserHiveFile = "$env:SystemDrive\Users\$UserName\NTUSER.DAT"

                    # load user hive
                    if (-not $(Test-Path -LiteralPath $HKU_userSID_Path)) {
                        if (Test-Path -LiteralPath $UserHiveFile) {
                            Write-LogMessage "[INFO]`r`n`t`tLoading User Hive $HKU_userSID_Path from $UserHiveFile"
                            Start-Process -FilePath "reg.exe" -ArgumentList "load `"HKU\$profileListId`" `"$UserHiveFile`"" -NoNewWindow -Wait -RedirectStandardOutput "\NUL"
                        } else {
                            Write-LogMessage "[ERROR]`r`n`t`tUser Hive File $UserHiveFile does not exist!"
                        }
                    } else {
                        Write-LogMessage "[INFO]`r`n`t`tUser Hive $UserHiveFile already loaded!"
                    }

                    # Continue only if HKU_SID Exists
                    if (Test-Path -LiteralPath $HKU_userSID_Path) {
                        # get network drives
                        if (Test-Path -LiteralPath "$HKU_userSID_Path\Network") {
                            $drives = Get-ChildItem -LiteralPath "$HKU_userSID_Path\Network"
                            Write-LogMessage "[INFO]`r`n`t`tExporting Network Drives to $netDrivesCMDfile"
                            foreach($drive in $drives ){
                                $letter=$drive.PSChildName
                                $remotePath=$drive.GetValue("RemotePath")
                                $netuselet="net use $($letter): '$remotePath' /persistent:yes"
                                Add-Content -LiteralPath $netDrivesCMDfile -Value $netuselet
                                Write-LogMessage "`t> $letter`t'$remotePath'"
                            }
                        } else {
                            Write-LogMessage "[INFO]`r`n`t`tNo Network Drives Setup for $UserName"
                        }
                        # get printers
                        if (Test-Path -LiteralPath "$HKU_userSID_Path\Printers\ConvertUserDevModesCount\") {
                            $printers = Get-Item -ea SilentlyContinue -LiteralPath "$HKU_userSID_Path\Printers\ConvertUserDevModesCount\" | Select-Object Property
                            $defaultPrinters=@("OneNote","OneNote (Desktop)","OneNote for Windows 10","SHRFAX:","Microsoft XPS Document Writer","Microsoft Print to PDF","Fax","Adobe PDF","WinDisc","TIFF Printer","ImagePrinter Pro","NULL")
                            Write-LogMessage "[INFO]`r`n`t`tExporting Printers to $printerListFile"
                            foreach ($printer in $printers.Property) {
                                # Check if the printer is not in the default list and does not contain the computer name
                                if (-not ($defaultPrinters -contains $printer) -and ($printer -notlike "*$env:ComputerName*")) {
                                    # Check if the printer is not redirected
                                    if (-not $($printer -match "\s*\(redirected\s*\d{1,2}\)$")) {
                                        Write-LogMessage "`t`t`t> $printer"
                                        Add-Content -LiteralPath $printerListFile -Value $printer
                                    }
                                }
                            }
                        } else {
                            Write-LogMessage "[INFO]`r`n`t`tNo Printers Setup for $UserName"
                        }

                        # Unload user hive.
                        # The reads above went through the HKU: PowerShell provider, which caches
                        # open registry handles. Those handles keep the hive loaded, so reg.exe unload
                        # fails with "Access is denied"; the hive then stays mounted, NTUSER.DAT remains
                        # locked, and the profile-folder rename fails. Force a GC to release the cached
                        # handles first, verify the unload actually took effect, and retry once if not.
                        Write-LogMessage "[INFO]`r`n`t`tUnloading User Hive $HKU_userSID_Path"
                        [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
                        Start-Process -FilePath "reg.exe" -ArgumentList "unload `"HKU\$profileListId`"" -NoNewWindow -Wait -RedirectStandardOutput "\NUL"
                        if (Test-Path -LiteralPath $HKU_userSID_Path) {
                            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
                            Start-Sleep -Milliseconds 500
                            Start-Process -FilePath "reg.exe" -ArgumentList "unload `"HKU\$profileListId`"" -NoNewWindow -Wait -RedirectStandardOutput "\NUL"
                        }
                        if (Test-Path -LiteralPath $HKU_userSID_Path) {
                            Write-LogMessage "[WARNING]`r`n`t`tUser Hive $HKU_userSID_Path could not be unloaded.`r`n`t`tNTUSER.DAT remains locked - the profile-folder rename will likely fail. Unload the hive manually (reg unload HKU\$profileListId) or reboot, then re-run."
                            $FailedEXPORTS.Add($HKU_userSID_Path)
                        } else {
                            Write-LogMessage "[SUCCESS]`r`n`t`tRegistry Key of ProfileList and HKey_Users - Backup completed"
                        }
                    } else {
                        Write-LogMessage "[WARNING]`r`n`t`tRegistry path $HKU_userSID_Path does not exist!`r`n`t`tNo NetworkDrives & Printers exported.`r`n`t`tNo Registry-Key to delete!"
                        Write-LogMessage "[INFO]`r`n`t`tThe abscense of the Registry-Key may be due to the profile being already deleted or not being loaded.`r`n`t`tDepending to System-Configuration, the System may be set up to only load active profiles into HKEY_USERS.`r`n`t`tBy Microsoft Default Configuration, the System only loads active profiles into HKEY_USERS.`r`n`t`tIf the profile is not loaded, the HKU user SID will not be present in the registry.`r`n`r`n`t`tThis data is loaded from the profile folder > NTUSER.DAT.`r`n`t`tIf the ProfileList Key does not exist and/or the User-Folder is deleted/renamed,`r`n`t`tthe Keys will therefore not be present/loaded into the Registry.`r`n"
                        $FailedEXPORTS.Add($HKU_userSID_Path)
                    }

                    # Remove Profile Folder (rename to .old by default, or permanently delete when opted in)
                    if ($doDelete) {
                        Write-LogMessage "[INFO]`r`n`t`tDeleting Profile Folder $profilePath"
                        try {
                            if (Test-Path -LiteralPath $profilePath) {
                                # Delete robustly, including children whose paths exceed the 260-char
                                # MAX_PATH limit (Remove-Item -Recurse fails on those): first empty the
                                # folder by mirroring an empty directory over it with robocopy, which uses
                                # the long-path API, then remove the now-empty folder.
                                $emptyDir = Join-Path $env:TEMP ("rup_empty_" + [guid]::NewGuid().ToString('N'))
                                New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
                                try {
                                    & robocopy.exe $emptyDir $profilePath /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS /NC /NS /NP > $null 2>&1
                                    $roboExit = $LASTEXITCODE
                                    # robocopy exit codes 0-7 are success; 8+ means at least one failure.
                                    if ($roboExit -ge 8) { throw "robocopy could not empty '$profilePath' (exit code $roboExit)." }
                                    Remove-Item -LiteralPath $profilePath -Recurse -Force -ErrorAction Stop
                                } finally {
                                    Remove-Item -LiteralPath $emptyDir -Recurse -Force -ErrorAction SilentlyContinue
                                }
                                $folderActionSucceeded = $true
                                Write-LogMessage "[SUCCESS]`r`n`t`tProfile Folder deleted: $profilePath"
                            } else {
                                $folderActionSucceeded = $true
                                Write-LogMessage "[WARNING]`r`n`t`tProfile Folder $profilePath does not exist - nothing to delete."
                            }
                        } catch {
                            Write-LogMessage "[ERROR]`r`n`t`tError occurred while deleting profile folder`r`n$($_.Exception.Message)"
                        }
                    } else {
                        Write-LogMessage "[INFO]`r`n`t`tRenaming Profile Folder $profilePath"
                        try {
                            Rename-Item -Force -LiteralPath $profilePath -NewName $profilePathOldName -ErrorAction Stop
                            $folderActionSucceeded = $true
                            Write-LogMessage "[SUCCESS]`r`n`t`tProfile Folder renamed to $profilePathOld"
                        } catch {
                            Write-LogMessage "[ERROR]`r`n`t`tError occurred while renaming profile folder`r`n$($_.Exception.Message)"
                        }
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
            if ($folderActionSucceeded) {
                $folderStatus = if ($doDelete) { "Profile-Folder deleted successfully." } else { "Profile-Folder renamed successfully." }
            } else {
                $folderStatus = if ($doDelete) { "Profile-Folder could NOT be deleted - please check the [ERROR] above and remove it manually." }
                                else { "Profile-Folder could NOT be renamed - please check the [ERROR] above and rename/remove it manually." }
            }
            if ($FailedEXPORTS.Count -gt 0) {
                $FailedEXPORTS = $FailedEXPORTS | ForEach-Object { $_ -replace "HKU:", "HKEY_USERS" }
                Write-LogMessage "[WARNING]`r`n`t`tThe following registry keys could not be Exported and Deleted:`r`n`t`t$([char]0x2022)  $($FailedEXPORTS -join "`r`n`t`t$([char]0x2022)  ")`r`n`r`n`t`t$folderStatus`r`n`r`n`t!!  Please double Check the Paths and, if necessary, Export/Delete them manually before proceeding!$endNote"
            } elseif ($folderActionSucceeded) {
                Write-LogMessage "[SUCCESS]`r`n`t`tAll Registry-Keys deleted successfully. $folderStatus$endNote"
            } else {
                Write-LogMessage "[WARNING]`r`n`t`tAll Registry-Keys deleted successfully, but $folderStatus$endNote"
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
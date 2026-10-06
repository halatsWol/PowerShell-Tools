# TempDataCleanup PowerShell Module

## Overview

The `TempDataCleanup` PowerShell module provides a function to clean up temporary files from user profiles and system folders. It can be executed on both local and remote computers, allowing for flexible management of temporary data in user environments. This module is useful for automating the removal of temporary files to free up disk space and enhance system performance.

## Functionality
### `Invoke-TempDataCleanup`

The primary function of this module is `Invoke-TempDataCleanup`, which removes temporary files from user profiles and, optionally, system folders, system logs, and software-distribution content caches (ConfigMgr/SCCM, Windows Update, Adaptiva, Intune). This function can be executed on the local computer or remotely on other systems. Deletion is guarded and long-path safe; items that are locked in the system folders and content caches are scheduled for deletion on the next reboot (a restart finishes those), while locked user-profile files are skipped.

#### Parameters

- **`-ComputerName`** (Optional): Specifies the name of the computer to run the cleanup on. Accepts PipeLine and Array input. If Null/Empty String ("") (except via Pipeline), or whitespace it will default to Local Host. With more than one computer, all devices are cleaned in parallel background jobs; instead of step output, each device prints one line (name, additional and total free space, or the failure reason) when it has finished. Duplicates and local aliases are cleaned only once.
- **`-IncludeSystemData`** (Optional): When this switch is provided, the cleanup will also include system folders such as the Windows `Temp` and `SoftwareDistribution\Download` folders. `Prefetch` is not cleared: Windows maintains it itself, and clearing it only slows down the next start of every application. The Windows Update and BITS services are force-stopped while `SoftwareDistribution\Download` is emptied (an interrupted download is simply fetched again) and started again afterwards; an update installation in progress is never interrupted but waited for up to 10 minutes; if it is still running then, the folder's contents are deleted at the next boot instead. Together with `-ContentCacheCleanup`, that folder is emptied once, by the content cache cleanup.
- **`-IncludeSystemLogs`** (Optional): When this switch is provided, the cleanup will also include system log files and reporting folders such as `C:\Windows\Logs`, `C:\Windows\Minidump`, and the Windows Error Reporting queues. Logs held open by Windows services are scheduled for deletion on the next reboot.
- **`-ContentCacheCleanup`** (Optional, alias `-IncludeCCMCache`): When this switch is provided, the cleanup will also clear the content/download caches of the software-distribution systems detected on the device: ConfigMgr/SCCM (`ccmcache`), Windows Update (`SoftwareDistribution\Download`), Adaptiva OneSite, and the Intune Management Extension. The ConfigMgr cache is relocation-aware, so a moved cache (e.g. `D:\SCCMCache`) is found instead of assuming `C:\Windows\ccmcache`.
- **`-IncludeBrowserData`** (Optional): When this switch is provided, the cleanup will also include the browser caches of Edge, Chrome, Firefox, Opera, Vivaldi, Brave and IE. Saved site data (Firefox site storage, IE cookies) is only cleared after confirming a prompt, or with `-ConfirmWarning`.
- **`-IncludeMSTeamsCache`** (Optional): When this switch is provided, the cleanup will also include the Microsoft Teams cache folders. A running Teams (new Teams, any signed-in user) is closed first, because its cache is locked; the users concerned are named in a warning and in the log.
- **`-IncludeIconCache`** (Optional): When this switch is used, the User Icon & ThumbCache will also be cleaned up.
- **`-IncludeAllPackages`** (Optional): When this switch is used, all packages in `$env:localappdata\Packages\` will be cleaned up.
- **`-LowDisk`** (Optional): Performs a System Cleanup using CleanMgr with basic settings. Additionally performs  `IncludeSystemData`, `ContentCacheCleanup` and `IncludeIconCache`
- **`-VeryLowDisk`** (Optional): Performs a System Cleanup as with 'LowDisk' with advanced settings. Additionally clears all Recycle-Bins and runs also `AutoClean`
- **`-AutoClean`** (Optional): Executes CleanMgr Upgrade Cleanup additional to `IncludeSystemData`, `ContentCacheCleanup` and `IncludeIconCache`
- **`-ConfirmWarning`** (Optional): Bypass the confirmation prompts of `VeryLowDisk`, `IncludeAllPackages` and the browser site data of `IncludeBrowserData`, all answered with yes (for unattended runs)
- **`-init`** (Optional): When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
- **`-ThrottleLimit`** (Optional): Maximum number of devices cleaned at the same time when more than one computer is given (1-100, default 10). Further devices start as soon as a running one has finished.
- **`-DeviceTimeoutMinutes`** (Optional): With more than one computer, the maximum run time per device (5-1440 minutes, default 90). A device still running after that is stopped and reported as failed.
- **`-Quiet`** (Optional): Suppresses all console output (progress, summary lines, warnings); only errors and the returned result objects remain, e.g. for scheduled or scripted runs. Confirmation prompts are still shown, use `-ConfirmWarning` to bypass them.
- **`-Credentials`** (Optional): when Specified, this will prompt for User-Credentials that will be used for the Remote-Access
This can be used e.g. by passing on a credential Object `-Credentials (Get-Credential)`


#### Example

```PowerShell
# Clean up temporary files from user profiles on the local computer
Invoke-TempDataCleanup -ComputerName "localhost"

# Clean up temporary files from user profiles on a remote computer
Invoke-TempDataCleanup -ComputerName "Computer01"

# Clean up temporary files from user profiles on a Computer using Pipeline (will not default to localhost if $Null or empty)
"comp1","comp2","comp3" | Invoke-TempDataCleanup

# Clean up temporary files from user profiles on a Computer using Array (will default to localhost if element is null or empty "")
Invoke-TempDataCleanup -ComputerName comp1,comp2,"",comp3

# Perform a cleanup (user temp and system temp files) on the local computer
Invoke-TempDataCleanup -ComputerName "localhost" -IncludeSystemData

# Perform a full cleanup (user temp, Browser Cache, MSTeams Cache and system temp files) on a remote computer
Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData -IncludeBrowserData -IncludeMSTeamsCache

# Clean user/system temp, system logs, and software-distribution content caches (ConfigMgr/WU/Adaptiva/Intune)
# Locked system/cache items are scheduled for deletion on the next reboot - restart to finish.
Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData -IncludeSystemLogs -ContentCacheCleanup

# Clean a device list 20 at a time and export the devices that failed, with their reason
$results = Invoke-TempDataCleanup -ComputerName (Get-Content .\devices.txt) -IncludeSystemData -ThrottleLimit 20
$results | Where-Object Status -eq 'Failed' | Select-Object ComputerName, Message | Export-Csv .\failed.csv -NoTypeInformation
```

#### Output

One `TempDataCleanup.Result` object per device is returned after all devices have finished: `ComputerName`, `Status` (`Completed` / `Failed`), `AdditionalFreeGB`, `TotalFreeGB`, `RestartRequired` (locked files were queued for deletion on the next restart; the closing restart reminder names only these devices), `Message` (failure reason, steps that failed while the others still ran, or note) and `LogFile` (the copied log for remote devices, else the log on the device). The console shows the first four as a table; the per-device summary lines are printed as before. A single device also prints its log path; with several devices the start banner says where the logs will be (the device folders below `LocalTargetPath`, and the local computer's own temp folder). With `-Quiet` nothing is printed and only the objects are returned:

```PowerShell
$results = Invoke-TempDataCleanup -ComputerName (Get-Content .\devices.txt) -IncludeSystemData -Quiet
```

## Requirements

- **Windows PowerShell**: This module relies on PowerShell's remoting capabilities. Ensure that PowerShell is available on both the local and remote machines.
- **WinRM**: Windows Remote Management (WinRM) must be enabled and properly configured on the remote machine to allow for remote execution of commands.
- **Administrative Privileges**: Some operations, particularly when cleaning system folders, may require administrative privileges on the target machine.
- **Network Configuration**: Additional configuration may be required if using IP addresses instead of computer names, especially in environments where DNS resolution is limited.

## Notes

- This script is provided as-is and is not supported by Microsoft.
- Test thoroughly before using on production systems as improper use may cause data loss or system instability.
- Ensure you understand the consequences before making system changes or deleting files.
- Deletion is guarded (it refuses drive-root / Windows / System32 targets) and long-path safe. Locked files under the **system** folders (`-IncludeSystemData` / `-IncludeSystemLogs`) and the **content caches** (`-ContentCacheCleanup`) are scheduled for deletion on the next reboot, so **restart the device to finish**. Locked user-profile files are skipped (best-effort) and are never queued for boot-time deletion.
- All targets are built from the Windows, ProgramData and profile folders resolved on the target device (never from hard-coded drive letters). A folder that cannot be resolved there skips its targets instead of falling back to a drive root.
- The default run only clears plain temp/installer package caches. App data kept in `LocalCache` by apps like Outlook for Windows, Photos, Snipping Tool or Camera is left alone unless `-IncludeAllPackages` is used.
- CleanMgr (`-LowDisk` / `-VeryLowDisk`) only completes in an interactive desktop session. Without one (remote/WinRM, SYSTEM) native equivalents are used instead: file-based CleanMgr options are applied from their own Windows definition, Delivery Optimization via `Delete-DeliveryOptimizationCache`, Update Cleanup via DISM `/StartComponentCleanup`, and Device Driver Packages by removing older, unused driver versions. Options without a native equivalent (Windows setup/upgrade leftovers, legacy IE/ActiveX caches) are skipped and logged.
- The log is written in CMTrace format (same layout as the Repair-System module) to `<SystemDrive>\_IT-temp` on the target. For remote runs the log (and the verbose transcript with `-Verbose`) is copied to `C:\remote-Files\<Computer>` on the caller, and only those files are then removed from the target; the folder and anything else in it are left untouched.

 :bangbang: If in Windows Terminal Settings, Terminal is set as Default Terminal Application, Powershell 5.1 may throw an error instead of prompting for User Credentials. As workaround you can pass on credentials using the `Get-CredentialObject` from the [`CredentialHander-Module`](https://github.com/halatsWol/PowerShell-Tools/tree/main/modules/CredentialHandler)

  Example:
 ```Powershell
 Invoke-TempDataCleanup -Computername myRemoteDevice1 -Credentials (Get-CredentialObject)
 ```

## Author

- **Author**: Wolfram Halatschek
- **Contact**: dev@kMarflow.com
- **Date**: 2026-08-15

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING IT.**
- **DO NOT RUN THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**
- **DELETING SYSTEM FILES WITHOUT UNDERSTANDING THEIR FUNCTION CAN CAUSE DATA LOSS OR SYSTEM INSTABILITY.**
- **NEVER MAKE CHANGES TO SYSTEM SETTINGS OR DELETE FILES WITHOUT PROPER AUTHORIZATION.**
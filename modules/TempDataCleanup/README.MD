# Shortcuts PowerShell Module

## Overview

The `TempDataCleanup` PowerShell module provides a function to clean up temporary files from user profiles and system folders. It can be executed on both local and remote computers, allowing for flexible management of temporary data in user environments. This module is useful for automating the removal of temporary files to free up disk space and enhance system performance.

## Functionality
### `Invoke-TempDataCleanup`

The primary function of this module is `Invoke-TempDataCleanup`, which removes temporary files from user profiles and, optionally, system folders. This function can be executed on the local computer or remotely on other systems. It also offers the flexibility to include system directories when performing a full cleanup.

#### Parameters

- **`-ComputerName`** (Optional): Specifies the name of the computer to run the cleanup on. Accepts PipeLine and Array input. If Null/Empty String ("") (except via Pipeline), or whitespace it will default to Local Host.
- **`-IncludeSystemData`** (Optional): When this switch is provided, the cleanup will also include system folders such as the Windows `Temp`, `Prefetch`, and `SoftwareDistribution` folders.
- **`-IncludeCCMCache`** (Optional): When this switch is provided, the cleanup will also include the Configuration Management Cache folder, if it exists.
- **`-IncludeBrowserData`** (Optional): When this switch is provided, the cleanup will also include Browser cache of MS Edge, Mozilla Firefox and Google Chrome
- **`-IncludeMSTeamsCache`** (Optional): When this switch is provided, the cleanup will also include the Microsoft Teams cache folders.
- **`-IncludeIconCache`** (Optional): When this switch is used, the User Icon & ThumbCache will also be cleaned up.
- **`-IncludeAllPackages`** (Optional): When this switch is used, all packages in `$env:localappdata\Packages\` will be cleaned up.
- **`-LowDisk`** (Optional): Performs a System Cleanup using CleanMgr with basic settings. Additionally performs  `IncludeSystemData`, `IncludeCCMCache` and `IncludeIconCache`
- **`-VeryLowDisk`** (Optional): Performs a System Cleanup as with 'LowDisk' with advanced settings. Additionally clears all Recycle-Bins and runs also `AutoClean`
- **`-AutoClean`** (Optional): Executes CleanMgr Upgrade Cleanup additional to `IncludeSystemData`, `IncludeCCMCache` and `IncludeIconCache`
- **`-ConfirmWarning`** (Optional): Bypass Confirmation when using `VeryLowDisk`
- **`-init`** (Optional): When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
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

 :bangbang: If in Windows Terminal Settings, Terminal is set as Default Terminal Application, Powershell 5.1 may throw an error instead of prompting for User Credentials. As workaround you can pass on credentials using the `Get-CredentialObject` from the [`CredentialHander-Module`](https://github.com/halatsWol/PowerShell-Tools/tree/main/modules/CredentialHandler)

  Example:
 ```Powershell
 Invoke-TempDataCleanup -Computername myRemoteDevice1 -Credentials (Get-CredentialObject)
 ```

## Author

- **Author**: Wolfram Halatschek
- **Contact**: dev@kMarflow.com
- **Date**: 2025-08-20

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING IT.**
- **DO NOT RUN THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**
- **DELETING SYSTEM FILES WITHOUT UNDERSTANDING THEIR FUNCTION CAN CAUSE DATA LOSS OR SYSTEM INSTABILITY.**
- **NEVER MAKE CHANGES TO SYSTEM SETTINGS OR DELETE FILES WITHOUT PROPER AUTHORIZATION.**
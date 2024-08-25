# Cleanup-Profile Module

## :bangbang: ``Module not working yet! Do not execute since it will cause damages``
This warning will be removed once development has advanced further

## Overview

The `Cleanup-Profile` PowerShell module provides a function to cleanup defective User-Profiles remotely by running various Task and Commands. It allows for extensive repair capabilities, including scanning and restoring system files, component cleanup, and Windows Update cleanup on a remote machine. The results are logged on the remote computer and are transferred to the local machine upon completion.
By default installer CMD-Files to easily set up previously mapped Network-Drives and Printers

## Functionality

### `Cleanup-RemoteProfile`

This function performs the following tasks on a specified remote computer:

- Pings the remote machine to check its availability.
- fetches mapped Network-Drives and creates a ``install-NetDrives.cmd``-file.
- fetches installed printers.
- Creates Backup of Registry for the user
- Performs Cleanup of Registry
- Renames User Profile-Folder to ``<UserName>.BAK``.

- Backup data will be Stored on Machine in ``C:\Cleanup-Profile\<UserName>\``

#### Parameters

- **`-ComputerName`** (Mandatory): The hostname or IP address of the remote computer.
- **`-UserName`** (Mandatory): The Username which shall be cleaned up
- **`-noPrinters`** (Optional): When specified, information about installed Printers will not be fetched.
- **`-noNetDrives`** (Optional): When specified, mapped network drives will not be fetched. The ``install-NetDrives.cmd``-file will not be created.
- **`-Quiet`** (Optional): Suppresses console output on the local machine. The output is always logged to files on the remote machine.
- **`-ForceLogout`** (Optional): logs out the Account on the maching if it is logged in


#### Examples

```PowerShell
# cleanup profile
Cleanup-RemoteProfile -ComputerName <remote-device> -UserName <UserName>

# cleanup profile in quiet mode
Cleanup-RemoteProfile -ComputerName <remote-device> -UserName <UserName> -Quiet

# cleanup profile not scanning for mapped Network Drives
Cleanup-RemoteProfile -ComputerName <remote-device> -UserName <UserName> -noNetDrives

```


#### Requirements

- **WinRM**: Must be enabled and configured on the remote computer.
- **Administrative Privileges**: Running this script may require administrative privileges on the remote computer.
    For this, Powershell must be started as the user, which has administrative privileges on the remote computer.


### `Cleanup-LocalProfile`

This function performs the same tasks as [Cleanup-RemoteProfile](#Cleanup-RemoteProfile) but only on the local machine. Therefore the `-ComputerName` parameter is not available

Additionally `WinRM` is not required for Cleanup-LocalProfile

## Notes

- This script is provided as-is and is not supported by Microsoft.
- Test thoroughly before using on production systems as improper use may cause data loss or system instability.
- Ensure you understand the consequences before making system changes or deleting files.
- If `-ComputerName` is the executing device (localhost/Devicename/Devices IP Addresses), `-UserName` cannot be the executing User

## Author

- **Author**: Wolfram Halatschek
- **Contact**: halatschek.wolfram@gmail.com
- **Date**: August 25, 2024

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **NEVER MAKE SYSTEM CHANGES WITHOUT AUTHORIZATION.**
- **DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**

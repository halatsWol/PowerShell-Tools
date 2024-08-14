# Repair-System Module

## Overview

The `Repair-System` PowerShell module provides a function to repair Windows systems remotely by running System File Checker (SFC) and Deployment Imaging Service and Management Tool (DISM) commands. It allows for extensive repair capabilities, including scanning and restoring system files, component cleanup, and Windows Update cleanup on a remote machine. The results are logged on the remote computer and can be optionally transferred to the local machine.

## Functionality

### `Repair-System`

This function performs the following tasks on a specified remote computer:

- Pings the remote machine to check its availability.
- Executes `sfc /scannow` to check and repair system files.
- Optionally, executes `DISM /Online /Cleanup-Image /ScanHealth` and `DISM /Online /Cleanup-Image /RestoreHealth` to repair the Windows image.
- Optionally, performs component cleanup and Windows Update cleanup.
- Logs the results on the remote machine and optionally shows them on the local console.
- Transfers the logs and relevant system files to the local machine.

### Parameters

- **`-ComputerName`** (Mandatory): The hostname or IP address of the remote computer.
- **`-sfcOnly`** (Optional): When specified, only the `sfc /scannow` command is executed, skipping the `DISM` commands.
- **`-Quiet`** (Optional): Suppresses console output on the local machine. The output is logged to files on the remote machine instead.
- **`-IncludeComponentCleanup`** (Optional): Performs `DISM /Online /Cleanup-Image /AnalyzeComponentStore` and, if recommended, `DISM /Online /Cleanup-Image /StartComponentCleanup`.
- **`-WindowsUpdateCleanup`** (Optional): Renames the `SoftwareDistribution` and `catroot2` folders after stopping related services, effectively performing a Windows Update cleanup.

### Examples

```powershell
# Run SFC and DISM on the remote computer
Repair-System -ComputerName <remote-device>

# Run only SFC on the remote computer
Repair-System -ComputerName <remote-device> -sfcOnly

# Run SFC and DISM on the remote computer with no console output
Repair-System -ComputerName <remote-device> -Quiet

# Analyze and clean up the component store
Repair-System -ComputerName <remote-device> -IncludeComponentCleanup

# Perform Windows Update cleanup
Repair-System -ComputerName <remote-device> -WindowsUpdateCleanup

## Requirements

- **WinRM**: Must be enabled and configured on the remote computer.
- **Administrative Privileges**: Running this script may require administrative privileges on the remote computer.

## Notes

- This script is provided as-is and is not supported by Microsoft.
- Test thoroughly before using on production systems as improper use may cause data loss or system instability.
- Ensure you understand the consequences before making system changes or deleting files.

## Author

- **Author**: Wolfram Halatschek
- **Contact**: halatschek.wolfram@gmail.com
- **Date**: August 14, 2024

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **NEVER MAKE SYSTEM CHANGES WITHOUT AUTHORIZATION.**
- **DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**

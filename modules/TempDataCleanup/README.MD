# Shortcuts PowerShell Module

## Overview

The `TempDataCleanup` PowerShell module provides a function to clean up temporary files from user profiles and system folders. It can be executed on both local and remote computers, allowing for flexible management of temporary data in user environments. This module is useful for automating the removal of temporary files to free up disk space and enhance system performance.

## Functionality
### `Invoke-TempDataCleanup`

The primary function of this module is `Invoke-TempDataCleanup`, which removes temporary files from user profiles and, optionally, system folders. This function can be executed on the local computer or remotely on other systems. It also offers the flexibility to include system directories when performing a full cleanup.

#### Parameters

- **`-ComputerName`** (Mandatory): Specifies the name of the computer to run the cleanup on. The default value is the local computer (`localhost`).
- **`-Full`** (Optional): When this switch is provided, the cleanup will also include system folders such as the Windows `Temp`, `Prefetch`, and `SoftwareDistribution` folders as well as Browser cache of MS Edge, Mozilla Firefox and Google Chrome.

#### Example

```PowerShell
# Clean up temporary files from user profiles on the local computer
Invoke-TempDataCleanup -ComputerName "localhost"

# Clean up temporary files from user profiles on a remote computer
Invoke-TempDataCleanup -ComputerName "Computer01"

# Perform a full cleanup (user and system temp files) on the local computer
Invoke-TempDataCleanup -ComputerName "localhost" -Full

# Perform a full cleanup (user and system temp files) on a remote computer
Invoke-TempDataCleanup -ComputerName "Computer01" -Full
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

## Author

- **Author**: Wolfram Halatschek
- **Contact**: halatschek.wolfram@gmail.com
- **Date**: October 06, 2024

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING IT.**
- **DO NOT RUN THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**
- **DELETING SYSTEM FILES WITHOUT UNDERSTANDING THEIR FUNCTION CAN CAUSE DATA LOSS OR SYSTEM INSTABILITY.**
- **NEVER MAKE CHANGES TO SYSTEM SETTINGS OR DELETE FILES WITHOUT PROPER AUTHORIZATION.**
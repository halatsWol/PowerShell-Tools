# RepairSystem Module

## Overview

The `RepairSystem` PowerShell module provides a function to repair Windows systems remotely by running System File Checker (SFC) and Deployment Imaging Service and Management Tool (DISM) commands. It allows for extensive repair capabilities, including scanning and restoring system files, component cleanup, and Windows Update cleanup on a remote machine. The results are logged on the remote computer and are transferred to the local machine upon completion.

## Functionality

### `Repair-System`

This function performs the following tasks on a specified computer (either locally or a Remote-Device):

- Pings the remote machine to check its availability.
- Executes `sfc /scannow` to check and repair system files.
- Optionally, executes `DISM /Online /Cleanup-Image /ScanHealth` and `DISM /Online /Cleanup-Image /RestoreHealth` to repair the Windows image.
- Optionally, performs Component Store cleanup and Windows Update Cache cleanup.
- Logs the results on the remote machine and optionally shows them on the local console.
- Transfers the logs and relevant system files to the local machine.

#### Parameters

- **`-ComputerName`** (optional): The hostname or IP address of the remote computer, If not provided, the command will be run locally, if provided, it will run on the specified remote-device.
- **`-remoteShareDrive`** (Optional):The ShareDrive of the Remote-Device on which Windows is installed. If non is provided, Default-Value 'C$' will be used
    The Command `Repair-System -ComputerName SomeDevice -remoteShareDrive D$` will result in Network-Path *\\\\SomeDevice\\D$\\*
- **`-noSfc`** (Optional): When specified, `sfc /scannow` command will be skipped.
- **`-noDism`** (Optional): When specified, all DISM commands will be skipped. This cannot be used in combination with `-IncludeComponentCleanup`.
- **`-Quiet`** (Optional): Suppresses console output on the local machine. The output is always logged to files on the remote machine.
- **`-IncludeComponentCleanup`** (Optional): Analyzes and if recommended cleans up the Windows Component Store. This cannot be used in combination with `-noDism`.
- **`-WindowsUpdateCleanup`** (Optional): Renames the `SoftwareDistribution` and `catroot2` folders after stopping related services, effectively performing a Windows Update Cache cleanup. Additionally runs Windows Update and BITS Diagnostics.
- **`-sccmCleanup`** (Optional): deletes the contents of the CCMCache folder and SoftwareDistribution\Download folder
- **`-KeepLogs`** (Optional): log files will be kept on the remote Device, but still be copied to the Client
- **`-noCopy`** (Optional): log files will not be copied to the Client. this will automatically use '-KeepLogs'
- **`-init`** (Optional): When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
- **`-Credentials`** (Optional): when Specified, this will prompt for User-Credentials that will be used for the Remote-Access
This can be used e.g. by passing on a credential Object `-Credentials (Get-Credential)`

#### Examples

```PowerShell
# Run SFC and DISM on the remote computer
Repair-System -ComputerName <remote-device>

# Run only SFC on the remote computer
Repair-System -ComputerName <remote-device> -noDism

# Run SFC and DISM on the remote computer with no console output
Repair-System -ComputerName <remote-device> -Quiet

# Analyze and clean up the component store
Repair-System -ComputerName <remote-device> -IncludeComponentCleanup

# Perform Windows Update cleanup
Repair-System -ComputerName <remote-device> -WindowsUpdateCleanup
```


#### Requirements

- **WinRM**: Must be enabled and configured on the remote computer, to be able to work with `-ComputerName`.
- **Administrative Privileges**: Running this script requires administrative privileges on the intended computer.
    For running this for a remote device, Powershell must be started as the user, which has administrative privileges on the remote computer.



## Notes

- This script is provided as-is and is not supported by Microsoft.
- Test thoroughly before using on production systems as improper use may cause data loss or system instability.
- Ensure you understand the consequences before making system changes or deleting files.


 :bangbang: If in Windows Terminal Settings, Terminal is set as Default Terminal Application, Powershell 5.1 may throw an error instead of prompting for User Credentials. As workaround you can pass on credentials using the `Get-CredentialObject` from the [`CredentialHander-Module`](https://github.com/halatsWol/PowerShell-Tools/tree/main/modules/CredentialHandler)

 Example:
 ```Powershell
 Repair-System -Computername myRemoteDevice1 -Credentials (Get-CredentialObject)
 ```

## Author

- **Author**: Wolfram Halatschek
- **Contact**: wolfram@kMarflow.com
- **Date**: 2025-05-31

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **NEVER MAKE SYSTEM CHANGES WITHOUT AUTHORIZATION.**
- **DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**

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
- **`-ChangeTimeout`** (Optional) use decimal value to change when DISM/SFC and Windows Update Diagnostics will timeout (value `-ChangeTimeout 2` will double the time, `-ChangeTimeout 0.5` will half it).
Range = 0.25 - 10.0
- **`-sccmCleanup`** (Optional): deletes the contents of the CCMCache folder and SoftwareDistribution\Download folder
- **`-KeepLogs`** (Optional): log files will be kept on the remote Device, but still be copied to the Client
- **`-noCopy`** (Optional): log files will not be copied to the Client. this will automatically use '-KeepLogs'
- **`-init`** (Optional): When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
- **`-Credentials`** (Optional): when Specified, this will prompt for User-Credentials that will be used for the Remote-Access
This can be used e.g. by passing on a credential Object `-Credentials (Get-Credential)`
- **`-RepairCCM`** (Optional): When specified, the CCMRepair.exe will be executed. This will also copy the ccmsetup.log to the local Temp-Path.
- **`-AnalyzeExitCode`** (Optional): Decodes a previously produced exit code (see Exit Codes below) into a human-readable, per-step breakdown. Cannot be combined with any other parameter and never performs any repair actions.

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

# Decode a previously produced exit code (runs standalone, no repair actions)
Repair-System -AnalyzeExitCode "0000000000"
```


#### Requirements

- **WinRM**: Must be enabled and configured on the remote computer, to be able to work with `-ComputerName`.
- **Administrative Privileges**: Running this script requires administrative privileges on the intended computer.
    For running this for a remote device, Powershell must be started as the user, which has administrative privileges on the remote computer.

#### Exit Codes

`$LASTEXITCODE` after `Repair-System` runs is a conventional single digit, suitable for scripts/CI/batch to branch on:

| Code | Meaning |
|---|---|
| 0 | Full success - every step succeeded or was not requested. |
| 1 | The run completed (possibly only partially, e.g. a mid-run connection loss) but one or more steps reported a problem. |
| 2 | A startup/fatal error meant no repair steps ran at all (bad parameters, target unreachable, WinRM failure, not elevated, config error, conflicting parameters). |

The full, lossless detail behind that digit is printed to the console as `Repair-System Detailed Exit Code: <code>` and also stored in `$global:RepairSystemDetailedExitCode` (mirroring the ExitCode/DetailedExitCode pattern used elsewhere, e.g. ConfigMgr), so it remains available even though `$LASTEXITCODE` itself is now just a plain digit.

The detailed code is made up of one field per step, concatenated in a fixed position order (no reordering, no delimiters). Each field starts with a single hex digit (`0`-`8`) giving how many hex digits follow (`0` alone means the step's value is `0`), then those digits (if any) are the step's real return value (DISM/SFC's own exit code, or the step's own small result code), so no detail is lost. Because the length prefix marks where each field ends, no separators are needed, and a fully successful run collapses to `0000000000` (ten `0` characters) instead of a long fixed-width string.

| Position | Step |
|---|---|
| 0 | Startup / Pre-Flight Checks (parameter/network/WinRM/elevation/config errors, or connection-lost mid-run) |
| 1 | SFC /scannow |
| 2 | DISM ScanHealth |
| 3 | DISM RestoreHealth |
| 4 | DISM AnalyzeComponentStore |
| 5 | DISM StartComponentCleanup |
| 6 | SCCM Cleanup |
| 7 | Windows Update Cleanup |
| 8 | Repair CCM |
| 9 | Zip CBS/DISM Logs |

If a step was not requested, or was skipped because the remote connection was already lost, its field is `0`. A field value of `5` means the step was requested but skipped because the remote connection was lost while/after the previous step ran. Run `Repair-System -AnalyzeExitCode <code>` to get a readable explanation of any code produced by a previous run.

For the SFC and DISM steps (positions 1-5), a raw process exit code is only trusted if the process actually had a fair chance to run: if Repair-System itself killed it for exceeding its time budget, that field reads `4294967294` ("timed out"); if it disappeared in well under 30 seconds without Repair-System killing it - implausibly fast for a real scan/repair - that field reads `4294967293` ("likely terminated externally, e.g. via Task Manager; its own exit code could not be trusted").

Example: `0000000000` means every step succeeded; `171100000000` means Startup reported code `7` (conflicting parameters) and SFC reported code `1` (failed), with every other step at `0`.


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
- **Contact**: dev@kMarflow.com
- **Date**: 2026-06-16

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **NEVER MAKE SYSTEM CHANGES WITHOUT AUTHORIZATION.**
- **DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**

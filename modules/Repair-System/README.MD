# RepairSystem Module

## Overview

The `RepairSystem` PowerShell module provides a function to repair Windows systems remotely by running System File Checker (SFC) and Deployment Imaging Service and Management Tool (DISM) commands. It allows for extensive repair capabilities, including scanning and restoring system files, component cleanup, and Windows Update cleanup on a remote machine. The results are logged on the remote computer and are transferred to the local machine upon completion.

## Functionality

### `Repair-System`

This function performs the following tasks on a specified computer (either locally or a Remote-Device):

- Pings the remote machine to check its availability.
- Executes `sfc /scannow` to check and repair system files.
- Optionally, executes `DISM /Online /Cleanup-Image /ScanHealth` and `DISM /Online /Cleanup-Image /RestoreHealth` to repair the Windows image.
- Optionally, performs Component Store cleanup and a history-preserving Windows Update reset (see `-WindowsUpdateCleanup`).
- If any DISM/SFC step does not complete during the run (it timed out, was terminated, or reported a reboot-pending / could-not-repair state), automatically registers a one-shot task that re-runs the full DISM + SFC pass once after the next reboot (default on; disable with `-NoRebootRepair`).
- Prints progress and status to the local console. Step outputs are written to temporary log files, then consolidated into a single master repair log (`SystemRepair_<PC>_<date>.log`) in CMTrace-compatible format; individual step log files are removed after embedding.
- On remote runs, transfers the master log and a CBS/DISM system log archive to the local machine.

#### Parameters

- **`-ComputerName`** (optional): The hostname or IP address of the remote computer, If not provided, the command will be run locally, if provided, it will run on the specified remote-device.
- **`-remoteShareDrive`** (Optional):The ShareDrive of the Remote-Device on which Windows is installed. If non is provided, Default-Value 'C$' will be used
    The Command `Repair-System -ComputerName SomeDevice -remoteShareDrive D$` will result in Network-Path *\\\\SomeDevice\\D$\\*
- **`-noSfc`** (Optional): When specified, `sfc /scannow` command will be skipped.
- **`-noDism`** (Optional): When specified, all DISM commands will be skipped. This cannot be used in combination with `-IncludeComponentCleanup`.
- **`-Quiet`** (Optional): Suppresses console output on the local machine. The output is always logged to files on the remote machine.
- **`-IncludeComponentCleanup`** (Optional): Analyzes and if recommended cleans up the Windows Component Store. This cannot be used in combination with `-noDism`.
- **`-WindowsUpdateCleanup`** (Optional): Resets the Windows Update client. Stops the update services, clears the `SoftwareDistribution` folder while **keeping the update history** (the `DataStore` database) when it passes an integrity check - it is only rebuilt when found corrupt - resets `catroot2`, and clears the BITS transfer queue. Any item held open by a running process is scheduled for removal on the next reboot; when that happens the step reports code `3010` ("Success (restart required)") and a restart completes the removal.
- **`-ResetUpdateHistory`** (Optional): Only meaningful together with `-WindowsUpdateCleanup`. Forces the `DataStore` (update history) to always be wiped and rebuilt, instead of being preserved when it is healthy. Use this to deliberately discard the Windows Update history.
- **`-IncludeLegacyRepair`** (Optional): Only meaningful together with `-WindowsUpdateCleanup`. Additionally performs invasive legacy repairs - re-registering the Windows Update COM DLLs, resetting the Winsock catalog, and rewriting the security descriptors of the `wuauserv`/`bits` services. These can affect networking and require a reboot. In an interactive session this prompts for confirmation; combine with `-Force` to skip the prompt (required to run it in a non-interactive session).
- **`-Force`** (Optional): Skips the confirmation prompt for `-IncludeLegacyRepair` (and is required to run legacy repair in a non-interactive session).
- **`-NoRebootRepair`** (Optional): Disables the automatic one-shot reboot re-run that is otherwise scheduled when a DISM/SFC step does not complete cleanly. The re-run task deletes itself before running (single attempt, no loop) and writes its own Repair-System log under `C:\_IT-RebootRepair` after the next restart.
- **`-ChangeTimeout`** (Optional) use decimal value to change when DISM/SFC and Windows Update Diagnostics will timeout (value `-ChangeTimeout 2` will double the time, `-ChangeTimeout 0.5` will half it).
Range = 0.25 - 10.0
- **`-sccmCleanup`** (Optional): deletes the contents of the CCMCache folder and SoftwareDistribution\Download folder
- **`-KeepLogs`** (Optional): individual step log files are retained alongside the master log instead of being deleted after their content is embedded. On remote runs, step logs remain on the remote device and the full set (step logs + master log) is transferred to the Client.
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

# Perform a history-preserving Windows Update reset
Repair-System -ComputerName <remote-device> -WindowsUpdateCleanup

# Windows Update reset that also discards the update history and runs the legacy repairs (non-interactive)
Repair-System -ComputerName <remote-device> -WindowsUpdateCleanup -ResetUpdateHistory -IncludeLegacyRepair -Force

# Skip the automatic post-reboot DISM/SFC re-run
Repair-System -ComputerName <remote-device> -NoRebootRepair

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

Positions follow the order the steps actually run in (DISM before SFC):

| Position | Step |
|---|---|
| 0 | Startup / Pre-Flight Checks (parameter/network/WinRM/elevation/config errors, or connection-lost mid-run) |
| 1 | DISM ScanHealth |
| 2 | DISM RestoreHealth |
| 3 | DISM AnalyzeComponentStore |
| 4 | DISM StartComponentCleanup |
| 5 | SFC /scannow |
| 6 | SCCM Cleanup |
| 7 | Windows Update Cleanup |
| 8 | Repair CCM |
| 9 | Zip CBS/DISM Logs |

If a step was not requested, or was skipped because the remote connection was already lost, its field is `0`. A field value of `5` means the step was requested but skipped because the remote connection was lost while/after the previous step ran. A field value of `-4` means the step was requested but deliberately did not run because it was not necessary (RestoreHealth when ScanHealth finds no corruption; StartComponentCleanup when AnalyzeComponentStore recommends none) or because a prerequisite step did not complete - reported as "Skipped (not needed)" and not counted as a failure. Run `Repair-System -AnalyzeExitCode <code>` to get a readable explanation of any code produced by a previous run.

For the DISM and SFC steps (positions 1-5), a raw process exit code is only trusted if it is a clean success or the process had a fair chance to run. A clean exit (code `0`) is always trusted, however quickly it arrives - some steps (e.g. AnalyzeComponentStore) legitimately finish in seconds. If Repair-System itself killed it for exceeding its time budget, that field reads `-2` ("timed out"); if it exited on its own with a NON-ZERO code in well under 30 seconds - implausibly fast for a real scan/repair to have failed legitimately - that field reads `-3` ("likely terminated externally, e.g. via Task Manager; its own exit code could not be trusted").

The out-of-band values `-2`, `-3` and `-4` are shown as these small signed numbers in the result object and in `-AnalyzeExitCode` output; inside the packed `DetailedExitCode` string they appear as the 32-bit two's-complement hex fields `FFFFFFFE`, `FFFFFFFD` and `FFFFFFFC`.

The Windows Update Cleanup step (position 7) reports `3010` when it deferred locked items (for example `catroot2` catalog files held open by CryptSvc) to the next reboot - surfaced as "Success (restart required)" in the per-step Analysis. This is not a failure; a restart finishes the removal, after which Windows rebuilds the affected caches automatically.

Example: `0000000000` means every step succeeded; `171100000000` means Startup reported code `7` (conflicting parameters) and DISM ScanHealth (position 1) reported code `1` (failed), with every other step at `0`.


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
- **Date**: 2026-08-15

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **NEVER MAKE SYSTEM CHANGES WITHOUT AUTHORIZATION.**
- **DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**

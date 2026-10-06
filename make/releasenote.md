Easy installer for PowerShell-Tools {{Tag}}

This .exe-installer will install the following Modules:

{{ModuleList}}

# Change Log:


- `TempDataCleanup`: several devices are cleaned in parallel background jobs (`-ThrottleLimit`, `-DeviceTimeoutMinutes`), each reporting one line when it has finished
- `TempDataCleanup`: returns one result object per device (status, free space, message, log file); new `-Quiet` switch for scripted runs
- `TempDataCleanup`: `-LowDisk` / `-VeryLowDisk` now also work remotely - CleanMgr never completes without an interactive desktop, so native equivalents are used there instead of a 10-20 minute hang
- `TempDataCleanup`: CMTrace-format log (same layout as Repair-System), and only the run's own log files are removed from the remote temp folder
- `TempDataCleanup`: safety hardening - all targets are built from folders resolved and validated on the device, and cache locations pointing at key system folders or user profiles are refused
- `TempDataCleanup`: many fixes (lost remote connections, bounded CleanMgr waits, prompts, config parsing, Teams backgrounds, profiles with `[`/`]`, reboot queue), and the default cleanup no longer touches app data such as Outlook for Windows
- `TempDataCleanup`: `SoftwareDistribution\Download` is cleared with the update services stopped, never during an update installation; a failing step no longer aborts the device; Prefetch is left alone
- `RepairSystem`: one PowerShell remoting session per run - no administrative share needed; logs stay on the device and are copied back
- `RepairSystem`: the reboot re-run script now sits in a folder only SYSTEM and Administrators can write to (security fix)
- `RepairSystem`: RestoreHealth runs directly (no separate ScanHealth scan), DISM/SFC results are read language-independently
- `RepairSystem`: Windows Update Cleanup stops only the services Microsoft's own reset stops and never interrupts an update or MSI installation




## Changed Modules
### RepairSystem

#### Security:

- **Reboot re-run folder.** The one-shot re-run script that runs as SYSTEM at the next boot used to sit in `C:\_IT-RebootRepair` with default permissions, so any user could change it. It now lives in a freshly created `<ProgramData>\RepairSystem-RebootRerun` that only SYSTEM and Administrators can write to; the log folder `<SystemDrive>\_IT-RebootRepair` gets the same protection (users can read). A junction or a folder locked against Administrators makes the registration refuse with a warning.

#### New Features:

- **One remoting session per run.** Every step runs through a single PowerShell remoting session (WinRM); no administrative share (`C$`) is needed any more. Step logs, the CBS/DISM archive and the ccmsetup.log copy are written on the device and copied back through the session; only the run's own files are removed. A dropped connection is reopened for up to 90 seconds before the remaining steps are marked as skipped.
- **Pipeline input.** `-ComputerName` accepts several computers from the pipeline; each is repaired in turn and returns its own result object.
- **Language-independent results.** DISM runs with `/English`, and the SFC result is read from its `[SR]` entries in `CBS.log` (also when CBS.log is rotated during the scan), so the reboot re-run decision works on any display language.
- **Outcome summary.** The run ends with a summary of what needs attention (failed, postponed or incomplete steps, restart required) instead of a fixed text.

#### Changes:

- `ModuleVersion` 1.10 → {{Version:RepairSystem}}.
- RestoreHealth runs directly; it scans the image itself and repairs only what it finds, so a damaged image is no longer scanned twice. Exit-code position 1 (ScanHealth) is kept and always `0`.
- Windows Update Cleanup stops only the services Microsoft's Windows Update reset stops (no longer `msiserver`, `trustedinstaller` or `ccmexec`) and starts only those that were running. An update or MSI installation in progress is waited for up to 10 minutes; if it is still running, the reset is carried out at the next boot instead. A running task sequence is stopped first.
- `-ContentCacheCleanup` empties `SoftwareDistribution\Download` with the update services stopped and never during an update installation; together with `-WindowsUpdateCleanup` the folder is cleared only once.
- Logs use the CMTrace format throughout and are named `<yyyy-MM-dd_HH-mm-ss>_<PC>_RepairSystem[_<Step>].log`; stderr output of a step is kept as its own file. `-Verbose` writes a transcript per step.
- New exit-code value `-5` "Postponed (restart required)" for StartComponentCleanup when a restart is pending.
- `-remoteShareDrive` and the `ShareDrive` Config-File key are no longer used but still accepted.

#### Fixes:

- `-init` could write an empty `TempDirName`, which pointed the temp folder at the drive root; the Config-File is now validated.
- On Windows PowerShell 5.1 the DISM/SFC exit codes were lost, so steps could be misreported; DISM no longer waits on a hidden restart prompt (`/NoRestart`).
- A hung service is killed only when it runs alone in its process, never a shared svchost.
- Locked files are queued for deletion at the next boot correctly (paths with the `\\?\` prefix were queued in a form Windows ignores).

### TempDataCleanup



#### New Features:

- **Parallel cleanup of several devices.** With more than one computer, every device is cleaned in its own background job, at most `-ThrottleLimit` at a time (default 10). There is no step output then; each device prints one line (name, additional and total free space, or the failure reason) as soon as it has finished. Duplicates and local aliases (`""`, `localhost`, the own computer name) are cleaned only once. `-DeviceTimeoutMinutes` (default 90) stops a device that runs too long and reports it as failed.
- **Result objects and `-Quiet`.** The function returns one `TempDataCleanup.Result` object per device (`ComputerName`, `Status`, `AdditionalFreeGB`, `TotalFreeGB`, `Message`, `LogFile`) after all devices have finished, so results can be filtered or exported. `-Quiet` suppresses all console output; errors and the result objects remain.
- **Native disk cleanup without an interactive desktop.** CleanMgr `/sagerun` never completes in a non-interactive session 0 (remote/WinRM, SYSTEM) - it waits behind hidden dialogs until killed. In those contexts `-LowDisk` / `-VeryLowDisk` now apply native equivalents: the file-based Disk Cleanup options are applied from their own Windows definition (folder, file pattern, age, flags), Delivery Optimization via `Delete-DeliveryOptimizationCache`, Update Cleanup via DISM `/StartComponentCleanup`, and Device Driver Packages by removing older, unused driver versions (`pnputil` without `/force`). Options without a native equivalent are skipped and logged. Interactive runs keep using CleanMgr.
- **CMTrace log.** The log is written in CMTrace format (same layout as Repair-System) with a component per step and warning/error highlighting, named with timestamp and the device's name. A single device prints its log path; with several devices the start banner shows where the logs will be.
- **Browser site data needs confirmation.** `-IncludeBrowserData` clears browser caches as before; saved site data (Firefox site storage, Internet Explorer cookies) is only cleared after confirming a prompt, or with `-ConfirmWarning`.

#### Fixes:

- **Remote runs:** a lost connection during the cleanup is reported as failed instead of "completed" with bogus free-space values; reachability is tested by opening the PowerShell session instead of a ping (which can be blocked while WinRM is open); the remote session is always closed; logs of later devices no longer land in nested folders of earlier ones; the verbose transcript is copied back; only the run's own log files are removed from the remote temp folder, never the whole folder.
- **CleanMgr:** the `-AutoClean` run no longer waits 5 extra minutes and reports a false "stuck" error, and the wait for leftover CleanMgr/DismHost processes is bounded instead of potentially endless.
- **Safety:** all cleanup targets are built from the Windows, ProgramData and profile folders resolved and validated on the target device instead of hard-coded `C:` paths, so an empty or failed lookup can never point a delete at a drive root. A ConfigMgr/Adaptiva cache location that points at a key system folder (Windows, System32, WinSxS, Program Files, ProgramData) or into a user profile is refused instead of emptied.
- **Prompts and checks:** the `-VeryLowDisk` confirmation is asked once for the whole run, "exit" really exits, and missing input no longer loops; the elevation check for the local computer runs before anything is cleaned and no longer blocks with `Pause`.
- **Teams:** background images are backed up outside the cache, and the cache is only cleared once the backup succeeded; a backup left by an interrupted run is restored. `ms-teams` is stopped once instead of once per profile.
- **Reboot queue:** locked files are queued for deletion once; all locked items of a folder are written in one registry update, skipping entries already queued.
- **Windows Update downloads:** `SoftwareDistribution\Download` is emptied with wuauserv/BITS force-stopped (an interrupted download is simply fetched again) and started again afterwards; an update installation in progress is never interrupted but waited for up to 10 minutes, after which the folder is cleared at the next boot instead. With `-ContentCacheCleanup` the folder is cleared only once.
- **Failing steps:** a step that fails on a device no longer aborts that device; the remaining steps still run, and the result's `Message` names the failed step.
- **Other:** profiles whose name contains `[` or `]` are no longer skipped; blank lines and comments in the Config-File no longer abort the run; `-AutoClean` now enables `-IncludeSystemData`, `-ContentCacheCleanup` and `-IncludeIconCache` as documented.

#### Changes:

- `ModuleVersion` 1.7 → {{Version:TempDataCleanup}}.
- The default package cleanup only clears plain temp/installer caches; app data kept in `LocalCache` by Outlook for Windows, Photos, Snipping Tool, Camera and legacy Edge is left alone unless `-IncludeAllPackages` is used.
- `-ConfirmWarning` also bypasses the `-IncludeAllPackages` and browser site data prompts (for unattended runs).
- Not running elevated for a local target and an invalid Config-File are now errors (visible with `-Quiet`) instead of warnings.
- The `ShareDrive` Config-File key is no longer used; existing files with it keep working, and `-init` no longer writes it.
- Each cleanup step now runs through one code path for local and remote devices instead of separate background jobs per step.
- Prefetch is no longer cleared with `-IncludeSystemData`; Windows maintains it itself.
- When `-IncludeMSTeamsCache` closes a running Teams, the affected users are named in a warning and in the log.

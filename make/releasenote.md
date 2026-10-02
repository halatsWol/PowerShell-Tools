Easy installer for PowerShell-Tools v1.8.0

This .exe-installer will install the following Modules:

- [RepairSystem](https://github.com/halatsWol/PowerShell-Tools/tree/v1.8.0/modules/Repair-System) (v1.10)
- [TempDataCleanup](https://github.com/halatsWol/PowerShell-Tools/tree/v1.8.0/modules/TempDataCleanup) (v1.8)
- [Shortcuts](https://github.com/halatsWol/PowerShell-Tools/tree/v1.8.0/modules/Shortcuts) (v1.0)
- [CredentialHandler](https://github.com/halatsWol/PowerShell-Tools/tree/v1.8.0/modules/CredentialHandler) (v1.0)

# Change Log:


- `TempDataCleanup`: several devices are cleaned in parallel background jobs (`-ThrottleLimit`, `-DeviceTimeoutMinutes`), each reporting one line when it has finished
- `TempDataCleanup`: returns one result object per device (status, free space, message, log file); new `-Quiet` switch for scripted runs
- `TempDataCleanup`: `-LowDisk` / `-VeryLowDisk` now also work remotely - CleanMgr never completes without an interactive desktop, so native equivalents are used there instead of a 10-20 minute hang
- `TempDataCleanup`: CMTrace-format log (same layout as Repair-System), and only the run's own log files are removed from the remote temp folder
- `TempDataCleanup`: safety hardening - all targets are built from folders resolved and validated on the device, and cache locations pointing at key system folders or user profiles are refused
- `TempDataCleanup`: many fixes (lost remote connections, bounded CleanMgr waits, prompts, config parsing, Teams backgrounds, profiles with `[`/`]`, reboot queue), and the default cleanup no longer touches app data such as Outlook for Windows




## Changed Modules
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
- **Other:** profiles whose name contains `[` or `]` are no longer skipped; blank lines and comments in the Config-File no longer abort the run; `-AutoClean` now enables `-IncludeSystemData`, `-ContentCacheCleanup` and `-IncludeIconCache` as documented.

#### Changes:

- `ModuleVersion` 1.7 → 1.8.
- The default package cleanup only clears plain temp/installer caches; app data kept in `LocalCache` by Outlook for Windows, Photos, Snipping Tool, Camera and legacy Edge is left alone unless `-IncludeAllPackages` is used.
- `-ConfirmWarning` also bypasses the `-IncludeAllPackages` and browser site data prompts (for unattended runs).
- Not running elevated for a local target and an invalid Config-File are now errors (visible with `-Quiet`) instead of warnings.
- The `ShareDrive` Config-File key is no longer used; existing files with it keep working, and `-init` no longer writes it.
- Each cleanup step now runs through one code path for local and remote devices instead of separate background jobs per step.

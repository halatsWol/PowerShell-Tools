Easy installer for PowerShell-Tools v1.5

This .exe-installer will install the following Modules:

- [RepairSystem](https://github.com/halatsWol/PowerShell-Tools/tree/v1.5/modules/Repair-System) (v1.6)
- [TempDataCleanup](https://github.com/halatsWol/PowerShell-Tools/tree/v1.5/modules/TempDataCleanup) (v1.6)
- [Shortcuts](https://github.com/halatsWol/PowerShell-Tools/tree/v1.5/modules/Shortcuts) (v1.0)
- [CredentialHandler](https://github.com/halatsWol/PowerShell-Tools/tree/v1.5/modules/CredentialHandler) (v1.0)

# Change Log:


- `Repair System`: added structured Exit Code system (`$LASTEXITCODE` 0/1/2 + detailed per-step exit code) and `-AnalyzeExitCode` to decode it
- `Repair System`: result object with `ExitCode`, `DetailedExitCode`, `ComputerName`, `LogPath`, `Actions`, `Analysis` — suppressed from default display, accessible via `$RepairSystemResult` global or property access
- `Repair System`: safer, more thorough service handling and CCM Repair logic
- `TempDataCleanup`: parallelized folder cleanup with background jobs to reduce total cleanup time





## Changed Modules
### RepairSystem



#### New Features:

- a consolidated master repair log (`SystemRepair_<PC>_<date>.log`) in CMTrace-compatible format is now created; individual step logs are embedded into it and deleted after embedding (unless `-KeepLogs`)
- added a structured Exit Code system: `$LASTEXITCODE` is now a conventional `0`/`1`/`2` result suitable for scripting/CI, while the full per-step detail is printed to console as `Detailed Exit Code: <code>`
- **`-AnalyzeExitCode`:** decodes a previously produced (detailed) exit code into a human-readable, per-step breakdown. Cannot be combined with any other parameter and never performs any repair actions. Value `0` for non-Startup steps is noted as ambiguous — success, not requested, or skipped cannot be distinguished without the original run context.
- **Result object:** `Repair-System` now returns a `RepairSystem.Result` object, suppressed from default display. Properties: `ExitCode`, `DetailedExitCode`, `ComputerName`, `LogPath`, `Actions` (which steps were requested), `Analysis` (per-step `Position`/`Label`/`Value`/`Status`). Access via `$r = Repair-System`, `(Repair-System).Property`, or `$RepairSystemResult` after any run.
- **`$global:RepairSystemResult`:** stores the last result object for post-run access without assignment.

#### Fixes:

- SCCM Client Action triggering in `Repair-CCM` now has per-action error handling; a single failed trigger no longer aborts the remaining actions
- step log writes (e.g. timeout/kill messages) now retry with a short back-off when the log file is locked, preventing lost entries when DISM/SFC still holds the file handle at termination time
- safer service stop/restart handling (`Stop-ServiceSafely`): services are stopped gracefully first, with a forced fallback (including killing the underlying process) only if they don't stop in time, reducing the risk of issues or hanging tasks due to processes not stopping when stopping Windows Update/BITS/CCM services during cleanup

#### Changes:


- CBS/DISM log zip now runs as a background job starting immediately after the last SFC/DISM step, overlapping with optional SCCM/WU/CCM steps
- `Repair-CCM`: now also clears the SCCM cache and triggers the standard SCCM Client Action schedules (Hardware/Software Inventory, Discovery Data, Machine Policy, Software Updates Scan/Deployment Evaluation, etc.) after the repair, and logs each step to a dedicated CCM repair log
- remote step execution (SFC/DISM/SCCM/Windows Update/CCM) now shares a single connection-loss handling path (`Invoke-RemoteStep` / `New-RemoteFunctionScriptBlock`), so a lost remote connection is reported consistently for whichever step it occurs in

### TempDataCleanup

#### Changes:

- folder cleanup (user/system temp folders, reporting directories, CCM cache) now runs as parallel background jobs instead of sequentially, and the user/system cleanup phases run concurrently, reducing total cleanup time on profiles/systems with many target folders





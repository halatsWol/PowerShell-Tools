Easy installer for PowerShell-Tools v1.6.0

This .exe-installer will install the following Modules:

- [RepairSystem](https://github.com/halatsWol/PowerShell-Tools/tree/v1.6.0/modules/Repair-System) (v1.9)
- [TempDataCleanup](https://github.com/halatsWol/PowerShell-Tools/tree/v1.6.0/modules/TempDataCleanup) (v1.6)
- [Shortcuts](https://github.com/halatsWol/PowerShell-Tools/tree/v1.6.0/modules/Shortcuts) (v1.0)
- [CredentialHandler](https://github.com/halatsWol/PowerShell-Tools/tree/v1.6.0/modules/CredentialHandler) (v1.0)

# Change Log:


- `Repair System`: multi-system content-cache cleanup - the former `-sccmCleanup` is now `-ContentCacheCleanup` and also clears Adaptiva OneSite and Intune (IME) caches, not just ConfigMgr + Windows Update
- `Repair System`: Windows Update reset reworked to preserve the update history and tolerate locked files
- `Repair System`: automatic one-shot DISM/SFC re-run after the next reboot when a repair step could not complete
- `Repair System`: more robust ConfigMgr cache-location detection (WMI can be empty even on a healthy client), plus WMI class re-registration for a broken client
- `Repair System`: DISM/SFC timeouts are now reported correctly instead of being masked as a generic failure
- `Repair System`: safety hardening - path handling can no longer turn an empty/garbage base into a drive-root or system-folder deletion (SCCM/CCM/WU), and a hung `ccmrepair.exe` is now timed out
- `Repair System`: a failing device no longer aborts a caller's `foreach` loop; `-Quiet` now suppresses progress output; and the pre-flight ping tolerates name-resolution failures




## Changed Modules
### RepairSystem



#### New Features:

- **Multi-system content-cache cleanup (`-ContentCacheCleanup`, alias `-sccmCleanup`).** The cache cleanup now auto-detects and clears the content/download caches of every software-distribution system present on the device: ConfigMgr (`ccmcache`), Windows Update (`SoftwareDistribution\Download`), **Adaptiva OneSite** (`<drive>:\AdaptivaCache`, on every fixed drive it lives on) and the **Intune Management Extension** (`IMECache` + the `Content\{Incoming,Staging,Staged}` staging folders). Systems that are not installed are skipped, and only the cache contents are removed (never the agent's install root). Items a running agent holds open are cleared best-effort now and the remainder is scheduled for removal on the next reboot (via `PendingFileRenameOperations`), in which case the step reports `3010` ("restart required"). The old `-sccmCleanup` switch is kept as an alias and now performs this broader cleanup.
- **History-preserving, lock-tolerant Windows Update reset (`-WindowsUpdateCleanup` reworked).** Replaces the old rename-to-`.bak` + MSDT-troubleshooter approach (a frequent source of hangs and "Close operation" transport errors) with a direct, deterministic reset: it stops the update services (medic/orchestrator first so they can't resurrect them), clears `SoftwareDistribution` while **keeping the update history** — the `DataStore` database is integrity-checked with `esentutl` and only rebuilt when it is actually corrupt — resets `catroot2`, and clears the Delivery Optimization job queue and the BITS transfer queue. Anything a running process still holds open is scheduled for deletion on the next reboot (via the Session Manager's `PendingFileRenameOperations`, processed before any service starts); when that happens the step reports `3010` ("Success (restart required)") and a restart completes the removal, after which Windows rebuilds the affected caches automatically.
- **`-ResetUpdateHistory`.** Opt-in switch (only meaningful with `-WindowsUpdateCleanup`) that always wipes and rebuilds the `DataStore`, deliberately discarding the Windows Update history instead of preserving it.
- **`-IncludeLegacyRepair` / `-Force`.** Opt-in legacy repairs (only with `-WindowsUpdateCleanup`): re-registering the Windows Update COM DLLs, resetting the Winsock catalog, and rewriting the security descriptors of the `wuauserv`/`bits` services. These can affect networking and require a reboot, so an interactive run prompts for confirmation; `-Force` skips the prompt and is required to run legacy repair in a non-interactive session.
- **Automatic one-shot reboot re-run for incomplete DISM/SFC (default on; `-NoRebootRepair` to disable).** If any DISM/SFC step does not truly complete during a run — it timed out, was terminated, produced an empty/incomplete log, or reported a reboot-pending / could-not-repair state — Repair-System registers a single self-deleting scheduled task that re-runs the full DISM + SFC pass once after the next reboot and writes its own Repair-System log under `C:\_IT-RebootRepair`. The task deletes itself before running, so it runs at most once and never loops. Pass `-NoRebootRepair` to opt out.

#### Fixes:

- **DISM/SFC timeouts are no longer mislabelled as a generic failure.** When Repair-System killed a DISM or SFC step for exceeding its time budget, the timeout sentinel (`-2`) could be overwritten by a stray `WaitForExit` return value and reported as a plain `1`, hiding the fact that the step never finished. Timed-out steps now correctly report `-2` ("timed out"), which also drives the automatic reboot re-run described above.
- **More robust ConfigMgr cache-location detection.** The `ccmcache` location is resolved through an ordered chain - WMI `CacheConfig` → the `UIResourceMgr` COM API (what Software Center reads) → the registry `CacheConfig` → the default under `%windir%` - because the WMI class can come back empty even on a healthy client, which previously left the cleanup falling back to the default path and potentially missing a relocated cache. A relocated, custom-named cache (e.g. `D:\SCCMCache`) is now honored, not just the default location. Applies to both the content-cache cleanup and the `-RepairCCM` cache clear. `-RepairCCM` additionally re-registers the CCM client WMI classes (recompiling the CCM MOFs with `mofcomp`, with `CcmExec` stopped) when a broken client is not registered in WMI.
- **A failing device no longer aborts the caller's loop.** The three pre-flight error exits (parameter conflict, ping failure, WinRM failure) used `break` instead of `return`; outside a loop `break` walks up the call stack, so when Repair-System is called inside a `foreach` over devices (the documented usage) one unreachable device silently aborted the loop and skipped every remaining device. They now `return`.
- **`-Quiet` is honored for progress output.** The SFC/DISM/cache "executing…" lines, the Repair-CCM step announcements, and the completion summary are now gated on `-Quiet` (they previously printed regardless); the file logs are unaffected.
- **Pre-flight ping tolerates name-resolution failures.** `Test-Connection` returns `$true`/`$false` for a normally unreachable host but still throws on a DNS-resolution failure; that throw is now caught and treated as unreachable (exit `2`) instead of escaping unhandled.
- **Path-safety hardening against empty-base deletion.** Every cleanup resolves the Windows directory from `[Environment]::GetFolderPath('Windows')` (robust against an empty `$env:windir`), validates it as an absolute, existing, drive-qualified directory, and builds/deletes paths only from that validated base; `Remove-PathReliable` additionally refuses any target that is a drive root, the Windows directory, or `System32` - blocking both the immediate delete and the reboot-deferred one. A hung `ccmrepair.exe` is now bounded by a 45-minute timeout so it cannot block the whole run.

#### Changes:

- `ModuleVersion` 1.7 → 1.9.

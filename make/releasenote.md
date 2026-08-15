Easy installer for PowerShell-Tools v1.6.0

This .exe-installer will install the following Modules:

- [RepairSystem](https://github.com/halatsWol/PowerShell-Tools/tree/v1.6.0/modules/Repair-System) (v1.8)
- [TempDataCleanup](https://github.com/halatsWol/PowerShell-Tools/tree/v1.6.0/modules/TempDataCleanup) (v1.6)
- [Shortcuts](https://github.com/halatsWol/PowerShell-Tools/tree/v1.6.0/modules/Shortcuts) (v1.0)
- [CredentialHandler](https://github.com/halatsWol/PowerShell-Tools/tree/v1.6.0/modules/CredentialHandler) (v1.0)

# Change Log:


- `Repair System`: Windows Update reset reworked to preserve the update history and tolerate locked files
- `Repair System`: automatic one-shot DISM/SFC re-run after the next reboot when a repair step could not complete
- `Repair System`: ConfigMgr (CCM) cache cleanup now detects the actual configured cache location; adds WMI re-registration and loop-break fixes
- `Repair System`: DISM/SFC timeouts are now reported correctly instead of being masked as a generic failure




## Changed Modules
### RepairSystem



#### New Features:

- **History-preserving, lock-tolerant Windows Update reset (`-WindowsUpdateCleanup` reworked).** Instead of blindly renaming folders, the reset stops the update services, clears `SoftwareDistribution` while **keeping the update history** — the `DataStore` database is integrity-checked and only rebuilt when it is actually corrupt — resets `catroot2`, and clears the BITS transfer queue. Anything a running process still holds open is scheduled for deletion on the next reboot (via the Session Manager's `PendingFileRenameOperations`, processed before any service starts); when that happens the step reports `3010` ("Success (restart required)") and a restart completes the removal, after which Windows rebuilds the affected caches automatically.
- **`-ResetUpdateHistory`.** Opt-in switch (only meaningful with `-WindowsUpdateCleanup`) that always wipes and rebuilds the `DataStore`, deliberately discarding the Windows Update history instead of preserving it.
- **`-IncludeLegacyRepair` / `-Force`.** Opt-in legacy repairs (only with `-WindowsUpdateCleanup`): re-registering the Windows Update COM DLLs, resetting the Winsock catalog, and rewriting the security descriptors of the `wuauserv`/`bits` services. These can affect networking and require a reboot, so an interactive run prompts for confirmation; `-Force` skips the prompt and is required to run legacy repair in a non-interactive session.
- **Automatic one-shot reboot re-run for incomplete DISM/SFC (default on; `-NoRebootRepair` to disable).** If any DISM/SFC step does not truly complete during a run — it timed out, was terminated, produced an empty/incomplete log, or reported a reboot-pending / could-not-repair state — Repair-System registers a single self-deleting scheduled task that re-runs the full DISM + SFC pass once after the next reboot and writes its own Repair-System log under `C:\_IT-RebootRepair`. The task deletes itself before running, so it runs at most once and never loops. Pass `-NoRebootRepair` to opt out.

#### Fixes:

- **DISM/SFC timeouts are no longer mislabelled as a generic failure.** When Repair-System killed a DISM or SFC step for exceeding its time budget, the timeout sentinel (`-2`) could be overwritten by a stray `WaitForExit` return value and reported as a plain `1`, hiding the fact that the step never finished. Timed-out steps now correctly report `-2` ("timed out"), which also drives the automatic reboot re-run described above.
- **ConfigMgr (CCM) cache cleanup honours the configured cache location.** The CCM cache cleanup now detects the actual `ccmcache` location from the client configuration (WMI) instead of assuming the default path, and re-registers the CCM WMI classes when they are missing. Includes loop-break fixes in the CCM handling.

#### Changes:

- `ModuleVersion` 1.7 → 1.8.

Easy installer for PowerShell-Tools v1.5.1

This .exe-installer will install the following Modules:

- [RepairSystem](https://github.com/halatsWol/PowerShell-Tools/tree/v1.5.1/modules/Repair-System) (v1.7)
- [TempDataCleanup](https://github.com/halatsWol/PowerShell-Tools/tree/v1.5.1/modules/TempDataCleanup) (v1.6)
- [Shortcuts](https://github.com/halatsWol/PowerShell-Tools/tree/v1.5.1/modules/Shortcuts) (v1.0)
- [CredentialHandler](https://github.com/halatsWol/PowerShell-Tools/tree/v1.5.1/modules/CredentialHandler) (v1.0)

# Change Log:


- `Repair System`: fixed fast, successful DISM/SFC steps (notably `AnalyzeComponentStore`) being mislabelled as "terminated externally", which silently skipped Component Store cleanup while still reporting success
- `Repair System`: steps that were requested but legitimately did not run now report `Skipped (not needed)` instead of `Success`
- `Repair System`: detailed exit-code step positions reordered to match execution order (DISM before SFC)
- `Repair System`: out-of-band exit values now shown as `-2`/`-3`/`-4` instead of their unsigned 32-bit form




## Changed Modules
### RepairSystem



#### Fixes:

- **Fast, successful DISM/SFC steps are no longer mislabelled as terminated.** A process that exits cleanly (code `0`) is now trusted no matter how quickly it finishes. Previously *any* completion in under 30 seconds — which `DISM /Online /Cleanup-Image /AnalyzeComponentStore` routinely does — was recorded as `-3` ("terminated externally"). That false result made the `StartComponentCleanup` gate fail, so Component Store cleanup was silently skipped even when it was recommended, yet the step still reported `Success`. The sub-30-second suspicion now applies only to *non-zero* exits.
- **"Requested but not executed" is no longer reported as success.** Conditional DISM steps that a run requests but legitimately skips — `RestoreHealth` when `ScanHealth` finds no corruption, `StartComponentCleanup` when `AnalyzeComponentStore` recommends none — now report `Skipped (not needed)` (a dedicated `-4` value) instead of `Success`. It is not counted as a failure, so a healthy run still exits `0`.

#### Changes:

- **Detailed exit-code positions now follow execution order.** Steps are numbered in the order they actually run: DISM ScanHealth / RestoreHealth / AnalyzeComponentStore / StartComponentCleanup = positions 1–4, SFC = position 5 (previously SFC was position 1 and the DISM steps were 2–5). Heads-up: this changes the meaning of the packed `DetailedExitCode` string, so a code saved from an earlier version decodes to different steps under 1.7 (`-AnalyzeExitCode` on an old code will mis-attribute them). `ModuleVersion` 1.6 → 1.7.
- **Out-of-band exit values are shown as small signed numbers.** The special values now display as `-2` (timed out), `-3` (terminated externally) and `-4` (skipped / not needed) in the result object's `Analysis` and in `-AnalyzeExitCode` output, instead of their unsigned 32-bit form (`4294967294`/`4294967293`/`4294967292`). The packed `DetailedExitCode` string itself is unchanged (still two's-complement hex).

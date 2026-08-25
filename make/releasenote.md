Easy installer for PowerShell-Tools v1.7.0

This .exe-installer will install the following Modules:

- [RepairSystem](https://github.com/halatsWol/PowerShell-Tools/tree/v1.7.0/modules/Repair-System) (v1.10)
- [TempDataCleanup](https://github.com/halatsWol/PowerShell-Tools/tree/v1.7.0/modules/TempDataCleanup) (v1.7)
- [Shortcuts](https://github.com/halatsWol/PowerShell-Tools/tree/v1.7.0/modules/Shortcuts) (v1.0)
- [CredentialHandler](https://github.com/halatsWol/PowerShell-Tools/tree/v1.7.0/modules/CredentialHandler) (v1.0)

# Change Log:


- `Repair System`: new `-RepairWMI` step - a non-destructive WMI repository check + repair (verify, then salvage if inconsistent), run before the WMI-dependent ConfigMgr/CCM steps
- `Repair System`: a DISM AnalyzeComponentStore that recommends a component-store cleanup is no longer misread as "terminated externally" (which had also skipped the cleanup and scheduled a needless reboot re-run)
- `Repair System`: clearer exit-code analysis - a `0` field now reads as "success or not requested" instead of ambiguously "or skipped"




## Changed Modules
### RepairSystem



#### New Features:

- **WMI repository repair (`-RepairWMI`).** New opt-in step that checks the WMI repository with `winmgmt /verifyrepository` and, when the store is reported inconsistent, repairs it non-destructively with `winmgmt /salvagerepository` followed by a re-verify. It never runs the destructive `/resetrepository`, so third-party WMI providers (ConfigMgr/SCCM, antivirus, monitoring agents) are preserved. The step runs **before** the WMI-dependent Content Cache Cleanup and CCM Repair steps so those act on a repaired store, and it is remote-capable like the rest of the module. The consistency verdict is taken from `winmgmt`'s exit code (locale-independent) - captured via a background job, because `winmgmt.exe` is a service stub that does not expose its exit code through `Start-Process`.

#### Fixes:

- **DISM AnalyzeComponentStore success is no longer misreported as "terminated externally" (`-3`).** AnalyzeComponentStore returns a *non-zero* exit code precisely when it recommends a component-store cleanup ("Component Store Cleanup Recommended: Yes"), and it legitimately finishes in seconds. That fast, non-zero-but-successful result tripped the "exited implausibly fast -> likely terminated externally" heuristic, so the step was recorded as `-3`, which additionally **suppressed the StartComponentCleanup step** (leaving reclaimable packages uncleaned) and scheduled an unnecessary reboot re-run. A self-completed analysis that produced a Yes/No verdict is now recorded as success, and the component-store cleanup runs as recommended. The reboot re-run's own DISM/SFC pass shares the fixed worker.
- **Exit-code `0` analysis wording corrected.** `-AnalyzeExitCode` and the `.Analysis` output described a `0` field as "success, not requested, or skipped ... skipped due to a prior failure or connection loss", but genuinely skipped steps carry their own codes (`-4` "not necessary", `5` "connection lost") and never surface as `0`. A `0` now reads as "success, or the step was not requested" - the only non-success meaning - and the module's README, about-help and comment-based help mirror the correction.

#### Changes:

- `ModuleVersion` 1.9 → 1.10.
- The detailed exit code gains a step at **position 6 (WMI Repository Repair)**; Content Cache Cleanup, Windows Update Cleanup, Repair CCM and Zip Logs shift to positions 7-10. `-AnalyzeExitCode` stays backward-compatible: it selects the step layout by the code's field count, so a pre-v1.10 ten-field code still decodes with its original labels.

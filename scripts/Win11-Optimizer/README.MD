# Win11-Optimizer

`Optimize-Windows11.ps1` — a flexible Windows 11 optimizer for PowerShell, with tiered intensity and a
restorable rollback.

> ## ⚠️ WORK IN PROGRESS — DO NOT USE ON A REAL / PRODUCTION MACHINE
>
> This script is **unfinished and under active development**. It changes system and user settings and
> **can break Windows, degrade features over time, or cause data loss**. The built-in rollback is not
> complete yet. **Only run it on a disposable VM or a machine you have a full snapshot/backup of.**
> Review the code before running. Use entirely at your own risk.

## About

A PowerShell reimagining of [TBOK-Win11Optimizer](https://github.com/TheBeardofKnowledge/TBOK-Win11Optimizer)
(a one-click Windows 11 optimizer `.bat` for IT/MSP use). Per its own README, TBOK draws on
[Chris Titus Tech's WinUtil](https://github.com/ChrisTitusTech/winutil), **Belim's FlyByOOBE**, and
**CrapFixer**.

What this project adds over TBOK:

- **Tiered intensity** (`-Level Minimal | Balanced | Full`, plus a guided `Custom`) so you don't have to
  apply everything — doing too much (especially disabling telemetry) can break Windows over time.
- **A real, stacked rollback** — a VSS restore point plus a generated undo script that records the prior
  state of everything a run touches, so any run can be reverted (repeated runs unwind one step at a time).
- **Defender is never weakened** by any level.

## Features

### Available now

- `-Level Minimal|Balanced|Full|Custom` selection. **Minimal**, **Balanced** and **Full** are implemented —
  Minimal: Explorer/UI quality-of-life, consumer ads/tips off, Fast Startup off, a few safe services to
  Manual; Balanced adds responsiveness/network tuning, Bing/web-search off, **telemetry reduced (not off)**,
  **desktop-only hibernation-off**, and **essential-service normalization**; **Full** does the aggressive
  set (telemetry fully OFF, more services disabled, WPBT/device-metadata hardening, Edge policies,
  svchost/RAM & SysMain tuning) **behind a confirmation prompt** (`-Force` to skip). Defender is never touched.
- `-Preview` — list the selected tweaks and their current on-machine values (changes nothing).
- Prior-state capture → snapshot under `%ProgramData%\Marflow Software\Win11Optimizer` (manifest,
  per-key `.reg` backups, and a self-contained **undo `.ps1`**).
- Live apply of **registry, service (incl. delayed-auto) and power** tweaks with `-WhatIf` / `-Confirm`
  support and an exit-code contract.
- Built-in **stacked rollback**: `-Rollback` (undo the last run), `-Rollback -To <id>`, `-Rollback -All`,
  and `-ListSnapshots` — repeated runs unwind one layer at a time.
- A **VSS System Restore point** is created before each apply (skip with `-SkipRestorePoint`), as a
  full-system safety net alongside the surgical undo.
- **Hardware-aware selection**: tweaks can be gated by chassis (laptop/desktop), disk type or RAM, and can
  compute their value from the machine (used more as the catalog grows).
- Hard guard: **Windows Defender keys/services are never touched**.

### Upcoming

- **Appx debloat** (remove Widgets/Bing) and `-IncludeAI` / `-IncludeGaming` add-ons (independently revertible).
- More Full coverage (wider service map, pagefile sizing).
- `-AllUsers` (all profiles) and the guided `Custom` walkthrough.

## Usage

```powershell
# See what a level would change (read-only)
.\Optimize-Windows11.ps1 -Preview -Level Minimal

# Dry run
.\Optimize-Windows11.ps1 -Level Minimal -WhatIf

# Apply (elevated)
.\Optimize-Windows11.ps1 -Level Minimal

# Roll back (elevated)
.\Optimize-Windows11.ps1 -ListSnapshots   # see snapshot ids
.\Optimize-Windows11.ps1 -Rollback        # undo the last run
.\Optimize-Windows11.ps1 -Rollback -All   # undo everything, back to baseline
```

## Requirements

- Windows 11, Windows PowerShell **5.1**, run **as Administrator**.

## Author

- **Author:** Wolfram Halatschek · **Contact:** dev@kMarflow.com

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **DO NOT USE ON PRODUCTION SYSTEMS — THIS IS UNFINISHED SOFTWARE.**
- Provided as-is, not supported by Microsoft.

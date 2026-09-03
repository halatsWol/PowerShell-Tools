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

- `-Level Minimal|Balanced|Full|Custom` selection.
  Minimal: Explorer/UI quality-of-life (no content-scan folder views, compact view, separate Explorer
  process, Quick Access recents off, feeds/Chat button off, visual-effects-for-performance), consumer
  ads/tips off, advertising ID off, Fast Startup off, a few safe services to Manual; Balanced adds
  responsiveness/network tuning, Bing/web-search off, the **suggested-apps / Start-ads cleanup**,
  background apps off, **telemetry reduced (not off)**, **desktop-only hibernation-off**, and
  **essential-service normalization**; **Full** does the aggressive set (telemetry fully OFF, more
  services disabled, **hibernation off on all machines incl. notebooks**, WPBT/device-metadata hardening,
  Edge policies, svchost/RAM & SysMain tuning) **behind a confirmation prompt** (`-Force` to skip).
  Defender is never touched.
- **`-Level Custom`** — a guided, interactive walkthrough: for each category it shows every tweak's impact
  and asks how far to go (**Skip / Minimal / Balanced / Full**), then offers the AI and Gaming add-ons, then
  summarises and asks you to confirm before anything is applied. Works with `-AllUsers` and the usual
  rollback.
- **`-IncludeAI` add-on** — turns off Copilot and Recall (AI data analysis), hides the Copilot taskbar
  button, disables the Edge Copilot/Discover sidebar, and removes the Copilot app (best-effort, re-registered
  from staged files on undo). Opt-in at any level, applied automatically at Full, and backed by its **own
  rollback stack** so you can peel just the AI layer off with `-Rollback -IncludeAI`.
- **`-IncludeGaming` add-on** — enables Hardware-Accelerated GPU Scheduling, raises the games task
  CPU/GPU/scheduling/storage-I/O priorities, and turns off Game DVR background recording. All registry,
  fully reversible, applied on laptops and desktops alike. Opt-in at any level, automatic at Full, with its
  **own rollback stack** (`-Rollback -IncludeGaming`). It deliberately does **not** touch the power plan
  (Ultimate-Performance is never set) or boot parameters.
- **`-AllUsers`** — applies the user-scope (HKCU) tweaks to **every** user profile, not just the current
  one: profiles are patched live where loaded, or by loading their `NTUSER.DAT` on demand, plus the
  **Default profile template** so newly created users inherit them. Each profile's prior state is captured,
  so rollback reverts every profile (re-loading hives as needed). Machine/service/power tweaks still apply
  once; Appx removal stays current-user for now.
- `-Preview` — list the selected tweaks and their current on-machine values (changes nothing).
- Prior-state capture → snapshot under `%ProgramData%\Marflow Software\Win11Optimizer` (manifest,
  per-key `.reg` backups, and a self-contained **undo `.ps1`** per segment).
- Live apply of **registry, service (incl. delayed-auto), power and Appx (app removal)** tweaks with
  `-WhatIf` / `-Confirm` support and an exit-code contract.
- Built-in **stacked rollback**: `-Rollback` (undo the last run), `-Rollback -To <id>`, `-Rollback -All`,
  and `-ListSnapshots` — repeated runs unwind one layer at a time.
- A **VSS System Restore point** is created before each apply (skip with `-SkipRestorePoint`), as a
  full-system safety net alongside the surgical undo.
- **Hardware-aware selection**: tweaks can be gated by chassis (laptop/desktop), disk type or RAM, and can
  compute their value from the machine (used more as the catalog grows).
- Hard guard: **Windows Defender keys/services are never touched**.

### Upcoming

- **Appx debloat** (remove Widgets/Bing).
- More Full coverage (wider service map, pagefile sizing).
- Comment-based help and an Invoke-ScriptAnalyzer / PS 5.1 polish pass.

## Usage

```powershell
# See what a level would change (read-only)
.\Optimize-Windows11.ps1 -Preview -Level Minimal

# Dry run
.\Optimize-Windows11.ps1 -Level Minimal -WhatIf

# Apply (elevated)
.\Optimize-Windows11.ps1 -Level Minimal

# Apply with add-ons (Copilot/Recall off, Copilot app removed; gaming priorities/HAGS/Game DVR off)
.\Optimize-Windows11.ps1 -Level Balanced -IncludeAI -IncludeGaming

# Apply user-scope tweaks to every profile (and the Default template for new users)
.\Optimize-Windows11.ps1 -Level Minimal -AllUsers

# Guided, interactive setup (choose intensity per category, confirm before applying)
.\Optimize-Windows11.ps1 -Level Custom

# Roll back (elevated)
.\Optimize-Windows11.ps1 -ListSnapshots          # see snapshot ids
.\Optimize-Windows11.ps1 -Rollback               # undo the last run (Level stack)
.\Optimize-Windows11.ps1 -Rollback -IncludeAI     # peel just the AI add-on back off
.\Optimize-Windows11.ps1 -Rollback -IncludeGaming # peel just the Gaming add-on back off
.\Optimize-Windows11.ps1 -Rollback -All          # undo everything, back to baseline
```

## Requirements

- Windows 11, Windows PowerShell **5.1**, run **as Administrator**.

## Author

- **Author:** Wolfram Halatschek · **Contact:** dev@kMarflow.com

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **DO NOT USE ON PRODUCTION SYSTEMS — THIS IS UNFINISHED SOFTWARE.**
- Provided as-is, not supported by Microsoft.

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

## How this differs from TBOK (and why)

TBOK is an excellent, fast, one-click tool. This project intentionally makes **different trade-offs**,
because the biggest real-world risk with an optimizer is not "too little speed" — it's **breaking Windows
or letting it degrade over time**. Every difference below exists to keep the machine healthy and every
change reversible.

- **Services: normalized, not mass-disabled.** TBOK sets **200+ services** to Manual/Disabled. We do
  *not*. Aggressive service disabling is the single most common way these tools break Windows: features
  silently stop working, Windows Update or the Store fail weeks later, and the cause is hard to trace. We
  touch only a small, well-understood set (a few safe services to Manual, and the telemetry services at
  Full) and otherwise **normalize** core services *toward* their correct Windows defaults — never below.
- **Telemetry is reduced, not blacked out, by default.** Fully zeroing telemetry and killing DiagTrack can,
  over time, interfere with Windows Update, the Store, licensing and staged feature rollouts. **Balanced
  keeps diagnostic data at "Required" (1)**; only **Full** — behind a confirmation prompt — turns it fully
  off. TBOK blacks it out unconditionally.
- **Windows Defender is never touched.** No level or add-on weakens Defender AV, real-time protection,
  tamper protection, SmartScreen or the security services — this is a hard, code-enforced guard. (The only
  Defender item that will ever be touchable is sample submission, opt-in, and it is not implemented yet.)
- **The power plan and boot config are left alone.** We deliberately **never create/activate the
  Ultimate-Performance plan** and make **no `bcdedit` boot-parameter changes** (HPET/`useplatformclock`,
  F8 menu). These are contentious and can hurt as often as help.
- **Everything is tiered and reversible.** TBOK is all-or-nothing; we offer **Minimal / Balanced / Full /
  guided Custom**, per-run **stacked rollback** with generated undo scripts, a **VSS restore point**, and
  independently revertible **AI / Gaming** add-ons.
- **We also skip a few TBOK items on purpose:** its OOBE-bypass keys (an imaging-time concern), obscure
  firmware/feature-flag overrides, and leaving the System Restore throttle permanently at 0 (we set it only
  for our own checkpoint and put it back).

**Still coming from TBOK's feature set:** Appx debloat (Widgets/Bing), pagefile sizing, a scheduled-task
engine (e.g. Office telemetry tasks), and an opt-in `bcdedit` engine.

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

## Benchmark

A rough, **indicative** benchmark on a single VirtualBox VM (Windows 11, 8 GB RAM). This is not a
controlled or bare-metal test, so treat the figures as **relative trends, not precise numbers**.

**Method:** for each configuration — restore a clean snapshot → apply → cold reboot → then, from logon,
sample CPU, free RAM (WMI `FreePhysicalMemory`, cross-checked against the hypervisor's
`Guest/RAM/Usage/Free` — the two agreed to within ~1%), process count and disk-time every 10 s for 12 min.
The table below is the **steady 10-minute window** (after a ~2-minute post-logon ramp), **averaged over 3
runs each** (Minimal has 1 usable run and Full 2 — the rest were lost to VM reboot/monitor timeouts).
`Full` already includes the AI + Gaming add-ons.

Steady-state, lower is better:

| Configuration            | CPU % | RAM used (MB) | Processes | Disk-time %† |
|--------------------------|------:|--------------:|----------:|-------------:|
| Baseline (no optimization) |  58 |          2474 |       147 |          108 |
| AI + Gaming only         |    61 |          2416 |       146 |           46 |
| Minimal ‡                |    62 |          2619 |       146 |          113 |
| Minimal + AI + Gaming    |    54 |          2448 |       144 |          140† |
| Balanced                 |    48 |          2395 |       141 |           54 |
| Balanced + AI + Gaming   |    40 |          2199 |       137 |           47 |
| Full                     |    32 |          2193 |       125 |           16 |

Improvement vs baseline (steady state):

| Configuration          | CPU  | RAM  | Processes |
|------------------------|-----:|-----:|----------:|
| Balanced               | −18% |  −3% |       −4% |
| Balanced + AI + Gaming | −31% | −11% |       −7% |
| Full                   | −45% | −11% |      −15% |

Takeaways:

- **Full** gives the largest steady-state reduction: ~45% less CPU, ~11% less RAM, ~15% fewer processes,
  and by far the lowest disk activity.
- **Balanced** already roughly halves background CPU (~18%) while staying far less aggressive.
- The **AI + Gaming add-ons add real headroom on top of a tier** — Balanced + AI + Gaming cut steady CPU a
  further ~13 points and RAM ~200 MB versus Balanced alone.
- **Minimal** and **AI + Gaming only** sit within the VM's run-to-run noise for CPU/RAM (they are UI /
  privacy / quality-of-life changes, not resource reducers); AI + Gaming only did noticeably cut disk
  activity (Game DVR off).

† Disk-time is very spiky run-to-run (a single background task can spike it past 100%); only large gaps are
meaningful. ‡ Minimal is a single run and its numbers are within noise. Boot time showed **no reliable
trend** on this VM (run-to-run variance dwarfed any difference) and is omitted. Overall run-to-run variance
was high — baseline steady-CPU alone ranged 48–72% across its three runs — so read every number as a trend.

## Requirements

- Windows 11, Windows PowerShell **5.1**, run **as Administrator**.

## Author

- **Author:** Wolfram Halatschek · **Contact:** dev@kMarflow.com

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **DO NOT USE ON PRODUCTION SYSTEMS — THIS IS UNFINISHED SOFTWARE.**
- Provided as-is, not supported by Microsoft.

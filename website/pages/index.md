---
title: Overview
template: home.html
hide:
  - navigation
  - toc
---

<div class="pst-features" markdown>

<div class="pst-feature" markdown>
:material-wrench-outline:{ .pst-icon }

### [Repair-System](manual/repair-system.md)

<p class="pst-kind">Module</p>

DISM and SFC, component store cleanup, a Windows Update reset that keeps the update history, WMI and ConfigMgr client repair. One remoting session, one log, a per-step exit code.
</div>

<div class="pst-feature" markdown>
:material-broom:{ .pst-icon }

### [TempDataCleanup](manual/tempdatacleanup.md)

<p class="pst-kind">Module</p>

User and system temp, logs, browser and Teams caches, and the ConfigMgr, Intune, Adaptiva and Windows Update content caches. A whole device list in parallel.
</div>

<div class="pst-feature" markdown>
:material-account-remove-outline:{ .pst-icon }

### [removeUserProfile.ps1](manual/scripts.md#removeuserprofileps1)

<p class="pst-kind">Script</p>

Removes Windows user profiles after backing up their registry keys, mapped drives and printers. Renames the folder to `.old`, or deletes it with `-Delete`.
</div>

<div class="pst-feature" markdown>
:material-delete-sweep-outline:{ .pst-icon }

### [AutoDeskCleanRemove.ps1](manual/scripts.md#autodeskcleanremoveps1)

<p class="pst-kind">Script</p>

Autodesk's clean uninstall (2022 and newer), unattended: every bundle and MSI product, folders, user data and registry keys, backed up first. Ready for Intune and ConfigMgr.
</div>

<div class="pst-feature" markdown>
:material-key-outline:{ .pst-icon }

### [CredentialHandler](manual/credentialhandler.md)

<p class="pst-kind">Module</p>

`Get-CredentialObject` asks for credentials in the console, where `Get-Credential` fails in Windows PowerShell 5.1 with Windows Terminal as the default terminal.
</div>

<div class="pst-feature" markdown>
:material-link-variant:{ .pst-icon }

### [Shortcuts](manual/shortcuts.md)

<p class="pst-kind">Module</p>

`Get-Shortcut` reads target, arguments, icon and hotkey of `.lnk` files, one file or a whole folder. `Set-Shortcut` creates or changes them.
</div>

</div>

## Built for IT work

- **Local or remote.** Repair-System and TempDataCleanup run on the local computer or over PowerShell remoting (WinRM), for one computer, a list or the pipeline, and copy their logs back to your PC.
- **Nothing half done.** What Windows keeps locked is finished at the next restart, and the run tells you so.
- **Logs you can read.** Repair-System, TempDataCleanup, removeUserProfile and AutoDeskCleanRemove write CMTrace-compatible logs, so they open in CMTrace or OneTrace with warnings and errors highlighted.
- **Exit codes for deployment tools.** Repair-System and the scripts return documented exit codes for ConfigMgr, Intune, scheduled tasks and your own scripts; Repair-System adds a detailed per-step code.
- **Careful by design.** TempDataCleanup refuses drive roots and system folders, the scripts back up registry keys before deleting them, and the invasive options ask before they run.

## Get the tools

The four modules come as one suite with an installer: one for all users (needs admin rights), one for your account only. Both are on the [latest release](https://github.com/halatsWol/PowerShell-Tools/releases/latest). The scripts are single `.ps1` files in the [repository](https://github.com/halatsWol/PowerShell-Tools/tree/main/scripts). The [user manual](manual/index.md) has the steps.

[:material-download: Download the installer](https://github.com/halatsWol/PowerShell-Tools/releases/latest){ .md-button .md-button--primary } [:fontawesome-brands-github: View on GitHub](https://github.com/halatsWol/PowerShell-Tools){ .md-button }

!!! warning "Review before you run"
    These tools repair, clean up and remove things on Windows systems. Read what a command does, test it on a test machine first, and only run it on devices you're authorized to change. They are provided as-is and are not supported by Microsoft.

## Documentation

<div class="pst-docs" markdown>

[:material-book-open-variant: **User manual**<br><span>Install, requirements, remote runs, config files, logs and exit codes, and a page per module and script.</span>](manual/index.md)

[:material-lifebuoy: **Help & troubleshooting**<br><span>Commands not found, remote connections, credential prompts, and how to report a problem.</span>](help.md)

[:material-tag-outline: **Releases**<br><span>The installers and the change log of every version, on GitHub.</span>](https://github.com/halatsWol/PowerShell-Tools/releases)

</div>

## Support

Questions: write to [contact@kmarflow.com](mailto:contact@kmarflow.com). A problem: [open an issue on GitHub](https://github.com/halatsWol/PowerShell-Tools/issues/new?template=issue_report.yml) or write an e-mail; [Reporting a problem](help.md#reporting-a-problem) lists what to include. An idea: [suggest it on GitHub](https://github.com/halatsWol/PowerShell-Tools/issues/new?template=feature_request.yml). News and articles are on the [blog at kmarflow.com](https://www.kmarflow.com), and the [PowerShell cmdlets](https://www.kmarflow.com/toolbox/cmdlets/) collection there has more commands for daily admin work.

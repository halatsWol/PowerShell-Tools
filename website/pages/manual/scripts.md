# Scripts

The scripts are single `.ps1` files in the [scripts folder](https://github.com/halatsWol/PowerShell-Tools/tree/main/scripts) of the repository. They aren't part of the installer: download the one you need and run it in an elevated Windows PowerShell, as described in [Run a script](index.md#run-a-script). Each has its full help built in:

```powershell
Get-Help .\AutoDeskCleanRemove.ps1 -Full
```

## removeUserProfile.ps1

Removes one or more Windows user profiles. System profiles are never listed; folders in the profiles directory without a profile registration (orphaned folders) are listed too.

For every selected profile, the script:

1. Skips it if its folder isn't directly below the profiles directory, or if any process runs as the user (signed in, or a service or task using the account).
2. Backs up the profile's registry keys, its mapped network drives (as a `.cmd` file that maps them again) and its printer connections. If a backup fails, nothing is changed.
3. Renames the profile folder to `<User>-<Date>.old` and removes the profile registration, or with `-Delete` removes the profile and its folder permanently.

What can't be done right away, because Windows holds the hive or files are locked, is finished during a restart: the folder is renamed at boot before any service starts, and a one-shot task completes the rest and removes itself.

| Parameter | What it does |
| --- | --- |
| `-UserName` | Profile folder name(s) to remove. Without it, the profiles are listed with a number and you select them: numbers, ranges and user names, comma separated (`1,3-5,jdoe`). |
| `-Delete` | Deletes the profiles permanently instead of renaming the folders to `.old`. Alias `-DeleteProfile`. |
| `-NoRestart` | Doesn't offer a restart when work was deferred; it runs at the next regular restart. Wins over `-ForceRestart`. |
| `-ForceRestart` | Restarts the computer 60 seconds after the run, without asking, when work was deferred. |

```powershell
# List the profiles, select them, rename the folders to .old
.\removeUserProfile.ps1

# Delete the profiles of jdoe and mmuster permanently
.\removeUserProfile.ps1 -UserName jdoe, mmuster -Delete
```

Logs and backups: `C:\_IT-ProfileCleanup\<Timestamp>_ProfileCleanup\`, one subfolder per profile.

| Exit code | Meaning |
| --- | --- |
| `0` | All selected profiles were removed, or nothing was selected. |
| `1` | Not elevated, the log folder couldn't be created, or at least one profile failed. |
| `3010` | Done so far; a restart finishes the deferred work. |

Profile deletion through `Win32_UserProfile`, its safety checks and the multi-profile selection are based on a profile cleanup script by [Dumpweed-Git](https://github.com/dumpweed-git).

## AutoDeskCleanRemove.ps1

Carries out [Autodesk's clean uninstall procedure](https://www.autodesk.com/support/technical/article/caas/sfdcarticles/sfdcarticles/Clean-uninstall.html) for versions 2022 and newer, unattended:

1. Stops the Autodesk services and processes, uninstalls every Autodesk bundle silently through ODIS (object enablers, then updates, then products), then every Autodesk MSI product still installed, and runs the Autodesk Access, ODIS and Licensing removers.
2. Runs the Autodesk Identity Manager uninstaller and the remaining uninstall helpers.
3. Removes leftover Autodesk services, clears `%TEMP%` of every profile, and deletes the Autodesk folders under Program Files, Common Files, ProgramData and every user profile.
4. Deletes `SOFTWARE\Autodesk` from HKLM and every user hive.
5. Uninstalls the Autodesk Genuine Service last, and removes shortcuts, file associations and PATH entries that still point into the deleted folders.

Every registry key and value it deletes is exported to a `.reg` backup first. Before it asks to proceed, it shows an estimated duration based on the size of what's installed. What's locked while Windows runs is finished at the next boot by a one-shot task. The exit code reflects the verified end state.

!!! danger "Before you run it"
    It removes the Autodesk data of **every** profile on the computer, including customizations under `AppData\Roaming\Autodesk`, and clears every profile's `%TEMP%`. Run it with `-WhatIf` first if you're unsure. **Uninstall Autodesk Fusion manually beforehand**: the script can't uninstall it, but deletes the folder it lives in. Not tested with Fusion 360.

| Parameter | What it does |
| --- | --- |
| `-LogPath` | Folder for the logs and the registry backup. Default `C:\_ADSK_CleanUninstall`. |
| `-LogLevel` | `None`, `Error`, `Warning`, `Info` or `Verbose` (default; embeds the full MSI logs in the main log). `Info` keeps the MSI logs as separate files. |
| `-Unattended` | No prompts and no completion toast. Required for Intune, ConfigMgr or any headless run. |
| `-NoRestart` | Never offers a restart. Wins over `-ForceRestart`. |
| `-ForceRestart` | Restarts as soon as the run completes, so the boot-time cleanup finishes right away. |
| `-WhatIf` | Dry run: reports everything it would uninstall, delete and schedule, and changes nothing. |

```powershell
# Interactive run
.\AutoDeskCleanRemove.ps1

# Dry run, changes nothing
.\AutoDeskCleanRemove.ps1 -WhatIf

# Deployment tool: no prompts, restart right away
.\AutoDeskCleanRemove.ps1 -Unattended -ForceRestart
```

| Exit code | Meaning |
| --- | --- |
| `0` | Completed; nothing left to finish. |
| `3010` | Completed; a restart finishes the cleanup. |
| `10` | Completed, but at least one product needed a forced Windows Installer cleanup. Verified clean; a restart is required. Map `10` to *Soft reboot* in ConfigMgr (deployment type ▸ Return Codes) or Intune (Win32 app ▸ Return codes), otherwise it counts as a failure. |
| `1` | Not elevated, the log folder couldn't be created, or Autodesk products or entries are left. |

One run plus one restart is normally enough. Running it a second time afterwards is a safe way to confirm nothing is left.

## bulkUninstall.ps1

Uninstalls the Windows Installer (MSI) products of one vendor. It asks for the vendor name, lists the matching products with a number, and lets you take products off the list before it uninstalls the rest. Uninstalling all Microsoft products needs an extra confirmation. The log is written to `C:\_temp\`.

!!! warning "Use at your own risk"
    Uninstalling software in the wrong order can damage other software components. Check the list before you confirm.

```powershell
.\bulkUninstall.ps1
```

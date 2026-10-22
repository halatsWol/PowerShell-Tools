# Getting started

PowerShell-Tools is a collection of PowerShell modules and scripts for IT work on Windows devices. The **modules** are installed together as a suite and give you new commands in every PowerShell session. The **scripts** are single `.ps1` files you download and run when you need them.

| Tool | Kind | What it does |
| --- | --- | --- |
| [Repair-System](repair-system.md) | Module | DISM, SFC, component store cleanup, Windows Update reset, WMI and ConfigMgr client repair, locally or remotely |
| [TempDataCleanup](tempdatacleanup.md) | Module | Cleans temp data, logs, browser, Teams and software-distribution caches on one or many devices |
| [CredentialHandler](credentialhandler.md) | Module | Asks for credentials in the console where `Get-Credential` fails |
| [Shortcuts](shortcuts.md) | Module | Reads, creates and changes `.lnk` shortcuts |
| [removeUserProfile.ps1](scripts.md#removeuserprofileps1) | Script | Removes Windows user profiles after a backup |
| [AutoDeskCleanRemove.ps1](scripts.md#autodeskcleanremoveps1) | Script | Clean uninstall of all Autodesk products (2022 and newer) |
| [bulkUninstall.ps1](scripts.md#bulkuninstallps1) | Script | Uninstalls the MSI products of one vendor |

## Requirements

- Windows with **Windows PowerShell 5.1**. The installers also put the modules into the module folder of PowerShell 7.
- **Administrator rights** on the device you repair or clean up. Start PowerShell with *Run as administrator* for local runs.
- For remote runs: **PowerShell remoting (WinRM)** enabled on the remote computer, and an account with administrator rights there. See [Remote computers](#remote-computers).

## Install the modules

1. Open the [latest release](https://github.com/halatsWol/PowerShell-Tools/releases/latest) on GitHub and download one of the installers:
    - `Setup_PowershellModulesSuite.exe` installs for **all users** and needs administrator rights. The modules go to `C:\Program Files\WindowsPowerShell\Modules` and `C:\Program Files\PowerShell\Modules`.
    - `Setup_PowershellModulesSuite_UserInstaller.exe` installs for **your account only**, without administrator rights. The modules go to `WindowsPowerShell\Modules` and `PowerShell\Modules` in your Documents folder.
2. Close all PowerShell windows, then run the installer.
3. Open a new PowerShell window. The modules are only found in sessions started after the installation.

Check that they're there:

```powershell
Get-Module -ListAvailable RepairSystem, TempDataCleanup, CredentialHandler, Shortcuts
```

**Updating:** run the installer of the newer release; it replaces the installed version. **Removing:** Settings ▸ Apps ▸ Installed apps ▸ *PowerShell-Tools - Modules Suite* ▸ Uninstall.

!!! note "Use one of the two installers"
    PowerShell finds the modules in your Documents folder before the ones in Program Files. If both installers were used, the copy that's found first may be the older one, so keep only one.

## Help in PowerShell

Every module has its help built in, with all parameters and examples:

```powershell
Get-Help Repair-System -Full
Get-Help Invoke-TempDataCleanup -Examples
Get-Help about_RepairSystem
Get-Command -Module TempDataCleanup
```

The module pages of this manual (in the menu) are the same text as the module READMEs on GitHub.

## Remote computers

`Repair-System` and `Invoke-TempDataCleanup` take `-ComputerName`. Without it they work on the local computer; with it they connect through PowerShell remoting and run every step over that one connection.

- The remote computer needs WinRM enabled, for example with `Enable-PSRemoting` or by Group Policy. Test it with `Test-WSMan PC042`.
- Use computer names. With IP addresses, Windows can't use Kerberos, and the connection needs the address in WinRM's TrustedHosts list or HTTPS.
- Start PowerShell as a user with administrator rights on the remote computer, or pass credentials with `-Credentials`. If `Get-Credential` fails without asking, use `Get-CredentialObject` from [CredentialHandler](credentialhandler.md):

```powershell
Repair-System -ComputerName PC042 -Credentials (Get-CredentialObject)
```

Several computers: pass a list or use the pipeline. Repair-System repairs them one after another; TempDataCleanup cleans them in parallel (`-ThrottleLimit`, default 10).

```powershell
Get-Content .\devices.txt | Invoke-TempDataCleanup -IncludeSystemData
```

## Config files

Repair-System and TempDataCleanup read an optional config file from their module folder. `-init` writes it with the defaults and never overwrites an existing one; with `-init`, nothing else runs. The module folder in Program Files is only writable with administrator rights.

```powershell
Repair-System -init
Invoke-TempDataCleanup -init
```

| Module | File | Keys (default) |
| --- | --- | --- |
| Repair-System | `RepairSystem.conf` | `TempDirName=_IT-temp`: the work folder below the target's system drive<br>`FinalDestinationPath=C:\remote-Files`: where the logs of remote runs go on your PC |
| TempDataCleanup | `TempDataCleanup.conf` | `TempFolder=_IT-temp`: the work folder below the target's system drive<br>`LocalTargetPath=C:\remote-Files`: where the logs of remote runs go on your PC |

Blank lines and lines starting with `#` are ignored.

## Logs

These logs are CMTrace-compatible: open them with CMTrace or OneTrace from Configuration Manager to see warnings and errors highlighted, or with any text editor.

| Tool | Where the log is |
| --- | --- |
| Repair-System | Local runs: `<SystemDrive>\_IT-temp`. Remote runs: `C:\remote-Files\<Computer>` on your PC. |
| TempDataCleanup | `<SystemDrive>\_IT-temp` on the device; for remote runs copied to `C:\remote-Files\<Computer>` on your PC. |
| removeUserProfile.ps1 | `C:\_IT-ProfileCleanup\<Timestamp>_ProfileCleanup\`, with the backups. |
| AutoDeskCleanRemove.ps1 | `C:\_ADSK_CleanUninstall`, with the registry backup (`-LogPath` to change). |

## Exit codes and restarts

- **Repair-System** sets `$LASTEXITCODE` to `0` (success), `1` (a step reported a problem) or `2` (nothing ran). The detailed per-step code is printed at the end and kept in `$global:RepairSystemDetailedExitCode`; `Repair-System -AnalyzeExitCode <code>` explains it. See [Exit Codes](repair-system.md#exit-codes).
- **removeUserProfile.ps1 and AutoDeskCleanRemove.ps1** exit with `0` (done), `3010` (done, a restart finishes the work) or `1` (failed, or something is left). AutoDeskCleanRemove adds `10`; see [Scripts](scripts.md).

Several tools finish what Windows keeps locked during the next restart: files are queued for deletion at boot, or a one-shot task runs once and removes itself. When a run says a restart is required, restart the device to complete it.

## Run a script

The scripts aren't part of the installer. Download the `.ps1` file from the [scripts folder](https://github.com/halatsWol/PowerShell-Tools/tree/main/scripts) on GitHub (open the file, then *Download raw file*), then in an elevated Windows PowerShell:

```powershell
Unblock-File .\removeUserProfile.ps1
Get-Help .\removeUserProfile.ps1 -Full
.\removeUserProfile.ps1
```

If the execution policy blocks scripts, allow it for this one PowerShell process only:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

!!! warning "Review before you run"
    These tools change, clean up and remove things on Windows systems. Read the help of a command before you use it, test it on a test machine first, and only run it on devices you're authorized to change. They are provided as-is and are not supported by Microsoft.

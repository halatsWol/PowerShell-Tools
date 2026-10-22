# Help & troubleshooting

## Installing and loading

### A command isn't found after installing

- Open a **new** PowerShell window. The modules are only found in sessions started after the installation.
- Check where PowerShell finds them: `Get-Module -ListAvailable RepairSystem, TempDataCleanup, CredentialHandler, Shortcuts`. The current-user installer installs for the account that ran it only; another user or an elevated session under a different admin account doesn't see those modules. Use the all-users installer then.
- If the execution policy is `Restricted`, PowerShell loads no modules. Allow local scripts for your account with `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`, or ask your administrator if a policy sets it.

### Get-Help or a command shows an older version

PowerShell finds the modules in your Documents folder before the ones in Program Files. If both installers were used, uninstall the one you don't need (Settings ▸ Apps ▸ Installed apps), then open a new PowerShell window. `Get-Module -ListAvailable RepairSystem | Select-Object Name, Version, ModuleBase` shows every copy and where it is.

### A script doesn't start: "running scripts is disabled" or "not digitally signed"

Files downloaded from the internet are marked as such, and the execution policy blocks them. Unblock the file and allow scripts for the current PowerShell process:

```powershell
Unblock-File .\removeUserProfile.ps1
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\removeUserProfile.ps1
```

## Remote runs

### Connecting to the remote computer fails

1. Check that WinRM answers: `Test-WSMan PC042`. If it doesn't, enable remoting on the remote computer (`Enable-PSRemoting` in an elevated PowerShell there, or by Group Policy) and check that a firewall doesn't block it (TCP 5985 for HTTP).
2. Check that you can open a session yourself: `Enter-PSSession PC042`. If that fails with *Access denied*, your account isn't an administrator on the remote computer. Pass other credentials with `-Credentials`.
3. Use the computer name, not the IP address. With an IP address, Windows can't use Kerberos, and the connection needs the address in WinRM's TrustedHosts list or HTTPS.

Repair-System reopens a dropped connection for up to 90 seconds; steps that can't run after that are marked as skipped (`5` in the detailed exit code).

### Get-Credential fails without asking

In Windows PowerShell 5.1 with Windows Terminal as the default terminal application, `Get-Credential` can fail at once with *Cannot process command because of one or more missing mandatory parameters: Credential*. Use `Get-CredentialObject` from the [CredentialHandler](manual/credentialhandler.md) module instead; it asks in the console:

```powershell
Invoke-TempDataCleanup -ComputerName PC042 -Credentials (Get-CredentialObject)
```

## Results and restarts

### The run says a restart is required

Windows keeps some files open while it runs: update caches, logs, a profile hive. The tools queue what's locked for deletion at the next boot, or register a one-shot task that runs once and removes itself. Restart the device to finish. removeUserProfile and AutoDeskCleanRemove exit with `3010` then, Repair-System shows the step as *Success (restart required)*, and TempDataCleanup sets `RestartRequired` in its `-PassThru` result.

### What does a Repair-System exit code mean?

Let it explain the code. Put it in quotes, so leading zeros are kept:

```powershell
Repair-System -AnalyzeExitCode "1701100000000"
```

The structure of the code is described under [Exit Codes](manual/repair-system.md#exit-codes).

### Where are the logs?

See [Logs](manual/index.md#logs) in the manual. For remote runs, Repair-System and TempDataCleanup copy them to `C:\remote-Files\<Computer>` on your PC.

## Reporting a problem

[Open an issue on GitHub](https://github.com/halatsWol/PowerShell-Tools/issues/new?template=issue_report.yml) or write to [contact@kmarflow.com](mailto:contact@kmarflow.com). Please include:

- The tool and its version: `Get-Module -ListAvailable RepairSystem | Select-Object Name, Version`, or the `Version` in the help of a script (`Get-Help .\AutoDeskCleanRemove.ps1 -Full`).
- The Windows version (`winver`) and the PowerShell version (`$PSVersionTable.PSVersion`).
- The exact command you ran, and whether it ran locally or against a remote computer.
- What you expected, and what happened instead: the error message, the exit code, and for Repair-System the detailed exit code.
- The log of the run.

!!! warning "Remove personal data first"
    Logs contain computer names, user names and paths. Remove or anonymize what you don't want to share before you attach them to a public issue, or send them by e-mail instead.

## Suggesting a feature

[Suggest it on GitHub](https://github.com/halatsWol/PowerShell-Tools/issues/new?template=feature_request.yml) or by e-mail to [contact@kmarflow.com](mailto:contact@kmarflow.com): what you'd like to do, how you do it today, and how often you'd use it.

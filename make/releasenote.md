Easy installer for PowerShell-Tools v1.4.1

This .exe-installer will install the following Modules:

- [RepairSystem](https://github.com/halatsWol/PowerShell-Tools/tree/v1.4.1/modules/Repair-System) (v1.5)
- [TempDataCleanup](https://github.com/halatsWol/PowerShell-Tools/tree/v1.4.1/modules/TempDataCleanup) (v1.5)
- [Shortcuts](https://github.com/halatsWol/PowerShell-Tools/tree/v1.4.1/modules/Shortcuts) (v1.0)
- [CredentialHandler](https://github.com/halatsWol/PowerShell-Tools/tree/v1.4.1/modules/CredentialHandler) (v1.0)

# Change Log:

_from [v1.4.1](https://github.com/halatsWol/PowerShell-Tools/releases/tag/v1.4.1)_

- `Repair System`: added TimeOut for SFC, DISM & Windows Update Diagnostics

_from [v1.4](https://github.com/halatsWol/PowerShell-Tools/releases/tag/v1.4)_
- Installers for global Installation and User-Only
- Implementation to pass on Credentials for Authentication (for Remote devices only)
- Added CCM Repair Option to Repair-System
- PowerShell 7 Support (beta-availability, not yet thoroughly tested, cmdlets not migrated)

## New Module
### CredentialHandler _(from [v1.4](https://github.com/halatsWol/PowerShell-Tools/releases/tag/v1.4))_
#### Description

If Windows Terminal is set as default Terminal, powershell.exe will always open via Terminal
When starting Powershell directly via PowerShell.exe, the Get-Credential cmdlet may not prompt for credentials as expected, but throws instantly an error.
This bug is caused in the dotNet framework (dotNet Foundation), which is not maintained anymore (in favour of dotNet core), which should normally Prompt Users using WPF GUI, which fails.
(This Bug does not occur when starting PowerShell by directly starting Terminal, or  in PowerShell 7)

More information on the Bog on [Github: microsoft/Terminal - Issue #11847](https://github.com/microsoft/terminal/issues/11847#issuecomment-1402554766) and [Github: microsoft/Terminal - Issue #14119](https://github.com/microsoft/terminal/issues/14119)

An alternative Solution to this Custom Module is to enable ConsolePrompting in the Registry:
```Powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $true
```

#### Function

- **`Get-CredentialObject`:** will prompt for User-Credentials

#### Usage

- As One-Liner
```Powershell
PS C:\> Repair-System -ComputerName somePC1 -Credentials (Get-CredentialObject)

PowerShell credential request
Enter your credentials.
User Name: someDomain\someAdminUser
Password: ***************
...
```

- or as pre-defined Var (for multiple commands e.g. in a script)
```Powershell
PS C:\> $ComputerName = somePC1
PS C:\> $cred = Get-CredentialObject -UserName "someDomain\someAdminUser"

PowerShell credential request
Enter your credentials.
Password: ***************

PS C:\>
>> Invoke-TempDataCleanup -ComputerName $ComputerName -Credentials $cred
>> Repair-System -ComputerName $ComputerName -Credentials $cred
>> $cred = $null
```

## Changed Modules
### RepairSystem

#### Fixes:

- `-Computername`: Leading/Trailing Whitespaces will be trimmed and won't throw errors anymore.
- *DISM_Error.log* will now be properly added into the Dism log-file each time after DISM has been executed.
- reduced chance of DISM & SFC Error log handling to cause Access denied due to race conditions

#### Changes:

_from [v1.4.1](https://github.com/halatsWol/PowerShell-Tools/releases/tag/v1.4.1)_

- added TimeOut for SFC, DISM & Windows Update Diagnostics
  - timeout durations are as following:

   | Task | Duration |
   | ---- | --------: |
   | DISM CheckHealth | 15 min |
   | DISM Restore | 40 min |
   | DISM Analyze Component Store | 5 min |
   | DISM Component Store Cleanup | 20 min |
   | SFC | 20 min |
   | Diagnostics: WindowsUpdate | 15 min |
   | Diagnostics: BITS | 10 min|

  if any of these fail or run into Timeout, Restarting the device and re-running `Repair-System` is adviced.
  Durations are approximated average Duration for medium corrupted Systems. Duration may be changed with a Multiplicator.

#### New Features

- **`-ChangeTimeout`:** use decimal value to change when DISM/SFC and Windows Update Diagnostics will timeout (value `-ChangeTimeout 2` will double the time, `-ChangeTimeout 0.5` will half it).
Range = 0.25 - 10.0

_from [v1.4](https://github.com/halatsWol/PowerShell-Tools/releases/tag/v1.4)_
- **`-Credentials`:** to Authenticate Remote Access and permissions on a remote Machine
Accepts PSCredential Object (Get-Credential / Get-CredentialObject)
If non are provided, it will prompt for user-input (please keep the Bug in mind, mentioned in the CredentialHandler Module)
- **`-RepairCCM`:** Repairs the Microsoft Configuration Manager Client (Software Center) on the remote machine
Prints install Exit Code and copies the ccmsetup.log file to the log-Directory of the `Repair-System` Function

### TempDataCleanup
#### New Features

_from [v1.4](https://github.com/halatsWol/PowerShell-Tools/releases/tag/v1.4)_
- **`-Credentials`:** to Authenticate Remote Access and permissions on a remote Machine
Accepts PSCredential Object (Get-Credential / Get-CredentialObject)
If non are provided, it will prompt for user-input (please keep the Bug in mind, mentioned in the CredentialHandler Module)




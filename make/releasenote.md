Easy installer for PowerShell-Tools

This .exe-installer will install the following Modules:

- [RepairSystem](https://github.com/halatsWol/PowerShell-Tools/tree/v1.3/modules/Repair-System) (v1.4)
- [TempDataCleanup](https://github.com/halatsWol/PowerShell-Tools/tree/v1.3/modules/TempDataCleanup) (v1.5)
- [Shortcuts](https://github.com/halatsWol/PowerShell-Tools/tree/v1.3/modules/Shortcuts) (v1.0)
- [CredentialHandler](https://github.com/halatsWol/PowerShell-Tools/tree/v1.3/modules/CredentialHandler) (v1.0)

# Change Log:

- Installers for global Installation and User-Only
- PowerShell 7 Support (beta-availability, not yet thoroughly tested, cmdlets not migrated)

## New Module
### CredentialHandler
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
#### New Features

- **`-Credentials`:** to Authenticate Remote Access and permissions on a remote Machine
Accepts PSCredential Object (Get-Credential / Get-CredentialObject)
If non are provided, it will prompt for user-input (please keep the Bug in mind, mentioned in the CredentialHandler Module)
- **`-RepairCCM`:** Repairs the Microsoft Configuration Manager Client (Software Center) on the remote machine
Prints install Exit Code and copies the ccmsetup.log file to the log-Directory of the `Repair-System` Function

### TempDataCleanup
#### New Features

- **`-Credentials`:** to Authenticate Remote Access and permissions on a remote Machine
Accepts PSCredential Object (Get-Credential / Get-CredentialObject)
If non are provided, it will prompt for user-input (please keep the Bug in mind, mentioned in the CredentialHandler Module)




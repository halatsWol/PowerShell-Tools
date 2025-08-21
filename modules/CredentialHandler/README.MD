# CredentialHanler PowerShell Module

## Overview

The `CredentialHandler` PowerShell module provides a workaround for a Windows Terminal/Powershell bug when prompting for Credentials:

If Windows Terminal is set as  Default Terminal application, and Powershell is not started by opening the Terminal app but powershell.exe (even though this starts Terminal as well), `Get-Credential` will not prompt for missing parameters, but instead fail instantly with the error stating missing parameters.

```Powershell
PS C:\> Get-Credential

cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:
Credential

Get-Credential : Cannot process command because of one or more missing mandatory parameters: Credential.
At line:1 char:1
+ get-credential
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Get-Credential], ParameterBindingException
    + FullyQualifiedErrorId : MissingMandatoryParameter,Microsoft.PowerShell.Commands.GetCredentialCommand
```

This Bug only happens with Powershell 5.1 on Windows 10 & 11 22H2 and later, when Dotnet tries to open the Credential Prompt using WPF GUI.
This will not be fixed due to the bug being caused in DotNet foundation, which is not maintained due to .Net core.
This can be resolved e.g. by enabling ConsolePrompting. Otherwise this can be worked around using `Get-CredentialObject` from this module to prompt for Usernam/Password within PowerShell which will then return a Credential object which can be used in Functions (e.g. as paramater): e.g. `Repair-System -ComputerName remoteDevice1 -Credential (Get-CredentialObject)`

More information on the Bog on [Github: microsoft/Terminal - Issue #11847](https://github.com/microsoft/terminal/issues/11847#issuecomment-1402554766) and [Github: microsoft/Terminal - Issue #14119](https://github.com/microsoft/terminal/issues/14119)


## Functionality

### `Get-CredentialObject`

Propmts for missing Parameters - Username (if missing), Password (always) - and returns a PSCredential Object

#### Parameters

- **`-UserName`** (Optional): specify the user directly during Function-Call.

#### Example

```PowerShell
# Get Credential (will prompt for username & Password)
Get-CredentialObject

# Get Credential for provided Domain User (will prompt only for password)
Get-CredentialObject -UserName myDomain\myUser

# Get Credential for provided local User (will prompt only for password)
Get-CredentialObject -UserName .\localAdmin

# Get Credential inline of another Function-Call
invoke-SomeThing -ComputerName someComputer -Credential (Get-CredentialObject)
```



## Notes

- This script is provided as-is and is not supported by Microsoft.
- Test thoroughly before using on production systems as improper use may cause data loss or system instability.
- Ensure you understand the consequences before making system changes or deleting files.

## Author

- **Author**: Wolfram Halatschek
- **Contact**: halatschek.wolfram@gmail.com
- **Date**: 2025-08-16

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **NEVER MAKE SYSTEM CHANGES WITHOUT AUTHORIZATION.**
- **DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**

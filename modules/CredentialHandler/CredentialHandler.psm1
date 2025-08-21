function Get-CredentialObject {

    <#
    .SYNOPSIS
    Custom Get-Credential Module for PowerShell 5.1

    .DESCRIPTION
    This function prompts the user for their credentials (username and password)
    and returns a PSCredential object.

    This Module is intended as a lightweight workaround for a bug in PowerShell 5.1 on Windows 10 & 11, 22H2 and later:
    When starting Powershell directly via Powershell, the Get-Credential cmdlet may not prompt for credentials as expected, But throws instantly an error.
    This bug is caused in the dotNet framework (dotNet Foundation), which is not maintained anymore (in favour of dotNet core), which should normally Prompt Users using WPF GUI, which fails.
    (This Bug does not occur when starting PowerShell by directly starting Terminal, or  in PowerShell 7.)

    This bug will not be fixed (More details under https://github.com/microsoft/terminal/issues/14119 & https://github.com/microsoft/terminal/issues/11847)

    An alternative Solution to this Custom Module is to enable ConsolePrompting in the Registry:
    ```
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $true
    ```

    .PARAMETER UserName
    The username to use for the credential object. If not specified, the user will be prompted for a username.

    .EXAMPLE
    Get-CredentialObject -UserName admin

    .NOTES
    Author: Wolfram Halatschek
    E-Mail: dev@kMarflow.com
    Date: 2025-08-14
    #>

    param (
        [Parameter(Mandatory=$false,Position=0)]
        [ValidatePattern('^(([a-zA-Z0-9_.\-]+(\\[a-zA-Z0-9_.\-]+)*)|(\.\\[a-zA-Z0-9_.\-]+)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$')]
        [string]$UserName
    )

    Write-Host "`r`nPowerShell credential request`r`nEnter your credentials."
    if (-not $UserName) {
        $UserName = Read-Host -Prompt "User Name"
    }
    if (-not $Password) {
        $Password = Read-Host -Prompt "Password" -AsSecureString
    }

    return [pscredential]::new($UserName,$Password)
}
Export-ModuleMember -Function Get-CredentialObject
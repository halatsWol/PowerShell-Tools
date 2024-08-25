
function Invoke-RemoteProfileCleanup {

    <#
    .SYNOPSIS
    Cleans up a Windows User-Profile on a remote computer.

    .DESCRIPTION
    The function cleans up a Windows User-Profile on a remote computer. It deletes the user profile Registy Keys and renames the User-Profile Folder.

    .PARAMETER ComputerName
    The name of the remote computer.

    .PARAMETER UserName
    The name of the user whose profile should be cleaned up.

    .PARAMETER noPrinters
    If set, the function will not check installed printers and create an install-Printers.cmd File.

    .PARAMETER noNetDrives
    If set, the function will not check mapped network drives and create an install-NetDrives.cmd File.

    .PARAMETER Quiet
    If set, the function will not output any information.

    .PARAMETER ForceLogout
    If set, the function will log out the user if logged in, before cleaning the profile.

    .EXAMPLE
    Invoke-RemoteProfileCleanup -ComputerName "Computer01" -UserName "User01"

    Cleans up the profile of User01 on Computer01.

    .EXAMPLE
    Invoke-RemoteProfileCleanup -ComputerName "Computer01" -UserName "User01" -ForceLogout

    Cleans up the profile of User01 on Computer01. If User01 is logged in, the function will log out the user before cleaning the profile.

    .NOTES
    This script is provided as-is and is not supported by Microsoft. Use it at your own risk.
    WinRM must be enabled and configured on the remote computer for this script to work. Using IP addresses may require additional configuration.
    Using this script may require administrative privileges on the remote computer.
    In a Domain, powershell can be executed locally as the user wich has the necessary permissions on the remote computer.

    WARNING:
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT PERMISSION OR AUTHORIZATION.
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT UNDERSTANDING THE CONSEQUENCES.
    NEVER RUN SCRIPTS FROM UNTRUSTED SOURCES WITHOUT REVIEWING AND UNDERSTANDING THE CODE.
    DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING. IT MAY CAUSE DATA LOSS OR SYSTEM INSTABILITY.


    Author: Wolfram Halatschek
    E-Mail: halatschek.wolfram@gmail.com
    Date: 2024-08-25
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [ValidatePattern('^(([a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$')]
        [string]$ComputerName,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$UserName,

        [Parameter(Mandatory = $false)]
        [switch]$noPrinters,

        [Parameter(Mandatory = $false)]
        [switch]$noNetDrives,

        [Parameter(Mandatory = $false)]
        [switch]$Quiet,

        [Parameter(Mandatory = $false)]
        [switch]$ForceLogout
    )

    $profilePath = "$env:USERPROFILE\$ProfileName"
    $ExitCode = @()

    if (Test-Path $profilePath) {
        Remove-Item $profilePath -Recurse -Force
    }

    # Ping the remote computer to check availability
    $pingResult = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction Stop
    if (-not $pingResult) {
        Write-Error "Unable to reach $ComputerName. Please check the Device-Name or the network connection to the remote Device."
        $ExitCode[0]=2
        $exitCode=$exitCode | Sort-Object {$_} -Descending
        $exitCode = $exitCode -join ""
        $global:LASTEXITCODE = $ExitCode
        break
    }

    #check if device is connectable
    try{
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-Process | Out-Null
        } -Verbose:$VerboseOption -ErrorAction Stop
    } catch {
        $winRMexit = "Unable to establish a remote PowerShell session to $ComputerName. Please check the WinRM configuration.`r`n `r`n `r`nError: $_"
        Write-Error $winRMexit
        if (-not (Test-Path -Path $localTempPath)) {
            New-Item -Path $localTempPath -ItemType Directory -Force
        }
        Add-Content -Path "$localTempPath\remoteConnectError_$currentDateTime.log" -Value "[$currentDateTime] - ERROR:`r`n$winRMexit"
        $ExitCode[0]=3
        $exitCode=$exitCode | Sort-Object {$_} -Descending
        $exitCode = $exitCode -join ""
        $global:LASTEXITCODE = $ExitCode
        break
    }

    #check if user is logged in
    $user,$id = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        function Get-TSSessions {
            query user|
            #Parse output
            ForEach-Object {
                # trim spaces at beginning and end
                $_ = $_.trim()
                # insert , at specific places for ConvertFrom-CSV command
                $_ = $_.insert(22,",").insert(42,",").insert(47,",").insert(56,",").insert(68,",")
                # Remove every space two or more spaces
                $_ = $_ -replace "\s\s+",""
                $_ = $_ -replace ">" , ""
                # for debug purposes, comment out above row and uncomment row below
                #$_ = $_ -replace "\s","_"

                # output to pipe
                $_

            } |
            #Convert to objects
            ConvertFrom-Csv
        }

        $sessions = Get-TSSessions | Where-Object { $_.USERNAME -eq $using:USERNAME } | Select-Object USERNAME,ID

        return $sessions | ForEach-Object {$_.username,$_.ID}
    } -Verbose:$VerboseOption -ErrorAction Stop

    if (-not $ForceLogout){
        if ($user -eq $UserName) {
            Write-Error "User $UserName is still logged in on $ComputerName. Please log out the user before cleaning the profile."
            $ExitCode[0]=4
            $exitCode=$exitCode | Sort-Object {$_} -Descending
            $exitCode = $exitCode -join ""
            $global:LASTEXITCODE = $ExitCode
            break
        }
    } else {
        if ($user -eq $UserName) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                logoff $using:id
            } -Verbose:$VerboseOption -ErrorAction Stop
        }
    }
}

Export-ModuleMember -Function Invoke-RemoteProfileCleanup
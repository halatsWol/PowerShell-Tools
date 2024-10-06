function Invoke-TempDataCleanup {
    <#
    .SYNOPSIS
    Clean up temporary files from user profiles and system folders

    .DESCRIPTION
    This function will clean up temporary files from user profiles and system folders. It can be run on the local computer or on a remote computer.

    .PARAMETER ComputerName
    The name of the computer to run the cleanup on. Use "localhost" for the local computer.

    .PARAMETER Full
    If this switch is present, the cleanup will also include system folders.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01"

    This will clean up temporary files from user profiles on Computer01.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01" -Full

    This will clean up temporary files from user profiles and system folders on Computer01.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "localhost" -Full

    This will clean up temporary files from user profiles and system folders on the local computer.

    .NOTES
    This script is provided as-is and is not supported by Microsoft. Use it at your own risk.
    WinRM must be enabled and configured on the remote computer for this script to work. Using IP addresses may require additional configuration.
    Using this script may require administrative privileges on the remote computer.
    In a Domain, powershell can be executed locally as the user wich has the necessary permissions on the remote computer.


    Further information:
    https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-5.1




    WARNING:
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT PERMISSION OR AUTHORIZATION.
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT UNDERSTANDING THE CONSEQUENCES.
    NEVER RUN SCRIPTS FROM UNTRUSTED SOURCES WITHOUT REVIEWING AND UNDERSTANDING THE CODE.
    DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING. IT MAY CAUSE DATA LOSS OR SYSTEM INSTABILITY.


    Author: Wolfram Halatschek
    E-Mail: halatschek.wolfram@gmail.com
    Date: 2024-10-06
    #>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$false)]
        [switch]$Full

    )

    $userTempFolders=@(
            "\AppData\Local\Temp",
            "\AppData\Local\Microsoft\Office\16.0\OfficeFileCache\0"
            )
    $extuserTempFolders=@(
            "\AppData\Local\Microsoft\Windows\INetCache",
            "\AppData\Local\Mozilla\Firefox\Profiles\*\cache2",
            "\AppData\Local\Google\Chrome\User Data\*\Cache",
            "\AppData\Local\Google\Chrome\User Data\*\Media Cache",
            "\AppData\Local\Google\Chrome\User Data\*\Code Cache",
            "\AppData\Local\Google\Chrome\User Data\*\GPUCache",
            "\AppData\Local\Google\Chrome\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\Google\Chrome\User Data\*\Service Worker\ScriptCache"
            )
    $systemTempFolders=@(
            "$env:Windir\Temp",
            "$env:Windir\Prefetch",
            "$env:Windir\SofwareDistribution\Download"
            )

    #get user profile folders
    if ($ComputerName -ne $env:ComputerName -and $ComputerName -ne "localhost") {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -Exclude "Public","Default","Default User","All Users" | Select-Object -ExpandProperty Name
            foreach ($profile in $userProfiles) {
                if ($Full){$userTempFolders=$userTempFolders+$extuserTempFolders}
                try{
                    foreach ($folder in $userTempFolders) {
                        $path = "$env:SystemDrive\Users\$profile$folder"
                        if (Test-Path $path) {
                            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }catch{
                    Write-Warning "Error while cleaning up $profile :`r`n $_"
                }
            }

            if($Full) {
                foreach ($folder in $systemTempFolders) {
                    if (Test-Path $folder) {
                        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    } else {
        $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -Exclude "Public","Default","Default User","All Users" | Select-Object -ExpandProperty Name

        foreach ($profile in $userProfiles) {
            if ($Full){$userTempFolders=$userTempFolders+$extuserTempFolders}
            foreach ($folder in $userTempFolders) {
                $path = "$env:SystemDrive\Users\$profile$folder"
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }

        if($Full) {
            foreach ($folder in $systemTempFolders) {
                if (Test-Path $folder) {
                    Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

Export-ModuleMember -Function Invoke-TempDataCleanup
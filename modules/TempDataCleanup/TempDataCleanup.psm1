function Invoke-TempDataCleanup {
    <#
    .SYNOPSIS
    Clean up temporary files from user profiles and system folders

    .DESCRIPTION
    This function will clean up temporary files from user profiles and system folders. It can be run on the local computer or on a remote computer.

    .PARAMETER ComputerName
    The name of the computer to run the cleanup on. Use "localhost" for the local computer.

    .PARAMETER IncludeSystemData
    If this switch is present, the cleanup will also include system folders.

    .PARAMETER IncludeCCMCache
    If this switch is present, the cleanup will also include the Configuration Manager cache folder, if it exists.

    .PARAMETER IncludeBrowserData
    If this switch is present, the cleanup will also include browser cache folders.

    .PARAMETER IncludeMSTeamsCache
    If this switch is present, the cleanup will also include Microsoft Teams cache folders.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01"

    This will clean up temporary files from user profiles on Computer01.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData

    This will clean up temporary files from user profiles and system folders on Computer01.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "localhost" -IncludeSystemData -IncludeBrowserData

    This will clean up temporary files including Browser-Cache Data from user profiles and system folders on the local computer.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData -IncludeBrowserData -IncludeMSTeamsCache

    This will clean up temporary files including Browser-Cache Data and Microsoft Teams cache from user profiles and system folders on Computer01.

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
    Date: 2024-10-16
    #>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeSystemData,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeCCMCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeBrowserData,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeMSTeamsCache

    )

    $userTempFolders=@(
        "\AppData\Local\Temp",
        "\AppData\Local\Microsoft\Office\16.0\OfficeFileCache"
    )
    $BrowserData=@(
        # Microsoft Internet Explorer
        "\AppData\Local\Microsoft\Windows\INetCache",
        "\AppData\Local\Microsoft\Windows\INetCookies",
        # Microsoft Edge (Chromium)
        "\AppData\Local\Microsoft\Edge\User Data\*\Cache",
        "\AppData\Local\Microsoft\Edge\User Data\*\Media Cache",
        "\AppData\Local\Microsoft\Edge\User Data\*\Code Cache",
        "\AppData\Local\Microsoft\Edge\User Data\*\GPUCache",
        "\AppData\Local\Microsoft\Edge\User Data\*\Service Worker\CacheStorage",
        "\AppData\Local\Microsoft\Edge\User Data\*\Service Worker\ScriptCache",
        # Mozilla Firefox
        "\AppData\Local\Mozilla\Firefox\Profiles\*\cache2",
        "\AppData\Local\Mozilla\Firefox\Profiles\*\storage\default",
        # Google Chrome
        "\AppData\Local\Google\Chrome\User Data\*\Cache",
        "\AppData\Local\Google\Chrome\User Data\*\Media Cache",
        "\AppData\Local\Google\Chrome\User Data\*\Code Cache",
        "\AppData\Local\Google\Chrome\User Data\*\GPUCache",
        "\AppData\Local\Google\Chrome\User Data\*\Service Worker\CacheStorage",
        "\AppData\Local\Google\Chrome\User Data\*\Service Worker\ScriptCache"
        # Opera
        "\AppData\Local\Opera Software\Opera Stable\Cache",
        "\AppData\Local\Opera Software\Opera Stable\Media Cache",
        "\AppData\Local\Opera Software\Opera Stable\Code Cache",
        "\AppData\Local\Opera Software\Opera Stable\GPUCache",
        "\AppData\Local\Opera Software\Opera Stable\Service Worker\CacheStorage",
        "\AppData\Local\Opera Software\Opera Stable\Service Worker\ScriptCache",
        # Vivaldi
        "\AppData\Local\Vivaldi\User Data\*\Cache",
        "\AppData\Local\Vivaldi\User Data\*\Media Cache",
        "\AppData\Local\Vivaldi\User Data\*\Code Cache",
        "\AppData\Local\Vivaldi\User Data\*\GPUCache",
        "\AppData\Local\Vivaldi\User Data\*\Service Worker\CacheStorage",
        "\AppData\Local\Vivaldi\User Data\*\Service Worker\ScriptCache"
        # Brave
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Cache",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Media Cache",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Code Cache",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\GPUCache",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Service Worker\CacheStorage",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Service Worker\ScriptCache"


    )
    $systemTempFolders=@(
        "$env:Windir\Temp",
        "$env:Windir\Prefetch",
        "$env:Windir\SofwareDistribution\Download"
    )
    $msTeamsCacheFolder="\AppData\local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache"
    $teamsClassicPath="\AppData\Roaming\Microsoft\Teams"
    $ccmCachePath="$env:Windir\ccmcache"

    $localTargetPath = "C:\remote-Files\$ComputerName"
    $currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
    $logdir="C:\_temp"
    $logfile="$logdir\TempDataCleanup_$currentDateTime.log"


    if ($IncludeBrowserData){$userTempFolders=$userTempFolders+$BrowserData}
    #get user profile folders
    if ($ComputerName -ne $env:ComputerName -and $ComputerName -ne "localhost") {
        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
            Write-Warning "Computer $ComputerName is not reachable"
            return
        }
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -Exclude "Public","Default","Default User","All Users" | Select-Object -ExpandProperty Name
            New-Item -Path $using:logdir -ItemType Directory -Force > $null
            Add-Content -Path $using:logfile -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm"))] User Profile cleanup on $env:ComputerName:"
            foreach ($profile in $userProfiles) {
                Add-Content -Path $using:logfile -Value "`tUser Profile: $profile"
                try{
                    foreach ($folder in $using:userTempFolders) {
                        $path = "$env:SystemDrive\Users\$profile$folder"
                        if (Test-Path $path) {
                            Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                            Add-Content -Path $using:logfile -Value "`t`t> $path"
                        }
                    }
                }catch{
                    Write-Warning "Error while cleaning up $profile :`r`n $_"
                }

                if($using:IncludeMSTeamsCache) {
                    $path = "$env:SystemDrive\Users\$profile$using:msTeamsCacheFolder"
                    $bgPath="$path\Microsoft\MSTeams"
                    $bgBackupPath="$path\.."
                    #move $msTeamsCacheFolder\Microsoft\MSTeams\Backgrounds to $msTeamsCacheFolder
                    if (Test-Path "$bgPath\Backgrounds") {
                        Move-Item -Path "$bgPath\Backgrounds" -Destination "$bgBackupPath" -Force -ErrorAction SilentlyContinue
                    }
                    #cleanup $msTeamsCacheFolder
                    $cpath = "$path"
                    if (Test-Path $cpath) {
                        Remove-Item -Path "$cpath\*" -Recurse -Force -ErrorAction SilentlyContinue
                        Add-Content -Path $using:logfile -Value "`t`t> $cpath"
                    }
                    #create bgPath
                    if (-not (Test-Path $bgPath)) {
                        New-Item -Path $bgPath -ItemType Directory -Force -ErrorAction SilentlyContinue
                    }
                    if(Test-Path "$bgBackupPath\Backgrounds") {
                        Move-Item -Path "$bgBackupPath\Backgrounds" -Destination "$bgPath" -Force -ErrorAction SilentlyContinue
                    }
                    #cleanup $teamsClassicPath
                    $path = "$env:SystemDrive\Users\$profile$teamsClassicPath"
                    if (Test-Path $path) {
                        Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                        Add-Content -Path $using:logfile -Value "`t`t> $path"
                    }
                }

            }

            if($using:IncludeSystemData) {
                Add-Content -Path $using:logfile -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm"))] System cleanup on $env:ComputerName:"
                foreach ($folder in $systemTempFolders) {
                    if (Test-Path $folder) {
                        Remove-Item -Path "$folder\*" -Recurse -Force -ErrorAction SilentlyContinue
                        Add-Content -Path $using:logfile -Value "`t`t> $folder"
                    }
                }
            }

            if($using:IncludeCCMCache) {
                if(-not $using:IncludeSystemData){
                    Add-Content -Path $using:logfile -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm"))] System cleanup on $env:ComputerName:"
                }
                if (Test-Path $using:ccmCachePath) {
                    Remove-Item -Path "$using:ccmCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $using:logfile -Value "`t`t> $ccmCachePath"
                }
            }


        }

        if (-not (Test-Path -Path $localTargetPath)) {
            New-Item -Path $localTargetPath -ItemType Directory -Force
        }
        Copy-Item -Path "\\$ComputerName\C$\_temp\*" -Destination $localTargetPath -Recurse -Force

        # Clear remote _temp folder if copy was successful

        if ($?) {

            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                Remove-Item -Path "C:\_temp\*" -Recurse -Force
            } -Verbose:$VerboseOption

        } else {
            Write-Error "An error occurred while copying the log files from $ComputerName."
        }
    } else {
        $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -Exclude "Public","Default","Default User","All Users" | Select-Object -ExpandProperty Name
        New-Item -Path $logdir -ItemType Directory -Force > $null
        Add-Content -Path $logfile -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm"))] User Profile cleanup on $env:ComputerName:"
        foreach ($profile in $userProfiles) {
            Add-Content -Path $logfile -Value "`tUser Profile: $profile"
            foreach ($folder in $userTempFolders) {
                $path = "$env:SystemDrive\Users\$profile$folder"
                if (Test-Path $path) {
                    Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t> $path"
                }
            }
            if($IncludeMSTeamsCache) {
                $path = "$env:SystemDrive\Users\$profile$msTeamsCacheFolder"
                $bgPath="$path\Microsoft\MSTeams"
                $bgBackupPath="$path\.."
                #move $msTeamsCacheFolder\Microsoft\MSTeams\Backgrounds to $msTeamsCacheFolder
                if (Test-Path "$bgPath\Backgrounds") {
                    Move-Item -Path "$bgPath\Backgrounds" -Destination "$bgBackupPath" -Force -ErrorAction SilentlyContinue
                }
                #cleanup $msTeamsCacheFolder
                $cpath = "$path"
                if (Test-Path $cpath) {
                    Remove-Item -Path "$cpath\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t> $cpath"
                }
                #create bgPath
                if (-not (Test-Path $bgPath)) {
                    New-Item -Path $bgPath -ItemType Directory -Force -ErrorAction SilentlyContinue
                }
                if(Test-Path "$bgBackupPath\Backgrounds") {
                    Move-Item -Path "$bgBackupPath\Backgrounds" -Destination "$bgPath" -Force -ErrorAction SilentlyContinue
                }
                #cleanup $teamsClassicPath
                $path = "$env:SystemDrive\Users\$profile$teamsClassicPath"
                if (Test-Path $path) {
                    Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t> $path"
                }
            }
        }

        if($IncludeSystemData) {
            Add-Content -Path $logfile -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm"))] System cleanup on $env:ComputerName:"
            foreach ($folder in $systemTempFolders) {
                if (Test-Path $folder) {
                    Remove-Item -Path "$folder\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t> $folder"
                }
            }
        }

        if($IncludeCCMCache) {
            if(-not $IncludeSystemData){
                Add-Content -Path $logfile -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm"))] System cleanup on $env:ComputerName:"
            }
            if (Test-Path $ccmCachePath) {
                Remove-Item -Path "$ccmCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
                Add-Content -Path $logfile -Value "`t`t> $ccmCachePath"
            }
        }
    }
}

Export-ModuleMember -Function Invoke-TempDataCleanup
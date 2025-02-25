function New-Folder {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FolderPath
    )
    if (-not (Test-Path -Path $FolderPath)) {New-Item -Path $FolderPath -ItemType Directory -Force > $null}
}

function Start-UserCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$logfile,

        [Parameter(Mandatory=$true,Position=1)]
        [string[]]$userTempFolders,

        [Parameter(Mandatory=$true,Position=2)]
        [string[]]$userReportingDirs,

        [Parameter(Mandatory=$true,Position=3)]
        [string]$explorerCacheDir,

        [Parameter(Mandatory=$true,Position=4)]
        [string]$localIconCacheDB,

        [Parameter(Mandatory=$true,Position=5)]
        [string]$msTeamsCacheFolder,

        [Parameter(Mandatory=$true,Position=6)]
        [string]$teamsClassicPath,

        [Parameter(Mandatory=$true,Position=7)]
        [switch]$IncludeSystemLogs,

        [Parameter(Mandatory=$true,Position=8)]
        [switch]$IncludeIconCache,

        [Parameter(Mandatory=$true,Position=9)]
        [switch]$IncludeMSTeamsCache
    )

    $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -Exclude "Public","Default","Default User","All Users" | Select-Object -ExpandProperty Name
    Add-Content -Path $logfile -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] User Profile cleanup on $env:ComputerName:"
    foreach ($userProfile in $userProfiles) {
        Add-Content -Path $logfile -Value "`tUser Profile: $userProfile"
        try{
            foreach ($folder in $userTempFolders) {
                $path = "$env:SystemDrive\Users\$userProfile$folder"
                if (Test-Path $path) {
                    Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t> $path"
                }

            }
            if ($IncludeSystemLogs) {
                foreach ($folder in $userReportingDirs) {
                    $path = "$env:SystemDrive\Users\$userProfile$folder"
                    if (Test-Path $path) {
                        Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                        Add-Content -Path $logfile -Value "`t`t> $path"
                    }
                }
            }
            if ($IncludeIconCache) {
                $path = "$env:SystemDrive\Users\$userProfile$explorerCacheDir"
                Add-Content -Path $logfile -Value "`t`tcleaning Icon & ThumbCache:"
                $pathI = "$path\iconcache*.db"
                $pathT = "$path\thumbcache*.db"
                $pathLI = "$env:SystemDrive\Users\$userProfile$localIconCacheDB"
                if (Test-Path $path) {
                    Remove-Item -Path "$pathI" -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t`t> $pathI"
                    Remove-Item -Path "$pathT" -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t`t> $pathT"
                    Remove-Item -Path "$pathLI" -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logfile -Value "`t`t`t> $pathLI"
                }
            }
        }catch{
            Write-Warning "Error while cleaning up $userProfile :`r`n $_"
        }

        if($IncludeMSTeamsCache) {
            $path = "$env:SystemDrive\Users\$userProfile$msTeamsCacheFolder"
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
            $path = "$env:SystemDrive\Users\$userProfile$teamsClassicPath"
            if (Test-Path $path) {
                Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Add-Content -Path $logfile -Value "`t`t> $path"
            }
        }

    }
}

function Start-SystemCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$logfile,

        [Parameter(Mandatory=$true,Position=1)]
        [string[]]$systemTempFolders,

        [Parameter(Mandatory=$true,Position=2)]
        [string[]]$sysReportingDirs,

        [Parameter(Mandatory=$true,Position=3)]
        [string]$ccmCachePath,

        [Parameter(Mandatory=$true,Position=4)]
        [switch]$IncludeSystemData,

        [Parameter(Mandatory=$true,Position=5)]
        [switch]$IncludeSystemLogs,

        [Parameter(Mandatory=$true,Position=6)]
        [switch]$IncludeCCMCache
    )

    Add-Content -Path $logfile -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] System cleanup on $env:ComputerName:"

    if($IncludeSystemData) {
        foreach ($folder in $systemTempFolders) {
            if (Test-Path $folder) {
                Remove-Item -Path "$folder\*" -Recurse -Force -ErrorAction SilentlyContinue
                Add-Content -Path $logfile -Value "`t`t> $folder"
            }
        }
        Start-Sleep -Milliseconds 200
    }

    if($IncludeSystemLogs) {
        foreach ($folder in $sysReportingDirs) {
            if (Test-Path $folder) {
                Remove-Item -Path "$folder\*" -Recurse -Force -ErrorAction SilentlyContinue
                Add-Content -Path $logfile -Value "`t`t> $folder"
            }
        }
        Start-Sleep -Milliseconds 200
    }



    if($IncludeCCMCache) {
        if (Test-Path $ccmCachePath) {
            Remove-Item -Path "$ccmCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Add-Content -Path $logfile -Value "`t`t> $ccmCachePath"
        }
        Start-Sleep -Milliseconds 200
    }

    Add-Content -Path $logfile -Value "`r`n"
}


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

    .PARAMETER IncludeSystemLogs
    If this switch is present, the cleanup will also include system log files like $env:WinDir\Logs\,  $env:WinDir\Minidmp\.

    .PARAMETER IncludeCCMCache
    If this switch is present, the cleanup will also include the Configuration Manager cache folder, if it exists.

    .PARAMETER IncludeBrowserData
    If this switch is present, the cleanup will also include browser cache folders.

    .PARAMETER IncludeMSTeamsCache
    If this switch is present, the cleanup will also include Microsoft Teams cache folders.

    .PARAMETER IncludeIconCache
    If this switch is present, the cleanup will also include the User Icon & ThumbCache files.

    .PARAMETER IncludeAllPackages
    If this switch is present, the cleanup will also include the LocalCache folders of all packages in $env:localappdata\Packages.
    This will render IncludeMSTeamsCache irrelevant.

    USE WITH CAUTION! This will Clean Up all LocalCache folders of all packages in $env:localappdata\Packages.

    .PARAMETER init
    When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
    When specified, no other Parameter will be executed (other provided Parameters will be ignored). This will retun 0 if the Config-File was created successfully, or already exists.

    Configuration-File Template:
    ```
    ShareDrive=C$                                       # ShareDrive-Letter of the Remote-Device on which Windows is installed
    TempFolder=_IT-temp                                 # Name of the temporary Directory on the Remote-Device
    LocalTargetPath=C:\remote-Files\$ComputerName       # Path where the Logs and Files will be copied to on the executing Client
    ```


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
    E-Mail: wolfram@kMarflow.com
    Date: 2025-02-25
    #>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeSystemData,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeSystemLogs,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeCCMCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeBrowserData,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeMSTeamsCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeIconCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeAllPackages,

        [Parameter(Mandatory=$false)]
        [switch]$init

    )


    $confFile="$PSScriptRoot\TempDataCleanup.conf"
    if($init){
        $ShareDrive="C$"
        $TempFolder="_IT-temp"
        $LocalTargetPath="$env:SystemDrive\remote-Files\"

        if(-not (Test-Path $confFile)){
            try {
                New-Item -Path $confFile -ItemType File -Force
                Add-Content -Path $confFile -Value "ShareDrive=$ShareDrive"
                Add-Content -Path $confFile -Value "TempFolder=$TempFolder"
                Add-Content -Path $confFile -Value "LocalTargetPath=$LocalTargetPath"
            } catch {
                Write-Error "Error creating Config-File. Please check if the Module-Path is writable`r`n `r`n$_"
                $global:LASTEXITCODE = 1
                return
            }
        } else {
            Write-Warning "Config-File already exists. If you want to reset the Config-File, please delete it manually"
        }
        $global:LASTEXITCODE = 0
        return
    }

    $userTempFolders=@(
        "\AppData\Local\Temp",
        "\AppData\Local\Microsoft\Office\16.0\OfficeFileCache",
        "\AppData\Local\Microsoft\Office\15.0\Lync\Tracing",
        "\AppData\Local\Microsoft\Office\16.0\Lync\Tracing",
        "\AppData\Local\Microsoft\EdgeWebView\Cache",
        "\AppData\LocalLow\Sun\Java\Deployment\cache"
    )
    $commonUserPackages=@(
        "\AppData\Local\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\LocalCache",
        "\AppData\Local\Packages\Microsoft.WindowsCamera_8wekyb3d8bbwe\LocalCache",
        "\AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache",
        "\AppData\Local\Packages\Microsoft.DiagnosticDataViewer_8wekyb3d8bbwe\LocalCache",
        "\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalCache",
        "\AppData\Local\Packages\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe\LocalCache",
        "\AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache",
        "\AppData\Local\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\LocalCache",
        "\AppData\Local\Packages\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe\TempState",
        "\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TempState"
    )
    $allPackagesCacheFolder="\AppData\Local\Packages\*\LocalCache"
    $BrowserData=@(
        # general
        "\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData",
        # Microsoft Internet Explorer
        "\AppData\Local\Microsoft\Windows\INetCache",
        "\AppData\Local\Microsoft\Windows\INetCookies",
        # Microsoft Edge (Chromium)
        "\AppData\Local\Microsoft\Edge\User Data\*\Temp",
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
        "\AppData\Local\Google\Chrome\User Data\*\Temp",
        "\AppData\Local\Google\Chrome\User Data\*\Cache",
        "\AppData\Local\Google\Chrome\User Data\*\Media Cache",
        "\AppData\Local\Google\Chrome\User Data\*\Code Cache",
        "\AppData\Local\Google\Chrome\User Data\*\GPUCache",
        "\AppData\Local\Google\Chrome\User Data\*\Service Worker\CacheStorage",
        "\AppData\Local\Google\Chrome\User Data\*\Service Worker\ScriptCache"
        # Opera
        "\AppData\Local\Opera Software\Opera Stable\Temp",
        "\AppData\Local\Opera Software\Opera Stable\Cache",
        "\AppData\Local\Opera Software\Opera Stable\Media Cache",
        "\AppData\Local\Opera Software\Opera Stable\Code Cache",
        "\AppData\Local\Opera Software\Opera Stable\GPUCache",
        "\AppData\Local\Opera Software\Opera Stable\Service Worker\CacheStorage",
        "\AppData\Local\Opera Software\Opera Stable\Service Worker\ScriptCache",
        # Vivaldi
        "\AppData\Local\Vivaldi\User Data\*\Temp",
        "\AppData\Local\Vivaldi\User Data\*\Cache",
        "\AppData\Local\Vivaldi\User Data\*\Media Cache",
        "\AppData\Local\Vivaldi\User Data\*\Code Cache",
        "\AppData\Local\Vivaldi\User Data\*\GPUCache",
        "\AppData\Local\Vivaldi\User Data\*\Service Worker\CacheStorage",
        "\AppData\Local\Vivaldi\User Data\*\Service Worker\ScriptCache"
        # Brave
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Temp",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Cache",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Media Cache",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Code Cache",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\GPUCache",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Service Worker\CacheStorage",
        "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Service Worker\ScriptCache"
    )

    $explorerCacheDir="\AppData\Local\Microsoft\Windows\Explorer"
    $localIconCacheDB="\AppData\Local\IconCache.db"


    $systemTempFolders=@(
        "$env:Windir\Temp",
        "$env:Windir\Prefetch",
        "$env:Windir\WinSxS\Temp",
        "$env:Windir\SofwareDistribution\Download"
    )
    $msTeamsCacheFolder="\AppData\local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache"
    $teamsClassicPath="\AppData\Roaming\Microsoft\Teams"
    $ccmCachePath="$env:Windir\ccmcache"

    $userReportingDirs=@(
        "\AppData\Local\CrashDumps",
        "\Appdata\Local\D3DSCache",
        "\AppData\Local\Microsoft\Windows\WER\ReportQueue",
        "\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
    )

    $sysReportingDirs=@(
        "$env:Windir\Logs",
        "$env:Windir\Minidump",
        "$env:Windir\LiveKernelReports",
        "$env:Windir\System32\LogFiles\WMI",
        "$env:Windir\System32\LogFiles\setupcln",
        "$env:Windir\ServiceProfiles\LocalService\AppData\Local\CrashDumps",
        "$env:Windir\sysWOW64\config\systemprofile\AppData\Local\CrashDumps",
        "$env:Windir\system32\config\systemprofile\AppData\Local\CrashDumps",
        "$env:Windir\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache",
        "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
        "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
    )

    $LocalTargetPath = "$env:SystemDrive\remote-Files\"
    $TempFolder="_IT-temp"
    $ShareDrive="C$"

    if(Test-Path $confFile){
        $confData = Get-Content -Path $confFile
        foreach ($line in $confData) {
            $key, $value = $line -split '=', 2
            if ($key -eq "ShareDrive") {$ShareDrive=$value}
            elseif ($key -eq "TempFolder") {$TempFolder=$value}
            elseif ($key -eq "LocalTargetPath") {$LocalTargetPath=$value}
            else {
                Write-Warning "Unknown Key in Config-File: $key"
                $global:LASTEXITCODE = 1
                return
            }
        }

    }


    $remote=$false
    $LocalTargetPath = "$LocalTargetPath\$ComputerName"

    $logdir="$env:SystemDrive\$TempFolder"
    $RemoteLogDir="\\$ComputerName\$ShareDrive\$TempFolder"
    $logfile="$logdir\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_TempDataCleanup.log"

    if($IncludeAllPackages){
        $confirmation=Read-Host "Are you sure you want to include ALL Packages in the cleanup?`r`nThis will render IncludeMSTeamsCache irrelevant. Do you want to continue?`r`n(enter [yes] to continue with this option)"
        if($confirmation -ne "yes"){
            $IncludeAllPackages=$false
            Write-Host "Cleanup will not use IncludeAllPackages"
        }
        else{
            $IncludeMSTeamsCache=$false
            Write-Host "Cleanup will use IncludeAllPackages"
        }
    }

    if ($ComputerName -ne "" -and $ComputerName -ne $env:COMPUTERNAME -and $ComputerName -ne "localhost"){
        $remote=$true
    }

    if ($remote){
        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)){
            Write-Warning "Computer $ComputerName is not reachable"
            return
        }
    }

    if ($IncludeAllPackages){$userTempFolders=$userTempFolders+$allPackagesCacheFolder}else{$userTempFolders=$userTempFolders+$commonUserPackages}
    if ($IncludeBrowserData){$userTempFolders=$userTempFolders+$BrowserData}



    if ($remote) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:New-Folder} -ArgumentList $logdir
    } else {
        New-Folder -FolderPath $logdir
    }

    if ($remote) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:Start-UserCleanup} -ArgumentList $logfile, $userTempFolders, $userReportingDirs, $explorerCacheDir, $localIconCacheDB, $msTeamsCacheFolder, $teamsClassicPath, $IncludeSystemLogs, $IncludeIconCache, $IncludeMSTeamsCache
    } else {
        Start-UserCleanup -logfile $logfile -userTempFolders $userTempFolders -userReportingDirs $userReportingDirs -explorerCacheDir $explorerCacheDir -localIconCacheDB $localIconCacheDB -msTeamsCacheFolder $msTeamsCacheFolder -teamsClassicPath $teamsClassicPath -IncludeSystemLogs:$IncludeSystemLogs -IncludeIconCache:$IncludeIconCache -IncludeMSTeamsCache:$IncludeMSTeamsCache
    }


    if( $IncludeSystemData -or $IncludeSystemLogs -or $IncludeCCMCache) {

        if ($remote) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {function:Start-SystemCleanup} -ArgumentList $logfile, $systemTempFolders, $sysReportingDirs, $ccmCachePath, $IncludeSystemData, $IncludeSystemLogs, $IncludeCCMCache
        } else {
            Start-SystemCleanup -logfile $logfile -systemTempFolders $systemTempFolders -sysReportingDirs $sysReportingDirs -ccmCachePath $ccmCachePath -IncludeSystemData:$IncludeSystemData -IncludeSystemLogs:$IncludeSystemLogs -IncludeCCMCache:$IncludeCCMCache
        }
    }

    if ($remote) {
        New-Folder -FolderPath $localTargetPath
        Copy-Item -Path "$RemoteLogDir\*" -Destination $localTargetPath -Recurse -Force
        if ($?) {

            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                Remove-Item -Path "$logdir\*" -Recurse -Force
            } -Verbose:$VerboseOption

        } else {
            Write-Error "An error occurred while copying the log files from $ComputerName."
        }
    }

}

Export-ModuleMember -Function Invoke-TempDataCleanup

function copy-LogsFiles{
    param(
        [string]$ComputerName,
        [string]$localTempPath
    )

    if (-not (Test-Path -Path $localTempPath)) {
        New-Item -Path $localTempPath -ItemType Directory -Force
    }
    Copy-Item -Path "\\$ComputerName\C$\_temp\*" -Destination $localTempPath -Recurse -Force

    # Clear remote _temp folder if copy was successful
    if ($?) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Remove-Item -Path "C:\_temp\*" -Recurse -Force
        } -Verbose:$VerboseOption
    }

    Start-Sleep -Seconds 2
}


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

    $currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
    $remoteTempPath = "$env:HOMEDRIVE\_temp"
    $cleanupLog=$remoteTempPath+"\cleanupProfileLog_$currentDateTime.log"
    $localTempPath = "C:\remote-Files\$ComputerName"
    $profilePath = "$env:USERPROFILE\$ProfileName"
    $regProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
    $regUserPath = "HKU:\"
    $ExitCode = 0,0,0,0,0


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

    if ($ForceLogout){
        if ($user -eq $UserName) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $message = "User $using:user (UID: $using:id) is still logged in. Logging off user $using:id."
                Write-Verbose $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO: $message`r`n"
                logoff $using:id
            } -Verbose:$VerboseOption -ErrorAction Stop
        }

    } else {
        if ($user -eq $UserName) {
            Write-Error "User $UserName is still logged in on $ComputerName. Please log out the user before cleaning the profile."
            $ExitCode[0]=4
            $exitCode=$exitCode | Sort-Object {$_} -Descending
            $exitCode = $exitCode -join ""
            $global:LASTEXITCODE = $ExitCode
            break
        }
    }

    #TODO: get list of installed printers


    #TODO: get list of mapped network drives


    #get registy profile list id
    $profileListId = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $profileList = Get-ChildItem $using:regProfileListPath | Get-ItemProperty | Where-Object { $_.ProfileImagePath -eq "C:\Users\$using:UserName" }
        return $profileList.PSChildName
    } -Verbose:$VerboseOption -ErrorAction Stop

    if( $null -ne $profileListId){
        #Backup ProfileList Key
        $success=Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $message = "Backing up ProfileList Key for User $using:UserName."
            Write-Verbose $message
            Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO: $message`r`n"
            try{
                $profileListKey = Get-Item -Path $using:regProfileListPath\$using:profileListId
                $outputFilePath = "$using:remoteTempPath\ProfileListBackup_$using:UserName"+"_$using:currentDateTime.reg"
                Start-Process -FilePath "reg.exe" -ArgumentList "export `"$profileListKey`" `"$outputFilePath`" /y" -NoNewWindow -Wait
                $message = "Exporting User Key for User $using:UserName from ProfileList Successfully.`r`n`tKey: ´$($profileListKey| Select-Object -ExpandProperty PSPath | ForEach-Object { $_ -replace 'Microsoft.PowerShell.Core\\Registry::', '' })´"
                Write-Verbose $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO:`r`n`t$message`r`n"
                Remove-Item -Path $profileListKey -Force
                $message = "`tKey deleted: ´$($profileListKey| Select-Object -ExpandProperty PSPath | ForEach-Object { $_ -replace 'Microsoft.PowerShell.Core\\Registry::', '' })´`r`n"
                Write-Verbose $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO:`r`n`t$message`r`n"
                return $true
            } catch {
                $message = "Error backing up ProfileList Key for User $using:UserName.`r`nError: `r`n$_"
                Write-Error $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - ERROR: $message`r`n"
                return $false
            }
        } -Verbose:$VerboseOption -ErrorAction Stop
    } else {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $message = "User $using:UserName does not have a profile listed in Registry/ProfileList."
            Write-Error $message
            Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - ERROR: $message`r`n"
        } -Verbose:$VerboseOption -ErrorAction Stop
    }

    if(-not $success){
        copy-LogsFiles -ComputerName $ComputerName -localTempPath $localTempPath
        Write-Host "`r`n Early Exit During UserProfile-Cleanup on $ComputerName.`r`nLog-Files can be found on this Machine under '$localTempPath+\cleanupProfileLog_$currentDateTime.log'.`r`n`r`n"
        #exit
        $ExitCode[3]=1
        $exitCode=$exitCode | Sort-Object {$_} -Descending
        $exitCode = $exitCode -join ""
        $global:LASTEXITCODE = $ExitCode
        break
    } else {
        #export profileListId Key from HKEY_USERS\
        $success=Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $message = "Exporting ProfileList Key for User $using:UserName from HKEY_USERS."
            Write-Verbose $message
            Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO: $message"

            try{
                $regUserPathKey = Get-Item -Path $using:regUserPath\$using:profileListId
                $regUserPathKey2=Get-Item -Path ("$using:regUserPath\$using:profileListId" +"_Classes")
                $outputFilePath = "$using:remoteTempPath\HKey_UsersBackup_$using:UserName"+"_$using:currentDateTime.reg"
                $outputFilePath2 = "$using:remoteTempPath\HKey_Users_Classes_Backup_$using:UserName"+"_$using:currentDateTime.reg"

                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO:`r`n`tExporting ´$($regUserPathKey| Select-Object -ExpandProperty PSPath | ForEach-Object { $_ -replace 'Microsoft.PowerShell.Core\\Registry::', '' })´`r`n`tto $outputFilePath"
                Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regUserPathKey`" `"$outputFilePath`" /y" -NoNewWindow -Wait
                $message = "Exporting User Key for User $using:UserName from ProfileList Successfully.`r`n`tKey: ´$($regUserPathKey| Select-Object -ExpandProperty PSPath | ForEach-Object { $_ -replace 'Microsoft.PowerShell.Core\\Registry::', '' })´"
                Write-Verbose $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO:`r`n`t$message`r`n"

                Remove-Item -Path $regUserPathKey -Force
                $message = "`tKey deleted: $($profileListKey| Select-Object -ExpandProperty PSPath | ForEach-Object { $_ -replace 'Microsoft.PowerShell.Core\\Registry::', '' })`r`n"
                Write-Verbose $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO:`r`n`t$message`r`n"


                Write-Verbose $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO:`r`n`tExporting ´$($regUserPathKey2| Select-Object -ExpandProperty PSPath | ForEach-Object { $_ -replace 'Microsoft.PowerShell.Core\\Registry::', '' })´`r`n`tto $outputFilePath2"
                Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regUserPathKey2`" `"$outputFilePath2`" /y" -NoNewWindow -Wait
                $message = "Exporting User Key for User $using:UserName from ProfileList Successfully.`r`n`tKey: ´$($profileListKey| Select-Object -ExpandProperty PSPath | ForEach-Object { $_ -replace 'Microsoft.PowerShell.Core\\Registry::', '' })´"
                Write-Verbose $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO:`r`n`t$message`r`n"
                Remove-Item -Path $regUserPathKey2 -Force
                $message = "`tKey deleted: $($regUserPathKey2| Select-Object -ExpandProperty PSPath | ForEach-Object { $_ -replace 'Microsoft.PowerShell.Core\\Registry::', '' })"
                Write-Verbose $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO:`r`n`t$message`r`n"
                return $true
            } catch {
                $message = "Error exporting User Key for User $using:UserName from HKEY_USERS.`r`nError: `r`n$_"
                Write-Error $message
                Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - ERROR: $message`r`n"
                return $false
            }
        } -Verbose:$VerboseOption -ErrorAction Stop
    }

    if(-not $success){
        copy-LogsFiles -ComputerName $ComputerName -localTempPath $localTempPath
        Write-Host "`r`n Early Exit During UserProfile-Cleanup on $ComputerName.`r`nLog-Files can be found on this Machine under '$localTempPath+\cleanupProfileLog_$currentDateTime.log'.`r`n`r`n"
        #exit
        $ExitCode[3]=2
        $exitCode=$exitCode | Sort-Object {$_} -Descending
        $exitCode = $exitCode -join ""
        $global:LASTEXITCODE = $ExitCode
        break
    }

    #Rename User-Profile Folder
    $success=Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $message = "Renaming User-Profile Folder for User $using:UserName."
        Write-Verbose $message
        Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO: $message`r`n"
        try{
            $profilePath = "$env:USERPROFILE\$using:UserName"
            #TODO: check if folder exists
            $newProfilePath = "$env:USERPROFILE\$using:UserName"+".bak"
            Rename-Item -Path $profilePath -NewName $newProfilePath -Force
            $message = "Renaming User-Profile Folder for User $using:UserName.`r`n`tSuccessful$_"
            Write-Verbose $message
            Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - INFO:`r`n`t$message`r`n"
            return $true
        } catch {
            $message = "Error renaming User-Profile Folder for User $using:UserName.`r`nError: `r`n$_"
            Write-Error $message
            Add-Content -Path $using:cleanupLog -Value "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss"))] - ERROR: $message`r`n"
            return $false
        }
    } -Verbose:$VerboseOption -ErrorAction Stop

    if(-not $success){
        copy-LogsFiles -ComputerName $ComputerName -localTempPath $localTempPath
        Write-Host "`r`n Early Exit During UserProfile-Cleanup on $ComputerName.`r`nLog-Files can be found on this Machine under '$localTempPath+\cleanupProfileLog_$currentDateTime.log'.`r`n`r`n"
        #exit
        $ExitCode[3]=3
    } else {
        copy-LogsFiles -ComputerName $ComputerName -localTempPath $localTempPath
        Write-Host "`r`n UserProfile-Cleanup on $ComputerName completed successfully.`r`nLog-Files can be found on this Machine under '$localTempPath+\cleanupProfileLog_$currentDateTime.log'.`r`n`r`n"
    }
    $exitCode=$exitCode | Sort-Object {$_} -Descending
    $exitCode = $exitCode -join ""
    $global:LASTEXITCODE = $ExitCode
    break

}

Export-ModuleMember -Function Invoke-RemoteProfileCleanup
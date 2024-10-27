$UserName = Read-Host "Enter the username of the profile to be removed"
if($UserName -eq "") {
    Write-Error "Username cannot be empty"
    exit
}
$currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
$TempPath = "$env:HOMEDRIVE\_temp"
$cleanupLog=$TempPath+"\cleanupProfileLog_$((Get-Date).ToString("yyyy-MM-dd_HH-mm")).log"
$profilePath = "$env:HOMEDRIVE\Users\$ProfileName"
$profilePathOld = "$env:HOMEDRIVE\Users\$ProfileName-$currentDateTime.old"
$regProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS > $null
$regUserPath = "HKU:\"

# Function to log messages
function Log-Message {
    param(
        [string]$message
    )
    $message = "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm"))] - $message"
    Write-Host $message
    $message | Out-File -FilePath $cleanupLog -Append
}

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

        # output to pipe
        $_

    } |
    #Convert to objects
    ConvertFrom-Csv
}

$sessions = Get-TSSessions | Where-Object { $_.USERNAME -eq $USERNAME } | Select-Object USERNAME,ID

$user,$id = $sessions | ForEach-Object {$_.username,$_.ID}

if (-not (Test-Path -Path $TempPath)) {
    New-Item -Path $TempPath -ItemType Directory -Force
}


if ($user -eq $UserName) {
    Write-Error "`r`nUser $UserName is still logged in on $env:computername . Please log out the user before cleaning the profile."
}
else{
    $profileList = Get-ChildItem $regProfileListPath | Get-ItemProperty | Where-Object { $_.ProfileImagePath -eq "C:\Users\$UserName" }
    $profileListId = $profileList.PSChildName

    if( $null -ne $profileListId){
        try{
            Log-Message "Profile with Username $UserName found in registry"
            Log-Message "Backing up Registry Profile List to $profilePathOld"
            $profileListKey = Get-Item -Path $regProfileListPath\$profileListId
            $outputFilePath = "$TempPath\ProfileListBackup_$UserName"+"_$currentDateTime.reg"
            Log-Message "Backing up Registry Profile List of $UserName to $outputFilePath"
            Start-Process -FilePath "reg.exe" -ArgumentList "export `"$profileListKey`" `"$outputFilePath`" /y" -NoNewWindow -Wait
            Log-Message "Deleting $profileListKey"
            Remove-Item -Path $profileListKey -Force
            $regUserPathKey2 = Get-Item -Path $regUserPath\$profileListId
            $regUserPathKey3=Get-Item -Path ("$regUserPath\$profileListId" +"_Classes")
            $outputFilePath2 = "$remoteTempPath\HKey_UsersBackup_$UserName"+"_$currentDateTime.reg"
            $outputFilePath3 = "$remoteTempPath\HKey_Users_Classes_Backup_$UserName"+"_$currentDateTime.reg"
            Log-Message "Backing up User Profile Registry to $outputFilePath2"
            Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regUserPathKey2`" `"$outputFilePath2`" /y" -NoNewWindow -Wait
            Log-Message "Deleting $regUserPathKey2"
            Remove-Item -Path $regUserPathKey2 -Force
            Log-Message "Backing up User Profile Registry Classes to $outputFilePath3"
            Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regUserPathKey3`" `"$outputFilePath3`" /y" -NoNewWindow -Wait
            Log-Message "Deleting $regUserPathKey3"
            Remove-Item -Path $regUserPathKey3 -Force
            Log-Message "Registry Profile List and User Profile Backup completed"
            Log-Message "Renaming Profile Folder $profilePath"
            Rename-Item -Force -Path $profilePath -NewName $profilePathOld
            Log-Message "Profile Folder renamed to $profilePathOld"
        } catch {
            Log-Message "Error occurred while deleting profile"
            Log-Message $_.Exception.Message
        }
    } else {
        Log-Message "Profile with Username $UserName not found in registry"
    }

    Log-Message "Profile cleanup completed"
}
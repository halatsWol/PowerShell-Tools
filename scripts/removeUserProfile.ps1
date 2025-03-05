$UserName = Read-Host "Enter the username of the profile to be removed"
if($UserName -eq "") {
    Write-Error "Username cannot be empty"
    exit
}
$currentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
$TempPath = "$env:HOMEDRIVE\_ProfileCleanup"
$cleanupLog=$TempPath+"\cleanupProfileLog_$((Get-Date).ToString("yyyy-MM-dd_HH-mm")).log"
$profilePath = "$env:HOMEDRIVE\Users\$UserName"
$profilePathOld = "$env:HOMEDRIVE\Users\$UserName-$currentDateTime.old"
$regProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS > $null
$regUserPath = "HKU:\"
$netDrivesCMDfile="$TempPath\NetDrives_$UserName.cmd"
$printerListFile="$TempPath\PrinterList_$UserName.txt"

# Function to log messages
function Write-LogMessage {
    param(
        [string]$message
    )
    $message = "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss.fff"))] - $message"
    Write-Host $message
    $message | Out-File -FilePath $cleanupLog -Append
}

function Get-TSSessions {
    query user|
    ForEach-Object {
        $UserSessions = $_.trim()
        # insert , at specific places for ConvertFrom-CSV command
        $UserSessions = $UserSessions.insert(22,",").insert(42,",").insert(47,",").insert(56,",").insert(68,",")
        $UserSessions = $UserSessions -replace "\s+",""
        $UserSessions = $UserSessions -replace ">" , ""
        $UserSessions
    } |
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
            Write-LogMessage "Profile with Username $UserName found in registry"
            Write-LogMessage "Backing up Registry Profile List to $profilePathOld"
            $profileListKey = Get-Item -Path $regProfileListPath\$profileListId
            $outputFilePath = "$TempPath\ProfileListBackup_$UserName"+"_$currentDateTime.reg"
            $regUserPathKey2 = Get-Item -Path $regUserPath\$profileListId
            $regUserPathKey3=Get-Item -Path ("$regUserPath\$profileListId" +"_Classes")
            Write-LogMessage "Backing up Registry Profile List of $UserName to $outputFilePath"
            Start-Process -FilePath "reg.exe" -ArgumentList "export `"$profileListKey`" `"$outputFilePath`" /y" -NoNewWindow -Wait

            # get network drives
            $drives = Get-ChildItem -Path "$regUserPath\$profileListId\Network"
            Write-LogMessage "Exporting Network Drives to $netDrivesCMDfile"
            foreach($drive in $drives ){
                $letter=$drive.PSChildName
                $remotePath=$drive.GetValue("RemotePath")
                $netuselet="net use $($letter): '$remotePath' /persistent:yes"
                Add-Content -Path $netDrivesCMDfile -Value $netuselet
                Write-LogMessage "`t> $letter`t'$remotePath'"
            }

            $printers = Get-Item -Path "$regUserPath\$profileListId\Printers\ConvertUserDevModesCount\" | Select-Object Property
            #get items of ConvertUserDevModesCount
            $defaultPrinters=@("OneNote (Desktop)","Microsoft XPS Document Writer","Microsoft Print to PDF","Fax","Adobe PDF","WinDisc","TIFF Printer","ImagePrinter Pro")
            Write-LogMessage "Exporting Printers to $printerListFile"
            foreach ($printer in $printers.Property) {
                # Check if the printer is not in the default list and does not contain the computer name
                if (-not ($defaultPrinters -contains $printer) -and ($printer -notlike "*$env:ComputerName*")) {
                    Write-LogMessage "`t> $printer"
                    Add-Content -Path $printerListFile -Value $printer
                }
            }


            if(Test-Path $regUserPath\$profileListId){
                Write-LogMessage "Deleting $regProfileListPath\$profileListId"
                Remove-Item -Path $regProfileListPath\$profileListId -Force -Recurse
            } else {
                Write-LogMessage "Item $regProfileListPath\$profileListId does not exist"
            }
            $outputFilePath2 = "$TempPath\HKey_UsersBackup_$UserName"+"_$currentDateTime.reg"
            $outputFilePath3 = "$TempPath\HKey_Users_Classes_Backup_$UserName"+"_$currentDateTime.reg"
            Write-LogMessage "Backing up User Profile Registry to $outputFilePath2"
            Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regUserPathKey2`" `"$outputFilePath2`" /y" -NoNewWindow -Wait

            if(Test-Path $regUserPath\$profileListId){
                Write-LogMessage "Deleting $regUserPath\$profileListId"
                Remove-Item -Path $regUserPath\$profileListId -Force -Recurse
            } else {
                Write-LogMessage "Item $regUserPath\$profileListId does not exist"
            }
            Write-LogMessage "Backing up User Profile Registry Classes to $outputFilePath3"
            Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regUserPathKey3`" `"$outputFilePath3`" /y" -NoNewWindow -Wait
            $classesPath = "$regUserPath\$profileListId" +"_Classes"
            if(Test-Path $classesPath){
                Write-LogMessage "Deleting $classesPath"
                Remove-Item -Path $classesPath -Force -Recurse
            } else {
                Write-LogMessage "Item $classesPath does not exist"
            }
            Write-LogMessage "Registry Profile List and User Profile Backup completed"
            Write-LogMessage "Renaming Profile Folder $profilePath"
            try{
                Rename-Item -Force -Path $profilePath -NewName $profilePathOld
                Write-LogMessage "Profile Folder renamed to $profilePathOld"
            } catch {
                $errormsg = "Error occurred while deleting profile`r`n$_.Exception.Message"
                Write-LogMessage $errormsg
            }

        } catch {
            Write-LogMessage "Error occurred during profile cleanup"
            Write-LogMessage $_.Exception.Message
            return
        }
    } else {
        Write-LogMessage "Profile with Username $UserName not found in registry"
    }

    Write-LogMessage "Profile cleanup completed"
}

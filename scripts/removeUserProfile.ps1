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
function Log-Message {
    param(
        [string]$message
    )
    $message = "[$((Get-Date).ToString("yyyy-MM-dd_HH-mm-ss.fff"))] - $message"
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
            $regUserPathKey2 = Get-Item -Path $regUserPath\$profileListId
            $regUserPathKey3=Get-Item -Path ("$regUserPath\$profileListId" +"_Classes")
            Log-Message "Backing up Registry Profile List of $UserName to $outputFilePath"
            Start-Process -FilePath "reg.exe" -ArgumentList "export `"$profileListKey`" `"$outputFilePath`" /y" -NoNewWindow -Wait

            # get network drives
            $drives = Get-ChildItem -Path "$regUserPath\$profileListId\Network"
            Log-Message "Exporting Network Drives to $netDrivesCMDfile"
            foreach($drive in $drives ){
                $letter=$drive.PSChildName
                $remotePath=$drive.GetValue("RemotePath")
                $netuselet="net use $($letter): '$remotePath' /persistent:yes"
                Add-Content -Path $netDrivesCMDfile -Value $netuselet
                Log-Message "`t> $letter`t'$remotePath'"
            }

            $printers = Get-Item -Path "$regUserPath\$profileListId\Printers\ConvertUserDevModesCount\" | Select-Object Property
            #get items of ConvertUserDevModesCount
            $defaultPrinters=@("OneNote (Desktop)","Microsoft XPS Document Writer","Microsoft Print to PDF","Fax","Adobe PDF","WinDisc","TIFF Printer","ImagePrinter Pro")
            Log-Message "Exporting Printers to $printerListFile"
            foreach ($printer in $printers.Property) {
                # Check if the printer is not in the default list and does not contain the computer name
                if (-not ($defaultPrinters -contains $printer) -and ($printer -notlike "*$env:ComputerName*")) {
                    Log-Message "`t> $printer"
                    Add-Content -Path $printerListFile -Value $printer
                }
            }
            
            
            if(Test-Path $regUserPath\$profileListId){
                Log-Message "Deleting $regProfileListPath\$profileListId"
                Remove-Item -Path $regProfileListPath\$profileListId -Force -Recurse
            } else {
                Log-Message "Item $regProfileListPath\$profileListId does not exist"
            }
            $outputFilePath2 = "$TempPath\HKey_UsersBackup_$UserName"+"_$currentDateTime.reg"
            $outputFilePath3 = "$TempPath\HKey_Users_Classes_Backup_$UserName"+"_$currentDateTime.reg"
            Log-Message "Backing up User Profile Registry to $outputFilePath2"
            Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regUserPathKey2`" `"$outputFilePath2`" /y" -NoNewWindow -Wait
            
            if(Test-Path $regUserPath\$profileListId){
                Log-Message "Deleting $regUserPath\$profileListId"
                Remove-Item -Path $regUserPath\$profileListId -Force -Recurse
            } else {
                Log-Message "Item $regUserPath\$profileListId does not exist"
            }
            Log-Message "Backing up User Profile Registry Classes to $outputFilePath3"
            Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regUserPathKey3`" `"$outputFilePath3`" /y" -NoNewWindow -Wait
            $classesPath = "$regUserPath\$profileListId" +"_Classes"
            if(Test-Path $classesPath){
                Log-Message "Deleting $classesPath"
                Remove-Item -Path $classesPath -Force -Recurse
            } else {
                Log-Message "Item $classesPath does not exist"
            }  
            Log-Message "Registry Profile List and User Profile Backup completed"
            Log-Message "Renaming Profile Folder $profilePath"
            try{
                Rename-Item -Force -Path $profilePath -NewName $profilePathOld
                Log-Message "Profile Folder renamed to $profilePathOld"
            } catch {
                $errormsg = "Error occurred while deleting profile`r`n$_.Exception.Message"
                Log-Message $errormsg
            }

        } catch {
            Log-Message "Error occurred during profile cleanup"
            Log-Message $_.Exception.Message
            return
        }
    } else {
        Log-Message "Profile with Username $UserName not found in registry"
    }

    Log-Message "Profile cleanup completed"
}

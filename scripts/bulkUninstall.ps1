

$vendor = Read-Host "Enter the Vendor-Name"
$logpath="C:\_temp\"
New-Item -ItemType Directory -Force -Path $logpath > $null
$logfile=$logpath+"uninstall_"+$vendor+"_products_"+(Get-Date -Format "yyyy-MM-dd_HH-mm")+".log"

function Write-Log {
    param(
        [string]$message,
        [string]$logFile,
        [switch]$logOnly
    )
    if(-not $logOnly) {Write-Host $message}
    $mes=""
    if ($message -ne "`r`n") {
        $mes = "[$(Get-Date -Format "yyyy-MM-dd_HH-mm-ss.fff")]`t- $message"
    } else {
        $mes = $message
    }

    Add-Content -Path $logFile -Value $mes
}

Write-Log "User-Input: '$vendor'" $logfile

if ("*Microsoft*".Contains($vendor)) {
    Write-Host "`r`n`r`nYou are about to " -NoNewline
    Write-Host "uninstall all Microsoft products" -ForegroundColor Red -NoNewline
    Write-Host "!"
    $confirm = Read-Host "Do you want to continue? (Y/N)"
    if ($confirm -notlike "Y") {
        Write-Log "`r`nOperation cancelled." §logfile
        return
    } else {
        Write-Log "`r`nMicrosoft Warning Confirmed" $logfile -logOnly
    }
}

$packages = Get-WmiObject -Class Win32_Product | Where-Object { $_.Vendor -like "*$vendor*" }

if ($packages) {
    Write-Log "`r`nThe following packages will be uninstalled:`r`n`r`n $($packages | ForEach-Object { $_.Name.Trim() + "`r`n"})" $logfile
    $confirm = Read-Host "Do you want to continue? (Y/N)"

    if ($confirm -notlike "Y") {
        Write-Log "`r`nOperation cancelled." $logfile
        return
    }

    $fails=New-Object System.Collections.ArrayList

    foreach ($pkg in $packages) {
        Write-Host "Uninstalling " -NoNewline
        Write-Host "'$($pkg.Name)'..." -ForegroundColor Green
        Write-Log "Uninstalling '$($pkg.Name)'..." $logfile -logOnly
        try {
            $output = $pkg.Uninstall()
            Write-Log -message $($output | Format-List | Out-String) -logFile $logfile -logOnly
            $returnValue = $output | ForEach-Object { $_.ReturnValue }
            if($returnValue -ne 0) {
                Write-Host "Error uninstalling " -NoNewline -ForegroundColor Red
                Write-Host "'$($pkg.Name)':`tExit[$returnValue]"
                Write-Log "Error uninstalling $($pkg.Name):`tExit[$returnValue])" $logfile -logOnly
                $fails.add("[$returnValue]`t- $($pkg.Name)") > $null
            } else {
                Write-Host "Uninstall '$($pkg.Name)' "-NoNewline
                Write-Host "successful." -ForegroundColor Green
                Write-Log "Uninstall '$($pkg.Name)' successful." $logfile -logOnly
            }
        } catch {
            Write-Log "`r`nError uninstalling $($pkg.Name):`r`n$($_.Exception.Message)" $logfile

        }
    }
    $suc=""
    if($fails -ne $null) {
        $suc = "partially"
    } else {
        $suc="fully"
    }
    Write-Log "Packages from vendor '$vendor' have been $suc uninstalled." $logfile
    if($fails -ne $null) {
        Write-Log "`r`nFollowing Packages were not removed and may need a restart of the Computer or simply cannot be uninstalled this way:`r`n$fails" $logfile
    }

    write-host "`r`n`r`nLog written to: $logfile"
} else {
    Write-Log "`r`n" $logfile
    Write-Log "No packages found from vendor '$vendor'."  $logfile
}

# Description: Script to resolve the IP of a remote host via MAC Address and update the settings.json of 'PowerToys Mouse Without Borders'
# All Hosts must be in the same Network, and the Remote Host must be reachable via ARP (e.g. in the same Subnet)
# The Script will restart PowerToys after updating the settings.json
# Use when DHCP assigned new addresses to the Hosts, or when another Network is used

# Prerequisites: PowerToys Mouse Without Borders must be installed and configured
# PowerToys Mouse Without Borders Documentation: https://learn.microsoft.com/en-us/windows/powertoys/mouse-without-borders

# Author: Wolfram Halatschek
# Date: 2021-12-10


$remoteHost="" # e.g. "MyRemotePC"
$remoteMAC="" # e.g. "E2-56-9C-42-E7-A4"
$remoteIP="" # will be resolved from MAC

$mwbSettings="$env:localappdata\Microsoft\PowerToys\MouseWithoutBorders\settings.json"
$shortcutName = "PowerToys*"

function Get-PowerToysExe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$shortcutName
    )

    $startMenuPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
    )

    # Function to resolve the target of a shortcut
    function Get-ShortcutTarget {
        param([string]$shortcutPath)
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        return $shortcut.TargetPath
    }

    foreach ($startMenuPath in $startMenuPaths) {
        $shortcuts = Get-ChildItem -Path $startMenuPath -Recurse -Filter "$shortcutName.lnk" -ErrorAction SilentlyContinue
        if ($shortcuts) {
            return Get-ShortcutTarget -shortcutPath $shortcuts[0].FullName
        }
    }

    # Return $null if no shortcut is found
    return $null
}


try {
    $remoteIP=Get-NetNeighbor -LinkLayerAddress $remoteMAC | Where-Object {$_.IPAddress -match '\d+\.\d+\.\d+\.\d+'} | Select-Object -ExpandProperty IPAddress

    if ($remoteHost -eq "") {
        Write-Error "No Remote Hostname provided. Please set the variable remoteHost in this Script-File."
        Read-Host "Press [Enter] to Continue ..."
        exit 1
    }
    if ($remoteMAC -eq "") {
        Write-Error "No Remote MAC provided. Please set the variable remoteMAC in this Script-File."
        Read-Host "Press [Enter] to Continue ..."
        exit 1
    }

    if ( -Not (Test-Path $mwbSettings) ) {
        Write-Error "no Settings-File found. Re-Enable PowerToys Mouse Without Borders and try again"
        Read-Host "Press [Enter] to Continue ..."
        exit 2
    }

    if (-not $remoteIP) {
        Write-Error "Failed to resolve IP address from MAC address.`r`nMAC-Address may be incorrect, Remote Device may not be in the Network, or the Resolver-Cache may have been recently cleared"
        Read-Host "Press [Enter] to Continue ..."
        exit 3
    }

    try {
        $json=Get-Content $mwbSettings | ConvertFrom-Json
        $json.properties.Name2IP.value = "$remoteHost $remoteIP"
        $json | ConvertTo-Json -Depth 10 | Set-Content -Path $mwbSettings -Encoding UTF8

        # Restart PowerToys
        Get-Process -Name PowerToys -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
        $powerToysPath = Get-PowerToysExe -shortcutName $shortcutName
        try{
            Start-Process -FilePath $powerToysPath
            Write-Host "PowerToys restarted successfully from Path: '$powerToysPath'" -ForegroundColor Green
        } catch {
            Write-Error "Failed to restart PowerToys from Path: '$powerToysPath'"
        }
        Write-Host "Updated Name2IP in settings.json successfully. Have Fun!" -ForegroundColor Green
        Read-Host "Press [Enter] to Continue ..."
        exit 0
    } catch {
        Write-Error "Failed to Parse and Modify Settings"
        Read-Host "Press [Enter] to Continue ..."
        exit 4
    }
} catch {
    Write-Error "$_"
    Read-Host "Press [Enter] to Continue ..."
    exit 5
}

$remoteHost="" # e.g. "MyRemotePC"
$remoteMAC="" # e.g. "E2-56-9C-42-E7-A4"
$remoteIP="" # will be resolved from MAC

$mwbSettings="$env:localappdata\Microsoft\PowerToys\MouseWithoutBorders\settings.json"
try {
    $remoteIP=Get-NetNeighbor -LinkLayerAddress $remoteMAC | Where-Object State -EQ "Reachable" | Select-Object -ExpandProperty IPAddress

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
        $powerToysPath = "$env:ProgramFiles\PowerToys\PowerToys.exe"
        Start-Process -FilePath $powerToysPath
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
$remoteHost=""
$remoteMAC=""
$remoteIP="" # will be resolved from MAC

$mwbSettings="$env:localappdata\Microsoft\PowerToys\MouseWithoutBorders\settings.json"

$remoteIP=Get-NetNeighbor -LinkLayerAddress $remoteMAC | Select-Object IPAddress

if (Test-Path -ne $mwbSettings) {
    Write-Error "no Settings-File found. Re-Enable PowerToys Mouse Without Borders and try again"
    Read-Host "Press [Enter] to Continue ..."
    exit 1
}

if (-not $remoteIP) {
    Write-Host "Failed to resolve IP address from MAC address." -ForegroundColor Red
    Read-Host "Press [Enter] to Continue ..."
    exit 2
}

try {
    $json=Get-Content $mwbSettings | ConvertFrom-Json
    $json.properties.Name2IP.value = "$remoteHost $remoteIP"
    $json | ConvertTo-Json -Depth 10 | Set-Content -Path $mwbSettings -Encoding UTF8

    Write-Host "Updated Name2IP in settings.json successfully. Have Fun!" -ForegroundColor Green
    Read-Host "Press [Enter] to Continue ..."
    exit 0
} catch {
    Write-Error "Failed to Parse and Modify Settings"
    Read-Host "Press [Enter] to Continue ..."
    exit 3
}
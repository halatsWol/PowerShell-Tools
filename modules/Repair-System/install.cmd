@echo off
setlocal

set "sourcePath=%~dp0"
set "destinationPath=%programfiles%\WindowsPowerShell\Modules\Repair-System"
set "destinationPathHelp=%destinationPath%\en-US"

if not exist "%destinationPath%" (
    mkdir "%destinationPath%"
)
if not exist "%destinationPathHelp%" (
    mkdir "%destinationPathHelp%"
)
copy "%sourcePath%RepairSystem.psm1" "%destinationPath%"
copy "%sourcePath%RepairSystem.psd1" "%destinationPath%"
copy "%sourcePath%en-US\about_RepairSystem.help.txt" "%destinationPathHelp%"

REM Check if the copy was successful
if %errorlevel% equ 0 (
    echo Files copied successfully.
    REM Import the module in PowerShell
    powershell.exe -Command "Import-Module RepairSystem"
    echo Module installed. Please restart any PowerShell session.
) else (
    echo Error occurred while copying files.
)

endlocal
pause
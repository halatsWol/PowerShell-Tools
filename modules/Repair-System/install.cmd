@echo off
setlocal

set "sourcePath=%~dp0"
set "destinationPath=%programfiles%\WindowsPowerShell\Modules\Repair-System"

if not exist "%destinationPath%" (
    mkdir "%destinationPath%"
)
copy "%sourcePath%Repair-System.psm1" "%destinationPath%"
copy "%sourcePath%Repair-System.psd1" "%destinationPath%"

REM Check if the copy was successful
if %errorlevel% equ 0 (
    echo Files copied successfully.
    REM Import the module in PowerShell
    powershell.exe -Command "Import-Module Repair-System"
    echo Module imported. Please restart any PowerShell session.
) else (
    echo Error occurred while copying files.
)

endlocal
pause
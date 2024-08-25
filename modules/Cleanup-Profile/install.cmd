@echo off
setlocal

set "sourcePath=%~dp0"
set "destinationPath=%programfiles%\WindowsPowerShell\Modules\Cleanup-Profile"

if not exist "%destinationPath%" (
    mkdir "%destinationPath%"
)
copy "%sourcePath%Cleanup-Profile.psm1" "%destinationPath%"
copy "%sourcePath%Cleanup-Profile.psd1" "%destinationPath%"

REM Check if the copy was successful
if %errorlevel% equ 0 (
    echo Files copied successfully.
    REM Import the module in PowerShell
    powershell.exe -Command "Import-Module Cleanup-Profile"
    echo Module installed. Please restart any PowerShell session.
) else (
    echo Error occurred while copying files.
)

endlocal
pause
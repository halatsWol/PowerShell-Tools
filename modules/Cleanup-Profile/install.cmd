@echo off
setlocal

set "sourcePath=%~dp0"
set "destinationPath=%programfiles%\WindowsPowerShell\Modules\Cleanup-Profile"

if not exist "%destinationPath%" (
    mkdir "%destinationPath%"
)
if not exist "%destinationPath%\en-US" (
    mkdir "%destinationPath%\en-US"
)

copy "%sourcePath%Cleanup-Profile.psm1" "%destinationPath%"
copy "%sourcePath%Cleanup-Profile.psd1" "%destinationPath%"
copy "%sourcePath%about_Cleanup-Profile.help.txt" "%destinationPath%\en-US\"

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
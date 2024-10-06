@echo off
setlocal

set "sourcePath=%~dp0"
set "destinationPath=%programfiles%\WindowsPowerShell\Modules\TempDataCleanup"
set "destinationPathHelp=%destinationPath%\en-US"

if not exist "%destinationPath%" (
    mkdir "%destinationPath%"
)
if not exist "%destinationPathHelp%" (
    mkdir "%destinationPathHelp%"
)
copy "%sourcePath%TempDataCleanup.psm1" "%destinationPath%"
copy "%sourcePath%TempDataCleanup.psd1" "%destinationPath%"
copy "%sourcePath%en-US\about_TempDataCleanup.help.txt" "%destinationPathHelp%"

REM Check if the copy was successful
if %errorlevel% equ 0 (
    echo Files copied successfully.
    REM Import the module in PowerShell
    powershell.exe -Command "Import-Module TempDataCleanup"
    echo Module installed. Please restart any PowerShell session.
) else (
    echo Error occurred while copying files.
)

endlocal
pause
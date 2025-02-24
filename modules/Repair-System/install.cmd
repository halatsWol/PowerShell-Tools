@echo off
setlocal

set moduleName=RepairSystem
set sourcePath=%~dp0
set destinationPath=%programfiles%\WindowsPowerShell\Modules\%moduleName%
set destinationPathHelp=%destinationPath%\en-US

if not exist "%destinationPath%" (
    mkdir "%destinationPath%"
)
if not exist "%destinationPathHelp%" (
    mkdir "%destinationPathHelp%"
)
copy "%sourcePath%\%moduleName%.psm1" "%destinationPath%"
copy "%sourcePath%\%moduleName%.psd1" "%destinationPath%"
copy "%sourcePath%en-US\about_%moduleName%.help.txt" "%destinationPathHelp%"

REM Check if the copy was successful
if %errorlevel% equ 0 (
    echo Files copied successfully.
    REM Import the module in PowerShell
    powershell.exe -Command "Import-Module %moduleName%"
    echo Module installed. Please restart any PowerShell session.
) else (
    echo Error occurred while copying files.
)

endlocal
pause
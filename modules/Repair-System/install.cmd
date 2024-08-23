@echo off
setlocal

REM Define source and destination paths
set "sourcePath=%~dp0"
set "destinationPath=%programfiles%\WindowsPowerShell\Modules\Repair-System"

REM Create destination directory if it does not exist
if not exist "%destinationPath%" (
    mkdir "%destinationPath%"
)

REM Copy the files
copy "%sourcePath%Repair-System.psm1" "%destinationPath%"
copy "%sourcePath%Repair-System.psd1" "%destinationPath%"

REM Check if the copy was successful
if %errorlevel% equ 0 (
    echo Files copied successfully.
) else (
    echo Error occurred while copying files.
)

endlocal
pause
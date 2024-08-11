# Define the Repair-System module
Module Repair-System {
    Export-ModuleMember -Function Repair-System
    
    function Repair-System {
		<#
        .SYNOPSIS
        Repairs the system by running SFC and DISM commands on a remote computer.

        .DESCRIPTION
        This function performs a series of system repair commands on a remote computer. It first checks the availability of the remote machine by pinging it.
        Then, depending on the options specified, it executes `sfc /scannow` and various `DISM` commands to scan and repair the Windows image.

        The results are logged both on the remote machine and optionally shown on the local console. Logs and relevant system files are then transferred to the local machine.

        .PARAMETER ComputerName
        The hostname or IP address of the remote computer where the system repair will be performed.

        .PARAMETER SfcOnly
        When specified, only the `sfc /scannow` command is executed. The `DISM` commands are skipped.

        .PARAMETER Quiet
        Suppresses console output on the local machine. The output is logged to files on the remote machine instead.

        .EXAMPLE
        Repair-System -ComputerName SomePC

        Runs the `sfc /scannow` and `DISM` commands on the remote computer `SomePC`. Outputs are shown on the console and logged to files.

        .EXAMPLE
        Repair-System SomePC -SfcOnly

        Runs only the `sfc /scannow` command on the remote computer `SomePC`. Outputs are shown on the console and logged to files.

        .EXAMPLE
        Repair-System SomePC -Quiet

        Runs the `sfc /scannow` and `DISM` commands on the remote computer `SomePC`. Outputs are logged to files but not shown on the console.

        .NOTES
        Author: Wolfram Halatschek
		E-Mail: halatschek.wolfram@gmail.com
        Date: 2024-08-11
        #>
	
        param (
            [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
            [string]$ComputerName,

            [Parameter(Position=1)]
            [switch]$SfcOnly,

            [Parameter(Position=2)]
            [switch]$Quiet
        )

        # Ping the remote computer to check availability
        $pingResult = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet

        if (-not $pingResult) {
            Write-Host "Unable to reach $ComputerName. Please check the network connection."
            return
        }

        # Set up paths and file names for logging
        $remoteTempPath = "\\$ComputerName\C$\_temp"
        $localTempPath = "C:\remoteFiles\$ComputerName"
        $sfcLog = "$remoteTempPath\sfc-scannow_$ComputerName.log"
        $dismScanLog = "$remoteTempPath\dism-scan_$ComputerName.log"
        $dismRestoreLog = "$remoteTempPath\dism-restore_$ComputerName.log"

        if (-not (Test-Path -Path $remoteTempPath)) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                New-Item -Path "C:\_temp" -ItemType Directory -Force
            }
        }

        # Execute sfc /scannow
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if ($using:Quiet) {
                sfc /scannow > $using:sfcLog 2>&1
            } else {
                sfc /scannow | Tee-Object -FilePath $using:sfcLog
            }
        }

        if (-not $SfcOnly) {
            # Execute dism /online /Cleanup-Image /Scanhealth
            $dismScanResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                if ($using:Quiet) {
                    dism /online /Cleanup-Image /Scanhealth > $using:dismScanLog 2>&1
                } else {
                    dism /online /Cleanup-Image /Scanhealth | Tee-Object -FilePath $using:dismScanLog
                }
                return $LASTEXITCODE
            }

            # Execute dism /online /Cleanup-Image /RestoreHealth only if scanhealth is not 0
            if ($dismScanResult -ne 0) {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    if ($using:Quiet) {
                        dism /online /Cleanup-Image /RestoreHealth > $using:dismRestoreLog 2>&1
                    } else {
                        dism /online /Cleanup-Image /RestoreHealth | Tee-Object -FilePath $using:dismRestoreLog
                    }
                }
            }
        }

        # Handle log outputs
        if (-not $Quiet) {
            Get-Content "\\$ComputerName\$sfcLog" -Tail 10
            if (-not $SfcOnly) {
                Get-Content "\\$ComputerName\$dismScanLog" -Tail 10
                if ($dismScanResult -ne 0) {
                    Get-Content "\\$ComputerName\$dismRestoreLog" -Tail 10
                }
            }
        }

        # Zip CBS.log and DISM.log
        $zipFile = "$remoteTempPath\logs_$ComputerName.zip"
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Add-Type -Assembly "System.IO.Compression.FileSystem"
            $zipFile = $using:zipFile
            $cbsLog = "$env:windir\Logs\CBS\CBS.log"
            $dismLog = "$env:windir\Logs\dism\dism.log"
            $tempPath = "$using:remoteTempPath"

            $zip = [System.IO.Compression.ZipFile]::CreateFromDirectory($tempPath, $zipFile)

            if (Test-Path $cbsLog) {
                [System.IO.Compression.ZipFile]::CreateEntryFromFile($zipFile, $cbsLog, "CBS.log")
            }

            if (-not $using:SfcOnly) {
                if (Test-Path $dismLog) {
                    [System.IO.Compression.ZipFile]::CreateEntryFromFile($zipFile, $dismLog, "dism.log")
                }
            }
        }

        # Copy log files to local machine
        if (-not (Test-Path -Path $localTempPath)) {
            New-Item -Path $localTempPath -ItemType Directory -Force
        }
        Copy-Item -Path "\\$ComputerName\C$\_temp\*" -Destination $localTempPath -Recurse -Force

        # Clear remote _temp folder if copy was successful
        if ($?) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                Remove-Item -Path "C:\_temp\*" -Recurse -Force
            }
        }
    }
}

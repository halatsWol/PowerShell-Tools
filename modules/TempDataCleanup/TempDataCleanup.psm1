function Invoke-TempDataCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$false)]
        [switch]$Full

    )

    $userTempFolders=@(
            "\AppData\Local\Temp",
            "\AppData\Local\Microsoft\Office\16.0\OfficeFileCache\0"
            )
    $extuserTempFolders=@(
            "\AppData\Local\Microsoft\Windows\INetCache",
            "\AppData\Local\Mozilla\Firefox\Profiles\*\cache2",
            "\AppData\Local\Google\Chrome\User Data\*\Cache",
            "\AppData\Local\Google\Chrome\User Data\*\Media Cache",
            "\AppData\Local\Google\Chrome\User Data\*\Code Cache",
            "\AppData\Local\Google\Chrome\User Data\*\GPUCache",
            "\AppData\Local\Google\Chrome\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\Google\Chrome\User Data\*\Service Worker\ScriptCache"
            )
    $systemTempFolders=@(
            "$env:Windir\Temp",
            "$env:Windir\Prefetch",
            "$env:Windir\SofwareDistribution\Download"
            )

    #get user profile folders
    if ($ComputerName -ne $env:ComputerName -or $ComputerName -ne "localhost") {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -Exclude "Public","Default","Default User","All Users" | Select-Object -ExpandProperty Name
            foreach ($profile in $userProfiles) {
                if ($Full){$userTempFolders=$userTempFolders+$extuserTempFolders}
                foreach ($folder in $userTempFolders) {
                    $path = "$env:SystemDrive\Users\$profile$folder"
                    if (Test-Path $path) {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            if($Full) {
                foreach ($folder in $systemTempFolders) {
                    if (Test-Path $folder) {
                        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    } else {
        $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -Exclude "Public","Default","Default User","All Users" | Select-Object -ExpandProperty Name

        foreach ($profile in $userProfiles) {
            if ($Full){$userTempFolders=$userTempFolders+$extuserTempFolders}
            foreach ($folder in $userTempFolders) {
                $path = "$env:SystemDrive\Users\$profile$folder"
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }

        if($Full) {
            foreach ($folder in $systemTempFolders) {
                if (Test-Path $folder) {
                    Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

}
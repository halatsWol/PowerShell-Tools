function New-Folder {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FolderPath
    )
    if (-not (Test-Path -Path $FolderPath)) {New-Item -Path $FolderPath -ItemType Directory -Force > $null}
}

function Remove-PathReliable {
    <#
    Deletes a file or directory as completely as possible right now (native, no external binary,
    long-path safe via the \\?\ prefix), then schedules whatever is still locked for deletion at the
    next reboot through the Session Manager's PendingFileRenameOperations - which are processed
    before any service starts, so a handle held right now no longer matters. Returns an object with
    Deleted / Scheduled / Error. Self-contained so it survives being shipped to a remote session.

    -BestEffort stops after the immediate delete: locked items are neither scheduled for reboot nor
    reported as an error. Used for user-profile temp, where boot-time deletion of a locked user file
    (eg. an open browser's cache) is not wanted.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [switch]$BestEffort
    )
    $result = [PSCustomObject]@{ Path = $Path; Deleted = $false; Scheduled = $false; Error = $null }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        $result.Deleted = $true
        return $result
    }

    # 0) Safety guard: refuse anything that isn't at least two levels below a drive root (e.g.
    #    C:\Windows\SoftwareDistribution). This is the last line of defence against an empty/garbage
    #    caller value - it stops both the immediate delete AND the reboot-time
    #    PendingFileRenameOperations from ever targeting a drive root or a top-level system folder.
    $checkPath  = if ($Path -like '\\?\*') { $Path.Substring(4) } else { $Path }
    $checkPath  = $checkPath.TrimEnd('\')
    $winDirNorm = ([Environment]::GetFolderPath('Windows')).TrimEnd('\')
    $sys32Norm  = ([Environment]::GetFolderPath('System')).TrimEnd('\')
    if (($checkPath -notmatch '^[A-Za-z]:\\[^\\]+\\[^\\]') -or
        ($winDirNorm -and ($checkPath -ieq $winDirNorm)) -or
        ($sys32Norm  -and ($checkPath -ieq $sys32Norm))) {
        $result.Error = "Refused: '$Path' is not a safe deletion target (drive root, Windows directory, or System32)."
        return $result
    }

    # 1) Best-effort immediate delete - removes everything not locked. The \\?\ prefix covers
    #    >260-char paths, and -LiteralPath avoids the '?' in the prefix being treated as a wildcard.
    $prefixed = if ($Path -like '\\?\*') { $Path } else { "\\?\$Path" }
    Remove-Item -LiteralPath $prefixed -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $Path)) {
        $result.Deleted = $true
        return $result
    }

    # -BestEffort: stop here - do not schedule locked items for reboot.
    if ($BestEffort) { return $result }

    # 2) Whatever survived is locked - schedule the remainder for deletion at next boot. Enumeration
    #    works on a locked tree (only deletion is blocked); order deepest-first so each directory is
    #    empty by the time its own entry is processed.
    try {
        $targets = New-Object System.Collections.Generic.List[string]
        @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue) |
            Sort-Object { $_.FullName.Length } -Descending |
            ForEach-Object { $targets.Add($_.FullName) }
        $targets.Add($Path)

        $smKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $pending = New-Object System.Collections.Generic.List[string]
        $current = (Get-ItemProperty -Path $smKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($current) { $pending.AddRange([string[]]$current) }
        foreach ($t in $targets) {
            $pending.Add('\??\' + $t)   # NT-namespace source path to remove
            $pending.Add('')            # empty destination => delete on boot
        }
        Set-ItemProperty -Path $smKey -Name PendingFileRenameOperations -Value $pending.ToArray() -Type MultiString
        $result.Scheduled = $true
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Clear-FolderContentsReliable {
    <#
    Deletes the CONTENTS of a folder (the folder itself is kept, matching temp-cleanup behaviour) by
    routing every child through Remove-PathReliable. -BestEffort skips reboot-scheduling of locked
    items (used for user-profile temp). Returns $true if anything was deferred to the next reboot.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Folder,

        [switch]$BestEffort
    )
    $deferred = $false
    if (-not (Test-Path -LiteralPath $Folder)) { return $false }
    Get-ChildItem -LiteralPath $Folder -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $r = if ($BestEffort) { Remove-PathReliable -Path $_.FullName -BestEffort } else { Remove-PathReliable -Path $_.FullName }
        if ($r -and $r.Scheduled) { $deferred = $true }
    }
    return $deferred
}

function New-RemoteFunctionScriptBlock {
    <#
    Invoke-Command -ScriptBlock ${function:Name} only ships that single function's body to the
    remote session (or Start-Job runspace), so helper functions it depends on (eg. Remove-PathReliable)
    are otherwise undefined there. This bundles the helper definitions together with the entry point
    into one script block, so the helper stays defined in a single place but still works when shipped.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$FunctionName,

        [Parameter(Mandatory=$true)]
        [string]$EntryPoint
    )

    $scriptText = ""
    foreach ($name in $FunctionName) {
        $scriptText += "function $name {`n" + (Get-Item "function:$name").ScriptBlock.ToString() + "`n}`n"
    }
    $scriptText += "$EntryPoint @args"
    return [scriptblock]::Create($scriptText)
}

function Invoke-ContentCacheCleanup {
    <#
    Clears the content/download caches of the software-distribution systems present on the device -
    ConfigMgr (ccmcache), Windows Update (SoftwareDistribution\Download), Adaptiva OneSite
    (<drive>:\AdaptivaCache) and the Intune Management Extension (IMECache + Content staging). Each
    location is auto-detected; systems that are not installed are skipped. Whatever a running agent
    holds open is cleared best-effort now and the remainder is scheduled for deletion on the next
    reboot (via Remove-PathReliable). Self-contained apart from Remove-PathReliable, so it can be
    shipped to a Start-Job runspace or a remote session.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$logfile,

        [Parameter(Mandatory=$true, Position=1)]
        [switch]$VerboseOption,

        [Parameter(Mandatory=$true, Position=2)]
        [string]$VerboseLogFile
    )
    $V = $PSCmdlet.MyInvocation.BoundParameters.Verbose
    if ($V -or $VerboseOption) { $VerboseOption = $true } else { $VerboseOption = $false }
    if ($VerboseOption) { Start-Transcript -Path $VerboseLogFile -Append }

    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Content Cache Cleanup (ConfigMgr / Windows Update / Adaptiva / Intune):"

    # Resolve the Windows directory from the OS itself - $env:windir can be empty in a stripped
    # environment, and an empty base is exactly how a cleanup can end up deleting from a drive root.
    # The result is validated, paths are only built from a validated base, and every deletion target
    # is re-checked below, so an empty/garbage value can never reach a delete.
    $winDir = [Environment]::GetFolderPath('Windows')
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:windir }
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:SystemRoot }
    $winDirValid = (-not [string]::IsNullOrWhiteSpace($winDir)) -and ($winDir -match '^[A-Za-z]:\\[^\\]') -and (Test-Path -LiteralPath $winDir -PathType Container)

    # Per-step log writer (captures the log path so it is safe to call from anywhere in the function).
    $log = {
        param($m)
        try { Add-Content -Path $logfile -Value "`t`t> $m" -ErrorAction SilentlyContinue } catch {}
    }.GetNewClosure()

    # A cache path is only safe to clear if it is absolute, at least one level below a drive root, not
    # the Windows directory or System32, and it exists. No folder-name requirement - a relocated cache
    # can be custom-named (e.g. D:\SCCMCache). An empty/garbage value fails the first checks, so it can
    # never become a root-level delete.
    $isSafeCache = {
        param($p, $win)
        if ([string]::IsNullOrWhiteSpace($p)) { return $false }
        $n = $p.TrimEnd('\')
        if ($n -notmatch '^[A-Za-z]:\\[^\\]+') { return $false }
        if (-not [string]::IsNullOrWhiteSpace($win)) {
            $w = $win.TrimEnd('\')
            if (($n -ieq $w) -or ($n -ieq ((Join-Path $w 'System32').TrimEnd('\')))) { return $false }
        }
        return (Test-Path -LiteralPath $n -PathType Container)
    }

    # Clears a validated folder's CONTENTS via Remove-PathReliable: deletes what is free right now and
    # schedules anything still locked for deletion at the next reboot. Returns $true if anything was
    # deferred to reboot.
    $clearContents = {
        param($folder)
        $deferred = $false
        Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $r = Remove-PathReliable -Path $_.FullName
            if ($r -and $r.Scheduled) { $deferred = $true }
        }
        return $deferred
    }

    # -----------------------------------------------------------------------------------------------
    # Detect each system's cache location(s). Absent systems yield nothing and are simply skipped.
    # -----------------------------------------------------------------------------------------------

    # ConfigMgr ccmcache (relocatable). The WMI CacheConfig class can come back empty even on a healthy
    # client, so try several sources in order and take the first trusted, non-empty path: WMI ->
    # UIResourceMgr COM (what Software Center reads) -> registry CacheConfig -> default under Windows.
    $ccmLoc = $null
    try { $ccmLoc = (Get-CimInstance -Namespace 'root\ccm\SoftMgmtAgent' -ClassName CacheConfig -ErrorAction Stop | Select-Object -First 1).Location } catch { $ccmLoc = $null }
    if ([string]::IsNullOrWhiteSpace($ccmLoc)) {
        try {
            $ui = New-Object -ComObject UIResource.UIResourceMgr
            $ccmLoc = $ui.GetCacheInfo().Location
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($ui)
        } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($ccmLoc)) {
        $ccmLoc = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\CacheConfig' -Name Location -ErrorAction SilentlyContinue).Location
    }
    if ([string]::IsNullOrWhiteSpace($ccmLoc) -and $winDirValid) { $ccmLoc = Join-Path $winDir 'ccmcache' }
    $ccmPaths = @(); if (-not [string]::IsNullOrWhiteSpace($ccmLoc)) { $ccmPaths = @($ccmLoc) }

    # Windows Update download cache - built only from the validated Windows directory.
    $wuPaths = @(); if ($winDirValid) { $wuPaths = @((Join-Path $winDir 'SoftwareDistribution\Download')) }

    # Adaptiva OneSite content cache. Content sits directly under <drive>:\AdaptivaCache (no \Client
    # subfolder). Relocatable via the registry value 'cache.folder' ('na' = use the default), which
    # lives somewhere under the HKLM\SOFTWARE\Adaptiva hive. Only touched when the Adaptiva client is
    # present, so a stray AdaptivaCache folder on a non-Adaptiva box is never cleared.
    $adaptivaPaths = @()
    $adaptivaPresent = ($null -ne (Get-Service -Name 'AdaptivaClient' -ErrorAction SilentlyContinue)) -or (Test-Path 'HKLM:\SOFTWARE\Adaptiva')
    if ($adaptivaPresent) {
        $cacheFolder = $null
        try {
            Get-ChildItem 'HKLM:\SOFTWARE\Adaptiva' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $v = (Get-ItemProperty -LiteralPath $_.PSPath -Name 'cache.folder' -ErrorAction SilentlyContinue).'cache.folder'
                if (-not [string]::IsNullOrWhiteSpace($v)) { $cacheFolder = [string]$v }
            }
        } catch { }
        if ((-not [string]::IsNullOrWhiteSpace($cacheFolder)) -and ($cacheFolder.Trim().ToLower() -ne 'na')) {
            $adaptivaPaths = @($cacheFolder.Trim())
        } else {
            $adaptivaPaths = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { Join-Path $_.RootDirectory.FullName 'AdaptivaCache' })
        }
    }

    # Intune Management Extension (Company Portal / Win32) staging + IMECache. IME normally self-cleans
    # on success but leaves residue on failure/locks. IMECache is under Windows; the Content staging
    # folders are under the IME install (Program Files (x86) on 64-bit, Program Files on 32-bit).
    $intunePaths = @()
    if ($winDirValid) { $intunePaths += (Join-Path $winDir 'IMECache') }
    $imeBases = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    foreach ($base in $imeBases) {
        $imeContent = Join-Path $base 'Microsoft Intune Management Extension\Content'
        if (Test-Path -LiteralPath $imeContent -PathType Container) {
            foreach ($sub in @('Incoming','Staging','Staged')) { $intunePaths += (Join-Path $imeContent $sub) }
        }
    }

    # -----------------------------------------------------------------------------------------------
    # Clear every detected, trusted cache location; defer whatever is locked to the next reboot.
    # -----------------------------------------------------------------------------------------------
    $providers = @(
        @{ Name = 'ConfigMgr (ccmcache)';                          Paths = $ccmPaths }
        @{ Name = 'Windows Update (SoftwareDistribution\Download)'; Paths = $wuPaths }
        @{ Name = 'Adaptiva OneSite (AdaptivaCache)';              Paths = $adaptivaPaths }
        @{ Name = 'Intune Management Extension (IMECache/Content)'; Paths = $intunePaths }
    )

    $anyDeferred = $false
    foreach ($prov in $providers) {
        $cleaned = New-Object System.Collections.Generic.List[string]
        foreach ($p in @($prov.Paths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
            if (& $isSafeCache $p $winDir) {
                $deferred = & $clearContents $p
                if ($deferred) { $anyDeferred = $true }
                if ($deferred) { $cleaned.Add("$p (locked items deferred to reboot)") } else { $cleaned.Add($p) }
            } else {
                & $log "$($prov.Name): skipped '$p' (not found or path could not be trusted)."
            }
        }
        if ($cleaned.Count -gt 0) { & $log "$($prov.Name): cleaned $($cleaned -join '; ')" }
        else { & $log "$($prov.Name): nothing to clean (not installed or no cache present)." }
    }

    if ($anyDeferred) { & $log 'One or more locked cache items were scheduled for deletion on the next reboot (restart required).' }
    if ($VerboseOption) { Stop-Transcript }
}

function Start-UserCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$logfile,

        [Parameter(Mandatory=$true, Position=1)]
        [string[]]$userTempFolders,

        [Parameter(Mandatory=$true, Position=2)]
        [string[]]$userReportingDirs,

        [Parameter(Mandatory=$true, Position=3)]
        [string]$explorerCacheDir,

        [Parameter(Mandatory=$true, Position=4)]
        [string]$localIconCacheDB,

        [Parameter(Mandatory=$true, Position=5)]
        [string]$msTeamsCacheFolder,

        [Parameter(Mandatory=$true, Position=6)]
        [string]$teamsClassicPath,

        [Parameter(Mandatory=$true, Position=7)]
        [switch]$IncludeSystemLogs,

        [Parameter(Mandatory=$true, Position=8)]
        [switch]$IncludeIconCache,

        [Parameter(Mandatory=$true, Position=9)]
        [switch]$IncludeMSTeamsCache,

        [Parameter(Mandatory=$true,Position=10)]
        [switch]$VerboseOption,

        [Parameter(Mandatory=$true,Position=11)]
        [string]$VerboseLogFile

    )

    $V = $PSCmdlet.MyInvocation.BoundParameters.Verbose
    if ($V -or $VerboseOption) {
        $VerboseOption = $true
    } else {
        $VerboseOption = $false
    }
    if($VerboseOption) {
        Start-Transcript -Path $VerboseLogFile -Append
    }
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -Exclude "Public","Default","Default User","All Users" | Select-Object -ExpandProperty Name
    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] User Profile cleanup:"
    foreach ($userProfile in $userProfiles) {
        Add-Content -Path $logfile -Value "`tUser Profile: $userProfile"
        try{
            foreach ($folder in $userTempFolders) {
                $path = Join-Path "C:\Users\$userProfile" $folder
                # $path may contain wildcards (eg. browser '\User Data\*\Cache'); expand to concrete folders.
                Get-Item -Path $path -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
                    Add-Content -Path $logfile -Value "`t`t> $($_.FullName)"
                    Clear-FolderContentsReliable -Folder $_.FullName -BestEffort | Out-Null
                }
            }
            if ($IncludeSystemLogs) {
                foreach ($folder in $userReportingDirs) {
                    $path = Join-Path "C:\Users\$userProfile" $folder
                    Get-Item -Path $path -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
                        Add-Content -Path $logfile -Value "`t`t> $($_.FullName)"
                        Clear-FolderContentsReliable -Folder $_.FullName -BestEffort | Out-Null
                    }
                }
            }
            if ($IncludeIconCache) {
                $path = Join-Path "C:\Users\$userProfile" $explorerCacheDir
                $pathLI = Join-Path "C:\Users\$userProfile" $localIconCacheDB
                Add-Content -Path $logfile -Value "`t`tcleaning Icon & ThumbCache:"
                if (Test-Path -LiteralPath $path) {
                    Get-ChildItem -Path "$path\iconcache*.db","$path\thumbcache*.db" -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Add-Content -Path $logfile -Value "`t`t`t> $($_.FullName)"
                        Remove-PathReliable -Path $_.FullName -BestEffort | Out-Null
                    }
                }
                if (Test-Path -LiteralPath $pathLI) {
                    Add-Content -Path $logfile -Value "`t`t`t> $pathLI"
                    Remove-PathReliable -Path $pathLI -BestEffort | Out-Null
                }
            }
        }catch{
            Write-Warning "Error while cleaning up $userProfile :`r`n $_"
        }

        if($IncludeMSTeamsCache) {
            Get-Process ms-teams -ErrorAction SilentlyContinue | stop-process -Force
            $path = Join-Path "C:\Users\$userProfile" $msTeamsCacheFolder
            $bgPath="$path\Microsoft\MSTeams"
            $bgBackupPath="$path\.."
            #move $msTeamsCacheFolder\Microsoft\MSTeams\Backgrounds to $msTeamsCacheFolder
            if (Test-Path "$bgPath\Backgrounds") {
                Add-Content -Path $logfile -Value "`t`t> Backing Up MS-Teams Background-Images"
                Move-Item -Path "$bgPath\Backgrounds" -Destination "$bgBackupPath" -Force -ErrorAction SilentlyContinue
            }
            #cleanup $msTeamsCacheFolder
            $cpath = "$path"
            if (Test-Path -LiteralPath $cpath) {
                Add-Content -Path $logfile -Value "`t`t> $cpath"
                Clear-FolderContentsReliable -Folder $cpath -BestEffort | Out-Null
            } else {
                Add-Content -Path $logfile -Value "`t`t> $cpath (not found)"
            }
            #create bgPath
            if (-not (Test-Path $bgPath)) {
                New-Item -Path $bgPath -ItemType Directory -Force -ErrorAction SilentlyContinue > $null
            }
            if(Test-Path "$bgBackupPath\Backgrounds") {
                Add-Content -Path $logfile -Value "`t`t> Recovering MS-Teams Background-Images"
                Move-Item -Path "$bgBackupPath\Backgrounds" -Destination "$bgPath" -Force -ErrorAction SilentlyContinue
            }
            #cleanup $teamsClassicPath
            $path = Join-Path "C:\Users\$userProfile" $teamsClassicPath
            if (Test-Path -LiteralPath $path) {
                Add-Content -Path $logfile -Value "`t`t> $path"
                Clear-FolderContentsReliable -Folder $path -BestEffort | Out-Null
            } else {
                Add-Content -Path $logfile -Value "`t`t> $path (not found)"
            }
        }

    }
    if($VerboseOption) {
        Stop-Transcript
    }
}

function Start-SystemCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$logfile,

        [Parameter(Mandatory=$true,Position=1)]
        [string[]]$systemTempFolders,

        [Parameter(Mandatory=$true,Position=2)]
        [string[]]$sysReportingDirs,

        [Parameter(Mandatory=$true,Position=3)]
        [switch]$IncludeSystemData,

        [Parameter(Mandatory=$true,Position=4)]
        [switch]$IncludeSystemLogs,

        [Parameter(Mandatory=$true,Position=5)]
        [switch]$VerboseOption,

        [Parameter(Mandatory=$true,Position=6)]
        [string]$VerboseLogFile

    )

    $V = $PSCmdlet.MyInvocation.BoundParameters.Verbose
    if ($V -or $VerboseOption) {
        $VerboseOption = $true
    } else {
        $VerboseOption = $false
    }
    if($VerboseOption) {
        Start-Transcript -Path $VerboseLogFile -Append
    }
    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] System cleanup:"

    # System temp/logs go through Remove-PathReliable (guarded, long-path safe) and are cleared
    # sequentially: locked items are scheduled for deletion at the next reboot, and every scheduling
    # write targets the single shared PendingFileRenameOperations value, so parallel writers would
    # clobber each other. Content caches (ccmcache/WU/Adaptiva/Intune) are handled by the separate
    # Invoke-ContentCacheCleanup step.
    if($IncludeSystemData) {
        foreach ($folder in $systemTempFolders) {
            if (Test-Path -LiteralPath $folder) {
                Add-Content -Path $logfile -Value "`t`t> $folder"
                Clear-FolderContentsReliable -Folder $folder | Out-Null
            } else {
                Add-Content -Path $logfile -Value "`t`t> $folder (not found)"
            }
        }
    }

    if($IncludeSystemLogs) {
        foreach ($folder in $sysReportingDirs) {
            if (Test-Path -LiteralPath $folder) {
                Add-Content -Path $logfile -Value "`t`t> $folder"
                Clear-FolderContentsReliable -Folder $folder | Out-Null
            } else {
                Add-Content -Path $logfile -Value "`t`t> $folder (not found)"
            }
        }
    }

    if($VerboseOption) {
        Stop-Transcript
    }
}

function Start-CleanMgr{
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$logfile,

        [Parameter(Mandatory=$true,Position=1)]
        [switch]$LowDisk,

        [Parameter(Mandatory=$true,Position=2)]
        [switch]$VeryLowDisk,

        [Parameter(Mandatory=$true,Position=3)]
        [switch]$ConfirmWarning,

        [Parameter(Mandatory=$true,Position=4)]
        [switch]$AutoClean
    )

    if ($VeryLowDisk -and -not $ConfirmWarning) {
        $confirmation = Read-Host "VeryLowDisk cleanup is selected. This will clean up the system including critical recovery-Files and remove all files in the Recycle Bin. (Selecting N will revert to -LowDisk)`r`nDo you want to continue? ([Y]es/[N]o/exit)"
        $validVal=$false
        while(-not $validVal) {
            $confirmation = $confirmation.ToLower()
            switch ($confirmation) {
                "y" {
                    $VeryLowDisk = $true
                    $validVal=$true
                    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] - VeryLowDisk Warning confirmed"
                }
                "n" {
                    $VeryLowDisk = $false
                    $LowDisk = $true
                    $validVal=$true
                    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] - VeryLowDisk Warning declined, reverting to LowDisk"
                }
                "exit" {
                    Write-Host "Exiting script."
                    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] - VeryLowDisk Warning declined with 'Exit', exiting script"
                    $global:LASTEXITCODE = 1
                    return
                }
                Default { $confirmation = Read-Host "`r`nInvalid input. Repeat the confirmation.`r`nDo you want to continue? ([Y]es/[N]o/exit)" }
            }
        }
    }



    if($LowDisk -or $VeryLowDisk){
        $options = @(
            "Active Setup Temp Folders"
            "D3D Shader Cache",
            "Delivery Optimization Files",
            "Diagnostic Data Viewer database files",
            "Downloaded Program Files",
            "Feedback Hub Archive log files",
            "Internet Cache Files",
            "Temporary Files",
            "Temporary Setup Files",
            "Thumbnail Cache",
            "Offline Pages Files",
            "System error memory dump files",
            "System error minidump files",
            "Old ChkDsk Files",
            "Windows Error Reporting Files"
        )

        $CleanMaxDurationVal=10
        if ($VeryLowDisk) {
            $options += @(
                "Update Cleanup",
                "Device Driver Packages",
                "Windows Defender",
                "Upgrade Discarded Files",
                "Windows ESD installation files",
                "Windows Reset Log Files",
                "Windows Upgrade Log Files",
                "Recycle Bin"
            )
            $CleanMaxDurationVal=20
        }

        $softwareDistributionPath = "C:\Windows\SoftwareDistribution"
        $catroot2Path = "C:\Windows\system32\catroot2"
        $softwareDistributionBackupPath = "$softwareDistributionPath.bak"
        $catroot2BackupPath = "$catroot2Path.bak"
        $softwareDistributionBackupPath2 = "$softwareDistributionPath.old"
        $catroot2BackupPath2 = "$catroot2Path.old"

        if ($VeryLowDisk) {
            Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Cleaning Recycle Bin"
            Remove-Item -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue
            Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Cleaning SoftwareDistribution and Catroot2 Backup folders"
            if (Test-Path $softwareDistributionBackupPath) {
                Add-Content -Path $logfile -Value "`t`t> $softwareDistributionBackupPath"
                Remove-Item -Path "\\?\$softwareDistributionBackupPath" -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $catroot2BackupPath) {
                Add-Content -Path $logfile -Value "`t`t> $catroot2BackupPath"
                Remove-Item -Path "\\?\$catroot2BackupPath" -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $softwareDistributionBackupPath2) {
                Add-Content -Path $logfile -Value "`t`t> $softwareDistributionBackupPath2"
                Remove-Item -Path "\\?\$softwareDistributionBackupPath2" -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $catroot2BackupPath2) {
                Add-Content -Path $logfile -Value "`t`t> $catroot2BackupPath2"
                Remove-Item -Path "\\?\$catroot2BackupPath2" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Starting CleanMgr Cleanup"
        Add-Content -Path $logfile -Value "`t`t> Enabling the following Cleanup options."
        foreach ($option in $options) {
            Add-Content -Path $logfile -Value "`t`t> $option"
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$option" -Name StateFlags0901 -Value 2 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        }

        $CleanMaxDuration = New-TimeSpan -Minutes $CleanMaxDurationVal
        Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Executing CleanMgr"
        Write-Host "Starting CleanMgr.exe,`r`nThis may take a while... (up to $($CleanMaxDuration.TotalMinutes) minutes)"
        # Start CleanMgr.exe with arguments and get the process object
        $process = Start-Process -FilePath "CleanMgr.exe" -ArgumentList '/sagerun:901' -PassThru
        $CleanMgrStartTime = Get-Date

        # Monitor the process
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 5

            $elapsed = (Get-Date) - $CleanMgrStartTime
            if ($elapsed -gt $CleanMaxDuration) {
                $cleanMgrStucknotify = "CleanMgr.exe has been running for more than $($CleanMaxDuration.TotalMinutes) minutes. Stopping it..."
                Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStucknotify"
                Write-Warning $cleanMgrStucknotify
                try {
                    $process.Kill()
                    $cleanMgrStuckTerminate = "CleanMgr.exe terminated."
                    Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStuckTerminate"
                    Write-Warning $cleanMgrStuckTerminate
                } catch {
                    $cleanMgrStuckTerminateFail = "Failed to terminate CleanMgr.exe: $_"
                    Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStuckTerminateFail"
                    Write-Warning $cleanMgrStuckTerminateFail
                }
                break
            }
        }
        Get-Process -Name cleanmgr,dismhost -ErrorAction SilentlyContinue | Wait-Process
        Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] CleanMgr Complete"
        Add-Content -Path $logfile -Value "`t`t> removing CleanMgr Automation-Settings"
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags0901 -ErrorAction SilentlyContinue | Remove-ItemProperty -Name StateFlags0901 -ErrorAction SilentlyContinue | Out-Null

    }

    if($AutoClean -or $VeryLowDisk){
        Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Starting CleanMgr Upgrade-Cleanup"
        $CleanMaxDurationVal = 5
        $CleanMaxDuration = New-TimeSpan -Minutes $CleanMaxDurationVal
        Write-Host "Starting CleanMgr Upgrade-Cleanup,`r`nThis may take a while... (up to $($CleanMaxDuration.TotalMinutes) minutes)"
        Start-Process -FilePath "C:\Windows\System32\cleanmgr.exe" -ArgumentList "/autoclean" -NoNewWindow -Wait -PassThru | Out-Null

        $CleanMgrStartTime = Get-Date
        while (-not $process.HasExited) {
            Start-Sleep -Seconds 10

            $elapsed = (Get-Date) - $CleanMgrStartTime
            if ($elapsed -gt $CleanMaxDuration) {
                $cleanMgrStucknotify = "CleanMgr.exe has been running for more than $($CleanMaxDuration.TotalMinutes) minutes. Stopping it..."
                Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStucknotify"
                Write-Warning $cleanMgrStucknotify
                try {
                    $process.Kill()
                    $cleanMgrStuckTerminate = "CleanMgr.exe terminated."
                    Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStuckTerminate"
                    Write-Warning $cleanMgrStuckTerminate
                } catch {
                    $cleanMgrStuckTerminateFail = "Failed to terminate CleanMgr.exe: $_"
                    Add-Content -Path $logfile -Value "!!`t`t> $cleanMgrStuckTerminateFail"
                    Write-Warning $cleanMgrStuckTerminateFail
                }
                break
            }
        }
    }
}


function Invoke-TempDataCleanup {
    <#
    .SYNOPSIS
    Clean up temporary files from user profiles and system folders

    .DESCRIPTION
    This function will clean up temporary files from user profiles and system folders. It can be run on the local computer or on a remote computer.

    Deletion is guarded and long-path safe (>260 characters): every target is validated first, and a
    drive root, the Windows directory, and System32 are always refused. Files that are locked at the
    time of the run are handled according to where they live:
    - User-profile temp is best-effort - locked files are skipped and left in place.
    - System folders (-IncludeSystemData / -IncludeSystemLogs) and the content caches (-IncludeCCMCache)
      schedule any still-locked item for deletion on the next reboot, so a restart is required to finish
      clearing those.

    .PARAMETER ComputerName
    The name of the computer to run the cleanup on. Use "localhost" for the local computer.
    Accepts multiple computer names as an array. Accepts pipeline input.
    If no computer name is provided, it defaults to "localhost".

    .PARAMETER IncludeSystemData
    If this switch is present, the cleanup will also include system folders such as the Windows Temp,
    Prefetch, and SoftwareDistribution\Download folders.

    .PARAMETER IncludeSystemLogs
    If this switch is present, the cleanup will also include system log files and reporting folders such
    as C:\Windows\Logs, C:\Windows\Minidump, and the Windows Error Reporting queues. Logs held open by
    Windows services are scheduled for deletion on the next reboot.

    .PARAMETER IncludeCCMCache
    If this switch is present, the cleanup will also clear the content/download caches of the
    software-distribution systems detected on the device. Each location is auto-detected and systems
    that are not installed are skipped:
    - ConfigMgr / SCCM (ccmcache) - relocation-aware (found via WMI, the Software Center COM API, the
      registry, or the default under the Windows directory), so a moved cache (e.g. D:\SCCMCache) is
      still found rather than assuming C:\Windows\ccmcache.
    - Windows Update (SoftwareDistribution\Download)
    - Adaptiva OneSite (<drive>:\AdaptivaCache)
    - Intune Management Extension (IMECache + Content staging)

    Items held open by a running agent are cleared best-effort now; anything still locked is scheduled
    for deletion on the next reboot. Restart the device to finish.

    .PARAMETER IncludeBrowserData
    If this switch is present, the cleanup will also include browser cache folders.

    .PARAMETER IncludeMSTeamsCache
    If this switch is present, the cleanup will also include Microsoft Teams cache folders.

    .PARAMETER IncludeIconCache
    If this switch is present, the cleanup will also include the User Icon & ThumbCache files.

    .PARAMETER IncludeAllPackages
    If this switch is present, the cleanup will also include the LocalCache folders of all packages in $env:localappdata\Packages.
    This will render IncludeMSTeamsCache irrelevant.

    USE WITH CAUTION! This will Clean Up all LocalCache folders of all packages in $env:localappdata\Packages.

    .PARAMETER LowDisk
    This Switch will Use the CleanMgr to clean up the system. This can be used with all other Switches.
    Please keep in mind that this may take a while to complete.
    Using this Switch will also set the following switches:
    -IncludeSystemData, -IncludeCCMCache, -IncludeIconCache

    Following CleanMgr Settings will be set:
    - D3D Shader Cache
    - Delivery Optimization Files
    - Downloaded Program Files
    - Internet Cache Files
    - Temporary Files
    - Temporary Setup Files
    - Thumbnail Cache
    - Feedback Hub Archive log files
    - Offline Pages Files
    - System error memory dump files
    - System error minidump files
    - Old ChkDsk Files
    - Windows Error Reporting Files


    .PARAMETER VeryLowDisk
    This Switch will Use the CleanMgr to clean up the system . This can be used with all other Switches.
    Please keep in mind that this may take a while to complete.
    Confirmation is required before proceeding with the cleanup (can be bypassed using -ConfirmWarning).
    If the Prompt is denied, the cleanup will fall back to -LowDisk
    Using this Switch will also set the following switches:
    -IncludeSystemData, -IncludeCCMCache, -IncludeIconCache

    This will use the same CleanMgr Settings as -LowDisk, but will also set the following settings:
    - Update Cleanup
    - Device Driver Packages
    - Windows Defender
    - Upgrade Discarded Files
    - Windows ESD installation files
    - Windows Reset Log Files
    - Windows Upgrade Log Files

    Additionally the Recycle Bin will be cleaned up, as well as the SoftwareDistribution and Catroot2 Backup (*.old / *.bak) folders.

    This will also perform -AutoClean

    .PARAMETER ConfirmWarning
    Using this switch will bypass the confirmation prompt of -VeryLowDisk and proceed with the cleanup.

    .PARAMETER AutoClean
    Automatically deletes the files that are left behind after you upgrade Windows. This can be used with all other Switches.
    Using this Switch will also set the following switches:
    -IncludeSystemData, -IncludeCCMCache, -IncludeIconCache

    .PARAMETER init
    When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
    When specified, no other Parameter will be executed (other provided Parameters will be ignored). This will retun 0 if the Config-File was created successfully, or already exists.

    Configuration-File Template:
    ```
    ShareDrive=C$                               # ShareDrive-Letter of the Remote-Device on which Windows is installed
    TempFolder=_IT-temp                         # Name of the temporary Directory on the Remote-Device
    LocalTargetPath=C:\remote-Files             # Path where the Logs and Files will be copied to on the executing Client
    ```

    .PARAMETER Credentials
    Specifies the user credentials to use for the remote Connection to Remote Computers.

    If Get-Credential is used, to obtain the credentials interactively, and it throws an error without prompting, please use Get-CredentialObject from the CredentialHandler Module of the Module-Suite (https://github.com/halatsWol/PowerShell-Tools)

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01"

    This will clean up temporary files from user profiles on Computer01.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData

    This will clean up temporary files from user profiles and system folders on Computer01.

    .EXAMPLE
    $DeviceList | Invoke-TempDataCleanup -IncludeSystemData

    This will clean up temporary files from user profiles and system folders on all computers in the $DeviceList array.
    ("" and $Null will not default to "localhost" and are skipped if list is longer than 1).

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName dev01,dev02,dev03,""

    This will clean up temporary files from user profiles on dev01, dev02, dev03 and the local computer ("").

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "localhost" -IncludeSystemData -IncludeBrowserData

    This will clean up temporary files including Browser-Cache Data from user profiles and system folders on the local computer.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData -IncludeBrowserData -IncludeMSTeamsCache

    This will clean up temporary files including Browser-Cache Data and Microsoft Teams cache from user profiles and system folders on Computer01.

    .EXAMPLE
    Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData -IncludeSystemLogs -IncludeCCMCache

    This will clean up user and system temp, system logs, and the software-distribution content caches
    (ConfigMgr/SCCM ccmcache, Windows Update, Adaptiva, Intune) on Computer01. The ConfigMgr cache is
    located dynamically, so a relocated cache is still found. Locked system/cache items are scheduled for
    deletion on the next reboot - restart Computer01 to finish.

    .INPUTS
    [string[]]$ComputerName - Accepts pipeline input of Multiple Computer Names.

    .LINK
    https://github.com/halatsWol/PowerShell-Tools

    .LINK
	https://www.kMarflow.com/

    .NOTES
    This script is provided as-is and is not supported by Microsoft. Use it at your own risk.
    WinRM must be enabled and configured on the remote computer for this script to work. Using IP addresses may require additional configuration.
    Using this script may require administrative privileges on the remote computer.
    In a Domain, powershell can be executed locally as the user wich has the necessary permissions on the remote computer.

    Deletion is guarded and long-path safe. Locked files under the system folders (-IncludeSystemData /
    -IncludeSystemLogs) and the content caches (-IncludeCCMCache) are scheduled for deletion on the next
    reboot, so a restart is required to finish. Locked user-profile files are skipped (best-effort) and
    are never queued for boot-time deletion.


    Further information:
    https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-5.1




    WARNING:
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT PERMISSION OR AUTHORIZATION.
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT UNDERSTANDING THE CONSEQUENCES.
    NEVER RUN SCRIPTS FROM UNTRUSTED SOURCES WITHOUT REVIEWING AND UNDERSTANDING THE CODE.
    DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING. IT MAY CAUSE DATA LOSS OR SYSTEM INSTABILITY.


    Author: Wolfram Halatschek
    E-Mail: dev@kMarflow.com
    Date: 2026-08-15
    #>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeSystemData,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeSystemLogs,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeCCMCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeBrowserData,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeMSTeamsCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeIconCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeAllPackages,

        [Parameter(Mandatory=$false)]
        [switch]$init,

        [Parameter(Mandatory=$false)]
        [switch]$LowDisk,

        [Parameter(Mandatory=$false)]
        [switch]$VeryLowDisk,

        [Parameter(Mandatory=$false)]
        [switch]$ConfirmWarning,

        [Parameter(Mandatory=$false)]
        [switch]$AutoClean,

        [Parameter(Mandatory=$false)]
        [pscredential]$Credentials

    )
    begin {
        $computerList = @()
    }
    process {
        if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
            $computerList += $ComputerName
        }
    }
    end {
        if ($computerList.Count -eq 0) {
            $computerList = @("localhost")
        }

        # check if verbose is enabled
        $VerboseOption = $PSCmdlet.MyInvocation.BoundParameters.Verbose

        $initFree_bytes=""
        $exitFree_bytes=""

        $confFile="$PSScriptRoot\TempDataCleanup.conf"
        if($init){
            $ShareDrive="C$"
            $TempFolder="_IT-temp"
            $LocalTargetPath="C:\remote-Files"

            if(-not (Test-Path $confFile)){
                try {
                    New-Item -Path $confFile -ItemType File -Force
                    Add-Content -Path $confFile -Value "ShareDrive=$ShareDrive"
                    Add-Content -Path $confFile -Value "TempFolder=$TempFolder"
                    Add-Content -Path $confFile -Value "LocalTargetPath=$LocalTargetPath"
                } catch {
                    Write-Error "Error creating Config-File. Please check if the Module-Path is writable`r`n `r`n$_"
                    $global:LASTEXITCODE = 1
                    return
                }
            } else {
                Write-Warning "Config-File already exists. If you want to reset the Config-File, please delete it manually"
            }
            $global:LASTEXITCODE = 0
            return
        }

        $userTempFolders=@(
            "\AppData\Local\Temp",
            "\AppData\Local\Microsoft\Office\16.0\OfficeFileCache",
            "\AppData\Local\Microsoft\Office\15.0\Lync\Tracing",
            "\AppData\Local\Microsoft\Office\16.0\Lync\Tracing",
            "\AppData\Local\Microsoft\EdgeWebView\Cache",
            "\AppData\LocalLow\Sun\Java\Deployment\cache"
        )
        $commonUserPackages=@(
            "\AppData\Local\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.WindowsCamera_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.DiagnosticDataViewer_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe\TempState",
            "\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TempState"
        )
        $allPackagesCacheFolder="\AppData\Local\Packages\*\LocalCache"
        $BrowserData=@(
            # general
            "\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData",
            # Microsoft Internet Explorer
            "\AppData\Local\Microsoft\Windows\INetCache",
            "\AppData\Local\Microsoft\Windows\INetCookies",
            # Microsoft Edge (Chromium)
            "\AppData\Local\Microsoft\Edge\User Data\*\Temp",
            "\AppData\Local\Microsoft\Edge\User Data\*\Cache",
            "\AppData\Local\Microsoft\Edge\User Data\*\Media Cache",
            "\AppData\Local\Microsoft\Edge\User Data\*\Code Cache",
            "\AppData\Local\Microsoft\Edge\User Data\*\GPUCache",
            "\AppData\Local\Microsoft\Edge\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\Microsoft\Edge\User Data\*\Service Worker\ScriptCache",
            # Mozilla Firefox
            "\AppData\Local\Mozilla\Firefox\Profiles\*\cache2",
            "\AppData\Local\Mozilla\Firefox\Profiles\*\storage\default",
            # Google Chrome
            "\AppData\Local\Google\Chrome\User Data\*\Temp",
            "\AppData\Local\Google\Chrome\User Data\*\Cache",
            "\AppData\Local\Google\Chrome\User Data\*\Media Cache",
            "\AppData\Local\Google\Chrome\User Data\*\Code Cache",
            "\AppData\Local\Google\Chrome\User Data\*\GPUCache",
            "\AppData\Local\Google\Chrome\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\Google\Chrome\User Data\*\Service Worker\ScriptCache"
            # Opera
            "\AppData\Local\Opera Software\Opera Stable\Temp",
            "\AppData\Local\Opera Software\Opera Stable\Cache",
            "\AppData\Local\Opera Software\Opera Stable\Media Cache",
            "\AppData\Local\Opera Software\Opera Stable\Code Cache",
            "\AppData\Local\Opera Software\Opera Stable\GPUCache",
            "\AppData\Local\Opera Software\Opera Stable\Service Worker\CacheStorage",
            "\AppData\Local\Opera Software\Opera Stable\Service Worker\ScriptCache",
            # Vivaldi
            "\AppData\Local\Vivaldi\User Data\*\Temp",
            "\AppData\Local\Vivaldi\User Data\*\Cache",
            "\AppData\Local\Vivaldi\User Data\*\Media Cache",
            "\AppData\Local\Vivaldi\User Data\*\Code Cache",
            "\AppData\Local\Vivaldi\User Data\*\GPUCache",
            "\AppData\Local\Vivaldi\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\Vivaldi\User Data\*\Service Worker\ScriptCache"
            # Brave
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Temp",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Cache",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Media Cache",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Code Cache",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\GPUCache",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Service Worker\CacheStorage",
            "\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Service Worker\ScriptCache"
        )

        $explorerCacheDir="\AppData\Local\Microsoft\Windows\Explorer"
        $localIconCacheDB="\AppData\Local\IconCache.db"


        $systemTempFolders=@(
            "C:\Windows\Temp",
            "C:\Windows\Prefetch",
            "C:\Windows\SoftwareDistribution\Download"
        )
        $msTeamsCacheFolder="\AppData\local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache"
        $teamsClassicPath="\AppData\Roaming\Microsoft\Teams"

        $userReportingDirs=@(
            "\AppData\Local\CrashDumps",
            "\Appdata\Local\D3DSCache",
            "\AppData\Local\Microsoft\Windows\WER\ReportQueue",
            "\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
        )

        $sysReportingDirs=@(
            "C:\Windows\Logs",
            "C:\Windows\Minidump",
            "C:\Windows\LiveKernelReports",
            "C:\Windows\System32\LogFiles\WMI",
            "C:\Windows\System32\LogFiles\setupcln",
            "C:\Windows\ServiceProfiles\LocalService\AppData\Local\CrashDumps",
            "C:\Windows\sysWOW64\config\systemprofile\AppData\Local\CrashDumps",
            "C:\Windows\system32\config\systemprofile\AppData\Local\CrashDumps",
            "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache",
            "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
            "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
        )

        $LocalTargetPath = "C:\remote-Files"
        $TempFolder="_IT-temp"
        $ShareDrive="C$"

        if(Test-Path $confFile){
            $confData = Get-Content -Path $confFile
            foreach ($line in $confData) {
                $key, $value = $line -split '=', 2
                if ($key -eq "ShareDrive") {$ShareDrive=$value}
                elseif ($key -eq "TempFolder") {$TempFolder=$value}
                elseif ($key -eq "LocalTargetPath") {$LocalTargetPath=$value}
                else {
                    Write-Warning "Unknown Key in Config-File: $key"
                    $global:LASTEXITCODE = 1
                    return
                }
            }

        }


        if($LowDisk -or $VeryLowDisk){
            $IncludeSystemData=$true
            $IncludeCCMCache=$true
            $IncludeIconCache=$true
        }

        if($IncludeAllPackages){
            $confirmation=Read-Host "Are you sure you want to include ALL Packages in the cleanup?`r`nThis will render IncludeMSTeamsCache irrelevant. Do you want to continue?`r`n(enter [yes] to continue with this option)"
            if($confirmation -ne "yes"){
                $IncludeAllPackages=$false
                Write-Host "Cleanup will not use IncludeAllPackages"
            }
            else{
                $IncludeMSTeamsCache=$false
                Write-Host "Cleanup will use IncludeAllPackages"
            }
        }

        if ($IncludeAllPackages){$userTempFolders=$userTempFolders+$allPackagesCacheFolder}else{$userTempFolders=$userTempFolders+$commonUserPackages}
        if ($IncludeBrowserData){$userTempFolders=$userTempFolders+$BrowserData}


        foreach ( $comp in $computerList ){

            $comp = $comp.Trim()
            if ($comp -and ($comp -notmatch '^(([a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$')) {
                Write-Error "Invalid ComputerName format: '$comp'.`r`nValid Windows hostnames must:
                - Only contain letters (A-Z, a-z), numbers (0-9), hyphens (-), underscores (_), and dots (.)
                - Not contain spaces or special characters
                - Not start or end with a hyphen or dot
                - Each label (separated by dots) must be 1-63 characters
                - The full name must be 1-255 characters
                - Alternatively, a valid IPv4 address (e.g. 192.168.1.1) is allowed."

                continue
            }

            $remote=$false
            $LocalTargetPath = "$LocalTargetPath\$comp"

            $logdir="C:\$TempFolder"
            $logfile="$logdir\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_TempDataCleanup.log"
            $VerboseLogFile="$logdir\$(Get-Date -Format 'yyyy-MM-dd_HH-mm')_TempDataCleanup_Verbose.log"
            $invokeParams =@{}
            if (
                    -not [string]::IsNullOrWhiteSpace($comp) -and
                    $comp.ToLower() -ne "localhost" -and
                    $comp.ToUpper() -ne $env:COMPUTERNAME.ToUpper()
                ) {
                $remote=$true
            } else {
                $comp = "localhost"
            }
            if ($remote){
                $invokeParams.ComputerName = $comp
                if ($Credentials) {
                    $invokeParams.Credential = $Credentials
                }
                if (-not (Test-Connection -ComputerName $comp -Count 1 -Quiet)){
                    Write-Host ""
                    Write-Warning "Computer $comp is not reachable`r`n"
                    Write-Host "`r`n-------------------------------"
                    continue
                }

                $initFree_bytes = Invoke-Command @invokeParams -ScriptBlock {
                    (Get-Volume -DriveLetter C).SizeRemaining
                }
                Invoke-Command @invokeParams -ScriptBlock ${function:New-Folder} -ArgumentList $logdir
                Invoke-Command @invokeParams -ScriptBlock {
                    param($logfile, $comp)
                    Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Starting Cleanup on $comp"
                } -ArgumentList $logfile, $comp
            } else {
                $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                $isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if ( -not $isElevated ) {
                    $("") ; Write-Warning "`r`nThis script must be run with administrative privileges. Please restart the script in an elevated PowerShell session.`r`n"
                    Pause ; $("")
                    $global:LASTEXITCODE=1
                    return
                }
                $initFree_bytes = (Get-Volume -DriveLetter C).SizeRemaining
                New-Folder -FolderPath $logdir
                Add-Content -Path $logfile -Value "[$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))] Starting Cleanup on $comp"
            }

            Write-Host "`r`nCleaning up  $comp`r`n"

            # Bundle each worker with the helpers it needs so they survive being shipped to a Start-Job
            # runspace or a remote session (module functions are otherwise undefined there).
            $userCleanupBlock   = New-RemoteFunctionScriptBlock -FunctionName 'Remove-PathReliable','Clear-FolderContentsReliable','Start-UserCleanup'   -EntryPoint 'Start-UserCleanup'
            $systemCleanupBlock = New-RemoteFunctionScriptBlock -FunctionName 'Remove-PathReliable','Clear-FolderContentsReliable','Start-SystemCleanup' -EntryPoint 'Start-SystemCleanup'
            $cacheCleanupBlock  = New-RemoteFunctionScriptBlock -FunctionName 'Remove-PathReliable','Invoke-ContentCacheCleanup' -EntryPoint 'Invoke-ContentCacheCleanup'

            Write-Host "Cleaning up User Data and Cache"
            if ($remote) {
                $userCleanupJob = Invoke-Command @invokeParams -ScriptBlock $userCleanupBlock -ArgumentList $logfile, $userTempFolders, $userReportingDirs, $explorerCacheDir, $localIconCacheDB, $msTeamsCacheFolder, $teamsClassicPath, $IncludeSystemLogs, $IncludeIconCache, $IncludeMSTeamsCache, $VerboseOption, $VerboseLogFile -AsJob
            } else {
                $userCleanupJob = Start-Job -ScriptBlock $userCleanupBlock -ArgumentList $logfile, $userTempFolders, $userReportingDirs, $explorerCacheDir, $localIconCacheDB, $msTeamsCacheFolder, $teamsClassicPath, $IncludeSystemLogs, $IncludeIconCache, $IncludeMSTeamsCache, $VerboseOption, $VerboseLogFile
            }
            Wait-Job -Job $userCleanupJob | Out-Null
            Receive-Job -Job $userCleanupJob
            Remove-Job -Job $userCleanupJob

            if( $IncludeSystemData -or $IncludeSystemLogs) {
                Write-Host "Cleaning up System Data"
                if ($remote) {
                    $systemCleanupJob = Invoke-Command @invokeParams -ScriptBlock $systemCleanupBlock -ArgumentList $logfile, $systemTempFolders, $sysReportingDirs, $IncludeSystemData, $IncludeSystemLogs, $VerboseOption, $VerboseLogFile -AsJob
                } else {
                    $systemCleanupJob = Start-Job -ScriptBlock $systemCleanupBlock -ArgumentList $logfile, $systemTempFolders, $sysReportingDirs, $IncludeSystemData, $IncludeSystemLogs, $VerboseOption, $VerboseLogFile
                }
                Wait-Job -Job $systemCleanupJob | Out-Null
                Receive-Job -Job $systemCleanupJob
                Remove-Job -Job $systemCleanupJob
            }

            # Content caches run as their own serialized step (ConfigMgr ccmcache is relocation-aware,
            # plus Windows Update / Adaptiva / Intune). Kept after system cleanup and Wait-Job'd so the
            # reboot-scheduling registry writes never overlap the system-cleanup ones.
            if( $IncludeCCMCache) {
                Write-Host "Cleaning up Content Caches (ConfigMgr / Windows Update / Adaptiva / Intune)"
                if ($remote) {
                    $cacheCleanupJob = Invoke-Command @invokeParams -ScriptBlock $cacheCleanupBlock -ArgumentList $logfile, $VerboseOption, $VerboseLogFile -AsJob
                } else {
                    $cacheCleanupJob = Start-Job -ScriptBlock $cacheCleanupBlock -ArgumentList $logfile, $VerboseOption, $VerboseLogFile
                }
                Wait-Job -Job $cacheCleanupJob | Out-Null
                Receive-Job -Job $cacheCleanupJob
                Remove-Job -Job $cacheCleanupJob
            }

            if($LowDisk -or $VeryLowDisk -or $AutoClean){
                if ($remote) {
                    Invoke-Command @invokeParams -ScriptBlock ${function:Start-CleanMgr} -ArgumentList $logfile, $LowDisk, $VeryLowDisk, $ConfirmWarning, $AutoClean
                } else {
                    Start-CleanMgr -logfile $logfile -LowDisk:$LowDisk -VeryLowDisk:$VeryLowDisk -ConfirmWarning:$ConfirmWarning -AutoClean:$AutoClean
                }
            }



            if ($remote) {
                New-Folder -FolderPath $localTargetPath

                $Session = New-PSSession @invokeParams
                Copy-Item -Path "$logfile" -Destination $localTargetPath -Recurse -Force -FromSession $Session

                if ($?) {

                    Invoke-Command @invokeParams -ScriptBlock {
                        Remove-Item -Path "$using:logdir" -Recurse
                    } -Verbose:$VerboseOption

                } else {
                    Write-Error "An error occurred while copying the log files from $comp."
                }
            }

            if ($remote){
                $exitFree_bytes = Invoke-Command @invokeParams -ScriptBlock {
                    (Get-Volume -DriveLetter C).SizeRemaining
                }
            } else {
                $exitFree_bytes = (Get-Volume -DriveLetter C).SizeRemaining
            }

            $additionalFree = "{0:N2}" -f (($exitFree_bytes - $initFree_bytes)/1GB)
            Write-Host "`r`nAdditional Free Space: $additionalFree GB`r`nTotal Free Space: $("{0:N2}" -f ($exitFree_bytes/1GB)) GB`r`n"
            Write-Host "-------------------------------"
        }
        Write-Host "`r`nCleanUp Complete" -ForegroundColor Green
        Write-Host "Please Restart the Computer to finalize the Cleanup!" -ForegroundColor Yellow
    }
}

Export-ModuleMember -Function Invoke-TempDataCleanup

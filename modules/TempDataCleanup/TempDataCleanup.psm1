function New-Folder {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FolderPath
    )
    if (-not (Test-Path -Path $FolderPath)) {New-Item -Path $FolderPath -ItemType Directory -Force > $null}
}

function Write-CleanupLog {
    <#
    Appends one CMTrace-format entry (same layout as Repair-System's Write-RepairLog), so the log reads
    cleanly in CMTrace/OneTrace with a component per step and Warning/Error highlighting. A multi-line
    message becomes a single entry. A briefly locked file (open viewer, AV scan) is retried and the
    function never throws - a lost log line must not abort the cleanup. Self-contained so it survives
    being shipped to a remote session.
    #>
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$Component,

        [Parameter(Mandatory=$true, Position=2)]
        [string]$LogPath,

        [Parameter(Position=3)]
        [ValidateSet('Info','Warning','Error')]
        [string]$Severity = 'Info'
    )
    $type   = @{ Info = 1; Warning = 2; Error = 3 }[$Severity]
    $now    = Get-Date
    $offset = [TimeZoneInfo]::Local.GetUtcOffset($now).TotalMinutes
    $source = if ($MyInvocation.ScriptName) { Split-Path -Path $MyInvocation.ScriptName -Leaf } else { 'TempDataCleanup' }
    $entry  = '<![LOG[{0}]LOG]!><time="{1}{2:+000;-000}" date="{3}" component="{4}" context="" type="{5}" thread="{6}" file="{7}:{8}">' -f
        $Message, $now.ToString('HH:mm:ss.fff'), $offset, $now.ToString('MM-dd-yyyy'), $Component, $type, $PID, $source, $MyInvocation.ScriptLineNumber

    # -Encoding UTF8 skips the BOM-detection read Add-Content otherwise does, which is the open that
    # fails on a transiently held file.
    for ($i = 0; $i -lt 10; $i++) {
        try {
            Add-Content -LiteralPath $LogPath -Value $entry -Encoding UTF8 -ErrorAction Stop
            return
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    Write-Warning "TempDataCleanup: a log entry could not be written to '$LogPath'; continuing."
}

function Get-CleanupBasePath {
    <#
    Resolves the OS folders every cleanup target is built from, on the machine being cleaned. A base is
    only accepted if it is absolute, below a drive root and exists; otherwise it is $null and callers
    skip the targets depending on it. An empty variable or failed lookup therefore never turns into a
    path at or near a drive root. Self-contained so it survives being shipped to a remote session.
    #>
    $firstValid = {
        foreach ($candidate in $args) {
            if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
            $candidate = ([string]$candidate).TrimEnd('\')
            if (($candidate -match '^[A-Za-z]:\\[^\\]') -and (Test-Path -LiteralPath $candidate -PathType Container)) {
                return $candidate
            }
        }
    }

    $windows  = & $firstValid ([Environment]::GetFolderPath('Windows')) $env:windir $env:SystemRoot
    $drive    = if ($windows) { Split-Path -Path $windows -Qualifier }
    $profiles = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory -ErrorAction SilentlyContinue).ProfilesDirectory

    @{
        ComputerName = $env:COMPUTERNAME
        Windows     = $windows
        SystemDrive = $drive
        ProgramData = & $firstValid ([Environment]::GetFolderPath('CommonApplicationData')) $env:ProgramData
        Profiles    = & $firstValid $profiles $(if ($drive) { "$drive\Users" })
    }
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

    # 2) Whatever survived is locked - schedule the remainder for deletion at next boot.
    try {
        Register-PendingDelete -Path $Path
        $result.Scheduled = $true
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Register-PendingDelete {
    <#
    Queues paths for deletion at the next boot via the Session Manager's PendingFileRenameOperations.
    A directory is expanded to its contents deepest-first (enumeration works on a locked tree), so each
    directory is empty by the time its own entry is processed; a file is queued once. The value is read
    and written once per call and paths already queued are skipped, so callers should pass all locked
    items of a folder together. Callers have already validated the paths (Remove-PathReliable guard).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Path
    )
    $smKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $pending = New-Object System.Collections.Generic.List[string]
    $queued  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $current = @((Get-ItemProperty -Path $smKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations | Where-Object { $null -ne $_ })
    $pending.AddRange([string[]]$current)
    # Entries are source/destination pairs; an empty destination means 'delete'.
    for ($i = 0; $i + 1 -lt $current.Count; $i += 2) {
        if ($current[$i + 1] -eq '') { [void]$queued.Add($current[$i]) }
    }

    $added = 0
    foreach ($root in $Path) {
        $targets = @(if (Test-Path -LiteralPath $root -PathType Container) {
            Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } -Descending |
                ForEach-Object { $_.FullName }
        }) + $root
        foreach ($target in $targets) {
            if ($queued.Add('\??\' + $target)) {
                $pending.Add('\??\' + $target)
                $pending.Add('')
                $added++
            }
        }
    }
    if ($added -gt 0) {
        Set-ItemProperty -Path $smKey -Name PendingFileRenameOperations -Value $pending.ToArray() -Type MultiString
    }
}

function Clear-FolderContentsReliable {
    <#
    Deletes the CONTENTS of a folder (the folder itself is kept, matching temp-cleanup behaviour) by
    routing every child through Remove-PathReliable. Whatever is still locked is queued for deletion at
    the next reboot in one go; -BestEffort skips that (used for user-profile temp). Returns $true if
    anything was deferred to the next reboot.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Folder,

        [switch]$BestEffort
    )
    if (-not (Test-Path -LiteralPath $Folder)) { return $false }
    # Refused items carry an Error and are never queued; only genuinely locked ones are collected.
    $locked = @(Get-ChildItem -LiteralPath $Folder -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $r = Remove-PathReliable -Path $_.FullName -BestEffort
        if (-not $r.Deleted -and -not $r.Error) { $_.FullName }
    })
    if ($BestEffort -or $locked.Count -eq 0) { return $false }
    try {
        Register-PendingDelete -Path $locked
        return $true
    } catch {
        return $false
    }
}

function New-RemoteFunctionScriptBlock {
    <#
    Invoke-Command -ScriptBlock ${function:Name} only ships that single function's body to the
    remote session, so helper functions it depends on (eg. Remove-PathReliable) are otherwise
    undefined there. This bundles the helper definitions together with the entry point into one
    script block, so the helper stays defined in a single place but still works when shipped. The
    block takes one hashtable (-ArgumentList $params) and splats it onto the entry point.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$FunctionName,

        [Parameter(Mandatory=$true)]
        [string]$EntryPoint
    )

    $scriptText = "param(`$Params)`n"
    foreach ($name in $FunctionName) {
        $scriptText += "function $name {`n" + (Get-Item "function:$name").ScriptBlock.ToString() + "`n}`n"
    }
    $scriptText += "$EntryPoint @Params"
    return [scriptblock]::Create($scriptText)
}

function Invoke-ContentCacheCleanup {
    <#
    Clears the content/download caches of the software-distribution systems present on the device -
    ConfigMgr (ccmcache), Windows Update (SoftwareDistribution\Download), Adaptiva OneSite
    (<drive>:\AdaptivaCache) and the Intune Management Extension (IMECache + Content staging). Each
    location is auto-detected; systems that are not installed are skipped. Whatever a running agent
    holds open is cleared best-effort now and the remainder is scheduled for deletion on the next
    reboot (via Clear-FolderContentsReliable). Self-contained apart from the bundled helpers, so it can
    be shipped to a remote session.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$logfile,

        [string]$TranscriptPath
    )
    if ($TranscriptPath) { Start-Transcript -Path $TranscriptPath -Append | Out-Null }

    $log = @{ LogPath = $logfile; Component = 'ContentCache' }
    Write-CleanupLog @log 'Content cache cleanup (ConfigMgr / Windows Update / Adaptiva / Intune)'

    # Resolve the Windows directory from the OS itself - $env:windir can be empty in a stripped
    # environment, and an empty base is exactly how a cleanup can end up deleting from a drive root.
    # The result is validated, paths are only built from a validated base, and every deletion target
    # is re-checked below, so an empty/garbage value can never reach a delete.
    $winDir = [Environment]::GetFolderPath('Windows')
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:windir }
    if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = $env:SystemRoot }
    $winDirValid = (-not [string]::IsNullOrWhiteSpace($winDir)) -and ($winDir -match '^[A-Za-z]:\\[^\\]') -and (Test-Path -LiteralPath $winDir -PathType Container)

    # A cache path is only safe to clear if it is absolute, at least one level below a drive root, it
    # exists, and it is not one of the system's key folders or inside a user profile - the location
    # comes from WMI/COM/registry and a misconfigured value must never empty eg. C:\Users or
    # C:\Program Files. No folder-name requirement: a relocated cache can be custom-named (D:\SCCMCache).
    $profilesDir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory -ErrorAction SilentlyContinue).ProfilesDirectory
    $protected = @(
        $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $profilesDir
        if ($winDirValid) { $winDir; foreach ($sub in 'System32', 'SysWOW64', 'WinSxS', 'servicing', 'Installer', 'SoftwareDistribution') { Join-Path $winDir $sub } }
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.TrimEnd('\') }
    $isSafeCache = {
        param($p)
        if ([string]::IsNullOrWhiteSpace($p)) { return $false }
        $n = $p.TrimEnd('\')
        if ($n -notmatch '^[A-Za-z]:\\[^\\]+') { return $false }
        if ($protected -contains $n) { return $false }
        if ($profilesDir -and $n.StartsWith($profilesDir.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return $false }
        return (Test-Path -LiteralPath $n -PathType Container)
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
            if (& $isSafeCache $p) {
                if (Clear-FolderContentsReliable -Folder $p) {
                    $anyDeferred = $true
                    $cleaned.Add("$p (locked items deferred to reboot)")
                } else {
                    $cleaned.Add($p)
                }
            } else {
                Write-CleanupLog @log "$($prov.Name): skipped '$p' (not found or path could not be trusted)."
            }
        }
        if ($cleaned.Count -gt 0) { Write-CleanupLog @log "$($prov.Name): cleaned $($cleaned -join '; ')" }
        else { Write-CleanupLog @log "$($prov.Name): nothing to clean (not installed or no cache present)." }
    }

    if ($anyDeferred) { Write-CleanupLog @log 'One or more locked cache items were scheduled for deletion on the next reboot (restart required).' -Severity Warning }
    if ($TranscriptPath) { Stop-Transcript | Out-Null }
}

function Start-UserCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$logfile,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases,

        [Parameter(Mandatory=$true)]
        [string[]]$userTempFolders,

        [string[]]$userReportingDirs,

        [string]$explorerCacheDir,

        [string]$localIconCacheDB,

        [string]$msTeamsCacheFolder,

        [string]$teamsClassicPath,

        [switch]$IncludeSystemLogs,

        [switch]$IncludeIconCache,

        [switch]$IncludeMSTeamsCache,

        [string]$TranscriptPath
    )

    if ($TranscriptPath) { Start-Transcript -Path $TranscriptPath -Append | Out-Null }
    $log = @{ LogPath = $logfile; Component = 'UserCleanup' }
    if (-not $Bases.Profiles) {
        Write-CleanupLog @log 'User profile directory could not be resolved; user profile cleanup skipped.' -Severity Error
        if ($TranscriptPath) { Stop-Transcript | Out-Null }
        return
    }
    if ($IncludeMSTeamsCache) {
        Get-Process ms-teams -ErrorAction SilentlyContinue | Stop-Process -Force
    }

    # Relative paths may contain wildcards (eg. browser '\User Data\*\Cache'); expand to concrete folders.
    # The profile part is escaped, so a profile name with '[' or ']' is not read as a wildcard range.
    $clearMatching = {
        param($profilePath, $relativePaths)
        foreach ($relative in $relativePaths) {
            Get-Item -Path (Join-Path ([WildcardPattern]::Escape($profilePath)) $relative) -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
                Clear-FolderContentsReliable -Folder $_.FullName -BestEffort | Out-Null
                Write-CleanupLog @log "Cleared $($_.FullName)"
            }
        }
    }

    $excludedProfiles = "Public","Default","Default User","All Users"
    $userProfiles = Get-ChildItem -LiteralPath $Bases.Profiles -Directory -ErrorAction SilentlyContinue | Where-Object { $excludedProfiles -notcontains $_.Name }
    Write-CleanupLog @log "User profile cleanup ($($Bases.Profiles))"
    foreach ($userProfile in $userProfiles) {
        $profilePath = $userProfile.FullName
        Write-CleanupLog @log "Profile: $($userProfile.Name)"
        try{
            & $clearMatching $profilePath $userTempFolders
            if ($IncludeSystemLogs) {
                & $clearMatching $profilePath $userReportingDirs
            }
            if ($IncludeIconCache) {
                $path = Join-Path $profilePath $explorerCacheDir
                $pathLI = Join-Path $profilePath $localIconCacheDB
                $cacheFiles = @()
                if (Test-Path -LiteralPath $path) {
                    $escaped = [WildcardPattern]::Escape($path)
                    $cacheFiles += Get-ChildItem -Path "$escaped\iconcache*.db","$escaped\thumbcache*.db" -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
                }
                if (Test-Path -LiteralPath $pathLI) {
                    $cacheFiles += $pathLI
                }
                if ($cacheFiles) {
                    $inUse = @($cacheFiles | Where-Object { -not (Remove-PathReliable -Path $_ -BestEffort).Deleted })
                    $iconMsg = "Removed $($cacheFiles.Count - $inUse.Count) of $($cacheFiles.Count) icon/thumbnail cache files"
                    if ($inUse) { $iconMsg += "; skipped (in use):`r`n" + ($inUse -join "`r`n") }
                    Write-CleanupLog @log $iconMsg
                }
            }

            if($IncludeMSTeamsCache) {
                $path = Join-Path $profilePath $msTeamsCacheFolder
                $backgrounds = Join-Path $path "Microsoft\MSTeams\Backgrounds"
                # The backup lives outside LocalCache; one left over from an interrupted run is restored below too.
                $bgBackup = Join-Path (Split-Path $path) "Backgrounds.TempDataCleanup"
                $backedUp = $true
                if (Test-Path -LiteralPath $backgrounds) {
                    New-Item -Path $bgBackup -ItemType Directory -Force | Out-Null
                    Get-ChildItem -LiteralPath $backgrounds -Force | Move-Item -Destination $bgBackup -Force -ErrorAction SilentlyContinue
                    $backedUp = -not (Get-ChildItem -LiteralPath $backgrounds -Force -ErrorAction SilentlyContinue)
                }
                if (-not $backedUp) {
                    Write-CleanupLog @log "MS-Teams background images could not be backed up; $path left untouched" -Severity Warning
                } elseif (Test-Path -LiteralPath $path) {
                    Clear-FolderContentsReliable -Folder $path -BestEffort | Out-Null
                    Write-CleanupLog @log "Cleared $path"
                } else {
                    Write-CleanupLog @log "Not found: $path"
                }
                $toRestore = @(Get-ChildItem -LiteralPath $bgBackup -Force -ErrorAction SilentlyContinue)
                if ($toRestore) {
                    New-Item -Path $backgrounds -ItemType Directory -Force | Out-Null
                    $toRestore | Move-Item -Destination $backgrounds -Force -ErrorAction SilentlyContinue
                    if (Get-ChildItem -LiteralPath $bgBackup -Force -ErrorAction SilentlyContinue) {
                        Write-CleanupLog @log "Some MS-Teams background images could not be restored; they remain in $bgBackup" -Severity Warning
                    } else {
                        Write-CleanupLog @log "Restored MS-Teams background images"
                    }
                }
                if ((Test-Path -LiteralPath $bgBackup) -and -not (Get-ChildItem -LiteralPath $bgBackup -Force -ErrorAction SilentlyContinue)) {
                    Remove-Item -LiteralPath $bgBackup -Force -ErrorAction SilentlyContinue
                }

                $path = Join-Path $profilePath $teamsClassicPath
                if (Test-Path -LiteralPath $path) {
                    Clear-FolderContentsReliable -Folder $path -BestEffort | Out-Null
                    Write-CleanupLog @log "Cleared $path"
                } else {
                    Write-CleanupLog @log "Not found: $path"
                }
            }
        }catch{
            Write-CleanupLog @log "Error while cleaning up $($userProfile.Name): $_" -Severity Error
            Write-Warning "Error while cleaning up $($userProfile.Name) :`r`n $_"
        }
    }
    if ($TranscriptPath) { Stop-Transcript | Out-Null }
}

function Start-SystemCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$logfile,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases,

        [hashtable]$systemTempFolders,

        [hashtable]$sysReportingDirs,

        [switch]$IncludeSystemData,

        [switch]$IncludeSystemLogs,

        [string]$TranscriptPath
    )

    if ($TranscriptPath) { Start-Transcript -Path $TranscriptPath -Append | Out-Null }
    $log = @{ LogPath = $logfile; Component = 'SystemCleanup' }
    Write-CleanupLog @log 'System cleanup'

    # System temp/logs go through Remove-PathReliable (guarded, long-path safe) and are cleared
    # sequentially: locked items are scheduled for deletion at the next reboot, and every scheduling
    # write targets the single shared PendingFileRenameOperations value, so parallel writers would
    # clobber each other. Content caches (ccmcache/WU/Adaptiva/Intune) are handled by the separate
    # Invoke-ContentCacheCleanup step.
    # Targets map a base name to paths relative to it; a base that could not be resolved on this
    # machine skips its targets instead of building them from an empty value.
    $clearTargets = {
        param([hashtable]$targets)
        foreach ($baseName in $targets.Keys) {
            $base = $Bases[$baseName]
            foreach ($relative in $targets[$baseName]) {
                if (-not $base) {
                    Write-CleanupLog @log "Skipped <$baseName>\$relative ($baseName folder could not be resolved)" -Severity Warning
                    continue
                }
                $folder = Join-Path $base $relative
                if (-not (Test-Path -LiteralPath $folder)) {
                    Write-CleanupLog @log "Not found: $folder"
                } elseif (Clear-FolderContentsReliable -Folder $folder) {
                    Write-CleanupLog @log "Cleared $folder (locked items scheduled for deletion on reboot)"
                } else {
                    Write-CleanupLog @log "Cleared $folder"
                }
            }
        }
    }

    if($IncludeSystemData) {
        & $clearTargets $systemTempFolders
    }

    if($IncludeSystemLogs) {
        & $clearTargets $sysReportingDirs
    }

    if ($TranscriptPath) { Stop-Transcript | Out-Null }
}

function Invoke-NativeDiskCleanup {
    <#
    Stand-in for CleanMgr /sagerun where it cannot run (no interactive desktop, e.g. remote/WinRM):
    each selected Disk Cleanup option is mapped to an equivalent that works in session 0. Data-driven
    options are applied from their own VolumeCaches definition (Folder / FileList / LastAccess / Flags),
    a few others map to native commands, and options without a safe equivalent are logged as skipped.
    Locked files are left in place (as CleanMgr does). Self-contained apart from Write-CleanupLog,
    Remove-PathReliable and Clear-FolderContentsReliable, so it can be shipped to a remote session.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$logfile,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases,

        [Parameter(Mandatory=$true)]
        [string[]]$Options,

        [Parameter(Mandatory=$true)]
        [int]$MaxMinutes
    )
    $log = @{ LogPath = $logfile; Component = 'NativeCleanup' }
    $volumeCaches = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    $fixedDrives = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.Name.Substring(0, 2) })
    $profilePaths = @{
        "D3D Shader Cache"     = "AppData\Local\D3DSCache"
        "Internet Cache Files" = "AppData\Local\Microsoft\Windows\INetCache"
    }

    # Handler definitions store Flags/LastAccess as DWORD or as REG_BINARY ("2 0 0 0").
    $toUInt = {
        param($value)
        if ($null -eq $value) { return [uint32]0 }
        if ($value -is [byte[]]) { return [BitConverter]::ToUInt32([byte[]]($value + [byte[]](0,0,0,0)), 0) }
        [uint32]$value
    }

    # Mirrors DATACLEN: files matching FileList below each Folder ('?:' = every fixed drive), not
    # accessed for LastAccess days; flag 0x1 includes subfolders, 0x40 removes emptied subfolders.
    $clearDataDriven = {
        param($name, $definition)
        $flags    = & $toUInt $definition.Flags
        $days     = & $toUInt $definition.LastAccess
        $recurse  = [bool]($flags -band 0x1)
        $cutoff   = (Get-Date).AddDays(-$days)
        $patterns = @($definition.FileList -split '\|' | ForEach-Object { if ($_ -eq '*.*') { '*' } else { $_ } })
        $folders  = foreach ($folder in $definition.Folder -split '\|') {
            if ($folder.StartsWith('?:\')) { foreach ($drive in $fixedDrives) { $drive + $folder.Substring(2) } } else { $folder }
        }
        $removed = 0; $inUse = 0
        foreach ($folder in $folders) {
            $folder = $folder.TrimEnd('\')
            if (($folder -notmatch '^[A-Za-z]:\\[^\\]') -or -not (Test-Path -LiteralPath $folder -PathType Container)) { continue }
            Get-ChildItem -LiteralPath $folder -File -Force -Recurse:$recurse -ErrorAction SilentlyContinue |
                Where-Object { $file = $_; ($file.LastAccessTime -lt $cutoff) -and ($patterns | Where-Object { $file.Name -like $_ }) } |
                ForEach-Object { if ((Remove-PathReliable -Path $_.FullName -BestEffort).Deleted) { $removed++ } else { $inUse++ } }
            if ($recurse -and ($flags -band 0x40)) {
                Get-ChildItem -LiteralPath $folder -Directory -Recurse -Force -ErrorAction SilentlyContinue |
                    Sort-Object { $_.FullName.Length } -Descending |
                    Where-Object { -not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue) } |
                    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
            }
        }
        $msg = "${name}: removed $removed file(s)"
        if ($days) { $msg += " not accessed for $days day(s)" }
        if ($inUse) { $msg += "; $inUse in use, left in place" }
        Write-CleanupLog @log $msg
    }

    Write-CleanupLog @log ("No interactive session: CleanMgr cannot complete here, applying native equivalents for:`r`n" + ($Options -join "`r`n")) -Severity Warning
    foreach ($option in $Options) {
        $definition = Get-ItemProperty -Path "$volumeCaches\$option" -ErrorAction SilentlyContinue
        switch ($option) {
            { $definition.Folder -and $definition.FileList } {
                & $clearDataDriven $option $definition
                break
            }
            { $profilePaths.ContainsKey($_) } {
                if (-not $Bases.Profiles) {
                    Write-CleanupLog @log "${option}: skipped, user profile directory could not be resolved" -Severity Warning
                    break
                }
                $cleared = 0
                foreach ($userProfile in Get-ChildItem -LiteralPath $Bases.Profiles -Directory -ErrorAction SilentlyContinue) {
                    $folder = Join-Path $userProfile.FullName $profilePaths[$option]
                    if (Test-Path -LiteralPath $folder) {
                        Clear-FolderContentsReliable -Folder $folder -BestEffort | Out-Null
                        $cleared++
                    }
                }
                Write-CleanupLog @log "${option}: cleared in $cleared profile(s)"
                break
            }
            "Delivery Optimization Files" {
                if (-not (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue)) {
                    Write-CleanupLog @log "${option}: skipped, Delete-DeliveryOptimizationCache is not available" -Severity Warning
                    break
                }
                try {
                    Delete-DeliveryOptimizationCache -Force -ErrorAction Stop 6>$null | Out-Null
                    Write-CleanupLog @log "${option}: cache deleted"
                } catch {
                    Write-CleanupLog @log "${option}: $_" -Severity Warning
                }
            }
            "Update Cleanup" {
                $dism = Start-Process -FilePath (Join-Path $Bases.Windows "System32\Dism.exe") -ArgumentList '/Online','/Cleanup-Image','/StartComponentCleanup','/Quiet','/NoRestart' -WindowStyle Hidden -PassThru
                $null = $dism.Handle   # keeps ExitCode readable after exit
                if ($dism.WaitForExit($MaxMinutes * 60000)) {
                    $severity = if ($dism.ExitCode -eq 0) { 'Info' } else { 'Warning' }
                    Write-CleanupLog @log "${option}: DISM StartComponentCleanup finished, exit code $($dism.ExitCode)" -Severity $severity
                } else {
                    try { $dism.Kill() } catch { }
                    Write-CleanupLog @log "${option}: DISM StartComponentCleanup exceeded $MaxMinutes minutes and was stopped" -Severity Warning
                }
            }
            "Device Driver Packages" {
                # Older versions of the same third-party driver package; pnputil (without /force)
                # refuses any package still used by a device, so only unused ones are removed.
                try {
                    $stale = @(Get-WindowsDriver -Online -ErrorAction Stop |
                        Group-Object { '{0}|{1}|{2}' -f (Split-Path $_.OriginalFileName -Leaf), $_.ProviderName, $_.ClassName } |
                        Where-Object Count -gt 1 |
                        ForEach-Object { $_.Group | Sort-Object { try { [version]$_.Version } catch { [version]'0.0' } }, Date -Descending | Select-Object -Skip 1 })
                } catch {
                    Write-CleanupLog @log "${option}: driver list could not be read: $_" -Severity Warning
                    break
                }
                $pnputil = Join-Path $Bases.Windows "System32\pnputil.exe"
                $removed = 0; $inUse = 0
                foreach ($driver in $stale) {
                    & $pnputil /delete-driver $driver.Driver | Out-Null
                    if ($LASTEXITCODE -eq 0) { $removed++ } else { $inUse++ }
                }
                $msg = "${option}: removed $removed older driver package(s)"
                if ($inUse) { $msg += "; $inUse still in use, kept" }
                Write-CleanupLog @log $msg
            }
            "Thumbnail Cache" {
                Write-CleanupLog @log "${option}: covered by the user icon/thumbnail cache cleanup"
            }
            "Recycle Bin" {
                Write-CleanupLog @log "${option}: covered by the Recycle Bin step"
            }
            default {
                Write-CleanupLog @log "${option}: skipped, no native equivalent outside an interactive session"
            }
        }
    }
}

function Start-CleanMgr{
    param (
        [Parameter(Mandatory=$true)]
        [string]$logfile,

        [Parameter(Mandatory=$true)]
        [hashtable]$Bases,

        [switch]$LowDisk,

        [switch]$VeryLowDisk,

        [switch]$AutoClean
    )

    $log = @{ LogPath = $logfile; Component = 'CleanMgr' }

    # CleanMgr, the Windows Update/catroot2 backups and the Recycle Bin are all located from the
    # validated Windows directory; without it nothing in this step can be targeted safely.
    if (-not $Bases.Windows) {
        Write-CleanupLog @log "Windows directory could not be resolved; CleanMgr cleanup skipped." -Severity Error
        return
    }
    $cleanMgrExe = Join-Path $Bases.Windows "System32\cleanmgr.exe"

    $waitCleanMgr = {
        param($process, [int]$maxMinutes)
        if ($process.WaitForExit($maxMinutes * 60000)) { return }
        $cleanMgrStucknotify = "CleanMgr.exe has been running for more than $maxMinutes minutes. Stopping it..."
        Write-CleanupLog @log $cleanMgrStucknotify -Severity Warning
        Write-Warning $cleanMgrStucknotify
        try {
            $process.Kill()
            Write-CleanupLog @log "CleanMgr.exe terminated." -Severity Warning
            Write-Warning "CleanMgr.exe terminated."
        } catch {
            $cleanMgrStuckTerminateFail = "Failed to terminate CleanMgr.exe: $_"
            Write-CleanupLog @log $cleanMgrStuckTerminateFail -Severity Error
            Write-Warning $cleanMgrStuckTerminateFail
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

        if ($VeryLowDisk) {
            # Clears each user's bin below <SystemDrive>\$Recycle.Bin; the folder itself is kept.
            Write-CleanupLog @log "Cleaning Recycle Bin"
            Clear-FolderContentsReliable -Folder (Join-Path $Bases.SystemDrive '$Recycle.Bin') -BestEffort | Out-Null

            Write-CleanupLog @log "Cleaning SoftwareDistribution and catroot2 backup folders"
            foreach ($backup in "SoftwareDistribution.bak","SoftwareDistribution.old","System32\catroot2.bak","System32\catroot2.old") {
                $backupPath = Join-Path $Bases.Windows $backup
                if (-not (Test-Path -LiteralPath $backupPath)) { continue }
                $result = Remove-PathReliable -Path $backupPath -BestEffort
                if ($result.Deleted) { Write-CleanupLog @log "Removed $backupPath" }
                else { Write-CleanupLog @log "Could not fully remove $backupPath $($result.Error)" -Severity Warning }
            }
        }

        # CleanMgr /sagerun never completes without an interactive desktop (remote/WinRM, SYSTEM): it
        # waits behind hidden progress dialogs until killed. Those contexts get native equivalents.
        if (-not ([Environment]::UserInteractive -and (Get-Process -Id $PID).SessionId -ne 0)) {
            Write-Host "No interactive session, running native equivalents of the CleanMgr options..."
            Invoke-NativeDiskCleanup -logfile $logfile -Bases $Bases -Options $options -MaxMinutes $CleanMaxDurationVal
        } else {
            Write-CleanupLog @log ("Enabling CleanMgr cleanup options:`r`n" + ($options -join "`r`n"))
            foreach ($option in $options) {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$option" -Name StateFlags0901 -Value 2 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
            }

            Write-CleanupLog @log "Executing CleanMgr /sagerun:901 (up to $CleanMaxDurationVal minutes)"
            Write-Host "Starting CleanMgr.exe,`r`nThis may take a while... (up to $CleanMaxDurationVal minutes)"
            $process = Start-Process -FilePath $cleanMgrExe -ArgumentList '/sagerun:901' -PassThru
            & $waitCleanMgr $process $CleanMaxDurationVal
            # Bounded: leftover DismHost children of a killed CleanMgr (or unrelated servicing) must not block forever.
            Get-Process -Name cleanmgr,dismhost -ErrorAction SilentlyContinue | Wait-Process -Timeout 120 -ErrorAction SilentlyContinue
            Write-CleanupLog @log "CleanMgr complete, removing CleanMgr automation settings"
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags0901 -ErrorAction SilentlyContinue | Remove-ItemProperty -Name StateFlags0901 -ErrorAction SilentlyContinue | Out-Null
        }
    }

    if($AutoClean -or $VeryLowDisk){
        $CleanMaxDurationVal = 5
        Write-CleanupLog @log "Executing CleanMgr /autoclean upgrade cleanup (up to $CleanMaxDurationVal minutes)"
        Write-Host "Starting CleanMgr Upgrade-Cleanup,`r`nThis may take a while... (up to $CleanMaxDurationVal minutes)"
        $process = Start-Process -FilePath $cleanMgrExe -ArgumentList "/autoclean" -NoNewWindow -PassThru
        & $waitCleanMgr $process $CleanMaxDurationVal
        Write-CleanupLog @log "CleanMgr upgrade cleanup complete"
    }
}


function Invoke-DeviceCleanup {
    <#
    Runs the complete cleanup of one device and returns a result object (ComputerName, Status,
    Message, AdditionalFreeGB, TotalFreeGB). Called directly for a single device (its step output is
    shown), and as the body of one parallel job per device when several are given (step output is
    discarded there and only the result is reported). The worker parameter sets come prepared from
    Invoke-TempDataCleanup; this function adds the per-device log file, bases and transcript.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$ComputerName,

        [pscredential]$Credentials,

        [Parameter(Mandatory=$true)]
        [string]$TempFolder,

        [Parameter(Mandatory=$true)]
        [string]$LocalTargetPath,

        [Parameter(Mandatory=$true)]
        [string]$RunOptions,

        [Parameter(Mandatory=$true)]
        [hashtable]$UserParams,

        [hashtable]$SystemParams,

        [switch]$ContentCache,

        [hashtable]$CleanMgrParams,

        [switch]$Transcript
    )

    $comp = $ComputerName.Trim()
    $remote = -not ([string]::IsNullOrWhiteSpace($comp) -or $comp -eq "localhost" -or $comp -eq $env:COMPUTERNAME)
    if (-not $remote) { $comp = "localhost" }
    $result = [PSCustomObject]@{ ComputerName = $comp; Status = 'Failed'; Message = ''; AdditionalFreeGB = $null; TotalFreeGB = $null; LogFile = $null }

    if ($remote -and ($comp -notmatch '^(([a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$')) {
        $result.Message = "Invalid ComputerName format: '$comp' (letters, digits, '-', '_' and '.' only, or an IPv4 address)"
        return $result
    }

    $session = $null
    # Empty for the local device: Invoke-Command without a session then runs in-process.
    $invokeParams = @{}
    if ($remote) {
        # Opening the session is the reachability test: a ping can be blocked while WinRM is open.
        $sessionParams = @{ ComputerName = $comp; SessionOption = (New-PSSessionOption -OpenTimeout 30000) }
        if ($Credentials) {
            $sessionParams.Credential = $Credentials
        }
        try {
            $session = New-PSSession @sessionParams -ErrorAction Stop
        } catch {
            $result.Message = "Not reachable via PowerShell remoting (WinRM): " + ($_.Exception.Message -split '(?<=\.)\s+')[0]
            return $result
        }
        $invokeParams.Session = $session
    }

    try {
        # Every path on the target is built from bases resolved and validated there; without a system
        # drive there is nowhere safe to log to or clean from.
        $bases = Invoke-Command @invokeParams -ScriptBlock ${function:Get-CleanupBasePath}
        if (-not $bases.SystemDrive) {
            $result.Message = "The Windows directory could not be resolved; nothing was cleaned"
            return $result
        }

        # The device's own name (also for IP targets) keeps logs of different devices apart.
        $runStamp = "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')_$($bases.ComputerName)"
        $logdir = "$($bases.SystemDrive)\$TempFolder"
        $logfile = "$logdir\${runStamp}_TempDataCleanup.log"
        $VerboseLogFile = "$logdir\${runStamp}_TempDataCleanup_Verbose.log"
        # -Verbose records each step's console output in a transcript next to the log.
        $transcriptPath = if ($Transcript) { $VerboseLogFile } else { "" }
        $freeSpaceBlock = {
            param($drive)
            (Get-Volume -DriveLetter $drive[0]).SizeRemaining
        }

        $initFree_bytes = Invoke-Command @invokeParams -ScriptBlock $freeSpaceBlock -ArgumentList $bases.SystemDrive
        Invoke-Command @invokeParams -ScriptBlock ${function:New-Folder} -ArgumentList $logdir

        # Bundle each worker with the helpers it needs so they survive being shipped to a remote
        # session (module functions are otherwise undefined there). Locally, Invoke-Command without
        # a session runs the same block in-process, so every step takes a single code path.
        $deleteHelpers      = 'Write-CleanupLog','Remove-PathReliable','Register-PendingDelete','Clear-FolderContentsReliable'
        $logBlock           = New-RemoteFunctionScriptBlock -FunctionName 'Write-CleanupLog' -EntryPoint 'Write-CleanupLog'
        $userCleanupBlock   = New-RemoteFunctionScriptBlock -FunctionName ($deleteHelpers + 'Start-UserCleanup') -EntryPoint 'Start-UserCleanup'
        $systemCleanupBlock = New-RemoteFunctionScriptBlock -FunctionName ($deleteHelpers + 'Start-SystemCleanup') -EntryPoint 'Start-SystemCleanup'
        $cacheCleanupBlock  = New-RemoteFunctionScriptBlock -FunctionName ($deleteHelpers + 'Invoke-ContentCacheCleanup') -EntryPoint 'Invoke-ContentCacheCleanup'
        $cleanMgrBlock      = New-RemoteFunctionScriptBlock -FunctionName ($deleteHelpers + 'Invoke-NativeDiskCleanup','Start-CleanMgr') -EntryPoint 'Start-CleanMgr'
        # A dropped remote session only produces non-terminating errors; stop the device run instead of
        # carrying on and reporting a bogus 'Completed'.
        $assertSession = {
            if ($session -and $session.State -ne 'Opened') { throw "Connection to $comp was lost during the cleanup (session state: $($session.State))" }
        }

        $runInfo = "Starting cleanup on $comp ($($bases.ComputerName))`r`n$RunOptions`r`n" +
            "Windows: $($bases.Windows); ProgramData: $($bases.ProgramData); Profiles: $($bases.Profiles)"
        Invoke-Command @invokeParams -ScriptBlock $logBlock -ArgumentList @{ Message = $runInfo; Component = 'TempDataCleanup'; LogPath = $logfile }

        Write-Host "`r`nCleaning up  $comp`r`n"
        $common = @{ logfile = $logfile; Bases = $bases }

        # Steps run one after another: locked system/cache items are scheduled for reboot through the
        # single shared PendingFileRenameOperations value, so overlapping steps would clobber it.
        Write-Host "Cleaning up User Data and Cache"
        $null = Invoke-Command @invokeParams -ScriptBlock $userCleanupBlock -ArgumentList ($UserParams + $common + @{ TranscriptPath = $transcriptPath })
        & $assertSession

        if ($SystemParams) {
            Write-Host "Cleaning up System Data"
            $null = Invoke-Command @invokeParams -ScriptBlock $systemCleanupBlock -ArgumentList ($SystemParams + $common + @{ TranscriptPath = $transcriptPath })
            & $assertSession
        }

        if ($ContentCache) {
            Write-Host "Cleaning up Content Caches (ConfigMgr / Windows Update / Adaptiva / Intune)"
            $null = Invoke-Command @invokeParams -ScriptBlock $cacheCleanupBlock -ArgumentList @{ logfile = $logfile; TranscriptPath = $transcriptPath }
            & $assertSession
        }

        if ($CleanMgrParams) {
            $null = Invoke-Command @invokeParams -ScriptBlock $cleanMgrBlock -ArgumentList ($CleanMgrParams + $common)
            & $assertSession
        }

        Invoke-Command @invokeParams -ScriptBlock $logBlock -ArgumentList @{ Message = "Cleanup on $comp finished"; Component = 'TempDataCleanup'; LogPath = $logfile }
        $result.LogFile = $logfile

        if ($remote) {
            $localTarget = Join-Path $LocalTargetPath $comp
            New-Folder -FolderPath $localTarget

            # Only this run's own files are removed; the temp folder may be in use by other tools.
            $runFiles = Invoke-Command @invokeParams -ScriptBlock {
                param($files)
                $files | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
            } -ArgumentList (,@($logfile, $VerboseLogFile))
            $notCopied = foreach ($file in $runFiles) {
                try {
                    Copy-Item -LiteralPath $file -Destination $localTarget -FromSession $session -Force -ErrorAction Stop
                    Invoke-Command @invokeParams -ScriptBlock { param($f) Remove-Item -LiteralPath $f -Force } -ArgumentList $file
                } catch {
                    $file
                }
            }
            if ($notCopied -contains $logfile) {
                $result.Message = "Log could not be copied and was left on the device: $($notCopied -join ', ')"
            } else {
                $result.LogFile = Join-Path $localTarget (Split-Path $logfile -Leaf)
                if ($notCopied) { $result.Message = "Log could not be copied and was left on the device: $($notCopied -join ', ')" }
            }
        }

        $exitFree_bytes = Invoke-Command @invokeParams -ScriptBlock $freeSpaceBlock -ArgumentList $bases.SystemDrive
        if ($null -ne $exitFree_bytes) {
            $result.TotalFreeGB = $exitFree_bytes / 1GB
            if ($null -ne $initFree_bytes) { $result.AdditionalFreeGB = ($exitFree_bytes - $initFree_bytes) / 1GB }
        }
        if ($null -eq $result.AdditionalFreeGB) {
            $result.Message = (@($result.Message, "Free space of $($bases.SystemDrive) could not be read") | Where-Object { $_ }) -join '; '
        }
        $result.Status = 'Completed'
        return $result
    } catch {
        $result.Message = if ($session -and $session.State -ne 'Opened') { "Connection to $comp was lost during the cleanup" } else { "Cleanup aborted: $($_.Exception.Message)" }
        if ($remote -and $logfile) {
            $result.LogFile = $logfile
            $result.Message += "; the log was left on the device: $logfile"
        }
        return $result
    } finally {
        if ($session) { Remove-PSSession -Session $session }
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
    - System folders (-IncludeSystemData / -IncludeSystemLogs) and the content caches (-ContentCacheCleanup)
      schedule any still-locked item for deletion on the next reboot, so a restart is required to finish
      clearing those.

    .PARAMETER ComputerName
    The name of the computer to run the cleanup on. Use "localhost" for the local computer.
    Accepts multiple computer names as an array. Accepts pipeline input.
    If no computer name is provided, it defaults to "localhost".
    With more than one computer, every device is cleaned in its own parallel background job. No
    step output is shown then; each device prints a single line (name, additional and total free
    space, or the reason it failed) as soon as it has finished. Duplicates and local aliases ("",
    "localhost", the own computer name) are cleaned only once.

    .PARAMETER IncludeSystemData
    If this switch is present, the cleanup will also include system folders such as the Windows Temp,
    Prefetch, and SoftwareDistribution\Download folders.

    .PARAMETER IncludeSystemLogs
    If this switch is present, the cleanup will also include system log files and reporting folders such
    as C:\Windows\Logs, C:\Windows\Minidump, and the Windows Error Reporting queues. Logs held open by
    Windows services are scheduled for deletion on the next reboot.

    .PARAMETER ContentCacheCleanup
    Alias: -IncludeCCMCache (kept for backwards compatibility).
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
    If this switch is present, the cleanup will also include browser cache folders (Edge, Chrome,
    Firefox, Opera, Vivaldi, Brave, IE). Saved site data - Firefox site storage (offline data and local
    storage of web apps) and Internet Explorer cookies - is only cleared after confirming a prompt, or
    with -ConfirmWarning.

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
    -IncludeSystemData, -ContentCacheCleanup, -IncludeIconCache

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
    -IncludeSystemData, -ContentCacheCleanup, -IncludeIconCache

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

    CleanMgr only completes in an interactive desktop session. Without one (remote/WinRM runs, SYSTEM)
    -LowDisk and -VeryLowDisk apply native equivalents of the selected CleanMgr options instead: the
    file-based options are applied from their own Windows definition (eg. Temporary Files older than
    7 days), Delivery Optimization via Delete-DeliveryOptimizationCache, Update Cleanup via DISM
    /StartComponentCleanup, and Device Driver Packages by removing older, unused driver versions.
    Options without a native equivalent (Windows setup/upgrade leftovers, legacy IE/ActiveX caches)
    are skipped and logged.

    .PARAMETER ConfirmWarning
    Using this switch will bypass the confirmation prompts of -VeryLowDisk, -IncludeAllPackages and the
    browser site data of -IncludeBrowserData (all answered with yes) and proceed with the cleanup (for unattended runs).

    .PARAMETER AutoClean
    Automatically deletes the files that are left behind after you upgrade Windows. This can be used with all other Switches.
    Using this Switch will also set the following switches:
    -IncludeSystemData, -ContentCacheCleanup, -IncludeIconCache

    .PARAMETER init
    When specified, the Config-File will be Written to the Module-Root-Directory. This will NOT overwrite an existing Config-File.
    When specified, no other Parameter will be executed (other provided Parameters will be ignored). This will retun 0 if the Config-File was created successfully, or already exists.

    Configuration-File Template:
    ```
    TempFolder=_IT-temp                         # Name of the temporary Directory on the target device (below its system drive)
    LocalTargetPath=C:\remote-Files             # Path where the Logs and Files will be copied to on the executing Client
    ```
    Blank lines and '#' comments are ignored. An older 'ShareDrive=' entry is still accepted but no longer used.

    .PARAMETER ThrottleLimit
    Maximum number of devices cleaned at the same time when more than one computer is given (1-100,
    default 10). Each running device uses its own background PowerShell process; further devices
    start as soon as a running one has finished.

    .PARAMETER DeviceTimeoutMinutes
    With more than one computer: maximum run time per device (5-1440 minutes, default 90). A device
    still running after that is stopped and reported as failed. Not applied to a single device.

    .PARAMETER Quiet
    Suppresses all console output (progress, summary lines, warnings); only errors and the returned
    result objects remain, eg. for scheduled or scripted runs. Confirmation prompts are still shown,
    use -ConfirmWarning to bypass them.

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
    Invoke-TempDataCleanup -ComputerName "Computer01" -IncludeSystemData -IncludeSystemLogs -ContentCacheCleanup

    This will clean up user and system temp, system logs, and the software-distribution content caches
    (ConfigMgr/SCCM ccmcache, Windows Update, Adaptiva, Intune) on Computer01. The ConfigMgr cache is
    located dynamically, so a relocated cache is still found. Locked system/cache items are scheduled for
    deletion on the next reboot - restart Computer01 to finish.

    .EXAMPLE
    $results = Invoke-TempDataCleanup -ComputerName (Get-Content .\devices.txt) -IncludeSystemData -ThrottleLimit 20
    $results | Where-Object Status -eq 'Failed' | Select-Object ComputerName, Message | Export-Csv .\failed.csv -NoTypeInformation

    Cleans all devices listed in devices.txt, 20 at a time, and exports the devices that failed with their reason.

    .INPUTS
    [string[]]$ComputerName - Accepts pipeline input of Multiple Computer Names.

    .OUTPUTS
    TempDataCleanup.Result - one object per device, returned after all devices have finished:
    ComputerName, Status ('Completed' / 'Failed'), AdditionalFreeGB, TotalFreeGB, Message (failure
    reason or note) and LogFile (the copied log for remote devices, else the log on the device).
    The console shows ComputerName, Status, AdditionalFreeGB and TotalFreeGB by default.

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
    -IncludeSystemLogs) and the content caches (-ContentCacheCleanup) are scheduled for deletion on the next
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
    Date: 2026-10-02
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
        [Alias('IncludeCCMCache')]
        [switch]$ContentCacheCleanup,

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
        [pscredential]$Credentials,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 100)]
        [int]$ThrottleLimit = 10,

        [Parameter(Mandatory=$false)]
        [ValidateRange(5, 1440)]
        [int]$DeviceTimeoutMinutes = 90,

        [Parameter(Mandatory=$false)]
        [switch]$Quiet

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
        # -Quiet: run the same cleanup once more with host messages and warnings redirected away,
        # so every step (local, remote or job) stays silent; errors and the result objects remain.
        if ($Quiet) {
            $forward = @{}
            foreach ($key in $PSBoundParameters.Keys) { $forward[$key] = $PSBoundParameters[$key] }
            $forward.Remove('Quiet')
            $forward.Remove('ComputerName')
            if ($computerList.Count -gt 0) { $forward.ComputerName = $computerList }
            # Errors are re-raised from this call so they point at the caller's command line.
            Invoke-TempDataCleanup @forward 6>$null 3>$null 2>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) {
                    $PSCmdlet.WriteError((New-Object System.Management.Automation.ErrorRecord $_.Exception, $_.FullyQualifiedErrorId, $_.CategoryInfo.Category, $_.TargetObject))
                } else {
                    $_
                }
            }
            return
        }

        if ($computerList.Count -eq 0) {
            $computerList = @("localhost")
        }

        $confFile="$PSScriptRoot\TempDataCleanup.conf"
        if($init){
            if(-not (Test-Path $confFile)){
                try {
                    Set-Content -Path $confFile -Value "TempFolder=_IT-temp","LocalTargetPath=C:\remote-Files" -ErrorAction Stop
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
        # Only plain temp/installer caches; apps that keep user data in LocalCache (Outlook, Photos,
        # Snipping Tool, Camera, ...) are left alone unless -IncludeAllPackages is used.
        $commonUserPackages=@(
            "\AppData\Local\Packages\Microsoft.DiagnosticDataViewer_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalCache",
            "\AppData\Local\Packages\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe\TempState",
            "\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TempState"
        )
        $allPackagesCacheFolder="\AppData\Local\Packages\*\LocalCache"
        # Saved site data rather than cache (web-app offline data, IndexedDB/localStorage, cookies):
        # only cleared after an explicit yes (or -ConfirmWarning).
        $BrowserSiteData=@(
            "\AppData\Local\Microsoft\Windows\INetCookies",
            "\AppData\Local\Mozilla\Firefox\Profiles\*\storage\default"
        )
        $BrowserData=@(
            # general
            "\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData",
            # Microsoft Internet Explorer
            "\AppData\Local\Microsoft\Windows\INetCache",
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


        # System targets are relative to base folders resolved and validated on the target device
        # (Get-CleanupBasePath), never to hard-coded drive letters.
        $systemTempFolders=@{
            Windows = @(
                "Temp",
                "Prefetch",
                "SoftwareDistribution\Download"
            )
        }
        $msTeamsCacheFolder="\AppData\local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache"
        $teamsClassicPath="\AppData\Roaming\Microsoft\Teams"

        $userReportingDirs=@(
            "\AppData\Local\CrashDumps",
            "\Appdata\Local\D3DSCache",
            "\AppData\Local\Microsoft\Windows\WER\ReportQueue",
            "\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
        )

        $sysReportingDirs=@{
            Windows = @(
                "Logs",
                "Minidump",
                "LiveKernelReports",
                "System32\LogFiles\WMI",
                "System32\LogFiles\setupcln",
                "ServiceProfiles\LocalService\AppData\Local\CrashDumps",
                "SysWOW64\config\systemprofile\AppData\Local\CrashDumps",
                "System32\config\systemprofile\AppData\Local\CrashDumps",
                "ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
            )
            ProgramData = @(
                "Microsoft\Windows\WER\ReportQueue",
                "Microsoft\Windows\WER\ReportArchive"
            )
        }

        $LocalTargetPath = "C:\remote-Files"
        $TempFolder="_IT-temp"

        if(Test-Path $confFile){
            # Blank lines, '#' comment lines and trailing ' # comments' are ignored.
            foreach ($line in Get-Content -Path $confFile) {
                $line = ($line -replace '(^|\s)#.*$', '').Trim()
                if (-not $line) { continue }
                $key, $value = $line -split '=', 2
                switch ($key.Trim()) {
                    "TempFolder"      { $TempFolder = "$value".Trim() }
                    "LocalTargetPath" { $LocalTargetPath = "$value".Trim() }
                    "ShareDrive"      { }   # no longer used; accepted so older Config-Files keep working
                    default {
                        Write-Error "Unknown Key in Config-File '$confFile': $key"
                        $global:LASTEXITCODE = 1
                        return
                    }
                }
            }
        }
        # TempFolder becomes <SystemDrive>\<TempFolder> on the target, so it must be a single plain folder name.
        if (($TempFolder -notmatch '^[^\\/:*?"<>|]+$') -or ($TempFolder -match '^\.+$')) {
            Write-Error "Invalid TempFolder '$TempFolder' in Config-File: a single folder name is required."
            $global:LASTEXITCODE = 1
            return
        }


        # A local target needs an elevated session; checked before anything is cleaned anywhere.
        $hasLocalTarget = @($computerList | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_.Trim() -eq "localhost" -or $_.Trim() -eq $env:COMPUTERNAME }).Count -gt 0
        if ($hasLocalTarget) {
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Write-Error "Cleaning the local computer requires administrative privileges. Please restart in an elevated PowerShell session. Nothing was cleaned."
                $global:LASTEXITCODE = 1
                return
            }
        }

        # Asked once for the whole run, before any computer is touched.
        if ($VeryLowDisk -and -not $ConfirmWarning) {
            $answer = $null
            for ($i = 0; ($i -lt 3) -and ($answer -notin 'y','n','exit'); $i++) {
                $answer = "$(Read-Host "VeryLowDisk cleanup is selected. This will clean up the system including critical recovery-Files and remove all files in the Recycle Bin. (Selecting N will revert to -LowDisk)`r`nDo you want to continue? ([Y]es/[N]o/exit)")".Trim().ToLower()
            }
            if ($answer -eq 'n') {
                $VeryLowDisk = $false
                $LowDisk = $true
                Write-Host "VeryLowDisk declined, reverting to LowDisk"
            } elseif ($answer -ne 'y') {
                Write-Host "Exiting script."
                $global:LASTEXITCODE = 1
                return
            }
        }

        if($LowDisk -or $VeryLowDisk -or $AutoClean){
            $IncludeSystemData=$true
            $ContentCacheCleanup=$true
            $IncludeIconCache=$true
        }

        $IncludeBrowserSiteData = $false
        if ($IncludeBrowserData) {
            if ($ConfirmWarning) {
                $IncludeBrowserSiteData = $true
            } else {
                $confirmation = Read-Host "IncludeBrowserData can also clear saved site data: Firefox site storage (offline data and local storage of web apps) and Internet Explorer cookies.`r`nInclude saved site data? (enter [yes] to include; anything else clears browser caches only)"
                $IncludeBrowserSiteData = $confirmation -eq "yes"
            }
            Write-Host "Browser cleanup: caches$(if ($IncludeBrowserSiteData) { ' and saved site data' } else { ' only' })"
        }

        if($IncludeAllPackages -and -not $ConfirmWarning){
            $confirmation=Read-Host "Are you sure you want to include ALL Packages in the cleanup?`r`nThis will render IncludeMSTeamsCache irrelevant. Do you want to continue?`r`n(enter [yes] to continue with this option)"
            if($confirmation -ne "yes"){
                $IncludeAllPackages=$false
                Write-Host "Cleanup will not use IncludeAllPackages"
            }
        }
        if($IncludeAllPackages){
            $IncludeMSTeamsCache=$false
            Write-Host "Cleanup will use IncludeAllPackages"
        }

        if ($IncludeAllPackages){$userTempFolders=$userTempFolders+$allPackagesCacheFolder}else{$userTempFolders=$userTempFolders+$commonUserPackages}
        if ($IncludeBrowserData){$userTempFolders=$userTempFolders+$BrowserData}
        if ($IncludeBrowserSiteData){$userTempFolders=$userTempFolders+$BrowserSiteData}


        # One entry per device: every local alias becomes 'localhost', duplicates are dropped, so the
        # same machine is never cleaned by two parallel jobs at once.
        $targets = New-Object System.Collections.Generic.List[string]
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($comp in $computerList) {
            $comp = "$comp".Trim()
            if ([string]::IsNullOrWhiteSpace($comp) -or $comp -eq $env:COMPUTERNAME) { $comp = "localhost" }
            if ($seen.Add($comp)) { $targets.Add($comp) }
        }

        $deviceParams = @{
            TempFolder      = $TempFolder
            LocalTargetPath = $LocalTargetPath
            Transcript      = ($VerbosePreference -eq 'Continue')
            ContentCache    = [bool]$ContentCacheCleanup
            RunOptions      = "SystemData: $IncludeSystemData; SystemLogs: $IncludeSystemLogs; ContentCache: $ContentCacheCleanup; BrowserData: $IncludeBrowserData; BrowserSiteData: $IncludeBrowserSiteData; " +
                              "MSTeamsCache: $IncludeMSTeamsCache; IconCache: $IncludeIconCache; AllPackages: $IncludeAllPackages; " +
                              "LowDisk: $LowDisk; VeryLowDisk: $VeryLowDisk; AutoClean: $AutoClean"
            UserParams      = @{
                userTempFolders     = $userTempFolders
                userReportingDirs   = $userReportingDirs
                explorerCacheDir    = $explorerCacheDir
                localIconCacheDB    = $localIconCacheDB
                msTeamsCacheFolder  = $msTeamsCacheFolder
                teamsClassicPath    = $teamsClassicPath
                IncludeSystemLogs   = [bool]$IncludeSystemLogs
                IncludeIconCache    = [bool]$IncludeIconCache
                IncludeMSTeamsCache = [bool]$IncludeMSTeamsCache
            }
        }
        if ($Credentials) { $deviceParams.Credentials = $Credentials }
        if ($IncludeSystemData -or $IncludeSystemLogs) {
            $deviceParams.SystemParams = @{
                systemTempFolders = $systemTempFolders
                sysReportingDirs  = $sysReportingDirs
                IncludeSystemData = [bool]$IncludeSystemData
                IncludeSystemLogs = [bool]$IncludeSystemLogs
            }
        }
        if ($LowDisk -or $VeryLowDisk -or $AutoClean) {
            $deviceParams.CleanMgrParams = @{ LowDisk = [bool]$LowDisk; VeryLowDisk = [bool]$VeryLowDisk; AutoClean = [bool]$AutoClean }
        }

        # Prints the device's summary line and keeps a clean result object (job results arrive
        # deserialized) for the function's output; the table view shows the four key columns.
        $results = New-Object System.Collections.Generic.List[object]
        $displaySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]('ComputerName','Status','AdditionalFreeGB','TotalFreeGB'))
        $report = {
            param($result)
            if ($result.Status -eq 'Completed') {
                $gb = { param($v) if ($null -ne $v) { "{0:N2} GB" -f $v } else { "n/a" } }
                $line = "[{0}] Cleanup complete - Additional free space: {1}, Total free space: {2}" -f $result.ComputerName, (& $gb $result.AdditionalFreeGB), (& $gb $result.TotalFreeGB)
                Write-Host $line -ForegroundColor Green
                if ($result.Message) { Write-Warning "[$($result.ComputerName)] $($result.Message)" }
            } else {
                Write-Warning "[$($result.ComputerName)] Cleanup failed - $($result.Message)"
            }
            $clean = [PSCustomObject]@{
                PSTypeName       = 'TempDataCleanup.Result'
                ComputerName     = $result.ComputerName
                Status           = $result.Status
                AdditionalFreeGB = if ($null -ne $result.AdditionalFreeGB) { [math]::Round($result.AdditionalFreeGB, 2) } else { $null }
                TotalFreeGB      = if ($null -ne $result.TotalFreeGB) { [math]::Round($result.TotalFreeGB, 2) } else { $null }
                Message          = $result.Message
                LogFile          = $result.LogFile
            }
            $clean | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value ([System.Management.Automation.PSMemberInfo[]]@($displaySet))
            $results.Add($clean)
        }

        if ($targets.Count -eq 1) {
            & $report (Invoke-DeviceCleanup -ComputerName $targets[0] @deviceParams)
            if ($results[0].Status -eq 'Completed' -and $results[0].LogFile) { Write-Host "Log file: $($results[0].LogFile)" }
        } else {
            # One background job per device, at most -ThrottleLimit at a time; their step output is
            # discarded and each device reports a single result line as soon as it has finished.
            $deviceBlock = New-RemoteFunctionScriptBlock -EntryPoint 'Invoke-DeviceCleanup' -FunctionName @(
                'New-Folder','Write-CleanupLog','Get-CleanupBasePath','Remove-PathReliable','Register-PendingDelete',
                'Clear-FolderContentsReliable','New-RemoteFunctionScriptBlock','Invoke-ContentCacheCleanup','Start-UserCleanup',
                'Start-SystemCleanup','Invoke-NativeDiskCleanup','Start-CleanMgr','Invoke-DeviceCleanup')
            $queue = New-Object System.Collections.Generic.Queue[string] (,[string[]]$targets)
            $pending = New-Object System.Collections.Generic.List[object]
            $jobTarget = @{}
            $jobStart = @{}
            $startJobs = {
                while (($pending.Count -lt $ThrottleLimit) -and ($queue.Count -gt 0)) {
                    $comp = $queue.Dequeue()
                    $job = Start-Job -Name "TempDataCleanup_$comp" -ScriptBlock $deviceBlock -ArgumentList ($deviceParams + @{ ComputerName = $comp })
                    $jobTarget[$job.Id] = $comp
                    $jobStart[$job.Id] = Get-Date
                    $pending.Add($job)
                }
            }
            Write-Host "Cleaning up $($targets.Count) devices in parallel (up to $ThrottleLimit at a time): $($targets -join ', ')"
            if (@($targets | Where-Object { $_ -ne 'localhost' }).Count -gt 0) {
                Write-Host "Logs will be located in their device folders in $LocalTargetPath\<ComputerName>"
            }
            if ($targets.Contains('localhost')) {
                $localDrive = Split-Path ([Environment]::GetFolderPath('Windows')) -Qualifier
                Write-Host "The log of the local computer stays in $localDrive\$TempFolder"
            }
            Write-Host "Each device reports when it has finished...`r`n"
            try {
                & $startJobs
                while ($pending.Count -gt 0) {
                    # Wake up at least every 30 s so a device exceeding -DeviceTimeoutMinutes is stopped.
                    $null = Wait-Job -Job $pending.ToArray() -Any -Timeout 30
                    $timedOut = @($pending | Where-Object { $_.State -eq 'Running' -and ((Get-Date) - $jobStart[$_.Id]).TotalMinutes -ge $DeviceTimeoutMinutes })
                    foreach ($job in $timedOut) { Stop-Job -Job $job }
                    foreach ($job in @($pending | Where-Object { $_.State -notin 'Running','NotStarted' })) {
                        # Read the result straight from the job's output: Receive-Job would replay the
                        # device's step output (Write-Host) to the console.
                        # A stopped job may still have emitted a result for its interrupted run; the timeout wins.
                        $result = if ($timedOut -notcontains $job) { $job.ChildJobs[0].Output | Where-Object { $_.PSObject.Properties['Status'] } | Select-Object -Last 1 }
                        if (-not $result) {
                            $reason = if ($timedOut -contains $job) { "Timed out after $DeviceTimeoutMinutes minutes and was stopped" }
                                      elseif ($job.JobStateInfo.Reason) { $job.JobStateInfo.Reason.Message }
                                      else { "no result returned (job state: $($job.State))" }
                            $result = [PSCustomObject]@{ ComputerName = $jobTarget[$job.Id]; Status = 'Failed'; Message = $reason }
                        }
                        & $report $result
                        Remove-Job -Job $job -Force
                        [void]$pending.Remove($job)
                    }
                    & $startJobs
                }
            } finally {
                # Reached early only on Ctrl+C: don't leave cleanup jobs running in the background.
                foreach ($job in $pending) { Stop-Job -Job $job; Remove-Job -Job $job -Force }
            }
        }
        Write-Host "`r`nCleanUp Complete" -ForegroundColor Green
        Write-Host "Please Restart the Computer to finalize the Cleanup!" -ForegroundColor Yellow
        $results
    }
}

Export-ModuleMember -Function Invoke-TempDataCleanup

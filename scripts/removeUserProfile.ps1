<#
.SYNOPSIS
    Removes Windows user profiles, after backing up their registry entries, mapped
    network drives and printer connections.

.DESCRIPTION
    Lists the user profiles on this computer and removes the selected ones. System
    profiles (Win32_UserProfile.Special) are never listed. Folders under the profiles
    directory without any profile registration (orphaned folders) are listed too.

    For every selected profile, in order:

      1. Re-reads the profile and skips it if its path is not directly below the
         profiles directory, or if any process runs as the user (signed in, or a
         service/task using the account).
      2. Backs up the profile's registry keys (ProfileList, including a .bak key,
         and ProfileGuid), the mapped network drives as a re-mapping .cmd file and
         the printer connections as a list. Nothing is changed if a backup fails.
      3. Releases the user hive if this script mounted it to read the backups.
      4. Rename (default): renames the folder to <User>-<Date>.old, then removes the
         profile registration through Win32_UserProfile.
         Delete (-Delete): removes the profile through Win32_UserProfile, which
         deletes registration and folder, then removes whatever the folder still
         contains.

    Whatever cannot be done right now - the hive is held by Windows, the folder is
    locked, or locked files survive the deletion - is finished during a restart:
    the folder is renamed at boot before any service starts (to <User>-<Date>.old,
    or to <User>-<Date>.pending-delete for deletion), and a one-shot SYSTEM task
    completes the rest and removes itself. Its entries are written into the log of
    the run that scheduled them, marked with a 'Deferred-' component; if that log no
    longer exists, a <log>_Deferred.log is created next to it.

    Logs and backups go to C:\_IT-ProfileCleanup\<Timestamp>_ProfileCleanup\, one
    subfolder per profile. The log is CMTrace-compatible.

.PARAMETER UserName
    Profile folder name(s) to remove. If omitted, the profiles are listed with a
    number and the selection is prompted for: numbers, ranges and usernames,
    comma separated (e.g. 1,3-5,jdoe).

.PARAMETER Delete
    Permanently deletes the profile folders instead of renaming them to .old.
    Alias: -DeleteProfile

.PARAMETER NoRestart
    Does not offer a restart when work was deferred to the next restart. The
    deferred work still runs at the next regular restart. Takes precedence over
    -ForceRestart if both are supplied.

.PARAMETER ForceRestart
    Restarts the computer 60 seconds after the run without asking when work was
    deferred. Without it, the users signed in to the computer are listed and the
    restart is prompted for.

.EXAMPLE
    PS> .\removeUserProfile.ps1

    Lists the profiles, prompts for the selection (e.g. 2,4-6) and renames the
    selected profile folders to <User>-<Date>.old.

.EXAMPLE
    PS> .\removeUserProfile.ps1 -UserName jdoe, mmuster -Delete

    Permanently deletes the profiles of jdoe and mmuster.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    None. Progress is written to the host, details to the log. Exit codes:

        0     All selected profiles were removed, or nothing was selected
        1     Not elevated, the log folder could not be created, or at least one
              profile failed
        3010  Done so far; a restart finishes the deferred work

.NOTES
    Author:   Halatschek Wolfram
    Date:     2026-10-06
    Version:  1.2
    Requires: Administrative privileges, Windows PowerShell 5.1 or later.

    Credits:  Profile discovery and deletion through Win32_UserProfile, the safety
              checks around it and the multi-profile selection are based on a
              profile cleanup script by Dumpweed-Git (https://github.com/dumpweed-git).

    Warning:  This script removes user profiles. Use with caution.

        !!    The Author of this script is not responsible for any data loss or
              system damage caused by the use of this script. Use at your own risk.

              If any errors occur that you wish to report to the Author, please
              open an issue on https://github.com/halatsWol/PowerShell-Tools

.LINK
    https://github.com/halatsWol/PowerShell-Tools

.LINK
    https://github.com/dumpweed-git
#>

[CmdletBinding()]
param(
    [string[]]$UserName,

    [Alias('DeleteProfile')]
    [switch]$Delete,

    [switch]$NoRestart,

    [switch]$ForceRestart,

    # Set by the startup task that finishes deferred work.
    [Parameter(DontShow)]
    [switch]$Deferred
)

$script:BaseDir         = "$env:SystemDrive\_IT-ProfileCleanup"
$script:WorkDir         = "$env:ProgramData\ProfileCleanup-Deferred"
$script:StateKey        = 'HKLM\SOFTWARE\PowerShell-Tools\removeUserProfile'
$script:TaskName        = 'removeUserProfile-DeferredCleanup'
$script:ProfileListKey  = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$script:ProfileGuidKey  = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid'
$script:LogFile         = $null
$script:ComponentPrefix = ''

$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    Write-Host ''
    Write-Warning "This script must be run with administrative privileges. Please restart the script in an elevated PowerShell session."
    Pause
    exit 1
}

if ($ForceRestart -and $NoRestart) {
    Write-Warning "-ForceRestart and -NoRestart were both specified; -NoRestart wins and the computer will not be restarted."
    $ForceRestart = $false
}

#region Logging

function Write-CMTraceLog {
    <#
    Appends one CMTrace-format entry. Identical in TempDataCleanup, Repair-System, removeUserProfile and
    AutoDeskCleanRemove; anything tool-specific lives in wrappers that call this. A multi-line message
    stays a single entry, and CMTrace delimiters inside it are escaped so an embedded log cannot split
    it. A briefly locked file (open viewer, AV scan) is retried and the function never throws - a lost
    log line must not abort the caller. Wrappers pass their own $MyInvocation as -Caller, so file= names
    the real call site. Self-contained so it survives being shipped to a remote session or script.
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
        [string]$Severity = 'Info',

        [System.Management.Automation.InvocationInfo]$Caller
    )
    if (-not $Caller) { $Caller = $MyInvocation }
    $type    = @{ Info = 1; Warning = 2; Error = 3 }[$Severity]
    $now     = Get-Date
    $offset  = [TimeZoneInfo]::Local.GetUtcOffset($now).TotalMinutes
    $source  = if ($Caller.ScriptName) { Split-Path -Path $Caller.ScriptName -Leaf } else {
        # Shipped scriptblock without a file: name the nearest named function that made the call.
        $stack = @(Get-PSCallStack)
        $i = 0
        while ($i -lt $stack.Count -and -not [object]::ReferenceEquals($stack[$i].InvocationInfo, $Caller)) { $i++ }
        $named = @($stack | Select-Object -Skip ($i + 1) | Where-Object { $_.FunctionName -ne '<ScriptBlock>' })
        if ($named.Count -gt 0) { $named[0].FunctionName } else { '<ScriptBlock>' }
    }
    $escaped = $Message -replace '<!\[LOG\[', '&lt;![LOG[' -replace '\]LOG\]!>', ']LOG]!&gt;'
    $entry   = '<![LOG[{0}]LOG]!><time="{1}{2:+000;-000}" date="{3}" component="{4}" context="" type="{5}" thread="{6}" file="{7}:{8}">' -f
        $escaped, $now.ToString('HH:mm:ss.fff'), $offset, $now.ToString('MM-dd-yyyy'), $Component, $type, $PID, $source, $Caller.ScriptLineNumber

    # -Encoding UTF8 skips the BOM-detection read Add-Content otherwise does, which is the open that
    # fails on a transiently held file. -WhatIf:$false keeps logging active in a -WhatIf run.
    for ($i = 0; $i -lt 10; $i++) {
        try {
            Add-Content -LiteralPath $LogPath -Value $entry -Encoding UTF8 -ErrorAction Stop -WhatIf:$false
            return
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    Write-Warning "A log entry could not be written to '$LogPath'; continuing."
}

function Write-ProfileLog {
    # Adds the deferred-run component prefix; nothing is logged until the log file is known.
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Position = 1)]
        [string]$Component = 'removeUserProfile',

        [ValidateSet('Info','Warning','Error')]
        [string]$Severity = 'Info',

        [System.Management.Automation.InvocationInfo]$Caller
    )
    if (-not $script:LogFile) { return }
    if (-not $Caller) { $Caller = $MyInvocation }
    Write-CMTraceLog $Message "$script:ComponentPrefix$Component" $script:LogFile $Severity -Caller $Caller
}
function Write-Status {
    # Console output for the operator, logged as well.
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [string]$Component = 'removeUserProfile',

        [ValidateSet('Info','Warning','Error')]
        [string]$Severity = 'Info'
    )
    Write-ProfileLog $Message $Component -Severity $Severity -Caller $MyInvocation
    $color = @{ Info = 'Gray'; Warning = 'Yellow'; Error = 'Red' }[$Severity]
    Write-Host $Message -ForegroundColor $color
}

function New-SecureDirectory {
    <#
        Creates a directory only SYSTEM and Administrators can modify, with the ACL
        applied at creation so there is no window in which it is open. A folder made
        directly under C:\ otherwise inherits Modify for Authenticated Users - and the
        deferred task runs as SYSTEM.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$UsersRead
    )
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rights = @{ 'S-1-5-18' = 'FullControl'; 'S-1-5-32-544' = 'FullControl' }
    if ($UsersRead) { $rights['S-1-5-32-545'] = 'ReadAndExecute' }
    foreach ($sid in $rights.Keys) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier $sid), $rights[$sid], 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop -WhatIf:$false | Out-Null
    }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($Path), $acl)
    } else {
        [void][System.IO.Directory]::CreateDirectory($Path, $acl)
    }
}

#endregion

#region Profiles

function Get-ProfilesRoot {
    $root = (Get-ItemProperty -LiteralPath "Registry::$script:ProfileListKey" -Name ProfilesDirectory -ErrorAction SilentlyContinue).ProfilesDirectory
    if (-not $root) { $root = "$env:SystemDrive\Users" }
    [IO.Path]::GetFullPath($root).TrimEnd('\')
}

function Get-ProfileCandidate {
    # Non-special Win32_UserProfile entries, plus folders under the profiles root that
    # belong to no profile at all. Default and Public are named in ProfileList, the
    # legacy 'All Users'/'Default User' entries are junctions.
    param([Parameter(Mandatory)][string]$Root)

    $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath })
    $known = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $profiles) { [void]$known.Add($p.LocalPath.TrimEnd('\')) }
    foreach ($name in 'Default', 'Public') {
        $path = (Get-ItemProperty -LiteralPath "Registry::$script:ProfileListKey" -Name $name -ErrorAction SilentlyContinue).$name
        if ($path) { [void]$known.Add($path.TrimEnd('\')) }
    }

    # A ProfileList <SID>.bak key shows up as a second instance with the same SID.
    foreach ($p in $profiles | Where-Object { -not $_.Special } | Sort-Object SID -Unique) {
        [pscustomobject]@{
            UserName     = Split-Path -Path $p.LocalPath -Leaf
            Sid          = $p.SID
            Path         = $p.LocalPath
            Registered   = $true
            FolderExists = Test-Path -LiteralPath $p.LocalPath -PathType Container
            Loaded       = [bool]$p.Loaded
            LastUse      = $p.LastUseTime
        }
    }
    Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue |
        Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and -not $known.Contains($_.FullName) } |
        ForEach-Object {
            [pscustomobject]@{
                UserName     = $_.Name
                Sid          = $null
                Path         = $_.FullName
                Registered   = $false
                FolderExists = $true
                Loaded       = $false
                LastUse      = $_.LastWriteTime
            }
        }
}

function Test-UserActive {
    # Any process running as the account means a session, service or task is using the profile.
    param([Parameter(Mandatory)][string]$Sid)
    try {
        $account = ([Security.Principal.SecurityIdentifier]$Sid).Translate([Security.Principal.NTAccount]).Value
    } catch {
        return $false
    }
    [bool](Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -eq $account } | Select-Object -First 1)
}

function Get-SignedInUser {
    # One explorer.exe per interactive desktop (console or RDS); language-neutral, unlike quser.
    $ownSession = [Diagnostics.Process]::GetCurrentProcess().SessionId
    Get-Process -Name explorer -IncludeUserName -ErrorAction SilentlyContinue |
        Where-Object { $_.UserName } |
        Sort-Object SessionId, UserName -Unique |
        ForEach-Object {
            $note = if ($_.SessionId -eq $ownSession) { ', this session' } else { '' }
            "$($_.UserName) (session $($_.SessionId)$note)"
        }
}

function Get-ProfileRegistryKey {
    # The profile's ProfileList key (and a .bak copy Windows leaves after a corrupt
    # profile), its WOW6432Node mirror and its ProfileGuid entry, in reg.exe notation.
    param([Parameter(Mandatory)][string]$Sid)
    $wowList = $script:ProfileListKey -replace '^HKLM\\SOFTWARE\\', 'HKLM\SOFTWARE\WOW6432Node\'
    foreach ($list in $script:ProfileListKey, $wowList) {
        foreach ($name in $Sid, "$Sid.bak") {
            if (Test-Path -LiteralPath "Registry::$list\$name") { "$list\$name" }
        }
    }
    Get-ChildItem -LiteralPath "Registry::$script:ProfileGuidKey" -ErrorAction SilentlyContinue |
        Where-Object { (Get-ItemProperty -LiteralPath $_.PSPath -Name SidString -ErrorAction SilentlyContinue).SidString -eq $Sid } |
        ForEach-Object { "$script:ProfileGuidKey\$($_.PSChildName)" }
}

function Export-ProfileRegistry {
    # Throws if any export fails, so the caller leaves the profile untouched.
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$BackupDir
    )
    foreach ($key in @(Get-ProfileRegistryKey -Sid $Sid)) {
        $fileName = ($key -replace '^.*\\CurrentVersion\\', '' -replace '\\', '_') + '.reg'
        if ($key -like '*\WOW6432Node\*') { $fileName = "WOW6432Node_$fileName" }
        $file = Join-Path -Path $BackupDir -ChildPath $fileName
        $output = & reg.exe export $key $file /y 2>&1
        if ($LASTEXITCODE -ne 0) { throw "reg export '$key' failed: $output" }
        Write-ProfileLog "Exported $key to $file" 'Backup'
    }
}

function Dismount-UserHive {
    # The GC releases registry handles still waiting for finalization; they would keep the hive loaded.
    param([Parameter(Mandatory)][string]$MountName)
    for ($i = 0; $i -lt 5; $i++) {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        $null = & reg.exe unload "HKU\$MountName" 2>&1
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep -Seconds 1
    }
    -not ([Microsoft.Win32.Registry]::Users.GetSubKeyNames() -contains $MountName)
}

function Export-UserSetting {
    <#
        Writes the user's mapped network drives as a re-mapping .cmd file and the
        printer connections as a list. A hive Windows already holds is read live;
        otherwise NTUSER.DAT is mounted and unloaded again. Keys are opened through
        .NET and disposed explicitly: the registry provider (HKU:\...) caches open
        handles, which keep the hive mounted and NTUSER.DAT locked. Returns $true if
        no hive is loaded for the profile afterwards.
    #>
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Path,
        [string]$Sid,
        [Parameter(Mandatory)][string]$BackupDir
    )
    $users = [Microsoft.Win32.Registry]::Users
    $mount = $null
    if ($Sid -and ($users.GetSubKeyNames() -contains $Sid)) {
        $hive = $Sid
        Write-ProfileLog "The user hive is loaded by Windows; reading it live." 'Backup' -Severity Warning
    } else {
        $ntUser = Join-Path -Path $Path -ChildPath 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $ntUser)) {
            Write-ProfileLog "No NTUSER.DAT in $Path; no network drives or printers to export." 'Backup' -Severity Warning
            return $true
        }
        $mount = 'RUP_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $output = & reg.exe load "HKU\$mount" $ntUser 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Could not load $ntUser : $output" }
        $hive = $mount
    }

    $defaultPrinters = @('OneNote', 'OneNote (Desktop)', 'OneNote for Windows 10', 'SHRFAX:', 'Microsoft XPS Document Writer',
                         'Microsoft Print to PDF', 'Fax', 'Adobe PDF', 'WinDisc', 'TIFF Printer', 'ImagePrinter Pro', 'NULL')
    $drives   = New-Object System.Collections.Generic.List[string]
    $printers = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try {
        $key = $users.OpenSubKey("$hive\Network")
        if ($key) {
            try {
                foreach ($letter in $key.GetSubKeyNames()) {
                    $drive = $key.OpenSubKey($letter)
                    try { $remotePath = $drive.GetValue('RemotePath') } finally { $drive.Dispose() }
                    $drives.Add("net use ${letter}: `"$remotePath`" /persistent:yes")
                }
            } finally { $key.Dispose() }
        }
        # Connections holds the network printers as ,,server,queue
        $key = $users.OpenSubKey("$hive\Printers\Connections")
        if ($key) {
            try { foreach ($name in $key.GetSubKeyNames()) { [void]$printers.Add($name.Replace(',', '\')) } } finally { $key.Dispose() }
        }
        $key = $users.OpenSubKey("$hive\Printers\ConvertUserDevModesCount")
        if ($key) {
            try {
                foreach ($name in $key.GetValueNames()) {
                    if ($name -and $name -notin $defaultPrinters -and $name -notlike "*$env:COMPUTERNAME*" -and $name -notmatch '\s*\(redirected\s*\d{1,2}\)$') {
                        [void]$printers.Add($name)
                    }
                }
            } finally { $key.Dispose() }
        }
    } finally {
        $released = $true
        if ($mount) {
            $released = Dismount-UserHive -MountName $mount
            if (-not $released) { Write-ProfileLog "The user hive mounted as HKU\$mount could not be unloaded." 'Backup' -Severity Warning }
        }
    }

    if ($drives.Count -gt 0) {
        $file = Join-Path -Path $BackupDir -ChildPath "NetDrives_$UserName.cmd"
        Set-Content -LiteralPath $file -Value $drives -Encoding OEM -ErrorAction Stop
        Write-ProfileLog "Exported $($drives.Count) network drive(s) to ${file}:`r`n$($drives -join "`r`n")" 'Backup'
    } else {
        Write-ProfileLog 'No mapped network drives.' 'Backup'
    }
    if ($printers.Count -gt 0) {
        $file = Join-Path -Path $BackupDir -ChildPath "PrinterList_$UserName.txt"
        Set-Content -LiteralPath $file -Value @($printers) -Encoding UTF8 -ErrorAction Stop
        Write-ProfileLog "Exported $($printers.Count) printer(s) to ${file}:`r`n$(@($printers) -join "`r`n")" 'Backup'
    } else {
        Write-ProfileLog 'No printer connections.' 'Backup'
    }

    return ($released -and -not ($Sid -and ($users.GetSubKeyNames() -contains $Sid)))
}

function Rename-ProfileFolder {
    # Retries briefly: an antivirus or indexer scan can hold a file for a moment.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$NewName
    )
    for ($i = 1; ; $i++) {
        try {
            Rename-Item -LiteralPath $Path -NewName $NewName -ErrorAction Stop
            return
        } catch {
            if ($i -ge 3) { throw }
            Start-Sleep -Seconds 2
        }
    }
}

function Remove-FolderTree {
    # \\?\ covers paths beyond 260 characters. Returns $true once the folder is gone.
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\[^\\]+\\[^\\]') { throw "Refused to delete '$Path': not a safe target." }
    Remove-Item -LiteralPath "\\?\$Path" -Recurse -Force -ErrorAction SilentlyContinue
    -not (Test-Path -LiteralPath $Path)
}

function Remove-ProfileRegistration {
    <#
        Removes the profile through Win32_UserProfile (Windows' DeleteProfile: the
        ProfileList and ProfileGuid entries, and the folder if it still exists at the
        registered path), then any leftover keys such as a .bak copy.
        -RequireFolderGone protects a renamed profile: if the folder is still at the
        registered path, nothing is removed, because that would delete it.
    #>
    param(
        [Parameter(Mandatory)][string]$Sid,
        [switch]$RequireFolderGone
    )
    # A .bak key appears as a second instance with the same SID, so repeat until none is left.
    for ($i = 0; $i -lt 3; $i++) {
        $cim = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$Sid'" -ErrorAction Stop | Select-Object -First 1
        if (-not $cim) { break }
        if ($RequireFolderGone -and (Test-Path -LiteralPath $cim.LocalPath)) {
            throw "The folder is still at '$($cim.LocalPath)'; the registration was kept so the folder is not deleted."
        }
        if ($cim.Loaded) { throw 'The profile is loaded; its registration cannot be removed.' }
        Remove-CimInstance -InputObject $cim -ErrorAction Stop
        Write-ProfileLog "Removed the Win32_UserProfile registration of $Sid ($($cim.LocalPath))." 'Registry'
    }
    foreach ($key in @(Get-ProfileRegistryKey -Sid $Sid)) {
        Remove-Item -LiteralPath "Registry::$key" -Recurse -Force -ErrorAction Stop
        Write-ProfileLog "Removed leftover registry key $key" 'Registry'
    }
}

#endregion

#region Deferred work

function Get-DeferredQueue {
    # Kept in HKLM, which standard users cannot write, rather than in a file on disk.
    # Returned unrolled: PS 5.1 pipes a parsed JSON array on as one single object.
    $json = (Get-ItemProperty -LiteralPath "Registry::$script:StateKey" -Name Queue -ErrorAction SilentlyContinue).Queue
    if ($json) {
        $queue = ConvertFrom-Json -InputObject $json
        $queue
    }
}

function Add-DeferredWork {
    <#
        Renames the folder at the next boot through PendingFileRenameOperations, which
        Windows processes before any service starts, and queues the rest for the
        startup task. Mode Rename: the folder becomes <User>-<Date>.old. Mode Delete:
        <User>-<Date>.pending-delete, which the task deletes.
    #>
    param(
        [Parameter(Mandatory)][string]$UserName,
        [string]$Sid,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][ValidateSet('Rename','Delete')][string]$Mode,
        [bool]$RemoveRegistration
    )
    if (Test-Path -LiteralPath $Path) {
        if (-not ('ProfileCleanup.NativeMethods' -as [type])) {
            Add-Type -Namespace ProfileCleanup -Name NativeMethods -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool MoveFileEx(string existingFileName, string newFileName, int flags);
'@
        }
        # 4 = MOVEFILE_DELAY_UNTIL_REBOOT
        if (-not [ProfileCleanup.NativeMethods]::MoveFileEx($Path, $Target, 4)) {
            throw (New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }
        Write-ProfileLog "Scheduled the rename of $Path to $Target at the next boot." 'Deferred'
    }

    $queue = @(Get-DeferredQueue) + [pscustomobject]@{
        UserName           = $UserName
        Sid                = $Sid
        Path               = $Path
        Target             = $Target
        Mode               = $Mode
        RemoveRegistration = $RemoveRegistration
        LogFile            = $script:LogFile
    }
    if (-not (Test-Path -LiteralPath "Registry::$script:StateKey")) { New-Item -Path "Registry::$script:StateKey" -Force | Out-Null }
    Set-ItemProperty -LiteralPath "Registry::$script:StateKey" -Name Queue -Value (ConvertTo-Json -InputObject @($queue) -Compress)
    Remove-ItemProperty -LiteralPath "Registry::$script:StateKey" -Name Attempt -ErrorAction SilentlyContinue
    Register-DeferredTask
}

function Register-DeferredTask {
    # The task runs a copy of this script as SYSTEM. The folder is recreated each time,
    # so a folder planted beforehand cannot keep weaker permissions; Directory.Delete
    # removes a planted junction itself rather than following it.
    if (Test-Path -LiteralPath $script:WorkDir) { [System.IO.Directory]::Delete($script:WorkDir, $true) }
    New-SecureDirectory -Path $script:WorkDir
    $scriptCopy = Join-Path -Path $script:WorkDir -ChildPath 'removeUserProfile.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $scriptCopy -Force -ErrorAction Stop

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                    -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$scriptCopy`" -Deferred"
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
                    -MultipleInstances IgnoreNew -RestartCount 0 `
                    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable:$false
    Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger $trigger -Principal $principal `
                           -Settings $settings -Description 'One-shot user profile cleanup; removes itself after running.' `
                           -Force -ErrorAction Stop | Out-Null
}

function Unregister-DeferredWork {
    Remove-Item -LiteralPath "Registry::$script:StateKey" -Recurse -Force -ErrorAction SilentlyContinue
    try { Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction Stop } catch {
        $null = & schtasks.exe /delete /tn $script:TaskName /f 2>&1
    }
    try { [System.IO.Directory]::Delete($script:WorkDir, $true) } catch { }
}

function Complete-DeferredWork {
    # One queued profile, after the restart. The boot-time rename has normally happened already.
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string]$Root
    )
    foreach ($p in $Entry.Path, $Entry.Target) {
        if (-not (Split-Path -Path $p -Parent).Equals($Root, [StringComparison]::OrdinalIgnoreCase)) {
            Write-ProfileLog "$($Entry.UserName): '$p' is not directly below $Root; skipped." 'Folder' -Severity Error
            return
        }
    }

    if (Test-Path -LiteralPath $Entry.Path) {
        try {
            Rename-ProfileFolder -Path $Entry.Path -NewName (Split-Path -Path $Entry.Target -Leaf)
            Write-ProfileLog "$($Entry.UserName): renamed $($Entry.Path) to $($Entry.Target)." 'Folder'
        } catch {
            Write-ProfileLog "$($Entry.UserName): the folder was not renamed at boot and still cannot be renamed: $($_.Exception.Message)" 'Folder' -Severity Error
            if ($Entry.Mode -eq 'Rename') { return }
        }
    } elseif (Test-Path -LiteralPath $Entry.Target) {
        Write-ProfileLog "$($Entry.UserName): the folder is at $($Entry.Target)." 'Folder'
    }

    if ($Entry.Mode -eq 'Delete') {
        foreach ($folder in $Entry.Target, $Entry.Path) {
            if (-not (Test-Path -LiteralPath $folder)) { continue }
            if (Remove-FolderTree -Path $folder) {
                Write-ProfileLog "$($Entry.UserName): deleted $folder." 'Folder'
            } else {
                Write-ProfileLog "$($Entry.UserName): $folder could not be fully deleted; delete the rest manually." 'Folder' -Severity Error
            }
        }
    }

    if ($Entry.RemoveRegistration -and $Entry.Sid) {
        try {
            Remove-ProfileRegistration -Sid $Entry.Sid -RequireFolderGone:($Entry.Mode -eq 'Rename')
            Write-ProfileLog "$($Entry.UserName): profile registration removed." 'Registry'
        } catch {
            Write-ProfileLog "$($Entry.UserName): the profile registration could not be removed: $($_.Exception.Message)" 'Registry' -Severity Error
        }
    }
}

function Invoke-DeferredWork {
    $script:ComponentPrefix = 'Deferred-'
    $queue = @(Get-DeferredQueue)

    # Written before any work: a run that hangs or is killed never gets a second attempt
    # at every following boot.
    $attempt = 1 + [int](Get-ItemProperty -LiteralPath "Registry::$script:StateKey" -Name Attempt -ErrorAction SilentlyContinue).Attempt
    Set-ItemProperty -LiteralPath "Registry::$script:StateKey" -Name Attempt -Value $attempt -ErrorAction SilentlyContinue

    try {
        $root = Get-ProfilesRoot
        foreach ($entry in $queue) {
            # Into the log of the run that queued the work; a new _Deferred.log only if that one is gone.
            $script:LogFile = $entry.LogFile
            if (-not (Test-Path -LiteralPath $script:LogFile)) {
                $script:LogFile = $entry.LogFile -replace '\.log$', '_Deferred.log'
                $logDir = Split-Path -Path $script:LogFile -Parent
                if (-not (Test-Path -LiteralPath $logDir)) { New-SecureDirectory -Path $logDir -UsersRead }
            }
            if ($attempt -gt 1) {
                Write-ProfileLog "$($entry.UserName): a previous deferred run did not finish; not retrying. Check the profile manually." -Severity Error
                continue
            }
            Write-ProfileLog "$($entry.UserName): finishing the profile cleanup after the restart (mode $($entry.Mode))."
            try {
                Complete-DeferredWork -Entry $entry -Root $root
            } catch {
                Write-ProfileLog "$($entry.UserName): deferred cleanup failed: $($_.Exception.Message)" -Severity Error
            }
        }
    } finally {
        Unregister-DeferredWork
    }
}

#endregion

#region Main

if ($Deferred) {
    Invoke-DeferredWork
    exit 0
}

$runStamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$runDir   = Join-Path -Path $script:BaseDir -ChildPath "${runStamp}_ProfileCleanup"
try {
    New-SecureDirectory -Path $runDir -UsersRead
} catch {
    Write-Warning "Cannot create the log folder '$runDir': $($_.Exception.Message)"
    Pause
    exit 1
}
$script:LogFile = Join-Path -Path $runDir -ChildPath "${runStamp}_$($env:COMPUTERNAME)_ProfileCleanup.log"

$scriptVersion = [regex]::Match((Get-Content -LiteralPath $PSCommandPath -Raw), '(?m)^\s*Version:\s*(\S+)').Groups[1].Value
Write-ProfileLog ("removeUserProfile.ps1 $scriptVersion started;`r`n" +
    "Source: https://github.com/halatsWol/PowerShell-Tools/blob/main/scripts/removeUserProfile.ps1;`r`n" +
    "Host: $env:COMPUTERNAME; User: $env:USERDOMAIN\$env:USERNAME; PowerShell: $($PSVersionTable.PSVersion);`r`n" +
    "UserName: $($UserName -join ', '); Delete: $Delete; NoRestart: $NoRestart; ForceRestart: $ForceRestart;")

$root       = Get-ProfilesRoot
$candidates = @(Get-ProfileCandidate -Root $root | Sort-Object UserName)
$pending    = @(Get-DeferredQueue)

if ($candidates.Count -eq 0) {
    Write-Status "No user profiles found on $env:COMPUTERNAME."
    Pause
    exit 0
}
for ($i = 0; $i -lt $candidates.Count; $i++) {
    $candidates[$i] | Add-Member -NotePropertyName '#' -NotePropertyValue ($i + 1)
}
$columns = '#', 'UserName', 'Registered', 'FolderExists', 'Loaded', 'LastUse', 'Path'
$table   = ($candidates | Format-Table $columns -AutoSize | Out-String).TrimEnd()
Write-ProfileLog "Profiles found:`r`n$table"

Write-Host ''
if ($pending.Count -gt 0) {
    Write-Status "Already scheduled for the next restart: $(($pending | ForEach-Object { $_.UserName }) -join ', ')" -Severity Warning
}
if (-not $UserName) {
    Write-Host "User profiles on $env:COMPUTERNAME ($root):" -ForegroundColor Cyan
    Write-Host $table
    Write-Host '  Registered=False: folder without a profile entry. FolderExists=False: profile entry without a folder.' -ForegroundColor DarkGray
    Write-Host ''
    $UserName = Read-Host 'Select the profile(s) to remove - numbers, ranges or usernames, comma separated (e.g. 1,3-5,jdoe)'
}

# powershell.exe -File passes "a,b" as one string, so commas are split here too.
$selected = New-Object System.Collections.Generic.List[object]
foreach ($token in @($UserName -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    $matched = @()
    if ($token -match '^(\d+)(?:-(\d+))?$') {
        $first = [int]$Matches[1]
        $last  = if ($Matches[2]) { [int]$Matches[2] } else { $first }
        $matched = @($candidates | Where-Object { $_.'#' -ge $first -and $_.'#' -le $last })
    }
    # A purely numeric folder name still matches by name if no list number fits.
    if ($matched.Count -eq 0) { $matched = @($candidates | Where-Object { $_.UserName -eq $token }) }
    if ($matched.Count -eq 0) { Write-Status "No profile matches '$token'." -Severity Warning }
    foreach ($profileRow in $matched) {
        if (-not $selected.Contains($profileRow)) { $selected.Add($profileRow) }
    }
}
if ($selected.Count -eq 0) {
    Write-Status 'Nothing selected; no changes made.'
    Pause
    exit 0
}

Write-Host ''
Write-Host ($selected | Format-Table $columns -AutoSize | Out-String).TrimEnd()
Write-Host ''
if ($Delete) {
    $answer = Read-Host "PERMANENTLY delete these $($selected.Count) profile(s)? Type DELETE to confirm"
    $proceed = $answer.Trim() -eq 'DELETE'
} else {
    $answer = Read-Host "Rename these $($selected.Count) profile folder(s) to <User>-<Date>.old? [Y] Yes  [N] No  (type DELETE to delete them permanently instead)"
    $proceed = $answer.Trim() -match '^(y|yes|delete)$'
    if ($answer.Trim() -eq 'DELETE') { $Delete = $true }
}
if (-not $proceed) {
    Write-Status 'Cancelled; no changes made.'
    Pause
    exit 0
}
$modeText = if ($Delete) { 'Delete' } else { 'Rename' }
Write-ProfileLog "Confirmed: $modeText $($selected.UserName -join ', ')"

$drive      = Get-PSDrive -Name $root.Substring(0, 1) -ErrorAction SilentlyContinue
$freeBefore = if ($drive) { $drive.Free } else { $null }
$results    = New-Object System.Collections.Generic.List[object]

foreach ($candidate in $selected) {
    $name   = $candidate.UserName
    $result = [pscustomobject]@{ UserName = $name; Result = 'Skipped'; Detail = '' }
    $results.Add($result)
    Write-Host ''
    Write-Status "--- $name ---" $name

    # Re-read right before acting; the state may have changed since the list was shown.
    $sid  = $candidate.Sid
    $path = $candidate.Path
    if ($sid) {
        $cim = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cim) { $result.Detail = 'The profile is no longer registered.'; Write-Status $result.Detail $name -Severity Warning; continue }
        $path = $cim.LocalPath
    }
    $path = [IO.Path]::GetFullPath($path).TrimEnd('\')
    if (-not (Split-Path -Path $path -Parent).Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
        $result.Detail = "'$path' is not directly below $root."
        Write-Status $result.Detail $name -Severity Warning
        continue
    }
    if ($sid -and (Test-UserActive -Sid $sid)) {
        $result.Detail = 'The user is signed in, or processes run as the user. Sign the user out (or restart) and run again.'
        Write-Status $result.Detail $name -Severity Warning
        continue
    }
    if ($pending | Where-Object { $_.Path -eq $path }) {
        $result.Detail = 'Already scheduled for the next restart.'
        Write-Status $result.Detail $name -Severity Warning
        continue
    }
    $folderExists = Test-Path -LiteralPath $path -PathType Container
    if (-not $folderExists -and -not $sid) {
        $result.Detail = 'The folder no longer exists.'
        Write-Status $result.Detail $name -Severity Warning
        continue
    }

    $backupDir = Join-Path -Path $runDir -ChildPath $name
    try {
        New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop | Out-Null
        if ($sid) { Export-ProfileRegistry -Sid $sid -BackupDir $backupDir }
        $hiveFree = $true
        if ($folderExists) { $hiveFree = Export-UserSetting -UserName $name -Path $path -Sid $sid -BackupDir $backupDir }
        Write-Status "Backup completed: $backupDir" $name
    } catch {
        $result.Result = 'Failed'
        $result.Detail = "Backup failed, nothing was changed: $($_.Exception.Message)"
        Write-Status $result.Detail $name -Severity Error
        continue
    }

    $stamp  = Get-Date -Format 'yyyy-MM-dd_HH-mm'
    $suffix = if ($Delete) { 'pending-delete' } else { 'old' }
    $deferredTarget = Join-Path -Path $root -ChildPath "$name-$stamp.$suffix"
    $deferArgs = @{ UserName = $name; Sid = $sid; Path = $path; Target = $deferredTarget; Mode = $modeText }

    try {
        if (-not $hiveFree) {
            Add-DeferredWork @deferArgs -RemoveRegistration ([bool]$sid)
            $result.Result = 'Deferred'
            $result.Detail = 'The user hive is in use; the profile is removed during the restart.'
        } elseif (-not $folderExists) {
            $registrationError = $null
            try { Remove-ProfileRegistration -Sid $sid } catch { $registrationError = $_.Exception.Message }
            if ($registrationError) {
                Add-DeferredWork @deferArgs -RemoveRegistration $true
                $result.Result = 'Deferred'
                $result.Detail = "The folder was already gone; the profile registration could not be removed now ($registrationError) and is removed during the restart."
            } else {
                $result.Result = 'Done'
                $result.Detail = 'Profile registration removed; the folder was already gone.'
            }
        } elseif ($Delete) {
            $registrationError = $null
            if ($sid) {
                try { Remove-ProfileRegistration -Sid $sid } catch { $registrationError = $_.Exception.Message }
            }
            # Win32_UserProfile reports success even when locked files keep part of the folder.
            if (-not (Test-Path -LiteralPath $path) -or (Remove-FolderTree -Path $path)) {
                if ($registrationError) {
                    # A registration without a folder gives the user a temporary profile at the next sign-in.
                    Add-DeferredWork @deferArgs -RemoveRegistration $true
                    $result.Result = 'Deferred'
                    $result.Detail = "Folder deleted; the profile registration could not be removed now ($registrationError) and is removed during the restart."
                } else {
                    $result.Result = 'Done'
                    $result.Detail = "Profile deleted: $path"
                }
            } else {
                Add-DeferredWork @deferArgs -RemoveRegistration ([bool]$registrationError)
                $result.Result = 'Deferred'
                $result.Detail = 'Locked files remain; the rest of the folder is deleted during the restart.'
            }
        } else {
            $renamed = $false
            try {
                Rename-ProfileFolder -Path $path -NewName (Split-Path -Path $deferredTarget -Leaf)
                $renamed = $true
            } catch {
                Write-ProfileLog "Rename failed: $($_.Exception.Message)" $name -Severity Warning
            }
            if ($renamed) {
                $registrationError = $null
                if ($sid) {
                    try { Remove-ProfileRegistration -Sid $sid -RequireFolderGone } catch { $registrationError = $_.Exception.Message }
                }
                if ($registrationError) {
                    Add-DeferredWork @deferArgs -RemoveRegistration $true
                    $result.Result = 'Deferred'
                    $result.Detail = "Profile folder renamed to $deferredTarget; the profile registration could not be removed now ($registrationError) and is removed during the restart."
                } else {
                    $result.Result = 'Done'
                    $result.Detail = "Profile folder renamed to $deferredTarget"
                }
            } else {
                Add-DeferredWork @deferArgs -RemoveRegistration ([bool]$sid)
                $result.Result = 'Deferred'
                $result.Detail = "The folder is locked; it is renamed to $deferredTarget during the restart."
            }
        }
    } catch {
        $result.Result = 'Failed'
        $result.Detail = $_.Exception.Message
    }
    $severity = @{ Done = 'Info'; Deferred = 'Warning'; Failed = 'Error' }[$result.Result]
    Write-Status "$($result.Result): $($result.Detail)" $name -Severity $severity
}

$summary = ($results | Format-Table UserName, Result, Detail -AutoSize -Wrap | Out-String).TrimEnd()
Write-Host ''
Write-Host 'Summary:' -ForegroundColor Cyan
Write-Host $summary
Write-ProfileLog "Summary:`r`n$summary" 'Summary'
if ($null -ne $freeBefore) {
    $freeAfter = (Get-PSDrive -Name $drive.Name).Free
    Write-Status ('Free space on {0}: {1:N2} GB before, {2:N2} GB after (recovered {3:N2} GB).' -f $drive.Root, ($freeBefore / 1GB), ($freeAfter / 1GB), (($freeAfter - $freeBefore) / 1GB)) 'Summary'
}
if (@($results | Where-Object { $_.Result -in 'Done', 'Deferred' }).Count -gt 0) {
    Write-Host ''
    Write-Host "Backups (registry, NetDrives_<User>.cmd for re-mapping, PrinterList_<User>.txt) and the log are in $runDir"
}

$failedCount   = @($results | Where-Object { $_.Result -eq 'Failed' }).Count
$deferredCount = @($results | Where-Object { $_.Result -eq 'Deferred' }).Count
$exitCode = if ($failedCount -gt 0) { 1 } elseif ($deferredCount -gt 0) { 3010 } else { 0 }

if ($deferredCount -gt 0) {
    Write-Host ''
    if ($NoRestart) {
        Write-Status "A restart is required to finish $deferredCount profile(s); the work runs automatically at the next restart." 'Summary' -Severity Warning
    } else {
        $signedIn = @(Get-SignedInUser)
        if ($signedIn.Count -gt 0) {
            Write-Status "Signed in on $env:COMPUTERNAME (unsaved work is lost on restart):`r`n  $($signedIn -join "`r`n  ")" 'Summary' -Severity Warning
        } else {
            Write-ProfileLog "No users are signed in on $env:COMPUTERNAME." 'Summary'
        }
        $restart = [bool]$ForceRestart
        if (-not $restart) {
            $answer = Read-Host "A restart finishes $deferredCount profile(s). Restart now? [Y] Yes  [N] No"
            $restart = "$answer".Trim() -match '^(y|yes)$'
            Write-ProfileLog "Restart prompt answered '$answer'." 'Summary'
        }
        if ($restart) {
            Write-Status "Restarting in 60 seconds to finish $deferredCount profile(s)$(if ($ForceRestart) { ' (-ForceRestart)' }). Cancel with: shutdown /a" 'Summary' -Severity Warning
            $null = & shutdown.exe /r /t 60 /d p:4:1 /c 'removeUserProfile: restarting to finish the user profile cleanup.' 2>&1
        } else {
            Write-Status "Not restarted; the remaining work for $deferredCount profile(s) runs automatically at the next restart." 'Summary' -Severity Warning
        }
    }
}
Write-ProfileLog "Finished with exit code $exitCode." 'Summary'
Pause
exit $exitCode

#endregion

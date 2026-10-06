<#
.SYNOPSIS
    Cleanly uninstalls all Autodesk products (2022 and newer) from a system, following Autodesk's
    official clean uninstall procedure.

.DESCRIPTION
    Implements Autodesk's clean uninstall procedure for versions 2022 and newer
    (https://www.autodesk.com/support/technical/article/caas/sfdcarticles/sfdcarticles/Clean-uninstall.html)
    unattended. Each Autodesk bundle is uninstalled silently with the same ODIS command Programs
    and Features starts; only ODIS removes the bundle's ODIS packages, which have no Windows
    Installer product, with their shortcuts, file associations, firewall rules and COM servers.
    Every Autodesk MSI product still installed afterwards is uninstalled by its product code: the
    products come from Windows Installer itself, the bundles under
    C:\ProgramData\Autodesk\Uninstallers decide the order.

      Step 1  Stops Autodesk services and processes and uninstalls the ODIS bundles - Object
              Enablers first, then updates, then products - then every Autodesk MSI product still
              installed except the Autodesk Genuine Service, components shared by several
              products last. Then runs the Autodesk Access, ODIS and Licensing removers. Finally
              every Autodesk registration Windows Installer still has - a product whose uninstall
              failed, or a registration left by an earlier failed install or uninstall - gets a
              forced registration cleanup with the scope of Microsoft's Program Install and
              Uninstall troubleshooter.
      Step 2  Runs the Autodesk Identity Manager uninstaller and waits until its folder is empty,
              then the remaining uninstall helpers.
      Step 3  Removes Autodesk services left behind, clears %TEMP% of every user profile and of
              the account running the script, deletes the FLEXnet adsk* files and the Autodesk
              folders under Program Files, Common Files, ProgramData and every profile (including
              the Default profile new users are created from).
      Step 4  Deletes SOFTWARE\Autodesk from HKLM and every loaded user hive.
      Step 5  Uninstalls the Autodesk Genuine Service, which only works once everything else is
              gone, then deletes what is left of C:\ProgramData\Autodesk. Autodesk-signed files
              outside the Autodesk folders (eg. styleman.cpl in System32) are deleted only once
              neither a Windows Installer product nor a SharedDLLs counter of another owner
              references them any more. Shortcuts, file associations and system PATH entries that
              still point into the deleted Autodesk folders are removed.

    Every registry key and value the script deletes is exported to a .reg backup first.

    Before it asks to proceed, it shows an estimated duration range from the size of what is
    installed: ODIS needs about 1.5 minutes per GB of a bundle, so a large product such as Revit
    takes far longer than a small one. The log records the estimate next to the actual duration.

    What cannot be done while Windows is running is finished at the next boot: anything still
    locked is queued into PendingFileRenameOperations, and a one-shot SYSTEM task unregisters the
    Autodesk COM/shell extensions, cleans SOFTWARE\Autodesk in every user hive - also of users who
    never sign in, and of the Default profile - and sweeps the Autodesk folders once more.
    AcSignCore16.dll (Autodesk Signature Core) is registered as a shell extension under hundreds of
    CLSIDs; explorer.exe loads it at every logon, it recreates HKCU\SOFTWARE\Autodesk, and because
    Explorer holds the file open it can never be deleted while Windows is running. Doing that work
    at boot, before any logon, is the only way to break the cycle. The task's script lives in
    C:\ProgramData\ADSK-DeferredCleanup, writable only by SYSTEM and Administrators.

    Logging is CMTrace-compatible, one entry per event with a component per phase. The deferred
    boot-time phase appends to the log of the run, its entries prefixed with 'DEFERRED TASK:' and
    logged under the component AutoDeskCleanRemove-Deferred; only if that log no longer exists is
    a <log>_Deferred.log created next to it. The registry backup sits next to the log:
        <timestamp>_<computer>_ADSK-CleanUninstall.log
        <timestamp>_<computer>_ADSK-CleanUninstall_RegistryBackup\

.PARAMETER LogPath
    Directory for all logs and the registry backup. MSI logs are written to <LogPath>\MSILogs.
    Defaults to C:\_ADSK_CleanUninstall. The script aborts if it cannot be created. A directory
    created by the script is writable only by SYSTEM and Administrators.

.PARAMETER LogLevel
    Verbosity threshold. Defaults to Verbose, which embeds the complete MSI logs into the main log.

        None    - no file logging
        Error   - errors only
        Warning - warnings and errors
        Info    - normal flow; MSI logs stay as separate files in MSILogs
        Verbose - everything, including full MSI logs   (default)
        Debug   - same as Verbose

    An MSI log is deleted only once it has been embedded in the main log and the uninstall
    succeeded; otherwise it is kept under <LogPath>\MSILogs.

.PARAMETER Unattended
    Suppresses every prompt and the completion toast. Required for Intune, SCCM or any headless
    execution - without it the script waits at Pause/Read-Host.

.PARAMETER NoRestart
    Never offers to restart, even in an interactive session. Takes precedence over -ForceRestart
    if both are supplied.

.PARAMETER ForceRestart
    Restarts the computer as soon as the run completes, without asking. Useful in unattended
    deployment so the deferred boot-time cleanup finishes immediately rather than waiting for the
    user's next restart.

.EXAMPLE
    PS> .\AutoDeskCleanRemove.ps1

    Interactive run with default logging to C:\_ADSK_CleanUninstall.

.EXAMPLE
    PS> .\AutoDeskCleanRemove.ps1 -WhatIf

    Dry run. Reports every uninstall, deletion, registry removal and the deferred task it would
    create, and changes nothing.

.EXAMPLE
    PS> .\AutoDeskCleanRemove.ps1 -Unattended -ForceRestart

    Unattended removal for a deployment tool, restarting immediately so the boot-time cleanup
    completes without waiting for the user.

.EXAMPLE
    PS> .\AutoDeskCleanRemove.ps1 -LogPath 'D:\Logs\ADSK' -LogLevel Info

    Logs to a custom directory and keeps the MSI logs as separate files instead of embedding them,
    producing a much smaller main log.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    None. Progress is written to the host, detail to the CMTrace logs under -LogPath, and the
    outcome is reported through the exit code:

        0     Completed; nothing is left to finish
        3010  Completed; a restart finishes the cleanup (boot-time task, locked files)
        10    Completed, but at least one product needed a forced Windows Installer registration
              cleanup: its uninstall failed, or an earlier failed install or uninstall had left a
              registration without a working product. Everything was verified clean afterwards;
              a restart is required. Deployment tools treat an unknown code as a failure - to
              accept a forced cleanup, map 10 to "Soft reboot" (ConfigMgr: deployment type >
              Return Codes; Intune: Win32 app > Return codes).
        1     Not elevated, the log directory could not be created, a system folder could not be
              resolved, or Autodesk products, entries, shortcuts, file associations or PATH
              entries are left after the cleanup

    The final check asks Windows Installer and reads its registry store directly for every
    Autodesk product code seen during the run, and looks for Programs and Features entries,
    shortcuts, file associations and PATH entries pointing into the deleted Autodesk folders, so
    the exit code reflects the actual end state.

.NOTES
    Author:   Halatschek Wolfram
    Date:     2026-10-06
    Version:  4.0
    Requires: Administrative privileges, Windows PowerShell 5.1 or later. Started from a 32-bit
              process on 64-bit Windows, it restarts itself in 64-bit PowerShell.

    A restart is required to complete removal - the deferred task does its work at the next boot.
    One run plus one restart is normally sufficient; running the script a second time afterwards
    remains a safe way to confirm nothing is left.

    Warning:  This script is provided "as is" without any warranty of any kind.

        !!    The Author of this script is not responsible for any data loss or system damage
              caused by the use of this script. Use at your own risk.

              This removes per-user Autodesk data for EVERY profile on the machine, including
              customisations under AppData\Roaming\Autodesk, and clears every profile's %TEMP%.
              Use -WhatIf first if you are unsure what will be removed.

              Autodesk Fusion must be uninstalled MANUALLY BEFOREHAND. It is not an MSI/ODIS
              product, so this script cannot uninstall it - but it does delete AppData\Local\
              Autodesk, which is where Fusion lives, without running Fusion's uninstaller.
              Running this with Fusion still installed leaves a corrupted, half-removed Fusion
              behind.

              If any errors occur that you wish to report to the Author, please open an issue on
              https://github.com/halatsWol/PowerShell-Tools

.LINK
    https://github.com/halatsWol/PowerShell-Tools

.LINK
    https://github.com/halatsWol/PowerShell-Tools/blob/main/scripts/AutoDeskCleanRemove.ps1
#>

# SupportsShouldProcess gives -WhatIf and -Confirm. ConfirmImpact is deliberately left at the
# default: 'High' would prompt for every one of the hundreds of destructive operations below.
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = "$env:SystemDrive\_ADSK_CleanUninstall",

    [ValidateSet('None','Error','Warning','Info','Verbose','Debug')]
    [string]$LogLevel = 'Verbose',

    [switch]$Unattended,

    [switch]$NoRestart,

    [switch]$ForceRestart
)

# In a 32-bit process (eg. a 32-bit deployment agent) Program Files, Common Files and
# HKLM\SOFTWARE are redirected, which would point every step at the wrong location.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $nativeArgs = @('-ExecutionPolicy', 'Bypass', '-NoProfile', '-File', $PSCommandPath)
    foreach ($parameter in $PSBoundParameters.GetEnumerator()) {
        if ($parameter.Value -is [switch]) {
            if ($parameter.Value) { $nativeArgs += "-$($parameter.Key)" }
        } else {
            $nativeArgs += "-$($parameter.Key)", $parameter.Value
        }
    }
    & (Join-Path $env:windir 'sysnative\WindowsPowerShell\v1.0\powershell.exe') @nativeArgs
    exit $LASTEXITCODE
}

# $PSSenderInfo alone does not detect a headless local session (e.g. a service or remote-exec
# context), which is why AppActivate could throw at the very end.
$script:Interactive = (-not $Unattended) -and (-not $PSSenderInfo) -and [Environment]::UserInteractive

# Conflicting intents: prefer the safer one rather than guessing.
if ($ForceRestart -and $NoRestart) {
    Write-Warning "-ForceRestart and -NoRestart were both specified; -NoRestart wins and the computer will not be restarted."
    $ForceRestart = $false
}

# $PSCmdlet is only bound at script scope, so capture it for use inside functions.
$script:Cmdlet = $PSCmdlet

function Test-ShouldProcess {
    <#
        Wrapper so nested functions can take part in -WhatIf / -Confirm. Returns $true when the
        action should actually be performed; under -WhatIf it returns $false and PowerShell prints
        the "What if:" line automatically.
    #>
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Action
    )
    if ($null -eq $script:Cmdlet) { return $true }
    return $script:Cmdlet.ShouldProcess($Target, $Action)
}

function Wait-ForUser {
    if ($script:Interactive) { Pause }
}

$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    Write-Host ''
    Write-Warning "This script must be run with administrative privileges. Please restart the script in an elevated PowerShell session."
    Wait-ForUser
    exit 1
}

# Pre-load CimCmdlets. Otherwise it autoloads mid-run and its alias registrations emit a dozen
# spurious "What if: Set Alias" lines. Import-Module does not support -WhatIf, so the preference
# is suppressed around the call instead.
$previousWhatIfPreference = $WhatIfPreference
$WhatIfPreference = $false
Import-Module CimCmdlets -ErrorAction SilentlyContinue
$WhatIfPreference = $previousWhatIfPreference

#region Logging

$script:LogRank = @{ None = 0; Error = 1; Warning = 2; Info = 3; Verbose = 4; Debug = 4 }[$LogLevel]

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

function Write-AdskLog {
    # Applies -LogLevel; Verbose is written as an info entry, but only at -LogLevel Verbose.
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Position = 1)]
        [string]$Component = 'AutoDeskCleanRemove',

        [ValidateSet('Info','Warning','Error','Verbose')]
        [string]$Severity = 'Info',

        [System.Management.Automation.InvocationInfo]$Caller
    )
    if (@{ Error = 1; Warning = 2; Info = 3; Verbose = 4 }[$Severity] -gt $script:LogRank) { return }
    if (-not $Caller) { $Caller = $MyInvocation }
    $cmSeverity = if ($Severity -eq 'Verbose') { 'Info' } else { $Severity }
    Write-CMTraceLog $Message $Component $script:LogFile $cmSeverity -Caller $Caller
}

function Write-AdskStatus {
    # Console output for the operator, logged as well.
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [string]$Component = 'AutoDeskCleanRemove',

        [ValidateSet('Info','Warning','Error')]
        [string]$Severity = 'Info'
    )
    Write-AdskLog $Message $Component -Severity $Severity -Caller $MyInvocation
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

$script:MsiLogPath = Join-Path -Path $LogPath -ChildPath 'MSILogs'
try {
    if (-not (Test-Path -LiteralPath $LogPath)) { New-SecureDirectory -Path $LogPath -UsersRead }
    if (-not (Test-Path -LiteralPath $script:MsiLogPath)) {
        New-Item -ItemType Directory -Path $script:MsiLogPath -Force -ErrorAction Stop -WhatIf:$false | Out-Null
    }
} catch {
    Write-Warning "Cannot create log directory '$LogPath': $($_.Exception.Message)"
    exit 1
}
$script:LogFile = Join-Path -Path $LogPath -ChildPath "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')_$($env:COMPUTERNAME)_ADSK-CleanUninstall.log"

#endregion

#region Locations and state

function Resolve-AdskFolder {
    # A known folder is only used when it is absolute and below a drive root; anything else would
    # turn a deletion target into a path at or near a drive root.
    param([string[]]$Candidate)
    foreach ($path in $Candidate) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $path = $path.TrimEnd('\')
        if ($path -match '^[A-Za-z]:\\[^\\]') { return $path }
    }
}

$script:Folders = @{
    ProgramFiles    = Resolve-AdskFolder ([Environment]::GetFolderPath('ProgramFiles'))
    ProgramFilesX86 = Resolve-AdskFolder ([Environment]::GetFolderPath('ProgramFilesX86'))
    CommonFiles     = Resolve-AdskFolder ([Environment]::GetFolderPath('CommonProgramFiles'))
    CommonFilesX86  = Resolve-AdskFolder ([Environment]::GetFolderPath('CommonProgramFilesX86'))
    ProgramData     = Resolve-AdskFolder ([Environment]::GetFolderPath('CommonApplicationData')), $env:ProgramData
    Windows         = Resolve-AdskFolder ([Environment]::GetFolderPath('Windows')), $env:windir
}
$missingFolders = @('ProgramFiles', 'CommonFiles', 'ProgramData', 'Windows' | Where-Object { -not $script:Folders[$_] })
if ($missingFolders) {
    $message = "Required system folder(s) could not be resolved: $($missingFolders -join ', '). Nothing was changed."
    Write-AdskLog $message 'AutoDeskCleanRemove' -Severity Error
    Write-Warning $message
    exit 1
}

# Official step 3, plus Common Files\Autodesk (32- and 64-bit), where the Autodesk Desktop
# Platform components live.
$script:AdskProgramFolders = @(
    foreach ($pair in @(@('ProgramFiles', 'Autodesk'), @('CommonFiles', 'Autodesk Shared'), @('CommonFiles', 'Autodesk'),
                        @('ProgramFilesX86', 'Autodesk'), @('CommonFilesX86', 'Autodesk Shared'), @('CommonFilesX86', 'Autodesk'))) {
        if ($script:Folders[$pair[0]]) { Join-Path -Path $script:Folders[$pair[0]] -ChildPath $pair[1] }
    }
) | Select-Object -Unique
$script:AdskProgramData   = Join-Path -Path $script:Folders.ProgramData -ChildPath 'Autodesk'
$script:AdskUninstallers  = Join-Path -Path $script:AdskProgramData -ChildPath 'Uninstallers'
# Component key paths are compared without the drive (they may read 'C?\...'), so a root is the
# folder from its first backslash on.
$script:AdskPathRoots     = @(foreach ($folder in @($script:AdskProgramFolders) + $script:AdskProgramData) { $folder.Substring(2) + '\' })

$script:UninstallRoots    = @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
$script:InstallerUserData = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
$script:InstallerManaged  = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed'
$script:DeferredWorkDir   = Join-Path -Path $script:Folders.ProgramData -ChildPath 'ADSK-DeferredCleanup'
$script:DeferredTaskName  = 'ADSK-DeferredCleanup'

$script:Installer = $null
try { $script:Installer = New-Object -ComObject WindowsInstaller.Installer } catch { }

$script:BundleResults  = @{}
$script:MsiResults     = @{}
$script:ForcedCleanups = New-Object System.Collections.Generic.List[object]
# Files outside the Autodesk folders whose Windows Installer references a forced cleanup removed:
# path -> removed reference count, and whether no product references the file any more.
$script:ExternalFiles  = @{}
$script:InstallerIndex = $null
$script:RebootRequired = $false
# Set by anything that removed something, so the deferred task is registered - also under
# -WhatIf, where nothing is actually scheduled.
$script:WorkDone       = $false
$script:BackupFolder   = $null
$script:BackupCount    = 0

function Write-AdskProgress {
    param(
        [Parameter(Mandatory)][int]$Step,
        [Parameter(Mandatory)][string]$Status,
        [double]$Fraction = 0
    )
    $percent = [int][math]::Min(100, (($Step - 1) + $Fraction) / 5 * 100)
    Write-Progress -Activity 'Autodesk clean uninstall' -Status "Step $Step of 5: $Status" -PercentComplete $percent
}

function Get-AdskProfile {
    # Every profile Windows knows - users, the Default profile new users are created from, and the
    # service accounts installs may have run as - so residue of users who never sign in again is
    # found too.
    $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($key in Get-ChildItem -LiteralPath $profileList -ErrorAction SilentlyContinue) {
        $path = (Get-ItemProperty -LiteralPath $key.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if (-not $path) { continue }
        $path = [Environment]::ExpandEnvironmentVariables($path).TrimEnd('\')
        if ((Test-Path -LiteralPath $path -PathType Container) -and $seen.Add($path)) {
            [pscustomobject]@{ Path = $path; IsUser = $key.PSChildName -match '^S-1-5-21-[\d-]+$' }
        }
    }
    $default = (Get-ItemProperty -LiteralPath $profileList -Name Default -ErrorAction SilentlyContinue).Default
    if ($default) {
        $default = [Environment]::ExpandEnvironmentVariables($default).TrimEnd('\')
        if ((Test-Path -LiteralPath $default -PathType Container) -and $seen.Add($default)) {
            [pscustomobject]@{ Path = $default; IsUser = $false }
        }
    }
}

#endregion

#region Registry

function Open-AdskRegistryKey {
    # Paths in reg.exe notation (HKLM\..., HKU\...), opened through .NET: no provider caching, no
    # wildcard interpretation of names.
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Writable
    )
    $root, $rest = $Path -split '\\', 2
    $base = switch ($root) {
        'HKLM' { [Microsoft.Win32.Registry]::LocalMachine }
        'HKU'  { [Microsoft.Win32.Registry]::Users }
        default { throw "Unsupported registry root in '$Path'." }
    }
    $base.OpenSubKey($rest, [bool]$Writable)
}

function Test-AdskRegistryKey {
    param([Parameter(Mandatory)][string]$Path)
    $key = Open-AdskRegistryKey $Path
    if ($key) { $key.Dispose(); return $true }
    $false
}

function Get-AdskSubKeyName {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -eq 'HKU') { return [Microsoft.Win32.Registry]::Users.GetSubKeyNames() }
    $key = Open-AdskRegistryKey $Path
    if (-not $key) { return }
    try { $key.GetSubKeyNames() } finally { $key.Dispose() }
}

function Get-AdskRegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name
    )
    $key = Open-AdskRegistryKey $Path
    if (-not $key) { return }
    try { $key.GetValue($Name) } finally { $key.Dispose() }
}

function Test-AdskRegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    $key = Open-AdskRegistryKey $Path
    if (-not $key) { return $false }
    try { $key.GetValueNames() -contains $Name } finally { $key.Dispose() }
}

function Get-AdskBackupFolder {
    if (-not $script:BackupFolder) {
        $script:BackupFolder = $script:LogFile -replace '\.log$', '_RegistryBackup'
        New-Item -ItemType Directory -Path $script:BackupFolder -Force -ErrorAction Stop -WhatIf:$false | Out-Null
    }
    $script:BackupFolder
}

function Backup-AdskRegistryKey {
    # reg export of a key about to be deleted; a failed backup stops the deletion.
    param([Parameter(Mandatory)][string]$Path)
    $script:BackupCount++
    $leaf = ($Path -split '\\')[-1] -replace '[^\w{}.-]', '_'
    $file = Join-Path -Path (Get-AdskBackupFolder) -ChildPath ('{0:D4}_{1}.reg' -f $script:BackupCount, $leaf)
    $output = & reg.exe export $Path $file /y 2>&1
    if ($LASTEXITCODE -ne 0) { throw "reg export of '$Path' failed: $output" }
}

function Backup-AdskRegistryValue {
    # Single values removed from shared keys (component and upgrade-code references, SharedDLLs
    # counters) go into one file that restores them all with a double-click. $false for a value
    # type this does not write; the caller then backs up the whole key.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][Microsoft.Win32.RegistryValueKind]$Kind,
        $Data
    )
    $quote = { param($s) '"' + $s.Replace('\', '\\').Replace('"', '\"') + '"' }
    $value = switch ($Kind) {
        'String'       { & $quote ([string]$Data) }
        'ExpandString' { 'hex(2):' + (([Text.Encoding]::Unicode.GetBytes([string]$Data + [char]0) | ForEach-Object { '{0:x2}' -f $_ }) -join ',') }
        'DWord'        { 'dword:{0:x8}' -f [uint32]([int64]$Data -band 0xFFFFFFFF) }
        default        { return $false }
    }
    $file = Join-Path -Path (Get-AdskBackupFolder) -ChildPath 'RemovedValues.reg'
    $text = if (Test-Path -LiteralPath $file) { '' } else { "Windows Registry Editor Version 5.00`r`n" }
    $hive = $Path -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKU\\', 'HKEY_USERS\'
    $text += "`r`n[$hive]`r`n$(& $quote $Name)=$value`r`n"
    [IO.File]::AppendAllText($file, $text, [Text.Encoding]::Unicode)
    $true
}

function Remove-AdskRegistryTree {
    # Deletes a key with everything below it, after its backup. $true when the key is gone.
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Component = 'Registry'
    )
    if (-not (Test-AdskRegistryKey $Path)) { return $true }
    if (-not (Test-ShouldProcess -Target $Path -Action 'Delete registry key')) { return $false }
    $split = $Path.LastIndexOf('\')
    try {
        Backup-AdskRegistryKey $Path
        $parent = Open-AdskRegistryKey $Path.Substring(0, $split) -Writable
        try { $parent.DeleteSubKeyTree($Path.Substring($split + 1), $false) } finally { $parent.Dispose() }
        $script:WorkDone = $true
        Write-AdskLog "Removed registry key $Path" $Component
        return $true
    } catch {
        Write-AdskLog "Registry key $Path could not be removed: $($_.Exception.Message)" $Component -Severity Warning
        return $false
    }
}

function Remove-AdskRegistryValue {
    # Removes one value after its backup; -RemoveEmptyKey also deletes the key once nothing is
    # left in it. $true when the value is gone.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [switch]$RemoveEmptyKey,
        [string]$Component = 'Registry'
    )
    $key = Open-AdskRegistryKey $Path -Writable
    if (-not $key) { return $true }
    try {
        if ($key.GetValueNames() -notcontains $Name) { return $true }
        if (-not (Backup-AdskRegistryValue $Path $Name $key.GetValueKind($Name) $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames'))) {
            Backup-AdskRegistryKey $Path
        }
        $key.DeleteValue($Name)
        $empty = $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0
    } catch {
        Write-AdskLog "Value '$Name' in $Path could not be removed: $($_.Exception.Message)" $Component -Severity Warning
        return $false
    } finally {
        $key.Dispose()
    }
    $script:WorkDone = $true
    if ($RemoveEmptyKey -and $empty) {
        $split = $Path.LastIndexOf('\')
        $parent = Open-AdskRegistryKey $Path.Substring(0, $split) -Writable
        try { $parent.DeleteSubKey($Path.Substring($split + 1), $false) } catch { } finally { $parent.Dispose() }
    }
    $true
}

#endregion

#region Services and processes

# Anchored so unrelated software is not force-killed (an unanchored "Inventor" matched e.g.
# InventoryAgent). ADPClientService holds cer.dll and has no "Autodesk" in its name.
$script:AdskProcNamePattern = '^(Autodesk|Adsk|AutoCAD|acad|cer_service|dwgviewr|message_router|AdODIS|senddmp|ADPClientService)|^Inventor(Server)?$'

function Get-AdskServices {
    # Name is matched too: ADPSvc has no "Autodesk" in its DisplayName.
    @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match 'Autodesk' -or $_.DisplayName -match 'ADSK' -or $_.Name -match '^(Autodesk|Adsk)|^ADPSvc$'
    })
}

function Get-AdskProcesses {
    @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -match $script:AdskProcNamePattern -or $_.Description -match 'Autodesk'
    })
}

function Stop-AdskServiceHard {
    <#
        Stop a service and PROVE it stopped.

        Stop-Service blocks on the SCM and then gives up quietly when a service does not answer
        SERVICE_CONTROL_STOP - that is what "Waiting for service ... to stop" means. The hosting
        process survives, keeps its file handles, and the folder deletion later fails. So: disable
        it (the SCM must not restart it), request the stop without blocking, poll for the result,
        and if it is still running terminate the hosting process by PID and confirm.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutSeconds = 30
    )
    $result = [ordered]@{ Name = $Name; Stopped = $false; Killed = $false; Message = '' }

    if (-not (Test-ShouldProcess -Target "service $Name" -Action 'Disable and stop')) {
        $result.Message = 'skipped (WhatIf)'
        return [pscustomobject]$result
    }

    # disable first so the SCM cannot bring it straight back
    & sc.exe config $Name start= disabled 2>&1 | Out-Null

    # capture the PID BEFORE stopping - it reads 0 once the service reports stopped
    $servicePid = 0
    try { $servicePid = [int](Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop).ProcessId } catch { }

    # non-blocking stop request; Stop-Service would hang on an unresponsive service
    & sc.exe stop $Name 2>&1 | Out-Null

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $svc -or $svc.Status -eq 'Stopped') { $result.Stopped = $true; break }
    } while ((Get-Date) -lt $deadline)

    if (-not $result.Stopped -and $servicePid -gt 0) {
        try {
            Stop-Process -Id $servicePid -Force -ErrorAction Stop
            $result.Killed = $true
            Start-Sleep -Seconds 2
            $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if ($null -eq $svc -or $svc.Status -eq 'Stopped') { $result.Stopped = $true }
            $result.Message = "did not answer SERVICE_CONTROL_STOP after ${TimeoutSeconds}s; terminated hosting process PID $servicePid"
        } catch {
            $result.Message = "stop timed out and PID $servicePid could not be terminated: $($_.Exception.Message)"
        }
    } elseif (-not $result.Stopped) {
        $result.Message = "stop timed out after ${TimeoutSeconds}s and no hosting PID was available"
    }
    [pscustomobject]$result
}

function Invoke-AdskServiceAndProcessSweep {
    <#
        Stop every Autodesk service, then kill every Autodesk process, verifying both. Returns the
        number of Autodesk processes still running.

        Called more than once. Uninstallers routinely start their own services again on the way
        out, and anything still running at deletion time holds handles that make the folder
        removal fail - so this runs again immediately before the filesystem cleanup rather than
        only at the start.
    #>
    param([string]$Phase = 'initial')

    $lines    = New-Object System.Collections.Generic.List[string]
    $severity = 'Info'

    $services = Get-AdskServices
    if ($services.Count -eq 0) {
        $lines.Add('no Autodesk services present')
    } else {
        $lines.Add("found $($services.Count) service(s): $($services.Name -join ', ')")
        foreach ($svc in $services) {
            $stopResult = Stop-AdskServiceHard -Name $svc.Name
            if ($stopResult.Stopped -and -not $stopResult.Killed) {
                $lines.Add("stopped service $($svc.Name)")
            } elseif ($stopResult.Stopped) {
                $lines.Add("service $($svc.Name): $($stopResult.Message)")
                if ($severity -ne 'Error') { $severity = 'Warning' }
                Write-Host "Service $($svc.Name) ignored the stop request; its process was terminated." -ForegroundColor Yellow
            } elseif ($WhatIfPreference) {
                # nothing was attempted, so this is not a failure worth reporting
                $lines.Add("(WhatIf) would disable and stop service $($svc.Name)")
            } else {
                $lines.Add("service $($svc.Name) still running: $($stopResult.Message)")
                $severity = 'Error'
                Write-Host "Service $($svc.Name) could not be stopped: $($stopResult.Message)" -ForegroundColor Yellow
            }
        }
    }

    # processes AFTER services, so the SCM cannot respawn what we kill
    $remaining = Get-AdskProcesses
    if ($remaining.Count -gt 0) {
        $lines.Add("found $($remaining.Count) process(es): $(($remaining.ProcessName | Select-Object -Unique) -join ', ')")
    }
    foreach ($pass in 1..3) {
        if ($remaining.Count -eq 0) { break }
        foreach ($proc in $remaining) {
            if (-not (Test-ShouldProcess -Target "$($proc.ProcessName) (PID $($proc.Id))" -Action 'Terminate process')) { continue }
            try { Stop-Process -InputObject $proc -Force -ErrorAction Stop }
            catch {
                $lines.Add("could not stop $($proc.ProcessName) (PID $($proc.Id)) on pass ${pass}: $($_.Exception.Message)")
                $severity = 'Error'
            }
        }
        if ($WhatIfPreference) { break }
        Start-Sleep -Seconds 2
        $remaining = Get-AdskProcesses
    }
    if ($remaining.Count -gt 0 -and $WhatIfPreference) {
        # -WhatIf killed nothing, so "still running" is expected and not a finding
        $lines.Add("(WhatIf) would terminate $($remaining.Count) process(es)")
    } elseif ($remaining.Count -gt 0) {
        $stillRunning = ($remaining.ProcessName | Select-Object -Unique) -join ', '
        $lines.Add("still running after 3 passes: $stillRunning")
        $severity = 'Error'
        Write-Host "Still running after 3 attempts: $stillRunning. These hold file handles; a reboot and second run will be required." -ForegroundColor Yellow
    } else {
        $lines.Add('no Autodesk processes remain')
    }

    Write-AdskLog ("Autodesk service/process sweep (${Phase}):`r`n  " + ($lines -join "`r`n  ")) -Component 'Sweep' -Severity $severity
    return $remaining.Count
}

function Remove-AdskService {
    <#
        Deletes Autodesk services the uninstallers left registered (eg. ADPSvc, pointing at a
        binary that is about to be deleted). The Genuine Service's own service is left to its
        uninstall in step 5 unless -IncludeGenuine.
    #>
    param([switch]$IncludeGenuine)
    foreach ($svc in Get-AdskServices) {
        if (-not $IncludeGenuine -and ($svc.Name -match 'Genuine' -or $svc.DisplayName -match 'Genuine')) { continue }
        if (-not (Test-ShouldProcess -Target "service $($svc.Name)" -Action 'Delete')) { continue }
        $output = & sc.exe delete $svc.Name 2>&1
        # 1072: already marked for deletion, completed once its last handle closes
        if ($LASTEXITCODE -in 0, 1072) {
            $script:WorkDone = $true
            Write-AdskLog "Deleted service $($svc.Name) ($($svc.DisplayName))." 'Sweep'
        } else {
            Write-AdskStatus "Service $($svc.Name) could not be deleted: $output" 'Sweep' -Severity Warning
        }
    }
}

#endregion

#region Windows Installer

function ConvertTo-PackedGuid {
    # {GUID} <-> the packed form Windows Installer uses in the registry: the first three groups
    # reversed whole, the remaining bytes nibble-swapped. The transformation is its own inverse,
    # so a packed code passed in returns the plain hex of the GUID. $null for a malformed value.
    param([Parameter(Mandatory)][string]$Guid)
    $hex = $Guid.Trim('{}') -replace '-'
    if ($hex -notmatch '^[0-9A-Fa-f]{32}$') { return $null }
    $reverse = { param($s) -join $s[($s.Length - 1)..0] }
    $packed = (& $reverse $hex.Substring(0, 8)) + (& $reverse $hex.Substring(8, 4)) + (& $reverse $hex.Substring(12, 4))
    for ($i = 16; $i -lt 32; $i += 2) { $packed += "$($hex[$i + 1])$($hex[$i])" }
    $packed.ToUpper()
}

function ConvertFrom-PackedGuid {
    param([Parameter(Mandatory)][string]$Packed)
    $hex = ConvertTo-PackedGuid $Packed
    if (-not $hex) { return $null }
    '{{{0}-{1}-{2}-{3}-{4}}}' -f $hex.Substring(0, 8), $hex.Substring(8, 4), $hex.Substring(12, 4), $hex.Substring(16, 4), $hex.Substring(20, 12)
}

function Get-AdskComProperty {
    # Parameterized properties of the WindowsInstaller COM objects (ProductsEx, ProductState,
    # InstallProperty, StringData) are not reachable through PowerShell's property syntax.
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        [object[]]$Arguments = @()
    )
    $Object.GetType().InvokeMember($Name, [Reflection.BindingFlags]::GetProperty, $null, $Object, $Arguments)
}

function Invoke-AdskComMethod {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        [object[]]$Arguments = @()
    )
    $Object.GetType().InvokeMember($Name, [Reflection.BindingFlags]::InvokeMethod, $null, $Object, $Arguments)
}

function Test-AdskPublisher {
    param($Product)
    ("$($Product.Publisher)" -match '^Autodesk') -or ("$($Product.Name)" -match '^Autodesk')
}

function Get-AdskProductState {
    # Windows Installer's own view: 5 installed, 1 advertised, 2 installed for another user,
    # -1 unknown. $null when Windows Installer cannot be queried.
    param([Parameter(Mandatory)][string]$ProductCode)
    if (-not $script:Installer) { return $null }
    try { [int](Get-AdskComProperty $script:Installer 'ProductState' @($ProductCode)) } catch { $null }
}

function Get-AdskRegisteredProduct {
    <#
        Every product Windows Installer has registered, in any context and for any user, with the
        properties used to attribute it to Autodesk. Never Win32_Product: querying it runs a
        consistency check on every installed product and can trigger repairs.
    #>
    if (-not $script:Installer) { throw 'the WindowsInstaller.Installer COM object is not available' }
    $products = Get-AdskComProperty $script:Installer 'ProductsEx' @('', 's-1-1-0', 7)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($product in $products) {
        $code = [string](Get-AdskComProperty $product 'ProductCode')
        if (-not $seen.Add($code)) { continue }
        $info = @{}
        foreach ($name in 'ProductName', 'Publisher') {
            try { $info[$name] = [string](Get-AdskComProperty $product 'InstallProperty' @($name)) } catch { $info[$name] = '' }
        }
        [pscustomobject]@{ ProductCode = $code.ToUpper(); Name = $info.ProductName; Publisher = $info.Publisher }
    }
}

function Get-AdskBundle {
    # The bundles under Uninstallers with their MSI product codes (packageType 0) in reverse
    # install order, and a sort class: Object Enablers first, updates next, products last.
    # PackageCodes are the bundle's ODIS packages (packageType 4): listed by their packed code,
    # they may have component registrations but no product registration; only the ODIS bundle
    # uninstall removes them, and the forced cleanup what a failed one left registered.
    foreach ($folder in Get-ChildItem -LiteralPath $script:AdskUninstallers -Directory -ErrorAction SilentlyContinue) {
        $bundleFile = Join-Path -Path $folder.FullName -ChildPath 'bundle_data.xml'
        if (-not (Test-Path -LiteralPath $bundleFile)) { continue }
        try {
            $xml = [xml](Get-Content -LiteralPath $bundleFile -Raw -ErrorAction Stop)
        } catch {
            Write-AdskStatus "Bundle data of $($folder.Name) could not be parsed ($($_.Exception.Message)); its products are still found through Windows Installer." 'Discovery' -Severity Warning
            continue
        }
        $codes    = New-Object System.Collections.Generic.List[string]
        $packages = New-Object System.Collections.Generic.List[string]
        foreach ($item in $xml.SelectNodes('//bundleData//m_packages/item')) {
            if ("$($item.m_productCode)" -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { continue }
            switch ([int]$item.m_packageType) {
                0 { $codes.Add("$($item.m_productCode)".ToUpper()) }
                4 { $packages.Add((ConvertFrom-PackedGuid "$($item.m_productCode)")) }
            }
        }
        $codes.Reverse()
        $class = if ($folder.Name -match 'Enabler') { 0 } elseif ($folder.Name -match 'Update|SP\d+(\.\d+)?|20\d{2}\.\d+(\.\d+)?') { 1 } else { 2 }
        [pscustomobject]@{ Name = $folder.Name; Class = $class; ProductCodes = $codes.ToArray(); PackageCodes = $packages.ToArray() }
    }
}

function Get-AdskUninstallEntry {
    # Autodesk entries in Programs and Features (both registry views): MSI products, and the ODIS
    # and uninstall-helper entries that have no Windows Installer registration.
    foreach ($root in $script:UninstallRoots) {
        foreach ($key in Get-ChildItem -LiteralPath "HKLM:\$root" -ErrorAction SilentlyContinue) {
            $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if (-not $properties -or -not ("$($properties.Publisher)" -match '^Autodesk' -or "$($properties.DisplayName)" -match '^Autodesk')) { continue }
            [pscustomobject]@{
                Path            = "HKLM\$root\$($key.PSChildName)"
                Code            = $key.PSChildName.ToUpper()
                Name            = [string]$properties.DisplayName
                IsMsi           = ($properties.WindowsInstaller -eq 1)
                IsGenuine       = ("$($properties.DisplayName)" -like 'Autodesk Genuine Service*')
                UninstallString = [string]$properties.UninstallString
                SizeKB          = [int64]("0$($properties.EstimatedSize)" -replace '\D')
            }
        }
    }
}

function Get-AdskUninstallOrder {
    <#
        Uninstall order of the Autodesk products found: products of one bundle only, by bundle
        (Object Enablers, updates, products) in reverse install order; then products that belong
        to no bundle (eg. Personal Accelerator for Revit); components several bundles share (CER,
        Interoperability Engine) last, once nothing depends on them any more.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Bundles,
        [Parameter(Mandatory)][hashtable]$Products
    )
    $sortedBundles = @($Bundles | Sort-Object Class, Name)
    $bundleCount = @{}
    foreach ($bundle in $Bundles) {
        foreach ($code in @($bundle.ProductCodes | Select-Object -Unique)) { $bundleCount[$code] = 1 + [int]$bundleCount[$code] }
    }
    $added = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($bundle in $sortedBundles) {
        foreach ($code in $bundle.ProductCodes) {
            if ($bundleCount[$code] -eq 1 -and $Products.ContainsKey($code) -and $added.Add($code)) { $code }
        }
    }
    $unbundled = $Products.Values | Where-Object { -not $bundleCount.ContainsKey($_.ProductCode) } |
        Sort-Object @{ Expression = { if ($_.Name -match 'Enabler') { 0 } elseif ($_.Name -match 'Update') { 1 } else { 2 } } }, Name
    foreach ($product in $unbundled) {
        if ($added.Add($product.ProductCode)) { $product.ProductCode }
    }
    foreach ($bundle in $sortedBundles) {
        foreach ($code in $bundle.ProductCodes) {
            if ($bundleCount[$code] -gt 1 -and $Products.ContainsKey($code) -and $added.Add($code)) { $code }
        }
    }
}

function Get-AdskBundleUninstall {
    <#
        The ODIS uninstall command of every Autodesk bundle in Programs and Features - exactly what
        Programs and Features starts - Object Enablers first, then updates, then products. Only
        bundle manifests: Autodesk Access (a package manifest) is left to its own remover.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)
    $installer = Join-Path -Path $script:Folders.ProgramFiles -ChildPath 'Autodesk\AdODIS\V1\Installer.exe'
    $bundles = foreach ($entry in $Entries) {
        if ($entry.IsMsi -or $entry.UninstallString -notmatch '^"?(?<exe>[^"]*\\Installer\.exe)"?\s+(?<args>.*)$') { continue }
        $arguments = $Matches['args']
        if ($Matches['exe'] -ne $installer -or $arguments -notmatch '(^|\s)-i uninstall(\s|$)' -or $arguments -notmatch 'bundleManifest\.xml') { continue }
        $class = if ($entry.Name -match 'Enabler') { 0 } elseif ($entry.Name -match 'Update|SP\d+(\.\d+)?|20\d{2}\.\d+(\.\d+)?') { 1 } else { 2 }
        [pscustomobject]@{ Name = $entry.Name; Code = $entry.Code; Class = $class; FilePath = $installer; Arguments = "$arguments -q"; SizeKB = $entry.SizeKB }
    }
    @($bundles | Sort-Object Class, Name)
}

function Invoke-AdskBundleUninstall {
    <#
        Uninstalls one ODIS bundle silently, the way Programs and Features does. ODIS removes the
        bundle's MSI products and its ODIS packages, which have no Windows Installer product, with
        their shortcuts, file associations, firewall rules and COM servers. It takes minutes per
        bundle. Its own per-package summary is copied into this log.
    #>
    param(
        [Parameter(Mandatory)][object]$Bundle,
        [int]$TimeoutMinutes = 60
    )
    $log   = @{ Component = 'BundleUninstall' }
    $label = "$($Bundle.Name) $($Bundle.Code)"
    if (-not (Test-ShouldProcess -Target "ODIS bundle $label" -Action 'Uninstall')) {
        return [pscustomobject]@{ Outcome = 'Skipped'; ExitCode = $null }
    }

    $summaryLog  = Join-Path -Path ([Environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'Autodesk\ODIS\Summary.log'
    $summaryFrom = if (Test-Path -LiteralPath $summaryLog) { (Get-Item -LiteralPath $summaryLog).Length } else { 0 }
    Write-AdskLog "Uninstalling ${label}: `"$($Bundle.FilePath)`" $($Bundle.Arguments)" @log
    $started = Get-Date
    try {
        $process = Start-Process -FilePath $Bundle.FilePath -ArgumentList $Bundle.Arguments -PassThru -ErrorAction Stop
    } catch {
        Write-AdskStatus "The ODIS uninstall of $label could not be started: $($_.Exception.Message)" 'BundleUninstall' -Severity Error
        return [pscustomobject]@{ Outcome = 'Failed'; ExitCode = $null }
    }
    # PS 5.1 loses the exit code of a -PassThru process unless its handle is opened while it runs
    $null = $process.Handle
    $script:WorkDone = $true
    $exitCode = $null
    if ($process.WaitForExit($TimeoutMinutes * 60000)) {
        $exitCode = $process.ExitCode
    } else {
        $odis = Split-Path -Path $Bundle.FilePath -Parent
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($odis, [StringComparison]::OrdinalIgnoreCase) } | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-AdskStatus "The ODIS uninstall of $label did not finish within $TimeoutMinutes minutes and was stopped." 'BundleUninstall' -Severity Error
    }

    if (Test-Path -LiteralPath $summaryLog) {
        try {
            $stream = [IO.File]::Open($summaryLog, 'Open', 'Read', 'ReadWrite')
            try {
                if ($stream.Length -ge $summaryFrom) { [void]$stream.Seek($summaryFrom, 'Begin') }
                $summary = (New-Object IO.StreamReader($stream)).ReadToEnd().Trim()
            } finally { $stream.Dispose() }
            if ($summary) { Write-AdskLog "ODIS summary for ${label}:`r`n{`r`n$summary`r`n}" @log }
        } catch {
            Write-AdskLog "The ODIS summary log could not be read: $($_.Exception.Message)" @log -Severity Warning
        }
    }

    $duration = [int]((Get-Date) - $started).TotalSeconds
    $outcome = switch ($exitCode) {
        0       { 'Removed'; Write-AdskLog "Uninstalled $label (exit 0, ${duration}s)." @log }
        3010    { 'RebootRequired'; $script:RebootRequired = $true; Write-AdskLog "Uninstalled $label; restart required (exit 3010, ${duration}s)." @log -Severity Warning }
        $null   { 'Failed' }
        default {
            'Failed'
            Write-AdskStatus "The ODIS uninstall of $label failed (exit $exitCode, ${duration}s); its products are uninstalled one by one." 'BundleUninstall' -Severity Error
        }
    }
    [pscustomobject]@{ Outcome = $outcome; ExitCode = $exitCode }
}

function Get-AdskDurationEstimate {
    <#
        Rough duration of the whole run from what is installed. ODIS time grows with the size of a
        bundle (its Programs and Features size); calibrated on 5 bundles with 30.5 GB that took 45
        minutes, plus about 5 minutes for everything else. Single bundles vary up to threefold -
        the one that is the last user of shared components pays for removing them - so the result
        is a range.

        ODIS records no usable size of its own (the manifest only has the setup payload), so a
        bundle without a Programs and Features size counts as the median of the bundles here that
        have one, or $defaultGB if none has; the upper bound then widens. Windows Installer always
        records the size of an MSI product; only a broken registration lacks it, and that is
        force-cleaned in seconds.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Bundles,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$MsiProducts
    )
    $minutesPerGB = 1.5
    $msiMinutes   = 0.5
    $fixedMinutes = 5
    $defaultGB    = 5
    $known = @($Bundles | Where-Object { $_.SizeKB -gt 0 } | ForEach-Object { $_.SizeKB / 1MB } | Sort-Object)
    $fallbackGB = if ($known.Count) { ($known[[math]::Floor(($known.Count - 1) / 2)] + $known[[math]::Ceiling(($known.Count - 1) / 2)]) / 2 } else { $defaultGB }
    $unsized = @($Bundles | Where-Object { -not ($_.SizeKB -gt 0) }).Count
    $sizeGB = ($known | Measure-Object -Sum).Sum + $unsized * $fallbackGB
    foreach ($product in $MsiProducts) { $sizeGB += $product.SizeKB / 1MB }
    $minutes = $fixedMinutes + $sizeGB * $minutesPerGB + $MsiProducts.Count * $msiMinutes
    [pscustomobject]@{
        Minutes    = [int][math]::Round($minutes)
        Low        = [int]([math]::Max(5, [math]::Floor($minutes * 0.7 / 5) * 5))
        High       = [int]([math]::Ceiling($minutes * $(if ($unsized) { 2 } else { 1.5 }) / 5) * 5)
        SizeGB     = [math]::Round($sizeGB, 1)
        Unsized    = $unsized
        FallbackGB = [math]::Round($fallbackGB, 1)
    }
}

function Find-AdskMsiSource {
    # The original .msi of a product whose cached copy is gone: the PackageName of its SourceList,
    # looked for in every registered network/local source, accepted only if its ProductCode
    # matches.
    param([Parameter(Mandatory)][string]$ProductCode)
    if (-not $script:Installer) { return }
    $sourceList = "HKLM\SOFTWARE\Classes\Installer\Products\$(ConvertTo-PackedGuid $ProductCode)\SourceList"
    $package = Get-AdskRegistryValue $sourceList 'PackageName'
    if (-not $package) { return }
    $netKey = Open-AdskRegistryKey "$sourceList\Net"
    if (-not $netKey) { return }
    try { $sources = @(foreach ($name in $netKey.GetValueNames()) { [string]$netKey.GetValue($name) }) } finally { $netKey.Dispose() }
    foreach ($source in $sources) {
        $candidate = Join-Path -Path ([Environment]::ExpandEnvironmentVariables($source)) -ChildPath $package
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try {
            $database = Invoke-AdskComMethod $script:Installer 'OpenDatabase' @($candidate, 0)
            $view = Invoke-AdskComMethod $database 'OpenView' @("SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductCode'")
            [void](Invoke-AdskComMethod $view 'Execute')
            $record = Invoke-AdskComMethod $view 'Fetch'
            $code = if ($record) { [string](Get-AdskComProperty $record 'StringData' @(1)) }
            [void](Invoke-AdskComMethod $view 'Close')
            if ($code -eq $ProductCode) { return $candidate }
        } catch { }
    }
}

function Add-AdskMsiLog {
    # Failure lines always reach the main log; the full MSI log is embedded at -LogLevel Verbose.
    # The file is kept unless it was embedded and the uninstall succeeded.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [switch]$Failed
    )
    $log = @{ Component = 'MsiUninstall' }
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-AdskLog "MSI log not found for $Label" @log
        return
    }
    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($content)) {
        Write-AdskLog "MSI log is empty for $Label" @log
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue -WhatIf:$false
        return
    }
    if ($Failed) {
        $tail = ($content -split '\r?\n') -match 'Return value 3|MainEngineThread is returning|Error \d{4}' | Select-Object -Last 20
        if ($tail) { Write-AdskLog "MSI failure detail for ${Label}:`r`n$($tail -join "`r`n")" -Severity Error @log }
    }
    if ($script:LogRank -ge 4) {
        Write-AdskLog "MSI log for ${Label}:`r`n{`r`n$($content.TrimEnd())`r`n}" -Severity Verbose @log
        if (-not $Failed) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue -WhatIf:$false
            return
        }
    }
    Write-AdskLog "MSI log for $Label kept at $Path" @log
}

function Invoke-AdskMsiUninstall {
    <#
        Uninstalls one MSI product and returns its outcome (Removed, RebootRequired, NotInstalled,
        Failed or Skipped) with the exit code. 1618 - another installation is running - is waited
        out; 1612/1620 - the cached package is gone - is retried once with the original package if
        its source is still reachable. Anything else that fails is left to the forced
        registration cleanup.
    #>
    param(
        [Parameter(Mandatory)][string]$ProductCode,
        [Parameter(Mandatory)][string]$Name
    )
    $log   = @{ Component = 'MsiUninstall' }
    $label = "$Name $ProductCode"
    if (-not (Test-ShouldProcess -Target "MSI product $label" -Action 'Uninstall')) {
        return [pscustomobject]@{ Outcome = 'Skipped'; ExitCode = $null }
    }

    $target = $ProductCode
    for ($attempt = 1; ; $attempt++) {
        $msiLog    = Join-Path -Path $script:MsiLogPath -ChildPath "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')_$($ProductCode.Trim('{}'))_MSIUninstall.log"
        $arguments = "/x `"$target`" /qn /norestart REBOOT=ReallySuppress /l*v `"$msiLog`""
        Write-AdskLog "Uninstalling ${label}: msiexec $arguments" @log
        $exitCode = (Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru).ExitCode
        $script:WorkDone = $true
        Add-AdskMsiLog -Path $msiLog -Label $label -Failed:($exitCode -notin 0, 1605, 1641, 3010)

        if ($exitCode -eq 1618 -and $attempt -le 10) {
            Write-AdskLog "Another installation is in progress (1618); retrying $label in 30 seconds ($attempt of 10)." @log -Severity Warning
            Start-Sleep -Seconds 30
            continue
        }
        if ($exitCode -in 1612, 1620 -and $target -eq $ProductCode) {
            $source = Find-AdskMsiSource -ProductCode $ProductCode
            if ($source) {
                Write-AdskLog "The cached package of $label is missing ($exitCode); retrying with the original package $source." @log -Severity Warning
                $target = $source
                continue
            }
        }
        break
    }

    $outcome = switch ($exitCode) {
        0       { 'Removed'; Write-AdskLog "Uninstalled $label (exit 0)." @log }
        3010    { 'RebootRequired'; $script:RebootRequired = $true; Write-AdskLog "Uninstalled $label; restart required (exit 3010)." @log -Severity Warning }
        1641    { 'RebootRequired'; $script:RebootRequired = $true; Write-AdskLog "Uninstalled $label; restart initiated by the package was suppressed (exit 1641)." @log -Severity Warning }
        1605    { 'NotInstalled'; Write-AdskLog "$label is not installed (exit 1605)." @log }
        default {
            'Failed'
            Write-AdskStatus "Uninstall of $label failed (msiexec exit $exitCode); its registration is cleaned up after the removers." 'MsiUninstall' -Severity Error
        }
    }
    [pscustomobject]@{ Outcome = $outcome; ExitCode = $exitCode }
}

function Test-AdskPathReference {
    # A component key path: a file ('C:\...', or 'C?\...' when not installed locally) or a
    # registry key ('02:\SOFTWARE\...'). True when it lies in an Autodesk folder or key.
    param([AllowEmptyString()][string]$Data)
    if ($Data -match '^\d\d:\\SOFTWARE\\(WOW6432Node\\)?Autodesk(\\|$)') { return $true }
    if ($Data -notmatch '^[A-Za-z][:?](\\.*)$') { return $false }
    $relative = $Matches[1]
    foreach ($root in $script:AdskPathRoots) {
        if ($relative.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

function Get-AdskInstallerIndex {
    <#
        One pass over Windows Installer's registry store: for every packed product code the
        component keys referencing it (and whether those point into Autodesk folders or not), the
        upgrade codes listing it, its registered properties (UserData) and the names on product
        keys. This is what finds registrations without a complete product behind them, and it lets
        the forced cleanup remove exactly the product's own values from shared keys.
    #>
    $hklm          = [Microsoft.Win32.Registry]::LocalMachine
    $components    = @{}
    $upgradeCodes  = @{}
    $products      = @{}
    $classProducts = @{}
    $adskRefs  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $otherRefs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    $userData = $hklm.OpenSubKey($script:InstallerUserData)
    if ($userData) {
        try {
            foreach ($sid in $userData.GetSubKeyNames()) {
                $componentRoot = $userData.OpenSubKey("$sid\Components")
                if ($componentRoot) {
                    try {
                        foreach ($component in $componentRoot.GetSubKeyNames()) {
                            $key = $componentRoot.OpenSubKey($component)
                            if (-not $key) { continue }
                            try {
                                foreach ($value in $key.GetValueNames()) {
                                    # 32 zeros marks a permanent component, not a product
                                    if ($value.Length -ne 32 -or $value -eq '00000000000000000000000000000000') { continue }
                                    if (-not $components.ContainsKey($value)) { $components[$value] = New-Object System.Collections.Generic.List[string] }
                                    $components[$value].Add("$sid\Components\$component")
                                    # registry key paths (eg. a Run entry) say nothing about who owns the files
                                    $data = [string]$key.GetValue($value)
                                    if (Test-AdskPathReference $data) { [void]$adskRefs.Add($value) }
                                    elseif ($data -notmatch '^\d\d:') { [void]$otherRefs.Add($value) }
                                }
                            } finally { $key.Dispose() }
                        }
                    } finally { $componentRoot.Dispose() }
                }
                $productRoot = $userData.OpenSubKey("$sid\Products")
                if ($productRoot) {
                    try {
                        foreach ($packed in $productRoot.GetSubKeyNames()) {
                            if ($products.ContainsKey($packed)) { continue }
                            $properties = $productRoot.OpenSubKey("$packed\InstallProperties")
                            $entry = [pscustomobject]@{ Name = ''; Publisher = '' }
                            if ($properties) {
                                try {
                                    $entry.Name = [string]$properties.GetValue('DisplayName')
                                    $entry.Publisher = [string]$properties.GetValue('Publisher')
                                } finally { $properties.Dispose() }
                            }
                            $products[$packed] = $entry
                        }
                    } finally { $productRoot.Dispose() }
                }
            }
        } finally { $userData.Dispose() }
    }

    $upgradeRoot = $hklm.OpenSubKey('SOFTWARE\Classes\Installer\UpgradeCodes')
    if ($upgradeRoot) {
        try {
            foreach ($upgrade in $upgradeRoot.GetSubKeyNames()) {
                $key = $upgradeRoot.OpenSubKey($upgrade)
                if (-not $key) { continue }
                try {
                    foreach ($value in $key.GetValueNames()) {
                        if ($value.Length -ne 32) { continue }
                        if (-not $upgradeCodes.ContainsKey($value)) { $upgradeCodes[$value] = New-Object System.Collections.Generic.List[string] }
                        $upgradeCodes[$value].Add($upgrade)
                    }
                } finally { $key.Dispose() }
            }
        } finally { $upgradeRoot.Dispose() }
    }

    $classRoot = $hklm.OpenSubKey('SOFTWARE\Classes\Installer\Products')
    if ($classRoot) {
        try {
            foreach ($packed in $classRoot.GetSubKeyNames()) {
                $key = $classRoot.OpenSubKey($packed)
                if (-not $key) { continue }
                try { $classProducts[$packed] = [string]$key.GetValue('ProductName') } finally { $key.Dispose() }
            }
        } finally { $classRoot.Dispose() }
    }

    [pscustomobject]@{
        Components    = $components
        UpgradeCodes  = $upgradeCodes
        Products      = $products
        ClassProducts = $classProducts
        AdskRefs      = $adskRefs
        OtherRefs     = $otherRefs
    }
}

function Get-AdskProductKeyPath {
    # Every registry key that belongs to exactly one product, in reg.exe notation: product,
    # feature and dependency keys, UserData of every SID, managed and per-user registrations,
    # and the Uninstall entries.
    param(
        [Parameter(Mandatory)][string]$ProductCode,
        [Parameter(Mandatory)][string]$Packed
    )
    "HKLM\SOFTWARE\Classes\Installer\Products\$Packed"
    "HKLM\SOFTWARE\Classes\Installer\Features\$Packed"
    "HKLM\SOFTWARE\Classes\Installer\Dependencies\$ProductCode"
    foreach ($sid in Get-AdskSubKeyName "HKLM\$script:InstallerUserData") { "HKLM\$script:InstallerUserData\$sid\Products\$Packed" }
    foreach ($sid in Get-AdskSubKeyName "HKLM\$script:InstallerManaged") {
        "HKLM\$script:InstallerManaged\$sid\Installer\Products\$Packed"
        "HKLM\$script:InstallerManaged\$sid\Installer\Features\$Packed"
    }
    foreach ($sid in Get-AdskSubKeyName 'HKU' | Where-Object { $_ -notlike '*_Classes' }) {
        "HKU\$sid\Software\Microsoft\Installer\Products\$Packed"
        "HKU\$sid\Software\Microsoft\Installer\Features\$Packed"
    }
    foreach ($root in $script:UninstallRoots) { "HKLM\$root\$ProductCode" }
}

function Get-AdskMsiResidue {
    # What Windows Installer still has of one product - its own state, keys, upgrade-code and
    # component references - read fresh from the system, never from what the cleanup did.
    param(
        [Parameter(Mandatory)][string]$ProductCode,
        $Index
    )
    $packed = ConvertTo-PackedGuid $ProductCode
    if (-not $packed) { return }
    $state = Get-AdskProductState $ProductCode
    if ($state -in 1, 2, 5) { "registered (Windows Installer state $state)" }
    foreach ($key in Get-AdskProductKeyPath $ProductCode $packed) {
        if (Test-AdskRegistryKey $key) { $key }
    }
    if ($Index) {
        foreach ($upgrade in $Index.UpgradeCodes[$packed]) {
            if (Test-AdskRegistryValue "HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\$upgrade" $packed) { "upgrade code $upgrade" }
        }
        $references = @($Index.Components[$packed] | Where-Object { Test-AdskRegistryValue "HKLM\$script:InstallerUserData\$_" $packed }).Count
        if ($references) { "$references component reference(s)" }
    }
}

function Test-AdskPatchInUse {
    param(
        [Parameter(Mandatory)][string]$Patch,
        [Parameter(Mandatory)][string]$ExceptProduct
    )
    foreach ($sid in Get-AdskSubKeyName "HKLM\$script:InstallerUserData") {
        foreach ($product in Get-AdskSubKeyName "HKLM\$script:InstallerUserData\$sid\Products") {
            if ($product -ne $ExceptProduct -and (Test-AdskRegistryKey "HKLM\$script:InstallerUserData\$sid\Products\$product\Patches\$Patch")) { return $true }
        }
    }
    $false
}

function Remove-AdskMsiRegistration {
    <#
        Forced cleanup of one product's Windows Installer registration, the scope of Microsoft's
        Program Install and Uninstall troubleshooter: its own value in every component and
        upgrade-code key (a key shared with other products keeps their values), the product,
        feature, dependency, UserData, managed, per-user and Uninstall keys, patches no other
        product uses, and the cached .msi/.msp files. Everything is backed up before it is
        deleted. Returns the residue left afterwards (nothing when the cleanup is complete).
    #>
    param(
        [Parameter(Mandatory)][string]$ProductCode,
        [Parameter(Mandatory)]$Index
    )
    $component = 'InstallerCleanup'
    $packed  = ConvertTo-PackedGuid $ProductCode
    $files   = New-Object System.Collections.Generic.List[string]
    $patches = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $userDataSids = @(Get-AdskSubKeyName "HKLM\$script:InstallerUserData")

    # read before anything is deleted: the cached package and the patches of the product
    foreach ($sid in $userDataSids) {
        $product = "HKLM\$script:InstallerUserData\$sid\Products\$packed"
        if (-not (Test-AdskRegistryKey $product)) { continue }
        $localPackage = Get-AdskRegistryValue "$product\InstallProperties" 'LocalPackage'
        if ($localPackage) { $files.Add([string]$localPackage) }
        foreach ($patch in Get-AdskSubKeyName "$product\Patches") { [void]$patches.Add($patch) }
    }

    $removedValues = 0
    foreach ($reference in $Index.Components[$packed]) {
        $componentKey = "HKLM\$script:InstallerUserData\$reference"
        $keyPath = [string](Get-AdskRegistryValue $componentKey $packed)
        if (-not (Remove-AdskRegistryValue $componentKey $packed -RemoveEmptyKey -Component $component)) { continue }
        $removedValues++
        # Files inside the Autodesk folders go with the folder deletion. Elsewhere (eg. System32)
        # the removed references are counted for Remove-AdskExternalFile, which settles the file's
        # SharedDLLs counter and deletes it once nobody owns it any more.
        if ($keyPath -match '^[A-Za-z]:\\' -and -not (Test-AdskPathReference $keyPath)) {
            if (-not $script:ExternalFiles.ContainsKey($keyPath)) { $script:ExternalFiles[$keyPath] = [pscustomobject]@{ Removed = 0; Orphaned = $false } }
            $script:ExternalFiles[$keyPath].Removed++
            if (-not (Test-AdskRegistryKey $componentKey)) { $script:ExternalFiles[$keyPath].Orphaned = $true }
        }
    }
    foreach ($upgrade in $Index.UpgradeCodes[$packed]) {
        if (Remove-AdskRegistryValue "HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\$upgrade" $packed -RemoveEmptyKey -Component $component) { $removedValues++ }
    }
    foreach ($key in Get-AdskProductKeyPath $ProductCode $packed) {
        [void](Remove-AdskRegistryTree $key -Component $component)
    }
    foreach ($patch in $patches) {
        if (Test-AdskPatchInUse -Patch $patch -ExceptProduct $packed) { continue }
        foreach ($sid in $userDataSids) {
            $patchKey = "HKLM\$script:InstallerUserData\$sid\Patches\$patch"
            if (-not (Test-AdskRegistryKey $patchKey)) { continue }
            $localPackage = Get-AdskRegistryValue $patchKey 'LocalPackage'
            if ($localPackage) { $files.Add([string]$localPackage) }
            [void](Remove-AdskRegistryTree $patchKey -Component $component)
        }
        [void](Remove-AdskRegistryTree "HKLM\SOFTWARE\Classes\Installer\Patches\$patch" -Component $component)
    }

    # only files in Windows Installer's own cache, never a path read from the registry elsewhere
    $installerCache = Join-Path -Path $script:Folders.Windows -ChildPath 'Installer'
    foreach ($file in @($files) + (Join-Path -Path $installerCache -ChildPath $ProductCode)) {
        if (-not $file.StartsWith("$installerCache\", [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $file)) { continue }
        Remove-Item -LiteralPath $file -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $file) { Write-AdskLog "Cached file $file could not be deleted." $component -Severity Warning }
        else { Write-AdskLog "Deleted cached file $file" $component }
    }
    Write-AdskLog "Removed $removedValues component/upgrade-code reference(s) of $ProductCode." $component

    Get-AdskMsiResidue -ProductCode $ProductCode -Index $Index
}

function Get-AdskLeftoverProduct {
    <#
        Products Windows Installer still knows, fully or partly, that belong to Autodesk: registered
        with an Autodesk publisher or name, a product key named Autodesk without a registration, a
        known Autodesk product code with anything left, or component references whose files all
        lie in Autodesk folders. A product registered by another publisher is never
        selected, even when it put files into an Autodesk folder (eg. a third-party add-in); it is
        reported instead. Returns product code -> name.
    #>
    param(
        [Parameter(Mandatory)]$Index,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$KnownCodes,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Exclude,
        [hashtable]$Names = @{}
    )
    $log = @{ Component = 'InstallerCleanup' }
    $candidates = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($packed in $Index.Products.Keys) { if (Test-AdskPublisher $Index.Products[$packed]) { [void]$candidates.Add($packed) } }
    foreach ($packed in $Index.ClassProducts.Keys) { if ($Index.ClassProducts[$packed] -match '^Autodesk') { [void]$candidates.Add($packed) } }
    foreach ($code in $KnownCodes) { $packed = ConvertTo-PackedGuid $code; if ($packed) { [void]$candidates.Add($packed) } }
    foreach ($packed in $Index.AdskRefs) {
        if ($Index.Products.ContainsKey($packed) -or $candidates.Contains($packed)) { continue }
        if ($Index.OtherRefs.Contains($packed)) {
            Write-AdskLog "Unregistered product $(ConvertFrom-PackedGuid $packed) has files inside and outside the Autodesk folders and cannot be attributed to Autodesk; left alone." @log -Severity Warning
            continue
        }
        [void]$candidates.Add($packed)
    }

    $leftovers = [ordered]@{}
    foreach ($packed in $candidates) {
        $code = ConvertFrom-PackedGuid $packed
        if (-not $code -or $Exclude.Contains($code)) { continue }
        $registered = $Index.Products[$packed]
        if ($registered -and -not (Test-AdskPublisher $registered)) {
            if ($Index.AdskRefs.Contains($packed) -or $KnownCodes.Contains($code)) {
                Write-AdskLog "$($registered.Name) $code (publisher '$($registered.Publisher)') is not an Autodesk product; left alone although it is listed in an Autodesk bundle or has files in an Autodesk folder." @log -Severity Warning
            }
            continue
        }
        if (@(Get-AdskMsiResidue -ProductCode $code -Index $Index).Count -eq 0) { continue }
        $name = @($(if ($registered) { $registered.Name }), $Index.ClassProducts[$packed], $Names[$code]) | Where-Object { $_ } | Select-Object -First 1
        $leftovers[$code] = if ($name) { $name } else { '(unnamed product)' }
    }
    $leftovers
}

function Invoke-AdskForcedCleanup {
    # Forced registration cleanup of one product, recorded for the summary and the exit code.
    param(
        [Parameter(Mandatory)][string]$ProductCode,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Index
    )
    $result  = $script:MsiResults[$ProductCode]
    $trigger = if ($result -and $result.Outcome -eq 'Failed') { "msiexec exit $($result.ExitCode)" } else { 'registration left without a working product' }
    if (-not (Test-ShouldProcess -Target "$Name $ProductCode" -Action 'Forced Windows Installer registration cleanup')) { return }
    Write-AdskStatus "Forced Windows Installer registration cleanup of $Name $ProductCode ($trigger)..." 'InstallerCleanup' -Severity Warning
    $residue = @(Remove-AdskMsiRegistration -ProductCode $ProductCode -Index $Index)
    $script:WorkDone = $true
    $script:RebootRequired = $true
    if ($residue.Count) {
        Write-AdskStatus "Forced cleanup of $Name $ProductCode is incomplete; still present:`r`n  $($residue -join "`r`n  ")" 'InstallerCleanup' -Severity Error
    } else {
        Write-AdskLog "Forced cleanup of $Name $ProductCode complete." 'InstallerCleanup'
    }
    $script:ForcedCleanups.Add([pscustomobject]@{ Name = $Name; ProductCode = $ProductCode; Trigger = $trigger; Complete = ($residue.Count -eq 0) })
}

function Invoke-AdskInstallerCleanup {
    <#
        The Program Install and Uninstall troubleshooter step of the official procedure: indexes
        Windows Installer's registry store and force-cleans every Autodesk registration still
        there - products whose uninstall failed, and leftovers of earlier failed installs or
        uninstalls. $Exclude keeps the Genuine Service for step 5.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$KnownCodes,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Exclude,
        [hashtable]$Names = @{}
    )
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $script:InstallerIndex = Get-AdskInstallerIndex
    Write-AdskLog ("Indexed Windows Installer registrations in {0:N0}s: {1} product(s) referenced by components, {2} of them in Autodesk folders." -f $watch.Elapsed.TotalSeconds, $script:InstallerIndex.Components.Count, $script:InstallerIndex.AdskRefs.Count) 'InstallerCleanup'
    $leftovers = Get-AdskLeftoverProduct -Index $script:InstallerIndex -KnownCodes $KnownCodes -Exclude $Exclude -Names $Names
    if ($leftovers.Count -eq 0) {
        Write-AdskLog 'No Autodesk Windows Installer registrations are left.' 'InstallerCleanup'
        return
    }
    foreach ($code in @($leftovers.Keys)) {
        Invoke-AdskForcedCleanup -ProductCode $code -Name $leftovers[$code] -Index $script:InstallerIndex
    }
}

#endregion

#region Uninstall helpers

function Invoke-AdskRemover {
    # Runs one shared-component remover or uninstall helper, if present. -WaitForEmptyFolder waits
    # until the remover's own folder is empty, as the official procedure does for the Identity
    # Manager, whose uninstaller finishes after its process has exited.
    param([Parameter(Mandatory)][hashtable]$Remover)
    $log = @{ Component = 'SharedComponents' }
    if (-not (Test-Path -LiteralPath $Remover.Path)) {
        Write-AdskLog "$($Remover.Label) not found at $($Remover.Path)" @log
        return
    }
    if (-not (Test-ShouldProcess -Target $Remover.Path -Action "Run $($Remover.Label)")) { return }

    Write-AdskStatus "Running $($Remover.Label)..." 'SharedComponents'
    $startParams = @{ FilePath = $Remover.Path; Wait = $true; PassThru = $true; ErrorAction = 'Stop' }
    if ($Remover.Arguments) { $startParams.ArgumentList = $Remover.Arguments }
    if ($Remover.NoNewWindow) { $startParams.NoNewWindow = $true }
    try {
        $exitCode = (Start-Process @startParams).ExitCode
        $script:WorkDone = $true
        $severity = if ($exitCode -eq 0) { 'Info' } else { 'Warning' }
        Write-AdskLog "$($Remover.Label) exited with code $exitCode." -Severity $severity @log
    } catch {
        Write-AdskLog "$($Remover.Label) could not be started: $($_.Exception.Message)" -Severity Error @log
        return
    }
    if ($Remover.WaitForEmptyFolder) {
        $folder = Split-Path -Path $Remover.Path -Parent
        $deadline = (Get-Date).AddMinutes(2)
        while ((Get-Date) -lt $deadline -and (Get-ChildItem -LiteralPath $folder -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First 1)) {
            Start-Sleep -Seconds 2
        }
        $left = @(Get-ChildItem -LiteralPath $folder -Recurse -File -Force -ErrorAction SilentlyContinue).Count
        if ($left) { Write-AdskLog "$left file(s) still in $folder two minutes after $($Remover.Label) finished; removed with the folders in step 3." @log -Severity Warning }
        else { Write-AdskLog "$folder is empty." @log }
    }
    # the helpers start message_router on the way out, which re-locks IDSDK
    if ($Remover.StopMessageRouter) {
        Get-Process -Name 'message_router' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Remove-AdskUninstallEntry {
    # Programs and Features entries of Autodesk software that has no Windows Installer
    # registration (ODIS bundles, Autodesk Access). Their uninstallers are gone once the removers
    # have run. MSI entries are never touched here - they belong to the products' registration.
    param([switch]$IncludeGenuine)
    foreach ($entry in Get-AdskUninstallEntry | Where-Object { -not $_.IsMsi -and ($IncludeGenuine -or -not $_.IsGenuine) }) {
        if (Remove-AdskRegistryTree $entry.Path -Component 'Registry') {
            Write-AdskLog "Removed the Programs and Features entry of $($entry.Name) ($($entry.Code))." 'Registry'
        }
    }
}

#endregion

#region Filesystem

function Get-AdskProgramDataResidue {
    # Everything under C:\ProgramData\Autodesk except the Uninstallers folder, which holds the
    # helpers of the later steps.
    if (-not (Test-Path -LiteralPath $script:AdskProgramData)) { return }
    Get-ChildItem -LiteralPath $script:AdskProgramData -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $script:AdskUninstallers } |
        ForEach-Object { $_.FullName }
}

function Remove-AdskItem {
    # Best-effort recursive delete through the \\?\ prefix, which also reaches paths longer than
    # 260 characters. Deliberately NOT -ErrorAction Stop: that aborts at the first locked file and
    # leaves the rest behind. Survivors are left for the caller to schedule for deletion at next
    # boot.
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Component = 'FileSystem'
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (-not (Test-ShouldProcess -Target $Path -Action 'Delete recursively')) { return }
    Write-AdskLog "Deleting $Path" $Component
    $deleteErrors = $null
    Remove-Item -LiteralPath "\\?\$Path" -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable deleteErrors
    $script:WorkDone = $true
    if (Test-Path -LiteralPath $Path) {
        $detail = @($deleteErrors | ForEach-Object { $_.Exception.Message } | Select-Object -Unique)
        Write-AdskLog ("Still present after delete attempt: $Path ($($deleteErrors.Count) item(s) failed)`r`n" + ($detail -join "`r`n")) $Component -Severity Warning
        Write-Host "Could not fully delete $Path ($($deleteErrors.Count) item(s) failed); the rest is removed at the next restart." -ForegroundColor Yellow
    }
}

function Register-PendingDelete {
    <#
    Queues paths for deletion at the next boot via the Session Manager's PendingFileRenameOperations,
    which runs before anything can load them again. A directory is expanded to its contents
    deepest-first (enumerated through \\?\, so locked trees and paths over 260 characters work), so each
    directory is empty by the time its own entry is processed. Entries Windows already had pending are
    kept and paths already queued are not added twice; the value is read and written once per call, so
    pass all locked items together. Returns the paths it added. A drive root or top-level folder is
    never queued: such a path is reported by throwing once everything else is queued. Identical in
    TempDataCleanup, Repair-System and AutoDeskCleanRemove; self-contained for remote shipping.
    #>
    param([Parameter(Mandatory=$true)][string[]]$Path)
    $smKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $pending = New-Object System.Collections.Generic.List[string]
    $queued  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $current = @((Get-ItemProperty -Path $smKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations | Where-Object { $null -ne $_ })
    $pending.AddRange([string[]]$current)
    # entries are source/destination pairs; an empty destination means 'delete'
    for ($i = 0; $i + 1 -lt $current.Count; $i += 2) {
        if ($current[$i + 1] -eq '') { [void]$queued.Add($current[$i]) }
    }

    $added   = New-Object System.Collections.Generic.List[string]
    $refused = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Path) {
        $root = $item -replace '^\\\\\?\\', ''
        if ($root -notmatch '^[A-Za-z]:\\[^\\]+\\[^\\]') { $refused.Add($item); continue }
        $targets = @(Get-ChildItem -LiteralPath "\\?\$root" -Recurse -Force -ErrorAction SilentlyContinue |
                     ForEach-Object { $_.FullName.Substring(4) } |
                     Sort-Object { $_.Length } -Descending) + $root
        foreach ($target in $targets) {
            if ($queued.Add("\??\$target")) {
                $pending.Add("\??\$target")
                $pending.Add('')
                $added.Add($target)
            }
        }
    }
    if ($added.Count -gt 0) {
        Set-ItemProperty -Path $smKey -Name PendingFileRenameOperations -Value $pending.ToArray() -Type MultiString -ErrorAction Stop
    }
    if ($refused.Count -gt 0) { throw "Refused to schedule $($refused -join ', ') for deletion: not a safe target." }
    $added.ToArray()
}

function Register-AdskSurvivors {
    # Schedules whatever is still present of $Path for deletion at next boot.
    param(
        [string[]]$Path,
        [string]$Component = 'PendingDelete'
    )
    $survivors = @($Path | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($survivors.Count -eq 0) { return }
    $script:WorkDone = $true
    if ($WhatIfPreference) {
        # nothing was deleted, so everything "survived"; enumerating it all would only cost time
        [void](Test-ShouldProcess -Target "$($survivors.Count) path(s) still present" -Action 'Schedule deletion at next boot (PendingFileRenameOperations)')
        return
    }
    try {
        $scheduled = @(Register-PendingDelete -Path $survivors)
        if ($scheduled.Count -gt 0) {
            $script:RebootRequired = $true
            Write-AdskLog "Scheduled $($scheduled.Count) locked item(s) under $($survivors.Count) path(s) for deletion at next boot:`r`n$($survivors -join "`r`n")" $Component -Severity Warning
            Write-AdskLog "Items scheduled for deletion at next boot:`r`n$($scheduled -join "`r`n")" $Component -Severity Verbose
            Write-Host "$($scheduled.Count) locked item(s) will be removed on the next restart." -ForegroundColor Yellow
        }
    } catch {
        Write-AdskStatus "Could not schedule locked items for deletion at next boot: $($_.Exception.Message)" $Component -Severity Error
    }
}

function Clear-AdskTempFolder {
    # Official step 3 clears %TEMP%; done for every user profile and the account running the
    # script. Best effort, as in the official procedure: whatever is in use stays. The folder this
    # script runs from is never touched.
    param([string[]]$Folder)
    foreach ($path in $Folder | Where-Object { $_ } | Select-Object -Unique) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
        if (-not (Test-ShouldProcess -Target $path -Action 'Delete the contents of the temp folder')) { continue }
        $items = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue |
            Where-Object { -not "$PSScriptRoot\".StartsWith("$($_.FullName)\", [StringComparison]::OrdinalIgnoreCase) })
        foreach ($item in $items) { Remove-Item -LiteralPath "\\?\$($item.FullName)" -Recurse -Force -ErrorAction SilentlyContinue }
        $left = @($items | Where-Object { Test-Path -LiteralPath $_.FullName }).Count
        if ($items.Count) { $script:WorkDone = $true }
        Write-AdskLog "Cleared ${path}: removed $($items.Count - $left) of $($items.Count) item(s)$(if ($left) { "; $left in use, left in place" })." 'FileSystem'
    }
}

function Remove-AdskExternalFile {
    <#
        Files outside the Autodesk folders (eg. AcSignExtRes.dll and styleman.cpl in System32,
        installed by ODIS packages no uninstall can reach) whose Windows Installer references the
        forced cleanup removed get what the products' own uninstall would have done: their
        SharedDLLs counter drops by the references removed, and a file is deleted only when no
        product references it any more, the counter leaves no other owner, and it carries a valid
        Autodesk signature - a same-named file of another vendor is never touched. Locked files
        are queued for deletion at the next boot.
    #>
    $component = 'FileSystem'
    $deleted = New-Object System.Collections.Generic.List[string]
    foreach ($file in @($script:ExternalFiles.Keys)) {
        $entry = $script:ExternalFiles[$file]
        $owners = 0
        foreach ($keyPath in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs') {
            $count = Get-AdskRegistryValue $keyPath $file
            if ($null -eq $count) { continue }
            $remaining = [math]::Max(0, [int]$count - $entry.Removed)
            $owners = [math]::Max($owners, $remaining)
            if (-not (Test-ShouldProcess -Target "$keyPath\$file" -Action "Set the shared-file counter to $remaining")) { continue }
            $key = Open-AdskRegistryKey $keyPath -Writable
            try {
                [void](Backup-AdskRegistryValue $keyPath $file ([Microsoft.Win32.RegistryValueKind]::DWord) $count)
                if ($remaining -eq 0) { $key.DeleteValue($file) } else { $key.SetValue($file, $remaining, [Microsoft.Win32.RegistryValueKind]::DWord) }
                Write-AdskLog "SharedDLLs counter of $file lowered from $count to $remaining." $component
            } catch {
                Write-AdskLog "SharedDLLs counter of $file could not be updated: $($_.Exception.Message)" $component -Severity Warning
            } finally { $key.Dispose() }
        }
        if (-not $entry.Orphaned -or -not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
        if ($owners -gt 0) {
            Write-AdskLog "$file is no longer referenced by Windows Installer, but SharedDLLs still counts $owners other owner(s); kept." $component -Severity Warning
            continue
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O="?Autodesk') {
            Write-AdskLog "$file is no longer referenced by Windows Installer, but it is not validly signed by Autodesk (signature: $($signature.Status), $($signature.SignerCertificate.Subject)); kept." $component -Severity Warning
            continue
        }
        Remove-AdskItem -Path $file
        $deleted.Add($file)
    }
    if ($deleted.Count) {
        Write-AdskLog "Deleted $($deleted.Count) Autodesk file(s) outside the Autodesk folders that no product owns any more:`r`n$($deleted -join "`r`n")" $component
        Register-AdskSurvivors -Path $deleted -Component $component
    }
}

function Remove-AdskStaleReference {
    # Shared-file counters (SharedDLLs) and Windows Installer folder entries pointing into Autodesk
    # folders that no longer exist; left behind whenever a registration had to be force-cleaned.
    $removed = 0
    foreach ($keyPath in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs',
                         'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders') {
        $key = Open-AdskRegistryKey $keyPath
        if (-not $key) { continue }
        try { $names = $key.GetValueNames() } finally { $key.Dispose() }
        foreach ($name in $names) {
            if (-not (Test-AdskPathReference $name) -or (Test-Path -LiteralPath $name)) { continue }
            if (-not (Test-ShouldProcess -Target "$keyPath\$name" -Action 'Delete stale registry value')) { continue }
            if (Remove-AdskRegistryValue $keyPath $name -Component 'Registry') { $removed++ }
        }
    }
    if ($removed) { Write-AdskLog "Removed $removed SharedDLLs / Installer folder entry(s) pointing into deleted Autodesk folders." 'Registry' }
}

function Get-AdskShellResidue {
    <#
        What the ODIS uninstall removes besides files, where it still points into an Autodesk
        folder: shortcuts in the Start menus and on the desktops of every profile, file
        associations (extension -> ProgID whose open command is an Autodesk program) and entries of
        the system PATH.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Profiles)
    $commandPath = { param($command) if ([Environment]::ExpandEnvironmentVariables("$command") -match '^\s*"?([A-Za-z]:\\[^"]*?\.(exe|dll|com))') { $Matches[1] } }

    $shell = New-Object -ComObject WScript.Shell
    $roots = @([Environment]::GetFolderPath('CommonPrograms'), [Environment]::GetFolderPath('CommonDesktopDirectory')) +
             @(foreach ($userProfile in $Profiles) { "$($userProfile.Path)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"; "$($userProfile.Path)\Desktop" })
    foreach ($root in $roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique) {
        foreach ($link in Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -Force -File -ErrorAction SilentlyContinue) {
            $target = try { $shell.CreateShortcut($link.FullName).TargetPath } catch { '' }
            if ($target -and (Test-AdskPathReference $target)) {
                [pscustomobject]@{ Kind = 'Shortcut'; Path = $link.FullName; Root = $root; Target = $target }
            }
        }
    }

    $classes = Open-AdskRegistryKey 'HKLM\SOFTWARE\Classes'
    try {
        foreach ($extension in $classes.GetSubKeyNames() -like '.*') {
            $extensionKey = $classes.OpenSubKey($extension)
            $progId = try { [string]$extensionKey.GetValue('') } finally { $extensionKey.Dispose() }
            if (-not $progId) { continue }
            $target = & $commandPath (Get-AdskRegistryValue "HKLM\SOFTWARE\Classes\$progId\shell\open\command" '')
            if ($target -and (Test-AdskPathReference $target)) {
                [pscustomobject]@{ Kind = 'FileAssociation'; Path = "HKLM\SOFTWARE\Classes\$extension"; ProgId = $progId; Target = $target }
            }
        }
    } finally { $classes.Dispose() }

    $environment = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $key = Open-AdskRegistryKey $environment
    $path = try { [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames') } finally { $key.Dispose() }
    foreach ($entry in $path -split ';' | Where-Object { $_ }) {
        $target = [Environment]::ExpandEnvironmentVariables($entry)
        # the roots end in a backslash, PATH entries mostly do not
        if (Test-AdskPathReference ($target.TrimEnd('\') + '\')) {
            [pscustomobject]@{ Kind = 'Path'; Path = "$environment\Path"; Entry = $entry; Target = $target }
        }
    }
}

function Remove-AdskShellResidue {
    # Removes what Get-AdskShellResidue finds - left behind when an ODIS uninstall failed or the
    # software was never uninstalled properly. Its targets are in the Autodesk folders, deleted now
    # or at the next boot, so nothing found here can still work. Only a ProgID whose open command
    # is an Autodesk program is deleted; the extension key stays and loses its default.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Profiles)
    $component = 'ShellCleanup'
    $residue = @(Get-AdskShellResidue -Profiles $Profiles)
    foreach ($item in $residue | Where-Object Kind -eq 'Shortcut') {
        Remove-AdskItem -Path $item.Path -Component $component
        # the product's Start menu folder, once its last shortcut is gone
        $folder = Split-Path -Path $item.Path -Parent
        while ($folder.Length -gt $item.Root.Length -and (Test-Path -LiteralPath $folder) -and -not (Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue)) {
            if (-not (Test-ShouldProcess -Target $folder -Action 'Delete empty folder')) { break }
            Remove-Item -LiteralPath $folder -Force -ErrorAction SilentlyContinue
            $folder = Split-Path -Path $folder -Parent
        }
    }
    # Start menu folders named Autodesk that the removers emptied (eg. Autodesk\Autodesk Access)
    $menus = @([Environment]::GetFolderPath('CommonPrograms')) + @(foreach ($userProfile in $Profiles) { "$($userProfile.Path)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" })
    foreach ($menu in $menus | Where-Object { $_ }) {
        $folder = Join-Path -Path $menu -ChildPath 'Autodesk'
        if ((Test-Path -LiteralPath $folder -PathType Container) -and -not (Get-ChildItem -LiteralPath $folder -Recurse -Force -File -ErrorAction SilentlyContinue | Select-Object -First 1)) {
            Remove-AdskItem -Path $folder -Component $component
        }
    }
    foreach ($item in $residue | Where-Object Kind -eq 'FileAssociation') {
        if (-not (Remove-AdskRegistryTree "HKLM\SOFTWARE\Classes\$($item.ProgId)" -Component $component)) { continue }
        if (-not (Test-ShouldProcess -Target $item.Path -Action "Clear the default value ($($item.ProgId))")) { continue }
        $key = Open-AdskRegistryKey $item.Path -Writable
        try {
            if ([string]$key.GetValue('') -eq $item.ProgId) {
                [void](Backup-AdskRegistryValue $item.Path '' ([Microsoft.Win32.RegistryValueKind]::String) $item.ProgId)
                $key.DeleteValue('', $false)
                Write-AdskLog "File association $($item.Path) -> $($item.ProgId) ($($item.Target)) removed." $component
            }
        } catch {
            Write-AdskLog "File association $($item.Path) could not be cleared: $($_.Exception.Message)" $component -Severity Warning
        } finally { $key.Dispose() }
    }
    $pathEntries = @($residue | Where-Object Kind -eq 'Path')
    if ($pathEntries.Count -and (Test-ShouldProcess -Target 'system PATH' -Action "Remove $($pathEntries.Entry -join '; ')")) {
        $environment = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        $key = Open-AdskRegistryKey $environment -Writable
        try {
            $kind = $key.GetValueKind('Path')
            $old = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
            $new = ($old -split ';' | Where-Object { $_ -and $pathEntries.Entry -notcontains $_ }) -join ';'
            [void](Backup-AdskRegistryValue $environment 'Path' $kind $old)
            $key.SetValue('Path', $new, $kind)
            $script:WorkDone = $true
            Write-AdskLog "Removed from the system PATH: $($pathEntries.Entry -join '; ')" $component
        } catch {
            Write-AdskLog "The system PATH could not be updated: $($_.Exception.Message)" $component -Severity Warning
        } finally { $key.Dispose() }
    }
}

#endregion

#region Deferred cleanup

function Get-AdskComRegistration {
    # COM classes served by an Autodesk binary or .NET assembly - eg. the AcSignCore16.dll shell
    # extension registered under hundreds of CLSIDs - as key paths below HKLM. Self-contained, as
    # the deferred script runs it too.
    $hklm = [Microsoft.Win32.Registry]::LocalMachine
    foreach ($root in 'SOFTWARE\Classes\CLSID', 'SOFTWARE\Classes\WOW6432Node\CLSID') {
        $rootKey = $hklm.OpenSubKey($root)
        if (-not $rootKey) { continue }
        try {
            foreach ($clsid in $rootKey.GetSubKeyNames()) {
                $isAutodesk = $false
                foreach ($serverName in 'InprocServer32', 'LocalServer32') {
                    $server = $rootKey.OpenSubKey("$clsid\$serverName")
                    if (-not $server) { continue }
                    try {
                        if (("$($server.GetValue(''))" -match '\\Autodesk|^Autodesk\.') -or ("$($server.GetValue('CodeBase'))" -match '\\Autodesk') -or
                            ("$($server.GetValue('Assembly'))" -match '^Autodesk\.')) { $isAutodesk = $true }
                    } finally { $server.Dispose() }
                }
                if ($isAutodesk) { "$root\$clsid" }
            }
        } finally { $rootKey.Dispose() }
    }
}

function Register-AdskDeferredCleanup {
    <#
        Registers a one-shot SYSTEM task that finishes the cleanup at next boot. Returns the path
        of the script it registered, or $null under -WhatIf.

        Why deferred rather than done here: AcSignCore16.dll is registered under hundreds of CLSIDs
        as a shell extension, and explorer.exe keeps it loaded for the life of the session.
        Removing those registrations from under a running shell stalls shutdown, and any per-user
        Autodesk key deleted now is simply rewritten by that still-loaded DLL.

        At next boot, by the time this task runs:
          - PendingFileRenameOperations has already deleted the DLLs
          - no user has logged on, so nothing can reload them
          - every user hive is UNLOADED and can be cleaned offline, which also reaches users who
            never sign in and the Default profile - something the live run cannot do, since
            HKEY_USERS only ever shows loaded hives.
    #>
    param([Parameter(Mandatory)][string]$WorkDir)

    if (-not (Test-ShouldProcess -Target "$script:DeferredTaskName (SYSTEM task at startup)" -Action 'Register one-shot deferred cleanup')) { return $null }

    # The script runs as SYSTEM, so its folder must not be writable by users. Start from a fresh
    # admin-only folder; Directory.Delete removes a planted junction itself rather than following
    # it. This also clears stale state from an earlier cleanup.
    if (Test-Path -LiteralPath $WorkDir) { [System.IO.Directory]::Delete($WorkDir, $true) }
    New-SecureDirectory -Path $WorkDir

    $deferredScript  = Join-Path -Path $WorkDir -ChildPath 'ADSK-DeferredCleanup.ps1'
    # one log per cleanup: the boot-time phase appends to the log of this run
    $deferredLog     = $script:LogFile
    # marker proving this task already ran, kept only if the task could not be unregistered
    $deferredDone    = Join-Path -Path $WorkDir -ChildPath 'ADSK-DeferredCleanup.done'
    # attempt counter, written before any work, so a hung/killed run is still detected
    $deferredAttempt = Join-Path -Path $WorkDir -ChildPath 'ADSK-DeferredCleanup.attempt'

    # single-quoted here-string: nothing below is expanded by THIS script
    $deferredTemplate = @'
$deferredLogPath     = '__LOGPATH__'
# into the log of the run that queued the work; a new _Deferred.log only if that one is gone
if (-not (Test-Path -LiteralPath $deferredLogPath)) { $deferredLogPath = $deferredLogPath -replace '\.log$', '_Deferred.log' }
$deferredWorkDir     = '__WORKDIR__'
$deferredDoneFile    = '__SENTINEL__'
$deferredAttemptFile = '__ATTEMPTFILE__'
$deferredScheduledAt = [datetime]::Parse('__SCHEDULEDAT__')
$deferredTaskName    = '__TASKNAME__'
$deferredFolders     = @(__FOLDERS__)

# the main script's CMTrace writer and COM-registration scan
__CMTRACELOG__

__COMSCAN__

function Write-DeferredLog {
    param([string]$Message, [ValidateSet('Info','Warning','Error')][string]$Level = 'Info')
    Write-CMTraceLog "DEFERRED TASK: $Message" 'AutoDeskCleanRemove-Deferred' $deferredLogPath $Level -Caller $MyInvocation
}

function Remove-DeferredCleanup {
    # Belt and braces: mark done FIRST, then unregister. Only once the task is gone are the script
    # and its folder deleted; otherwise the marker stays, so any later boot exits immediately.
    try { New-Item -Path $deferredDoneFile -ItemType File -Force -ErrorAction Stop | Out-Null } catch { }
    $unregistered = $false
    try {
        Unregister-ScheduledTask -TaskName $deferredTaskName -Confirm:$false -ErrorAction Stop
        $unregistered = $true
    } catch {
        & schtasks.exe /delete /tn $deferredTaskName /f 2>&1 | Out-Null
        $unregistered = ($LASTEXITCODE -eq 0)
    }
    if ($unregistered) {
        Remove-Item -LiteralPath $deferredWorkDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-DeferredLog "The task could not be unregistered; the completion marker stays so it exits at once if it runs again." -Level Warning
        Remove-Item -LiteralPath $deferredAttemptFile, $PSCommandPath -Force -ErrorAction SilentlyContinue
    }
}

# Record this script's own source as the first entry, before anything else runs and before any
# guard can exit. The script deletes itself as its last act, so without this the log is the only
# survivor and there is no way to audit what it actually did.
try {
    # The writer escapes the CMTrace delimiters this source contains, so it stays one entry.
    $deferredSelfSource = Get-Content -LiteralPath $PSCommandPath -Raw -ErrorAction Stop
    Write-DeferredLog "Deferred cleanup script source ($PSCommandPath) - CMTrace delimiters escaped as &lt; / &gt; so this stays one entry:`r`n{`r`n$deferredSelfSource`r`n}"
} catch {
    Write-DeferredLog "Could not read own source for the log: $($_.Exception.Message)" -Level Warning
}

# GUARD 1 - completion marker. Set by a previous run that could not unregister the task.
if (Test-Path -LiteralPath $deferredDoneFile) {
    Write-DeferredLog "Deferred cleanup already completed previously; removing the task and exiting." -Level Warning
    Remove-DeferredCleanup
    exit 0
}

# GUARD 1a - attempt counter, written BEFORE any work is done. Covers the case the finally block
# cannot: the script hanging or being killed mid-run, so it never marked itself done. A second
# sighting means it already had its chance.
$deferredAttempt = 1
try {
    if (Test-Path -LiteralPath $deferredAttemptFile) {
        $deferredAttempt = [int]((Get-Content -LiteralPath $deferredAttemptFile -Raw -ErrorAction Stop).Trim()) + 1
    }
} catch { $deferredAttempt = 2 }   # unreadable counter -> assume this is a retry
try { Set-Content -LiteralPath $deferredAttemptFile -Value $deferredAttempt -Force -ErrorAction Stop } catch { }
if ($deferredAttempt -gt 1) {
    Write-DeferredLog "This is attempt $deferredAttempt; a previous run started but did not finish. Removing the task rather than retrying indefinitely." -Level Warning
    Remove-DeferredCleanup
    exit 0
}

# GUARD 1b - boots since the task was scheduled. Independent of any file we write, so it still
# holds if the counter above could not be persisted. Event 6005 ("Event log service was started")
# fires once per boot; the task is AtStartup, so on its legitimate first run exactly ONE boot has
# occurred since scheduling.
try {
    $bootsSinceScheduled = @(Get-WinEvent -FilterHashtable @{
        LogName = 'System'; Id = 6005; StartTime = $deferredScheduledAt
    } -ErrorAction Stop).Count
    if ($bootsSinceScheduled -gt 1) {
        Write-DeferredLog "$bootsSinceScheduled boots have occurred since scheduling; this task should already have run. Removing it." -Level Warning
        Remove-DeferredCleanup
        exit 0
    }
    Write-DeferredLog "Boots since scheduling: $bootsSinceScheduled (expected 1)."
} catch {
    Write-DeferredLog "Could not count boots since scheduling: $($_.Exception.Message)" -Level Warning
}

# GUARD 2 - everything below runs inside try/finally, so the task and script are removed even if
# the body throws. Without this, a failure part-way through would leave the task registered and it
# would fire on EVERY subsequent boot.
try {

Write-DeferredLog "Deferred Autodesk cleanup started (running as $env:USERNAME)."

# --- 1. unregister Autodesk COM / shell extensions ----------------------------
$clsidRemoved = 0
$clsidFailed  = 0
foreach ($clsidKey in @(Get-AdskComRegistration)) {
    try { [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($clsidKey, $false); $clsidRemoved++ } catch { $clsidFailed++ }
}
Write-DeferredLog "Unregistered $clsidRemoved Autodesk COM class(es)$(if ($clsidFailed) { "; $clsidFailed could not be removed" })." -Level $(if ($clsidFailed) { 'Warning' } else { 'Info' })

# --- 2. clean every profile's hive: offline, or live if it is already loaded --
$profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$profiles = @(foreach ($profileKey in Get-ChildItem -LiteralPath $profileList -ErrorAction SilentlyContinue) {
    $profilePath = (Get-ItemProperty -LiteralPath $profileKey.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
    if ($profilePath) { [pscustomobject]@{ Sid = $profileKey.PSChildName -replace '\.bak$'; Path = [Environment]::ExpandEnvironmentVariables($profilePath).TrimEnd('\') } }
})
$defaultProfile = (Get-ItemProperty -LiteralPath $profileList -Name Default -ErrorAction SilentlyContinue).Default
if ($defaultProfile) { $profiles += [pscustomobject]@{ Sid = $null; Path = [Environment]::ExpandEnvironmentVariables($defaultProfile).TrimEnd('\') } }

$keysRemoved = 0
$mountIndex  = 0
$hivesSeen   = @{}
foreach ($userProfile in $profiles) {
    $ntUser = Join-Path $userProfile.Path 'NTUSER.DAT'
    if ($hivesSeen.ContainsKey($ntUser) -or -not (Test-Path -LiteralPath $ntUser)) { continue }
    $hivesSeen[$ntUser] = $true
    $profileName = Split-Path $userProfile.Path -Leaf
    $mount = $null
    if ($userProfile.Sid -and (Test-Path -LiteralPath "Registry::HKEY_USERS\$($userProfile.Sid)")) {
        # signed in before this task ran (eg. auto-logon), or a service account: clean it live -
        # the shell extension DLL is already gone, so nothing can write the key back
        $hiveRoot = "Registry::HKEY_USERS\$($userProfile.Sid)"
    } else {
        $mountIndex++
        $mount = "adskdef_$mountIndex"
        & reg.exe load "HKU\$mount" $ntUser 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-DeferredLog "Could not load the hive of $profileName ($ntUser); skipped." -Level Warning
            continue
        }
        $hiveRoot = "Registry::HKEY_USERS\$mount"
    }
    foreach ($suffix in 'SOFTWARE\Autodesk', 'SOFTWARE\WOW6432Node\Autodesk') {
        $hivePath = "$hiveRoot\$suffix"
        if (Test-Path -LiteralPath $hivePath) {
            Remove-Item -LiteralPath $hivePath -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path -LiteralPath $hivePath)) {
                $keysRemoved++
                Write-DeferredLog "Removed $suffix for $profileName."
            } else {
                Write-DeferredLog "FAILED to remove $suffix for $profileName." -Level Error
            }
        }
    }
    if ($mount) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 500
        foreach ($unloadTry in 1..5) {
            & reg.exe unload "HKU\$mount" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { break }
            [gc]::Collect(); Start-Sleep -Seconds 1
        }
    }
}
Write-DeferredLog "Removed $keysRemoved per-user Autodesk key(s)."

# --- 3. remove the Autodesk folders that are now unlocked ---------------------
$profileFolders = foreach ($userProfile in $profiles) {
    Join-Path $userProfile.Path 'AppData\Local\Autodesk'
    Join-Path $userProfile.Path 'AppData\Roaming\Autodesk'
}
foreach ($folder in @($deferredFolders) + @($profileFolders) | Select-Object -Unique) {
    if (-not (Test-Path -LiteralPath $folder)) { continue }
    Remove-Item -LiteralPath "\\?\$folder" -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $folder) { Write-DeferredLog "Folder ${folder}: still present" -Level Warning } else { Write-DeferredLog "Folder ${folder}: removed" }
}

Write-DeferredLog "Deferred Autodesk cleanup finished."

} catch {
    Write-DeferredLog "Deferred cleanup failed: $($_.Exception.Message)`r`n$($_.InvocationInfo.PositionMessage)" -Level Error
} finally {
    # ALWAYS runs - success, failure, or a terminating error part-way through
    Write-DeferredLog "Removing the deferred cleanup task and script."
    Remove-DeferredCleanup
}
'@
    $quote   = { param($s) "'" + $s.Replace("'", "''") + "'" }
    $folders = @($script:AdskProgramFolders) + $script:AdskProgramData | ForEach-Object { & $quote $_ }
    # .Replace, not -replace: '$' in a path would be read as a substitution. Values land inside
    # single-quoted literals, so a quote in the path is doubled.
    $deferredBody = $deferredTemplate.Replace('__LOGPATH__', $deferredLog.Replace("'", "''"))
    $deferredBody = $deferredBody.Replace('__WORKDIR__', $WorkDir.Replace("'", "''"))
    $deferredBody = $deferredBody.Replace('__SENTINEL__', $deferredDone.Replace("'", "''"))
    $deferredBody = $deferredBody.Replace('__ATTEMPTFILE__', $deferredAttempt.Replace("'", "''"))
    $deferredBody = $deferredBody.Replace('__SCHEDULEDAT__', (Get-Date).ToString('o'))
    $deferredBody = $deferredBody.Replace('__TASKNAME__', $script:DeferredTaskName)
    $deferredBody = $deferredBody.Replace('__FOLDERS__', ($folders -join ', '))
    $deferredBody = $deferredBody.Replace('__CMTRACELOG__', "function Write-CMTraceLog {$(${function:Write-CMTraceLog})}")
    $deferredBody = $deferredBody.Replace('__COMSCAN__', "function Get-AdskComRegistration {$(${function:Get-AdskComRegistration})}")
    Set-Content -LiteralPath $deferredScript -Value $deferredBody -Encoding UTF8 -Force -ErrorAction Stop

    $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$deferredScript`""
    $taskTrigger   = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # GUARD 3 - bounded runtime, never retried, never concurrent. Even if the script somehow failed
    # to remove itself, the task cannot pile up or run forever.
    $taskSettings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
                        -MultipleInstances IgnoreNew -RestartCount 0 `
                        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable:$false
    # -Force replaces any existing task of the same name, so repeated runs never stack
    Register-ScheduledTask -TaskName $script:DeferredTaskName -Action $taskAction -Trigger $taskTrigger `
                           -Principal $taskPrincipal -Settings $taskSettings `
                           -Description 'One-shot Autodesk cleanup; removes itself after running.' `
                           -Force -ErrorAction Stop | Out-Null
    return $deferredScript
}

#endregion

#region Main

$scriptVersion = [regex]::Match((Get-Content -LiteralPath $PSCommandPath -Raw), '(?m)^\s*Version:\s*(\S+)').Groups[1].Value
Write-AdskLog ("AutoDeskCleanRemove.ps1 $scriptVersion started;`r`n" +
    "Source: https://github.com/halatsWol/PowerShell-Tools/blob/main/scripts/AutoDeskCleanRemove.ps1;`r`n" +
    "Host: $env:COMPUTERNAME; User: $env:USERDOMAIN\$env:USERNAME; PowerShell: $($PSVersionTable.PSVersion);`r`n" +
    "LogPath: $LogPath; LogLevel: $LogLevel; Unattended: $Unattended; NoRestart: $NoRestart; ForceRestart: $ForceRestart; WhatIf: $WhatIfPreference; Interactive: $script:Interactive;")

# ---- discovery ----
$bundles = @(Get-AdskBundle)
$uninstallEntries = @(Get-AdskUninstallEntry)
$registered = @()
try {
    $registered = @(Get-AdskRegisteredProduct)
} catch {
    Write-AdskStatus "Windows Installer could not be queried ($($_.Exception.Message)); every Autodesk registration is removed by the forced cleanup instead." 'Discovery' -Severity Error
}
$bundleCodes = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($bundle in $bundles) { foreach ($code in $bundle.ProductCodes) { [void]$bundleCodes.Add($code) } }

$autodeskProducts = @{}
$genuineCodes = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$productNames = @{}
foreach ($product in $registered) {
    $productNames[$product.ProductCode] = $product.Name
    if (-not (Test-AdskPublisher $product)) {
        if ($bundleCodes.Contains($product.ProductCode)) {
            Write-AdskLog "$($product.Name) $($product.ProductCode) is listed in an Autodesk bundle but published by '$($product.Publisher)'; it is not uninstalled." 'Discovery' -Severity Warning
        }
        continue
    }
    if ($product.Name -like 'Autodesk Genuine Service*') { [void]$genuineCodes.Add($product.ProductCode) }
    else { $autodeskProducts[$product.ProductCode] = $product }
}
foreach ($entry in $uninstallEntries) {
    if (-not $productNames.ContainsKey($entry.Code)) { $productNames[$entry.Code] = $entry.Name }
    if ($entry.IsMsi -and $entry.IsGenuine) { [void]$genuineCodes.Add($entry.Code) }
}
# Every Autodesk product code seen anywhere; the final verification checks each one.
$knownCodes = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($code in @($autodeskProducts.Keys) + @($genuineCodes) + @($bundleCodes) + @($uninstallEntries | Where-Object IsMsi | ForEach-Object { $_.Code })) { [void]$knownCodes.Add($code) }
$packageCount = 0
foreach ($bundle in $bundles) {
    foreach ($code in $bundle.PackageCodes) {
        if ($knownCodes.Add($code)) { $packageCount++ }
        if (-not $productNames.ContainsKey($code)) { $productNames[$code] = "$($bundle.Name) (ODIS package)" }
    }
}

Write-AdskLog ("Discovery: $($bundles.Count) bundle(s) under $script:AdskUninstallers with $packageCount ODIS package(s); $($autodeskProducts.Count) Autodesk MSI product(s) registered with Windows Installer$(if ($genuineCodes.Count) { ' plus the Autodesk Genuine Service' }); $($uninstallEntries.Count) Autodesk Programs and Features entries.`r`n" +
    (($autodeskProducts.Values | Sort-Object Name | ForEach-Object { "  $($_.Name) $($_.ProductCode)" }) -join "`r`n")) 'Discovery'

$bundleUninstalls = @(Get-AdskBundleUninstall -Entries $uninstallEntries)
# Without any ODIS bundle every MSI product is uninstalled on its own.
$entrySizes = @{}
foreach ($entry in $uninstallEntries) { $entrySizes[$entry.Code] = $entry.SizeKB }
$ownMsiProducts = @(foreach ($code in $autodeskProducts.Keys) {
    if ($bundleUninstalls.Count -and $bundleCodes.Contains($code)) { continue }
    [pscustomobject]@{ Code = $code; SizeKB = [int64]$entrySizes[$code] }
})
$estimate = Get-AdskDurationEstimate -Bundles $bundleUninstalls -MsiProducts $ownMsiProducts
Write-AdskStatus ("Estimated duration: approx. $($estimate.Low)-$($estimate.High) minutes ($($bundleUninstalls.Count) ODIS bundle(s) and $($ownMsiProducts.Count) " +
    "further MSI product(s), $($estimate.SizeGB) GB installed$(if ($estimate.Unsized) { "; $($estimate.Unsized) bundle(s) without a size counted as $($estimate.FallbackGB) GB each" })). " +
    "Do not restart or shut down the computer meanwhile.") 'Discovery'

Write-Host "`r`nThis script will remove all Autodesk products from your system."
Write-Host "Please ensure that you have closed all Autodesk applications before proceeding."
# Fusion is not an MSI/ODIS product - nothing here uninstalls it. Its payload under
# %LOCALAPPDATA%\Autodesk\webdeploy is nevertheless deleted along with the rest of
# AppData\Local\Autodesk, while its per-user uninstall entry (HKCU) survives. The result is a
# half-removed install, so this has to be a warning rather than a note.
Write-Warning "Autodesk Fusion is NOT uninstalled by this script - but it WILL be corrupted by it.`r`nFusion installs per-user under %LOCALAPPDATA%\Autodesk\webdeploy. This script deletes that folder without ever running Fusion's own uninstaller, which leaves the program files gone while Fusion still appears in Apps & Features.`r`nIf Fusion is installed, stop now and uninstall it manually first."
Write-Warning "Please note that this may prompt OneDrive regarding the deletion of files. This is to be expected.`r`nMultiple Windows may appear, please do not close them manually.`r`nThe script will close them automatically after the uninstallation process."
Wait-ForUser
Write-Host "`r`n`r`nStarting Autodesk Clean Uninstall...`r`nThis may take a while, please be patient...`r`n"
$script:RunClock = [Diagnostics.Stopwatch]::StartNew()

# ==== Step 1: uninstall all Autodesk software except the Genuine Service ====
Write-AdskProgress -Step 1 -Status 'Stopping Autodesk services and processes'
# Services first, then processes - killing a service's process only makes the SCM restart it.
$null = Invoke-AdskServiceAndProcessSweep -Phase 'initial'

# The bundles first, through ODIS as Programs and Features does: only ODIS removes its packages
# that have no Windows Installer product. Whatever MSI product is still installed afterwards -
# ODIS failed, or it belongs to no bundle - is uninstalled by its product code.
for ($i = 0; $i -lt $bundleUninstalls.Count; $i++) {
    $bundle = $bundleUninstalls[$i]
    Write-AdskProgress -Step 1 -Status "Uninstalling $($bundle.Name)" -Fraction ($i / [math]::Max(1, $bundleUninstalls.Count) * 0.5)
    Write-Host "Uninstalling $($bundle.Name)..."
    $script:BundleResults[$bundle.Code] = Invoke-AdskBundleUninstall -Bundle $bundle
}

$order = @(Get-AdskUninstallOrder -Bundles $bundles -Products $autodeskProducts)
for ($i = 0; $i -lt $order.Count; $i++) {
    $code = $order[$i]
    $name = $autodeskProducts[$code].Name
    if ($bundleUninstalls.Count -and -not $WhatIfPreference -and (Get-AdskProductState $code) -notin 1, 2, 5) {
        Write-AdskLog "$name $code was removed with its bundle." 'MsiUninstall'
        continue
    }
    Write-AdskProgress -Step 1 -Status "Uninstalling $name" -Fraction (0.5 + $i / [math]::Max(1, $order.Count) * 0.2)
    Write-Host "Uninstalling $name..."
    $script:MsiResults[$code] = Invoke-AdskMsiUninstall -ProductCode $code -Name $name
}

$programFiles   = $script:Folders.ProgramFiles
$commonFilesX86 = if ($script:Folders.CommonFilesX86) { $script:Folders.CommonFilesX86 } else { $script:Folders.CommonFiles }
# Autodesk Access first: its remover lives inside the ODIS folder.
$sharedRemovers = @(
    @{ Label = 'Autodesk Access remover';          Path = "$programFiles\Autodesk\AdODIS\V1\Access\RemoveAccess.exe"; Arguments = '--mode unattended' }
    @{ Label = 'Autodesk Access uninstall helper'; Path = "$script:AdskUninstallers\Autodesk Access\AdskUninstallHelper.exe" }
    @{ Label = 'Autodesk ODIS remover';            Path = "$programFiles\Autodesk\AdODIS\V1\RemoveODIS.exe"; Arguments = '--mode unattended' }
    @{ Label = 'Autodesk Licensing remover';       Path = "$commonFilesX86\Autodesk Shared\AdskLicensing\uninstall.exe"; Arguments = '--mode unattended' }
)
Write-AdskProgress -Step 1 -Status 'Running the shared component removers' -Fraction 0.75
foreach ($remover in $sharedRemovers) { Invoke-AdskRemover -Remover $remover }

Write-AdskProgress -Step 1 -Status 'Cleaning Windows Installer registrations' -Fraction 0.9
Invoke-AdskInstallerCleanup -KnownCodes $knownCodes -Exclude $genuineCodes -Names $productNames
Remove-AdskUninstallEntry

# ==== Step 2: Identity Manager and the remaining uninstall helpers ====
Write-AdskProgress -Step 2 -Status 'Uninstalling the Autodesk Identity Manager'
$step2Removers = @(
    @{ Label = 'Autodesk Identity Manager uninstaller'; Path = "$programFiles\Autodesk\AdskIdentityManager\uninstall.exe"; Arguments = '--mode unattended'; WaitForEmptyFolder = $true }
    @{ Label = 'Autodesk Identity Manager Component uninstall helper'; Path = "$script:AdskUninstallers\Autodesk Identity Manager Component\AdskUninstallHelper.exe"; NoNewWindow = $true; StopMessageRouter = $true }
    @{ Label = 'Autodesk Installer uninstall helper'; Path = "$script:AdskUninstallers\Autodesk Installer\AdskUninstallHelper.exe"; NoNewWindow = $true; StopMessageRouter = $true }
)
foreach ($remover in $step2Removers) { Invoke-AdskRemover -Remover $remover }

# ==== Step 3: services, %TEMP%, FLEXnet and folders ====
Write-AdskProgress -Step 3 -Status 'Stopping what the uninstallers restarted'
# The uninstallers routinely start their own services again on the way out (Autodesk Access and
# the licensing agent both do), and anything running here holds file handles that make the
# deletion below fail.
$adskStillRunning = Invoke-AdskServiceAndProcessSweep -Phase 'pre-deletion'
if ($adskStillRunning -gt 0 -and -not $WhatIfPreference) {
    Write-AdskLog "$adskStillRunning Autodesk process(es) still running going into folder deletion; expect locked files." 'FileSystem' -Severity Error
}
Remove-AdskService

$profiles = @(Get-AdskProfile)
Write-AdskProgress -Step 3 -Status 'Clearing the temp folders' -Fraction 0.1
# A user's own %TEMP% is one of the profile folders already; run as SYSTEM (deployment tools) it
# is the system temp folder, which is cleared as that account's %TEMP%.
$tempFolders = @($profiles | Where-Object IsUser | ForEach-Object { Join-Path -Path $_.Path -ChildPath 'AppData\Local\Temp' })
if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { $tempFolders += $env:TEMP }
Clear-AdskTempFolder -Folder $tempFolders

$flexnet = Join-Path -Path $script:Folders.ProgramData -ChildPath 'FLEXnet'
$flexnetFiles = @(Get-ChildItem -LiteralPath $flexnet -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^adsk' })
if ($flexnetFiles.Count -gt 0 -and (Test-ShouldProcess -Target $flexnet -Action "Delete $($flexnetFiles.Count) adsk* license file(s)")) {
    $flexnetErrors = $null
    $flexnetFiles | Remove-Item -Force -ErrorAction SilentlyContinue -ErrorVariable flexnetErrors
    $script:WorkDone = $true
    if ($flexnetErrors) {
        Write-AdskLog ("Removed $($flexnetFiles.Count - $flexnetErrors.Count) of $($flexnetFiles.Count) Autodesk FLEXnet file(s); failures:`r`n" + (($flexnetErrors | ForEach-Object { $_.Exception.Message }) -join "`r`n")) 'FileSystem' -Severity Error
    } else {
        Write-AdskLog "Removed $($flexnetFiles.Count) Autodesk FLEXnet file(s)." 'FileSystem'
    }
}

$profileFolders = foreach ($userProfile in $profiles) {
    Join-Path -Path $userProfile.Path -ChildPath 'AppData\Local\Autodesk'
    Join-Path -Path $userProfile.Path -ChildPath 'AppData\Roaming\Autodesk'
}
$foldersToDelete = @(@($script:AdskProgramFolders) + @($profileFolders) + @(Get-AdskProgramDataResidue) | Where-Object { Test-Path -LiteralPath $_ })
if ($foldersToDelete.Count -eq 0) {
    Write-AdskLog 'No Autodesk folders present to delete.' 'FileSystem'
} else {
    Write-AdskLog "Deleting $($foldersToDelete.Count) Autodesk folder(s)..." 'FileSystem'
    for ($i = 0; $i -lt $foldersToDelete.Count; $i++) {
        Write-AdskProgress -Step 3 -Status "Deleting $($foldersToDelete[$i])" -Fraction (0.2 + $i / $foldersToDelete.Count * 0.7)
        Remove-AdskItem -Path $foldersToDelete[$i]
    }
}
# Anything that survived is held open by a running process; remove it at next boot, before
# anything can reload it.
Register-AdskSurvivors -Path $foldersToDelete -Component 'FileSystem'
Remove-AdskStaleReference

# ==== Step 4: registry ====
# HKEY_USERS only shows loaded hives (signed-in users, service accounts); the deferred task
# reaches the others.
Write-AdskProgress -Step 4 -Status 'Removing the Autodesk registry keys'
$loadedHives = @(Get-AdskSubKeyName 'HKU' | Where-Object { $_ -notlike '*_Classes' })
$autodeskKeys = @('HKLM\SOFTWARE\Autodesk', 'HKLM\SOFTWARE\WOW6432Node\Autodesk') +
                @(foreach ($hive in $loadedHives) { "HKU\$hive\SOFTWARE\Autodesk"; "HKU\$hive\SOFTWARE\WOW6432Node\Autodesk" })
foreach ($key in $autodeskKeys) { [void](Remove-AdskRegistryTree $key -Component 'Registry') }

# ==== Step 5: Autodesk Genuine Service, then the rest of C:\ProgramData\Autodesk ====
# It can only be uninstalled once all Autodesk software, files, folders and registry keys are gone.
Write-AdskProgress -Step 5 -Status 'Uninstalling the Autodesk Genuine Service'
foreach ($code in $genuineCodes) {
    $state = Get-AdskProductState $code
    if ($state -in 1, 2, 5) {
        Write-Host 'Uninstalling Autodesk Genuine Service...'
        $script:MsiResults[$code] = Invoke-AdskMsiUninstall -ProductCode $code -Name $productNames[$code]
    }
    if (@(Get-AdskMsiResidue -ProductCode $code -Index $script:InstallerIndex).Count -and $script:InstallerIndex) {
        Invoke-AdskForcedCleanup -ProductCode $code -Name $productNames[$code] -Index $script:InstallerIndex
    }
}
Invoke-AdskRemover -Remover @{ Label = 'Autodesk Genuine Service uninstall helper'; Path = "$script:AdskUninstallers\Autodesk Genuine Service\AdskUninstallHelper.exe"; NoNewWindow = $true; StopMessageRouter = $true }
Remove-AdskService -IncludeGenuine
Remove-AdskUninstallEntry -IncludeGenuine

Write-AdskProgress -Step 5 -Status "Deleting $script:AdskProgramData" -Fraction 0.8
Remove-AdskItem -Path $script:AdskProgramData
Register-AdskSurvivors -Path @($script:AdskProgramData) -Component 'FileSystem'
Remove-AdskExternalFile
Remove-AdskShellResidue -Profiles $profiles

# ---- deferred boot-time cleanup ----
# The COM/shell-extension removal and the final per-user key cleanup wait for a one-shot SYSTEM
# task at next boot: doing either now would stall shutdown (the registrations belong to a DLL
# explorer.exe still has loaded) and the key would simply be rewritten by that DLL.
$deferredScriptPath = $null
$comRegistrations = @(Get-AdskComRegistration).Count
$foldersLeft = @(@($script:AdskProgramFolders) + $script:AdskProgramData | Where-Object { Test-Path -LiteralPath $_ }).Count
if ($script:WorkDone -or $comRegistrations -gt 0 -or $foldersLeft -gt 0) {
    try {
        $deferredScriptPath = Register-AdskDeferredCleanup -WorkDir $script:DeferredWorkDir
        if ($deferredScriptPath) {
            $script:RebootRequired = $true
            Write-AdskLog "Registered one-shot deferred cleanup task '$script:DeferredTaskName' -> $deferredScriptPath ($comRegistrations Autodesk COM registration(s) pending)" 'Deferred' -Severity Warning
            Write-Host "Remaining Autodesk COM registrations and per-user keys will be removed on the next restart." -ForegroundColor Yellow
        }
    } catch {
        Write-AdskStatus "Could not register the deferred cleanup task: $($_.Exception.Message)" 'Deferred' -Severity Error
    }
}

# Kept MSI logs stay; remove the folder only when empty, and only if it is a real directory, not
# a redirect.
$msiLogDir = Get-Item -LiteralPath $script:MsiLogPath -Force -ErrorAction SilentlyContinue
if ($msiLogDir -and -not ($msiLogDir.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
    -not (Get-ChildItem -LiteralPath $script:MsiLogPath -Force -ErrorAction SilentlyContinue)) {
    Remove-Item -LiteralPath $script:MsiLogPath -Force -ErrorAction SilentlyContinue -WhatIf:$false
}

# ---- verification ----
# Every Autodesk product code seen during the run is checked against what Windows Installer
# reports and what its registry store holds right now - never against what the cleanup did - so
# the exit code reflects the actual end state.
foreach ($forced in $script:ForcedCleanups) { [void]$knownCodes.Add($forced.ProductCode) }
$unresolved = New-Object System.Collections.Generic.List[string]
if (-not $WhatIfPreference) {
    foreach ($code in $knownCodes) {
        $residue = @(Get-AdskMsiResidue -ProductCode $code -Index $script:InstallerIndex)
        if ($residue.Count) { $unresolved.Add("$($productNames[$code]) $code`r`n    $($residue -join "`r`n    ")") }
    }
    foreach ($entry in Get-AdskUninstallEntry | Where-Object { -not $knownCodes.Contains($_.Code) }) {
        $unresolved.Add("$($entry.Name) $($entry.Code)`r`n    $($entry.Path)")
    }
    foreach ($item in Get-AdskShellResidue -Profiles $profiles) {
        $unresolved.Add("$($item.Kind) $($item.Path)$(if ($item.Kind -eq 'Path') { " ($($item.Entry))" })`r`n    -> $($item.Target)")
    }
}

$failedUninstalls = @($script:MsiResults.GetEnumerator() | Where-Object { $_.Value.Outcome -eq 'Failed' })
if ($script:ForcedCleanups.Count) {
    $forcedText = ($script:ForcedCleanups | ForEach-Object { "  $($_.Name) $($_.ProductCode) ($($_.Trigger))" }) -join "`r`n"
    Write-AdskLog "Forced Windows Installer cleanup was needed for $($script:ForcedCleanups.Count) product(s):`r`n$forcedText`r`nBackup of every removed key and value: $script:BackupFolder" 'Summary' -Severity Warning
}
if ($unresolved.Count) {
    $exitCode = 1
    Write-AdskLog "Autodesk clean uninstall finished with $($unresolved.Count) item(s) left (registrations, entries, shortcuts, associations, PATH):`r`n$($unresolved -join "`r`n")" 'Summary' -Severity Error
} elseif ($script:ForcedCleanups.Count) {
    $exitCode = 10
    Write-AdskLog 'Autodesk clean uninstall completed with forced registration cleanup; everything verified clean; restart required (Exit Code 10).' 'Summary' -Severity Warning
} elseif ($script:RebootRequired) {
    $exitCode = 3010
    Write-AdskLog 'Autodesk clean uninstall completed; restart required (Exit Code 3010).' 'Summary' -Severity Warning
} else {
    $exitCode = 0
    Write-AdskLog 'Autodesk clean uninstall completed (Exit Code 0).' 'Summary'
}
$failedBundles = @($script:BundleResults.Values | Where-Object { $_.Outcome -eq 'Failed' })
Write-AdskLog ("Uninstalled $(@($script:BundleResults.Values | Where-Object { $_.Outcome -in 'Removed', 'RebootRequired' }).Count) ODIS bundle(s) ($($failedBundles.Count) failed) and " +
    "$(@($script:MsiResults.Values | Where-Object { $_.Outcome -in 'Removed', 'RebootRequired' }).Count) further MSI product(s) ($($failedUninstalls.Count) failed); $($script:ForcedCleanups.Count) forced cleanup(s).") 'Summary'
# estimate against reality, to recalibrate Get-AdskDurationEstimate from real deployments
Write-AdskLog "Duration: $([math]::Round($script:RunClock.Elapsed.TotalMinutes, 1)) minutes; estimated $($estimate.Minutes) ($($estimate.Low)-$($estimate.High)) for $($estimate.SizeGB) GB." 'Summary'

Write-Progress -Activity 'Autodesk clean uninstall' -Completed

$notification = $null
if ($script:Interactive) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $notification = New-Object System.Windows.Forms.NotifyIcon
    $notification.Icon = [System.Drawing.SystemIcons]::Information
    $notification.BalloonTipTitle = "Autodesk Uninstall Completed..."
    $notification.BalloonTipText = "Please follow the instruction in the PowerShell-Window."
    $notification.Visible = $true
    $notification.ShowBalloonTip(30000)
    Add-Type -AssemblyName Microsoft.VisualBasic
    # AppActivate throws "Process was not found" when there is no window to activate; never let
    # a cosmetic notification emit an error at the end
    try { [Microsoft.VisualBasic.Interaction]::AppActivate($PID) } catch { }
}

if ($unresolved.Count) {
    Write-Host "`r`nAutodesk removal finished, but $($unresolved.Count) item(s) are left:" -ForegroundColor Red
    $unresolved | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host "A complete Log has been generated at $script:LogFile" -ForegroundColor Red
} else {
    Write-Host "`r`nAutodesk products have been uninstalled successfully.`r`nA complete Log has been generated at $script:LogFile" -ForegroundColor Green
    if ($script:ForcedCleanups.Count) {
        Write-Host "$($script:ForcedCleanups.Count) product(s) needed a forced Windows Installer cleanup (see the log); a backup of everything removed is in $script:BackupFolder" -ForegroundColor Yellow
    }
}
# Always ask for a restart, even when nothing is left pending: the sweep disabled and stopped
# services and killed processes holding Autodesk handles, and only a reboot brings the remaining
# system state back to a known-good baseline.
Write-Host "Please restart your computer to complete the uninstallation process." -ForegroundColor Yellow
if ($deferredScriptPath) {
    Write-Host "The remaining cleanup runs automatically during that restart, before anyone logs on," -ForegroundColor Yellow
    Write-Host "then removes itself. It appends to $script:LogFile" -ForegroundColor Yellow
}
Wait-ForUser
if ($notification) { $notification.Dispose() }

# -ForceRestart: restart without asking, whether interactive or not. Checked before the
# interactive branch so it works in unattended deployments, where the deferred boot-time cleanup
# should complete straight away.
if ($ForceRestart) {
    Write-AdskLog '-ForceRestart specified: restarting the computer now.' 'Summary' -Severity Warning
    Write-Host "`r`nRestarting now (-ForceRestart)..." -ForegroundColor Yellow
    if (Test-ShouldProcess -Target $env:COMPUTERNAME -Action 'Restart computer') { Restart-Computer -Force }
    exit $exitCode
}

if (-not $script:Interactive -or $NoRestart) {
    Write-AdskLog 'Non-interactive or -NoRestart: skipping the restart prompt.' 'Summary'
    exit $exitCode
}

$answer = Read-Host -Prompt "`r`nWould you like to restart your computer now? (Y/N)"
switch -Regex ($answer) {
    '^(y|yes)$' {
        Write-AdskLog 'Restarting the computer as per user request.' 'Summary'
        if (Test-ShouldProcess -Target $env:COMPUTERNAME -Action 'Restart computer') { Restart-Computer -Force }
    }
    '^(n|no)$' {
        Write-AdskLog 'User chose not to restart the computer.' 'Summary'
        Write-Host "Please restart your computer manually to complete the uninstallation process."
    }
    default {
        Write-AdskLog "Unknown response from user regarding restart: '$answer'. Skipping restart." 'Summary'
        Write-Host "Unknown Response. Please restart your computer manually to complete the uninstallation process."
    }
}

exit $exitCode

#endregion

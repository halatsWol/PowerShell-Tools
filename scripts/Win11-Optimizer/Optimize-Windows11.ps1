#Requires -Version 5.1

<#
.SYNOPSIS
    Flexible Windows 11 optimizer with tiered intensity and a stacked, restorable rollback.

.DESCRIPTION
    A PowerShell reimagining of TBOK-Win11Optimizer. Applies Windows 11 optimizations at a chosen
    intensity (-Level Minimal | Balanced | Full, or a guided Custom walkthrough), while capturing the
    prior state of everything it touches so any run can be rolled back - including layered runs, which
    unwind one step at a time.

    Implemented: the Minimal / Balanced / Full tiers, a guided Custom walkthrough, the optional
    -IncludeAI / -IncludeGaming add-ons, -AllUsers fan-out of user-scope tweaks across every profile
    (including the Default template), a hardware-aware data-driven tweak catalog, live apply of registry /
    service / power / Appx / scheduled-task tweaks, a VSS restore point, and a stacked (LIFO) rollback with per-run,
    per-segment undo scripts under ProgramData. Windows Defender is never weakened by any level or add-on.

.PARAMETER Level
    Intensity to apply: Minimal (safest), Balanced (default, recommended), Full (aggressive; behind a
    confirmation prompt), or Custom (an interactive, per-category guided walkthrough). Levels are
    cumulative: Full includes Balanced includes Minimal.

.PARAMETER IncludeAI
    Also apply the AI add-on (turn off Copilot and Recall, remove the Copilot app). Automatic at Full;
    opt-in at other levels. Captured into its own rollback stack (see -Rollback -IncludeAI).

.PARAMETER IncludeGaming
    Also apply the Gaming add-on (Hardware-Accelerated GPU Scheduling, game task priorities, Game DVR off).
    Automatic at Full; opt-in at other levels. Captured into its own rollback stack.

.PARAMETER Categories
    Restrict the run to one or more tweak categories (e.g. Explorer, Privacy, Services). Applies to Apply
    and -Preview.

.PARAMETER AllUsers
    Apply the user-scope (HKCU) tweaks to every user profile - loaded live where present, or by loading each
    profile's NTUSER.DAT on demand - plus the Default profile template so new users inherit them. Machine
    tweaks still apply once.

.PARAMETER SkipRestorePoint
    Skip creating the VSS System Restore point before applying (the surgical undo script + snapshot remain).

.PARAMETER NoRollbackScript
    Do not emit the standalone undo .ps1 files (the JSON snapshot and in-process -Rollback still work).

.PARAMETER Force
    Skip the Full-tier confirmation prompt (required to run Full non-interactively).

.PARAMETER Preview
    Read-only: list the selected tweaks and their current on-machine values without changing anything.

.PARAMETER Rollback
    Undo previously applied runs. On its own, undoes the newest Level layer; combine with -To, -All,
    -IncludeAI or -IncludeGaming.

.PARAMETER To
    With -Rollback: unwind Level layers from newest back to the given snapshot id (inclusive). See
    -ListSnapshots for ids.

.PARAMETER All
    With -Rollback: undo every active layer across all stacks (return to baseline).

.PARAMETER ListSnapshots
    List the recorded snapshot layers (ids, timestamps, tweak counts, status) and the top of each stack.

.PARAMETER NoProtectSnapshots
    Skip ACL-hardening of the ProgramData snapshot store.

.PARAMETER Quiet
    Suppress console output (the run log file is still written).

.EXAMPLE
    .\Optimize-Windows11.ps1 -Preview -Level Balanced
    Show what Balanced would change, read-only.

.EXAMPLE
    .\Optimize-Windows11.ps1 -Level Minimal -AllUsers
    Apply the Minimal tier to every user profile and the Default template.

.EXAMPLE
    .\Optimize-Windows11.ps1 -Level Full -Force
    Apply the aggressive Full tier (and the AI/Gaming add-ons) without the interactive prompt.

.EXAMPLE
    .\Optimize-Windows11.ps1 -Rollback -All
    Undo every applied run, back to baseline.

.NOTES
    Author: Wolfram Halatschek
    E-Mail: dev@kMarflow.com
    Date:   2026-09-01

    Provided as-is, not supported by Microsoft. Review and understand the code, and test on a
    non-production machine, before running. Requires administrative privileges to apply or roll back.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Apply')]
param (
    # --- Apply / Preview -------------------------------------------------------------------------
    [Parameter(ParameterSetName = 'Apply', Position = 0)]
    [Parameter(ParameterSetName = 'Preview')]
    [ValidateSet('Minimal', 'Balanced', 'Full', 'Custom')]
    [string]$Level = 'Balanced',

    [Parameter(ParameterSetName = 'Apply')]
    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Rollback')]
    [switch]$IncludeAI,

    [Parameter(ParameterSetName = 'Apply')]
    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Rollback')]
    [switch]$IncludeGaming,

    [Parameter(ParameterSetName = 'Apply')]
    [Parameter(ParameterSetName = 'Preview')]
    [string[]]$Categories,

    [Parameter(ParameterSetName = 'Apply')]
    [switch]$AllUsers,

    [Parameter(ParameterSetName = 'Apply')]
    [switch]$SkipRestorePoint,

    [Parameter(ParameterSetName = 'Apply')]
    [switch]$NoRollbackScript,

    [Parameter(ParameterSetName = 'Apply')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Preview', Mandatory = $true)]
    [Alias('ListTweaks')]
    [switch]$Preview,

    # --- Rollback --------------------------------------------------------------------------------
    [Parameter(ParameterSetName = 'Rollback', Mandatory = $true)]
    [switch]$Rollback,

    [Parameter(ParameterSetName = 'Rollback')]
    [string]$To,

    [Parameter(ParameterSetName = 'Rollback')]
    [switch]$All,

    [Parameter(ParameterSetName = 'ListSnapshots', Mandatory = $true)]
    [switch]$ListSnapshots,

    # --- Cross-cutting (valid in every mode) -----------------------------------------------------
    [switch]$NoProtectSnapshots,

    [switch]$Quiet
)

# =================================================================================================
# Constants
# =================================================================================================
$script:ScriptVersion   = '0.17.0'
$script:VendorRoot       = Join-Path $env:ProgramData 'Marflow Software'
$script:StoreRoot        = Join-Path $script:VendorRoot 'Win11Optimizer'
$script:SnapshotsRoot    = Join-Path $script:StoreRoot 'Snapshots'
$script:RolledBackRoot   = Join-Path $script:SnapshotsRoot '_rolledback'
$script:LogsRoot         = Join-Path $script:StoreRoot 'Logs'
$script:StackIndexPath   = Join-Path $script:StoreRoot 'stack-index.json'
$script:StartStamp       = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
$script:LogFile          = $null                 # resolved once the store is ready
$script:ExitCode         = 0                     # 0 ok, 1 partial/problem, 2 fatal/startup
$script:WindowsBuildMin  = 22000                 # Windows 11 = build 22000+

# =================================================================================================
# Logging & exit-code helpers
# =================================================================================================
function Write-OptiLog {
    <#
        Timestamped, single-line logging. Always appends to the run log file (once it exists);
        mirrors to the console per level unless -Quiet was requested. Never throws on a logging
        failure - a broken log must not abort an optimization run.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    # Logging is bookkeeping, not a system change: it must run (and be recorded) even under -WhatIf.
    $WhatIfPreference = $false

    $line = "[{0}] {1,-7} {2}" -f (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'), $Level.ToUpper(), $Message

    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    }

    if (-not $Quiet) {
        switch ($Level) {
            'Warning' { Write-Warning $Message }
            'Error'   { Write-Host $Message -ForegroundColor Red }
            'Success' { Write-Host $Message -ForegroundColor Green }
            default   { Write-Host $Message }
        }
    }
}

function Set-OptiExit {
    <#
        Escalates the process exit code using highest-severity-wins so a later success can never mask
        an earlier problem. 2 (fatal) outranks 1 (partial) outranks 0 (ok).
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 2)]
        [int]$Code
    )
    if ($Code -gt $script:ExitCode) { $script:ExitCode = $Code }
}

# =================================================================================================
# Environment guards
# =================================================================================================
function Test-OptiElevated {
    # $true when the current session is elevated (running as Administrator).
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-OptiOSInfo {
    <#
        Returns the facts the guards and (later) the conditional tweak engine need: build number and
        whether this is a client or server SKU. Server has no Checkpoint-Computer, so the restore-point
        step degrades on it later.
    #>
    $WhatIfPreference = $false   # read-only probe; never a -WhatIf target (and avoids CIM module-load WhatIf noise)
    $info = [PSCustomObject]@{
        Build      = 0
        Caption    = ''
        IsClient   = $true
        IsWindows11 = $false
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $info.Build    = [int]($os.BuildNumber)
        $info.Caption  = [string]$os.Caption
        $info.IsClient = ($os.ProductType -eq 1)   # 1 = Workstation, 2 = DC, 3 = Server
    } catch {
        $info.Build = [int][Environment]::OSVersion.Version.Build
    }
    $info.IsWindows11 = ($info.Build -ge $script:WindowsBuildMin)
    return $info
}

# =================================================================================================
# Snapshot store (ProgramData) bootstrap + ACL hardening
# =================================================================================================
function Initialize-SnapshotStore {
    <#
        Creates the ProgramData store tree (vendor root, Snapshots, _rolledback, Logs) and resolves the
        run log file. Returns $true on success. In a read-only mode without the rights to create it, it
        degrades to console-only logging rather than failing.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param ([switch]$ReadOnlyMode)

    $WhatIfPreference = $false   # store + log setup is infrastructure, not a -WhatIf target

    try {
        foreach ($dir in @($script:VendorRoot, $script:StoreRoot, $script:SnapshotsRoot, $script:RolledBackRoot, $script:LogsRoot)) {
            if (-not (Test-Path -LiteralPath $dir)) {
                New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        }
        $script:LogFile = Join-Path $script:LogsRoot ("Optimize-Windows11_{0}_{1}.log" -f $env:COMPUTERNAME, $script:StartStamp)
        return $true
    } catch {
        if ($ReadOnlyMode) {
            Write-Warning "Could not create the snapshot store at '$script:StoreRoot' ($($_.Exception.Message)). Continuing with console-only output."
            return $true
        }
        Write-Error "Failed to create the snapshot store at '$script:StoreRoot': $($_.Exception.Message)"
        return $false
    }
}

function Protect-SnapshotStore {
    <#
        Locks down the store so a standard user cannot casually delete the rollback history: inheritance
        is disabled and only SYSTEM + Administrators get full control; Users keep read/execute (so
        read-only modes still work) but no write/delete. Well-known SIDs are used so it is locale
        independent. A failure here is warned, not fatal - it hardens, it does not gate functionality.
    #>
    [CmdletBinding()]
    param ()

    $WhatIfPreference = $false   # ACL hardening is infrastructure, not a -WhatIf target

    if ($NoProtectSnapshots) {
        Write-OptiLog "Snapshot-store ACL hardening skipped (-NoProtectSnapshots)." 'Info'
        return
    }

    try {
        $sidSystem = New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $sidAdmins = New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $sidUsers  = New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)

        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $prop    = [Security.AccessControl.PropagationFlags]::None
        $allow   = [Security.AccessControl.AccessControlType]::Allow

        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited ACEs
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sidSystem, 'FullControl', $inherit, $prop, $allow)))
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sidAdmins, 'FullControl', $inherit, $prop, $allow)))
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sidUsers,  'ReadAndExecute', $inherit, $prop, $allow)))

        Set-Acl -LiteralPath $script:StoreRoot -AclObject $acl -ErrorAction Stop
        Write-OptiLog "Snapshot store hardened (SYSTEM + Administrators full control; Users read-only)." 'Info'
    } catch {
        Write-OptiLog "Could not harden the snapshot-store ACL: $($_.Exception.Message)" 'Warning'
    }
}

# =================================================================================================
# Tweak catalog
# =================================================================================================
# One declarative row per tweak. Apply, preview, capture and rollback are all derived from these
# fields, so there is no per-tweak imperative code. Fields:
#   Id/Name/Category/Impact - identity + guided-mode text.
#   MinLevel  - lowest tier a level row belongs to (cumulative: Full includes Balanced includes Minimal).
#   AddOn     - 'AI' | 'Gaming' for add-on rows (selected only when the add-on is requested / at Full);
#               $null for ordinary level rows.
#   Scope     - 'User' (HKCU) | 'Machine' (HKLM).
#   Risk / Reversible - reporting + guided-mode.
#   Type      - Registry | Service | Powercfg | Appx (implemented); ScheduledTask | Bcdedit (future).
#   Registry payload: Path / ValueName / ValueType / Data. Appx payload: PackageName (Get-AppxPackage -Name).
# The Minimal / Balanced / Full tiers and the AI add-on rows are all defined below.
function Get-TweakCatalog {
    @(
        [pscustomobject]@{
            Id = 'Explorer.LaunchToThisPC'; Name = 'Open File Explorer to This PC'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Opens File Explorer to This PC instead of Home/Quick Access.'
            Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'LaunchTo'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Explorer.HideTaskViewButton'; Name = 'Hide Task View button'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Hides the Task View button from the taskbar (feature stays available via Win+Tab).'
            Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'ShowTaskViewButton'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Explorer.TaskbarSearchIcon'; Name = 'Collapse taskbar search to an icon'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Shrinks the taskbar search box to a single icon to reclaim taskbar space.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
            ValueName = 'SearchboxTaskbarMode'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Performance.MenuShowDelay'; Name = 'Faster menu animations'; Category = 'Performance'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Reduces the menu open delay from 400ms to 10ms (snappier UI, no functional change).'
            Type = 'Registry'; Path = 'HKCU:\Control Panel\Desktop'
            ValueName = 'MenuShowDelay'; ValueType = 'String'; Data = '10'
        }
        [pscustomobject]@{
            Id = 'Privacy.DisableAdvertisingId'; Name = 'Disable advertising ID'; Category = 'Privacy'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops apps using an advertising ID to profile you. No functional loss.'
            Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
            ValueName = 'Enabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Privacy.LockScreenAdOverlay'; Name = 'Disable lock-screen ads (overlay)'; Category = 'Privacy'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = "Turns off ads and 'fun facts' shown on the lock screen (Spotlight overlay)."
            Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName = 'RotatingLockScreenOverlayEnabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Privacy.LockScreenAdSuggestions'; Name = 'Disable lock-screen suggestions'; Category = 'Privacy'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off suggested content / ads on the lock screen.'
            Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName = 'SubscribedContent-338387Enabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Performance.LongPathsEnabled'; Name = 'Enable Win32 long paths'; Category = 'Performance'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Allows paths longer than 260 characters for apps that opt in. Safe, widely recommended.'
            Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
            ValueName = 'LongPathsEnabled'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Power.FastStartupOff'; Name = 'Disable Fast Startup'; Category = 'Power'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables Fast Startup so Windows Update and drivers initialise cleanly; hibernation itself stays available.'
            Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
            ValueName = 'HiberbootEnabled'; ValueType = 'DWord'; Data = 0
        }
        # NOTE (deferred): 'Restore the full right-click menu' (a default-value write under a *created*
        # CLSID key) needs the undo engine to track and remove created keys - a later enhancement.
        # 'Hide the Widgets button' (TaskbarDa) is refused with UnauthorizedAccess on protected hives.
        # Both are deferred until they can be applied+rolled back reliably.
        [pscustomobject]@{
            Id = 'Explorer.EnableEndTaskOnTaskbar'; Name = 'Enable "End task" on taskbar'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Adds "End task" to the taskbar right-click menu for quickly killing a hung app.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings'
            ValueName = 'TaskbarEndTask'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Explorer.HideMeetNow'; Name = 'Hide "Meet Now"'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Removes the "Meet Now" (Skype) icon from the taskbar/notification area.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'HideSCAMeetNow'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Privacy.DisableWelcomeExperience'; Name = 'Disable Windows welcome/tips'; Category = 'Privacy'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off the "Windows welcome experience" and post-update suggestion screens.'
            Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName = 'SoftLandingEnabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Privacy.DisableTipsSuggestions'; Name = 'Disable tips & suggestions'; Category = 'Privacy'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops Windows showing "tips, tricks, and suggestions" as you use it.'
            Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName = 'SubscribedContent-338389Enabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Accessibility.DisableStickyKeysPrompt'; Name = 'Disable Sticky Keys shortcut prompt'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops the "press Shift five times" Sticky Keys pop-up (the feature can still be enabled in Settings).'
            Type = 'Registry'; Path = 'HKCU:\Control Panel\Accessibility\StickyKeys'
            ValueName = 'Flags'; ValueType = 'String'; Data = '506'
        }
        [pscustomobject]@{
            Id = 'Services.FaxManual'; Name = 'Fax service -> Manual'; Category = 'Services'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets the Fax service to start on-demand instead of automatically. Zero loss unless you fax.'
            Type = 'Service'; ServiceName = 'Fax'; StartupType = 'Manual'
        }
        [pscustomobject]@{
            Id = 'Services.MapsBrokerManual'; Name = 'Downloaded Maps Manager -> Manual'; Category = 'Services'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets the offline-maps service (MapsBroker) to start on-demand. Zero loss unless you use offline Maps.'
            Type = 'Service'; ServiceName = 'MapsBroker'; StartupType = 'Manual'
        }
        [pscustomobject]@{
            Id = 'Services.RetailDemoManual'; Name = 'Retail Demo service -> Manual'; Category = 'Services'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets RetailDemo (store demo mode) to start on-demand. Not used on normal machines.'
            Type = 'Service'; ServiceName = 'RetailDemo'; StartupType = 'Manual'
        }
        [pscustomobject]@{
            Id = 'Services.WMPNetworkManual'; Name = 'WMP Network Sharing -> Manual'; Category = 'Services'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets the legacy Windows Media Player network sharing service to start on-demand.'
            Type = 'Service'; ServiceName = 'WMPNetworkSvc'; StartupType = 'Manual'
        }
        [pscustomobject]@{
            Id = 'Explorer.SeparateProcess'; Name = 'Open each Explorer window in its own process'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Runs each File Explorer window in a separate process, so one hung window does not take the others (or the desktop) down with it.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'SeparateProcess'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Explorer.DisableFolderTypeDiscovery'; Name = 'Stop content-based folder view scanning'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; NoAllUsers = $true
            Impact = "Stops Explorer scanning a folder's contents to auto-pick a view (Automatic Folder Type Discovery); all folders use the General template for a consistent, faster open. Lives in the per-user UsrClass hive, so it applies to the current user only (not fanned out by -AllUsers)."
            Type = 'Registry'; Path = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell'
            ValueName = 'FolderType'; ValueType = 'String'; Data = 'NotSpecified'
        }
        [pscustomobject]@{
            Id = 'Explorer.QuickAccessNoRecentFiles'; Name = 'Hide recent files in Quick Access'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Hides recently used files in Quick Access / Home, cutting the scan Explorer does when it opens.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
            ValueName = 'ShowRecent'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Explorer.QuickAccessNoFrequentFolders'; Name = 'Hide frequent folders in Quick Access'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Hides frequently used folders in Quick Access / Home.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
            ValueName = 'ShowFrequent'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Explorer.CompactView'; Name = 'Use compact view spacing'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Uses the denser "compact view" row spacing in File Explorer, fitting more items per screen (list-friendly).'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'UseCompactMode'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Explorer.DisableFeeds'; Name = 'Disable News & Interests / feeds'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off the News & Interests / feeds widget on the taskbar (EnableFeeds policy).'
            Type = 'Registry'; Path = 'HKCU:\Software\Policies\Microsoft\Windows\Windows Feeds'
            ValueName = 'EnableFeeds'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Explorer.HideChatButton'; Name = 'Hide the Chat (Teams) taskbar button'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Removes the Chat / Microsoft Teams consumer button from the taskbar.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'TaskbarMn'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Explorer.DetailedCopyDialog'; Name = 'Detailed file-operation dialog'; Category = 'Explorer'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Always shows the detailed copy/move dialog (with the throughput graph) by default.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager'
            ValueName = 'EnthusiastMode'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Performance.VisualFxBestPerformance'; Name = 'Visual effects: adjust for best performance'; Category = 'Performance'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets the visual-effects mode to "adjust for best performance" (VisualFXSetting=3).'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
            ValueName = 'VisualFXSetting'; ValueType = 'DWord'; Data = 3
        }
        [pscustomobject]@{
            Id = 'Performance.DisableWindowAnimations'; Name = 'Disable window minimize/maximize animations'; Category = 'Performance'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off the window minimize/maximize animation for snappier windowing.'
            Type = 'Registry'; Path = 'HKCU:\Control Panel\Desktop\WindowMetrics'
            ValueName = 'MinAnimate'; ValueType = 'String'; Data = '0'
        }
        [pscustomobject]@{
            Id = 'Performance.DisableAeroPeek'; Name = 'Disable Aero Peek'; Category = 'Performance'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off the Aero Peek desktop-preview effect.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\DWM'
            ValueName = 'EnableAeroPeek'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Privacy.DisableAdvertisingIdPolicy'; Name = 'Disable advertising ID (machine policy)'; Category = 'Privacy'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the advertising ID for all users via group policy (complements the per-user setting).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
            ValueName = 'DisabledByGroupPolicy'; ValueType = 'DWord'; Data = 1
        }

        # ---- Balanced ----------------------------------------------------------------------------
        [pscustomobject]@{
            Id = 'Performance.SystemResponsiveness'; Name = 'Tune multimedia responsiveness'; Category = 'Performance'
            MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Lowers the multimedia scheduler reserve from 20 to 10 (Microsoft-documented value) for a touch more responsiveness.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            ValueName = 'SystemResponsiveness'; ValueType = 'DWord'; Data = 10
        }
        [pscustomobject]@{
            Id = 'Network.IRPStackSize'; Name = 'Increase network IRP stack size'; Category = 'Network'
            MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Raises the LanmanServer IRP stack size to 30 to avoid file-sharing stalls on busy networks.'
            Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName = 'IRPStackSize'; ValueType = 'DWord'; Data = 30
        }
        [pscustomobject]@{
            Id = 'Privacy.DisableBingSearch'; Name = 'Disable Bing in Start search'; Category = 'Privacy'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops the Start menu / search box from sending queries to Bing.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
            ValueName = 'BingSearchEnabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Privacy.DisableSearchSuggestions'; Name = 'Disable web search suggestions'; Category = 'Privacy'
            MinLevel = 'Minimal'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off web/search-box suggestions in the Start menu.'
            Type = 'Registry'; Path = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'DisableSearchBoxSuggestions'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Privacy.DisableTailoredExperiences'; Name = 'Disable tailored experiences'; Category = 'Privacy'
            MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops Windows using your diagnostic data to tailor tips, ads and recommendations.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'
            ValueName = 'TailoredExperiencesWithDiagnosticDataEnabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Privacy.ReduceTelemetry'; Name = 'Reduce telemetry to Required (not off)'; Category = 'Privacy'
            MinLevel = 'Balanced'; MaxLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets diagnostic data to the Required level (1) - NOT off - so Windows Update and the Store keep working. Full turns it fully off instead.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Explorer.DisableTaskbarAnimations'; Name = 'Disable taskbar animations'; Category = 'Explorer'
            MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off taskbar animations for a snappier feel (purely cosmetic).'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'TaskbarAnimations'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Power.HibernationOff'; Name = 'Disable hibernation (desktops only)'; Category = 'Power'
            MinLevel = 'Balanced'; MaxLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'On desktops, disables hibernation and reclaims hiberfil.sys. Skipped on laptops so low-battery hibernate still protects unsaved work. Full disables it on laptops too.'
            Condition = { param($hw) $hw.IsDesktop }
            Type = 'Powercfg'; PowercfgAction = 'hibernate-off'
        }

        # Consumer-content / suggested-apps cleanup: stop Windows silently installing suggested apps and
        # showing Start / Explorer / setup suggestions and ads. All per-user, fully reversible.
        [pscustomobject]@{ Id = 'Privacy.NoSilentInstalledApps'; Name = 'Stop silently installed suggested apps'; Category = 'Privacy'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; Impact = 'Stops Windows silently installing "suggested" apps in the background.'; Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SilentInstalledAppsEnabled'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{ Id = 'Privacy.NoContentDelivery';     Name = 'Disable content-delivery suggestions'; Category = 'Privacy'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; Impact = 'Turns off the content-delivery engine behind Start / Settings / lock-screen suggestions.'; Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'ContentDeliveryAllowed'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{ Id = 'Privacy.NoOemPreinstalled';     Name = 'Disable OEM pre-installed suggestions'; Category = 'Privacy'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; Impact = 'Stops OEM pre-installed app suggestions.'; Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'OemPreInstalledAppsEnabled'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{ Id = 'Privacy.NoPreinstalledApps';    Name = 'Disable pre-installed app suggestions'; Category = 'Privacy'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; Impact = 'Stops Windows pre-installing suggested apps for the account.'; Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'PreInstalledAppsEnabled'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{ Id = 'Privacy.NoStartSuggestions';    Name = 'Disable Start-menu suggestions'; Category = 'Privacy'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; Impact = 'Turns off suggested apps / ads in the Start menu (SystemPaneSuggestions).'; Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SystemPaneSuggestionsEnabled'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{ Id = 'Privacy.NoStartAppPromo';       Name = 'Disable Start app promotions'; Category = 'Privacy'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; Impact = 'Turns off promoted-app content in Start (SubscribedContent-338388).'; Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-338388Enabled'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{ Id = 'Privacy.NoStartIrisRecommend';  Name = 'Disable Start recommendations'; Category = 'Privacy'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; Impact = 'Turns off the "recommended" recommendation content in Start (Iris).'; Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; ValueName = 'Start_IrisRecommendations'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{ Id = 'Privacy.NoSyncProviderAds';     Name = 'Disable Explorer sync-provider ads'; Category = 'Privacy'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; Impact = 'Stops the OneDrive / "sync provider" promotional notifications shown in File Explorer.'; Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; ValueName = 'ShowSyncProviderNotifications'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{ Id = 'Privacy.NoScoobePrompts';       Name = 'Disable post-update setup prompts'; Category = 'Privacy'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true; Impact = 'Turns off the "finish setting up your device" prompts after updates (SCOOBE).'; Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement'; ValueName = 'ScoobeSystemSettingEnabled'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{
            Id = 'Performance.DisableBackgroundApps'; Name = 'Disable background apps (global)'; Category = 'Performance'
            MinLevel = 'Balanced'; AddOn = $null; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops UWP / Store apps running in the background for the current user, freeing CPU and RAM.'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
            ValueName = 'GlobalUserDisabled'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Performance.VerboseStatus'; Name = 'Verbose startup/shutdown messages'; Category = 'Performance'
            MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Shows detailed status messages during startup/shutdown (handy for diagnosing slow boots).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'VerboseStatus'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Performance.WaitToKillServiceTimeout'; Name = 'Trim service shutdown wait'; Category = 'Performance'
            MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets the service shutdown wait to 5000 ms so shutdown / restart does not hang on a slow service.'
            Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control'
            ValueName = 'WaitToKillServiceTimeout'; ValueType = 'String'; Data = '5000'
        }

        # Essential-service baseline normalization: set core services back to their correct Windows
        # default start type. Idempotent (only changes a service that actually differs) and only ever
        # moves a service TOWARD its running baseline - never disables/weakens one (the Defender guard
        # still blocks any weakening of a protected service).
        [pscustomobject]@{ Id = 'Services.NormEventLog';   Name = 'Normalize EventLog';          Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the Windows Event Log service is Automatic (no change if already correct).';       Type = 'Service'; ServiceName = 'EventLog';           StartupType = 'Automatic' }
        [pscustomobject]@{ Id = 'Services.NormRpcSs';      Name = 'Normalize RPC';               Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the Remote Procedure Call service is Automatic (no change if already correct).';       Type = 'Service'; ServiceName = 'RpcSs';              StartupType = 'Automatic' }
        [pscustomobject]@{ Id = 'Services.NormDhcp';       Name = 'Normalize DHCP client';       Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the DHCP Client service is Automatic (no change if already correct).';                 Type = 'Service'; ServiceName = 'Dhcp';               StartupType = 'Automatic' }
        [pscustomobject]@{ Id = 'Services.NormDnscache';   Name = 'Normalize DNS client';        Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the DNS Client service is Automatic (no change if already correct).';                  Type = 'Service'; ServiceName = 'Dnscache';           StartupType = 'Automatic' }
        [pscustomobject]@{ Id = 'Services.NormBFE';        Name = 'Normalize Base Filtering';    Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the Base Filtering Engine (firewall core) is Automatic (no change if already correct).'; Type = 'Service'; ServiceName = 'BFE';                StartupType = 'Automatic' }
        [pscustomobject]@{ Id = 'Services.NormMpsSvc';     Name = 'Normalize Windows Firewall';  Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the Windows Firewall service is Automatic (no change if already correct).';            Type = 'Service'; ServiceName = 'mpssvc';             StartupType = 'Automatic' }
        [pscustomobject]@{ Id = 'Services.NormWinmgmt';    Name = 'Normalize WMI';               Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the WMI (Windows Management Instrumentation) service is Automatic (no change if already correct).'; Type = 'Service'; ServiceName = 'Winmgmt';        StartupType = 'Automatic' }
        [pscustomobject]@{ Id = 'Services.NormSchedule';   Name = 'Normalize Task Scheduler';    Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the Task Scheduler service is Automatic (no change if already correct).';              Type = 'Service'; ServiceName = 'Schedule';           StartupType = 'Automatic' }
        [pscustomobject]@{ Id = 'Services.NormLanmanWks';  Name = 'Normalize Workstation';       Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the Workstation (SMB client) service is Automatic (no change if already correct).';     Type = 'Service'; ServiceName = 'LanmanWorkstation';  StartupType = 'Automatic' }
        [pscustomobject]@{ Id = 'Services.NormThemes';     Name = 'Normalize Themes';            Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the Themes service is Automatic (no change if already correct).';                      Type = 'Service'; ServiceName = 'Themes';              StartupType = 'Automatic' }
        # (SecurityHealthService is intentionally NOT normalized: Windows protects it so even an admin
        #  gets Access Denied configuring it - it is left entirely to Windows to manage.)
        [pscustomobject]@{ Id = 'Services.NormWscSvc';     Name = 'Normalize Security Center';   Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures the Security Center service is Delayed-Auto (its default). Strengthens, never weakens.'; Type = 'Service'; ServiceName = 'wscsvc';              StartupType = 'AutomaticDelayedStart' }
        [pscustomobject]@{ Id = 'Services.NormWSearch';    Name = 'Normalize Windows Search';    Category = 'Services'; MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Ensures Windows Search is Delayed-Auto (its default; no change if already correct).';           Type = 'Service'; ServiceName = 'WSearch';             StartupType = 'AutomaticDelayedStart' }

        # ---- Scheduled tasks (telemetry / CEIP) --------------------------------------------------
        # Disabled, never deleted, and each is re-enabled on rollback only if it was enabled at capture.
        # Absent tasks (e.g. Office not installed) are skipped. Tiering mirrors the telemetry policy:
        # Office telemetry agents at Balanced (privacy, not core Windows), the Windows telemetry/CEIP
        # tasks only at Full - the same gate as turning diagnostic data fully off. Defender/Update/
        # System-Restore tasks are never touched.
        [pscustomobject]@{
            Id = 'Tasks.OfficeTelemetryLogon'; Name = 'Disable Office telemetry agent (logon)'; Category = 'ScheduledTasks'
            MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the Office telemetry agent that runs at logon. Skipped if Office is not installed.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Office\'; TaskName = 'OfficeTelemetryAgentLogOn'
        }
        [pscustomobject]@{
            Id = 'Tasks.OfficeTelemetryFallback'; Name = 'Disable Office telemetry agent (fallback)'; Category = 'ScheduledTasks'
            MinLevel = 'Balanced'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the Office telemetry agent fallback task. Skipped if Office is not installed.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Office\'; TaskName = 'OfficeTelemetryAgentFallBack'
        }
        [pscustomobject]@{
            Id = 'Tasks.CompatAppraiser'; Name = 'Disable Compatibility Appraiser'; Category = 'ScheduledTasks'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Medium'; Reversible = $true
            Impact = 'Disables the Windows telemetry Compatibility Appraiser task (feeds diagnostic/compat data). Aggressive - only at Full, matching the telemetry-off policy.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Windows\Application Experience\'; TaskName = 'Microsoft Compatibility Appraiser'
        }
        [pscustomobject]@{
            Id = 'Tasks.ProgramDataUpdater'; Name = 'Disable ProgramDataUpdater'; Category = 'ScheduledTasks'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the Application Experience ProgramDataUpdater telemetry task.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Windows\Application Experience\'; TaskName = 'ProgramDataUpdater'
        }
        [pscustomobject]@{
            Id = 'Tasks.CeipConsolidator'; Name = 'Disable CEIP Consolidator'; Category = 'ScheduledTasks'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the Customer Experience Improvement Program Consolidator task.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program\'; TaskName = 'Consolidator'
        }
        [pscustomobject]@{
            Id = 'Tasks.CeipUsb'; Name = 'Disable CEIP USB data task'; Category = 'ScheduledTasks'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the CEIP USB (UsbCeip) data-collection task.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program\'; TaskName = 'UsbCeip'
        }
        [pscustomobject]@{
            Id = 'Tasks.AutochkProxy'; Name = 'Disable Autochk Proxy (CEIP)'; Category = 'ScheduledTasks'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the Autochk Proxy task that collects CEIP/SQM data.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Windows\Autochk\'; TaskName = 'Proxy'
        }
        [pscustomobject]@{
            Id = 'Tasks.FeedbackDmClient'; Name = 'Disable feedback DmClient'; Category = 'ScheduledTasks'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the Feedback/Siuf DmClient diagnostic-upload task.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Windows\Feedback\Siuf\'; TaskName = 'DmClient'
        }
        [pscustomobject]@{
            Id = 'Tasks.FeedbackDmClientScenario'; Name = 'Disable feedback DmClient (scenario)'; Category = 'ScheduledTasks'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the Feedback/Siuf DmClientOnScenarioDownload diagnostic task.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Windows\Feedback\Siuf\'; TaskName = 'DmClientOnScenarioDownload'
        }
        [pscustomobject]@{
            Id = 'Tasks.DiskDiagnosticCollector'; Name = 'Disable disk SMART data upload'; Category = 'ScheduledTasks'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the DiskDiagnostic DATA COLLECTOR (sends SMART data to Microsoft). The disk-failure RESOLVER that warns you of a failing disk is deliberately left enabled.'
            Type = 'ScheduledTask'; TaskPath = '\Microsoft\Windows\DiskDiagnostic\'; TaskName = 'Microsoft-Windows-DiskDiagnosticDataCollector'
        }

        # ---- Full (aggressive - behind the confirmation gate) ------------------------------------
        # NOTE: appx debloat (Widgets/Bing removal) rides on the Appx engine that arrives with the AI
        # add-on; it is not in this tier yet.
        [pscustomobject]@{
            Id = 'Privacy.DisableTelemetry'; Name = 'Turn telemetry fully off'; Category = 'Privacy'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'High'; Reversible = $true
            Impact = 'Sets diagnostic data to 0 (off). Can interfere with Windows Update / Store / licensing over time - that is why Balanced keeps it at Required.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Privacy.DisableFeedbackNotifications'; Name = 'Disable feedback notifications'; Category = 'Privacy'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops Windows prompting you for feedback.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'DoNotShowFeedbackNotifications'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Privacy.DisableErrorReporting'; Name = 'Disable Windows Error Reporting'; Category = 'Privacy'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Medium'; Reversible = $true
            Impact = 'Turns off Windows Error Reporting (no crash data sent to Microsoft).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'Disabled'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Update.DisableDeliveryOptimization'; Name = 'Disable Delivery Optimization'; Category = 'Update'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops peer-to-peer sharing of Windows/Store update files (DODownloadMode=0).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
            ValueName = 'DODownloadMode'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Security.DisableWpbt'; Name = 'Disable WPBT vendor boot execution'; Category = 'Security'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Medium'; Reversible = $true
            Impact = 'Blocks the Windows Platform Binary Table so firmware cannot silently inject vendor software at boot.'
            Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            ValueName = 'DisableWpbtExecution'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Security.PreventDeviceMetadata'; Name = 'Block hardware metadata from network'; Category = 'Security'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops Windows fetching device metadata/drivers from the network unsolicited.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'
            ValueName = 'PreventDeviceMetadataFromNetwork'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'Network.DisableThrottling'; Name = 'Disable network throttling'; Category = 'Network'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets NetworkThrottlingIndex to 0xFFFFFFFF (off) for maximum network throughput.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            ValueName = 'NetworkThrottlingIndex'; ValueType = 'DWord'; Data = -1
        }
        [pscustomobject]@{
            Id = 'Performance.SvcHostSplitThreshold'; Name = 'Group svchost processes by RAM'; Category = 'Performance'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets the svchost split threshold to total RAM (KB) so services share fewer host processes.'
            Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control'
            ValueName = 'SvcHostSplitThresholdInKB'; ValueType = 'DWord'; Data = { param($hw) [int]([math]::Round($hw.RamBytes / 1KB)) }
        }
        [pscustomobject]@{
            Id = 'Edge.DisableStartupBoost'; Name = 'Disable Edge startup boost'; Category = 'Edge'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops Microsoft Edge pre-launching at sign-in.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'StartupBoostEnabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Edge.DisableBackgroundMode'; Name = 'Disable Edge background running'; Category = 'Edge'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Stops Microsoft Edge continuing to run in the background after you close it.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'BackgroundModeEnabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{ Id = 'Services.DisableDiagTrack';  Name = 'Disable DiagTrack telemetry';       Category = 'Services'; MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'High';   Reversible = $true; Impact = 'Disables the Connected User Experiences and Telemetry (DiagTrack) service. Part of the telemetry blackout.'; Type = 'Service'; ServiceName = 'DiagTrack';         StartupType = 'Disabled' }
        [pscustomobject]@{ Id = 'Services.DisableDmwappush'; Name = 'Disable WAP push telemetry';        Category = 'Services'; MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Medium'; Reversible = $true; Impact = 'Disables the dmwappushservice (device-management WAP push) telemetry channel.';                     Type = 'Service'; ServiceName = 'dmwappushservice'; StartupType = 'Disabled' }
        [pscustomobject]@{ Id = 'Services.DisableDiagHub';   Name = 'Disable diagnostics hub collector'; Category = 'Services'; MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Medium'; Reversible = $true; Impact = 'Disables the Diagnostics Hub standard collector service.';                                             Type = 'Service'; ServiceName = 'diagnosticshub.standardcollector.service'; StartupType = 'Disabled' }
        [pscustomobject]@{
            Id = 'Services.SysMainConditional'; Name = 'Tune SysMain by disk/RAM'; Category = 'Services'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Medium'; Reversible = $true
            Impact = 'On SSD/NVMe (or low-RAM HDD) SysMain (Superfetch) is Disabled; on an HDD with plenty of RAM it is set to Manual.'
            Type = 'Service'; ServiceName = 'SysMain'
            StartupType = { param($hw) if ($hw.SystemDiskIsSSD) { 'Disabled' } elseif ($hw.RamGB -gt 12) { 'Manual' } else { 'Disabled' } }
        }
        [pscustomobject]@{
            Id = 'Power.HibernationOffFull'; Name = 'Disable hibernation (all machines, incl. notebooks)'; Category = 'Power'
            MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Medium'; Reversible = $true
            Impact = 'At Full, disables hibernation on ALL machines including notebooks and reclaims hiberfil.sys. On a laptop this means a low battery will no longer hibernate to protect unsaved work.'
            Type = 'Powercfg'; PowercfgAction = 'hibernate-off'
        }
        [pscustomobject]@{
            Id = 'Explorer.AutoEndTasks'; Name = 'Auto-end hung tasks on shutdown'; Category = 'Explorer'
            MinLevel = 'Full'; AddOn = $null; Scope = 'User'; Risk = 'Medium'; Reversible = $true
            Impact = 'Automatically ends unresponsive apps at logoff/shutdown instead of waiting. Faster shutdown, but an app with unsaved work will not get a chance to prompt.'
            Type = 'Registry'; Path = 'HKCU:\Control Panel\Desktop'
            ValueName = 'AutoEndTasks'; ValueType = 'String'; Data = '1'
        }
        [pscustomobject]@{ Id = 'Edge.HideFirstRun';        Name = 'Skip Edge first-run experience'; Category = 'Edge'; MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Skips the Microsoft Edge first-run / welcome experience.'; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; ValueName = 'HideFirstRunExperience'; ValueType = 'DWord'; Data = 1 }
        [pscustomobject]@{ Id = 'Edge.DisableShopping';     Name = 'Disable Edge shopping assistant'; Category = 'Edge'; MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Turns off the Edge shopping / price-comparison assistant.'; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; ValueName = 'EdgeShoppingAssistantEnabled'; ValueType = 'DWord'; Data = 0 }
        [pscustomobject]@{ Id = 'Edge.DisableUserFeedback'; Name = 'Disable Edge feedback prompts'; Category = 'Edge'; MinLevel = 'Full'; AddOn = $null; Scope = 'Machine'; Risk = 'Low'; Reversible = $true; Impact = 'Turns off the Microsoft Edge user-feedback prompts.'; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; ValueName = 'UserFeedbackAllowed'; ValueType = 'DWord'; Data = 0 }

        # ---- AI add-on (-IncludeAI; auto-applied at Full) ----------------------------------------
        # Trims the Copilot / Recall / AI surfaces. The registry rows are fully reversible; the Appx
        # removal is best-effort - undo re-registers the app from its staged files when they are still
        # present, otherwise it must be reinstalled from the Store. None of these touch Defender, and
        # each AI row is captured into its own 'AI' stack so `-Rollback -IncludeAI` can peel just the
        # add-on back off (even after a Full run that pulled it in automatically).
        [pscustomobject]@{
            Id = 'AI.TurnOffCopilot'; Name = 'Turn off Windows Copilot'; Category = 'AI'
            MinLevel = $null; AddOn = 'AI'; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the Windows Copilot experience for the current user (policy TurnOffWindowsCopilot).'
            Type = 'Registry'; Path = 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot'
            ValueName = 'TurnOffWindowsCopilot'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'AI.HideCopilotButton'; Name = 'Hide the Copilot taskbar button'; Category = 'AI'
            MinLevel = $null; AddOn = 'AI'; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Removes the Copilot button from the taskbar (the feature itself is governed by the policy above).'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'ShowCopilotButton'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'AI.DisableRecallUser'; Name = 'Disable Recall / AI data analysis (user)'; Category = 'AI'
            MinLevel = $null; AddOn = 'AI'; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off Windows Recall (AI snapshot analysis) for the current user (DisableAIDataAnalysis).'
            Type = 'Registry'; Path = 'HKCU:\Software\Policies\Microsoft\Windows\WindowsAI'
            ValueName = 'DisableAIDataAnalysis'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'AI.DisableRecallMachine'; Name = 'Disable Recall / AI data analysis (machine)'; Category = 'AI'
            MinLevel = $null; AddOn = 'AI'; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off Windows Recall (AI snapshot analysis) machine-wide (DisableAIDataAnalysis).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            ValueName = 'DisableAIDataAnalysis'; ValueType = 'DWord'; Data = 1
        }
        [pscustomobject]@{
            Id = 'AI.DisableEdgeSidebar'; Name = 'Disable the Edge Copilot/Discover sidebar'; Category = 'AI'
            MinLevel = $null; AddOn = 'AI'; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables the Microsoft Edge sidebar that hosts Copilot and Discover (HubsSidebarEnabled=0).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'HubsSidebarEnabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'AI.RemoveCopilotApp'; Name = 'Remove the Copilot app (current user)'; Category = 'AI'
            MinLevel = $null; AddOn = 'AI'; Scope = 'User'; Risk = 'Medium'; Reversible = $true
            Impact = 'Removes the Microsoft Copilot Store app for the current user. Best-effort undo: re-registered from its staged files if still present, otherwise reinstall from the Store.'
            Type = 'Appx'; PackageName = 'Microsoft.Copilot'
        }
        [pscustomobject]@{
            Id = 'AI.DisableCopilotRuntime'; Name = 'Disable the Copilot runtime'; Category = 'AI'
            MinLevel = $null; AddOn = 'AI'; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Blocks the Windows Copilot runtime from loading (AllowCopilotRuntime=0).'
            Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsCopilot'
            ValueName = 'AllowCopilotRuntime'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'AI.DisableRecallEnablement'; Name = 'Block Recall from being enabled'; Category = 'AI'
            MinLevel = $null; AddOn = 'AI'; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Prevents Windows Recall from being enabled machine-wide (AllowRecallEnablement=0).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            ValueName = 'AllowRecallEnablement'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'AI.DisableCrossDeviceResume'; Name = 'Disable cross-device resume'; Category = 'AI'
            MinLevel = $null; AddOn = 'AI'; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off the phone/PC cross-device resume hand-off (IsResumeAllowed=0).'
            Type = 'Registry'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration'
            ValueName = 'IsResumeAllowed'; ValueType = 'DWord'; Data = 0
        }

        # ---- Gaming add-on (-IncludeGaming; auto-applied at Full) --------------------------------
        # All registry, all reversible; applies on laptops and desktops alike (no chassis gate). Captured
        # into its own 'Gaming' stack so `-Rollback -IncludeGaming` peels just this add-on back off. No
        # power-plan change (the Ultimate-Performance plan is deliberately never created/activated), no
        # boot-parameter (bcdedit) changes, and nothing here touches Defender.
        [pscustomobject]@{
            Id = 'Gaming.GpuHardwareScheduling'; Name = 'Enable Hardware-Accelerated GPU Scheduling'; Category = 'Gaming'
            MinLevel = $null; AddOn = 'Gaming'; Scope = 'Machine'; Risk = 'Medium'; Reversible = $true
            Impact = 'Turns on HAGS so the GPU manages its own scheduling. Needs a supported GPU/driver and a reboot to take effect.'
            Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
            ValueName = 'HwSchMode'; ValueType = 'DWord'; Data = 2
        }
        [pscustomobject]@{
            Id = 'Gaming.GamesTaskGpuPriority'; Name = 'Raise game GPU priority'; Category = 'Gaming'
            MinLevel = $null; AddOn = 'Gaming'; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets the multimedia scheduler GPU priority for games to 8 (high).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            ValueName = 'GPU Priority'; ValueType = 'DWord'; Data = 8
        }
        [pscustomobject]@{
            Id = 'Gaming.GamesTaskPriority'; Name = 'Raise game CPU priority'; Category = 'Gaming'
            MinLevel = $null; AddOn = 'Gaming'; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Sets the multimedia scheduler CPU priority for games to 6 (high).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            ValueName = 'Priority'; ValueType = 'DWord'; Data = 6
        }
        [pscustomobject]@{
            Id = 'Gaming.GamesTaskSchedulingCategory'; Name = 'Set game scheduling category to High'; Category = 'Gaming'
            MinLevel = $null; AddOn = 'Gaming'; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Raises the games task Scheduling Category to High so games get more CPU time under load.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            ValueName = 'Scheduling Category'; ValueType = 'String'; Data = 'High'
        }
        [pscustomobject]@{
            Id = 'Gaming.GamesTaskSfioPriority'; Name = 'Set game storage I/O priority to High'; Category = 'Gaming'
            MinLevel = $null; AddOn = 'Gaming'; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Raises the games task SFIO (storage I/O) priority to High.'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            ValueName = 'SFIO Priority'; ValueType = 'String'; Data = 'High'
        }
        [pscustomobject]@{
            Id = 'Gaming.DisableGameDVR'; Name = 'Disable Game DVR (user)'; Category = 'Gaming'
            MinLevel = $null; AddOn = 'Gaming'; Scope = 'User'; Risk = 'Low'; Reversible = $true
            Impact = 'Turns off background game recording (Game DVR) for the current user to cut capture overhead.'
            Type = 'Registry'; Path = 'HKCU:\System\GameConfigStore'
            ValueName = 'GameDVR_Enabled'; ValueType = 'DWord'; Data = 0
        }
        [pscustomobject]@{
            Id = 'Gaming.DisableGameDVRPolicy'; Name = 'Disable Game DVR (machine policy)'; Category = 'Gaming'
            MinLevel = $null; AddOn = 'Gaming'; Scope = 'Machine'; Risk = 'Low'; Reversible = $true
            Impact = 'Disables Game DVR / recording machine-wide via policy (AllowGameDVR=0).'
            Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
            ValueName = 'AllowGameDVR'; ValueType = 'DWord'; Data = 0
        }
    )
}

# =================================================================================================
# Defender safety guard (hard invariant - see script header / DESIGN section 5.1)
# =================================================================================================
function Test-IsDefenderTarget {
    <#
        Returns $true when a tweak would weaken Windows/Microsoft Defender, so the selection pipeline can
        drop it. No level or add-on may ever disable Defender. Registry: any Defender policy/product key
        is blocked outright. Service: a protected AV/Security service is blocked only when the desired
        start type would weaken it (Disabled/Manual) - normalising it toward Automatic is allowed.
    #>
    param ([Parameter(Mandatory = $true)]$Tweak)

    switch ($Tweak.Type) {
        'Registry' {
            $p = [string]$Tweak.Path
            $patterns = @(
                '\\Microsoft\\Windows Defender',
                '\\Microsoft\\Windows Defender Security Center',
                '\\Microsoft\\Microsoft Antimalware',
                '\\Microsoft\\Windows Defender Exploit Guard'
            )
            foreach ($pat in $patterns) { if ($p -match $pat) { return $true } }
            return $false
        }
        'Service' {
            $protected = @('WinDefend', 'WdNisSvc', 'WdNisDrv', 'WdFilter', 'Sense', 'MsSecFlt',
                'SecurityHealthService', 'wscsvc', 'webthreatdefsvc', 'webthreatdefusersvc')
            if (($protected -contains [string]$Tweak.ServiceName) -and
                (@('Disabled', 'Manual') -contains [string]$Tweak.StartupType)) {
                return $true
            }
            return $false
        }
        'ScheduledTask' {
            # Never disable a Defender scheduled task (defence in depth - the catalog has none).
            if ([string]$Tweak.TaskPath -match '\\Windows Defender') { return $true }
            return $false
        }
        default { return $false }
    }
}

# =================================================================================================
# Selection engine
# =================================================================================================
function Get-OptiHardware {
    <#
        One-shot (cached) read of the hardware facts the conditional/computed catalog rows need: installed
        RAM, whether the machine is a laptop or desktop, the OS-disk media type, and the OS build. All
        reads are best-effort with safe defaults, so a probe failure never blocks selection.
    #>
    if ($script:HardwareFacts) { return $script:HardwareFacts }
    $WhatIfPreference = $false

    $hw = [pscustomobject]@{
        RamBytes = [int64]0; RamGB = 0.0
        IsLaptop = $false; IsDesktop = $true; ChassisTypes = @()
        OSBuild = [int][Environment]::OSVersion.Version.Build
        SystemDiskMediaType = 'Unknown'; SystemDiskIsSSD = $false
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hw.RamBytes = [int64]$cs.TotalPhysicalMemory
    } catch { }
    if ($hw.RamBytes -le 0) {
        try { $hw.RamBytes = [int64]((Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue | Measure-Object -Property Capacity -Sum).Sum) } catch { }
    }
    if ($hw.RamBytes -gt 0) { $hw.RamGB = [math]::Round($hw.RamBytes / 1GB, 2) }

    # Laptop detection: a laptop chassis type, or the presence of a battery.
    $laptopChassis = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
    try {
        $types = @()
        foreach ($e in @(Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue)) {
            if ($e.ChassisTypes) { $types += @($e.ChassisTypes | ForEach-Object { [int]$_ }) }
        }
        $hw.ChassisTypes = $types
        if (@($types | Where-Object { $laptopChassis -contains $_ }).Count -gt 0) { $hw.IsLaptop = $true }
    } catch { }
    try { if (@(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0) { $hw.IsLaptop = $true } } catch { }
    $hw.IsDesktop = -not $hw.IsLaptop

    # OS-disk media type (SSD / NVMe / HDD).
    try {
        $sysLetter = $env:SystemDrive.TrimEnd(':', '\')
        $diskNum = (Get-Partition -DriveLetter $sysLetter -ErrorAction SilentlyContinue).DiskNumber
        if ($null -ne $diskNum) {
            $pd = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { [int]$_.DeviceId -eq [int]$diskNum } | Select-Object -First 1
            if ($pd) {
                $bus = [string]$pd.BusType; $media = [string]$pd.MediaType
                if ($bus -eq 'NVMe') { $hw.SystemDiskMediaType = 'NVMe'; $hw.SystemDiskIsSSD = $true }
                elseif ($media -eq 'SSD') { $hw.SystemDiskMediaType = 'SSD'; $hw.SystemDiskIsSSD = $true }
                elseif ($media -eq 'HDD') { $hw.SystemDiskMediaType = 'HDD' }
                elseif ($media) { $hw.SystemDiskMediaType = $media }
            }
        }
    } catch { }

    $script:HardwareFacts = $hw
    return $hw
}

function Select-Tweaks {
    <#
        Resolves the effective tweak set for the requested Level / Categories / add-ons. Levels are
        cumulative; add-on rows are included only when their add-on is requested or the Level is Full;
        Custom (guided mode, later commit) previews the whole catalog. Each candidate then passes:
          1. the Defender guard (a protected target is dropped with a warning),
          2. its optional hardware `Condition` (a scriptblock given the hardware facts; false => dropped),
          3. computed-`Data` resolution (a scriptblock `Data` is evaluated to a concrete value on a copy,
             so apply/preview/capture see a literal).
    #>
    param (
        [string]$Level,
        [string[]]$Categories,
        [switch]$IncludeAI,
        [switch]$IncludeGaming
    )

    $rank = @{ Minimal = 1; Balanced = 2; Full = 3 }
    $wantAI     = $IncludeAI.IsPresent     -or ($Level -in @('Full', 'Custom'))
    $wantGaming = $IncludeGaming.IsPresent -or ($Level -in @('Full', 'Custom'))
    $hw = Get-OptiHardware

    $selected = foreach ($t in (Get-TweakCatalog)) {
        # Level / add-on membership. A level row applies when MinLevel <= chosen level <= MaxLevel
        # (MaxLevel defaults to Full); MaxLevel lets a Balanced choice be superseded by a Full one that
        # targets the same setting (e.g. telemetry Required at Balanced vs Off at Full).
        if ($t.AddOn -eq 'AI')          { $include = $wantAI }
        elseif ($t.AddOn -eq 'Gaming')  { $include = $wantGaming }
        elseif ($Level -eq 'Custom')    { $include = $true }
        else {
            $maxL = if ($t.MaxLevel) { $t.MaxLevel } else { 'Full' }
            $include = ($rank[$t.MinLevel] -le $rank[$Level]) -and ($rank[$Level] -le $rank[$maxL])
        }
        if (-not $include) { continue }

        # Optional category filter.
        if ($Categories -and (-not ($Categories -contains $t.Category))) { continue }

        # Defender guard.
        if (Test-IsDefenderTarget -Tweak $t) {
            Write-OptiLog "Skipping '$($t.Id)': targets a protected Windows Defender key/service and is never applied." 'Warning'
            continue
        }

        # Hardware condition.
        if ($t.Condition) {
            $applies = $false
            try { $applies = [bool](& $t.Condition $hw) } catch { Write-OptiLog "Condition check failed for '$($t.Id)': $($_.Exception.Message) - skipped." 'Warning' }
            if (-not $applies) { continue }
        }

        # Computed value(s) -> resolve on a copy so downstream sees literals (Data for registry,
        # StartupType for a service e.g. SysMain by disk/RAM).
        if (($t.Data -is [scriptblock]) -or ($t.StartupType -is [scriptblock])) {
            $resolved = $t.PSObject.Copy()
            try {
                if ($t.Data -is [scriptblock]) { $resolved.Data = (& $t.Data $hw) }
                if ($t.StartupType -is [scriptblock]) { $resolved.StartupType = (& $t.StartupType $hw) }
            } catch { Write-OptiLog "Computed value failed for '$($t.Id)': $($_.Exception.Message) - skipped." 'Warning'; continue }
            $resolved
        } else {
            $t
        }
    }

    return @($selected)
}

# =================================================================================================
# Multi-user (-AllUsers) engine: profile enumeration, hive mount cache, per-profile fan-out
# =================================================================================================
# With -AllUsers, each User-scope (HKCU) registry tweak is expanded to one row per user profile - real
# profiles (loaded live, or loaded on demand from their NTUSER.DAT) plus the Default profile template so
# newly created users inherit it. Machine-scope tweaks apply once; Appx removal stays current-user in this
# build. Hives loaded on demand are cached here and unloaded together by Clear-OptiMounts.
$script:HiveMounts = @{}   # sid -> @{ Base; MountName; NeedsUnload }

function Get-OptiUserProfiles {
    # Real user profiles under ProfileList (SID S-1-5-21-*, NTUSER.DAT present) plus the Default template.
    $WhatIfPreference = $false
    $result = @()
    $plKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    try {
        foreach ($sub in @(Get-ChildItem -LiteralPath $plKey -ErrorAction SilentlyContinue)) {
            $sid = Split-Path $sub.Name -Leaf
            if ($sid -notmatch '^S-1-5-21-') { continue }   # interactive users only (skips system SIDs)
            if ($sid -match '\.bak$') { continue }
            $pip = (Get-ItemProperty -LiteralPath $sub.PSPath -Name 'ProfileImagePath' -ErrorAction SilentlyContinue).ProfileImagePath
            if (-not $pip) { continue }
            $dat = Join-Path $pip 'NTUSER.DAT'
            if (-not (Test-Path -LiteralPath $dat)) { continue }
            $loaded = $false
            try { $loaded = [bool](Test-Path -LiteralPath "Registry::HKEY_USERS\$sid") } catch { }
            $result += [pscustomobject]@{ Sid = $sid; ProfilePath = $pip; NtuserDat = $dat; IsLoaded = $loaded; IsDefault = $false }
        }
    } catch { Write-OptiLog "  (profile enumeration warning: $($_.Exception.Message))" 'Warning' }

    $defRoot = $null
    try { $defRoot = (Get-ItemProperty -LiteralPath $plKey -Name 'Default' -ErrorAction SilentlyContinue).Default } catch { }
    if (-not $defRoot) { $defRoot = Join-Path $env:SystemDrive 'Users\Default' }
    $defDat = Join-Path $defRoot 'NTUSER.DAT'
    if (Test-Path -LiteralPath $defDat) {
        $result += [pscustomobject]@{ Sid = 'Default'; ProfilePath = $defRoot; NtuserDat = $defDat; IsLoaded = $false; IsDefault = $true }
    }
    return @($result)
}

function Get-OptiHiveBase {
    # Registry provider base path for a profile's hive (e.g. 'Registry::HKEY_USERS\<sid>'), loading it from
    # NTUSER.DAT on demand when not already loaded. On-demand mounts are cached and released together by
    # Clear-OptiMounts. Returns $null on a load failure.
    param ([string]$Sid, [string]$NtuserDat)
    $WhatIfPreference = $false
    if ($Sid -ne 'Default' -and (Test-Path -LiteralPath "Registry::HKEY_USERS\$Sid")) {
        return "Registry::HKEY_USERS\$Sid"   # live hive (logged-in / current user): never file-load
    }
    if ($script:HiveMounts.ContainsKey($Sid)) { return $script:HiveMounts[$Sid].Base }
    if (-not (Test-Path -LiteralPath $NtuserDat)) { return $null }
    $mountName = 'OptiW11_{0}_{1}' -f $PID, ($Sid -replace '[^A-Za-z0-9]', '_')
    if ($mountName.Length -gt 240) { $mountName = $mountName.Substring(0, 240) }
    & reg.exe load "HKU\$mountName" "$NtuserDat" > $null 2>&1
    if ($LASTEXITCODE -ne 0) { return $null }
    $base = "Registry::HKEY_USERS\$mountName"
    $script:HiveMounts[$Sid] = @{ Base = $base; MountName = $mountName; NeedsUnload = $true }
    return $base
}

function Clear-OptiMounts {
    # Unloads every on-demand hive (GC first so the registry provider releases its handles before unload).
    $WhatIfPreference = $false
    if ($script:HiveMounts.Count -eq 0) { return }
    [gc]::Collect(); [gc]::WaitForPendingFinalizers(); [gc]::Collect()
    foreach ($k in @($script:HiveMounts.Keys)) {
        $m = $script:HiveMounts[$k]
        if (-not $m.NeedsUnload) { continue }
        for ($i = 0; $i -lt 5; $i++) {
            & reg.exe unload "HKU\$($m.MountName)" > $null 2>&1
            if ($LASTEXITCODE -eq 0) { break }
            [gc]::Collect(); [gc]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 200
        }
    }
    $script:HiveMounts = @{}
}

function ConvertTo-HiveSubPath {
    # Strips an HKCU: prefix, returning the path relative to the user-hive root (e.g. 'Software\...').
    param ([string]$Path)
    return ($Path -replace '^HKCU:\\', '')
}

function Expand-AllUsersRows {
    # Fans out User-scope registry rows across all profiles for -AllUsers (loading unloaded hives unless
    # this is a -WhatIf dry run). Machine-scope and Appx rows pass through unchanged.
    param ([object[]]$Rows, [switch]$DryRun)

    $profiles = @(Get-OptiUserProfiles)
    $names = ($profiles | ForEach-Object { if ($_.IsDefault) { 'Default(template)' } else { Split-Path $_.ProfilePath -Leaf } }) -join ', '
    Write-OptiLog ("-AllUsers: fanning out user-scope tweaks across {0} profile(s): {1}." -f $profiles.Count, $names) 'Info'

    $out = @()
    foreach ($t in $Rows) {
        $noAU = (($t.PSObject.Properties.Name -contains 'NoAllUsers') -and $t.NoAllUsers)
        if ($t.Scope -ne 'User' -or $t.Type -ne 'Registry' -or $noAU) {
            if ($noAU) { Write-OptiLog "  ($($t.Id) applies to the current user only - not fanned out to other profiles.)" 'Info' }
            $out += $t; continue
        }
        $sub = ConvertTo-HiveSubPath -Path $t.Path
        foreach ($p in $profiles) {
            if ($DryRun) {
                $base = if ($p.IsLoaded) { "Registry::HKEY_USERS\$($p.Sid)" } else { "Registry::HKEY_USERS\(NTUSER.DAT@$($p.ProfilePath))" }
            } else {
                $base = Get-OptiHiveBase -Sid $p.Sid -NtuserDat $p.NtuserDat
                if (-not $base) { Write-OptiLog "  (could not load hive for '$($p.ProfilePath)' - $($t.Id) skipped for it)" 'Warning'; continue }
            }
            $row = $t.PSObject.Copy()
            $label = if ($p.IsDefault) { 'Default(template)' } else { Split-Path $p.ProfilePath -Leaf }
            $row | Add-Member -NotePropertyName IsUserHive    -NotePropertyValue $true            -Force
            $row | Add-Member -NotePropertyName HiveSid       -NotePropertyValue $p.Sid           -Force
            $row | Add-Member -NotePropertyName HiveNtuserDat -NotePropertyValue $p.NtuserDat     -Force
            $row | Add-Member -NotePropertyName HiveSubPath   -NotePropertyValue $sub             -Force
            $row | Add-Member -NotePropertyName ProfileLabel  -NotePropertyValue $label           -Force
            $row.Path = ($base.TrimEnd('\') + '\' + $sub)
            $out += $row
        }
    }
    return @($out)
}

# =================================================================================================
# Current-state reads (read half of the capture engine)
# =================================================================================================
function Get-RegistryValueState {
    # Returns Exists / Data / Kind for a single registry value without altering anything. The catalog
    # uses '(default)' for a key's default value; the .NET APIs address it as the empty string.
    param ([string]$Path, [string]$ValueName)

    $vn = if ($ValueName -eq '(default)') { '' } else { $ValueName }
    $res = [pscustomobject]@{ Exists = $false; Data = $null; Kind = $null }
    try {
        if (Test-Path -LiteralPath $Path) {
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($key.GetValueNames() -contains $vn) {
                $res.Exists = $true
                $res.Data   = $key.GetValue($vn, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $res.Kind   = $key.GetValueKind($vn).ToString()
            }
        }
    } catch { }
    return $res
}

function Get-TweakCurrentState {
    # Human-readable current on-machine value for a tweak (read-only).
    param ($Tweak)
    switch ($Tweak.Type) {
        'Registry' {
            $s = Get-RegistryValueState -Path $Tweak.Path -ValueName $Tweak.ValueName
            if ($s.Exists) { return [string]$s.Data } else { return '<absent>' }
        }
        'Service' {
            $st = Get-ServiceStartupState -Name $Tweak.ServiceName
            if ($null -ne $st) { return $st } else { return '<absent>' }
        }
        'Powercfg' {
            $he = Get-HibernateEnabled
            if ($he -eq 1) { return 'hibernate-on' } elseif ($he -eq 0) { return 'hibernate-off' } else { return '<unknown>' }
        }
        'Appx' {
            $n = 0
            try { $n = @(Get-AppxPackage -Name $Tweak.PackageName -ErrorAction SilentlyContinue).Count } catch { }
            if ($n -gt 0) { return 'installed' } else { return '<absent>' }
        }
        'ScheduledTask' {
            $task = $null
            try { $task = Get-ScheduledTask -TaskPath $Tweak.TaskPath -TaskName $Tweak.TaskName -ErrorAction SilentlyContinue } catch { }
            if ($task) { return [string]$task.State } else { return '<absent>' }
        }
        default { return '<n/a>' }
    }
}

function Get-TweakDesiredText {
    # The concrete desired value a tweak sets (used for preview and the ShouldProcess message).
    param ($Tweak)
    switch ($Tweak.Type) {
        'Registry' { return [string]$Tweak.Data }
        'Service'  { return [string]$Tweak.StartupType }
        'Powercfg'      { return [string]$Tweak.PowercfgAction }
        'Appx'          { return 'removed' }
        'ScheduledTask' { return 'Disabled' }
        default         { return '' }
    }
}

function Get-TweakTargetText {
    # Short human description of what a tweak touches.
    param ($Tweak)
    switch ($Tweak.Type) {
        'Registry' {
            if (($Tweak.PSObject.Properties.Name -contains 'IsUserHive') -and $Tweak.IsUserHive) {
                return "[$($Tweak.ProfileLabel)] HKU:\$($Tweak.HiveSubPath)\$($Tweak.ValueName)"
            }
            return "$($Tweak.Path)\$($Tweak.ValueName)"
        }
        'Service'       { return "Service:$($Tweak.ServiceName)" }
        'Powercfg'      { return "Powercfg:$($Tweak.PowercfgAction)" }
        'Appx'          { return "Appx:$($Tweak.PackageName)" }
        'ScheduledTask' { return "Task:$($Tweak.TaskPath)$($Tweak.TaskName)" }
        default         { return $Tweak.Id }
    }
}

# =================================================================================================
# Capture engine + snapshot / undo-script generation
# Captures the prior state of every selected tweak (registry / service / power / Appx / scheduled-task) and writes the
# per-segment undo scripts, .reg backups and stack-index entry that make a run reversible.
# =================================================================================================
function Get-ServiceStartupState {
    # Returns a service's start type as one of Automatic / AutomaticDelayedStart / Manual / Disabled /
    # (Boot|System), or $null when the service is absent. ServiceController.StartType cannot tell
    # delayed-auto from plain auto, so the DelayedAutostart registry flag is consulted.
    param ([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return $null }
    $st = [string]$svc.StartType
    if ($st -eq 'Automatic') {
        $da = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name 'DelayedAutostart' -ErrorAction SilentlyContinue).DelayedAutostart
        if ($da -eq 1) { return 'AutomaticDelayedStart' }
    }
    return $st
}

function Set-ServiceStartupState {
    # Sets a service's start type, including delayed-auto (which Set-Service alone cannot do in 5.1).
    param ([string]$Name, [string]$Type)
    if ($Type -eq 'AutomaticDelayedStart') {
        Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
        New-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name 'DelayedAutostart' -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
    } else {
        Set-Service -Name $Name -StartupType $Type -ErrorAction Stop
        if ($Type -eq 'Automatic') {
            New-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name 'DelayedAutostart' -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

function Get-HibernateEnabled {
    # 1 if hibernation is enabled, 0 if disabled, $null if unknown.
    $he = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled' -ErrorAction SilentlyContinue).HibernateEnabled
    if ($null -ne $he) { return [int]$he } else { return $null }
}

function Get-TweakCaptureRecord {
    # Records the live prior state of a tweak so an undo can restore it exactly. Read-only.
    param ($Tweak)
    switch ($Tweak.Type) {
        'Registry' {
            $state = Get-RegistryValueState -Path $Tweak.Path -ValueName $Tweak.ValueName
            $rec = [pscustomobject]@{
                Id = $Tweak.Id; Category = $Tweak.Category; Type = 'Registry'; Scope = $Tweak.Scope
                AddOn = $Tweak.AddOn
                Path = $Tweak.Path; ValueName = $Tweak.ValueName
                DesiredType = $Tweak.ValueType; DesiredData = $Tweak.Data
                PriorExists = $state.Exists; PriorData = $state.Data; PriorKind = $state.Kind
                KeyExisted = (Test-Path -LiteralPath $Tweak.Path)
                IsUserHive = $false
            }
            if (($Tweak.PSObject.Properties.Name -contains 'IsUserHive') -and $Tweak.IsUserHive) {
                # Per-profile row: store SID + NTUSER.DAT + sub-path so rollback re-targets the right hive
                # (the concrete Path above points at a transient mount that will not exist next run).
                $rec.IsUserHive = $true
                $rec | Add-Member -NotePropertyName HiveSid       -NotePropertyValue $Tweak.HiveSid       -Force
                $rec | Add-Member -NotePropertyName HiveNtuserDat -NotePropertyValue $Tweak.HiveNtuserDat -Force
                $rec | Add-Member -NotePropertyName HiveSubPath   -NotePropertyValue $Tweak.HiveSubPath   -Force
                $rec | Add-Member -NotePropertyName ProfileLabel  -NotePropertyValue $Tweak.ProfileLabel  -Force
            }
            return $rec
        }
        'Service' {
            $svc = Get-Service -Name $Tweak.ServiceName -ErrorAction SilentlyContinue
            return [pscustomobject]@{
                Id = $Tweak.Id; Category = $Tweak.Category; Type = 'Service'; Scope = $Tweak.Scope
                AddOn = $Tweak.AddOn
                ServiceName = $Tweak.ServiceName; DesiredStartupType = $Tweak.StartupType
                ServiceExists = [bool]$svc
                PriorStartupType = $(if ($svc) { Get-ServiceStartupState -Name $Tweak.ServiceName } else { $null })
                PriorStatus = $(if ($svc) { [string]$svc.Status } else { $null })
            }
        }
        'Powercfg' {
            return [pscustomobject]@{
                Id = $Tweak.Id; Category = $Tweak.Category; Type = 'Powercfg'; Scope = $Tweak.Scope
                AddOn = $Tweak.AddOn
                PowercfgAction = $Tweak.PowercfgAction
                PriorHibernateEnabled = (Get-HibernateEnabled)
            }
        }
        'Appx' {
            # Record every current-user package matching the name (usually one), keeping each staged
            # InstallLocation so undo can best-effort re-register the app after removal.
            $pkgs = @()
            try { $pkgs = @(Get-AppxPackage -Name $Tweak.PackageName -ErrorAction SilentlyContinue) } catch { }
            $installed = @($pkgs | ForEach-Object {
                [pscustomobject]@{ PackageFullName = [string]$_.PackageFullName; Name = [string]$_.Name; InstallLocation = [string]$_.InstallLocation }
            })
            return [pscustomobject]@{
                Id = $Tweak.Id; Category = $Tweak.Category; Type = 'Appx'; Scope = $Tweak.Scope
                AddOn = $Tweak.AddOn
                PackageName = $Tweak.PackageName
                PriorInstalled = ($installed.Count -gt 0)
                Packages = $installed
            }
        }
        'ScheduledTask' {
            $task = $null
            try { $task = Get-ScheduledTask -TaskPath $Tweak.TaskPath -TaskName $Tweak.TaskName -ErrorAction SilentlyContinue } catch { }
            return [pscustomobject]@{
                Id = $Tweak.Id; Category = $Tweak.Category; Type = 'ScheduledTask'; Scope = $Tweak.Scope
                AddOn = $Tweak.AddOn
                TaskPath = $Tweak.TaskPath; TaskName = $Tweak.TaskName
                TaskExists = [bool]$task
                PriorState = $(if ($task) { [string]$task.State } else { $null })
            }
        }
        default { throw "Capture for tweak type '$($Tweak.Type)' is not implemented in this build." }
    }
}

function ConvertTo-RegLiteral {
    # Renders a registry value as a PowerShell literal for the generated undo script.
    param ($Kind, $Data)
    switch ($Kind) {
        'DWord'       { return [string]([int64]$Data) }
        'QWord'       { return [string]([int64]$Data) }
        'Binary'      { if ($null -eq $Data) { return '@()' }; return '@(' + ((@($Data) | ForEach-Object { [int]$_ }) -join ',') + ')' }
        'MultiString' { return '@(' + ((@($Data) | ForEach-Object { "'" + ([string]$_ -replace "'", "''") + "'" }) -join ',') + ')' }
        default       { return "'" + ([string]$Data -replace "'", "''") + "'" }   # String / ExpandString
    }
}

function Get-RegistryRestoreLines {
    # Core restore lines for one registry value, given a PowerShell path EXPRESSION ($PathExpr - a quoted
    # literal like 'HKCU:\...' or a variable like $__p) and a quoted value-name literal. Shared by the
    # literal-path and per-profile (user-hive) undo emitters.
    param ($PathExpr, $NameLit, $Record)
    $lines = New-Object System.Collections.Generic.List[string]
    if ($Record.PriorExists) {
        $valLit = ConvertTo-RegLiteral -Kind $Record.PriorKind -Data $Record.PriorData
        $lines.Add("if (-not (Test-Path -LiteralPath $PathExpr)) { New-Item -Path $PathExpr -Force | Out-Null }")
        $lines.Add("New-ItemProperty -LiteralPath $PathExpr -Name $NameLit -PropertyType $($Record.PriorKind) -Value $valLit -Force | Out-Null")
    } else {
        $lines.Add("Remove-ItemProperty -LiteralPath $PathExpr -Name $NameLit -Force -ErrorAction SilentlyContinue")
        if (-not $Record.KeyExisted) {
            $lines.Add("if (Test-Path -LiteralPath $PathExpr) { `$k = Get-Item -LiteralPath $PathExpr; if (`$k.ValueCount -eq 0 -and `$k.SubKeyCount -eq 0) { Remove-Item -LiteralPath $PathExpr -Force -ErrorAction SilentlyContinue } }")
        }
    }
    return $lines
}

function New-RegistryUndoLine {
    # PowerShell lines that restore one registry value to its captured prior state. For a per-profile
    # (user-hive) record the value is restored inside that profile's hive, loading it from NTUSER.DAT on
    # demand (via the Mount/Dismount helpers that New-UndoScriptFile embeds) and unloading it afterward.
    param ($Record)
    $lines = New-Object System.Collections.Generic.List[string]
    if ($Record.Type -ne 'Registry') {
        $lines.Add("# (skip: undo for type '$($Record.Type)' is not implemented in this build)")
        return $lines
    }
    $nameLit = "'" + ([string]$Record.ValueName -replace "'", "''") + "'"

    if (($Record.PSObject.Properties.Name -contains 'IsUserHive') -and $Record.IsUserHive) {
        $sidLit = "'" + ([string]$Record.HiveSid -replace "'", "''") + "'"
        $datLit = "'" + ([string]$Record.HiveNtuserDat -replace "'", "''") + "'"
        $subLit = "'" + ([string]$Record.HiveSubPath -replace "'", "''") + "'"
        $lines.Add("`$__m = Mount-OptiUndoHive -Sid $sidLit -NtuserDat $datLit")
        $lines.Add("if (`$__m) {")
        $lines.Add("    `$__p = `$__m.Base + '\' + $subLit")
        foreach ($l in (Get-RegistryRestoreLines -PathExpr '$__p' -NameLit $nameLit -Record $Record)) { $lines.Add("    $l") }
        $lines.Add("    Dismount-OptiUndoHive -Mount `$__m")
        $lines.Add("} else { Write-Warning '  hive unavailable for profile [$($Record.ProfileLabel)] - skipped' }")
        return $lines
    }

    $pathLit = "'" + ([string]$Record.Path -replace "'", "''") + "'"
    foreach ($l in (Get-RegistryRestoreLines -PathExpr $pathLit -NameLit $nameLit -Record $Record)) { $lines.Add($l) }
    return $lines
}

function New-ServiceUndoLine {
    # PowerShell line(s) that restore one service's start type to its captured prior value (delayed-auto aware).
    param ($Record)
    $lines = New-Object System.Collections.Generic.List[string]
    $name = [string]$Record.ServiceName
    $svcLit = "'" + ($name -replace "'", "''") + "'"
    $regLit = "'HKLM:\SYSTEM\CurrentControlSet\Services\" + ($name -replace "'", "''") + "'"
    $sp = [string]$Record.PriorStartupType
    if ($Record.ServiceExists -and (@('Automatic', 'AutomaticDelayedStart', 'Manual', 'Disabled') -contains $sp)) {
        if ($sp -eq 'AutomaticDelayedStart') {
            $lines.Add("if (Get-Service -Name $svcLit -ErrorAction SilentlyContinue) { Set-Service -Name $svcLit -StartupType Automatic -ErrorAction SilentlyContinue; New-ItemProperty -LiteralPath $regLit -Name DelayedAutostart -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null }")
        } elseif ($sp -eq 'Automatic') {
            $lines.Add("if (Get-Service -Name $svcLit -ErrorAction SilentlyContinue) { Set-Service -Name $svcLit -StartupType Automatic -ErrorAction SilentlyContinue; New-ItemProperty -LiteralPath $regLit -Name DelayedAutostart -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null }")
        } else {
            $lines.Add("if (Get-Service -Name $svcLit -ErrorAction SilentlyContinue) { Set-Service -Name $svcLit -StartupType $sp -ErrorAction SilentlyContinue }")
        }
    } else {
        $lines.Add("# service $svcLit was not present (or had an unsupported start type) at capture - nothing to undo")
    }
    return $lines
}

function New-PowercfgUndoLine {
    # PowerShell line that restores hibernation to its captured prior state.
    param ($Record)
    $lines = New-Object System.Collections.Generic.List[string]
    if ($Record.PriorHibernateEnabled -eq 0) { $lines.Add("& powercfg.exe /hibernate off 2>&1 | Out-Null") }
    else { $lines.Add("& powercfg.exe /hibernate on 2>&1 | Out-Null") }
    return $lines
}

function New-AppxUndoLine {
    # PowerShell line(s) that best-effort re-register a removed Appx package from its captured staged
    # files. If the files are gone (fully uninstalled) the app must be reinstalled from the Store - the
    # generated undo says so rather than failing.
    param ($Record)
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $Record.PriorInstalled) {
        $lines.Add("# Appx '$($Record.PackageName)' was not installed for this user at capture - nothing to undo.")
        return $lines
    }
    foreach ($p in @($Record.Packages)) {
        $loc = [string]$p.InstallLocation
        if ([string]::IsNullOrEmpty($loc)) {
            $lines.Add("# $($p.Name): no staged install location was captured - reinstall it from the Microsoft Store.")
            continue
        }
        $locLit = "'" + ($loc -replace "'", "''") + "'"
        $lines.Add("if (Test-Path -LiteralPath (Join-Path $locLit 'AppxManifest.xml')) {")
        $lines.Add("    try { Add-AppxPackage -Register (Join-Path $locLit 'AppxManifest.xml') -DisableDevelopmentMode -ErrorAction Stop; Write-Host '  re-registered $($p.Name)' }")
        $lines.Add("    catch { Write-Warning '  could not re-register $($p.Name) - reinstall it from the Microsoft Store.' }")
        $lines.Add("} else { Write-Warning '  staged files for $($p.Name) are gone - reinstall it from the Microsoft Store.' }")
    }
    return $lines
}

function New-ScheduledTaskUndoLine {
    # PowerShell line(s) that re-enable one scheduled task - but only if it was enabled at capture, so an
    # undo never turns on a task the user already had off.
    param ($Record)
    $lines = New-Object System.Collections.Generic.List[string]
    $pathLit = "'" + ([string]$Record.TaskPath -replace "'", "''") + "'"
    $nameLit = "'" + ([string]$Record.TaskName -replace "'", "''") + "'"
    if ($Record.TaskExists -and (@('Ready', 'Running', 'Queued') -contains [string]$Record.PriorState)) {
        $lines.Add("if (Get-ScheduledTask -TaskPath $pathLit -TaskName $nameLit -ErrorAction SilentlyContinue) { Enable-ScheduledTask -TaskPath $pathLit -TaskName $nameLit -ErrorAction SilentlyContinue | Out-Null }")
    } else {
        $lines.Add("# scheduled task $pathLit$nameLit was disabled or absent at capture - nothing to undo")
    }
    return $lines
}

function New-UndoLine {
    # Dispatches undo-line generation by record type.
    param ($Record)
    switch ($Record.Type) {
        'Registry'      { return (New-RegistryUndoLine -Record $Record) }
        'Service'       { return (New-ServiceUndoLine -Record $Record) }
        'Powercfg'      { return (New-PowercfgUndoLine -Record $Record) }
        'Appx'          { return (New-AppxUndoLine -Record $Record) }
        'ScheduledTask' { return (New-ScheduledTaskUndoLine -Record $Record) }
        default         { $l = New-Object System.Collections.Generic.List[string]; $l.Add("# (undo for type '$($Record.Type)' not implemented)"); return $l }
    }
}

function Restore-TweakRecord {
    # In-process twin of New-RegistryUndoLine: restores one captured record to its prior state. Used by
    # the built-in -Rollback runner (the generated .ps1 is for standalone use).
    param ($Record)
    $ConfirmPreference = 'None'; $WhatIfPreference = $false
    switch ($Record.Type) {
        'Registry' {
            $path = [string]$Record.Path
            if (($Record.PSObject.Properties.Name -contains 'IsUserHive') -and $Record.IsUserHive) {
                # Re-target the profile's hive (loading it on demand); the stored Path is a stale mount.
                $base = Get-OptiHiveBase -Sid $Record.HiveSid -NtuserDat $Record.HiveNtuserDat
                if (-not $base) { Write-OptiLog "    (hive for [$($Record.ProfileLabel)] unavailable - $($Record.Id) not restored)" 'Warning'; return }
                $path = ($base.TrimEnd('\') + '\' + $Record.HiveSubPath)
            }
            $name = [string]$Record.ValueName
            if ($Record.PriorExists) {
                if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
                New-ItemProperty -LiteralPath $path -Name $name -PropertyType $Record.PriorKind -Value $Record.PriorData -Force | Out-Null
            } else {
                Remove-ItemProperty -LiteralPath $path -Name $name -Force -ErrorAction SilentlyContinue
                if ((-not $Record.KeyExisted) -and (Test-Path -LiteralPath $path)) {
                    $k = Get-Item -LiteralPath $path
                    if ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
                }
            }
        }
        'Service' {
            if ($Record.ServiceExists -and (@('Automatic', 'AutomaticDelayedStart', 'Manual', 'Disabled') -contains [string]$Record.PriorStartupType)) {
                if (Get-Service -Name $Record.ServiceName -ErrorAction SilentlyContinue) {
                    try { Set-ServiceStartupState -Name $Record.ServiceName -Type $Record.PriorStartupType } catch { }
                }
            }
        }
        'Powercfg' {
            # Default to re-enabling hibernation unless it was explicitly off at capture (absent value =
            # hibernation in its default/available state, so 'on' is the safe restore).
            if ($Record.PriorHibernateEnabled -eq 0) { & powercfg.exe /hibernate off 2>&1 | Out-Null }
            else { & powercfg.exe /hibernate on 2>&1 | Out-Null }
        }
        'Appx' {
            # Best-effort re-registration from staged files; if they are gone the app must be reinstalled
            # from the Store (a hard failure here must not abort the wider rollback).
            if (-not $Record.PriorInstalled) { return }
            foreach ($p in @($Record.Packages)) {
                $loc = [string]$p.InstallLocation
                $m = if ($loc) { Join-Path $loc 'AppxManifest.xml' } else { $null }
                if ($m -and (Test-Path -LiteralPath $m)) {
                    try { Add-AppxPackage -Register $m -DisableDevelopmentMode -ErrorAction Stop }
                    catch { Write-OptiLog "    could not re-register $($p.Name): $($_.Exception.Message) - reinstall it from the Store." 'Warning' }
                } else {
                    Write-OptiLog "    staged files for $($p.Name) are gone - reinstall it from the Microsoft Store." 'Warning'
                }
            }
        }
        'ScheduledTask' {
            # Re-enable only if the task was enabled at capture (never turn on one the user had off).
            if ($Record.TaskExists -and (@('Ready', 'Running', 'Queued') -contains [string]$Record.PriorState)) {
                if (Get-ScheduledTask -TaskPath $Record.TaskPath -TaskName $Record.TaskName -ErrorAction SilentlyContinue) {
                    try { Enable-ScheduledTask -TaskPath $Record.TaskPath -TaskName $Record.TaskName -ErrorAction Stop | Out-Null } catch { }
                }
            }
        }
        default { throw "Undo for type '$($Record.Type)' is not implemented in this build." }
    }
}

function New-UndoScriptFile {
    # Writes a self-contained, idempotent undo .ps1 for one snapshot segment.
    param ($SnapshotFolder, $Stamp, $Segment, $Level, [object[]]$Records)
    $file = Join-Path $SnapshotFolder ("Undo-{0}_{1}.ps1" -f $Segment, $Stamp)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("#Requires -Version 5.1")
    [void]$sb.AppendLine("<#")
    [void]$sb.AppendLine("  Auto-generated rollback for Optimize-Windows11 snapshot $Stamp (segment: $Segment; level: $Level).")
    [void]$sb.AppendLine("  Restores the prior state captured before the run. Self-contained and idempotent - safe to re-run.")
    [void]$sb.AppendLine("  Run in an ELEVATED Windows PowerShell (HKLM changes require administrator).")
    [void]$sb.AppendLine("#>")
    [void]$sb.AppendLine("`$ErrorActionPreference = 'Continue'")

    # When any record targets a per-profile hive, embed the mount/unmount helpers it needs.
    $hasUserHive = @($Records | Where-Object { ($_.PSObject.Properties.Name -contains 'IsUserHive') -and $_.IsUserHive }).Count -gt 0
    if ($hasUserHive) {
        $helper = @'

function Mount-OptiUndoHive {
    param($Sid, $NtuserDat)
    if ($Sid -ne 'Default' -and (Test-Path -LiteralPath "Registry::HKEY_USERS\$Sid")) {
        return @{ Base = "Registry::HKEY_USERS\$Sid"; Name = $null }
    }
    if (-not (Test-Path -LiteralPath $NtuserDat)) { return $null }
    $n = 'OptiUndo_' + ($Sid -replace '[^A-Za-z0-9]', '_')
    & reg.exe load "HKU\$n" "$NtuserDat" > $null 2>&1
    if ($LASTEXITCODE -ne 0) { return $null }
    return @{ Base = "Registry::HKEY_USERS\$n"; Name = $n }
}
function Dismount-OptiUndoHive {
    param($Mount)
    if ($Mount -and $Mount.Name) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        & reg.exe unload "HKU\$($Mount.Name)" > $null 2>&1
    }
}
'@
        [void]$sb.AppendLine($helper)
    }

    [void]$sb.AppendLine("Write-Host 'Undoing Optimize-Windows11 snapshot $Stamp ($Segment segment)...'")
    foreach ($r in $Records) {
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("# $($r.Id)  [$($r.Type)]  ->  $(Get-TweakTargetText -Tweak $r)")
        foreach ($line in (New-UndoLine -Record $r)) { [void]$sb.AppendLine($line) }
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Write-Host 'Undo complete for snapshot $Stamp ($Segment segment).'")
    Set-Content -LiteralPath $file -Value $sb.ToString() -Encoding UTF8
    return $file
}

function ConvertTo-RegExePath {
    # HKCU:\... -> HKEY_CURRENT_USER\... for reg.exe export.
    param ($PsPath)
    $map = [ordered]@{
        'HKLM:' = 'HKEY_LOCAL_MACHINE'; 'HKCU:' = 'HKEY_CURRENT_USER'; 'HKU:' = 'HKEY_USERS'
        'HKCR:' = 'HKEY_CLASSES_ROOT'; 'HKCC:' = 'HKEY_CURRENT_CONFIG'
    }
    foreach ($k in $map.Keys) { if ($PsPath.StartsWith($k, [System.StringComparison]::OrdinalIgnoreCase)) { return ($map[$k] + $PsPath.Substring($k.Length)) } }
    return $null
}

function Export-RegistrySubtree {
    # Belt-and-suspenders: exports one existing registry key to a .reg file. Absent keys are skipped.
    param ($PsPath, $DestFolder)
    if (-not (Test-Path -LiteralPath $PsPath)) { return $null }
    $regPath = ConvertTo-RegExePath -PsPath $PsPath
    if (-not $regPath) { return $null }
    $safe = ($regPath -replace '[\\:/*?"<>|]', '_')
    if ($safe.Length -gt 120) { $safe = $safe.Substring(0, 120) }
    $file = Join-Path $DestFolder ($safe + '.reg')
    & reg.exe export "$regPath" "$file" /y > $null 2>&1
    if ($LASTEXITCODE -eq 0) { return $file } else { return $null }
}

function Get-StackIndex {
    if (Test-Path -LiteralPath $script:StackIndexPath) {
        try { return (Get-Content -Raw -LiteralPath $script:StackIndexPath | ConvertFrom-Json) } catch { }
    }
    return [pscustomobject]@{ SchemaVersion = 1; Layers = @() }
}

function Save-StackIndex {
    param ($State)
    $State | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:StackIndexPath -Encoding UTF8
}

function New-OptiRestorePoint {
    <#
        Creates a VSS System Restore point as the coarse, full-system safety net (complementing the
        surgical undo script). Returns the new restore point's sequence number, or $null when it was
        skipped or could not be created - in which case the undo .ps1 + .reg backups remain the
        deterministic rollback, so failure here is warned, never fatal. Uses Windows PowerShell 5.1's
        *-ComputerRestore cmdlets (absent from PowerShell 7).
    #>
    param ([string]$Description)
    $WhatIfPreference = $false; $ConfirmPreference = 'None'

    if ($SkipRestorePoint) { Write-OptiLog "VSS restore point skipped (-SkipRestorePoint)." 'Info'; return $null }

    $os = Get-OptiOSInfo
    if (-not $os.IsClient) { Write-OptiLog "VSS restore point skipped: System Restore is unavailable on Server SKUs." 'Warning'; return $null }

    $sysDrive = ($env:SystemDrive.TrimEnd('\')) + '\'
    $freqKey  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $priorFreq = $null; $freqExisted = $false
    $seq = $null
    try {
        Enable-ComputerRestore -Drive $sysDrive -ErrorAction Stop

        # Defeat the once-per-24h throttle for this checkpoint (remember the prior value to restore it).
        if (-not (Test-Path -LiteralPath $freqKey)) { New-Item -Path $freqKey -Force | Out-Null }
        $fp = Get-ItemProperty -LiteralPath $freqKey -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue
        if ($fp -and ($fp.PSObject.Properties.Name -contains 'SystemRestorePointCreationFrequency')) { $priorFreq = $fp.SystemRestorePointCreationFrequency; $freqExisted = $true }
        New-ItemProperty -LiteralPath $freqKey -Name 'SystemRestorePointCreationFrequency' -PropertyType DWord -Value 0 -Force | Out-Null

        $before = (@(Get-ComputerRestorePoint -ErrorAction SilentlyContinue) | Measure-Object -Property SequenceNumber -Maximum).Maximum
        if ($null -eq $before) { $before = 0 }

        Write-OptiLog "Creating VSS restore point ('$Description') - this can take a moment..." 'Info'
        Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop

        $after = (@(Get-ComputerRestorePoint -ErrorAction SilentlyContinue) | Measure-Object -Property SequenceNumber -Maximum).Maximum
        if ($null -eq $after) { $after = 0 }

        if ($after -gt $before) { $seq = [int]$after; Write-OptiLog "VSS restore point created (sequence #$seq)." 'Success' }
        else { Write-OptiLog "Checkpoint-Computer returned without a new restore point (System Restore may be disabled by policy, or storage is low). Continuing." 'Warning' }
    } catch {
        Write-OptiLog "VSS restore point could not be created: $($_.Exception.Message). Continuing - the undo script and .reg backups remain your rollback." 'Warning'
    } finally {
        try {
            if ($freqExisted) { New-ItemProperty -LiteralPath $freqKey -Name 'SystemRestorePointCreationFrequency' -PropertyType DWord -Value $priorFreq -Force | Out-Null }
            else { Remove-ItemProperty -LiteralPath $freqKey -Name 'SystemRestorePointCreationFrequency' -Force -ErrorAction SilentlyContinue }
        } catch { }
    }
    return $seq
}

function New-OptiSnapshot {
    <#
        Captures the prior state of every selected tweak and writes a stack layer under ProgramData:
        a snapshot folder with per-segment undo .ps1 scripts, .reg backups of the touched keys, a
        snapshot.json manifest, and an entry in stack-index.json. Does NOT modify the system.
    #>
    param ([object[]]$Tweaks, [string]$Level, $RestorePointSeq = $null)

    # One folder per run (never overwritten).
    $stamp = $script:StartStamp
    $folder = Join-Path $script:SnapshotsRoot $stamp
    $n = 1
    while (Test-Path -LiteralPath $folder) { $n++; $stamp = "$($script:StartStamp)_$n"; $folder = Join-Path $script:SnapshotsRoot $stamp }
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
    $regFolder = Join-Path $folder 'registry-backup'
    New-Item -Path $regFolder -ItemType Directory -Force | Out-Null

    # Capture prior state.
    $records = @(foreach ($t in $Tweaks) { Get-TweakCaptureRecord -Tweak $t })

    # .reg export of each distinct existing registry key.
    foreach ($k in (@($records | Where-Object { $_.Type -eq 'Registry' } | Select-Object -ExpandProperty Path -Unique))) {
        Export-RegistrySubtree -PsPath $k -DestFolder $regFolder | Out-Null
    }

    # Group into undo segments: Level / AI / Gaming (independent stacks).
    $segments = @{}
    foreach ($r in $records) {
        $seg = if ($r.AddOn) { $r.AddOn } else { 'Level' }
        if (-not $segments.ContainsKey($seg)) { $segments[$seg] = New-Object System.Collections.Generic.List[object] }
        $segments[$seg].Add($r)
    }

    # Compute this run's index once (shared across its segment layers).
    $idxState = Get-StackIndex
    $index = 0
    foreach ($l in @($idxState.Layers)) { if ($l.Index -gt $index) { $index = $l.Index } }
    $index++

    $segmentInfo = @{}
    foreach ($seg in $segments.Keys) {
        $segRecords = $segments[$seg].ToArray()
        $undoName = $null
        if (-not $NoRollbackScript) {
            $undoName = Split-Path (New-UndoScriptFile -SnapshotFolder $folder -Stamp $stamp -Segment $seg -Level $Level -Records $segRecords) -Leaf
        }
        $segmentInfo[$seg] = [pscustomobject]@{ UndoScript = $undoName; TweakCount = $segRecords.Count; Records = $segRecords }
    }

    # Manifest.
    $manifest = [pscustomobject]@{
        SchemaVersion   = 1
        Index           = $index
        Stamp           = $stamp
        Computer        = $env:COMPUTERNAME
        ScriptVersion   = $script:ScriptVersion
        Level           = $Level
        AddOns          = @($segments.Keys | Where-Object { $_ -ne 'Level' })
        Status          = 'Active'
        RestorePointSeq = $RestorePointSeq
        Created         = (Get-Date).ToString('o')
        Segments        = $segmentInfo
    }
    $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $folder 'snapshot.json') -Encoding UTF8

    # Stack index: one layer entry per segment produced this run.
    $layers = @($idxState.Layers)
    foreach ($seg in $segmentInfo.Keys) {
        $info = $segmentInfo[$seg]
        $layers += [pscustomobject]@{
            Index = $index; Stamp = $stamp; Folder = $stamp; Segment = $seg; Level = $Level
            Status = 'Active'; UndoScript = $info.UndoScript; TweakCount = $info.TweakCount
        }
    }
    $idxState.Layers = $layers
    Save-StackIndex -State $idxState

    return [pscustomobject]@{ Folder = $folder; Stamp = $stamp; Index = $index; Segments = $segmentInfo }
}

# =================================================================================================
# Modes
# =================================================================================================
function Invoke-TweakApply {
    # Applies one tweak to the system. Returns $true on success; throws on failure.
    param ($Tweak)
    $ConfirmPreference = 'None'   # the caller already gated this via ShouldProcess
    $WhatIfPreference = $false
    switch ($Tweak.Type) {
        'Registry' {
            if (-not (Test-Path -LiteralPath $Tweak.Path)) { New-Item -Path $Tweak.Path -Force | Out-Null }
            New-ItemProperty -LiteralPath $Tweak.Path -Name $Tweak.ValueName -PropertyType $Tweak.ValueType -Value $Tweak.Data -Force | Out-Null
            return $true
        }
        'Service' {
            $cur = Get-ServiceStartupState -Name $Tweak.ServiceName
            if ($null -eq $cur) {
                Write-OptiLog "  (service '$($Tweak.ServiceName)' not present - skipped)" 'Info'
                return $true
            }
            if ($cur -eq $Tweak.StartupType) { return $true }   # normalization is idempotent: only change where it differs
            Set-ServiceStartupState -Name $Tweak.ServiceName -Type $Tweak.StartupType
            return $true
        }
        'Powercfg' {
            switch ($Tweak.PowercfgAction) {
                'hibernate-off' { & powercfg.exe /hibernate off 2>&1 | Out-Null; return $true }
                'hibernate-on'  { & powercfg.exe /hibernate on  2>&1 | Out-Null; return $true }
                default         { throw "Unknown Powercfg action '$($Tweak.PowercfgAction)'." }
            }
        }
        'Appx' {
            # Remove the matching package(s) for the CURRENT USER only (no -AllUsers / deprovision in v1),
            # which leaves the staged files in place so undo can re-register the app. Idempotent: absent
            # package = nothing to do.
            $pkgs = @(Get-AppxPackage -Name $Tweak.PackageName -ErrorAction SilentlyContinue)
            if ($pkgs.Count -eq 0) { Write-OptiLog "  (Appx '$($Tweak.PackageName)' not installed for this user - skipped)" 'Info'; return $true }
            foreach ($p in $pkgs) { Remove-AppxPackage -Package $p.PackageFullName -ErrorAction Stop }
            return $true
        }
        'ScheduledTask' {
            # Disable the task (never delete). Idempotent: absent task = nothing to do; already-disabled = done.
            $task = Get-ScheduledTask -TaskPath $Tweak.TaskPath -TaskName $Tweak.TaskName -ErrorAction SilentlyContinue
            if (-not $task) { Write-OptiLog "  (scheduled task '$($Tweak.TaskPath)$($Tweak.TaskName)' not present - skipped)" 'Info'; return $true }
            if ([string]$task.State -eq 'Disabled') { return $true }
            Disable-ScheduledTask -TaskPath $Tweak.TaskPath -TaskName $Tweak.TaskName -ErrorAction Stop | Out-Null
            return $true
        }
        default { throw "Apply for tweak type '$($Tweak.Type)' is not implemented in this build." }
    }
}

function Read-OptiChoice {
    # Prompts for a single-letter choice from $Choices (case-insensitive), returning the upper-cased key.
    # Empty input (or no console) yields $Default, so a redirected/exhausted stdin degrades to the default.
    param ([string]$Prompt, [string[]]$Choices, [string]$Default)
    $set = @($Choices | ForEach-Object { $_.ToUpper() })
    for ($i = 0; $i -lt 20; $i++) {
        $ans = ''
        try { $ans = Read-Host $Prompt } catch { return $Default }
        if ([string]::IsNullOrWhiteSpace($ans)) { return $Default }
        $a = $ans.Trim().Substring(0, 1).ToUpper()
        if ($set -contains $a) { return $a }
        Write-Host "    (please answer one of: $($set -join ', '))" -ForegroundColor DarkYellow
    }
    return $Default
}

function Invoke-CustomWalkthrough {
    <#
        Guided Custom mode: walks each category, shows every tweak's impact/risk, and asks how far to go
        (Skip / Minimal / Balanced / Full); then offers the AI and Gaming add-ons; then summarises and asks
        for a final confirmation. Builds the selection by reusing Select-Tweaks per category (so the
        membership, Defender guard and computed-value logic are shared). Returns the chosen rows, or an
        empty set if the session is non-interactive or the user backs out.
    #>
    param ([switch]$IsWhatIf)

    $stdinRedir = $false
    try { $stdinRedir = [Console]::IsInputRedirected } catch { }
    if (-not (([Environment]::UserInteractive) -or $stdinRedir)) {
        Write-OptiLog "Custom (guided) mode needs an interactive session. Re-run in a normal PowerShell window, or choose -Level Minimal|Balanced|Full." 'Error'
        Set-OptiExit 2
        return @()
    }

    $catalog = Get-TweakCatalog

    Write-Host ""
    Write-Host "== Guided Custom setup ==" -ForegroundColor Cyan
    Write-Host "For each category, choose how far to go. Nothing is applied until you confirm at the end."
    Write-Host "  [S]kip   [M]inimal (safest)   [B]alanced (recommended)   [F]ull (aggressive)"
    Write-Host ""

    $orderPref = @('Explorer', 'Performance', 'Privacy', 'Network', 'Power', 'Services', 'ScheduledTasks', 'Security', 'Update', 'Edge')
    $present = @($catalog | Where-Object { -not $_.AddOn } | Select-Object -ExpandProperty Category -Unique)
    $cats = @($orderPref | Where-Object { $present -contains $_ }) + @($present | Where-Object { $orderPref -notcontains $_ })

    $selected = @()
    foreach ($cat in $cats) {
        $catRows = @($catalog | Where-Object { -not $_.AddOn -and $_.Category -eq $cat })
        $tiers = @('Minimal', 'Balanced', 'Full' | Where-Object { $t = $_; @($catRows | Where-Object { $_.MinLevel -eq $t }).Count -gt 0 })
        Write-Host ("-- {0} --  (available at: {1})" -f $cat, ($tiers -join ', ')) -ForegroundColor Cyan
        foreach ($lvl in @('Minimal', 'Balanced', 'Full')) {
            foreach ($r in @($catRows | Where-Object { $_.MinLevel -eq $lvl })) {
                Write-Host ("    [{0}] {1} - {2} (risk {3})" -f $lvl.Substring(0, 1), $r.Name, $r.Impact, $r.Risk)
            }
        }
        $choice = Read-OptiChoice -Prompt ("  {0}: [S]kip / [M]inimal / [B]alanced / [F]ull? (Enter = Balanced)" -f $cat) -Choices @('S', 'M', 'B', 'F') -Default 'B'
        Write-Host ""
        if ($choice -eq 'S') { continue }
        $lvl = switch ($choice) { 'M' { 'Minimal' } 'B' { 'Balanced' } 'F' { 'Full' } }
        $selected += @(Select-Tweaks -Level $lvl -Categories @($cat))
    }

    foreach ($addon in @('AI', 'Gaming')) {
        $aRows = @($catalog | Where-Object { $_.AddOn -eq $addon })
        if ($aRows.Count -eq 0) { continue }
        Write-Host ("-- {0} add-on --" -f $addon) -ForegroundColor Cyan
        foreach ($r in $aRows) { Write-Host ("    {0} - {1}" -f $r.Name, $r.Impact) }
        $ans = Read-OptiChoice -Prompt ("  Include the {0} add-on? [y/N]" -f $addon) -Choices @('Y', 'N') -Default 'N'
        Write-Host ""
        if ($ans -eq 'Y') {
            if ($addon -eq 'AI') { $selected += @(Select-Tweaks -Level Minimal -IncludeAI -Categories @('AI')) }
            else { $selected += @(Select-Tweaks -Level Minimal -IncludeGaming -Categories @('Gaming')) }
        }
    }

    $selected = @($selected)
    if ($selected.Count -eq 0) { Write-OptiLog "Custom: nothing selected - no changes to make." 'Info'; return @() }

    Write-Host ("== Custom selection: {0} tweak(s) ==" -f $selected.Count) -ForegroundColor Cyan
    foreach ($t in $selected) {
        $tier = if ($t.AddOn) { "+$($t.AddOn)" } else { $t.MinLevel }
        Write-Host ("    [{0}/{1}] {2}" -f $tier, $t.Category, $t.Id)
    }
    $high = @($selected | Where-Object { $_.Risk -eq 'High' })
    if ($high.Count -gt 0) { Write-Host ("  NOTE: {0} of these are HIGH-risk (aggressive) change(s)." -f $high.Count) -ForegroundColor Yellow }
    Write-Host ""

    if ($IsWhatIf) { return $selected }   # dry run: the -WhatIf path reports what would apply, no confirm needed

    $ans = ''
    try { $ans = Read-Host "Apply these $($selected.Count) change(s)? Type 'yes' to proceed" } catch { $ans = '' }
    if ($ans -ne 'yes') { Write-OptiLog "Custom aborted before applying - no changes made." 'Info'; return @() }
    return $selected
}

function Invoke-ApplyMode {
    param ([System.Management.Automation.PSCmdlet]$Cmdlet)

    $isWhatIf = [bool]$WhatIfPreference

    # Custom runs the guided walkthrough (which builds its own selection and asks its own confirmation);
    # every other level selects declaratively from the catalog.
    if ($Level -eq 'Custom') {
        $rows = @(Invoke-CustomWalkthrough -IsWhatIf:$isWhatIf)
    } else {
        $rows = @(Select-Tweaks -Level $Level -Categories $Categories -IncludeAI:$IncludeAI -IncludeGaming:$IncludeGaming)
    }

    $tags = @()
    if ($Level -eq 'Custom') { $tags += 'custom' }
    else {
        if ($IncludeAI -or $Level -eq 'Full') { $tags += '+AI' }
        if ($IncludeGaming -or $Level -eq 'Full') { $tags += '+Gaming' }
    }
    if ($AllUsers) { $tags += 'all-users' }
    $suffix = if ($tags) { " ($($tags -join ', '))" } else { '' }

    if ($rows.Count -eq 0) {
        Write-OptiLog "Apply - Level '$Level'$suffix : no tweaks selected; nothing to do." 'Info'
        return
    }

    # Full is aggressive - confirm before proceeding (skipped by -Force, and not needed for a -WhatIf dry run).
    if ($Level -eq 'Full' -and -not $Force -and -not $isWhatIf) {
        Write-OptiLog "Full applies AGGRESSIVE changes (telemetry OFF, services disabled, security hardening) that can degrade Windows Update / Store / features over time. Balanced is recommended for most machines." 'Warning'
        if (-not [Environment]::UserInteractive) {
            Write-OptiLog "Full requires confirmation; re-run with -Force to proceed non-interactively. Aborted - no changes made." 'Error'
            Set-OptiExit 2; return
        }
        $resp = ''
        try { $resp = Read-Host "Type 'yes' to proceed with Full (anything else aborts)" } catch { $resp = '' }
        if ($resp -ne 'yes') { Write-OptiLog "Full aborted by user - no changes made." 'Info'; return }
    }

  try {
    # -AllUsers: fan out user-scope registry rows across every profile (loads unloaded hives on demand,
    # released by Clear-OptiMounts in the finally below). Machine/service/power/Appx rows are untouched.
    if ($AllUsers) {
        $rows = @(Expand-AllUsersRows -Rows $rows -DryRun:$isWhatIf)
        if ($rows.Count -eq 0) { Write-OptiLog "Apply - Level '$Level'$suffix : no applicable tweaks after profile expansion." 'Info'; return }
    }

    # Capture + snapshot BEFORE any change (skipped for a -WhatIf dry run). A snapshot failure throws
    # up to the main handler, so we never apply without a rollback in place.
    if (-not $isWhatIf) {
        Write-OptiLog "Apply - Level '$Level'$suffix : preparing rollback for $($rows.Count) tweak(s)..." 'Info'
        $rpSeq = New-OptiRestorePoint -Description "Before Optimize-Windows11 ($Level) $script:StartStamp"
        $snap = New-OptiSnapshot -Tweaks $rows -Level $Level -RestorePointSeq $rpSeq
        Write-OptiLog "Snapshot #$($snap.Index) written: $($snap.Folder)" 'Info'
        foreach ($seg in $snap.Segments.Keys) {
            $u = $snap.Segments[$seg].UndoScript
            if ($u) { Write-OptiLog "  undo ($seg, $($snap.Segments[$seg].TweakCount) tweak(s)): $u" 'Info' }
        }
    } else {
        Write-OptiLog "WhatIf - Level '$Level'$suffix : $($rows.Count) tweak(s) would be applied (no snapshot written, system unchanged)." 'Info'
    }

    # Apply each tweak under ShouldProcess (so -WhatIf previews per tweak and -Confirm can gate each).
    $applied = 0; $failed = 0; $skipped = 0
    foreach ($t in $rows) {
        $target = Get-TweakTargetText -Tweak $t
        $desired = Get-TweakDesiredText -Tweak $t
        if ($Cmdlet.ShouldProcess($target, "Set to '$desired' [$($t.Id)]")) {
            try {
                Invoke-TweakApply -Tweak $t | Out-Null
                $applied++
                Write-OptiLog "applied: $($t.Id) -> $target = $desired" 'Info'
            } catch {
                $failed++
                Write-OptiLog "FAILED: $($t.Id) ($target): $($_.Exception.Message)" 'Warning'
            }
        } else {
            $skipped++
        }
    }

    if ($isWhatIf) {
        Write-OptiLog "WhatIf complete: $($rows.Count) tweak(s) would be applied. Nothing changed." 'Info'
    } else {
        $lvl = if ($failed -gt 0) { 'Warning' } else { 'Success' }
        Write-OptiLog "Apply complete: $applied applied, $failed failed, $skipped skipped." $lvl
        if ($failed -gt 0) { Set-OptiExit 1 }
    }
  } finally {
    if ($AllUsers) { Clear-OptiMounts }
  }
}

function Invoke-PreviewMode {
    $rows = @(Select-Tweaks -Level $Level -Categories $Categories -IncludeAI:$IncludeAI -IncludeGaming:$IncludeGaming)
    Write-OptiLog "Preview - Level '$Level': $($rows.Count) tweak(s) would be evaluated (read-only; nothing changed)." 'Info'

    if (-not $Quiet) {
        foreach ($t in $rows) {
            $tier    = if ($t.AddOn) { "+$($t.AddOn)" } else { $t.MinLevel }
            $current = Get-TweakCurrentState -Tweak $t
            $desired = Get-TweakDesiredText -Tweak $t
            $flag    = if ($current -eq $desired) { 'ok' } elseif ($current -eq '<absent>') { 'new' } else { 'change' }
            Write-Host ""
            Write-Host ("  [{0}/{1}] {2}" -f $tier, $t.Category, $t.Id) -ForegroundColor Cyan
            Write-Host ("      {0}" -f (Get-TweakTargetText -Tweak $t))
            Write-Host ("      current: {0}   ->   desired: {1}   [{2}, risk {3}]" -f $current, $desired, $flag, $t.Risk)
        }
        Write-Host ""
    }
}

function Invoke-RollbackMode {
    <#
        Unwinds snapshot layers (LIFO). Default: the newest active Level layer. -To <id>: Level layers
        newest -> <id> inclusive. -All: every active layer, all stacks, newest first. -IncludeAI /
        -IncludeGaming: the newest active AI / Gaming add-on layer (independent of the Level stack).
    #>
    $idxState = Get-StackIndex
    $active = @($idxState.Layers | Where-Object { $_.Status -eq 'Active' })
    if ($active.Count -eq 0) { Write-OptiLog "No active snapshot layers to roll back." 'Info'; return }

    # Resolve the target layer set (newest Index first).
    $targets = @()
    if ($All) {
        $targets = @($active)
    } elseif ($IncludeAI -or $IncludeGaming) {
        $segs = @(); if ($IncludeAI) { $segs += 'AI' }; if ($IncludeGaming) { $segs += 'Gaming' }
        foreach ($s in $segs) {
            $top = @($active | Where-Object { $_.Segment -eq $s } | Sort-Object Index -Descending | Select-Object -First 1)
            if ($top.Count -eq 0) { Write-OptiLog "No active '$s' add-on layer to roll back." 'Warning' } else { $targets += $top[0] }
        }
    } elseif ($To) {
        $toIdx = 0
        if (-not [int]::TryParse($To, [ref]$toIdx)) { Write-OptiLog "-To expects a numeric snapshot id (see -ListSnapshots)." 'Error'; Set-OptiExit 2; return }
        $lvlActive = @($active | Where-Object { $_.Segment -eq 'Level' })
        if ($lvlActive.Index -notcontains $toIdx) { Write-OptiLog "No active Level layer with id $toIdx. Use -ListSnapshots to see available ids." 'Error'; Set-OptiExit 2; return }
        $targets = @($lvlActive | Where-Object { $_.Index -ge $toIdx })
    } else {
        $top = @($active | Where-Object { $_.Segment -eq 'Level' } | Sort-Object Index -Descending | Select-Object -First 1)
        if ($top.Count -eq 0) { Write-OptiLog "No active Level layer to roll back. Try -Rollback -All, or -IncludeAI / -IncludeGaming." 'Info'; return }
        $targets = @($top[0])
    }

    $targets = @($targets | Sort-Object Index -Descending)
    if ($targets.Count -eq 0) { Write-OptiLog "Nothing to roll back for the given options." 'Info'; return }

    Write-OptiLog "Rolling back $($targets.Count) layer(s) newest-first: $((($targets | ForEach-Object { "#$($_.Index)/$($_.Segment)" }) -join ', '))." 'Info'
    $failed = 0
    foreach ($layer in $targets) {
        $folderPath = Join-Path $script:SnapshotsRoot $layer.Folder
        $manifestPath = Join-Path $folderPath 'snapshot.json'
        if (-not (Test-Path -LiteralPath $manifestPath)) { Write-OptiLog "  #$($layer.Index)/$($layer.Segment): snapshot.json missing ($folderPath) - skipped." 'Warning'; $failed++; continue }
        try { $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json } catch { Write-OptiLog "  #$($layer.Index)/$($layer.Segment): unreadable manifest - skipped." 'Warning'; $failed++; continue }
        $segProp = $manifest.Segments.PSObject.Properties[$layer.Segment]
        $records = @()
        if ($segProp) { $records = @($segProp.Value.Records) }
        Write-OptiLog "  #$($layer.Index)/$($layer.Segment): restoring $($records.Count) tweak(s)..." 'Info'
        foreach ($r in $records) {
            try { Restore-TweakRecord -Record $r } catch { $failed++; Write-OptiLog "    FAILED $($r.Id): $($_.Exception.Message)" 'Warning' }
        }
        $layer.Status = 'RolledBack'   # $layer is a reference into $idxState.Layers
    }
    Clear-OptiMounts   # release any per-profile hives loaded on demand during restore

    # Persist status, then update manifests and archive any fully-consumed run folders.
    Save-StackIndex -State $idxState
    foreach ($f in (@($targets | Select-Object -ExpandProperty Folder -Unique))) {
        $folderPath = Join-Path $script:SnapshotsRoot $f
        $mp = Join-Path $folderPath 'snapshot.json'
        if (-not (Test-Path -LiteralPath $mp)) { continue }
        try {
            $m = Get-Content -Raw -LiteralPath $mp | ConvertFrom-Json
            $runLayers = @($idxState.Layers | Where-Object { $_.Folder -eq $f })
            foreach ($rl in $runLayers) {
                $sp = $m.Segments.PSObject.Properties[$rl.Segment]
                if ($sp) { $sp.Value | Add-Member -NotePropertyName Status -NotePropertyValue $rl.Status -Force }
            }
            $allConsumed = (@($runLayers | Where-Object { $_.Status -eq 'Active' }).Count -eq 0)
            $m | Add-Member -NotePropertyName Status -NotePropertyValue $(if ($allConsumed) { 'RolledBack' } else { 'Partial' }) -Force
            $m | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $mp -Encoding UTF8
            if ($allConsumed) {
                $dest = Join-Path $script:RolledBackRoot $f
                if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue }
                Move-Item -LiteralPath $folderPath -Destination $dest -Force -ErrorAction Stop
                foreach ($rl in $runLayers) { $rl.Folder = (Join-Path '_rolledback' $f) }
                Save-StackIndex -State $idxState
                Write-OptiLog "  archived fully-rolled-back snapshot -> _rolledback\$f" 'Info'
            }
        } catch { Write-OptiLog "  (post-rollback update for $f failed: $($_.Exception.Message))" 'Warning' }
    }

    if ($failed -gt 0) { Set-OptiExit 1; Write-OptiLog "Rollback finished with $failed error(s)." 'Warning' }
    else { Write-OptiLog "Rollback complete." 'Success' }
}

function Invoke-ListSnapshotsMode {
    $idxState = Get-StackIndex
    $layers = @($idxState.Layers)
    if ($layers.Count -eq 0) { Write-OptiLog "No snapshots recorded yet." 'Info'; return }

    Write-OptiLog "$($layers.Count) snapshot layer(s) recorded (id = number to pass to -Rollback -To):" 'Info'
    if (-not $Quiet) {
        $view = $layers | Sort-Object Index, Segment | ForEach-Object {
            [pscustomobject]@{ Id = $_.Index; Stamp = $_.Stamp; Segment = $_.Segment; Level = $_.Level; Tweaks = $_.TweakCount; Status = $_.Status }
        }
        ($view | Format-Table -AutoSize | Out-String).Trim() | Write-Host
        foreach ($seg in @('Level', 'AI', 'Gaming')) {
            $top = @($layers | Where-Object { $_.Segment -eq $seg -and $_.Status -eq 'Active' } | Sort-Object Index -Descending | Select-Object -First 1)
            if ($top.Count) {
                $how = if ($seg -eq 'Level') { '-Rollback' } else { "-Rollback -Include$seg" }
                Write-Host ("  top of {0} stack: #{1} ({2})  <- {3}" -f $seg, $top[0].Index, $top[0].Stamp, $how)
            }
        }
    }
}

# =================================================================================================
# Main
# =================================================================================================
$mode = $PSCmdlet.ParameterSetName
$readOnly = ($mode -in @('Preview', 'ListSnapshots'))

try {
    # 1) Store + logging first, so everything from here on is recorded.
    if (-not (Initialize-SnapshotStore -ReadOnlyMode:$readOnly)) {
        Set-OptiExit 2
        exit $script:ExitCode
    }

    Write-OptiLog "Optimize-Windows11 v$script:ScriptVersion starting - mode '$mode' on $env:COMPUTERNAME." 'Info'

    # 2) Elevation. Apply and Rollback mutate the system and the protected store; require admin.
    if (-not (Test-OptiElevated)) {
        if ($readOnly) {
            Write-OptiLog "Not running elevated - continuing in read-only mode (some values may be unreadable)." 'Warning'
        } else {
            Write-OptiLog "Administrative privileges are required for '$mode'. Re-run from an elevated PowerShell session." 'Error'
            Set-OptiExit 2
            exit $script:ExitCode
        }
    }

    # 3) OS check. Windows 11 is expected; warn (do not block) on Windows 10 / Server.
    $os = Get-OptiOSInfo
    if (-not $os.IsWindows11) {
        Write-OptiLog "This tool targets Windows 11 (build $script:WindowsBuildMin+). Detected build $($os.Build) - '$($os.Caption)'. Some tweaks may not apply as intended." 'Warning'
    }
    if (-not $os.IsClient) {
        Write-OptiLog "A Server SKU was detected. System Restore points are unavailable there; the restore-point step will be skipped when it is added." 'Warning'
    }

    # 4) Harden the store (skipped for read-only, non-elevated sessions that could not create it).
    if (-not $readOnly -or (Test-Path -LiteralPath $script:StoreRoot)) {
        if (Test-OptiElevated) { Protect-SnapshotStore }
    }

    # 5) Dispatch.
    switch ($mode) {
        'Apply'         { Invoke-ApplyMode -Cmdlet $PSCmdlet }
        'Preview'       { Invoke-PreviewMode }
        'Rollback'      { Invoke-RollbackMode }
        'ListSnapshots' { Invoke-ListSnapshotsMode }
        default         { Invoke-ApplyMode -Cmdlet $PSCmdlet }
    }

    Write-OptiLog "Done - exit code $script:ExitCode. Log: $script:LogFile" 'Success'
} catch {
    Write-OptiLog "Unhandled error: $($_.Exception.Message)" 'Error'
    if ($_.ScriptStackTrace) { Write-OptiLog "  at: $(($_.ScriptStackTrace -split "`r?`n") -join ' <- ')" 'Error' }
    Set-OptiExit 2
}

exit $script:ExitCode

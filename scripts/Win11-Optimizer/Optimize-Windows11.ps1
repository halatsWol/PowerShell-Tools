#Requires -Version 5.1

<#
.SYNOPSIS
    Flexible Windows 11 optimizer with tiered intensity and a stacked, restorable rollback.

.DESCRIPTION
    A PowerShell reimagining of TBOK-Win11Optimizer. Applies Windows 11 optimizations at a chosen
    intensity (-Level Minimal | Balanced | Full, or a guided Custom walkthrough), while capturing the
    prior state of everything it touches so any run can be rolled back - including layered runs, which
    unwind one step at a time.

    This is the Phase A / commit 1 skeleton: parameter surface, elevation / OS guards, the ProgramData
    snapshot store (created and ACL-hardened), logging and the exit-code contract. No tweaks are applied
    yet - the tweak catalog, apply/capture engine, rollback runner and restore-point step arrive in the
    following commits.

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
$script:ScriptVersion   = '0.8.0'
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
#   Type      - Registry | Service | ScheduledTask | Appx | Bcdedit | Powercfg (only Registry so far).
#   Registry payload: Path / ValueName / ValueType / Data.
# This commit seeds a representative slice of the Minimal tier; later commits flesh out every tier.
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
        # Level / add-on membership.
        if ($t.AddOn -eq 'AI')          { $include = $wantAI }
        elseif ($t.AddOn -eq 'Gaming')  { $include = $wantGaming }
        elseif ($Level -eq 'Custom')    { $include = $true }
        else                            { $include = ($rank[$t.MinLevel] -le $rank[$Level]) }
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

        # Computed value -> resolve on a copy so downstream sees a literal.
        if ($t.Data -is [scriptblock]) {
            $resolved = $t.PSObject.Copy()
            try { $resolved.Data = (& $t.Data $hw) } catch { Write-OptiLog "Computed value failed for '$($t.Id)': $($_.Exception.Message) - skipped." 'Warning'; continue }
            $resolved
        } else {
            $t
        }
    }

    return @($selected)
}

# =================================================================================================
# Current-state reads (the read half of the capture engine; full capture arrives in a later commit)
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
            $svc = Get-Service -Name $Tweak.ServiceName -ErrorAction SilentlyContinue
            if ($svc) { return [string]$svc.StartType } else { return '<absent>' }
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
        default    { return '' }
    }
}

function Get-TweakTargetText {
    # Short human description of what a tweak touches.
    param ($Tweak)
    switch ($Tweak.Type) {
        'Registry' { return "$($Tweak.Path)\$($Tweak.ValueName)" }
        'Service'  { return "Service:$($Tweak.ServiceName)" }
        default    { return $Tweak.Id }
    }
}

# =================================================================================================
# Capture engine + snapshot / undo-script generation
# (This commit captures prior state and writes the rollback artifacts; the live apply that will sit
#  between capture and finish arrives in the next commit.)
# =================================================================================================
function Get-TweakCaptureRecord {
    # Records the live prior state of a tweak so an undo can restore it exactly. Read-only.
    param ($Tweak)
    switch ($Tweak.Type) {
        'Registry' {
            $state = Get-RegistryValueState -Path $Tweak.Path -ValueName $Tweak.ValueName
            return [pscustomobject]@{
                Id = $Tweak.Id; Category = $Tweak.Category; Type = 'Registry'; Scope = $Tweak.Scope
                AddOn = $Tweak.AddOn
                Path = $Tweak.Path; ValueName = $Tweak.ValueName
                DesiredType = $Tweak.ValueType; DesiredData = $Tweak.Data
                PriorExists = $state.Exists; PriorData = $state.Data; PriorKind = $state.Kind
                KeyExisted = (Test-Path -LiteralPath $Tweak.Path)
            }
        }
        'Service' {
            $svc = Get-Service -Name $Tweak.ServiceName -ErrorAction SilentlyContinue
            return [pscustomobject]@{
                Id = $Tweak.Id; Category = $Tweak.Category; Type = 'Service'; Scope = $Tweak.Scope
                AddOn = $Tweak.AddOn
                ServiceName = $Tweak.ServiceName; DesiredStartupType = $Tweak.StartupType
                ServiceExists = [bool]$svc
                PriorStartupType = $(if ($svc) { [string]$svc.StartType } else { $null })
                PriorStatus = $(if ($svc) { [string]$svc.Status } else { $null })
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

function New-RegistryUndoLine {
    # PowerShell lines that restore one registry value to its captured prior state.
    param ($Record)
    $lines = New-Object System.Collections.Generic.List[string]
    if ($Record.Type -ne 'Registry') {
        $lines.Add("# (skip: undo for type '$($Record.Type)' is not implemented in this build)")
        return $lines
    }
    $pathLit = "'" + ([string]$Record.Path -replace "'", "''") + "'"
    $nameLit = "'" + ([string]$Record.ValueName -replace "'", "''") + "'"
    if ($Record.PriorExists) {
        $valLit = ConvertTo-RegLiteral -Kind $Record.PriorKind -Data $Record.PriorData
        $lines.Add("if (-not (Test-Path -LiteralPath $pathLit)) { New-Item -Path $pathLit -Force | Out-Null }")
        $lines.Add("New-ItemProperty -LiteralPath $pathLit -Name $nameLit -PropertyType $($Record.PriorKind) -Value $valLit -Force | Out-Null")
    } else {
        $lines.Add("Remove-ItemProperty -LiteralPath $pathLit -Name $nameLit -Force -ErrorAction SilentlyContinue")
        if (-not $Record.KeyExisted) {
            $lines.Add("if (Test-Path -LiteralPath $pathLit) { `$k = Get-Item -LiteralPath $pathLit; if (`$k.ValueCount -eq 0 -and `$k.SubKeyCount -eq 0) { Remove-Item -LiteralPath $pathLit -Force -ErrorAction SilentlyContinue } }")
        }
    }
    return $lines
}

function New-ServiceUndoLine {
    # PowerShell line that restores one service's start type to its captured prior value.
    param ($Record)
    $lines = New-Object System.Collections.Generic.List[string]
    $svcLit = "'" + ([string]$Record.ServiceName -replace "'", "''") + "'"
    if ($Record.ServiceExists -and (@('Automatic', 'Manual', 'Disabled') -contains [string]$Record.PriorStartupType)) {
        $lines.Add("if (Get-Service -Name $svcLit -ErrorAction SilentlyContinue) { Set-Service -Name $svcLit -StartupType $($Record.PriorStartupType) -ErrorAction SilentlyContinue }")
    } else {
        $lines.Add("# service $svcLit was not present (or had an unsupported start type) at capture - nothing to undo")
    }
    return $lines
}

function New-UndoLine {
    # Dispatches undo-line generation by record type.
    param ($Record)
    switch ($Record.Type) {
        'Registry' { return (New-RegistryUndoLine -Record $Record) }
        'Service'  { return (New-ServiceUndoLine -Record $Record) }
        default    { $l = New-Object System.Collections.Generic.List[string]; $l.Add("# (undo for type '$($Record.Type)' not implemented)"); return $l }
    }
}

function Restore-TweakRecord {
    # In-process twin of New-RegistryUndoLine: restores one captured record to its prior state. Used by
    # the built-in -Rollback runner (the generated .ps1 is for standalone use). Registry only so far.
    param ($Record)
    $ConfirmPreference = 'None'; $WhatIfPreference = $false
    switch ($Record.Type) {
        'Registry' {
            $path = [string]$Record.Path
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
            if ($Record.ServiceExists -and (@('Automatic', 'Manual', 'Disabled') -contains [string]$Record.PriorStartupType)) {
                if (Get-Service -Name $Record.ServiceName -ErrorAction SilentlyContinue) {
                    Set-Service -Name $Record.ServiceName -StartupType $Record.PriorStartupType -ErrorAction SilentlyContinue
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
    # Applies one tweak to the system. Returns $true on success; throws on failure. Registry only so far.
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
            if (-not (Get-Service -Name $Tweak.ServiceName -ErrorAction SilentlyContinue)) {
                Write-OptiLog "  (service '$($Tweak.ServiceName)' not present - skipped)" 'Info'
                return $true
            }
            Set-Service -Name $Tweak.ServiceName -StartupType $Tweak.StartupType -ErrorAction Stop
            return $true
        }
        default { throw "Apply for tweak type '$($Tweak.Type)' is not implemented in this build." }
    }
}

function Invoke-ApplyMode {
    param ([System.Management.Automation.PSCmdlet]$Cmdlet)

    $rows = @(Select-Tweaks -Level $Level -Categories $Categories -IncludeAI:$IncludeAI -IncludeGaming:$IncludeGaming)
    $addons = @(); if ($IncludeAI -or $Level -eq 'Full') { $addons += 'AI' }; if ($IncludeGaming -or $Level -eq 'Full') { $addons += 'Gaming' }
    $suffix = if ($addons) { " (+$($addons -join ', +'))" } else { '' }

    if ($rows.Count -eq 0) {
        Write-OptiLog "Apply - Level '$Level'$suffix : no tweaks selected; nothing to do." 'Info'
        return
    }

    $isWhatIf = [bool]$WhatIfPreference

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
    Set-OptiExit 2
}

exit $script:ExitCode

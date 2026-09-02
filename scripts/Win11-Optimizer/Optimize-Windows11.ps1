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
$script:ScriptVersion   = '0.4.0'
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
function Select-Tweaks {
    <#
        Resolves the effective tweak set for the requested Level / Categories / add-ons, then runs every
        row through the Defender guard (blocked rows are dropped with a warning). Levels are cumulative;
        add-on rows are included only when their add-on is requested or the Level is Full. Custom (guided
        mode, later commit) previews the whole catalog.
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

    $selected = foreach ($t in (Get-TweakCatalog)) {
        # Level / add-on membership.
        if ($t.AddOn -eq 'AI')          { $include = $wantAI }
        elseif ($t.AddOn -eq 'Gaming')  { $include = $wantGaming }
        elseif ($Level -eq 'Custom')    { $include = $true }
        else                            { $include = ($rank[$t.MinLevel] -le $rank[$Level]) }

        # Optional category filter.
        if ($include -and $Categories) { $include = ($Categories -contains $t.Category) }

        if ($include) {
            if (Test-IsDefenderTarget -Tweak $t) {
                Write-OptiLog "Skipping '$($t.Id)': targets a protected Windows Defender key/service and is never applied." 'Warning'
            } else {
                $t
            }
        }
    }

    return @($selected)
}

# =================================================================================================
# Current-state reads (the read half of the capture engine; full capture arrives in a later commit)
# =================================================================================================
function Get-RegistryValueState {
    # Returns Exists / Data / Kind for a single registry value without altering anything.
    param ([string]$Path, [string]$ValueName)

    $res = [pscustomobject]@{ Exists = $false; Data = $null; Kind = $null }
    try {
        if (Test-Path -LiteralPath $Path) {
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($key.GetValueNames() -contains $ValueName) {
                $res.Exists = $true
                $res.Data   = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $res.Kind   = $key.GetValueKind($ValueName).ToString()
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
        default { return '<n/a>' }
    }
}

function Get-TweakTargetText {
    # Short human description of what a tweak touches.
    param ($Tweak)
    switch ($Tweak.Type) {
        'Registry' { return "$($Tweak.Path)\$($Tweak.ValueName)" }
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
        foreach ($line in (New-RegistryUndoLine -Record $r)) { [void]$sb.AppendLine($line) }
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

function New-OptiSnapshot {
    <#
        Captures the prior state of every selected tweak and writes a stack layer under ProgramData:
        a snapshot folder with per-segment undo .ps1 scripts, .reg backups of the touched keys, a
        snapshot.json manifest, and an entry in stack-index.json. Does NOT modify the system.
    #>
    param ([object[]]$Tweaks, [string]$Level)

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
        RestorePointSeq = $null
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
        default { throw "Apply for tweak type '$($Tweak.Type)' is not implemented in this build." }
    }
}

function Invoke-ApplyMode {
    param ([System.Management.Automation.PSCmdlet]$Cmdlet)

    $rows = Select-Tweaks -Level $Level -Categories $Categories -IncludeAI:$IncludeAI -IncludeGaming:$IncludeGaming
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
        Write-OptiLog "Apply - Level '$Level'$suffix : capturing prior state of $($rows.Count) tweak(s)..." 'Info'
        $snap = New-OptiSnapshot -Tweaks $rows -Level $Level
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
        $desired = if ($t.Type -eq 'Registry') { [string]$t.Data } else { '' }
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
    $rows = Select-Tweaks -Level $Level -Categories $Categories -IncludeAI:$IncludeAI -IncludeGaming:$IncludeGaming
    Write-OptiLog "Preview - Level '$Level': $($rows.Count) tweak(s) would be evaluated (read-only; nothing changed)." 'Info'

    if (-not $Quiet) {
        foreach ($t in $rows) {
            $tier    = if ($t.AddOn) { "+$($t.AddOn)" } else { $t.MinLevel }
            $current = Get-TweakCurrentState -Tweak $t
            $desired = if ($t.Type -eq 'Registry') { [string]$t.Data } else { '' }
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
    Write-OptiLog "Rollback mode. The snapshot stack and rollback runner are not implemented yet." 'Info'
}

function Invoke-ListSnapshotsMode {
    Write-OptiLog "No snapshots exist yet (snapshot creation is not implemented in this build)." 'Info'
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

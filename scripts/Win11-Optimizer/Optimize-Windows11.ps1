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

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Apply')]
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
$script:ScriptVersion   = '0.1.0'
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
# Mode stubs (fleshed out in later commits)
# =================================================================================================
function Invoke-ApplyMode {
    Write-OptiLog "Apply mode - Level '$Level'$(if ($IncludeAI) {' +AI'})$(if ($IncludeGaming) {' +Gaming'})." 'Info'
    Write-OptiLog "No tweak catalog is wired up yet (skeleton build). Nothing was changed." 'Info'
}

function Invoke-PreviewMode {
    Write-OptiLog "Preview mode - Level '$Level'. The tweak catalog is not implemented yet; nothing to list." 'Info'
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
        'Apply'         { Invoke-ApplyMode }
        'Preview'       { Invoke-PreviewMode }
        'Rollback'      { Invoke-RollbackMode }
        'ListSnapshots' { Invoke-ListSnapshotsMode }
        default         { Invoke-ApplyMode }
    }

    Write-OptiLog "Done - exit code $script:ExitCode. Log: $script:LogFile" 'Success'
} catch {
    Write-OptiLog "Unhandled error: $($_.Exception.Message)" 'Error'
    Set-OptiExit 2
}

exit $script:ExitCode

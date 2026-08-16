<#
.SYNOPSIS
    Make the module .psd1 files the single source of truth for the version numbers shown in the
    release artifacts, so they never have to be maintained by hand.

.DESCRIPTION
    Reads ModuleVersion from every modules/*/*.psd1 and rewrites the "(vX.Y)" that follows each
    module's name in make/Pre-Install.nfo and the manifest lines of make/releasenote.md. With -Tag,
    it also sets the suite version in the release-note header and the /tree/<tag>/ module links from
    the release tag. Idempotent - safe to run repeatedly.

    The release workflow (.github/workflows/release.yml) runs this on tag push, before building the
    installers (which embed Pre-Install.nfo) and before reading releasenote.md as the release body.
    Run it locally any time to keep the checked-in files in sync with the manifests.

.PARAMETER Tag
    Optional suite/release version (e.g. the git tag 'v1.6.1'). When given, the release-note header
    and the module tree-links are updated to it. Omit to leave the suite version untouched.

.EXAMPLE
    pwsh make/Sync-ReleaseVersions.ps1 -Tag v1.6.1
#>
[CmdletBinding()]
param(
    [string]$Tag
)

$ErrorActionPreference = 'Stop'
$make = $PSScriptRoot
$repo = Split-Path $make -Parent

# module name (= .psd1 base name) -> ModuleVersion, straight from the manifests
$versions = [ordered]@{}
foreach ($dir in (Get-ChildItem (Join-Path $repo 'modules') -Directory | Sort-Object Name)) {
    $psd1 = Get-ChildItem $dir.FullName -Filter '*.psd1' -File | Select-Object -First 1
    if ($psd1) { $versions[$psd1.BaseName] = [string](Import-PowerShellDataFile $psd1.FullName).ModuleVersion }
}
if ($versions.Count -eq 0) { throw "No module .psd1 files found under '$repo\modules'." }

function Update-File([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { Write-Warning "Skipping missing file: $path"; return }
    $text = [System.IO.File]::ReadAllText($path)
    foreach ($name in $versions.Keys) {
        $v = $versions[$name]
        # The "(vX.Y[.Z])" that follows the module name on a manifest / nfo list line. The version is
        # required to start with a digit, so prose like "(via WMI...)" is never matched.
        $rx = '(?m)^(?<pre>[^\r\n]*\b' + [regex]::Escape($name) + '\b[^\r\n]*?\(v)\d[^)\r\n]*(?<post>\))'
        $text = [regex]::Replace($text, $rx, { param($mm) $mm.Groups['pre'].Value + $v + $mm.Groups['post'].Value })
    }
    if ($Tag) {
        $text = [regex]::Replace($text, '(?m)^(Easy installer for PowerShell-Tools )v\S+', "`${1}$Tag")
        $text = [regex]::Replace($text, '/tree/[^/]+/', "/tree/$Tag/")
    }
    [System.IO.File]::WriteAllText($path, $text)
}

Update-File (Join-Path $make 'Pre-Install.nfo')
Update-File (Join-Path $make 'releasenote.md')

Write-Host "Applied module versions from .psd1:"
$versions.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-18} v{1}" -f $_.Key, $_.Value) }
if ($Tag) { Write-Host "Suite/tag version: $Tag" }

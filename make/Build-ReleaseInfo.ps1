<#
.SYNOPSIS
    Render the release info templates (installer pre-install info, release note) with the module
    versions from the .psd1 manifests and the suite/release tag.

.DESCRIPTION
    make/Pre-Install.nfo and make/releasenote.md are templates; the rendered copies are written to
    make/build/. The templates stay untouched, so they never drift from the manifests.

    Placeholders:
        {{Tag}}               suite/release version, e.g. v1.8.0
        {{Version:<Module>}}  ModuleVersion of that module's .psd1, e.g. {{Version:TempDataCleanup}} -> 1.8
        {{ModuleList}}        one line per module, generated from modules/*/*.psd1. Must be alone on
                              its line; any indentation before it is repeated on every line.
                              .md:  - [Name](https://github.com/.../tree/<Tag>/modules/<Folder>) (vX.Y)
                              else: - Name (vX.Y)

    <Module> is the .psd1 base name (RepairSystem, not Repair-System). An unknown placeholder or
    module name fails the run, so a typo can't slip into a release.

    Both installer scripts (make/*.iss) run this from the Inno preprocessor with their MyAppVersion,
    and the release workflow runs it before reading make/build/releasenote.md as the release body.

.PARAMETER Tag
    Suite/release version (the git tag, e.g. 'v1.8.0'). Defaults to 'dev' for local builds.

.EXAMPLE
    pwsh make/Build-ReleaseInfo.ps1 -Tag v1.8.0
#>
[CmdletBinding()]
param(
    [string]$Tag = 'dev'
)

$ErrorActionPreference = 'Stop'
$make = $PSScriptRoot
$repo = Split-Path $make -Parent
$out = Join-Path $make 'build'
$repoUrl = 'https://github.com/halatsWol/PowerShell-Tools'

# Parsed directly instead of Import-PowerShellDataFile: when the Inno preprocessor starts
# powershell.exe from a pwsh 7 shell, the inherited PSModulePath hides that cmdlet.
function Read-Psd1([string]$path) {
    $tokens = $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Cannot parse '$path': $($errors[0].Message)" }
    $hash = $ast.Find({ param($a) $a -is [System.Management.Automation.Language.HashtableAst] }, $false)
    if (-not $hash) { throw "No manifest hashtable in '$path'." }
    $hash.SafeGetValue()
}

$modules = foreach ($dir in (Get-ChildItem (Join-Path $repo 'modules') -Directory | Sort-Object Name)) {
    $psd1 = Get-ChildItem $dir.FullName -Filter '*.psd1' -File | Select-Object -First 1
    if ($psd1) {
        [pscustomobject]@{
            Name    = $psd1.BaseName
            Folder  = $dir.Name
            Version = [string](Read-Psd1 $psd1.FullName).ModuleVersion
        }
    }
}
if (-not $modules) { throw "No module .psd1 files found under '$repo\modules'." }
$modules | Where-Object { -not $_.Version } | ForEach-Object { throw "$($_.Name).psd1 has no ModuleVersion." }

function Expand-Template([string]$name) {
    $src = Join-Path $make $name
    $bytes = [System.IO.File]::ReadAllBytes($src)
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $text = [System.IO.File]::ReadAllText($src)
    $nl = if ($text -match "`r`n") { "`r`n" } else { "`n" }
    $isMarkdown = [System.IO.Path]::GetExtension($name) -eq '.md'

    $text = [regex]::Replace($text, '(?m)^(?<indent>[ \t]*)\{\{ModuleList\}\}[ \t]*(?=\r?$)', {
        param($m)
        $lines = foreach ($mod in $modules) {
            if ($isMarkdown) { "- [$($mod.Name)]($repoUrl/tree/$Tag/modules/$($mod.Folder)) (v$($mod.Version))" }
            else { "- $($mod.Name) (v$($mod.Version))" }
        }
        ($lines | ForEach-Object { $m.Groups['indent'].Value + $_ }) -join $nl
    })

    $text = [regex]::Replace($text, '\{\{(?<key>[^{}]*)\}\}', {
        param($m)
        $key = $m.Groups['key'].Value
        if ($key -eq 'Tag') { return $Tag }
        if ($key -match '^Version:(?<mod>.+)$') {
            $mod = $modules | Where-Object Name -eq $Matches['mod']
            if ($mod) { return $mod.Version }
            throw "$name`: unknown module in placeholder '{{$key}}'. Known: $($modules.Name -join ', ')"
        }
        throw "$name`: unknown placeholder '{{$key}}' ({{ModuleList}} must be alone on its line)."
    })

    $null = New-Item -ItemType Directory -Path $out -Force
    [System.IO.File]::WriteAllText((Join-Path $out $name), $text, (New-Object System.Text.UTF8Encoding $hasBom))
}

Expand-Template 'Pre-Install.nfo'
Expand-Template 'releasenote.md'

Write-Host "Rendered release info to $out (tag $Tag):"
$modules | ForEach-Object { Write-Host ("  {0,-18} v{1}" -f $_.Name, $_.Version) }

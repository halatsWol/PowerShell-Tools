# Builds the documentation site (GitHub Pages, https://software.kmarflow.com/PowerShell-Tools/) with MkDocs.
# Stages website/mkdocs.yml, website/overrides and website/pages, and adds each module's README as its page of the
# manual, so the READMEs on GitHub and the site come from one text. A README's own title is replaced by the module
# name, its Author section is left out (the site has its own contact), and links to a module folder on GitHub are
# pointed at that module's page.
#
# Usage: pwsh -File make/Build-Website.ps1 -OutDir make/build/website     (needs mkdocs-material: pip install mkdocs-material)
param(
    [string]$OutDir = 'make/build/website',
    [string]$MkDocs = 'mkdocs'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$stage = Join-Path $root $OutDir
$docs = Join-Path $stage 'docs'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $docs | Out-Null

Copy-Item (Join-Path $root 'website/mkdocs.yml') $stage
Copy-Item (Join-Path $root 'website/overrides') $stage -Recurse
Copy-Item (Join-Path $root 'website/pages/*') $docs -Recurse

$modules = @(
    @{ Folder = 'Repair-System'; Page = 'repair-system.md' },
    @{ Folder = 'TempDataCleanup'; Page = 'tempdatacleanup.md' },
    @{ Folder = 'CredentialHandler'; Page = 'credentialhandler.md' },
    @{ Folder = 'Shortcuts'; Page = 'shortcuts.md' }
)
foreach ($m in $modules) {
    $text = (Get-Content (Join-Path $root "modules/$($m.Folder)/README.MD") -Raw -Encoding utf8) -replace "`r`n", "`n"
    $text = $text -replace '\A\s*#[^\n]*', "# $($m.Folder)"
    $text = $text -replace '(?ms)^## Author\n.*?(?=^## |\z)', ''
    foreach ($other in $modules) {
        $text = $text -replace "\]\(https://github\.com/halatsWol/PowerShell-Tools/tree/main/modules/$($other.Folder)/?\)", "]($($other.Page))"
    }
    $outside = [regex]::Match($text, '\]\((?!https?:|mailto:|#)[^)]*\.\./[^)]*\)')
    if ($outside.Success) { Write-Warning "$($m.Folder)/README.MD still links outside the site: $($outside.Value)" }
    Set-Content (Join-Path $docs "manual/$($m.Page)") $text -Encoding utf8 -NoNewline
}

Push-Location $stage
try {
    & $MkDocs build --strict
    if ($LASTEXITCODE -ne 0) { throw 'mkdocs build failed' }
}
finally { Pop-Location }
Write-Host "Site built: $(Join-Path $stage 'site')"

$(
# =====================================================================
# Find files that would exceed the SharePoint/OneDrive path limit
# after being moved into a SharePoint sync folder.
#
# Example:
# Source Root      : I:\Projects
# Sync Folder Name : YourTeamsGroup - Documents
#
# A file:
# I:\Projects\FolderA\FolderB\File.pdf
#
# Is evaluated as:
# YourTeamsGroup - Documents\FolderA\FolderB\File.pdf
#
# Files exceeding 259 characters are grouped by folder.
#
# =====================================================================
# Can also be used for local Sync Folder:
#
# Example:
# Source Root      : C:\Users\myUser\CompanySyncRoot\YourTeamsGroup - Documents
# Sync Folder Name : YourTeamsGroup - Documents
# 
# >> this will list all Files exceeding the limit starting with "YourTeamsGroup - Documents" down
# to the file Extension
#
# A file:
# C:\Users\myUser\CompanySyncRoot\YourTeamsGroup - Documents\Projects\FolderA\FolderB\File.pdf
#
# Is evaluated as:
# YourTeamsGroup - Documents\Projects\FolderA\FolderB\File.pdf
#
#
# =====================================================================
# Retruns the result like the following:
#
# >> Folder: I:\Projects\Engineering\Documentation
# >> Affected Files: 3
# >> Longest Path Length: 292
# >> --------------------------------------------------------------------------------
# >> VeryLongTechnicalDocumentName_v27_Final.pdf (+33)
# >> Archive\Drawing_Revision_2021_Approved.dwg (+21)
# >> Specifications\Vendor\ExtremelyLongFilename.xlsx (+8)
# >> 
# >> Folder: I:\Projects\SAP\Exports
# >> Affected Files: 2
# >> Longest Path Length: 274
# >> --------------------------------------------------------------------------------
# >> Export_20260824_DetailedReport.xlsx (+15)
# >> Export_20260825_DetailedReport.xlsx (+7)
#
# =====================================================================

$SourceRoot = Read-Host "Enter source root directory (e.g. I:\Projects)"
$SyncFolderName = Read-Host "Enter SharePoint Sync Folder Name (e.g. YourTeamsGroup - Documents)"

$MaxLength = 259

if (!(Test-Path $SourceRoot)) {
    Write-Host "Source path not found: $SourceRoot" -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "Scanning files..." -ForegroundColor Yellow

$Results = foreach ($File in Get-ChildItem -Path $SourceRoot -File -Recurse -Force -ErrorAction SilentlyContinue) {

    $RelativePath = $File.FullName.Substring($SourceRoot.TrimEnd('\').Length + 1)

    # Simulated SharePoint path after migration
    $TargetPath = "$SyncFolderName\$RelativePath"

    $Length = $TargetPath.Length

    if ($Length -gt $MaxLength) {

        [PSCustomObject]@{
            Folder       = Split-Path $File.FullName -Parent
            FileName     = $File.Name
            FullPath     = $File.FullName
            TargetPath   = $TargetPath
            Length       = $Length
            ExcessChars  = $Length - $MaxLength
        }
    }
}

if (-not $Results) {
    Write-Host ""
    Write-Host "No files would exceed $MaxLength characters." -ForegroundColor Green
    return
}

# ---------------------------------------------------------------------
# Console Report
# ---------------------------------------------------------------------

$GroupedResults = $Results | Group-Object Folder | Sort-Object Name

Write-Host ""
Write-Host "===== LONG PATH REPORT =====" -ForegroundColor Cyan

foreach ($Group in $GroupedResults) {

    $Longest = $Group.Group |
        Sort-Object Length -Descending |
        Select-Object -First 1

    Write-Host ""
    Write-Host "Folder: $($Group.Name)" -ForegroundColor Yellow
    Write-Host "Affected Files: $($Group.Count)"
    Write-Host "Longest Path Length: $($Longest.Length)"
    Write-Host ('-' * 80)

    $Group.Group |
        Sort-Object ExcessChars -Descending |
        ForEach-Object {

            $RelativeFile = $_.FullPath.Substring($Group.Name.Length + 1)

            Write-Host ("{0} (+{1})" -f $RelativeFile, $_.ExcessChars)
        }
}

# ---------------------------------------------------------------------
# Folder Summary CSV
# ---------------------------------------------------------------------

$FolderSummary = foreach ($Group in $GroupedResults) {

    $Longest = $Group.Group |
        Sort-Object Length -Descending |
        Select-Object -First 1

    [PSCustomObject]@{
        Folder            = $Group.Name
        AffectedFiles     = $Group.Count
        LongestPathLength = $Longest.Length
        ExceedsBy         = $Longest.ExcessChars
    }
}

# ---------------------------------------------------------------------
# Detailed CSV
# ---------------------------------------------------------------------

$DetailedCsv = Join-Path $PWD "LongPathFiles_Detailed.csv"
$SummaryCsv  = Join-Path $PWD "LongPathFolders_Summary.csv"

$Results |
    Sort-Object ExcessChars -Descending |
    Export-Csv $DetailedCsv -NoTypeInformation -Encoding UTF8

$FolderSummary |
    Export-Csv $SummaryCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "===== SUMMARY =====" -ForegroundColor Cyan
Write-Host "Affected folders : $($GroupedResults.Count)"
Write-Host "Affected files   : $($Results.Count)"
Write-Host ""
Write-Host "Detailed CSV : $DetailedCsv" -ForegroundColor Green
Write-Host "Summary CSV  : $SummaryCsv" -ForegroundColor Green
pause)

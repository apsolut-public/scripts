<#
.SYNOPSIS
    Delete files whose name is a Windows reserved device name (nul, con, aux, prn, com0-9, lpt0-9).

.DESCRIPTION
    AI coding tools (Cursor, Copilot, and friends) occasionally create a file literally
    named `nul`. Windows treats that as a device, not a file, so Explorer and a plain
    `del` both refuse to touch it. The escape hatch is the \\?\ prefix, which skips
    Win32 path parsing and hands the raw path to the filesystem.

    This scans a directory for any such file and deletes it that way.

    Git already refuses to track reserved names, so these files never reach a remote --
    they just sit in the working tree and clutter `git status`.

.PARAMETER Path
    Directory to scan. Defaults to the current directory.

.PARAMETER Recurse
    Scan subdirectories too.

.PARAMETER Quiet
    Only report deletions and errors, not the "nothing found" case.

.EXAMPLE
    .\nuke-nul.ps1
    Scan the current directory.

.EXAMPLE
    .\nuke-nul.ps1 -Path D:\sites\git -Recurse -WhatIf
    Show what would be deleted across a whole tree, without deleting anything.

.NOTES
    If deletion fails with access denied, re-run in an elevated PowerShell.
    Reference: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Position = 0)]
    [string] $Path = '.',

    [switch] $Recurse,

    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# CON PRN AUX NUL COM0-9 LPT9 -- reserved with or without an extension, so `nul.txt` counts too.
$reserved = @('CON', 'PRN', 'AUX', 'NUL') +
            (0..9 | ForEach-Object { "COM$_" }) +
            (0..9 | ForEach-Object { "LPT$_" })

$reservedPattern = '^(' + ($reserved -join '|') + ')(\..*)?$'

try {
    $root = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
}
catch {
    Write-Error "Path not found: $Path"
    exit 1
}

if ($root -like '\\*') {
    Write-Error "UNC paths are not supported -- map the share to a drive letter first. Got: $root"
    exit 1
}

Write-Verbose "Scanning $root (recurse: $($Recurse.IsPresent))"

$found = @(
    Get-ChildItem -LiteralPath $root -Force -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $reservedPattern }
)

if ($found.Count -eq 0) {
    if (-not $Quiet) { Write-Host "No reserved-name files under $root" -ForegroundColor Green }
    exit 0
}

$deleted = 0
$failed = 0

foreach ($file in $found) {
    $target = $file.FullName

    if (-not $PSCmdlet.ShouldProcess($target, 'Delete reserved-name file')) { continue }

    # \\?\ bypasses Win32 path parsing, which is what makes the device name deletable.
    # cmd's del handles this prefix; Remove-Item does not.
    cmd /c del /f /q "\\?\$target" 2>&1 | Out-Null

    if (Test-Path -LiteralPath "\\?\$target") {
        Write-Warning "Could not delete: $target -- try again in an elevated PowerShell"
        $failed++
    }
    else {
        Write-Host "Deleted $target" -ForegroundColor Yellow
        $deleted++
    }
}

if (-not $Quiet -or $failed -gt 0) {
    Write-Host "$deleted deleted, $failed failed, $($found.Count) found" -ForegroundColor Cyan
}

if ($failed -gt 0) { exit 1 }

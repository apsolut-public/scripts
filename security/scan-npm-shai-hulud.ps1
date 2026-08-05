<#
.SYNOPSIS
    Scan a directory tree for Shai-Hulud npm supply-chain indicators of compromise.

.DESCRIPTION
    Standalone and read-only. Download this one file, or copy-paste it into a local
    .ps1 -- it needs nothing else from this repo and installs nothing.

    Six checks:
      1. Malicious payload files by name (SHA-256 printed alongside each hit)
      2. package.json with a preinstall hook that runs a payload
      3. Compromised package versions installed under node_modules (scoped included)
      4. GitHub Actions workflows that dump the whole secrets context
      5. IDE persistence written into .vscode/tasks.json or .claude/settings.json
      6. Exfiltration strings -- fallback domain, campaign marker, wallet address

    A payload filename is reported whether or not its hash matches a known variant.
    A matching hash confirms the exact published sample; a non-matching hash means an
    unknown variant, not a clean file. Triage every hit by hand.

.PARAMETER Path
    Directory to scan. Defaults to the current directory.

.PARAMETER Quiet
    Suppress the per-check "Clear" lines; print findings and the summary only.

.EXAMPLE
    .\scan-npm-shai-hulud.ps1 -Path D:\sites

.EXAMPLE
    .\scan-npm-shai-hulud.ps1; if ($LASTEXITCODE -ne 0) { "compromised" }

.NOTES
    Exit codes: 0 = nothing found, 1 = findings, 2 = bad usage.

    Covers two waves of the same campaign:
      Aug 2026 -- https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack
      Nov 2025 -- earlier Shai-Hulud wave (bun payload filenames)
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $Path = '.',

    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ IoC data
# Everything the scan knows lives here. Update these tables when new indicators
# are published; nothing below needs to change.

# Aug 2026 wave
$payloadFiles = @('setup.mjs', 'math_init.js', 'Math_Symbol.js')
# Nov 2025 wave -- carried forward, not listed in the Aug 2026 writeup
$payloadFiles += @('setup_bun.js', 'bun_environment.js')

$knownHashes = @{
    '54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668' = 'setup.mjs (Aug 2026)'
    'fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb' = 'setup.mjs community variant (Aug 2026)'
    '9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc' = 'Math_Symbol.js / math_init.js (Aug 2026)'
}

$compromised = @{
    'keyv'                  = '6.0.0'
    'flat-cache'            = '6.1.24'
    'file-entry-cache'      = '11.1.6'
    'cacheable-request'     = '13.0.20'
    'cacheable'             = '2.5.1'
    '@cacheable/memory'     = '2.2.1'
    'cache-manager'         = '7.2.10'
    '@cacheable/node-cache' = '3.1.2'
    '@cacheable/utils'      = '2.5.1'
    '@cacheable/net'        = '2.1.1'
    'ecto'                  = '5.0.1'
}

$exfilStrings = @(
    'npm-cache.com',
    'Shai-Hulud: Here We Go Again',
    '0xE1f2395ee43e45A1556EC6438a88c31B83493103'
)

# --------------------------------------------------------------------- setup

try {
    $root = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
}
catch {
    Write-Error "Path not found: $Path"
    exit 2
}

$findings = 0

function Write-Finding {
    param([string] $Message)
    $script:findings++
    Write-Host "  FINDING: $Message" -ForegroundColor Red
}

function Write-Clear {
    param([string] $Message)
    if (-not $Quiet) { Write-Host "  Clear: $Message" -ForegroundColor Green }
}

function Write-Check {
    param([string] $Message)
    if (-not $Quiet) { Write-Host "`n$Message" -ForegroundColor Yellow }
}

Write-Host "Scanning $root for Shai-Hulud IoCs..." -ForegroundColor Cyan

# One enumeration, reused by every check. -Force picks up dotted dirs like .vscode/.claude.
$allFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)

if (-not $Quiet) { Write-Host "  ($($allFiles.Count) files)" -ForegroundColor DarkGray }

# --------------------------------------------------- 1. payload files by name

Write-Check '1. Malicious payload files'
$before = $findings
foreach ($file in $allFiles | Where-Object { $payloadFiles -contains $_.Name }) {
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLower()
    $note = if ($knownHashes.ContainsKey($hash)) { "matches $($knownHashes[$hash])" } else { 'unknown variant -- hash not in the published set' }
    Write-Finding "$($file.FullName)`n           sha256 $hash ($note)"
}
if ($findings -eq $before) { Write-Clear 'no known payload filenames' }

# ------------------------------------------------ 2. preinstall hook in a manifest

Write-Check '2. package.json preinstall hooks running a payload'
$before = $findings
$payloadPattern = ($payloadFiles | ForEach-Object { [regex]::Escape($_) }) -join '|'
foreach ($file in $allFiles | Where-Object { $_.Name -eq 'package.json' }) {
    $hits = Select-String -LiteralPath $file.FullName -Pattern "`"preinstall`"\s*:\s*`".*($payloadPattern)" -ErrorAction SilentlyContinue
    foreach ($hit in $hits) {
        Write-Finding "$($file.FullName) (line $($hit.LineNumber)): $($hit.Line.Trim())"
    }
}
if ($findings -eq $before) { Write-Clear 'no payload preinstall hooks' }

# --------------------------------------- 3. compromised versions in node_modules

Write-Check '3. Compromised package versions under node_modules'
$before = $findings
foreach ($file in $allFiles | Where-Object { $_.Name -eq 'package.json' }) {
    $normalized = $file.FullName -replace '\\', '/'
    $marker = '/node_modules/'
    $idx = $normalized.LastIndexOf($marker)
    if ($idx -lt 0) { continue }

    # Everything after the LAST node_modules/, minus /package.json, is the package
    # key. Handles nesting and @scope/name alike.
    $key = $normalized.Substring($idx + $marker.Length) -replace '/package\.json$', ''
    if (-not $compromised.ContainsKey($key)) { continue }

    try {
        $version = (Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json).version
    }
    catch {
        continue   # unparseable manifest -- not an indicator on its own
    }

    if ($version -eq $compromised[$key]) {
        Write-Finding "$key@$version installed at $($file.DirectoryName)"
    }
}
if ($findings -eq $before) { Write-Clear 'no compromised versions installed' }

# ------------------------------------------------ 4. workflow secret exfiltration

Write-Check '4. GitHub Actions workflows dumping secrets'
$before = $findings
$workflows = $allFiles | Where-Object {
    ($_.Extension -in '.yml', '.yaml') -and (($_.FullName -replace '\\', '/') -match '/\.github/workflows/')
}
foreach ($hit in $workflows | ForEach-Object { Select-String -LiteralPath $_.FullName -Pattern 'toJSON\(\s*secrets\s*\)' -ErrorAction SilentlyContinue }) {
    Write-Finding "$($hit.Path) (line $($hit.LineNumber)): $($hit.Line.Trim())"
}
if ($findings -eq $before) { Write-Clear 'no secrets-context dumps in workflows' }

# ---------------------------------------------------- 5. IDE persistence files

Write-Check '5. IDE persistence (.vscode / .claude)'
$before = $findings
$ideFiles = $allFiles | Where-Object {
    $p = $_.FullName -replace '\\', '/'
    ($p -match '/\.vscode/tasks\.json$') -or ($p -match '/\.claude/settings\.json$')
}
foreach ($file in $ideFiles) {
    $hits = Select-String -LiteralPath $file.FullName -Pattern $payloadPattern -ErrorAction SilentlyContinue
    foreach ($hit in $hits) {
        Write-Finding "$($file.FullName) (line $($hit.LineNumber)): references a payload -- $($hit.Line.Trim())"
    }
}
if ($findings -eq $before) { Write-Clear 'no payload references in IDE config' }

# ------------------------------------------------------- 6. exfiltration strings

Write-Check '6. Exfiltration infrastructure strings'
$before = $findings
$exfilPattern = ($exfilStrings | ForEach-Object { [regex]::Escape($_) }) -join '|'
$textLike = $allFiles | Where-Object { $_.Length -lt 2MB -and $_.Extension -notin '.png', '.jpg', '.jpeg', '.gif', '.zip', '.gz', '.pdf', '.woff', '.woff2', '.ico', '.mp4' }
foreach ($hit in $textLike | ForEach-Object { Select-String -LiteralPath $_.FullName -Pattern $exfilPattern -ErrorAction SilentlyContinue }) {
    Write-Finding "$($hit.Path) (line $($hit.LineNumber)): $($hit.Matches[0].Value)"
}
if ($findings -eq $before) { Write-Clear 'no exfiltration strings' }

# ------------------------------------------------------------------- summary

Write-Host ''
if ($findings -gt 0) {
    Write-Host "$findings finding(s) -- triage every one by hand." -ForegroundColor Red
    Write-Host "Rotate npm/GitHub/cloud tokens before assuming this was a false positive." -ForegroundColor Red
    exit 1
}

Write-Host "No indicators found in $root" -ForegroundColor Green
exit 0

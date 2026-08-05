<#
.SYNOPSIS
    Scan a directory tree for Shai-Hulud npm supply-chain indicators of compromise.

.DESCRIPTION
    Standalone and read-only. Download this one file, or copy-paste it into a local
    script -- it needs nothing else from this repo and installs nothing.

    Six checks:
      1. Malicious payload files by name (SHA-256 printed alongside each hit)
      2. package.json with a preinstall hook that runs a payload
      3. Compromised package versions installed under node_modules (scoped included)
      4. GitHub Actions workflows that dump the whole secrets context
      5. IDE persistence written into .vscode/tasks.json or .claude/settings.json
      6. Exfiltration strings -- fallback domain, campaign marker, wallet address

    Built for speed on trees full of node_modules. It enumerates paths once with
    the native `dir /s /b`, which is orders of magnitude faster than PowerShell's
    Get-ChildItem -Recurse, then narrows by string matching before opening any
    file. Content searches run through `findstr` against a prepared file list, so
    each check is a single native process rather than a per-file pipeline.

    A payload filename is reported whether or not its hash matches a known variant.
    A matching hash confirms the exact published sample; a non-matching hash means an
    unknown variant, not a clean file. Triage every hit by hand.

.PARAMETER Path
    Directory to scan. Defaults to the current directory.

.PARAMETER Quiet
    Suppress the per-check "Clear" lines; print findings and the summary only.

.EXAMPLE
    PS> .\scan-npm-shai-hulud.ps1 -Path D:\sites

.EXAMPLE
    PS> .\scan-npm-shai-hulud.ps1 -Path C:\sites -Quiet
    PS> if ($LASTEXITCODE -ne 0) { "compromised" }

.NOTES
    Exit codes: 0 = nothing found, 1 = findings, 2 = bad usage.

    Covers two waves of the same campaign:
      Aug 2026 -- keyv and friends
      Nov 2025 -- earlier Shai-Hulud wave (bun payload filenames)

    CREDIT
    The Aug 2026 indicators -- affected packages and versions, payload filenames,
    SHA-256 hashes, and exfiltration infrastructure -- were researched and published
    by Aikido Security. This script only automates checking for what they found.
    Thank you.

      https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack
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

# Legitimate files that happen to share a payload name. regenerate-unicode-properties
# is a very common transitive dependency and genuinely ships a Math_Symbol.js full of
# unicode data. Without this, a clean machine reports a handful of scary hits and the
# scan stops being worth reading.
#
# Only applied when the hash does NOT match a known-bad sample -- a real payload
# planted at one of these paths is still reported.
$knownBenign = @(
    @{ Suffix = '/regenerate-unicode-properties/General_Category/Math_Symbol.js'
       Reason = 'regenerate-unicode-properties -- legitimate unicode data table' }
)

# Extensions worth searching for embedded strings. Skips binaries and media,
# which is what keeps check 6 from reading gigabytes of images and archives.
$textExtensions = @('.js', '.mjs', '.cjs', '.ts', '.json', '.yml', '.yaml', '.txt',
                    '.md', '.sh', '.ps1', '.bat', '.cmd', '.env', '.lock', '.map')

# --------------------------------------------------------------------- setup

try {
    $root = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath.TrimEnd('\')
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

# findstr recurses natively with /s and prints just the matching filenames with
# /m. One native process per check beats opening every candidate from PowerShell.
# Never name the splat variable $args -- that is an automatic variable, and
# splatting it inside a function passes the wrong values.
function Find-InTree {
    param([string] $Root, [string[]] $FileSpecs, [string[]] $Literals)
    $fsArgs = @('/s', '/m', '/i') + ($Literals | ForEach-Object { '/c:' + $_ })
    $fsArgs += ($FileSpecs | ForEach-Object { Join-Path $Root $_ })
    $matched = & findstr.exe @fsArgs 2>$null
    if ($null -eq $matched) { return @() }
    return @($matched | Where-Object { $_ -match '\S' })
}

Write-Host "Scanning $root for Shai-Hulud IoCs..." -ForegroundColor Cyan

# ---------------------------------------------------------- one enumeration
# `dir /s /b /a-d` walks the tree in native code and prints one full path per
# line. On a projects root full of node_modules this finishes in seconds where
# Get-ChildItem -Recurse can take hours.

if (-not $Quiet) { Write-Host "  Enumerating paths..." -NoNewline -ForegroundColor DarkGray }
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$allPaths = @(& cmd.exe /c "dir /s /b /a-d `"$root`" 2>nul")
$allPaths = @($allPaths | Where-Object { $_ -match '\S' })

$sw.Stop()
if (-not $Quiet) {
    Write-Host " $($allPaths.Count) files in $([math]::Round($sw.Elapsed.TotalSeconds,1))s" -ForegroundColor DarkGray
}

if ($allPaths.Count -eq 0) {
    Write-Host "No files found under $root -- is the path right?" -ForegroundColor Yellow
    exit 2
}

# Precompute leaf names once; every check below filters on strings, not on disk.
$leaf = @{}
foreach ($p in $allPaths) { $leaf[$p] = [System.IO.Path]::GetFileName($p) }

# --------------------------------------------------- 1. payload files by name

Write-Check '1. Malicious payload files'
$before = $findings
$benign = 0
foreach ($p in $allPaths) {
    if ($payloadFiles -notcontains $leaf[$p]) { continue }
    $hash = try { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() } catch { 'unavailable' }

    if (-not $knownHashes.ContainsKey($hash)) {
        $normalized = $p -replace '\\', '/'
        $match = @($knownBenign | Where-Object { $normalized.EndsWith($_.Suffix) })
        if ($match.Count -gt 0) {
            $benign++
            if (-not $Quiet) { Write-Host "  ignored: $p ($($match[0].Reason))" -ForegroundColor DarkGray }
            continue
        }
    }

    $note = if ($knownHashes.ContainsKey($hash)) { "matches $($knownHashes[$hash])" } else { 'unknown variant -- hash not in the published set' }
    Write-Finding "$p`n           sha256 $hash ($note)"
}
if ($findings -eq $before) {
    $suffix = if ($benign -gt 0) { " ($benign known-benign file(s) ignored)" } else { '' }
    Write-Clear "no known payload filenames$suffix"
}

# ------------------------------------------------ 2. preinstall hook in a manifest

Write-Check '2. package.json preinstall hooks running a payload'
$before = $findings
$manifests = @($allPaths | Where-Object { $leaf[$_] -eq 'package.json' })
$payloadPattern = ($payloadFiles | ForEach-Object { [regex]::Escape($_) }) -join '|'

# Narrow to manifests mentioning a payload at all, then read only those.
$candidates = Find-InTree -Root $root -FileSpecs @('package.json') -Literals $payloadFiles
foreach ($file in $candidates) {
    $hits = Select-String -LiteralPath $file -Pattern "`"preinstall`"\s*:\s*`".*($payloadPattern)" -ErrorAction SilentlyContinue
    foreach ($hit in $hits) {
        Write-Finding "$file (line $($hit.LineNumber)): $($hit.Line.Trim())"
    }
}
if ($findings -eq $before) { Write-Clear "no payload preinstall hooks ($($manifests.Count) manifests)" }

# --------------------------------------- 3. compromised versions in node_modules

Write-Check '3. Compromised package versions under node_modules'
$before = $findings
$checked = 0
foreach ($p in $manifests) {
    $normalized = $p -replace '\\', '/'
    $idx = $normalized.LastIndexOf('/node_modules/')
    if ($idx -lt 0) { continue }

    # Everything after the LAST node_modules/, minus /package.json, is the package
    # key. Handles nesting and @scope/name alike.
    $key = $normalized.Substring($idx + 14) -replace '/package\.json$', ''
    if (-not $compromised.ContainsKey($key)) { continue }

    $checked++
    try {
        $version = (Get-Content -LiteralPath $p -Raw -ErrorAction Stop | ConvertFrom-Json).version
    }
    catch {
        continue   # unparseable manifest -- not an indicator on its own
    }

    if ($version -eq $compromised[$key]) {
        Write-Finding "$key@$version installed at $([System.IO.Path]::GetDirectoryName($p))"
    }
}
if ($findings -eq $before) { Write-Clear "no compromised versions installed ($checked matching packages inspected)" }

# ------------------------------------------------ 4. workflow secret exfiltration

Write-Check '4. GitHub Actions workflows dumping secrets'
$before = $findings
$workflows = @($allPaths | Where-Object {
    ($_ -like '*.yml' -or $_ -like '*.yaml') -and ($_ -replace '\\', '/') -match '/\.github/workflows/'
})
# Workflow files are few even in a big tree, so read them directly.
foreach ($file in $workflows) {
    foreach ($hit in (Select-String -LiteralPath $file -Pattern 'toJSON\(\s*secrets\s*\)' -ErrorAction SilentlyContinue)) {
        Write-Finding "$file (line $($hit.LineNumber)): $($hit.Line.Trim())"
    }
}
if ($findings -eq $before) { Write-Clear "no secrets-context dumps in workflows ($($workflows.Count) workflow files)" }

# ---------------------------------------------------- 5. IDE persistence files

Write-Check '5. IDE persistence (.vscode / .claude)'
$before = $findings
$ideFiles = @($allPaths | Where-Object {
    $n = ($_ -replace '\\', '/')
    ($n -match '/\.vscode/tasks\.json$') -or ($n -match '/\.claude/settings\.json$')
})
# Also few in number -- one .vscode/.claude pair per project at most.
foreach ($file in $ideFiles) {
    foreach ($hit in (Select-String -LiteralPath $file -Pattern $payloadPattern -ErrorAction SilentlyContinue)) {
        Write-Finding "$file (line $($hit.LineNumber)): references a payload -- $($hit.Line.Trim())"
    }
}
if ($findings -eq $before) { Write-Clear "no payload references in IDE config ($($ideFiles.Count) config files)" }

# ------------------------------------------------------- 6. exfiltration strings

Write-Check '6. Exfiltration infrastructure strings'
$before = $findings
$textFiles = @($allPaths | Where-Object { $textExtensions -contains [System.IO.Path]::GetExtension($_).ToLower() })
$exfilPattern = ($exfilStrings | ForEach-Object { [regex]::Escape($_) }) -join '|'
$specs = $textExtensions | ForEach-Object { '*' + $_ }
# This script carries the indicator strings itself, so it would flag its own copy.
$self = if ($PSCommandPath) { $PSCommandPath } else { '' }
foreach ($file in (Find-InTree -Root $root -FileSpecs $specs -Literals $exfilStrings)) {
    if ($self -and ($file -ieq $self)) { continue }
    foreach ($hit in (Select-String -LiteralPath $file -Pattern $exfilPattern -ErrorAction SilentlyContinue)) {
        Write-Finding "$file (line $($hit.LineNumber)): $($hit.Matches[0].Value)"
    }
}
if ($findings -eq $before) { Write-Clear "no exfiltration strings ($($textFiles.Count) text files searched)" }

# ------------------------------------------------------------------- summary

Write-Host ''
if ($findings -gt 0) {
    Write-Host "$findings finding(s) -- triage every one by hand." -ForegroundColor Red
    Write-Host "Rotate npm/GitHub/cloud tokens before assuming this was a false positive." -ForegroundColor Red
    exit 1
}

Write-Host "No indicators found in $root" -ForegroundColor Green
exit 0

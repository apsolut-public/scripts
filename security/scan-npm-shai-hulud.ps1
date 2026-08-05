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

    Built for trees with hundreds of node_modules. Nothing here ever enumerates
    the whole tree: each check runs one targeted native search (`dir /s /b` for
    a specific filename, `findstr /s` for content) and only the handful of
    matching paths ever cross into PowerShell. Listing every file and filtering
    it in a pipeline is what makes naive versions of this scan run for hours.

    A payload filename is reported whether or not its hash matches a known variant.
    A matching hash confirms the exact published sample; a non-matching hash means an
    unknown variant, not a clean file. Triage every hit by hand.

.PARAMETER Path
    Directory to scan. Defaults to the current directory.

.PARAMETER Quiet
    Suppress the per-check "Clear" lines; print findings and the summary only.

.PARAMETER Deep
    Include node_modules in check 6's content sweep. Off by default: on a tree with
    millions of vendored files that sweep dominates the runtime, while checks 1-3
    already cover malicious packages by filename and by version. Turn it on when you
    want the exhaustive pass and can wait.

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

    [switch] $Quiet,

    [switch] $Deep
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

# Extensions worth searching for embedded strings. Skips binaries and media,
# which is what keeps check 6 from reading gigabytes of images and archives.
$textExtensions = @('.js', '.mjs', '.cjs', '.ts', '.json', '.yml', '.yaml', '.txt',
                    '.md', '.sh', '.ps1', '.bat', '.cmd', '.env', '.lock', '.map')

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

# --------------------------------------------------------------------- setup

try {
    $root = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath.TrimEnd('\')
}
catch {
    Write-Error "Path not found: $Path"
    exit 2
}

$findings = 0
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

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
    if (-not $Quiet) {
        Write-Host "`n$Message" -NoNewline -ForegroundColor Yellow
        Write-Host "  [$([math]::Round($script:stopwatch.Elapsed.TotalSeconds,1))s]" -ForegroundColor DarkGray
    }
}

# Traversing the tree is the single dominant cost -- roughly 5.6 minutes for 7.5M
# files -- so do it exactly ONCE, with cmd redirecting straight to disk. Nothing
# is ever piped into PowerShell here; a 7.5M-element array plus a hashtable keyed
# on every path is what made earlier versions run out of memory and hang.
#
# Every check below is then a sequential findstr over that one list file, which
# costs seconds rather than another full walk of the disk.
# Invoke findstr.exe directly with an argument array rather than building a
# `cmd /c` string: a pattern ending in a backslash (\.github\workflows\) would
# escape the closing quote inside a cmd string and silently match nothing.
function Select-Paths {
    param([string] $ListFile, [string[]] $Patterns, [switch] $EndsWith, [switch] $Exclude)
    $fsArgs = @('/i')
    if ($EndsWith) { $fsArgs += '/e' }
    if ($Exclude)  { $fsArgs += '/v' }
    $fsArgs += ($Patterns | ForEach-Object { '/c:' + $_ })
    $fsArgs += $ListFile
    $out = & findstr.exe @fsArgs 2>$null
    if ($null -eq $out) { return @() }
    return @($out | Where-Object { $_ })
}

# Content search over a narrowed set of files.
#
# Deliberately NOT using findstr's /f: list-file option: with long absolute paths
# it silently matches nothing while the identical files passed as arguments match
# fine. A search tool that quietly finds nothing is the worst possible failure
# here, so files go in as arguments, batched to stay under the command-line limit.
function Search-Content {
    param([string[]] $Files, [string[]] $Literals)
    if ($Files.Count -eq 0) { return @() }

    $patternArgs = @('/m', '/i') + ($Literals | ForEach-Object { '/c:' + $_ })
    $matched = New-Object System.Collections.Generic.List[string]

    $batch = New-Object System.Collections.Generic.List[string]
    $length = 0
    foreach ($file in $Files) {
        $batch.Add($file)
        $length += $file.Length + 3
        if ($length -gt 24000) {
            $out = & findstr.exe @patternArgs @($batch.ToArray()) 2>$null
            foreach ($o in $out) { if ($o) { $matched.Add($o) } }
            $batch.Clear(); $length = 0
        }
    }
    if ($batch.Count -gt 0) {
        $out = & findstr.exe @patternArgs @($batch.ToArray()) 2>$null
        foreach ($o in $out) { if ($o) { $matched.Add($o) } }
    }

    return @($matched)
}

Write-Host "Scanning $root for Shai-Hulud IoCs..." -ForegroundColor Cyan

# ------------------------------------------------------- single tree traversal

$workspace = Join-Path ([System.IO.Path]::GetTempPath()) ('shai-hulud-' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($workspace)
$listFile = Join-Path $workspace 'all-paths.txt'

if (-not $Quiet) {
    Write-Host "  Listing the tree once (the slow part -- minutes on a large disk)..." -NoNewline -ForegroundColor DarkGray
}
& cmd.exe /c "dir /s /b /a-d `"$root`" > `"$listFile`" 2>nul" | Out-Null

$fileCount = 0
if (Test-Path -LiteralPath $listFile) {
    # Count without loading the file into memory.
    $reader = [System.IO.File]::OpenText($listFile)
    try { while ($null -ne $reader.ReadLine()) { $fileCount++ } } finally { $reader.Dispose() }
}
if (-not $Quiet) {
    Write-Host " $fileCount files, $([math]::Round($stopwatch.Elapsed.TotalSeconds,1))s" -ForegroundColor DarkGray
}

if ($fileCount -eq 0) {
    Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "No files found under $root -- is the path right?" -ForegroundColor Yellow
    exit 2
}

# Every list below comes from one sequential pass over that file, never the disk.
$nameSuffixes = @($payloadFiles | ForEach-Object { '\' + $_ }) + @('\tasks.json', '\settings.json')
$namedPaths   = @(Select-Paths -ListFile $listFile -Patterns $nameSuffixes -EndsWith)
$manifests    = @(Select-Paths -ListFile $listFile -Patterns @('\package.json') -EndsWith)
$workflowYaml = @(Select-Paths -ListFile $listFile -Patterns @('\.github\workflows\') |
                  Where-Object { $_ -like '*.yml' -or $_ -like '*.yaml' })

# Compromised packages are found by deriving each manifest's package key in
# PowerShell rather than by findstr pattern: a scoped name like @cacheable/memory
# contains an "@", and findstr silently matches nothing on a /c: pattern
# containing one. String work over the manifest list is cheap and exact.
$compromisedManifests = @($manifests | Where-Object {
    $n = $_ -replace '\\', '/'
    $i = $n.LastIndexOf('/node_modules/')
    ($i -ge 0) -and $compromised.ContainsKey(($n.Substring($i + 14) -replace '/package\.json$', ''))
})

# --------------------------------------------------- 1. payload files by name

Write-Check '1. Malicious payload files'
$before = $findings
$benign = 0
foreach ($p in ($namedPaths | Where-Object { $payloadFiles -contains [System.IO.Path]::GetFileName($_) })) {
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
$payloadPattern = ($payloadFiles | ForEach-Object { [regex]::Escape($_) }) -join '|'
# findstr narrows to the few manifests mentioning a payload; only those are opened.
foreach ($file in (Search-Content -Files $manifests -Literals $payloadFiles)) {
    foreach ($hit in (Select-String -LiteralPath $file -Pattern "`"preinstall`"\s*:\s*`".*($payloadPattern)" -ErrorAction SilentlyContinue)) {
        Write-Finding "$file (line $($hit.LineNumber)): $($hit.Line.Trim())"
    }
}
if ($findings -eq $before) { Write-Clear 'no payload preinstall hooks' }

# --------------------------------------- 3. compromised versions in node_modules

Write-Check '3. Compromised package versions under node_modules'
$before = $findings
foreach ($manifest in $compromisedManifests) {
    $normalized = $manifest -replace '\\', '/'
    $idx = $normalized.LastIndexOf('/node_modules/')
    if ($idx -lt 0) { continue }
    $key = $normalized.Substring($idx + 14) -replace '/package\.json$', ''
    if (-not $compromised.ContainsKey($key)) { continue }

    try {
        $version = (Get-Content -LiteralPath $manifest -Raw -ErrorAction Stop | ConvertFrom-Json).version
    }
    catch { continue }   # unparseable manifest -- not an indicator on its own

    if ($version -eq $compromised[$key]) {
        Write-Finding "$key@$version installed at $([System.IO.Path]::GetDirectoryName($manifest))"
    }
}
if ($findings -eq $before) {
    Write-Clear "no compromised versions installed ($($compromisedManifests.Count) of the 11 watched packages present, $($manifests.Count) manifests total)"
}

# ------------------------------------------------ 4. workflow secret exfiltration

Write-Check '4. GitHub Actions workflows dumping secrets'
$before = $findings
foreach ($file in (Search-Content -Files $workflowYaml -Literals @('toJSON'))) {
    foreach ($hit in (Select-String -LiteralPath $file -Pattern 'toJSON\(\s*secrets\s*\)' -ErrorAction SilentlyContinue)) {
        Write-Finding "$file (line $($hit.LineNumber)): $($hit.Line.Trim())"
    }
}
if ($findings -eq $before) { Write-Clear "no secrets-context dumps in workflows ($($workflowYaml.Count) workflow files)" }

# ---------------------------------------------------- 5. IDE persistence files

Write-Check '5. IDE persistence (.vscode / .claude)'
$before = $findings
$ideFiles = @($namedPaths | Where-Object {
    $n = $_ -replace '\\', '/'
    ($n -match '/\.vscode/tasks\.json$') -or ($n -match '/\.claude/settings\.json$')
})
foreach ($file in $ideFiles) {
    foreach ($hit in (Select-String -LiteralPath $file -Pattern $payloadPattern -ErrorAction SilentlyContinue)) {
        Write-Finding "$file (line $($hit.LineNumber)): references a payload -- $($hit.Line.Trim())"
    }
}
if ($findings -eq $before) { Write-Clear "no payload references in IDE config ($($ideFiles.Count) config files)" }

# ------------------------------------------------------- 6. exfiltration strings

Write-Check '6. Exfiltration infrastructure strings'
$before = $findings
$exfilPattern = ($exfilStrings | ForEach-Object { [regex]::Escape($_) }) -join '|'
$textFiles = @(Select-Paths -ListFile $listFile -Patterns ($textExtensions) -EndsWith)
$scopeNote = 'whole tree'
if (-not $Deep) {
    # On a tree with millions of vendored files this sweep dominates everything
    # else, and checks 1-3 already cover malicious packages by name and version.
    # Excluded rather than silently truncated -- the count is always reported.
    $vendored = $textFiles.Count
    $textFiles = @($textFiles | Where-Object { $_ -notlike '*\node_modules\*' })
    $scopeNote = "excluding node_modules; $($vendored - $textFiles.Count) vendored files skipped, use -Deep to include them"
}
# This script carries the indicator strings itself, so it would flag its own copy.
$self = if ($PSCommandPath) { $PSCommandPath } else { '' }
foreach ($file in (Search-Content -Files $textFiles -Literals $exfilStrings)) {
    if ($self -and ($file -ieq $self)) { continue }
    foreach ($hit in (Select-String -LiteralPath $file -Pattern $exfilPattern -ErrorAction SilentlyContinue)) {
        Write-Finding "$file (line $($hit.LineNumber)): $($hit.Matches[0].Value)"
    }
}
if ($findings -eq $before) { Write-Clear "no exfiltration strings ($($textFiles.Count) files searched, $scopeNote)" }

# ------------------------------------------------------------------- summary

$stopwatch.Stop()
Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($findings -gt 0) {
    Write-Host "$findings finding(s) in $([math]::Round($stopwatch.Elapsed.TotalSeconds,1))s -- triage every one by hand." -ForegroundColor Red
    Write-Host "Rotate npm/GitHub/cloud tokens before assuming this was a false positive." -ForegroundColor Red
    exit 1
}

Write-Host "No indicators found in $root ($([math]::Round($stopwatch.Elapsed.TotalSeconds,1))s)" -ForegroundColor Green
exit 0

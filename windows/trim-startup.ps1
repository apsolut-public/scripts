<#
.SYNOPSIS
    Find what slows Windows boot and sign-in, and defer the startup junk -- reversibly.

.DESCRIPTION
    Slow boots on fast SSDs are almost always software, not hardware. Windows already
    measures every boot and names the processes that delayed it (the
    Diagnostics-Performance event log), but nothing surfaces it. -List does.

    The usual culprits, in rough order of damage:

      * Two antivirus engines at once -- a third-party AV that's installed but expired or
        switched off still loads its drivers, while Defender runs full real-time scanning
        alongside it. -List flags this. Fix it by reactivating or uninstalling the
        third-party AV; this script deliberately never touches security software.
      * Scheduled tasks with a logon trigger. Task Manager's Startup tab doesn't show
        them, so an app you "disabled" there (OneDrive is the classic) keeps launching.
      * Vendor services set to Automatic that only matter when their app is open.
      * Updaters that also hook the Run key at sign-in on top of their own schedule.

    Applying makes three kinds of change, all reversible:

      * Services matching the data block go Automatic -> Manual. They still start when
        an app asks for them; they just stop costing boot time.
      * Matching scheduled tasks are disabled, not deleted.
      * Matching Run / Startup-folder entries are disabled exactly the way Task Manager
        does it (StartupApproved), so they show as "Disabled" there and can be
        re-enabled from the Startup tab.

    Before changing anything the original value of every item is written to
      %LOCALAPPDATA%\trim-startup\state.json
    and -Restore puts those values back. Items already recorded are never re-recorded,
    so the file always holds the true originals however many times you run it. Items
    already Manual / disabled are skipped -- running twice changes nothing.

    The defaults are only patterns for common, non-essential startup items. Run -List,
    then add your own with -Service / -Task / -RunEntry, or edit the data block.

.PARAMETER List
    Read-only report: recent boot times, the processes Windows blamed for slowing them,
    antivirus status, and every enabled startup entry, logon task and non-Microsoft
    automatic service -- marked where the defaults would act. Boot data needs an
    elevated shell; the rest works without.

.PARAMETER Service
    Extra service names to set to Manual. Wildcards allowed.

.PARAMETER Task
    Extra scheduled tasks to disable, as '\Path\Name'. Wildcards allowed.

.PARAMETER RunEntry
    Extra Run-key or Startup-folder entry names to disable. Wildcards allowed.

.PARAMETER NoDefaults
    Ignore the built-in patterns; act only on -Service / -Task / -RunEntry.

.PARAMETER Restore
    Put back every item recorded in state.json, then archive the file.

.EXAMPLE
    .\trim-startup.ps1 -List
    See boot times, what delayed them, and what starts with Windows.

.EXAMPLE
    .\trim-startup.ps1 -WhatIf
    Show what the defaults would change, change nothing.

.EXAMPLE
    .\trim-startup.ps1 -Service 'MaonoAiServices' -RunEntry 'Hedy','Spotify'
    Defaults plus your own picks. Run from an elevated shell.

.EXAMPLE
    .\trim-startup.ps1 -Restore
    Undo everything.

.NOTES
    Needs an elevated shell to change services, tasks and HKLM entries; without one
    those are skipped with a warning and only per-user entries change.
    Changes take effect on the next boot. Measure with Restart, not Shut down: with
    Fast Startup on, Shut down skips the full boot that Windows times.
    Exit 0 on success, 1 if anything failed, 2 on bad usage.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]   $List,
    [string[]] $Service  = @(),
    [string[]] $Task     = @(),
    [string[]] $RunEntry = @(),
    [switch]   $NoDefaults,
    [switch]   $Restore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# DATA -- patterns for items that are safe to defer. Wildcards allowed.
# Only items currently Automatic / enabled are touched. Security software is never listed.
# ============================================================================

$DefaultServices = @(
    'UIFlow*'                       # Power Automate for desktop (4 services)
    'Wondershare*'                  # Wondershare install helpers
    'ss_conn_service*'              # Samsung phone connectivity
    'SamsungMagicianSVC'            # Samsung Magician SSD tool
    'com.docker.service'            # Docker Desktop (Desktop starts it when launched)
    'PCManager*'                    # Microsoft PC Manager
    'OptionsPlusUpdaterService'     # Logi Options+ updater
    'AdobeUpdateService'            # Adobe updater
    'TeraCopyService'               # TeraCopy
)

$DefaultTasks = @(
    '\OneDrive Startup Task-*'      # relaunches OneDrive even when disabled in Task Manager
    '\nWizard_*'                    # NVIDIA nView wizard
    '\Adobe Creative Cloud'
    '\SamsungMagician'
    '\Opera scheduled assistant Autoupdate*'
)

$DefaultRunEntries = @(
    '*UpdaterTaskUser*'             # Google / Comet / Brave updaters -- they also run on a schedule
    'Microsoft Edge Update'
    'Opera Browser Assistant'
    'Logi Download Assistant'
)

# ============================================================================

$StateDir  = Join-Path $env:LOCALAPPDATA 'trim-startup'
$StateFile = Join-Path $StateDir 'state.json'

if ($List -and $Restore) { [Console]::Error.WriteLine('Use -List or -Restore, not both.'); exit 2 }

$svcPatterns  = @($Service)  + $(if ($NoDefaults) { @() } else { $DefaultServices })
$taskPatterns = @($Task)     + $(if ($NoDefaults) { @() } else { $DefaultTasks })
$runPatterns  = @($RunEntry) + $(if ($NoDefaults) { @() } else { $DefaultRunEntries })

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Test-Match([string] $Value, [string[]] $Patterns) {
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
    return $false
}

# Run-key locations and the StartupApproved key Task Manager uses for each.
$RunSources = @(
    @{ Run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';             Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    @{ Run = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run';             Approved = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    @{ Run = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' }
    @{ Folder = [Environment]::GetFolderPath('Startup');       Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
    @{ Folder = [Environment]::GetFolderPath('CommonStartup'); Approved = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
)

function Get-ApprovedBytes([string] $Key, [string] $Name) {
    $item = Get-Item -LiteralPath $Key -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    $v = $item.GetValue($Name, $null)
    if ($v -is [byte[]]) { return $v }
    return $null
}

# Every startup entry: Name, Command, Approved key, Enabled. Odd first byte = disabled.
function Get-StartupEntries {
    foreach ($src in $RunSources) {
        $names = @()
        if ($src.ContainsKey('Run')) {
            $k = Get-Item -LiteralPath $src.Run -ErrorAction SilentlyContinue
            if ($k) { $names = foreach ($n in $k.GetValueNames()) { if ($n) { @{ Name = $n; Command = [string]$k.GetValue($n) } } } }
        }
        else {
            if ($src.Folder -and (Test-Path -LiteralPath $src.Folder)) {
                $names = foreach ($f in Get-ChildItem -LiteralPath $src.Folder -File -Force | Where-Object Name -ne 'desktop.ini') { @{ Name = $f.Name; Command = $f.FullName } }
            }
        }
        foreach ($n in $names) {
            $b = Get-ApprovedBytes $src.Approved $n.Name
            [pscustomobject]@{
                Name     = $n.Name
                Command  = $n.Command
                Approved = $src.Approved
                Enabled  = -not ($b -and ($b[0] -band 1))
            }
        }
    }
}

function Get-LogonTasks {
    foreach ($t in Get-ScheduledTask) {
        # State can read 'Running' on a disabled task that is still open; Settings.Enabled is the truth.
        if ($t.TaskPath -like '\Microsoft\*' -or -not $t.Settings.Enabled) { continue }
        $hit = $false
        foreach ($tr in @($t.Triggers)) { if ($tr -and $tr.CimClass.CimClassName -match 'Logon|Boot') { $hit = $true } }
        if ($hit) { $t }
    }
}

function Get-ThirdPartyAutoServices {
    Get-CimInstance Win32_Service -Filter "StartMode='Auto'" |
        Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\|\\Windows Defender\\' }
}

function Read-State {
    if (Test-Path -LiteralPath $StateFile) { return @(Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json) }
    return @()
}
function Save-State($Items) {
    if ($WhatIfPreference) { return }
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    ConvertTo-Json -InputObject @($Items) -Depth 4 | Out-File -LiteralPath $StateFile -Encoding utf8
}

# ---------------------------------------------------------------------------- -List
if ($List) {
    $admin = Test-Admin

    Write-Host "`n== Recent boots" -ForegroundColor Cyan
    if (-not $admin) { Write-Host '   (needs an elevated shell)' -ForegroundColor DarkGray }
    else {
        $log = 'Microsoft-Windows-Diagnostics-Performance/Operational'
        $boots = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 100 } -MaxEvents 8 -ErrorAction SilentlyContinue)
        if (-not $boots) { Write-Host '   no boot events recorded' -ForegroundColor DarkGray }
        foreach ($e in $boots) {
            $d = @{}; foreach ($x in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
            Write-Host ('   {0:yyyy-MM-dd HH:mm}  total {1,6:N1}s   to desktop {2,6:N1}s   after desktop {3,6:N1}s' -f
                $e.TimeCreated, ($d.BootTime / 1000), ($d.MainPathBootTime / 1000), ($d.BootPostBootTime / 1000))
        }

        Write-Host "`n== What Windows blamed for slowing them (avg delay)" -ForegroundColor Cyan
        $deg = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 101, 102, 103, 106, 109 } -MaxEvents 200 -ErrorAction SilentlyContinue)
        $deg | ForEach-Object {
            $d = @{}; foreach ($x in ([xml]$_.ToXml()).Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
            $name = @($d['FriendlyName'], $d['Name'], $d['FileName']) | Where-Object { $_ } | Select-Object -First 1
            [pscustomobject]@{ Name = $name; Delay = [int]$d['DegradationTime'] }
        } | Group-Object Name | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Hits = $_.Count; AvgSec = [math]::Round((($_.Group | Measure-Object Delay -Average).Average) / 1000, 1) }
        } | Sort-Object AvgSec -Descending | Select-Object -First 15 | Format-Table -AutoSize | Out-String | Write-Host
    }

    Write-Host '== Antivirus' -ForegroundColor Cyan
    $mode = try { (Get-MpComputerStatus -ErrorAction Stop).AMRunningMode } catch { 'unknown' }
    $third = @()
    foreach ($av in @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue)) {
        $on = ((([int]$av.productState) -shr 12) -band 0xF) -eq 1
        Write-Host ('   {0,-30} {1}' -f $av.displayName, $(if ($on) { 'active' } else { 'installed, NOT active' }))
        if ($av.displayName -notmatch 'Defender') { $third += [pscustomobject]@{ Name = $av.displayName; On = $on } }
    }
    Write-Host "   Defender mode: $mode"
    foreach ($t in $third) {
        if (-not $t.On -and $mode -eq 'Normal') {
            Write-Host "   !! $($t.Name) is installed but inactive while Defender runs full scanning -- its drivers" -ForegroundColor Yellow
            Write-Host '      still load at boot. Reactivate it (Defender goes passive) or uninstall it.' -ForegroundColor Yellow
        }
    }

    Write-Host "`n== Enabled startup entries   (* = defaults/arguments would disable)" -ForegroundColor Cyan
    Get-StartupEntries | Where-Object Enabled | ForEach-Object {
        Write-Host ('  {0} {1,-40} {2}' -f $(if (Test-Match $_.Name $runPatterns) { '*' } else { ' ' }), $_.Name, ($_.Command -replace '^(.{90}).+', '$1...'))
    }

    Write-Host "`n== Enabled non-Microsoft logon/boot tasks (Task Manager doesn't show these)" -ForegroundColor Cyan
    foreach ($t in Get-LogonTasks) {
        $id = "$($t.TaskPath)$($t.TaskName)"
        Write-Host ('  {0} {1}' -f $(if (Test-Match $id $taskPatterns) { '*' } else { ' ' }), $id)
    }

    Write-Host "`n== Non-Microsoft services set to Automatic" -ForegroundColor Cyan
    foreach ($s in Get-ThirdPartyAutoServices | Sort-Object Name) {
        Write-Host ('  {0} {1,-40} {2}' -f $(if (Test-Match $s.Name $svcPatterns) { '*' } else { ' ' }), $s.Name, $s.DisplayName)
    }
    Write-Host ''
    exit 0
}

$failed = 0; $changed = 0; $skipped = 0
$admin = Test-Admin

# ---------------------------------------------------------------------------- -Restore
if ($Restore) {
    $state = Read-State
    if (-not $state) { Write-Host "Nothing to restore ($StateFile not found)." -ForegroundColor Green; exit 0 }
    foreach ($s in $state) {
        if ($s.Kind -ne 'run' -and -not $admin) { Write-Warning "Needs admin: $($s.Kind) $($s.Id)"; $failed++; continue }
        if ($s.Approved -like 'HKLM:*' -and -not $admin) { Write-Warning "Needs admin: run $($s.Id)"; $failed++; continue }
        if (-not $PSCmdlet.ShouldProcess("$($s.Kind) $($s.Id)", 'Restore')) { continue }
        try {
            switch ($s.Kind) {
                'service' {
                    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Id)"
                    if (Test-Path -LiteralPath $k) {
                        Set-ItemProperty -LiteralPath $k -Name Start -Value ([int]$s.Start) -Type DWord
                        Set-ItemProperty -LiteralPath $k -Name DelayedAutostart -Value ([int]$s.Delayed) -Type DWord
                    }
                }
                'task' { Enable-ScheduledTask -TaskPath $s.Path -TaskName $s.Name | Out-Null }
                'run' {
                    if ($s.Original) { New-ItemProperty -LiteralPath $s.Approved -Name $s.Id -Value ([Convert]::FromBase64String($s.Original)) -PropertyType Binary -Force | Out-Null }
                    else { Remove-ItemProperty -LiteralPath $s.Approved -Name $s.Id -ErrorAction SilentlyContinue }
                }
            }
            Write-Host "restored $($s.Kind) $($s.Id)" -ForegroundColor Yellow; $changed++
        }
        catch { Write-Warning "Could not restore $($s.Kind) $($s.Id): $_"; $failed++ }
    }
    if ($failed -eq 0 -and -not $WhatIfPreference) {
        Move-Item -LiteralPath $StateFile -Destination "$StateFile.restored-$(Get-Date -Format yyyyMMdd-HHmmss)"
    }
    Write-Host "$changed restored, $failed failed. Reboot to apply." -ForegroundColor Cyan
    if ($failed -gt 0) { exit 1 }
    exit 0
}

# ---------------------------------------------------------------------------- apply
$state = [Collections.Generic.List[object]]::new()
foreach ($s in Read-State) { $state.Add($s) }
function Test-Recorded([string] $Kind, [string] $Id) { [bool]($state | Where-Object { $_.Kind -eq $Kind -and $_.Id -eq $Id }) }
$needAdmin = 0

# services
foreach ($s in Get-ThirdPartyAutoServices) {
    if (-not (Test-Match $s.Name $svcPatterns)) { continue }
    if (-not $admin -and -not $WhatIfPreference) { $needAdmin++; continue }
    if (-not $PSCmdlet.ShouldProcess("$($s.Name) ($($s.DisplayName))", 'Set service to Manual')) { continue }
    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)"
    try {
        $p = Get-Item -LiteralPath $k
        if (-not (Test-Recorded 'service' $s.Name)) {
            $state.Add([pscustomobject]@{ Kind = 'service'; Id = $s.Name; Start = [int]$p.GetValue('Start'); Delayed = [int]$p.GetValue('DelayedAutostart', 0) })
            Save-State $state
        }
        Set-ItemProperty -LiteralPath $k -Name Start -Value 3 -Type DWord
        Write-Host "manual   service $($s.Name)" -ForegroundColor Yellow; $changed++
    }
    catch { Write-Warning "Could not change service $($s.Name): $_"; $failed++ }
}

# tasks (only enabled ones are returned)
foreach ($t in Get-LogonTasks) {
    $id = "$($t.TaskPath)$($t.TaskName)"
    if (-not (Test-Match $id $taskPatterns)) { continue }
    if (-not $admin -and -not $WhatIfPreference) { $needAdmin++; continue }
    if (-not $PSCmdlet.ShouldProcess($id, 'Disable scheduled task')) { continue }
    try {
        if (-not (Test-Recorded 'task' $id)) {
            $state.Add([pscustomobject]@{ Kind = 'task'; Id = $id; Path = $t.TaskPath; Name = $t.TaskName })
            Save-State $state
        }
        Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName | Out-Null
        Write-Host "disabled task    $id" -ForegroundColor Yellow; $changed++
    }
    catch { Write-Warning "Could not disable task ${id}: $_"; $failed++ }
}

# run / startup-folder entries
foreach ($e in Get-StartupEntries) {
    if (-not (Test-Match $e.Name $runPatterns)) { continue }
    if (-not $e.Enabled) { $skipped++; continue }
    if ($e.Approved -like 'HKLM:*' -and -not $admin -and -not $WhatIfPreference) { $needAdmin++; continue }
    if (-not $PSCmdlet.ShouldProcess($e.Name, 'Disable startup entry')) { continue }
    try {
        $orig = Get-ApprovedBytes $e.Approved $e.Name
        if (-not (Test-Recorded 'run' $e.Name)) {
            $state.Add([pscustomobject]@{ Kind = 'run'; Id = $e.Name; Approved = $e.Approved; Original = $(if ($orig) { [Convert]::ToBase64String($orig) } else { $null }) })
            Save-State $state
        }
        if (-not (Test-Path -LiteralPath $e.Approved)) { New-Item -Path $e.Approved -Force | Out-Null }
        $bytes = [byte[]](@(3, 0, 0, 0) + [BitConverter]::GetBytes([DateTime]::Now.ToFileTime()))
        New-ItemProperty -LiteralPath $e.Approved -Name $e.Name -Value $bytes -PropertyType Binary -Force | Out-Null
        Write-Host "disabled startup $($e.Name)" -ForegroundColor Yellow; $changed++
    }
    catch { Write-Warning "Could not disable startup entry $($e.Name): $_"; $failed++ }
}

if ($needAdmin -gt 0) { Write-Warning "$needAdmin item(s) need an elevated shell and were skipped." }
Write-Host "$changed changed, $skipped already disabled, $failed failed." -ForegroundColor Cyan
if ($changed -gt 0 -and -not $WhatIfPreference) { Write-Host "Reboot to apply. Undo with -Restore. State: $StateFile" -ForegroundColor Cyan }
if ($failed -gt 0) { exit 1 }
exit 0

<#
.SYNOPSIS
    Make the Explorer right-click menu fast by hiding the shell extensions you never use.

.DESCRIPTION
    A slow right-click is almost never Explorer itself. Every shell extension registered
    for the thing you clicked -- Dropbox, Google Drive, OneDrive, antivirus, NVIDIA,
    PowerToys, Copilot -- gets its DLL loaded and asked for menu items before the menu
    can draw. One slow handler stalls the whole menu, every time.

    This script hides them two ways, neither of which deletes anything:

    1. Handlers (classic ContextMenuHandlers AND Windows 11 packaged menu items) are
       blocked by CLSID under
         HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked
       Explorer refuses to load a blocked CLSID at all, so the DLL never costs anything.
       Per-user, no admin needed, and it survives the app re-registering itself on update.

    2. Static verbs (plain "shell\<verb>" entries such as Git Bash Here or WSL) cost no
       DLL load, they're just clutter. They get a LegacyDisable value, which hides them.
       Most live in HKLM, so this part needs an elevated shell; without one it is skipped
       with a warning and the handler blocking still applies.

    Every value written carries the tag "trim-context-menu", and -Restore removes only
    tagged values. Anything already blocked or disabled by you or another tool is left
    alone, so running it twice -- or after a manual tweak -- changes nothing.

    What gets hidden is the data block at the top of the script. The defaults keep
    7-Zip, Notepad++, Open with, Copy as path, Pin to Start/Taskbar and New -- edit the
    block to taste. Run -List first to see every handler on your machine with its CLSID.

.PARAMETER List
    Read-only. Print every context menu handler and Windows 11 packaged menu item on this
    machine with its CLSID and whether it is currently blocked. Changes nothing.

.PARAMETER Restore
    Remove every block and LegacyDisable value this script wrote. Leaves anything it
    didn't write untouched.

.PARAMETER NoRestart
    Don't restart Explorer afterwards. Changes take effect on the next Explorer start.

.EXAMPLE
    .\trim-context-menu.ps1 -List
    See what is hooked into your right-click menu.

.EXAMPLE
    .\trim-context-menu.ps1 -WhatIf
    Show what would be hidden, change nothing.

.EXAMPLE
    .\trim-context-menu.ps1
    Hide everything in the data block. Run from an elevated shell to hide verbs too.

.EXAMPLE
    .\trim-context-menu.ps1 -Restore
    Put everything back.

.NOTES
    Exit 0 on success, 1 if any write failed, 2 on bad usage.
    Shell Extensions\Blocked: https://learn.microsoft.com/en-us/windows/win32/shell/reg-shell-exts
    Windows 11 packaged items come from desktop4:FileExplorerContextMenus in each app's
    AppxManifest; -List reads them straight from there.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch] $List,
    [switch] $Restore,
    [switch] $NoRestart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# DATA -- edit this block. Anything NOT listed here stays in the menu.
# ============================================================================

# CLSID -> label. Blocked per-user; applies to classic and Windows 11 menus alike.
$BlockedHandlers = [ordered]@{
    # --- desktop / folder background -----------------------------------------
    '{1E9B04FB-F9E5-4718-997B-B8DA88302A48}' = 'NVIDIA nView (very slow)'
    '{3D1975AF-48C6-4f8e-A182-BE0E08FA86A9}' = 'NVIDIA Control Panel'
    '{0bf754aa-c967-445c-ab3d-d8fda9bae7ef}' = 'Next desktop background (slideshow)'

    # --- cloud sync ------------------------------------------------------------
    '{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}' = 'OneDrive (classic)'
    '{1FA0E654-C9F2-4A1F-9800-B9A75D744B00}' = 'OneDrive 0'
    '{1FA0E654-C9F2-4A1F-9800-B9A75D744B01}' = 'OneDrive 1'
    '{1FA0E654-C9F2-4A1F-9800-B9A75D744B02}' = 'OneDrive 2'
    '{1FA0E654-C9F2-4A1F-9800-B9A75D744B03}' = 'OneDrive 3'
    '{1FA0E654-C9F2-4A1F-9800-B9A75D744B04}' = 'OneDrive 4'
    '{1FA0E654-C9F2-4A1F-9800-B9A75D744B05}' = 'OneDrive 5'
    '{5250E46F-BB09-D602-5891-F476DC89B700}' = 'OneDrive (shortcuts)'
    '{ECD97DE5-3C8F-4ACB-AEEE-CCAB78F7711C}' = 'Dropbox (classic)'
    '{73961f92-4e9c-11ee-be56-0242ac120002}' = 'Dropbox: transfer'
    '{B165B4C7-D18D-4C23-B46C-380E219BA5B9}' = 'Dropbox: transfer (work)'
    '{95C5E6AC-93FA-4234-8301-1B3D5424AA6B}' = 'Dropbox: move'
    '{646E22C5-CD0B-44CE-9570-82165CCDA505}' = 'Dropbox: move (work)'
    '{67CA84CB-DE8C-47EE-9F3B-48123B1C634C}' = 'Dropbox: back up'
    '{0f6a5364-18f2-4d9d-899f-263b7c569d87}' = 'Dropbox: copy to'
    '{b97e7965-f679-4a55-a272-78dddc3c012f}' = 'Dropbox: share'
    '{EE15C2BD-CECB-49F8-A113-CA1BFC528F5B}' = 'Google Drive'

    # --- third-party tools -----------------------------------------------------
    '{36D7AD11-6890-4ADB-B2DA-C74D182CDB7C}' = 'Kaspersky (classic)'
    '{AC2512EE-996B-4B15-918E-D801FD7DB91B}' = 'Kaspersky'
    '{211B6F25-950C-49CD-AB86-A448EF85686A}' = 'Nitro PDF Pro'
    '{5D924130-4CB1-11DB-B0DE-0800200C9A66}' = 'Bulk Rename Utility'
    '{CC8811D0-1B32-4f3d-A9BF-D21C8F3C0366}' = 'SmartSVN'
    '{A8005AF0-D6E8-48AF-8DFA-023B1CF660A7}' = 'TeraCopy (menu only; copy hook unaffected)'
    '{559F1A79-1264-4219-9F15-F919BBBB2CA4}' = 'Adobe'
    '{84D68575-E186-46AD-B0CB-BAEB45EE29C0}' = 'PowerToys File Locksmith (classic)'
    '{AAF1E27D-4976-49C2-8895-AAFA743C0A7E}' = 'PowerToys File Locksmith'
    '{0440049F-D1DC-4E46-B27B-98393D79486B}' = 'PowerToys PowerRename (classic)'
    '{1861E28B-A1F0-4EF4-A1FE-4C8CA88E2174}' = 'PowerToys PowerRename'
    '{51B4D7E5-7568-4234-B4BB-47FB3C016A69}' = 'PowerToys Image Resizer (classic)'
    '{8F491918-259F-451A-950F-8C3EBF4864AF}' = 'PowerToys Image Resizer'
    '{1C6DF0C0-192A-4451-BE36-6A59A86A692E}' = 'Open with Code'
    '{74024f7c-c922-4695-b6e6-2d025881911c}' = 'Google Lens search'

    # --- Windows extras ----------------------------------------------------------
    '{09A47860-11B0-4DA5-AFA5-26D86198A780}' = 'Scan with Microsoft Defender'
    '{E61BF828-5E63-4287-BEF1-60B1A4FDE0E3}' = 'Work Folders'
    '{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}' = 'Give access to'
    '{e2bf9676-5f8f-435c-97eb-11607a5bedf7}' = 'Share'
    '{474C98EE-CF3D-41f5-80E3-4AAB0AB04301}' = 'Offline Files'
    '{596AB062-B4D2-4215-9F74-E9109B0A8153}' = 'Restore previous versions'
    '{A470F8CF-A1E8-4f65-8335-227475AA5C46}' = 'File ownership / encryption'
    '{3dad6c5d-2167-4cae-9914-f99e41c12cfa}' = 'Include in library'
    '{7BA4C740-9E81-11CF-99D3-00AA004AE837}' = 'Send to (incl. Compressed folder)'
    '{CA6CC9F1-867A-481E-951E-A28C5E4F01EA}' = 'Edit in Notepad'
    '{2430F218-B743-4FD6-97BF-5C76541B4AE9}' = 'Edit in Paint'
    '{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}' = 'Edit with Photos'
    '{8AB635F8-9A67-4698-AB99-784AD929F3B4}' = 'Edit with Clipchamp'
    '{9f156763-7844-4dc4-b2b1-901f640f5155}' = 'Open in Terminal'
    '{1E1F2315-7C3C-4603-BE7B-D2F2117D6DFF}' = 'Open in Intelligent Terminal'
    '{ED215C26-C810-49CE-929E-31D7E83A82E9}' = 'Ask Copilot'
    '{4a616e61-3bfe-4f5c-937f-b8602bf16679}' = 'Ask M365 Copilot'
}

# Static verbs, as paths under HKEY_CLASSES_ROOT. Hidden with LegacyDisable.
# cmd / Powershell are owned by TrustedInstaller and already hidden by Windows; not listed.
$HiddenVerbs = @(
    'Directory\Background\shell\git_gui'
    'Directory\Background\shell\git_shell'
    'Directory\Background\shell\WSL'
    'Directory\Background\shell\smartsynchronize'
    'Directory\Background\shell\00-laragon-terminal'
    'Directory\shell\git_gui'
    'Directory\shell\git_shell'
    'Directory\shell\WSL'
    'Directory\shell\smartsynchronize'
    'Directory\shell\00-laragon-terminal'
    'Directory\shell\AddToPlaylistVLC'
    'Directory\shell\PlayWithVLC'
    'Drive\shell\WSL'
    '*\shell\Compare with SmartSynchronize'
    '*\shell\00-laragon-sublime'
)

# Where -List and -Restore look.
$Scopes = @('*', 'AllFilesystemObjects', 'Directory', 'Directory\Background', 'DesktopBackground',
            'Folder', 'Drive', 'LibraryFolder')

# ============================================================================

$Tag        = 'trim-context-menu'
$BlockedKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked'

if ($List -and $Restore) {
    [Console]::Error.WriteLine('Use -List or -Restore, not both.')
    exit 2
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal] $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-BlockedValue([string] $Clsid) {
    $props = Get-ItemProperty -LiteralPath $BlockedKey -ErrorAction SilentlyContinue
    if (-not $props) { return $null }
    $p = $props.PSObject.Properties | Where-Object { $_.Name -eq $Clsid }
    if ($p) { return [string] $p.Value }
    return $null
}

function Get-VerbKeys([string] $Rel) {
    # A verb can live in either hive; HKCR is just the merged view.
    foreach ($hive in 'HKCU:', 'HKLM:') {
        $p = "$hive\Software\Classes\$Rel"
        if (Test-Path -LiteralPath $p) { $p }
    }
}

function Restart-Explorer {
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) { Start-Process explorer }
}

# ---------------------------------------------------------------------------- -List
if ($List) {
    $blockedNames = @()
    $props = Get-ItemProperty -LiteralPath $BlockedKey -ErrorAction SilentlyContinue
    if ($props) { $blockedNames = @($props.PSObject.Properties | Where-Object { $_.Name -match '^\{' } | ForEach-Object { $_.Name.ToLower() }) }

    $rows = foreach ($scope in $Scopes) {
        $p = "Registry::HKEY_CLASSES_ROOT\$scope\shellex\ContextMenuHandlers"
        if (-not (Test-Path -LiteralPath $p)) { continue }
        foreach ($k in Get-ChildItem -LiteralPath $p) {
            $default = [string] $k.GetValue('')
            $clsid = if ($default -match '^\{') { $default } elseif ($k.PSChildName -match '^\{') { $k.PSChildName } else { '' }
            $dll = ''
            $srv = Get-Item -LiteralPath "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue
            if ($clsid -and $srv) { $dll = [string] $srv.GetValue('') }
            [pscustomobject]@{
                Blocked = [bool]($clsid -and $blockedNames -contains $clsid.ToLower())
                Kind    = 'classic'
                Scope   = $scope
                Name    = $k.PSChildName.Trim()
                Clsid   = $clsid
                Source  = $dll
            }
        }
    }

    $packaged = try { Get-AppxPackage -ErrorAction Stop } catch { Write-Warning "Get-AppxPackage failed, skipping Windows 11 items: $_"; @() }
    $rows += foreach ($pkg in $packaged) {
        $m = Get-AppxPackageManifest $pkg -ErrorAction SilentlyContinue
        if (-not $m -or $m.OuterXml -notmatch 'FileExplorerContextMenus') { continue }
        $seen = @{}
        foreach ($v in $m.SelectNodes("//*[local-name()='FileExplorerContextMenus']/*/*[local-name()='Verb']")) {
            $clsid = '{' + $v.Clsid.Trim('{}') + '}'
            if ($seen[$clsid]) { continue }; $seen[$clsid] = $true
            [pscustomobject]@{
                Blocked = [bool]($blockedNames -contains $clsid.ToLower())
                Kind    = 'win11'
                Scope   = $v.ParentNode.Type
                Name    = $v.Id
                Clsid   = $clsid
                Source  = $pkg.Name
            }
        }
    }

    $rows | Sort-Object Blocked, Kind, Source | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host

    $verbRows = foreach ($scope in $Scopes) {
        $p = "Registry::HKEY_CLASSES_ROOT\$scope\shell"
        if (-not (Test-Path -LiteralPath $p)) { continue }
        foreach ($k in Get-ChildItem -LiteralPath $p) {
            $hidden = $null -ne (Get-ItemProperty -LiteralPath $k.PSPath -Name LegacyDisable -ErrorAction SilentlyContinue)
            [pscustomobject]@{ Hidden = $hidden; Verb = "$scope\shell\$($k.PSChildName)" }
        }
    }
    Write-Host 'Static verbs:' -ForegroundColor Cyan
    $verbRows | Sort-Object Hidden, Verb | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
    exit 0
}

$failed  = 0
$changed = 0

# ---------------------------------------------------------------------------- -Restore
if ($Restore) {
    $props = Get-ItemProperty -LiteralPath $BlockedKey -ErrorAction SilentlyContinue
    if ($props) {
        foreach ($p in @($props.PSObject.Properties | Where-Object { $_.Value -is [string] -and $_.Value.StartsWith($Tag) })) {
            if ($PSCmdlet.ShouldProcess("$($p.Name) ($($p.Value))", 'Unblock')) {
                try { Remove-ItemProperty -LiteralPath $BlockedKey -Name $p.Name; $changed++ }
                catch { Write-Warning "Could not unblock $($p.Name): $_"; $failed++ }
            }
        }
    }

    $admin = Test-Admin
    foreach ($scope in $Scopes) {
        foreach ($hive in 'HKCU:', 'HKLM:') {
            $p = "$hive\Software\Classes\$scope\shell"
            if (-not (Test-Path -LiteralPath $p)) { continue }
            foreach ($k in Get-ChildItem -LiteralPath $p) {
                $v = Get-ItemProperty -LiteralPath $k.PSPath -Name LegacyDisable -ErrorAction SilentlyContinue
                if (-not $v -or [string]$v.LegacyDisable -ne $Tag) { continue }
                if ($hive -eq 'HKLM:' -and -not $admin) { Write-Warning "Needs admin to un-hide: $($k.Name)"; $failed++; continue }
                if ($PSCmdlet.ShouldProcess($k.Name, 'Un-hide verb')) {
                    try { Remove-ItemProperty -LiteralPath $k.PSPath -Name LegacyDisable; $changed++ }
                    catch { Write-Warning "Could not un-hide $($k.Name): $_"; $failed++ }
                }
            }
        }
    }

    Write-Host "$changed restored, $failed failed" -ForegroundColor Cyan
    if ($changed -gt 0 -and -not $NoRestart -and -not $WhatIfPreference) { Restart-Explorer }
    if ($failed -gt 0) { exit 1 }
    exit 0
}

# ---------------------------------------------------------------------------- apply
$skipped = 0
if (-not (Test-Path -LiteralPath $BlockedKey) -and -not $WhatIfPreference) {
    New-Item -Path $BlockedKey -Force | Out-Null
}

foreach ($clsid in $BlockedHandlers.Keys) {
    $label    = $BlockedHandlers[$clsid]
    $existing = Get-BlockedValue $clsid
    if ($null -ne $existing) { Write-Verbose "already blocked: $clsid $label"; $skipped++; continue }
    if ($PSCmdlet.ShouldProcess("$clsid $label", 'Block handler')) {
        try {
            New-ItemProperty -LiteralPath $BlockedKey -Name $clsid -Value "$Tag : $label" -PropertyType String -Force | Out-Null
            Write-Host "blocked  $label" -ForegroundColor Yellow
            $changed++
        }
        catch { Write-Warning "Could not block $clsid ($label): $_"; $failed++ }
    }
}

$admin = Test-Admin
$needAdmin = 0
foreach ($rel in $HiddenVerbs) {
    foreach ($key in Get-VerbKeys $rel) {
        if ($null -ne (Get-ItemProperty -LiteralPath $key -Name LegacyDisable -ErrorAction SilentlyContinue)) {
            Write-Verbose "already hidden: $key"; $skipped++; continue
        }
        if ($key -like 'HKLM:*' -and -not $admin) { $needAdmin++; continue }
        if ($PSCmdlet.ShouldProcess($key, 'Hide verb')) {
            try {
                New-ItemProperty -LiteralPath $key -Name LegacyDisable -Value $Tag -PropertyType String -Force | Out-Null
                Write-Host "hidden   $rel" -ForegroundColor Yellow
                $changed++
            }
            catch { Write-Warning "Could not hide ${key}: $_"; $failed++ }
        }
    }
}

if ($needAdmin -gt 0) {
    Write-Warning "$needAdmin verb(s) live in HKLM and were skipped -- re-run from an elevated shell to hide them too."
}
Write-Host "$changed changed, $skipped already done, $failed failed" -ForegroundColor Cyan

if ($changed -gt 0 -and -not $NoRestart -and -not $WhatIfPreference) { Restart-Explorer }
if ($failed -gt 0) { exit 1 }
exit 0

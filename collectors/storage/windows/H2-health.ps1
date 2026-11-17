#Requires -Version 7.0
<#
.SYNOPSIS
  H2 - System health: broken references with a real effect, disk health, broken shortcuts,
  zero-byte files, incomplete downloads and file-type mismatches (Windows, read-only).
.DESCRIPTION
  Writes data\<scanId>\storage\H2.json (bvs.module/1). Inventory keys: registryRefs, diskHealth,
  brokenShortcuts, zeroByteFiles, incompleteDownloads, typeMismatches, summary (bvs.items/1 shape).
  Reuses S01 autostarts and G0 inventory\files.tsv. Never suggests a registry cleaner. Changes nothing.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force

$run      = Initialize-BvsRun -Module H2 -Area storage
$scanDir  = Split-Path $run.OutDir -Parent
$projRoot = Split-Path (Split-Path $scanDir -Parent) -Parent
$script:seq = 0; $script:stats = [ordered]@{}
$honest   = "Registry cleaners don't speed Windows up; this is listed only because it has a visible effect."
$autoruns = 'Autoruns (Microsoft Sysinternals, run as admin): entries shown as "File not found" -> untick to disable (reversible)'

function New-H2Item {
    param([string]$Prefix, [string]$Path, [string]$Kind, $Bytes, [string]$Category, [string]$Purpose, [string]$Owner,
          [string]$Safety = 'review', [string]$Method = 'none', [string]$How = '', [bool]$Reversible = $true,
          [string[]]$Flags = @(), [System.Collections.IDictionary]$Extra)
    $script:seq++
    $o = [ordered]@{ id = ('{0}-{1:d5}' -f $Prefix, $script:seq); path = $Path; kind = $Kind; bytes = $Bytes
        category = $Category; purpose = $Purpose; owner = $Owner; safety = $Safety; method = $Method; how = $How
        reversible = $Reversible; flags = @($Flags | Where-Object { $_ } | Select-Object -Unique) }
    if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
    [pscustomobject]$o
}
function Expand-H2([string]$s) { if ($s) { [Environment]::ExpandEnvironmentVariables($s.Trim().Trim('"')).TrimEnd('\') } }
function Get-H2RegMap([string]$Path, [string]$View) {
    $h = @{}
    $vals = if ($View) { Get-BvsRegValues -Path $Path -View $View } else { Get-BvsRegValues -Path $Path }
    foreach ($v in @($vals)) { if ($v) { $h[$v.Name] = $v.Value } }
    $h
}
function Test-H2Target([string]$p) {
    if (-not $p) { return $true }
    $x = [Environment]::ExpandEnvironmentVariables($p.Trim().Trim('"')) -replace '^\\\\\?\\', ''   # strip \\?\ long-path prefix
    if ($x -match '^[a-z][a-z0-9+.-]+://' -or $x.StartsWith('\\')) { return $true }   # URLs / network paths are not tested
    if ($x -notmatch '\\') {
        foreach ($d in @([Environment]::GetFolderPath('System'), $env:windir, (Join-Path $env:windir 'SysWOW64'))) { if (Test-Path -LiteralPath (Join-Path $d $x)) { return $true } }
        return [bool](Get-Command $x -CommandType Application -ErrorAction SilentlyContinue)
    }
    Test-Path -LiteralPath $x
}
# Returns the files a command line needs (exe plus DLL arguments) that do not exist.
function Get-H2Missing([string]$Cmd) {
    if (-not $Cmd -or $Cmd -match '^\s*[/-]') { return @() }
    $rc = Resolve-BvsCommandLine -CommandLine ([Environment]::ExpandEnvironmentVariables($Cmd))
    $c = [System.Collections.Generic.List[string]]::new()
    if ("$($rc.Executable)" -match '\.\w{2,4}$') { $c.Add([string]$rc.Executable) }   # no extension = parse artefact, not evidence
    foreach ($m in [regex]::Matches([string]$rc.Arguments, '(?i)(?:[a-z]:\\[^",]+?|[\w.-]+)\.(?:dll|ocx|cpl)\b')) { $c.Add($m.Value) }
    @($c | Where-Object { -not (Test-H2Target $_) })
}
function Get-H2RealCommand($e) {
    switch ($e.category) {
        'active_setup' { return [string](Get-H2RegMap $e.location '')['StubPath'] }
        'service' { return [string](Get-H2RegMap $e.location '')['ImagePath'] }
        'scheduled_task' {
            $tn = Split-Path $e.name -Leaf; $tp = $e.name.Substring(0, $e.name.Length - $tn.Length)
            $t = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue
            return (@($t.Actions | Where-Object { $_.Execute } | ForEach-Object { "`"$($_.Execute)`" $($_.Arguments)" }) | Select-Object -First 1)
        }
        default { return [string]$e.command }
    }
}
function New-H2Ref {
    param([string]$Category, [string]$Path, [string]$Name, [string]$Target, [string]$What, [string]$Impact, [string]$Fix, [string]$Risk,
          [string]$Method = 'tool', [string]$Safety = 'safe_after_check', [string]$Owner = '', [string]$Kind = 'registry', [string[]]$More = @())
    New-H2Item -Prefix 'h2r' -Path $Path -Kind $Kind -Bytes 0 -Category $Category -Purpose "$What $honest" -Owner $Owner -Safety $Safety -Method $Method `
        -How $Fix -Reversible $true -Flags (@('backup_required') + $More) -Extra ([ordered]@{ name = $Name; target = $Target; impact = $Impact; risk = $Risk })
}

$refs = Invoke-BvsCheck -Run $run -Id 'H2.registryRefs' -Description 'Broken registry references with a real effect (never a registry cleaner)' -Script {
    # 1. Ghost uninstall entries
    $roots = @(@{ P = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; V = ''; L = 'HKLM\SOFTWARE' },
               @{ P = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; V = '32'; L = 'HKLM\SOFTWARE\WOW6432Node' },
               @{ P = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall'; V = ''; L = 'HKCU\Software' })
    foreach ($root in $roots) {
        $subs = if ($root.V) { Get-BvsRegSubKeys -Path $root.P -View $root.V } else { Get-BvsRegSubKeys -Path $root.P }
        foreach ($sk in @($subs)) {
            if (-not $sk) { continue }
            $m = Get-H2RegMap "$($root.P)\$sk" $root.V; $dn = [string]$m['DisplayName']
            if (-not $dn -or "$($m['SystemComponent'])" -eq '1') { continue }
            $loc = Expand-H2 $m['InstallLocation']; $un = [string]$m['UninstallString']
            $locMissing = [bool]($loc -and -not (Test-Path -LiteralPath $loc))
            $exe = if ($un -and $un -notmatch '(?i)msiexec') { [string](Resolve-BvsCommandLine -CommandLine ([Environment]::ExpandEnvironmentVariables($un))).Executable } else { $null }
            $unMissing = [bool]($exe -match '\.(exe|cmd|bat|com)$' -and -not (Test-H2Target $exe))
            $icon = Expand-H2 (([string]$m['DisplayIcon']) -replace ',\s*-?\d+$', '')
            $present = $icon -and -not $icon.StartsWith($env:windir, 'OrdinalIgnoreCase') -and (Test-Path -LiteralPath $icon)
            if (-not ($locMissing -or $unMissing) -or $present) { continue }
            New-H2Ref -Category 'ghost-uninstall' -Path "$($root.L)\Microsoft\Windows\CurrentVersion\Uninstall\$sk" -Name $dn -Target $(if ($unMissing) { $exe } else { $loc }) -Owner ([string]$m['Publisher']) `
                -What "Ghost uninstall entry: '$dn' is listed in Settings -> Apps but its $(if ($unMissing) { 'uninstaller' } else { 'install folder' }) is gone." `
                -Impact "The app still shows as installed; Uninstall $(if ($unMissing) { 'fails with a missing-file error' } else { 'only removes the leftover entry' })." `
                -Fix $(if ($unMissing) { "1) Settings -> Apps -> Installed apps -> '$dn' -> Uninstall (Windows offers to remove the entry). 2) If that fails, Microsoft's 'Program Install and Uninstall troubleshooter'. 3) Last resort: reinstall the same version, then uninstall it." } else { "Settings -> Apps -> Installed apps -> '$dn' -> Uninstall; the vendor uninstaller clears the leftover entry." }) `
                -Risk 'Low: the program files are already gone.' -Method $(if ($unMissing) { 'tool' } else { 'setting' })
        }
    }
    # 2. Startup / task / service targets missing (re-verified from S01)
    $script:stats.s01FalsePositives = 0; $script:stats.startupApprovedOrphans = 0
    $s01f = Join-Path $scanDir 'security\S01.json'
    if (Test-Path -LiteralPath $s01f) {
        $s01 = Get-Content -LiteralPath $s01f -Raw | ConvertFrom-Json
        $script:stats.startupApprovedOrphans = @($s01.inventory.startupApprovedStale).Count
        foreach ($e in @($s01.inventory.autostarts | Where-Object { $_.exists -eq $false -and $_.enabled })) {
            $miss = @(Get-H2Missing (Get-H2RealCommand $e))
            if (-not $miss.Count) { $script:stats.s01FalsePositives++; continue }
            $win = [bool]$e.microsoft -or "$($e.location) $($e.name)" -match '\\Microsoft\\Windows\\'
            New-H2Ref -Category 'missing-startup-target' -Path $e.location -Name $e.name -Target ($miss -join '; ') -Owner ([string]$e.signer) `
                -What "$($e.category) '$($e.name)' points to a missing file ($($miss -join ', '))." `
                -Impact $(switch ($e.category) { 'scheduled_task' { 'The task fails each time it triggers (silent; visible in Task Scheduler history).' } 'service' { 'The service fails at every boot (event-log errors, can delay startup).' } default { 'Windows tries to run it at every logon and fails.' } }) `
                -Fix $(if ($win) { 'Windows component: do not delete it. To repair, run DISM /Online /Cleanup-Image /RestoreHealth and then sfc /scannow in an admin terminal (pending admin run).' } else { "Reinstall or uninstall the owning app via Settings -> Apps first; if it is already gone, disable the entry with $autoruns." }) `
                -Risk $(if ($win) { 'Deleting Windows tasks can break updates or features.' } else { 'Low once the owning app is gone.' }) -Safety $(if ($win) { 'do_not_touch' } else { 'safe_after_check' })
        }
    } else { Set-BvsCheckStatus -Id 'H2.registryRefs' -Status partial -Reason 'S01.json not found; startup targets not checked' }
    # 3. App Paths (64-bit view only: that is what Win+R and 'start' use)
    foreach ($ap in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths', 'HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths') {
        foreach ($sk in @(Get-BvsRegSubKeys -Path $ap)) {
            if (-not $sk) { continue }
            $t = Expand-H2 (Get-H2RegMap "$ap\$sk" '')['']
            if (-not $t -or (Test-H2Target $t)) { continue }
            New-H2Ref -Category 'app-path' -Path "$ap\$sk" -Name $sk -Target $t -What "App Paths entry '$sk' points to a missing file." `
                -Impact "Win+R -> '$sk' and 'start $sk' fail with 'cannot find'." -Risk 'Low: nothing can use a path that does not exist.' `
                -Fix "Reinstall or uninstall the app that owned '$sk' (Settings -> Apps). If it is gone: regedit -> select the key -> File -> Export (backup) -> delete the '$sk' key."
        }
    }
    # 4. Open command of common file types
    foreach ($x in '.txt', '.log', '.md', '.json', '.xml', '.csv', '.htm', '.html', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.mp3', '.mp4', '.mkv', '.zip', '.7z', '.rar', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.py', '.js') {
        $fe = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$x"
        $progId = @([string](Get-H2RegMap "$fe\UserChoiceLatest\ProgId" '')['ProgId'], [string](Get-H2RegMap "$fe\UserChoice" '')['ProgId'], [string](Get-H2RegMap "HKCR\$x" '')['']) | Where-Object { $_ } | Select-Object -First 1
        if (-not $progId -or $progId -like 'AppX*') { continue }
        $cmd = [string](Get-H2RegMap "HKCR\$progId\shell\open\command" '')['']
        $miss = @(Get-H2Missing $cmd)
        if (-not $miss.Count) { continue }
        New-H2Ref -Category 'file-association' -Path "HKCR\$progId\shell\open\command" -Name $x -Target ($miss -join '; ') -Method 'setting' -Safety 'safe' `
            -What "Files of type $x open with '$progId', whose program is missing ($($miss -join ', '))." -Impact "Double-clicking a $x file shows an error instead of opening it." `
            -Fix "Settings -> Apps -> Default apps -> 'Choose defaults by file type' -> $x -> pick an installed app." -Risk 'None: only changes which app opens the file.'
    }
    # 5. Context-menu handlers whose DLL is missing (they slow down or break right-click)
    $seenClsid = @{}
    foreach ($base in '*', 'AllFilesystemObjects', 'Directory', 'Directory\Background', 'Folder', 'Drive') {
        $kp = "HKCR\$base\shellex\ContextMenuHandlers"
        foreach ($h in @(Get-BvsRegSubKeys -Path $kp)) {
            if (-not $h) { continue }
            $clsid = [string](Get-H2RegMap "$kp\$h" '')['']; if ($clsid -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { $clsid = $h.Trim() }
            if ($clsid -notmatch '^\{[0-9A-Fa-f-]{36}\}$' -or $seenClsid[$clsid]) { continue }
            $dll = Expand-H2 (Get-H2RegMap "HKCR\CLSID\$clsid\InprocServer32" '')['']
            if (-not $dll -or (Test-H2Target $dll)) { continue }
            $seenClsid[$clsid] = 1; $owner = [string](Get-H2RegMap "HKCR\CLSID\$clsid" '')['']
            New-H2Ref -Category 'context-menu-handler' -Path "$kp\$h" -Name $h.Trim() -Target $dll -Owner $owner `
                -What "Right-click handler '$($h.Trim())' ($owner) points to a missing DLL." -Impact "Explorer tries to load a missing DLL on every right-click on $(if ($base -eq '*') { 'files' } else { $base.ToLower() }); can add delay or errors." `
                -Fix "Repair or uninstall the program it belongs to via Settings -> Apps; if it is already gone, disable it in $autoruns (Explorer tab)." -Risk 'Low: the DLL is already missing.'
        }
    }
    # 6. Stale Security Center registrations
    foreach ($cls in 'AntiVirusProduct', 'AntiSpywareProduct', 'FirewallProduct') {
        foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName $cls -ErrorAction SilentlyContinue)) {
            $paths = @($p.pathToSignedProductExe, $p.pathToSignedReportingExe) | Where-Object { $_ -and $_ -notmatch '^[a-z]+://' }
            if (-not @($paths).Count -or @($paths | Where-Object { Test-H2Target $_ }).Count) { continue }
            $type = $cls -replace 'Product$', ''
            New-H2Ref -Category 'security-center' -Path "root\SecurityCenter2\$cls" -Name $p.displayName -Target (@($paths) -join '; ') -Owner $p.displayName `
                -What "Windows Security still lists '$($p.displayName)' as a $type provider$(if ((([int]$p.productState -shr 8) -band 0xF0) -eq 0x10) { ' (reported as ON)' }), but its program files are gone." `
                -Impact "Windows Security shows the wrong $type provider and may keep its own $type switched off or report a confusing status." `
                -Fix "Run the vendor's removal tool (McAfee: MCPR 'McAfee Consumer Product Removal'), restart, then check Windows Security -> Firewall & network protection / Virus & threat protection." `
                -Risk 'Low: the product is already uninstalled.'
        }
    }
    # 7. Dead PATH entries
    foreach ($sc in @(@{ S = 'User'; P = 'HKCU\Environment' }, @{ S = 'Machine'; P = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' })) {
        foreach ($ent in @(([string](Get-H2RegMap $sc.P '')['Path']) -split ';' | Where-Object { $_.Trim() } | Select-Object -Unique)) {
            $x = [Environment]::ExpandEnvironmentVariables($ent.Trim().Trim('"'))
            if ($x -notmatch '%' -and (Test-Path -LiteralPath $x -PathType Container)) { continue }
            $parent = if ($x -match '%') { $null } else { $x }; while ($parent -and -not (Test-Path -LiteralPath $parent)) { $parent = Split-Path $parent -Parent }
            $plant = $sc.S -eq 'Machine' -and $parent -and (Test-BvsUserWritable -Path $parent)
            New-H2Ref -Category 'dead-path-entry' -Kind 'setting' -Path "$($sc.P)\Path" -Name $ent.Trim() -Target $x -Method 'setting' -More @($(if ($plant) { 'planting_risk' })) `
                -What "$($sc.S) PATH entry '$($ent.Trim())' points to a folder that does not exist$(if ($x -match '%') { ' (undefined variable)' })." `
                -Impact $(if ($plant) { 'A standard user could create this folder; anything placed there would be found on the system PATH by every user (planting risk). Also a tiny delay per command lookup.' } else { 'Every command lookup checks a missing folder (tiny delay); commands from that tool no longer work.' }) `
                -Fix "Win+R -> sysdm.cpl -> Advanced -> Environment Variables -> $(if ($sc.S -eq 'User') { 'User variables' } else { 'System variables (admin)' }) -> Path -> Edit -> select '$($ent.Trim())' -> Delete." `
                -Risk 'Low: re-add it if a command stops working.'
        }
    }
}
$refs = @($refs | Where-Object { $_ })
Add-BvsInventory -Run $run -Name 'registryRefs' -Data $refs

$disk = Invoke-BvsCheck -Run $run -Id 'H2.diskHealth' -Description 'Physical disk health; disk/NTFS/WHEA/crash events and Ntfs/Operational errors (90 days)' -Script {
    foreach ($d in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
        $ok = "$($d.HealthStatus)" -eq 'Healthy'
        New-H2Item -Prefix 'h2d' -Path "PhysicalDisk $($d.DeviceId)" -Kind 'setting' -Bytes 0 -Category 'disk' -Owner ([string]$d.FriendlyName) -Safety $(if ($ok) { 'safe' } else { 'review' }) -Method 'none' `
            -Purpose ("{0} ({1}, {2}, {3:N0} GB): health {4}, status {5}" -f $d.FriendlyName, $d.MediaType, $d.BusType, ($d.Size / 1GB), $d.HealthStatus, ($d.OperationalStatus -join ', ')) `
            -How $(if ($ok) { 'No action. Keep regular backups.' } else { 'Back up now, then check the drive with the vendor tool; SMART/reliability counters need admin (pending).' }) `
            -Flags @($(if (-not $ok) { 'disk_warning' })) -Extra ([ordered]@{ healthStatus = "$($d.HealthStatus)"; operationalStatus = "$($d.OperationalStatus -join ', ')"; mediaType = "$($d.MediaType)"; busType = "$($d.BusType)"; sizeBytes = [int64]$d.Size })
    }
    $meaning = @{ 'disk/7' = 'Bad block on a disk'; 'disk/11' = 'Disk controller error'; 'disk/51' = 'Paging I/O error on a disk'; 'disk/153' = 'Disk I/O had to be retried'
        'stornvme/129' = 'NVMe controller reset after an I/O timeout'; 'Ntfs/55' = 'File-system corruption detected'; 'Ntfs/98' = 'Volume needs an offline chkdsk'; 'Ntfs/137' = 'NTFS transaction error'
        'volmgr/161' = 'Crash-dump file could not be written'; 'WHEA/17' = 'Corrected PCIe hardware error'; 'WHEA/18' = 'Fatal hardware error (machine check)'; 'WHEA/19' = 'Corrected CPU/cache error'
        'WHEA/47' = 'Corrected memory error'; 'Kernel-Power/41' = 'Unexpected shutdown or reboot'; 'BugCheck/1001' = 'Blue screen (bugcheck) recorded' }
    $advice = @{ disk = 'Back up important data, run "chkdsk C: /scan" in an admin terminal (online, read-only), update storage drivers and SSD firmware, check the vendor SSD tool.'
        stornvme = 'Update the NVMe/storage driver, chipset driver and SSD firmware; back up if it repeats.'; Ntfs = 'Run "chkdsk C: /scan" in an admin terminal; if it reports errors, schedule "chkdsk C: /spotfix".'
        volmgr = 'Keep the page file on C: with enough free space (System -> Advanced -> Startup and Recovery) so crash dumps can be written.'
        WHEA = 'Update BIOS and chipset drivers; if frequent, run Windows Memory Diagnostic (mdsched) and check temperatures.'
        'Kernel-Power' = 'If not a forced power-off or empty battery: check overheating and drivers; Reliability Monitor (perfmon /rel) shows what happened before.'
        BugCheck = 'Note the stop code in Reliability Monitor (perfmon /rel); update drivers/BIOS. Minidumps need admin to read (pending).' }
    $sources = @(@{ P = 'disk'; L = 'disk'; Ids = 7, 11, 51, 153 }, @{ P = 'stornvme'; L = 'stornvme'; Ids = @(129) }, @{ P = 'Ntfs'; L = 'Ntfs'; Ids = 55, 98, 137 }, @{ P = 'Microsoft-Windows-Ntfs'; L = 'Ntfs'; Ids = 55, 98, 137 },
        @{ P = 'volmgr'; L = 'volmgr'; Ids = @(161) }, @{ P = 'Microsoft-Windows-WHEA-Logger'; L = 'WHEA'; Ids = 17, 18, 19, 47 }, @{ P = 'Microsoft-Windows-Kernel-Power'; L = 'Kernel-Power'; Ids = @(41) },
        @{ P = 'BugCheck'; L = 'BugCheck'; Ids = @(1001) }, @{ P = 'Microsoft-Windows-WER-SystemErrorReporting'; L = 'BugCheck'; Ids = @(1001) })
    $agg = [ordered]@{}
    foreach ($s in $sources) {
        $xp = "*[System[Provider[@Name='$($s.P)'] and (" + (($s.Ids | ForEach-Object { "EventID=$_" }) -join ' or ') + ') and TimeCreated[timediff(@SystemTime) <= 7776000000]]]'
        foreach ($e in @(Get-WinEvent -LogName System -FilterXPath $xp -ErrorAction SilentlyContinue)) {
            if ($s.L -eq 'Ntfs' -and $e.Id -eq 98 -and $e.Level -ge 4) { continue }   # Ntfs 98 at Information level = "volume is healthy"
            $k = "$($s.L)/$($e.Id)"; $t = $e.TimeCreated.ToUniversalTime()
            if (-not $agg[$k]) { $agg[$k] = [pscustomobject]@{ Label = $s.L; Id = $e.Id; Count = 0; Latest = $t; Codes = @{} } }
            $agg[$k].Count++; if ($t -gt $agg[$k].Latest) { $agg[$k].Latest = $t }
            if ($s.L -in 'BugCheck', 'Kernel-Power' -and $e.Properties.Count) {   # stop code from EventData (locale-independent)
                $v0 = $e.Properties[0].Value
                $code = try { if ($v0 -is [string]) { '0x{0:X}' -f [Convert]::ToInt64([regex]::Match($v0, '0x([0-9a-fA-F]+)').Groups[1].Value, 16) } else { '0x{0:X}' -f [int64]$v0 } } catch { $null }
                if ($code) { $agg[$k].Codes[$code]++ }
            }
        }
    }
    $script:stats.diskEvents = [ordered]@{}
    foreach ($k in $meaning.Keys | Sort-Object) { $script:stats.diskEvents[$k] = $(if ($agg[$k]) { $agg[$k].Count } else { 0 }) }
    foreach ($a in $agg.Values) {
        $k = "$($a.Label)/$($a.Id)"
        New-H2Item -Prefix 'h2d' -Path "System log: $k" -Kind 'setting' -Bytes 0 -Category 'disk-events' -Owner $a.Label -Safety 'review' -Method 'none' -How $advice[$a.Label] `
            -Purpose ("{0}: {1}x in 90 days (latest {2:yyyy-MM-dd}){3}" -f $meaning[$k], $a.Count, $a.Latest, $(if ($a.Codes.Count) { '; codes: ' + (($a.Codes.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key) x$($_.Value)" }) -join ', ') + $(if ($a.Label -eq 'Kernel-Power') { ' (0x0 = power loss or hard hang, otherwise a bugcheck)' }) } else { '' })) `
            -Flags @($(if ($a.Label -in 'disk', 'stornvme', 'Ntfs' -or $k -eq 'WHEA/18') { 'hardware_warning' }), $(if ($a.Label -in 'BugCheck', 'Kernel-Power' -and $a.Count -ge 5) { 'stability_hot_spot' })) `
            -Extra ([ordered]@{ provider = $a.Label; eventId = $a.Id; count = $a.Count; latestUtc = $a.Latest.ToString('o'); meaning = $meaning[$k]; codes = $a.Codes })
    }
    if (-not $agg.Count) { New-H2Item -Prefix 'h2d' -Path 'System log' -Kind 'setting' -Bytes 0 -Category 'disk-events' -Owner 'Windows' -Safety 'safe' -Method 'none' -How 'No action.' -Purpose 'No disk, NVMe, NTFS, WHEA, unexpected-shutdown or bugcheck events in 90 days.' }
    $nt = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Ntfs/Operational'; Level = 1, 2, 3; StartTime = (Get-Date).AddDays(-90) } -ErrorAction SilentlyContinue -ErrorVariable ntErr)
    if ($ntErr | Where-Object { "$($_.FullyQualifiedErrorId)" -notmatch 'NoMatchingEventsFound' }) { Set-BvsCheckStatus -Id 'H2.diskHealth' -Status partial -Reason 'Ntfs/Operational log not readable' }
    $script:stats.ntfsOperationalProblems = $nt.Count
    $ntMeaning = @{ '147' = 'an I/O took longer than 30 s'; '149' = 'hourly summary of high-latency or failed I/O'; '304' = 'volume dismount failed' }
    foreach ($g in @($nt | Group-Object Id)) {
        $lv = @($g.Group | ForEach-Object { if ($_.Level -le 2) { 'error' } else { 'warning' } } | Select-Object -Unique) -join '/'
        New-H2Item -Prefix 'h2d' -Path 'Microsoft-Windows-Ntfs/Operational' -Kind 'setting' -Bytes 0 -Category 'ntfs-operational' -Owner 'Ntfs' -Safety 'review' -Method 'none' `
            -Purpose ("NTFS operational event {0} - {1} ({2}): {3}x in 90 days (latest {4:yyyy-MM-dd})" -f $g.Name, $(if ($ntMeaning[$g.Name]) { $ntMeaning[$g.Name] } else { 'see sample' }), $lv, $g.Count, ($g.Group | Measure-Object TimeCreated -Maximum).Maximum) `
            -How $(if ($g.Name -in '147', '149') { 'I/O stalls point to the SSD, its driver or power saving: update the NVMe/storage and chipset drivers and the SSD firmware (vendor tool); SMART needs admin (pending). Keep backups.' } else { 'See the sample message; if errors keep growing, run "chkdsk C: /scan" in an admin terminal.' }) `
            -Flags @($(if ($g.Name -in '147', '149') { 'hardware_warning' })) `
            -Extra ([ordered]@{ eventId = [int]$g.Name; count = $g.Count; level = $lv; sample = $(($m0 = ("$($g.Group[0].Message)" -replace '\s+', ' ')).Substring(0, [Math]::Min(200, $m0.Length))) })
    }
    foreach ($pend in @(@{ N = 'Reliability counters (wear, temperature, uncorrected read errors)'; C = 'Get-StorageReliabilityCounter' }, @{ N = 'System file integrity (sfc /verifyonly, DISM /CheckHealth)'; C = 'sfc / DISM' })) {
        New-H2Item -Prefix 'h2d' -Path $pend.C -Kind 'setting' -Bytes 0 -Category 'pending-admin' -Owner 'Windows' -Safety 'safe' -Method 'none' -Flags @('needs_admin') `
            -Purpose "$($pend.N): pending - needs an elevated run (UAC was cancelled)." -How 'Run the admin module (elevated) to collect this.'
    }
}
Add-BvsInventory -Run $run -Name 'diskHealth' -Data @($disk | Where-Object { $_ })
$null = Invoke-BvsCheck -Run $run -Id 'H2.reliabilityCounters' -Description 'Storage reliability counters (Get-StorageReliabilityCounter)' -Script {
    Set-BvsCheckStatus -Id 'H2.reliabilityCounters' -Status needs_admin -Reason 'Needs elevation; pending the admin run' }
$null = Invoke-BvsCheck -Run $run -Id 'H2.systemFileIntegrity' -Description 'sfc /verifyonly and DISM /CheckHealth' -Script {
    Set-BvsCheckStatus -Id 'H2.systemFileIntegrity' -Status needs_admin -Reason 'sfc and DISM need elevation; pending the admin run' }

$lnks = Invoke-BvsCheck -Run $run -Id 'H2.brokenShortcuts' -Description 'Desktop, Start Menu and taskbar shortcuts whose target is missing' -Script {
    $sh = New-Object -ComObject WScript.Shell   # CreateShortcut only reads; Save() is never called
    $script:stats.shortcutsCloudSkipped = 0
    $places = @(@{ P = [Environment]::GetFolderPath('Desktop'); R = $false; S = 'user desktop'; All = $false }, @{ P = [Environment]::GetFolderPath('CommonDesktopDirectory'); R = $false; S = 'public desktop'; All = $true },
        @{ P = [Environment]::GetFolderPath('StartMenu'); R = $true; S = 'user Start Menu'; All = $false }, @{ P = [Environment]::GetFolderPath('CommonStartMenu'); R = $true; S = 'all-users Start Menu'; All = $true },
        @{ P = (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'); R = $false; S = 'taskbar pin'; All = $false })
    foreach ($pl in $places) {
        if (-not $pl.P -or -not (Test-Path -LiteralPath $pl.P)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $pl.P -Filter '*.lnk' -File -Recurse:$pl.R -Force -ErrorAction SilentlyContinue)) {
            if (Test-BvsNeverRead -Path $f.FullName) { continue }
            if (Test-BvsCloudOnly -Item $f) { $script:stats.shortcutsCloudSkipped++; continue }
            $t = try { $sh.CreateShortcut($f.FullName).TargetPath } catch { $null }
            if (-not $t) { continue }
            $tx = [Environment]::ExpandEnvironmentVariables($t)
            if ($tx.StartsWith('\\') -or (Test-Path -LiteralPath $tx)) { continue }
            $drv = [IO.Path]::GetPathRoot($tx); $drvOk = $drv -and (Test-Path -LiteralPath $drv)
            New-H2Item -Prefix 'h2s' -Path $f.FullName -Kind 'file' -Bytes $f.Length -Category 'broken-shortcut' -Owner $pl.S -Method 'recycle' `
                -Purpose "Shortcut '$($f.BaseName)' ($($pl.S)) points to a missing $(if ($drvOk) { 'file' } else { 'drive' }): $tx" -Safety $(if ($drvOk) { 'safe' } else { 'review' }) `
                -How $(if (-not $drvOk) { "Target drive $drv is not connected; delete only if that drive is gone for good." } elseif ($pl.All) { 'Delete it in File Explorer (asks for admin confirmation); it goes to the Recycle Bin.' } else { 'Right-click the shortcut -> Delete (Recycle Bin). Taskbar pins: right-click the icon -> Unpin.' }) `
                -Flags @($(if (-not $drvOk) { 'drive_missing' }), $(if ($pl.All) { 'all_users' })) -Extra ([ordered]@{ target = $tx; location = $pl.S })
        }
    }
}
Add-BvsInventory -Run $run -Name 'brokenShortcuts' -Data @($lnks | Where-Object { $_ })

# files.tsv (G0): path, sizeBytes, allocBytes, createdUtc, modifiedUtc, attributes, ext, reason
$script:tsv = [System.Collections.Generic.List[object]]::new()
$tsvPath = Join-Path $scanDir 'inventory\files.tsv'
if (Test-Path -LiteralPath $tsvPath) {
    foreach ($line in [IO.File]::ReadLines($tsvPath)) {
        $c = $line.Split("`t"); if ($c.Count -lt 8 -or $c[7] -notmatch 'zero-byte|partial-download|root-of-user-folder') { continue }
        if ($c[0].StartsWith($projRoot + '\', 'OrdinalIgnoreCase')) { continue }   # never report our own files
        $script:tsv.Add([pscustomobject]@{ Path = $c[0]; Size = [int64]$c[1]; Modified = $c[4]; Reason = $c[7] })
    }
}
$dlDir = Expand-H2 (Get-H2RegMap 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '')['{374DE290-123F-4565-9164-39C4925E467B}']
if (-not $dlDir) { $dlDir = Join-Path $env:USERPROFILE 'Downloads' }
$visible = @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('MyDocuments'), $dlDir, [Environment]::GetFolderPath('MyPictures'), [Environment]::GetFolderPath('MyVideos'), [Environment]::GetFolderPath('MyMusic')) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' }
$devRe = '\\(\.git|node_modules|\.venv|venv|site-packages|__pycache__|\.cache|\.npm|\.nuget|\.gradle|\.m2|\.cargo|\.rustup|\.idea|\.vs|vendor|dist|build|target)\\'

$zero = Invoke-BvsCheck -Run $run -Id 'H2.zeroByteFiles' -Description 'Zero-byte files (from G0 files.tsv): user-visible ones listed, the rest grouped' -Script {
    if (-not (Test-Path -LiteralPath $tsvPath)) { Set-BvsCheckStatus -Id 'H2.zeroByteFiles' -Status skipped -Reason 'files.tsv not found; run G0 first'; return }
    $rows = @($script:tsv | Where-Object { $_.Reason -match 'zero-byte' }); $script:stats.zeroByteFiles = $rows.Count
    $vis = [System.Collections.Generic.List[object]]::new(); $other = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $rows) { $p = $r.Path; if ($p -notmatch $devRe -and @($visible | Where-Object { $p.StartsWith($_, 'OrdinalIgnoreCase') }).Count) { $vis.Add($r) } else { $other.Add($r) } }
    $script:stats.zeroByteUserVisible = $vis.Count
    foreach ($r in @($vis | Select-Object -First 300)) {
        if (-not (Test-Path -LiteralPath $r.Path)) { continue }
        New-H2Item -Prefix 'h2z' -Path $r.Path -Kind 'file' -Bytes 0 -Category 'zero-byte' -Owner '' -Safety 'safe_after_check' -Method 'recycle' `
            -Purpose 'Empty file (0 bytes). Deleting it frees no space; it is only clutter, unless you keep it as a placeholder.' `
            -How 'If you do not recognise it as a placeholder you meant to keep, delete it (Recycle Bin).' -Extra ([ordered]@{ modifiedUtc = $r.Modified })
    }
    $rest = @($other | Group-Object { Split-Path $_.Path -Parent } | Sort-Object Count -Descending)
    $script:stats.zeroByteFolders = $rest.Count
    foreach ($g in @($rest | Select-Object -First 100)) {
        New-H2Item -Prefix 'h2z' -Path $g.Name -Kind 'dir' -Bytes 0 -Category 'zero-byte' -Owner '' -Safety 'do_not_touch' -Method 'none' `
            -Purpose "$($g.Count) empty files: app markers, locks or developer metadata. Deleting them frees nothing and can break the app." -How 'Leave them.' `
            -Extra ([ordered]@{ files = $g.Count; sample = @($g.Group | Select-Object -First 3 | ForEach-Object { Split-Path $_.Path -Leaf }) })
    }
}
Add-BvsInventory -Run $run -Name 'zeroByteFiles' -Data @($zero | Where-Object { $_ })

$partial = Invoke-BvsCheck -Run $run -Id 'H2.incompleteDownloads' -Description 'Unfinished downloads (.crdownload/.part/...) from files.tsv' -Script {
    if (-not (Test-Path -LiteralPath $tsvPath)) { Set-BvsCheckStatus -Id 'H2.incompleteDownloads' -Status skipped -Reason 'files.tsv not found; run G0 first'; return }
    foreach ($r in @($script:tsv | Where-Object { $_.Reason -match 'partial-download' })) {
        $fi = Get-Item -LiteralPath $r.Path -Force -ErrorAction SilentlyContinue; if (-not $fi) { continue }
        $age = [math]::Round(((Get-Date).ToUniversalTime() - $fi.LastWriteTimeUtc).TotalDays, 1)
        New-H2Item -Prefix 'h2p' -Path $fi.FullName -Kind 'file' -Bytes $fi.Length -Category 'partial-download' -Owner 'browser/download manager' `
            -Safety $(if ($age -ge 1) { 'safe_after_check' } else { 'review' }) -Method 'recycle' -Flags @($(if ($age -ge 7) { 'stale' })) `
            -Purpose ("Unfinished download of {0:N1} MB, last written {1} days ago." -f ($fi.Length / 1MB), $age) `
            -How "Check the browser's Downloads list (Ctrl+J) shows nothing in progress for it, then delete it (Recycle Bin); download again if you still need it." `
            -Extra ([ordered]@{ ageDays = $age; modifiedUtc = $fi.LastWriteTimeUtc.ToString('o') })
    }
}
Add-BvsInventory -Run $run -Name 'incompleteDownloads' -Data @($partial | Where-Object { $_ })

$mism = Invoke-BvsCheck -Run $run -Id 'H2.typeMismatches' -Description 'Files in Desktop/Downloads/Documents whose header does not match the extension' -Script {
    if (-not (Test-Path -LiteralPath $tsvPath)) { Set-BvsCheckStatus -Id 'H2.typeMismatches' -Status skipped -Reason 'files.tsv not found; run G0 first'; return }
    $roots = @([Environment]::GetFolderPath('Desktop'), $dlDir, [Environment]::GetFolderPath('MyDocuments')) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }
    $script:stats.typeChecked = 0; $script:stats.typeCloudSkipped = 0; $script:stats.disguisedExecutables = 0
    foreach ($r in @($script:tsv | Where-Object { $_.Reason -match 'root-of-user-folder' -and (Split-Path $_.Path -Parent) -in $roots })) {
        $f = $r.Path
        if ((Test-BvsNeverRead -Path $f) -or -not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
        $fi = Get-Item -LiteralPath $f -Force
        if (Test-BvsCloudOnly -Item $fi) { $script:stats.typeCloudSkipped++; continue }
        $script:stats.typeChecked++
        $m = Test-BvsMagicMismatch -Path $f
        if (-not $m -or -not $m.Mismatch) { continue }
        $bad = [bool]$m.IsDisguisedExecutable
        if ($bad) {
            $script:stats.disguisedExecutables++; $sig = Get-BvsSignature -Path $f
            New-BvsFinding -Run $run -Check 'H2.typeMismatches' -Title "Executable disguised as a $($m.Extension) file in $(Split-Path (Split-Path $f -Parent) -Leaf)" -Severity high -Class suspicious -Confidence medium `
                -Reasons @("The header is '$($m.Actual)' but the extension $($m.Extension) expects '$($m.Expected)'.") -Mitre @('T1036.008') -Entities @{ file = $f } `
                -Evidence @([ordered]@{ path = $f; extension = $m.Extension; expected = $m.Expected; actual = $m.Actual; headerHex = $m.Hex; size = $fi.Length; modifiedUtc = $fi.LastWriteTimeUtc.ToString('o'); signer = $sig.Signer; sigStatus = $sig.Status }) `
                -Recommendation 'Do not open it. Check where it came from (right-click -> Properties), scan it with Microsoft Defender (right-click -> Scan with Microsoft Defender) and delete it if you did not expect a program.' `
                -FpNotes 'Some tools ship renamed executables (installer payloads, game data), or a program was renamed to get past an e-mail filter.'
        }
        New-H2Item -Prefix 'h2t' -Path $f -Kind 'file' -Bytes $fi.Length -Category 'type-mismatch' -Owner '' -Safety 'review' -Method 'none' -Flags @($(if ($bad) { 'disguised_executable' }), $(if ($bad) { 'security_finding' })) `
            -Purpose "Extension $($m.Extension) but the content looks like '$($m.Actual)' (expected '$($m.Expected)')." `
            -How $(if ($bad) { 'Do not open it; see the security finding (scan with Defender, delete if unexpected).' } else { "If you know the file, rename it to the right extension ('$($m.Actual)'); otherwise check where it came from before opening it." }) `
            -Extra ([ordered]@{ extension = $m.Extension; expected = $m.Expected; actual = $m.Actual; modifiedUtc = $fi.LastWriteTimeUtc.ToString('o') })
    }
}
Add-BvsInventory -Run $run -Name 'typeMismatches' -Data @($mism | Where-Object { $_ })

$summary = [ordered]@{
    registryRefs = [ordered]@{}; diskHealth = @($disk | Where-Object { $_ -and $_.category -eq 'disk' } | ForEach-Object { $_.purpose })
    brokenShortcuts = @($lnks | Where-Object { $_ }).Count; incompleteDownloads = @($partial | Where-Object { $_ }).Count; typeMismatches = @($mism | Where-Object { $_ }).Count
    stats = $script:stats; pendingAdmin = @('Storage reliability counters', 'sfc / DISM integrity')
}
foreach ($g in @($refs | Group-Object category)) { $summary.registryRefs[$g.Name] = @($g.Group | ForEach-Object { $_.name }) }
Add-BvsInventory -Run $run -Name 'summary' -Data $summary
$res = Complete-BvsRun -Run $run
Protect-BvsText (($summary | ConvertTo-Json -Depth 4 -Compress))
Protect-BvsText ("H2 done: " + ($res | ConvertTo-Json -Depth 2 -Compress))

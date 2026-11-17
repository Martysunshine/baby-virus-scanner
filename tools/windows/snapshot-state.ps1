#Requires -Version 7.2
<#
.SYNOPSIS  Record security-relevant system state (read-only) so we can prove a scan changed nothing.
.EXAMPLE   pwsh -NoProfile -File tools\windows\snapshot-state.ps1 -Label before
.EXAMPLE   pwsh -NoProfile -File tools\windows\snapshot-state.ps1 -Label after -CompareTo before
#>
[CmdletBinding()]
param([string]$Label = 'before', [string]$CompareTo)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\lib\windows\BVS.Common.psm1') -Force
$scanDir = Get-BvsScanDir

function Get-Lines([scriptblock]$Block) {
    # leading comma stops PowerShell unrolling 0/1-element arrays on return
    try { , [string[]]@(& $Block | ForEach-Object { [string]$_ }) } catch { , [string[]]@("ERROR: $($_.Exception.Message)") }
}
$metaKeys = 'schema', 'label', 'takenUtc'

$runKeys = @(
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
$ifeo = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

$snap = [ordered]@{ schema = 'bvs.snapshot/1'; label = $Label; takenUtc = [datetime]::UtcNow.ToString('o') }
$snap.runKeys = Get-Lines { foreach ($k in $runKeys) { Get-BvsRegValues -Path $k | ForEach-Object { "$k|$($_.Name)|$($_.Value)" } } }
$snap.startupFolders = Get-Lines { foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) { if ($d -and (Test-Path -LiteralPath $d)) { Get-ChildItem -LiteralPath $d -Force | ForEach-Object { "$d|$($_.Name)|$($_.Length)|$($_.LastWriteTimeUtc.ToString('o'))" } } } }
$snap.tasks = Get-Lines { Get-ScheduledTask | ForEach-Object { $a = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '; "$($_.TaskPath)$($_.TaskName)|$a" } }
$snap.services = Get-Lines { Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name)|$($_.StartMode)|$($_.PathName)" } }
$snap.firewallRules = Get-Lines { Get-NetFirewallRule | ForEach-Object { "$($_.Name)|$($_.Enabled)|$($_.Direction)|$($_.Action)|$($_.Profile)" } }
$snap.hosts = Get-Lines { (Get-FileHash -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" -Algorithm SHA256).Hash }
$snap.pathUser = Get-Lines { [Environment]::GetEnvironmentVariable('Path', 'User') -split ';' }
$snap.pathMachine = Get-Lines { [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' }
$snap.rootCerts = Get-Lines {
    foreach ($s in 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\AuthRoot', 'Cert:\LocalMachine\Disallowed', 'Cert:\LocalMachine\TrustedPublisher') { Get-ChildItem $s | ForEach-Object { "$s|$($_.Thumbprint)" } }
    Get-BvsRegSubKeys 'HKCU\Software\Microsoft\SystemCertificates\Root\Certificates' | ForEach-Object { "HKCU-Root|$_" }
}
$snap.localUsers = Get-Lines { Get-LocalUser | ForEach-Object { "$($_.Name)|$($_.Enabled)|$($_.SID)" } }
$snap.wmiSubscription = Get-Lines { foreach ($c in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') { "$c|" + @(Get-CimInstance -Namespace root\subscription -ClassName $c -ErrorAction Stop).Count } }
$snap.winlogon = Get-Lines { Get-BvsRegValues 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Where-Object Name -in 'Shell', 'Userinit', 'Taskman', 'AppSetup' | ForEach-Object { "$($_.Name)|$($_.Value)" } }
$snap.ifeoDebuggers = Get-Lines { foreach ($sk in @(Get-BvsRegSubKeys $ifeo)) { Get-BvsRegValues "$ifeo\$sk" | Where-Object Name -in 'Debugger', 'GlobalFlag' | ForEach-Object { "$sk|$($_.Name)|$($_.Value)" } } }
$snap.avastChest = Get-Lines { $p = Join-Path $env:ProgramData 'Avast Software\Avast\chest\index.xml'; if (Test-Path -LiteralPath $p) { $f = Get-Item -LiteralPath $p; "$($f.Length)|$($f.LastWriteTimeUtc.ToString('o'))|$((Get-FileHash -LiteralPath $p).Hash)" } else { 'absent-or-unreadable' } }
$snap.recycleBin = Get-Lines {
    $sid = (Get-BvsIdentity).User
    foreach ($drv in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' })) {
        $d = Join-Path $drv.Root ('$Recycle.Bin\' + $sid)
        if ([IO.Directory]::Exists($d)) { $files = @(Get-BvsFiles -Path $d -NoPrune); "$($drv.Name)|count=$($files.Count)|bytes=$(($files | Measure-Object Length -Sum).Sum)" }
    }
}
$snap.gitconfig = Get-Lines { $p = Join-Path $env:USERPROFILE '.gitconfig'; if (Test-Path -LiteralPath $p) { (Get-FileHash -LiteralPath $p).Hash } else { 'absent' } }
$snap.claudeSettings = Get-Lines { foreach ($n in 'settings.json', 'settings.local.json') { $p = Join-Path $env:USERPROFILE ".claude\$n"; if (Test-Path -LiteralPath $p) { "$n|$((Get-FileHash -LiteralPath $p).Hash)" } } }

$out = Write-BvsJson -InputObject $snap -Path (Join-Path $scanDir "snapshot-$Label.json")
"snapshot written: $out"
foreach ($k in $snap.Keys) { if ($k -notin $metaKeys) { "  {0,-16} {1} entries" -f $k, @($snap[$k]).Count } }

if ($CompareTo) {
    $old = Get-Content -LiteralPath (Join-Path $scanDir "snapshot-$CompareTo.json") -Raw | ConvertFrom-Json
    "`nDIFF $CompareTo -> $Label"
    $changed = 0
    foreach ($k in $snap.Keys) {
        if ($k -in $metaKeys) { continue }
        $a = @($old.$k); $b = @($snap[$k])
        $added = @($b | Where-Object { $_ -notin $a }); $removed = @($a | Where-Object { $_ -notin $b })
        if ($added.Count -or $removed.Count) {
            $changed++
            "  [$k] +$($added.Count) -$($removed.Count)"
            $added | Select-Object -First 10 | ForEach-Object { "     + $_" }
            $removed | Select-Object -First 10 | ForEach-Object { "     - $_" }
        }
    }
    if (-not $changed) { '  no differences' }
}

#Requires -Version 7.2
<#
.SYNOPSIS  Start a new scan session: creates data\<scanId>\..., scan-meta.json and data\latest.txt.
.OUTPUTS   The new scanId (yyyyMMdd-HHmmss).
#>
[CmdletBinding()]
param([string]$Note = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scanId = [datetime]::Now.ToString('yyyyMMdd-HHmmss')
$dir = Join-Path $root "data\$scanId"
foreach ($d in 'security', 'admin', 'verify', 'inventory', 'storage', 'requests', 'js') { [void][IO.Directory]::CreateDirectory((Join-Path $dir $d)) }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$os = Get-CimInstance Win32_OperatingSystem
$meta = [ordered]@{
    schema        = 'bvs.scan/1'
    scanId        = $scanId
    auditStartUtc = [datetime]::UtcNow.ToString('o')
    host          = $env:COMPUTERNAME
    user          = $env:USERNAME
    userSid       = $id.User.Value
    platform      = 'windows'
    os            = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; language = $os.OSLanguage; installDate = $os.InstallDate; lastBoot = $os.LastBootUpTime }
    elevated      = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    tool          = 'baby-virus-scanner'
    toolVersion   = '0.1.0'
    note          = $Note
}
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $dir 'scan-meta.json'), ($meta | ConvertTo-Json -Depth 5), $utf8)
[IO.File]::WriteAllText((Join-Path $root 'data\latest.txt'), $scanId, $utf8)
$scanId

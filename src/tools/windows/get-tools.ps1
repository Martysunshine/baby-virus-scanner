#Requires -Version 7.2
<#
.SYNOPSIS
    Download the two optional external tools the scanner can use, and verify each one before it is kept.
.DESCRIPTION
    Ask the user before running this. Nothing is installed system-wide and this script runs neither tool.

    -Msert  Microsoft Safety Scanner (msert.exe), from Microsoft's official download link, into
            intel\msert\msert.exe. Kept only if it carries a valid Authenticode signature from
            Microsoft Corporation. It cannot be pinned by hash: Microsoft rebuilds it several times a
            day, and a copy expires 10 days after download, so download it again before each use.
            `bvs.ps1 admin` runs it detect-only (/N) and re-checks hash and signature first.

    -Gh     GitHub CLI, a fixed version, from its official GitHub release, into vendor\gh\. Kept only
            if the archive matches the SHA-256 pinned below and gh.exe carries a valid Authenticode
            signature from GitHub, Inc. Used by the signed-in GitHub checks (S13) with its own
            configuration folder (vendor\gh-config).

    Both folders are git-ignored. Network: go.microsoft.com / Microsoft download servers, and
    github.com release assets. These two downloads are the only time the project fetches a program.
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\tools\windows\get-tools.ps1 -Msert
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\tools\windows\get-tools.ps1 -Gh
#>
[CmdletBinding()]
param([switch]$Msert, [switch]$Gh)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$utf8 = [Text.UTF8Encoding]::new($false)

# Official Microsoft Safety Scanner links (learn.microsoft.com/defender-endpoint/safety-scanner-download).
$MsertUrl = if ([Environment]::Is64BitOperatingSystem) { 'https://go.microsoft.com/fwlink/?LinkId=212732' } else { 'https://go.microsoft.com/fwlink/?LinkId=212733' }

# GitHub CLI release pinned by version and by the SHA-256 values from the release's checksums file.
$GhVersion = '2.102.0'
$GhSha256 = @{
    amd64 = 'ae64e556ecc240b200f7eba60d550e4bb60d78e860e69dd88c449405b86067f4'
    arm64 = '5dcf12aa8525eabd0c46ec414f323ab6cf65229fc2cd46543cc705001bbaf223'
    '386' = '6bb9a59f4dc0de75286e066fd875652958096ec58903a2947a3ba03f9c7db12e'
}

if (-not $Msert -and -not $Gh) {
    Write-Host 'Nothing selected. Use -Msert (Microsoft Safety Scanner) and/or -Gh (GitHub CLI). Ask the user first.'
    exit 1
}

function Test-Signer([string]$File, [string]$SubjectPattern) {
    $sig = Get-AuthenticodeSignature -LiteralPath $File
    [pscustomobject]@{
        Ok      = ($sig.Status -eq 'Valid' -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match $SubjectPattern)
        Status  = [string]$sig.Status
        Subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(unsigned)' }
    }
}
function Get-Download([string]$Url, [string]$Target) {
    # Downloaded next to the target under a temporary name, so a failed or unverified download never replaces a good copy.
    $tmp = "$Target.download"
    if (Test-Path -LiteralPath $tmp) { [IO.File]::Delete($tmp) }
    Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 600
    $tmp
}

$failed = 0

if ($Msert) {
    $dir = Join-Path $root 'intel\msert'; [void][IO.Directory]::CreateDirectory($dir)
    $target = Join-Path $dir 'msert.exe'
    Write-Host 'Microsoft Safety Scanner: downloading from Microsoft (about 200 MB) ...'
    try {
        $tmp = Get-Download $MsertUrl $target
        $s = Test-Signer $tmp 'O=Microsoft Corporation'
        if (-not $s.Ok) {
            [IO.File]::Delete($tmp)
            throw "the download is not validly signed by Microsoft Corporation (status: $($s.Status); signer: $($s.Subject)). Nothing was kept."
        }
        [IO.File]::Move($tmp, $target, $true)
        $info = Get-Item -LiteralPath $target
        Write-Host ('  kept:    {0}  ({1:N0} MB)' -f $target, ($info.Length / 1MB))
        Write-Host ('  signer:  {0}' -f $s.Subject)
        Write-Host ('  version: {0}' -f $info.VersionInfo.ProductVersion)
        Write-Host ('  SHA-256: {0}' -f (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash)
        Write-Host '  It expires 10 days after download. Run it only through: bvs.ps1 admin (detect-only, never removes anything).'
    }
    catch { Write-Host "ERROR (Safety Scanner): $($_.Exception.Message)"; $failed++ }
}

if ($Gh) {
    $arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) { 'Arm64' { 'arm64' } 'X86' { '386' } default { 'amd64' } }
    $zipName = "gh_${GhVersion}_windows_$arch.zip"
    $url = "https://github.com/cli/cli/releases/download/v$GhVersion/$zipName"
    $vendor = Join-Path $root 'vendor'; $dest = Join-Path $vendor 'gh'; [void][IO.Directory]::CreateDirectory($vendor)
    $exe = Join-Path $dest 'bin\gh.exe'
    try {
        $have = (Test-Path -LiteralPath $exe) -and (Test-Signer $exe 'O="?GitHub, Inc\.').Ok -and ((Get-Item -LiteralPath $exe).VersionInfo.ProductVersion -eq $GhVersion)
        if ($have) { Write-Host "GitHub CLI $GhVersion is already present and validly signed: $exe" }
        else {
            Write-Host "GitHub CLI ${GhVersion}: downloading $zipName from github.com (about 15 MB) ..."
            $zip = Join-Path $vendor $zipName
            $tmp = Get-Download $url $zip
            $hash = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($hash -ne $GhSha256[$arch]) {
                [IO.File]::Delete($tmp)
                throw "the archive does not match the pinned SHA-256 (got $hash). Nothing was kept."
            }
            Expand-Archive -LiteralPath $tmp -DestinationPath $dest -Force
            [IO.File]::Delete($tmp)
            $s = Test-Signer $exe 'O="?GitHub, Inc\.'
            if (-not $s.Ok) { throw "gh.exe is not validly signed by GitHub, Inc. (status: $($s.Status); signer: $($s.Subject)). The scanner will refuse to run it." }
            Write-Host "  kept:    $exe"
            Write-Host "  signer:  $($s.Subject)"
            Write-Host "  archive SHA-256 matches the pinned value for $zipName"
        }
        Write-Host '  Sign in (the user does this, in the browser): pwsh -NoProfile -File .\bvs.ps1 github-login'
    }
    catch { Write-Host "ERROR (GitHub CLI): $($_.Exception.Message)"; $failed++ }
}

exit ([int]($failed -gt 0))

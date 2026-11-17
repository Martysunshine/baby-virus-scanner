#Requires -Version 7.2
<# Self-test for lib\windows\BVS.Common.psm1. Uses synthetic fake secrets built at runtime. Read-only. #>
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\lib\windows\BVS.Common.psm1') -Force
$pass = 0; $fail = 0
function Assert([string]$Name, [bool]$Cond, [string]$Detail = '') {
    if ($Cond) { $script:pass++; "  PASS $Name" } else { $script:fail++; "  FAIL $Name $Detail" }
}

'masking'
$fakeNpm = 'npm_' + ('A1b2C3d4E5f6' * 3)
$fakeGh = 'ghp_' + ('Z9y8X7w6V5u4' * 3)
$fakeAnt = 'sk-ant-api03-' + ('q' * 40)
$fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.' + ('s' * 30)
$pem = "-----BEGIN OPENSSH PRIVATE KEY-----`nb3BlbnNzaC1rZXktdjEAAAAA`n-----END OPENSSH PRIVATE KEY-----"
$text = "token=$fakeNpm gh=$fakeGh key: $fakeAnt jwt $fakeJwt url https://bob:SuperSecret123@example.com/x $pem --password Hunter2Hunter2 PasswordLastSet=2025-01-02T10:00:00 path=C:\Users\x\AppData"
$masked = Protect-BvsText $text
Assert 'npm masked' ($masked -notmatch [regex]::Escape($fakeNpm))
Assert 'github masked' ($masked -notmatch [regex]::Escape($fakeGh))
Assert 'anthropic masked' ($masked -notmatch [regex]::Escape($fakeAnt))
Assert 'jwt masked' ($masked -notmatch 's{30}')
Assert 'url password masked' ($masked -notmatch 'SuperSecret123')
Assert 'pem masked' ($masked -notmatch 'b3BlbnNzaC1rZXktdjEAAAAA')
Assert 'cli password masked' ($masked -notmatch 'Hunter2Hunter2')
Assert 'date kept' ($masked -match '2025-01-02T10:00:00')
Assert 'path kept' ($masked -match 'C:\\Users\\x\\AppData')
$hits = @(Find-BvsSecrets $text)
Assert 'find secrets returns hits' ($hits.Count -ge 5) "($($hits.Count))"
Assert 'json masking via Write-BvsJson path guard' ($(try { Write-BvsJson -InputObject @{a = 1 } -Path 'C:\Windows\Temp\x.json'; $false } catch { $true }))

'files and signatures'
$np = Join-Path $env:SystemRoot 'System32\notepad.exe'
if (-not (Test-Path $np)) { $np = Join-Path $env:SystemRoot 'notepad.exe' }
$sig = Get-BvsSignature $np
Assert 'notepad signed' ($sig.Status -eq 'Valid') "($($sig.Status) $($sig.Signer))"
Assert 'notepad magic pe' ((Get-BvsMagic $np).Type -eq 'pe')
Assert 'hash 64 hex' ((Get-BvsHash $np) -match '^[0-9a-f]{64}$')
Assert 'System32 not user-writable' (-not (Test-BvsUserWritable (Join-Path $env:SystemRoot 'System32')))
Assert 'TEMP user-writable' (Test-BvsUserWritable $env:TEMP)
Assert 'never-read login data' (Test-BvsNeverRead 'C:\Users\x\AppData\Local\Google\Chrome\User Data\Default\Login Data')
Assert 'never-read ssh private key' (Test-BvsNeverRead 'C:\Users\x\.ssh\id_ed25519')
Assert 'ssh pub readable' (-not (Test-BvsNeverRead 'C:\Users\x\.ssh\id_ed25519.pub'))
$some = @(Get-BvsFiles -Path (Join-Path $env:SystemRoot 'System32\drivers\etc') -MaxDepth 0)
Assert 'enumeration finds hosts' (($some | Where-Object Name -eq 'hosts').Count -eq 1)

'registry and command lines'
$lw = Get-BvsRegKeyLastWrite 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Assert 'run key lastwrite' ($lw -is [datetime]) "($lw)"
$r = Resolve-BvsCommandLine 'rundll32.exe "C:\Users\x\AppData\Roaming\evil.dll",Start'
Assert 'rundll32 target' ($r.Target -eq 'C:\Users\x\AppData\Roaming\evil.dll') "($($r.Target))"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output hello'))
$r2 = Resolve-BvsCommandLine "powershell.exe -NoP -W Hidden -EncodedCommand $enc"
Assert 'encoded command decoded' ($r2.DecodedCommand -eq 'Write-Output hello') "($($r2.DecodedCommand))"
Assert 'process table' (@(Get-BvsProcessTable).Count -gt 20)

"`nRESULT: $pass passed, $fail failed"
if ($fail) { exit 1 }

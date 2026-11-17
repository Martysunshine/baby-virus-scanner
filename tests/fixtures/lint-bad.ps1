# Fixture for src\tools\windows\check-collector.ps1 - every line below must be flagged. NEVER RUN THIS FILE.
Remove-Item C:\temp\x
reg add HKCU\Software\X /v Y /d Z
schtasks /create /tn evil /tr calc.exe
git checkout main
git status
gh api -X DELETE repos/a/b
Invoke-WebRequest https://example.com
[IO.File]::WriteAllText('C:\Windows\Temp\x.txt', 'x')
$shortcut.Save()
npm ls -g
Start-Process notepad -Verb RunAs
"hello" > C:\temp\out.txt

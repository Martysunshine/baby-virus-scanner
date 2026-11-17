#Requires -Version 7.2
<#
.SYNOPSIS
    baby-virus-scanner command-line entry point (Windows).
.DESCRIPTION
    Start here
      doctor                      check that this PC can run the scanner; changes nothing
      scan [-Lan] [-Parallel N] [-Resume] [-Background]
                                  the whole read-only scan in one command (order below)
      status                      what the current scan has produced so far, and its verdict
      report                      aggregate + verdict + dashboard data (Python); prints the verdict
      dashboard                   serve the local dashboard for the current scan (http://127.0.0.1:8777)
      demo [-NoBrowser]           open the dashboard on synthetic demo data; no scan needed

    Single steps, in the order `scan` runs them
      new [-Note text]            start a scan session (data\<scanId>)
      snapshot <label>            record system state; 'after' is compared with 'before'
      inventory [-Path <folder>]  file-system metadata pass (G0); -Path limits it to one folder (test mode)
      security [-Only S01,S07] [-Parallel N] [-Lan]
                                  security collectors; each is linted first
      storage [-Only G1,H1]       storage / programs / health collectors (need inventory)

    Optional extras. Ask the user first; each one is off unless you run it
      get-tools [-Msert] [-Gh]    download Microsoft Safety Scanner and/or GitHub CLI; signatures are verified
      admin [-FullScan]           ONE Windows admin prompt: elevated read-only checks + Safety Scanner quick pass
                                  (/N, report-only). -FullScan adds the full pass, which can take hours
      github-login                sign in to GitHub in the browser for the account checks (S13)
      github-logout               remove that sign-in again

    Maintenance
      selftest                    library self-test
      lint                        safety-lint every collector
      check-publish               privacy check of the files git would publish

    Nothing here deletes or changes the system; collectors are read-only and linted.
    -Lan allows active discovery on the local network (ping sweep, router queries). Without it the
    LAN module only reads this PC's own ARP cache.
    Module runs print one status line each. What the modules themselves print describes this PC, so
    it goes to logs\bvs-console.log; add -ShowOutput to see it on screen too.
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 doctor
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 scan -Parallel 4
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][ValidateSet('help', 'doctor', 'scan', 'status', 'report', 'dashboard', 'demo', 'new', 'snapshot', 'inventory',
        'security', 'storage', 'get-tools', 'admin', 'github-login', 'github-logout', 'selftest', 'lint', 'check-publish')][string]$Command = 'help',
    [Parameter(Position = 1)][string]$Arg,
    [string[]]$Only,
    [ValidateRange(1, 16)][int]$Parallel = 1,
    [string]$Note = '',
    [string[]]$Path,
    [switch]$Lan,
    [switch]$Resume,
    [switch]$Background,
    [switch]$ShowOutput,
    [switch]$FullScan,
    [switch]$SkipFullScan,   # accepted for older commands; the full pass is now opt-in (-FullScan)
    [switch]$Msert,
    [switch]$Gh,
    [switch]$NoBrowser
)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$pwshExe = Join-Path $PSHOME 'pwsh.exe'
$ResumeMaxHours = 6

#region ---------- helpers ----------
# `pwsh -File` passes "a,b" as ONE string, so lists are split here.
function Split-List($Values) { @(@($Values) | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

function Get-ScanDir {
    $latest = Join-Path $Root 'data\latest.txt'
    if (-not (Test-Path -LiteralPath $latest)) { throw 'No scan yet. Run: pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 scan' }
    Join-Path $Root ('data\' + (Get-Content -LiteralPath $latest -Raw).Trim())
}

# Python 3: $env:BVS_PYTHON, else the py launcher, else python.exe (never the Microsoft Store alias).
function Get-PythonCommand {
    if ($env:BVS_PYTHON -and (Test-Path -LiteralPath $env:BVS_PYTHON)) { return , @($env:BVS_PYTHON) }
    $py = Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($py) { return , @($py.Source, '-3') }
    foreach ($n in 'python.exe', 'python3.exe') {
        $c = Get-Command $n -CommandType Application -All -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch '\\WindowsApps\\' } | Select-Object -First 1
        if ($c) { return , @($c.Source) }
    }
    return $null
}
function Invoke-Python {
    $cmd = Get-PythonCommand
    if (-not $cmd) { throw 'Python 3 not found (needed for report, dashboard and demo). Install Python 3.9 or newer, or set $env:BVS_PYTHON to python.exe.' }
    $exe = $cmd[0]; $pre = @($cmd | Select-Object -Skip 1) + @('-I', '-B')
    & $exe @pre @args
}

function Get-ModuleId([string]$Script) { if ([IO.Path]::GetFileName($Script) -match '^([A-Z]\d{1,2})-') { $Matches[1] } }
function Get-ModuleOutput([string]$ScanDir, [string]$Script) {
    $id = Get-ModuleId $Script
    if (-not $id) { return $null }
    $area = if ($id -like 'S*') { 'security' } elseif ($id -eq 'G0') { 'inventory' } else { 'storage' }
    Join-Path $ScanDir "$area\$id.json"
}

function Get-Collectors([string]$Dir, [string]$Pattern) {
    if (-not (Test-Path -LiteralPath $Dir)) { return @() }
    $all = @(Get-ChildItem -LiteralPath $Dir -Filter '*.ps1' | Where-Object { $_.Name -match $Pattern } | Sort-Object Name)
    $want = Split-List $Only
    if ($want.Count) {
        $all = @($all | Where-Object { $n = $_.Name; @($want | Where-Object { $n -like "$_*" }).Count -gt 0 })
        if (-not $all.Count) { throw "No collector in $Dir matches -Only $($want -join ',')" }
    }
    @($all.FullName)
}

# The LAN module is passive unless the user agreed to active discovery (-Lan).
function Get-CollectorArgs([string]$Script) { if ($Lan -and (Get-ModuleId $Script) -eq 'S08') { @('-Active') } else { @() } }

$script:Failed = [System.Collections.Generic.List[string]]::new()
$script:ConsoleLog = Join-Path $Root 'logs\bvs-console.log'

# What a collector prints describes this PC (adapter, network name, counts). It goes to a local log file, and
# the console gets one status line per module, so an AI agent running this does not receive those details
# unless the user agreed. -ShowOutput prints them as well.
function Write-ModuleResult([string]$Name, [bool]$Ok, [string]$Why, [double]$Seconds, $Output) {
    try {
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $script:ConsoleLog))
        $head = '===== {0:o}  {1}  {2}' -f [datetime]::Now, $Name, $Why
        [IO.File]::AppendAllLines($script:ConsoleLog, [string[]](@($head) + @($Output | ForEach-Object { "$_" })), [Text.UTF8Encoding]::new($false))
    }
    catch { }
    Write-Host ('==> {0,-28} {1,-22} {2,5:N0} s' -f $Name, $(if ($Ok) { 'ok' } else { "FAILED ($Why)" }), $Seconds)
    if ($ShowOutput) { @($Output) | ForEach-Object { Write-Host "    $_" } }
    if (-not $Ok) { $script:Failed.Add("$Name ($Why)") }
}
function Invoke-Collector([string]$Script) {
    $name = [IO.Path]::GetFileName($Script); $sw = [Diagnostics.Stopwatch]::StartNew()
    $lint = & $pwshExe -NoProfile -File (Join-Path $Root 'src\tools\windows\check-collector.ps1') -Path $Script 2>&1
    if ($LASTEXITCODE -ne 0) { Write-ModuleResult $name $false 'lint' $sw.Elapsed.TotalSeconds $lint; return }
    $extra = Get-CollectorArgs $Script
    $out = & $pwshExe -NoProfile -ExecutionPolicy Bypass -File $Script @extra 2>&1
    Write-ModuleResult $name ($LASTEXITCODE -eq 0) "exit $LASTEXITCODE" $sw.Elapsed.TotalSeconds $out
}
function Invoke-Collectors([string[]]$Scripts, [int]$Throttle = 1) {
    if (-not $Scripts.Count) { return }
    if ($Throttle -le 1) { foreach ($s in $Scripts) { Invoke-Collector $s }; return }
    $jobs = @($Scripts | ForEach-Object { [pscustomobject]@{ Script = $_; Extra = @(Get-CollectorArgs $_) } })
    $results = $jobs | ForEach-Object -ThrottleLimit $Throttle -Parallel {
        $r = $using:Root; $p = $using:pwshExe; $name = [IO.Path]::GetFileName($_.Script); $extra = @($_.Extra); $sw = [Diagnostics.Stopwatch]::StartNew()
        $lint = & $p -NoProfile -File (Join-Path $r 'src\tools\windows\check-collector.ps1') -Path $_.Script 2>&1
        if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ Name = $name; Ok = $false; Why = 'lint'; Seconds = $sw.Elapsed.TotalSeconds; Output = @($lint) } }
        $out = & $p -NoProfile -ExecutionPolicy Bypass -File $_.Script @extra 2>&1
        [pscustomobject]@{ Name = $name; Ok = ($LASTEXITCODE -eq 0); Why = "exit $LASTEXITCODE"; Seconds = $sw.Elapsed.TotalSeconds; Output = @($out) }
    }
    foreach ($x in @($results | Sort-Object Name)) { Write-ModuleResult $x.Name $x.Ok $x.Why $x.Seconds $x.Output }
}

function Invoke-Snapshot([string]$Label) {
    $extra = if ($Label -ne 'before') { @('-CompareTo', 'before') } else { @() }
    & $pwshExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'src\tools\windows\snapshot-state.ps1') -Label $Label @extra
}

# The elevated script writes raw section files (bvs.admin/1) that the aggregator does not read. This turns its
# admin-meta.json into the coverage envelope admin\X1.json: one check per section, no findings. It never
# replaces an existing X1.json, so findings a reviewer added there are kept (docs\agent\admin-triage.md).
function Update-AdminSummary([string]$ScanDir) {
    $dir = Join-Path $ScanDir 'admin'; $metaFile = Join-Path $dir 'admin-meta.json'; $x1 = Join-Path $dir 'X1.json'
    if (-not (Test-Path -LiteralPath $metaFile) -or (Test-Path -LiteralPath $x1)) { return }
    $m = Get-Content -LiteralPath $metaFile -Raw | ConvertFrom-Json
    $checks = @(foreach ($p in $m.sections.PSObject.Properties) {
            [ordered]@{
                id = 'admin.' + ($p.Name -replace '-', '_'); description = "Elevated read-only check: $($p.Name)"; status = [string]$p.Value.status
                reason = $p.Value.error; items = $null; ms = [int]([double]$p.Value.seconds * 1000)
            }
        })
    $envelope = [ordered]@{
        schema = 'bvs.module/1'; module = 'X1'; area = 'admin'; scanId = (Split-Path -Leaf $ScanDir); host = $m.host; platform = 'windows'
        elevated = [bool]$m.elevated; started = $m.started; finished = $m.finished; checks = $checks; findings = @()
        inventory = [ordered]@{ note = 'Coverage only, written by bvs.ps1 from admin-meta.json. The raw section files next to this file hold the data.'; sections = @($m.sections.PSObject.Properties.Name) }
        errors = @()
    }
    [IO.File]::WriteAllText($x1, ($envelope | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Write-Host "admin: wrote $x1 ($($checks.Count) checks)"
}

function Invoke-Report([string]$ScanDir) {
    Update-AdminSummary $ScanDir
    Invoke-Python (Join-Path $Root 'src\core\build_datajs.py') --scan $ScanDir | Out-Host   # runs the aggregator first
    if ($LASTEXITCODE -ne 0) { throw "report failed (build_datajs.py exit $LASTEXITCODE)" }
}

# Verdict, counts and everything the aggregator could not use. Numbers and file names only: finding
# titles and evidence are untrusted text and are never printed here.
function Show-Summary([string]$ScanDir) {
    $f = Join-Path $ScanDir 'summary.json'
    if (-not (Test-Path -LiteralPath $f)) { Write-Host 'No report yet. Run: pwsh -NoProfile -File .\bvs.ps1 report'; return $null }
    $s = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json -Depth 64
    $fmt = { param($o) if ($o) { @($o.PSObject.Properties | Where-Object { $_.Value } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ' } else { '' } }
    Write-Host ''
    Write-Host ("VERDICT: {0}   (confidence: {1})" -f $s.verdict, $s.confidence.level)
    Write-Host ("  {0}" -f $s.verdictMeaning)
    if ($s.verdictSource -ne 'computed') {
        Write-Warning ("The verdict was set by hand (verdict-override.json, by '{0}'). The rubric computed: {1}." -f $s.override.by, $s.computedVerdict)
    }
    Write-Host ("  findings still open: {0}" -f (& $fmt $s.counts.bySeverityActive))
    Write-Host ("  checks:              {0}" -f (& $fmt $s.coverage.byStatus))
    if (@($s.coverage.missingModules).Count) { Write-Host ("  modules not run:     {0}" -f (@($s.coverage.missingModules) -join ', ')) }
    # Raw admin section files are the input for admin\X1.json by design, so they are not listed here.
    foreach ($u in @($s.coverage.unrecognizedFiles | Where-Object { $_.file -notmatch '^admin[\\/]' })) { Write-Warning "not used by the report (not a bvs.module/1 envelope): $($u.file)" }
    foreach ($u in @($s.coverage.parseErrors)) { Write-Warning "not used by the report (invalid JSON): $($u.file)" }
    foreach ($u in @($s.coverage.orphanVerifications)) { Write-Warning "verification record matches no finding: $($u.source) -> $($u.ref)" }
    foreach ($w in @($s.warnings)) { Write-Warning "$w" }
    $s
}

function Write-ScanStatus([string]$ScanDir, [hashtable]$State) {
    $State.updatedAt = [datetime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText((Join-Path $ScanDir 'scan-status.json'), ($State | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
}

# Asks GitHub CLI itself (with the scanner's own settings folder). Its settings file stays after a sign-out,
# so the file's existence says nothing. Prints nothing; the token is never read.
function Test-GhSignedIn {
    $exe = Join-Path $Root 'vendor\gh\bin\gh.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return $false }
    $saved = $env:GH_CONFIG_DIR
    try {
        $env:GH_CONFIG_DIR = Join-Path $Root 'vendor\gh-config'
        $null = & $exe auth status --hostname github.com 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    catch { return $false }
    finally { $env:GH_CONFIG_DIR = $saved }
}

function Get-GhExe {
    $exe = Join-Path $Root 'vendor\gh\bin\gh.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw "GitHub CLI is not installed for the scanner ($exe). After the user agrees, run: pwsh -NoProfile -File .\bvs.ps1 get-tools -Gh" }
    $sig = Get-AuthenticodeSignature -LiteralPath $exe
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O="?GitHub, Inc\.') { throw "gh.exe signature is not a valid GitHub signature ($($sig.Status)). Refusing to run it." }
    $exe
}
#endregion

try {
switch ($Command) {
    'doctor' {
        $bad = 0; $warn = 0
        $line = { param($State, $Name, $Detail) '{0,-6} {1,-22} {2}' -f "[$State]", $Name, $Detail | Write-Host }
        $os = [Environment]::OSVersion.Version
        if ($IsWindows -and $os.Major -ge 10) { & $line 'ok' 'Windows' "build $($os.Build)" } else { & $line 'FAIL' 'Windows' 'Windows 10 or 11 is required'; $bad++ }
        $v = $PSVersionTable.PSVersion
        if ($v -ge [version]'7.4') { & $line 'ok' 'PowerShell' "$v" } else { & $line 'warn' 'PowerShell' "$v works, but 7.4 or newer is recommended (one npm check needs it)"; $warn++ }
        $py = Get-PythonCommand
        if (-not $py) { & $line 'FAIL' 'Python 3' 'not found. Install Python 3.9+ (python.org) or set $env:BVS_PYTHON. Needed for the report and the dashboard'; $bad++ }
        else {
            $exe = $py[0]; $pre = @($py | Select-Object -Skip 1)
            $pv = (& $exe @pre -I -B -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null | Select-Object -First 1)
            if ($pv -and [version]$pv -ge [version]'3.9') { & $line 'ok' 'Python 3' "$pv ($exe)" } else { & $line 'FAIL' 'Python 3' "found $pv at $exe, but 3.9 or newer is required"; $bad++ }
        }
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if (([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { & $line 'warn' 'Not elevated' 'this terminal runs as administrator. Run the scan from a normal terminal; only `admin` elevates, with its own prompt'; $warn++ }
        else { & $line 'ok' 'Not elevated' 'normal user rights (the scan does not need admin)' }
        if (Get-Item -LiteralPath $PSCommandPath -Stream Zone.Identifier -ErrorAction SilentlyContinue) { & $line 'warn' 'Downloaded files' 'these files carry the "downloaded from the internet" mark (ZIP download). Use `git clone`, or always start with -ExecutionPolicy Bypass as shown in the README'; $warn++ }
        try {
            $probe = Join-Path $Root ('data\.write-test-' + [guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory((Join-Path $Root 'data')); [IO.File]::WriteAllText($probe, 'x'); [IO.File]::Delete($probe)
            $free = [math]::Round((Get-PSDrive -Name $Root.Substring(0, 1)).Free / 1GB, 1)
            if ($free -lt 2) { & $line 'warn' 'Project folder' "writable, but only $free GB free (a scan writes up to a few hundred MB under data\)"; $warn++ } else { & $line 'ok' 'Project folder' "writable, $free GB free" }
        }
        catch { & $line 'FAIL' 'Project folder' "cannot write under data\: $($_.Exception.Message)"; $bad++ }
        if (Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue) { & $line 'ok' 'git' 'found (used read-only to check copies of code projects)' } else { & $line 'info' 'git' 'not found: the duplicate-project check will be skipped' }
        # Note: $Msert and $Gh are this script's switches, so local paths need other names.
        $msertPath = Join-Path $Root 'intel\msert\msert.exe'
        if (Test-Path -LiteralPath $msertPath) {
            $age = [math]::Floor(([datetime]::Now - (Get-Item -LiteralPath $msertPath).LastWriteTime).TotalDays)
            if ($age -gt 10) { & $line 'info' 'Safety Scanner' "present but $age days old (Microsoft expires it after 10). Optional: get-tools -Msert" } else { & $line 'ok' 'Safety Scanner' "present, $age day(s) old (optional, used by the admin step)" }
        }
        else { & $line 'info' 'Safety Scanner' 'not downloaded. Optional, only for the admin step: get-tools -Msert (ask the user first)' }
        $ghPath = Join-Path $Root 'vendor\gh\bin\gh.exe'
        if (Test-Path -LiteralPath $ghPath) { & $line 'ok' 'GitHub CLI' ('present (optional, for the signed-in GitHub checks). Signed in: ' + $(if (Test-GhSignedIn) { 'yes' } else { 'no' })) }
        else { & $line 'info' 'GitHub CLI' 'not downloaded. Optional, only for signed-in GitHub checks: get-tools -Gh (ask the user first)' }
        if (Get-Command claude -ErrorAction SilentlyContinue) { & $line 'ok' 'Claude CLI' 'found (optional: AI answers in the dashboard, only after the user opts in)' } else { & $line 'info' 'Claude CLI' 'not found: the dashboard uses its built-in explanations' }
        $latest = Join-Path $Root 'data\latest.txt'
        if (Test-Path -LiteralPath $latest) { & $line 'info' 'Latest scan' (Get-Content -LiteralPath $latest -Raw).Trim() } else { & $line 'info' 'Latest scan' 'none yet' }
        Write-Host ''
        if ($bad) { Write-Host "NOT READY: $bad problem(s) above must be fixed first."; exit 1 }
        Write-Host ("READY" + $(if ($warn) { " ($warn warning(s) above)" } else { '' }) + '. Next: pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 scan')
        exit 0
    }

    'scan' {
        if ($Background) {
            $logDir = Join-Path $Root 'logs'; [void][IO.Directory]::CreateDirectory($logDir)
            $log = Join-Path $logDir ('scan-' + [datetime]::Now.ToString('yyyyMMdd-HHmmss') + '.log')
            $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", 'scan', '-Parallel', "$Parallel")
            if ($Lan) { $a += '-Lan' }; if ($Resume) { $a += '-Resume' }
            $p = Start-Process -FilePath $pwshExe -ArgumentList $a -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru
            Write-Host "Scan started in the background (process $($p.Id)). It takes roughly 15 to 40 minutes."
            Write-Host 'Progress:  pwsh -NoProfile -File .\bvs.ps1 status'
            Write-Host "Log:       $log"
            exit 0
        }
        if (-not (Get-PythonCommand)) { throw 'Python 3 not found. Run `bvs.ps1 doctor` first.' }
        if ($Resume) {
            $scan = Get-ScanDir
            $meta = Get-Content -LiteralPath (Join-Path $scan 'scan-meta.json') -Raw | ConvertFrom-Json
            $ageH = ([datetime]::UtcNow - ([datetime]$meta.auditStartUtc).ToUniversalTime()).TotalHours
            # Events after the scan start are treated as the scanner's own activity, so an old session must not be continued.
            if ($ageH -gt $ResumeMaxHours) { throw ("This scan started {0:N1} hours ago. Scans older than {1} hours are not resumed; start a new one without -Resume." -f $ageH, $ResumeMaxHours) }
        }
        else {
            $null = & $pwshExe -NoProfile -File (Join-Path $Root 'src\tools\windows\new-scan.ps1') -Note $Note
            if ($LASTEXITCODE -ne 0) { throw 'could not start a scan session' }
            $scan = Get-ScanDir
        }
        Write-Host "scan: $scan  (LAN discovery: $(if ($Lan) { 'active, user agreed' } else { 'passive only' }))"
        $st = @{ schema = 'bvs.scanstatus/1'; scanId = (Split-Path -Leaf $scan); state = 'running'; step = ''; pid = $PID; startedAt = [datetime]::UtcNow.ToString('o'); lanActive = [bool]$Lan; verdict = $null; failed = @() }
        $todo = { param([string[]]$Scripts) if ($Resume) { @($Scripts | Where-Object { -not (Test-Path -LiteralPath (Get-ModuleOutput $scan $_)) }) } else { $Scripts } }
        try {
            $st.step = 'snapshot before'; Write-ScanStatus $scan $st
            if (-not ($Resume -and (Test-Path -LiteralPath (Join-Path $scan 'snapshot-before.json')))) {
                $snap = Invoke-Snapshot 'before'
                if ($ShowOutput) { $snap | Out-Host }
                Write-Host '==> snapshot before              recorded'
            }

            # Inventory first: S02 cross-checks it, and the storage modules need it.
            $st.step = 'inventory'; Write-ScanStatus $scan $st
            Invoke-Collectors (& $todo @(Join-Path $Root 'src\collectors\inventory\windows\G0-inventory.ps1')) 1

            $st.step = 'security'; Write-ScanStatus $scan $st
            Invoke-Collectors (& $todo (Get-Collectors (Join-Path $Root 'src\collectors\security\windows') '^S\d\d-.*\.ps1$')) $Parallel

            $st.step = 'report (security)'; Write-ScanStatus $scan $st
            Invoke-Report $scan
            $sum = Get-Content -LiteralPath (Join-Path $scan 'summary.json') -Raw | ConvertFrom-Json -Depth 64
            $st.verdict = $sum.verdict

            if ($sum.verdict -eq 'COMPROMISED') {
                # Gate (docs\METHODOLOGY.md): storage and clean-up wait until a compromise is dealt with.
                $st.step = 'stopped: verdict gate'
            }
            else {
                $st.step = 'storage'; Write-ScanStatus $scan $st
                Invoke-Collectors (& $todo (Get-Collectors (Join-Path $Root 'src\collectors\storage\windows') '^[GH]\d-.*\.ps1$')) 1
                $st.step = 'report'; Write-ScanStatus $scan $st
                Invoke-Report $scan
            }

            $st.step = 'snapshot after'; Write-ScanStatus $scan $st
            $diff = Invoke-Snapshot 'after'
            if ($ShowOutput) { $diff | Out-Host }
            [IO.File]::WriteAllLines((Join-Path $scan 'snapshot-diff.txt'), [string[]]@($diff | ForEach-Object { "$_" }), [Text.UTF8Encoding]::new($false))
            Write-Host "==> snapshot after               comparison saved: $(Join-Path $scan 'snapshot-diff.txt')"
        }
        catch {
            $st.state = 'failed'; $st.failed = @($script:Failed) + @("$($_.Exception.Message)"); Write-ScanStatus $scan $st
            Write-Warning "scan failed at step '$($st.step)': $($_.Exception.Message)"
            exit 1
        }
        $st.failed = @($script:Failed)
        $st.state = if ($st.verdict -eq 'COMPROMISED') { 'stopped_at_gate' } elseif ($script:Failed.Count) { 'done_with_errors' } else { 'done' }
        $st.step = 'finished'; Write-ScanStatus $scan $st
        $null = Show-Summary $scan
        Write-Host ''
        if ($script:Failed.Count) { Write-Warning ("collectors that did not finish: " + ($script:Failed -join ', ')) }
        if ($st.verdict -eq 'COMPROMISED') {
            Write-Host 'STOPPED AT THE VERDICT GATE. Storage and clean-up are skipped. Do not delete anything. See AGENTS.md, "If the verdict is COMPROMISED".'
            exit 2
        }
        Write-Host 'Scan finished. Next: pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 dashboard   (or double-click start-dashboard.cmd)'
        exit ([int]($script:Failed.Count -gt 0))
    }

    'status' {
        $scan = Get-ScanDir
        "scan: $scan"
        foreach ($area in 'security', 'admin', 'verify', 'inventory', 'storage') {
            $d = Join-Path $scan $area
            $files = if (Test-Path -LiteralPath $d) { @(Get-ChildItem -LiteralPath $d -Filter '*.json' -File | Select-Object -ExpandProperty Name) } else { @() }
            '  {0,-10} {1}' -f $area, ($files -join ', ')
        }
        $stFile = Join-Path $scan 'scan-status.json'
        if (Test-Path -LiteralPath $stFile) {
            $s = Get-Content -LiteralPath $stFile -Raw | ConvertFrom-Json
            $alive = if ($s.state -eq 'running') { if (Get-Process -Id $s.pid -ErrorAction SilentlyContinue) { '' } else { '  (its process is gone: run `scan -Resume`)' } } else { '' }
            "  state:     $($s.state), step: $($s.step)$alive"
            if (@($s.failed).Count) { '  failed:    ' + (@($s.failed) -join ', ') }
        }
        $el = Join-Path $scan 'admin\elevated-status.json'
        if (Test-Path -LiteralPath $el) { '  elevated:  ' + ((Get-Content -LiteralPath $el -Raw | ConvertFrom-Json).current) }
        if (Test-Path -LiteralPath (Join-Path $scan 'summary.json')) { $null = Show-Summary $scan }
    }

    'report' { $scan = Get-ScanDir; Invoke-Report $scan; $null = Show-Summary $scan }

    'dashboard' {
        $scan = Get-ScanDir
        if (-not (Test-Path -LiteralPath (Join-Path $scan 'js\manifest.js'))) { Invoke-Report $scan }
        Write-Host 'Dashboard (this PC only). Stop it with Ctrl+C.'
        Invoke-Python (Join-Path $Root 'src\server\serve.py') --scan $scan
    }

    'demo' {
        # Synthetic data only (tests\fixtures\demo-scan). It is copied under data\ so the tracked fixture is never rewritten.
        $src = Join-Path $Root 'tests\fixtures\demo-scan'; $dst = Join-Path $Root 'data\demo-scan'
        [void][IO.Directory]::CreateDirectory($dst)
        foreach ($f in Get-ChildItem -LiteralPath $src -Recurse -File | Where-Object { $_.FullName -notmatch '\\js\\' -and $_.Name -ne 'summary.json' }) {
            $to = Join-Path $dst $f.FullName.Substring($src.Length + 1)
            [void][IO.Directory]::CreateDirectory((Split-Path -Parent $to)); [IO.File]::Copy($f.FullName, $to, $true)
        }
        Invoke-Report $dst
        Write-Host 'Demo dashboard on synthetic data (host DEMO-PC). AI answers are off. Stop it with Ctrl+C.'
        $state = Join-Path $dst 'state'; [void][IO.Directory]::CreateDirectory($state)   # keeps demo clicks apart from real scans
        $serve = @((Join-Path $Root 'src\server\serve.py'), '--scan', $dst, '--no-ai', '--state-root', $state)
        if (-not $NoBrowser) { $serve += '--open' }
        Invoke-Python @serve
    }

    'new' { & $pwshExe -NoProfile -File (Join-Path $Root 'src\tools\windows\new-scan.ps1') -Note $Note }
    'snapshot' { Invoke-Snapshot $(if ($Arg) { $Arg } else { 'before' }) }

    'inventory' {
        $g0 = Join-Path $Root 'src\collectors\inventory\windows\G0-inventory.ps1'
        $lint = & $pwshExe -NoProfile -File (Join-Path $Root 'src\tools\windows\check-collector.ps1') -Path $g0
        if ($LASTEXITCODE -ne 0) { $lint; throw 'G0 failed lint' }
        $paths = Split-List $Path
        if ($paths.Count) { & $pwshExe -NoProfile -ExecutionPolicy Bypass -File $g0 -Path ($paths -join ',') } else { & $pwshExe -NoProfile -ExecutionPolicy Bypass -File $g0 }
        exit $LASTEXITCODE
    }
    'security' {
        Invoke-Collectors (Get-Collectors (Join-Path $Root 'src\collectors\security\windows') '^S\d\d-.*\.ps1$') $Parallel
        exit ([int]($script:Failed.Count -gt 0))
    }
    'storage' {
        Invoke-Collectors (Get-Collectors (Join-Path $Root 'src\collectors\storage\windows') '^[GH]\d-.*\.ps1$') 1
        exit ([int]($script:Failed.Count -gt 0))
    }

    'get-tools' {
        $a = @(); if ($Msert) { $a += '-Msert' }; if ($Gh) { $a += '-Gh' }
        & $pwshExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'src\tools\windows\get-tools.ps1') @a
        exit $LASTEXITCODE
    }

    'admin' {
        $admin = Join-Path $Root 'src\admin\windows\admin-checks.ps1'
        $msertExe = Join-Path $Root 'intel\msert\msert.exe'
        if (-not (Test-Path -LiteralPath $msertExe)) { throw "Microsoft Safety Scanner is not downloaded ($msertExe). After the user agrees, run: pwsh -NoProfile -File .\bvs.ps1 get-tools -Msert" }
        $null = Get-ScanDir
        $aHash = (Get-FileHash -LiteralPath $admin -Algorithm SHA256).Hash
        $mHash = (Get-FileHash -LiteralPath $msertExe -Algorithm SHA256).Hash
        Write-Host "admin-checks.ps1 SHA-256: $aHash"
        Write-Host "msert.exe        SHA-256: $mHash"
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $Root 'src\admin\windows\launch-elevated.ps1')`"", '-AdminScriptSha256', $aHash, '-MsertSha256', $mHash)
        if (-not $FullScan) { $argList += '-SkipFullScan' }
        Start-Process -FilePath $pwshExe -Verb RunAs -ArgumentList $argList -WindowStyle Minimized
        Write-Host "Elevated run started (one Windows admin prompt). Progress: $(Join-Path (Get-ScanDir) 'admin\elevated-status.json')"
    }

    'github-login' {
        $ghExe = Get-GhExe
        $cfg = Join-Path $Root 'vendor\gh-config'
        # GitHub CLI keeps its token in Windows Credential Manager per host, not per config folder.
        # Signing in here would replace the token of an existing GitHub CLI login, so refuse in that case.
        $ours = Test-Path -LiteralPath (Join-Path $cfg 'hosts.yml')
        $existing = @(& cmdkey.exe /list 2>$null | Where-Object { $_ -match 'gh:github\.com' }).Count -gt 0
        if ($existing -and -not $ours) {
            Write-Warning 'This PC already has a GitHub CLI sign-in. Signing in for the scanner would replace its stored token, so this command stops here.'
            Write-Host 'The public GitHub checks still run without a sign-in. Reusing an existing sign-in is on the roadmap.'
            exit 1
        }
        [void][IO.Directory]::CreateDirectory($cfg)
        $env:GH_CONFIG_DIR = $cfg
        foreach ($v in 'GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN') { Remove-Item -LiteralPath "Env:$v" -ErrorAction SilentlyContinue }
        Write-Host 'GitHub CLI opens a browser page and shows a one-time code. The scanner only sends read requests.'
        Write-Host 'Note: GitHub CLI always asks for its standard scopes (repo, read:org, gist). Sign out again with: bvs.ps1 github-logout'
        & $ghExe auth login --hostname github.com --git-protocol ssh --skip-ssh-key --web --scopes 'read:public_key,read:gpg_key,read:ssh_signing_key,read:repo_hook,read:user,user:email'
        exit $LASTEXITCODE
    }
    'github-logout' {
        $ghExe = Get-GhExe
        $env:GH_CONFIG_DIR = Join-Path $Root 'vendor\gh-config'
        if (-not (Test-GhSignedIn)) { Write-Host 'The scanner is not signed in to GitHub.'; exit 0 }
        & $ghExe auth logout --hostname github.com
        exit $LASTEXITCODE
    }

    'selftest' { & $pwshExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'tests\windows\lib.selftest.ps1'); exit $LASTEXITCODE }
    'lint' {
        $files = @(Get-ChildItem -LiteralPath (Join-Path $Root 'src\collectors') -Recurse -Filter '*.ps1' | Select-Object -ExpandProperty FullName)
        if (-not $files.Count) { throw 'no collectors found' }
        # In-process: `pwsh -File script -Path a b c` would bind only the first file.
        & (Join-Path $Root 'src\tools\windows\check-collector.ps1') -Path $files
        exit $LASTEXITCODE
    }
    'check-publish' { & $pwshExe -NoProfile -File (Join-Path $Root 'src\tools\windows\check-publish.ps1'); exit $LASTEXITCODE }

    default {
        # Print this file's own header. (Get-Help does not see a help block that follows #Requires.)
        $m = [regex]::Match((Get-Content -LiteralPath $PSCommandPath -Raw), '(?s)<#\r?\n(.*?)\r?\n#>')
        if ($m.Success) { ($m.Groups[1].Value -split "\r?\n") | Where-Object { $_ -notmatch '^\.(SYNOPSIS|DESCRIPTION)\s*$' } | ForEach-Object { $_ -replace '^\.EXAMPLE\s*$', 'Example:' } | Write-Host }
    }
}
}
catch {
    # One clear line instead of a PowerShell error record; agents and people read this.
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}

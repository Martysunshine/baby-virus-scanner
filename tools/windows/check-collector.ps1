#Requires -Version 7.2
<#
.SYNOPSIS
    Static safety lint for collector scripts. Exit 0 = OK, 1 = at least one FAIL.
.DESCRIPTION
    Collectors must be read-only. This checker parses each script into an AST and inspects the
    commands and .NET member calls the script will actually execute. String literals are not
    commands, so IoC/detection lists inside strings are fine.
    FAIL = forbidden (system change, install, elevation, raw network, credential access).
    WARN = needs a human look (dynamic invocation, COM, Add-Type, cmd /c ...).
.EXAMPLE
    pwsh -NoProfile -File tools\windows\check-collector.ps1 -Path collectors\security\windows\S01-persistence.ps1
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string[]]$Path)

$ErrorActionPreference = 'Stop'
$projectRef = '(?i)\$run\b|Get-BvsRoot|Get-BvsScanDir|OutDir|ScanDir|\$PSScriptRoot|\$BvsRoot'

# Always forbidden (lower-case command name without extension)
$always = @{}
@(
    # file system / ACL changes
    'remove-item', 'remove-itemproperty', 'set-itemproperty', 'new-itemproperty', 'rename-item', 'rename-itemproperty', 'move-item', 'copy-item',
    'clear-content', 'clear-item', 'clear-itemproperty', 'set-acl', 'clear-recyclebin', 'takeown', 'cipher', 'format', 'diskpart',
    # processes / services / power
    'stop-process', 'stop-service', 'start-service', 'restart-service', 'suspend-service', 'resume-service', 'set-service', 'new-service',
    'remove-service', 'restart-computer', 'stop-computer', 'taskkill', 'shutdown', 'logoff',
    # scheduled tasks
    'register-scheduledtask', 'unregister-scheduledtask', 'set-scheduledtask', 'start-scheduledtask', 'stop-scheduledtask',
    'enable-scheduledtask', 'disable-scheduledtask',
    # AV
    'set-mppreference', 'add-mppreference', 'remove-mppreference', 'start-mpscan', 'start-mpwdoscan', 'remove-mpthreat', 'update-mpsignature',
    'mpcmdrun', 'msert',
    # firewall / network config
    'new-netfirewallrule', 'set-netfirewallrule', 'remove-netfirewallrule', 'enable-netfirewallrule', 'disable-netfirewallrule',
    'set-netfirewallprofile', 'copy-netfirewallrule', 'set-dnsclientserveraddress', 'set-dnsclient', 'clear-dnsclientcache',
    'set-netipinterface', 'set-netipaddress', 'new-netipaddress', 'remove-netipaddress', 'set-netconnectionprofile', 'new-netroute',
    'remove-netroute', 'set-nettcpsetting', 'set-smbserverconfiguration', 'new-smbshare', 'remove-smbshare', 'set-smbshare',
    'grant-smbshareaccess', 'revoke-smbshareaccess', 'disable-netadapter', 'enable-netadapter', 'restart-netadapter', 'set-netadapter',
    # code execution / raw network (use Invoke-BvsIntel)
    'invoke-expression', 'iex', 'invoke-webrequest', 'invoke-restmethod', 'iwr', 'irm', 'start-bitstransfer', 'curl', 'wget',
    'bitsadmin', 'mshta', 'rundll32', 'regsvr32', 'msiexec', 'cleanmgr', 'wscript', 'npx', 'ssh', 'scp', 'sftp', 'plink', 'nc', 'ncat',
    # package managers (side effects even on "read" commands: logs, caches)
    'npm', 'pnpm', 'yarn', 'bun', 'pip', 'pip3', 'pipx', 'uv', 'poetry', 'conda', 'choco', 'scoop', 'winget', 'code', 'cursor',
    'install-module', 'install-package', 'install-script', 'update-module', 'install-psresource', 'uninstall-module', 'uninstall-package',
    # users / policy / remoting
    'new-localuser', 'set-localuser', 'remove-localuser', 'add-localgroupmember', 'remove-localgroupmember', 'enable-localuser',
    'disable-localuser', 'set-executionpolicy', 'enable-psremoting', 'set-item', 'set-wsmaninstance',
    # WMI writes
    'set-ciminstance', 'set-wmiinstance', 'remove-ciminstance', 'remove-wmiobject', 'invoke-cimmethod', 'invoke-wmimethod', 'new-ciminstance',
    # disks / logs / shadow copies
    'format-volume', 'clear-disk', 'initialize-disk', 'vssadmin', 'wbadmin', 'clear-eventlog', 'remove-eventlog', 'limit-eventlog',
    'write-eventlog', 'new-eventlog', 'repair-volume', 'optimize-volume'
) | ForEach-Object { $always[$_] = $true }

# Forbidden only with certain arguments (regex over the argument text, case-insensitive)
$byArgs = @{
    'reg'        = '(?i)^\s*(add|delete|import|copy|restore|load|unload|save|export)\b'
    'sc'         = '(?i)^\s*(config|delete|stop|start|create|pause|continue|failure|failureflag|sdset|privs|sidtype|control|description|triggerinfo|managedaccount)\b'
    'schtasks'   = '(?i)/(create|delete|change|run|end)\b'
    'netsh'      = '(?i)\b(set|add|delete|reset|import|install|uninstall|dump)\b|key\s*=\s*clear'
    'python'     = '(?i)-m\s+(pip|ensurepip|venv|virtualenv)\b'
    'python3'    = '(?i)-m\s+(pip|ensurepip|venv|virtualenv)\b'
    'py'         = '(?i)-m\s+(pip|ensurepip|venv|virtualenv)\b'
    'dism'       = '(?i)/(restorehealth|startcomponentcleanup|resetbase|enable-feature|disable-feature|add-|remove-|apply-|set-|cleanup-mountpoints|commit|unmount)'
    'sfc'        = '(?i)/(scannow|scanfile|offbootdir|offwindir)'
    'certutil'   = '(?i)-(urlcache|decode|decodehex|encode|addstore|delstore|importpfx|setreg|installcert|repairstore|f\b)'
    'fsutil'     = '(?i)\b(set|setzerodata|deletejournal|createnew|delete|repair|setshortname|seteof|setvaliddata|setsparse|setflags)\b'
    'bcdedit'    = '(?i)/(set|delete|deletevalue|create|copy|import|export|default|timeout|bootsequence|displayorder|toolsdisplayorder)\b'
    'wevtutil'   = '(?i)^\s*(cl|clear-log|sl|set-log|im|install-manifest|um|uninstall-manifest|epl|export-log|al|archive-log)\b'
    'icacls'     = '(?i)/(grant|deny|remove|reset|setowner|setintegritylevel|restore|inheritance|save)\b'
    'ipconfig'   = '(?i)/(flushdns|release|renew|registerdns|setclassid|release6|renew6)'
    'route'      = '(?i)^\s*(add|delete|change|-f)\b'
    'arp'        = '(?i)(^|\s)-(d|s)\b'
    'net'        = '(?i)^\s*(stop|start|pause|continue)\b|(^|\s)/(add|delete|del|active|y|passwordchg|persistent)\b|^\s*use\s+\\\\'
    'auditpol'   = '(?i)/(set|clear|remove|restore|backup)\b'
    'powercfg'   = '(?i)/(setactive|change|x|h|hibernate|delete|d|duplicatescheme|import|setacvalueindex|setdcvalueindex|s|energy|sleepstudy|srumutil)\b'
    'tailscale'  = '(?i)^\s*(up|down|set|logout|login|switch|cert|file|ssh|nc|web|update|configure|drive|lock|syspolicy)\b|^\s*(serve|funnel)\s+(?!status)|^\s*exit-node\s+(?!list)'
    'vboxmanage' = '(?i)^\s*(?!list\b|showvminfo\b|--version\b|-v\b|-version\b)'
    'docker'     = '(?i)^\s*(?!version\b|context\s+ls\b|--version\b)'
    'wsl'        = '(?i)^\s*(?!(-l|--list|-v|--verbose|--status|--version|-l\s+-v|--list\s+--verbose)\s*$)'
    'ssh-keygen' = '(?i)^(?!.*(^|\s)-l\b)'
    'ollama'     = '(?i)^\s*(?!list\b|ps\b|--version\b|-v\b)'
    'gh'         = '__gh__'
    'git'        = '__git__'
    'powershell' = '(?i)(^|\s)-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b'
    'pwsh'       = '(?i)(^|\s)-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b'
    'start-process' = '(?i)-verb\s+["'']?runas'
    'cmd'        = '(?i)\b(del|erase|rd|rmdir|move|ren|rename|format|mklink|attrib)\b|\breg\s+(add|delete|import)|\bsc\s+(config|delete|stop|create)|schtasks\s+/(create|delete|change)|takeown|icacls\s+.*/grant|bitsadmin|certutil\s+-urlcache|\bcurl\b|\bwget\b|powershell\s+.*-e(nc)?\b'
}
$warnCmds = @{ 'start-process' = 'Start-Process: make sure the program only reads'; 'cmd' = 'cmd.exe: prefer native PowerShell'; 'cscript' = 'cscript: script host'; 'add-type' = 'Add-Type: compiled code - keep it read-only'; 'new-object' = $null; 'powercfg' = 'powercfg: read-only switches only' }
$fileWriteCmds = 'out-file', 'set-content', 'add-content', 'new-item', 'tee-object', 'export-csv', 'export-clixml', 'expand-archive', 'compress-archive', 'start-transcript', 'export-alias'

$gitRead = 'status', 'log', 'rev-parse', 'remote', 'branch', 'show', 'ls-files', 'config', 'worktree', 'stash', 'diff', 'for-each-ref', 'describe', 'tag', 'cat-file', 'rev-list', 'show-ref', 'blame', 'shortlog', 'count-objects', 'symbolic-ref', 'var', 'check-ignore', 'name-rev', 'merge-base', 'reflog', 'version', '--version'

$memberAlwaysDeny = 'delete', 'deletesubkey', 'deletesubkeytree', 'deletevalue', 'setvalue', 'createsubkey', 'setaccesscontrol', 'setattributes',
    'setlastwritetime', 'setcreationtime', 'setlastaccesstime', 'encrypt', 'decrypt', 'kill', 'moveto', 'save', 'invokeverb', 'invokeverbex',
    'shellexecute', 'copyhere', 'movehere', 'emptyrecyclebin'
$memberWriteNeedsProject = 'writealltext', 'writeallbytes', 'writealllines', 'appendalltext', 'appendalllines', 'create', 'createtext', 'openwrite',
    'appendtext', 'createdirectory', 'move', 'copy', 'replace', 'copyto'
$memberWarn = 'start', 'run', 'exec'

function Test-GitArgs([string[]]$a) {
    $all = $a -join ' '
    if ($all -notmatch '--no-optional-locks') { return 'git must use --no-optional-locks' }
    $sub = ($a | Where-Object { $_ -notmatch '^-' -and $_ -notmatch '^(-C|-c)$' } | Select-Object -First 1)
    $prev = $null
    foreach ($x in $a) { if ($prev -in '-C', '-c') { $prev = $null; continue }; if ($x -match '^-') { $prev = $x; continue }; $sub = $x; break }
    if (-not $sub) { return $null }
    $sub = $sub.Trim('"', "'").ToLowerInvariant()
    if ($sub -notin $gitRead) { return "git subcommand '$sub' is not read-only" }
    switch ($sub) {
        'config' { if ($all -notmatch '--(get|get-all|get-regexp|list|show-origin|show-scope)\b|\s-l\b') { return 'git config must be a --get/--list read' } }
        'remote' { if ($all -match '\bremote\s+(add|remove|rm|rename|set-url|set-head|set-branches|prune|update|show)\b') { return 'git remote write/network subcommand' } }
        'branch' { if ($all -match '\s(-d|-D|-m|-M|-c|-C|--delete|--move|--copy|--set-upstream-to|-u|--unset-upstream|--edit-description|-f|--force)\b') { return 'git branch write option' } }
        'worktree' { if ($all -notmatch '\bworktree\s+list\b') { return 'only git worktree list' } }
        'stash' { if ($all -notmatch '\bstash\s+(list|show)\b') { return 'only git stash list/show' } }
        'tag' { if ($all -match '\s(-d|-a|-s|-f|-m|-u|--delete|--annotate|--sign|--force)\b') { return 'git tag write option' } }
        'reflog' { if ($all -match '\breflog\s+(expire|delete)\b') { return 'git reflog write' } }
    }
    $null
}

function Test-GhArgs([string[]]$a) {
    $all = ($a -join ' ')
    if ($all -match '(?i)\bauth\s+(token|refresh|login|logout|setup-git|switch)\b') { return 'gh auth write/secret subcommand' }
    if ($all -match '(?i)^\s*(repo|secret|variable|ssh-key|gpg-key|workflow|run|release|issue|pr|codespace|gist|label|extension|alias|config|cache|project|ruleset|attestation)\s+(create|delete|edit|fork|rename|archive|unarchive|sync|clone|set-default|add|remove|set|enable|disable|cancel|rerun|upload|close|reopen|merge|comment|review|lock|unlock|transfer|pin|unpin|install|upgrade|exec|stop|ssh|cp|ports|develop|download|watch|deploy-key|link|unlink|copy|mark-template)\b') { return 'gh mutating subcommand' }
    if ($all -match '(?i)^\s*api\b') {
        if ($all -match '(?i)(-X|--method)\s*["'']?(POST|PUT|PATCH|DELETE)') { return 'gh api non-GET method' }
        $isGraphql = $all -match '(?i)\bapi\s+graphql\b'
        if ($isGraphql -and $all -match '(?i)\bmutation\b') { return 'gh api graphql mutation' }
        if (-not $isGraphql -and $all -match '(?i)(^|\s)(-f|-F|--field|--raw-field|--input)\b') { return 'gh api with fields defaults to POST' }
    }
    $null
}

$neverReadNames = '(?i)Login Data|\\Cookies\b|\\History\b|Web Data|Local Extension Settings|\.credentials\.json|\\auth\.json|\.git-credentials|key4\.db|logins\.json'
$totalFail = 0
foreach ($p in $Path) {
    $full = (Resolve-Path -LiteralPath $p).Path
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$errors)
    $issues = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $errors) { $issues.Add([pscustomobject]@{ Sev = 'FAIL'; Line = $e.Extent.StartLineNumber; Msg = "parse error: $($e.Message)" }) }

    foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $c.GetCommandName()
        $line = $c.Extent.StartLineNumber
        $argEls = @($c.CommandElements | Select-Object -Skip 1)
        $argText = ($argEls | ForEach-Object { $_.Extent.Text }) -join ' '
        $argVals = @($argEls | ForEach-Object { if ($_ -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $_.Value } else { $_.Extent.Text } })
        if (-not $name) {
            $issues.Add([pscustomobject]@{ Sev = 'WARN'; Line = $line; Msg = "dynamic command '$($c.CommandElements[0].Extent.Text)': make sure it only reads (args: $argText)" })
            continue
        }
        $leaf = [IO.Path]::GetFileNameWithoutExtension($name).ToLowerInvariant()
        if ($always.ContainsKey($leaf)) { $issues.Add([pscustomobject]@{ Sev = 'FAIL'; Line = $line; Msg = "'$name' is not allowed in a read-only collector" }); continue }
        if ($fileWriteCmds -contains $leaf -and $argText -notmatch $projectRef) {
            $issues.Add([pscustomobject]@{ Sev = 'FAIL'; Line = $line; Msg = "'$name' writes files; only allowed into the project (reference `$run/OutDir/Get-BvsRoot)" }); continue
        }
        if ($byArgs.ContainsKey($leaf)) {
            $rx = $byArgs[$leaf]
            if ($rx -eq '__git__') { $m = Test-GitArgs $argVals; if ($m) { $issues.Add([pscustomobject]@{ Sev = 'FAIL'; Line = $line; Msg = $m }) } }
            elseif ($rx -eq '__gh__') { $m = Test-GhArgs $argVals; if ($m) { $issues.Add([pscustomobject]@{ Sev = 'FAIL'; Line = $line; Msg = $m }) } }
            elseif (($argVals -join ' ') -match $rx) { $issues.Add([pscustomobject]@{ Sev = 'FAIL'; Line = $line; Msg = "'$name $argText' changes the system" }) }
        }
        if ($warnCmds.ContainsKey($leaf) -and $warnCmds[$leaf]) { $issues.Add([pscustomobject]@{ Sev = 'WARN'; Line = $line; Msg = $warnCmds[$leaf] }) }
        if ($leaf -eq 'new-object' -and $argText -match '(?i)-com(object)?') { $issues.Add([pscustomobject]@{ Sev = 'WARN'; Line = $line; Msg = "COM object ($argText): read-only use only, never .Save()/InvokeVerb" }) }
    }

    foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
        $member = if ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $m.Member.Value.ToLowerInvariant() } else { '' }
        $line = $m.Extent.StartLineNumber
        $target = $m.Expression.Extent.Text
        if ($memberAlwaysDeny -contains $member) { $issues.Add([pscustomobject]@{ Sev = 'FAIL'; Line = $line; Msg = "method .$($m.Member.Value)() on $target changes the system" }); continue }
        if ($memberWriteNeedsProject -contains $member) {
            $isStream = $member -eq 'copyto' -and $target -notmatch '(?i)file|dir'
            $isFs = $target -match '(?i)\[(System\.)?IO\.(File|Directory|FileInfo|DirectoryInfo)\]|FileInfo|DirectoryInfo|\$fi\b|\$file\b|\$dir\b'
            $firstArg = if ($m.Arguments -and $m.Arguments.Count -gt 0) { $m.Arguments[0].Extent.Text } else { '' }
            if (-not $isStream -and ($isFs -or $member -match '^(writeall|appendall|createtext|openwrite|appendtext|createdirectory)') -and $firstArg -notmatch $projectRef -and $target -notmatch $projectRef) {
                $issues.Add([pscustomobject]@{ Sev = 'FAIL'; Line = $line; Msg = "$target::$($m.Member.Value)($firstArg) writes outside the project" })
            }
            continue
        }
        if ($memberWarn -contains $member -and $target -notmatch '(?i)stopwatch|\$sw\b|timer|regex|task') { $issues.Add([pscustomobject]@{ Sev = 'WARN'; Line = $line; Msg = "$target.$($m.Member.Value)(): make sure this does not launch programs" }) }
    }

    foreach ($r in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst] }, $true)) {
        $loc = $r.Location.Extent.Text
        if ($loc -notmatch '^\$null$' -and $loc -notmatch $projectRef) { $issues.Add([pscustomobject]@{ Sev = 'FAIL'; Line = $r.Extent.StartLineNumber; Msg = "redirection to '$loc' writes outside the project" }) }
    }

    foreach ($s in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)) {
        $v = $s.Extent.Text
        if ($v -match $neverReadNames) { $issues.Add([pscustomobject]@{ Sev = 'WARN'; Line = $s.Extent.StartLineNumber; Msg = "string mentions a never-read file ($($Matches[0])): use Test-BvsNeverRead, never open it" }) }
    }

    $fails = @($issues | Where-Object Sev -eq 'FAIL')
    $warns = @($issues | Where-Object Sev -eq 'WARN')
    $totalFail += $fails.Count
    "check-collector: $full"
    foreach ($i in ($issues | Sort-Object Line | Select-Object -First 60)) { "  {0} line {1}: {2}" -f $i.Sev, $i.Line, $i.Msg }
    "  RESULT: {0} ({1} fail, {2} warn)" -f $(if ($fails.Count) { 'FAIL' } else { 'OK' }), $fails.Count, $warns.Count
}
if ($totalFail -gt 0) { exit 1 } else { exit 0 }

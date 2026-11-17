#Requires -Version 7.2
<#
.SYNOPSIS  Generate docs\playbooks\<ID>-<name>.md from a collector's own code (header help, checks, sidecars, parameters).
.DESCRIPTION
    Used when a module has no hand-written playbook. Never overwrites an existing playbook unless -Force.
    Sources: the script's comment-based help, every Invoke-BvsCheck -Id/-Description, the sidecar JSON
    files (<ID>-*.json next to the collector) and the script's parameters.
    It reads code only. Results of a scan never go into a playbook: they describe one machine.
.EXAMPLE   pwsh -File tools\windows\gen-playbook.ps1 -Path collectors\security\windows\S07-network.ps1
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string[]]$Path, [switch]$Force)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# `pwsh -File` passes "a,b" as one string.
$Path = @($Path | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Get-HelpSection([string]$Help, [string]$Name) {
    $m = [regex]::Match($Help, "(?ms)^\s*\.$Name\s*?\r?\n(.*?)(?=^\s*\.[A-Z]+\b|\z)")
    if (-not $m.Success) { return $null }
    $lines = @($m.Groups[1].Value -split "\r?\n")
    $indent = @($lines | Where-Object { $_.Trim() } | ForEach-Object { ($_ -replace '^(\s*).*$', '$1').Length } | Measure-Object -Minimum).Minimum
    (@($lines | ForEach-Object { if ($_.Length -ge $indent) { $_.Substring($indent) } else { $_.TrimStart() } }) -join "`n").Trim()
}

foreach ($p in $Path) {
    $full = (Resolve-Path -LiteralPath $p).Path
    $name = [IO.Path]::GetFileNameWithoutExtension($full)                # e.g. S07-network
    $id = ($name -split '-')[0]
    $out = Join-Path $root "docs\playbooks\$name.md"
    if ((Test-Path -LiteralPath $out) -and -not $Force) { "skip (exists): $out"; continue }
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$errors)
    # The header help is the first block comment (it follows #Requires, so GetHelpContent() does not see it).
    $block = @($tokens | Where-Object { $_.Kind -eq 'Comment' -and $_.Text.StartsWith('<#') }) | Select-Object -First 1
    $help = if ($block) { $block.Text -replace '^<#', '' -replace '#>$', '' } else { '' }
    $synopsis = Get-HelpSection $help 'SYNOPSIS'
    $description = Get-HelpSection $help 'DESCRIPTION'
    $checks = foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-BvsCheck' }, $true)) {
        $els = $c.CommandElements; $cid = $null; $desc = $null
        for ($i = 0; $i -lt $els.Count - 1; $i++) {
            if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst]) {
                $v = $els[$i + 1]
                $const = if ($v -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $v.Value } else { $null }
                if ($els[$i].ParameterName -eq 'Id') { $cid = $const }
                elseif ($els[$i].ParameterName -eq 'Description') {
                    $desc = if ($const) { $const } elseif ($v -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { $v.Value } else { '(description is built at run time; see the script)' }
                }
            }
        }
        [pscustomobject]@{ Id = $cid; Description = $desc }
    }
    # A check ID can appear in two code branches; list it once.
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $named = @($checks | Where-Object { $_.Id -and $seen.Add($_.Id) })
    $dynamic = @($checks | Where-Object { -not $_.Id }).Count
    $sidecars = Get-ChildItem -LiteralPath (Split-Path $full) -Filter "$id-*.json" -File -ErrorAction SilentlyContinue
    $area = if ($full -match '\\collectors\\([^\\]+)\\') { $Matches[1] } else { 'security' }
    $rel = $full.Substring($root.Length + 1)
    $params = if ($ast.ParamBlock) { @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) } else { @() }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# $name")
    $lines.Add('')
    $lines.Add("> Generated from the collector's own code by ``tools/windows/gen-playbook.ps1``. After changing the collector,")
    $lines.Add("> regenerate it: ``pwsh -File tools\windows\gen-playbook.ps1 -Path $rel -Force``. See ``docs/METHODOLOGY.md`` for the overall method.")
    $lines.Add('')
    $lines.Add('## (a) Purpose')
    $lines.Add('')
    $lines.Add($(if ($synopsis) { $synopsis } else { '(the script header has no synopsis)' }))
    if ($description) { $lines.Add(''); $lines.Add('```text'); $lines.Add($description); $lines.Add('```') }
    $lines.Add('')
    $lines.Add('## (b) Implementation')
    $lines.Add('')
    $lines.Add("Collector: ``$rel``. Library: ``lib\windows\BVS.Common.psm1``.")
    if ($sidecars) { $lines.Add(''); $lines.Add('Sidecar data (IoC lists and reference tables): ' + (($sidecars | ForEach-Object { "``$($_.Name)``" }) -join ', ') + '.') }
    $lines.Add('')
    $lines.Add('| Check | What it does |')
    $lines.Add('|---|---|')
    foreach ($c in $named) { $lines.Add("| ``$($c.Id)`` | $("$($c.Description)" -replace '\|', '/' -replace '\s+', ' ') |") }
    if ($dynamic) { $lines.Add(''); $lines.Add("Plus $dynamic check(s) whose ID is built at run time (see the script).") }
    if ($params.Count) { $lines.Add(''); $lines.Add('Parameters: ' + (($params | ForEach-Object { "``-$_``" }) -join ', ') + '.') }
    $lines.Add('')
    $lines.Add('## (c) Run')
    $lines.Add('')
    $lines.Add('```powershell')
    $lines.Add("pwsh -NoProfile -File tools\windows\check-collector.ps1 -Path $rel")
    $lines.Add("pwsh -NoProfile -ExecutionPolicy Bypass -File $rel")
    $lines.Add('```')
    $lines.Add('')
    $lines.Add("Output: ``data\<scanId>\$area\$id.json`` (``bvs.module/1``). Log: ``logs\$id.log``.")
    [IO.File]::WriteAllText($out, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    "wrote $out ($($named.Count) checks)"
}

<#
.SYNOPSIS
  把 docs/04-plan/tasks/*.md 中的任务卡同步为 GitHub Milestone 与 Issue（幂等）。

.DESCRIPTION
  - 每个阶段文件头部的 `> 里程碑：` / `> 截止：` → Milestone（不存在则创建，截止日期不同则更新）。
  - 每张 `### Pn-AREA-NN 标题` 任务卡 → Issue `[Pn-AREA-NN] 标题`。
    以标题前缀查重：不存在则创建；存在且为 open 则更新标题/正文/里程碑并追加标签；
    已关闭的 Issue 不重新打开、不更新。
  - 标签由字段生成：area:* platform:* type:* phase:Pn size:* priority:* + 「额外标签」。
    只追加不删除（保留手工标签，如 status:blocked）。
  - 「依赖」中的任务编号在正文中替换为 #Issue编号（已知时）。
  - -DryRun 只打印计划动作，不调用任何写入类 gh 命令；未登录 gh 时也可运行。

  格式规范见 docs/04-plan/tasks/README.md。兼容 PowerShell 7 与 Windows PowerShell 5.1。

.EXAMPLE
  pwsh scripts/sync-issues.ps1 -DryRun
  pwsh scripts/sync-issues.ps1 -Phase P0
  pwsh scripts/sync-issues.ps1 -Phase P0,P1 -ProjectOwner '@me' -ProjectNumber 3
#>
[CmdletBinding()]
param(
    # 只同步指定阶段，如 P0 或 P0,P1；省略则全部。
    [string[]]$Phase,
    # 只打印计划，不写入 GitHub。
    [switch]$DryRun,
    # owner/repo；省略则用 `gh repo view` 推断（DryRun 下推断失败不报错）。
    [string]$Repo,
    # 任务卡目录；默认 <脚本目录>/../docs/04-plan/tasks。
    [string]$TasksDir,
    # 生成任务卡链接时使用的分支。
    [string]$Branch = 'main',
    # 可选：把 Issue 加入 Projects v2（如 '@me' 或组织名 + 项目编号）。
    [string]$ProjectOwner,
    [int]$ProjectNumber = 0,
    # labels.json 路径，用于校验标签是否已定义。
    [string]$LabelsFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not $TasksDir)   { $TasksDir   = Join-Path $PSScriptRoot '..\docs\04-plan\tasks' }
if (-not $LabelsFile) { $LabelsFile = Join-Path $PSScriptRoot 'labels.json' }

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$OutputEncoding = [System.Text.Encoding]::UTF8

$IdPattern = '^P\d+-[A-Z]+-\d{2,}$'

# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------

function Get-HeadingAnchor {
    param([string]$Heading)
    # 近似 GitHub 的锚点生成：小写、去标点（保留字母/数字/汉字/-/_）、空格转 -。
    $s = $Heading.Trim().ToLowerInvariant()
    $s = [regex]::Replace($s, '[^\p{L}\p{N}\p{Mn}\- _]', '')
    return ($s -replace ' ', '-')
}

function Get-PhaseHeader {
    param([string[]]$Lines, [string]$Key)
    foreach ($l in $Lines) {
        if ($l -match ('^>\s*' + [regex]::Escape($Key) + '\s*[:：]\s*(.+?)\s*$')) {
            $v = $Matches[1]
            $v = ($v -split '\s+←')[0].Trim()   # 去掉行尾注释
            return $v
        }
        if ($l -match '^##\s') { break }
    }
    return $null
}

function Split-List {
    param([string]$Value)
    if (-not $Value) { return @() }
    $parts = $Value -split '[,，、]' | ForEach-Object { $_.Trim().Trim('`') } | Where-Object { $_ -and $_ -ne '无' -and $_ -ne '-' }
    return @($parts)
}

function Get-TaskCards {
    <#
      解析单个阶段文件，返回：
        @{ File; Phase; Milestone; Due; Cards = @( @{ Id; Title; Fields(hashtable); Body; Anchor; Line } ) }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $text  = [System.IO.File]::ReadAllText((Resolve-Path $Path).Path, [System.Text.Encoding]::UTF8)
    $lines = $text -split "`r?`n"

    $phase = $null
    if ([System.IO.Path]::GetFileName($Path) -match '^(P\d+)-') { $phase = $Matches[1] }

    $result = [ordered]@{
        File      = [System.IO.Path]::GetFileName($Path)
        Phase     = $phase
        Milestone = Get-PhaseHeader -Lines $lines -Key '里程碑'
        Due       = Get-PhaseHeader -Lines $lines -Key '截止'
        Cards     = New-Object System.Collections.ArrayList
    }

    $cur = $null
    $inFence = $false
    $bodyLines = $null

    $finish = {
        if ($null -ne $cur) {
            # 去掉字段列表之后的正文首尾空行
            $cur.Body = ($bodyLines -join "`n").Trim()
            [void]$result.Cards.Add([pscustomobject]$cur)
        }
    }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        if ($line -match '^\s*(```|~~~)') { $inFence = -not $inFence }

        if (-not $inFence -and $line -match '^###\s+(P\d+-[A-Z]+-\d{2,})\s+(.+?)\s*$') {
            . $finish
            $heading = $line -replace '^###\s+', ''
            $cur = [ordered]@{
                Id     = $Matches[1]
                Title  = $Matches[2]
                Fields = [ordered]@{}
                Body   = ''
                Anchor = Get-HeadingAnchor $heading
                Line   = $i + 1
            }
            $bodyLines = New-Object System.Collections.ArrayList
            $inFields = $true
            continue
        }

        if ($null -eq $cur) { continue }

        if (-not $inFence -and $line -match '^#{2,3}\s') {
            . $finish
            $cur = $null
            continue
        }

        if ($inFields) {
            if ($line -match '^-\s+\*\*(.+?)\*\*\s*[:：]\s*(.*?)\s*$') {
                $cur.Fields[$Matches[1].Trim()] = $Matches[2]
                continue
            }
            if ($line.Trim() -eq '') { continue }
            $inFields = $false
        }
        [void]$bodyLines.Add($line)
    }
    . $finish

    return [pscustomobject]$result
}

function Get-CardLabels {
    param($Card, [string]$Phase)
    $f = $Card.Fields
    $labels = New-Object System.Collections.ArrayList
    $area = ($Card.Id -split '-')[1]
    if ($f.Contains('AREA') -and $f['AREA']) { $area = $f['AREA'].Trim() }
    [void]$labels.Add('area:' + $area.ToLowerInvariant())
    foreach ($p in (Split-List $f['平台'])) { [void]$labels.Add('platform:' + $p.ToLowerInvariant()) }
    if ($f.Contains('类型')   -and $f['类型'])   { [void]$labels.Add('type:' + $f['类型'].Trim().ToLowerInvariant()) }
    [void]$labels.Add('phase:' + $Phase)
    if ($f.Contains('规模')   -and $f['规模'])   { [void]$labels.Add('size:' + $f['规模'].Trim().ToUpperInvariant()) }
    if ($f.Contains('优先级') -and $f['优先级']) { [void]$labels.Add('priority:' + $f['优先级'].Trim().ToUpperInvariant()) }
    foreach ($x in (Split-List $f['额外标签'])) { [void]$labels.Add($x) }
    return @($labels | Select-Object -Unique)
}

function Get-CardIssueTitle { param($Card) return ('[{0}] {1}' -f $Card.Id, $Card.Title) }

function Get-CardBody {
    param($Card, [string]$File, [hashtable]$IssueNumbers, [string]$RepoName, [string]$BranchName)
    $f = $Card.Fields
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('| 字段 | 值 |')
    [void]$sb.AppendLine('|---|---|')
    foreach ($k in $f.Keys) {
        if ($k -eq '依赖' -or $k -eq '额外标签') { continue }
        [void]$sb.AppendLine(('| {0} | {1} |' -f $k, ($f[$k] -replace '\|', '\|')))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('**依赖**：')
    $deps = @(Split-List $f['依赖'])
    if ($deps.Count -eq 0) {
        [void]$sb.AppendLine('- 无')
    } else {
        foreach ($d in $deps) {
            if ($d -match $IdPattern -and $IssueNumbers.ContainsKey($d)) {
                [void]$sb.AppendLine(('- [ ] {0} #{1}' -f $d, $IssueNumbers[$d]))
            } else {
                [void]$sb.AppendLine(('- [ ] {0}' -f $d))
            }
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine($Card.Body)
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    $rel = 'docs/04-plan/tasks/' + $File
    if ($RepoName) {
        $src = ('https://github.com/{0}/blob/{1}/{2}#{3}' -f $RepoName, $BranchName, $rel, $Card.Anchor)
    } else {
        $src = ('{0}#{1}' -f $rel, $Card.Anchor)
    }
    [void]$sb.AppendLine(('来源：[{0}]({1})' -f $rel, $src))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> 本正文由 `scripts/sync-issues.ps1` 生成。请修改任务卡后重新同步，不要直接编辑此处。')
    # 将正文中的相对链接改为指向仓库的绝对链接
    $out = $sb.ToString().TrimEnd()
    if ($RepoName) {
        $base = ('https://github.com/{0}/blob/{1}/' -f $RepoName, $BranchName)
        $out = [regex]::Replace($out, '\]\((?!https?://|#|mailto:)([^)\s]+)\)', {
            param($m)
            # 以 docs/04-plan/tasks/ 为基准解析相对路径，消去 ../
            $segs = New-Object System.Collections.ArrayList
            foreach ($s in @('docs', '04-plan', 'tasks')) { [void]$segs.Add($s) }
            foreach ($s in ($m.Groups[1].Value -split '/')) {
                if ($s -eq '..') { if ($segs.Count -gt 0) { $segs.RemoveAt($segs.Count - 1) } }
                elseif ($s -ne '.' -and $s -ne '') { [void]$segs.Add($s) }
            }
            return '](' + $base + ($segs -join '/') + ')'
        })
    }
    return $out
}

# ---------------------------------------------------------------------------
# gh 封装
# ---------------------------------------------------------------------------

function Invoke-Gh {
    param([Parameter(ValueFromRemainingArguments)][string[]]$GhArgs)
    $out = & gh @GhArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw ("gh {0} 失败：{1}" -f ($GhArgs -join ' '), ($out | Out-String)) }
    return ($out | Out-String)
}

function Invoke-GhWithBody {
    # 正文通过临时文件传递，避免命令行长度与引号问题
    param([string[]]$GhArgs, [string]$Body)
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tmp, $Body, (New-Object System.Text.UTF8Encoding($false)))
        return (Invoke-Gh @($GhArgs + @('--body-file', $tmp)))
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

$ghAvailable = [bool](Get-Command gh -ErrorAction SilentlyContinue)
if (-not $DryRun -and -not $ghAvailable) { throw '未找到 gh CLI；请安装 https://cli.github.com/ 并 gh auth login。' }

if (-not $Repo -and $ghAvailable) {
    try {
        $Repo = (& gh repo view --json nameWithOwner -q .nameWithOwner 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { $Repo = $null }
    } catch { $Repo = $null }
}
if (-not $Repo -and -not $DryRun) { throw '无法确定仓库；请传入 -Repo owner/name。' }

# 已定义标签（用于告警）
$knownLabels = @{}
if (Test-Path $LabelsFile) {
    $raw = [System.IO.File]::ReadAllText((Resolve-Path $LabelsFile).Path, [System.Text.Encoding]::UTF8)
    foreach ($l in @(($raw | ConvertFrom-Json) | ForEach-Object { $_ })) { $knownLabels[$l.name] = $true }
}

# 读取任务卡
$files = Get-ChildItem -Path $TasksDir -Filter 'P*-*.md' | Sort-Object Name
if ($Phase) {
    $want = @($Phase | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToUpperInvariant() })
    $files = @($files | Where-Object { $_.Name -match '^(P\d+)-' -and ($want -contains $Matches[1]) })
}
if (-not $files -or @($files).Count -eq 0) { throw ("在 {0} 中未找到匹配的阶段文件。" -f $TasksDir) }

$phases = @()
$errors = New-Object System.Collections.ArrayList
$seen = @{}
foreach ($f in $files) {
    $p = Get-TaskCards -Path $f.FullName
    if (-not $p.Milestone) { [void]$errors.Add("{0}: 缺少 '> 里程碑：'" -f $p.File) }
    if ($p.Due -and $p.Due -notmatch '^\d{4}-\d{2}-\d{2}$') { [void]$errors.Add("{0}: '> 截止：' 不是 YYYY-MM-DD：{1}" -f $p.File, $p.Due) }
    foreach ($c in $p.Cards) {
        if ($seen.ContainsKey($c.Id)) { [void]$errors.Add(("编号重复：{0}（{1}:{2} 与 {3}）" -f $c.Id, $p.File, $c.Line, $seen[$c.Id])) }
        $seen[$c.Id] = ('{0}:{1}' -f $p.File, $c.Line)
        if (-not $c.Id.StartsWith($p.Phase + '-')) { [void]$errors.Add(("{0}:{1} 编号 {2} 不属于阶段 {3}" -f $p.File, $c.Line, $c.Id, $p.Phase)) }
        foreach ($req in @('AREA', '平台', '类型', '优先级', '规模')) {
            if (-not $c.Fields.Contains($req)) { [void]$errors.Add(("{0}:{1} {2} 缺少字段 {3}" -f $p.File, $c.Line, $c.Id, $req)) }
        }
    }
    $phases += $p
}
if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Warning $_ }
    if (-not $DryRun) { throw '任务卡校验失败，已中止（DryRun 下仅告警）。' }
}

# 现有 Milestone 与 Issue
$existingMilestones = @{}
$existingIssues = @{}   # Id -> @{ number; state; title; body; labels[]; milestone }
$canQuery = $false
if ($Repo -and $ghAvailable) {
    try {
        $msJson = & gh api --paginate ("repos/{0}/milestones?state=all&per_page=100" -f $Repo) 2>$null | Out-String
        if ($LASTEXITCODE -eq 0) {
            $canQuery = $true
            # --paginate 会拼接多个数组；统一成一个
            $msJson = $msJson -replace '\]\s*\[', ','
            foreach ($m in ($msJson | ConvertFrom-Json)) { $existingMilestones[$m.title] = $m }
            $isJson = & gh issue list --repo $Repo --state all --limit 2000 --json number,title,state,body,labels,milestone 2>$null | Out-String
            if ($LASTEXITCODE -eq 0) {
                foreach ($it in ($isJson | ConvertFrom-Json)) {
                    if ($it.title -match '^\[(P\d+-[A-Z]+-\d{2,})\]') {
                        $existingIssues[$Matches[1]] = $it
                    }
                }
            }
        }
    } catch { $canQuery = $false }
}
if (-not $canQuery) {
    if ($DryRun) { Write-Host '[DryRun] 未能读取 GitHub（未登录或未指定仓库），按“全部不存在”生成计划。' -ForegroundColor Yellow }
    else { throw '无法读取仓库的 Milestone/Issue，请检查 gh auth status 与 -Repo。' }
}

$issueNumbers = @{}
foreach ($k in $existingIssues.Keys) { $issueNumbers[$k] = $existingIssues[$k].number }

$stats = [ordered]@{ MilestoneCreate = 0; MilestoneUpdate = 0; IssueCreate = 0; IssueUpdate = 0; IssueUnchanged = 0; IssueClosedSkip = 0; ProjectAdd = 0; UnknownLabels = 0 }
$prefix = ''
if ($DryRun) { $prefix = '[DryRun] ' }
$created = New-Object System.Collections.ArrayList

# ---- Pass 1: Milestone + 创建缺失 Issue ----
foreach ($p in $phases) {
    Write-Host ''
    Write-Host ('== {0}  里程碑：{1}  截止：{2}  任务卡：{3}' -f $p.File, $p.Milestone, $p.Due, $p.Cards.Count) -ForegroundColor Cyan

    if ($p.Milestone) {
        $dueOn = $null
        if ($p.Due) { $dueOn = $p.Due + 'T23:59:59Z' }
        if ($existingMilestones.ContainsKey($p.Milestone)) {
            $m = $existingMilestones[$p.Milestone]
            $curDue = ''
            if ($m.due_on) { $curDue = ([string]$m.due_on).Substring(0, 10) }
            if ($p.Due -and $curDue -ne $p.Due) {
                Write-Host ('{0}更新 Milestone "{1}" 截止 {2} → {3}' -f $prefix, $p.Milestone, $curDue, $p.Due)
                $stats.MilestoneUpdate++
                if (-not $DryRun) { [void](Invoke-Gh api -X PATCH ("repos/{0}/milestones/{1}" -f $Repo, $m.number) -f ("due_on=" + $dueOn)) }
            }
        } else {
            Write-Host ('{0}创建 Milestone "{1}"（截止 {2}）' -f $prefix, $p.Milestone, $p.Due)
            $stats.MilestoneCreate++
            if (-not $DryRun) {
                $ghArgs = @('api', '-X', 'POST', ("repos/{0}/milestones" -f $Repo), '-f', ('title=' + $p.Milestone))
                if ($dueOn) { $ghArgs += @('-f', ('due_on=' + $dueOn)) }
                $resp = Invoke-Gh @ghArgs | ConvertFrom-Json
                $existingMilestones[$p.Milestone] = $resp
            }
        }
    }

    foreach ($c in $p.Cards) {
        $labels = Get-CardLabels -Card $c -Phase $p.Phase
        foreach ($l in $labels) {
            if ($knownLabels.Count -gt 0 -and -not $knownLabels.ContainsKey($l)) {
                Write-Warning ('{0} 使用了 labels.json 未定义的标签：{1}' -f $c.Id, $l)
                $stats.UnknownLabels++
            }
        }
        if ($existingIssues.ContainsKey($c.Id)) { continue }

        $title = Get-CardIssueTitle $c
        Write-Host ('{0}创建  {1}' -f $prefix, $title) -ForegroundColor Green
        Write-Host ('          标签：{0}' -f ($labels -join ', '))
        $stats.IssueCreate++
        if (-not $DryRun) {
            $body = Get-CardBody -Card $c -File $p.File -IssueNumbers $issueNumbers -RepoName $Repo -BranchName $Branch
            $ghArgs = @('issue', 'create', '--repo', $Repo, '--title', $title, '--label', ($labels -join ','))
            if ($p.Milestone) { $ghArgs += @('--milestone', $p.Milestone) }
            $url = (Invoke-GhWithBody -GhArgs $ghArgs -Body $body).Trim()
            if ($url -match '/issues/(\d+)\s*$') {
                $issueNumbers[$c.Id] = [int]$Matches[1]
                [void]$created.Add(@{ Card = $c; Phase = $p; Body = $body; Url = $url })
            }
            if ($ProjectOwner -and $ProjectNumber -gt 0) {
                [void](Invoke-Gh project item-add $ProjectNumber --owner $ProjectOwner --url $url)
                $stats.ProjectAdd++
            }
        } elseif ($ProjectOwner -and $ProjectNumber -gt 0) {
            $stats.ProjectAdd++
        }
    }
}

# ---- Pass 2: 更新已有 Issue；为新建 Issue 回填依赖链接 ----
foreach ($p in $phases) {
    foreach ($c in $p.Cards) {
        $title  = Get-CardIssueTitle $c
        $labels = Get-CardLabels -Card $c -Phase $p.Phase
        $body   = Get-CardBody -Card $c -File $p.File -IssueNumbers $issueNumbers -RepoName $Repo -BranchName $Branch

        $new = $created | Where-Object { $_.Card.Id -eq $c.Id } | Select-Object -First 1
        if ($new) {
            if ($new.Body -ne $body) {
                [void](Invoke-GhWithBody -GhArgs @('issue', 'edit', [string]$issueNumbers[$c.Id], '--repo', $Repo) -Body $body)
            }
            continue
        }
        if (-not $existingIssues.ContainsKey($c.Id)) { continue }   # DryRun 下的“将创建”

        $it = $existingIssues[$c.Id]
        if ($it.state -ne 'OPEN') {
            Write-Host ('{0}跳过  #{1} {2}（已关闭）' -f $prefix, $it.number, $title) -ForegroundColor DarkGray
            $stats.IssueClosedSkip++
            continue
        }
        $curLabels = @($it.labels | ForEach-Object { $_.name })
        $addLabels = @($labels | Where-Object { $curLabels -notcontains $_ })
        $curMs = ''
        if ($it.milestone) { $curMs = $it.milestone.title }
        $changes = @()
        if ($it.title -ne $title) { $changes += '标题' }
        if (($it.body -replace "`r", '').Trim() -ne $body.Trim()) { $changes += '正文' }
        if ($addLabels.Count -gt 0) { $changes += ('标签+' + ($addLabels -join ',')) }
        if ($p.Milestone -and $curMs -ne $p.Milestone) { $changes += '里程碑' }

        if ($changes.Count -eq 0) {
            $stats.IssueUnchanged++
            continue
        }
        Write-Host ('{0}更新  #{1} {2}：{3}' -f $prefix, $it.number, $title, ($changes -join '、')) -ForegroundColor Yellow
        $stats.IssueUpdate++
        if (-not $DryRun) {
            $ghArgs = @('issue', 'edit', [string]$it.number, '--repo', $Repo, '--title', $title)
            if ($addLabels.Count -gt 0) { $ghArgs += @('--add-label', ($addLabels -join ',')) }
            if ($p.Milestone) { $ghArgs += @('--milestone', $p.Milestone) }
            [void](Invoke-GhWithBody -GhArgs $ghArgs -Body $body)
        }
    }
}

# ---- 汇总 ----
Write-Host ''
Write-Host ('{0}汇总：阶段 {1}，任务卡 {2}' -f $prefix, @($phases).Count, (@($phases | ForEach-Object { $_.Cards.Count }) | Measure-Object -Sum).Sum) -ForegroundColor Cyan
foreach ($k in $stats.Keys) { Write-Host ('  {0,-16} {1}' -f $k, $stats[$k]) }
if ($errors.Count -gt 0) { Write-Host ('  校验告警        {0}' -f $errors.Count) -ForegroundColor Yellow }

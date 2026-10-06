<#
.SYNOPSIS
  按 scripts/labels.json 创建或更新 GitHub 标签（幂等，使用 gh label create --force）。

.EXAMPLE
  pwsh scripts/sync-labels.ps1 -DryRun
  pwsh scripts/sync-labels.ps1 -Repo owner/AgentWatch
#>
[CmdletBinding()]
param(
    # 只打印计划，不写入 GitHub。
    [switch]$DryRun,
    # owner/repo；省略则使用当前目录对应的仓库。
    [string]$Repo,
    # 标签定义文件。
    [string]$LabelsFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

if (-not $LabelsFile) { $LabelsFile = Join-Path $PSScriptRoot 'labels.json' }
$raw = [System.IO.File]::ReadAllText((Resolve-Path $LabelsFile).Path, [System.Text.Encoding]::UTF8)
$labels = @(($raw | ConvertFrom-Json) | ForEach-Object { $_ })

$names = @{}
foreach ($l in $labels) {
    if (-not $l.name -or -not $l.color) { throw ('标签定义缺少 name 或 color：{0}' -f ($l | ConvertTo-Json -Compress)) }
    if ($l.color -notmatch '^[0-9a-fA-F]{6}$') { throw ('标签 {0} 的 color 不是 6 位十六进制：{1}' -f $l.name, $l.color) }
    if ($names.ContainsKey($l.name)) { throw ('标签重复：{0}' -f $l.name) }
    $names[$l.name] = $true
}

if (-not $DryRun -and -not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw '未找到 gh CLI；请安装 https://cli.github.com/ 并 gh auth login。'
}

$prefix = ''
if ($DryRun) { $prefix = '[DryRun] ' }
$ok = 0
foreach ($l in $labels) {
    $desc = ''
    if ($l.PSObject.Properties['description'] -and $l.description) { $desc = [string]$l.description }
    Write-Host ('{0}创建/更新 {1,-18} #{2}  {3}' -f $prefix, $l.name, $l.color, $desc)
    if (-not $DryRun) {
        $ghArgs = @('label', 'create', $l.name, '--color', $l.color, '--description', $desc, '--force')
        if ($Repo) { $ghArgs += @('--repo', $Repo) }
        $out = & gh @ghArgs 2>&1
        if ($LASTEXITCODE -ne 0) { throw ('标签 {0} 同步失败：{1}' -f $l.name, ($out | Out-String)) }
    }
    $ok++
}
Write-Host ('{0}完成：{1} 个标签。已有但未在 labels.json 中定义的标签不会被删除。' -f $prefix, $ok)

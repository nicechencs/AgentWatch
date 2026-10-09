<#
.SYNOPSIS
  逐个检查目录下产物的大小（P4-CI-06 / NFR-04）。

.DESCRIPTION
  对 -Path 下的每个普通文件（不递归子目录）比较字节大小。
  超过 -LimitMB 时以非零退出码失败；达到限额的 -WarnPercent（默认 90）
  但未超过限额时退出码为 0，并打印警告。
  路径不存在、不是目录、或目录里没有普通文件时，以非零退出码失败。

.EXAMPLE
  pwsh scripts/check-size.ps1 -Path dist/
  pwsh scripts/check-size.ps1 -Path dist/ -LimitMB 1
  pwsh scripts/check-size.ps1 -Path dist/ -LimitMB 25 -WarnPercent 90
#>
[CmdletBinding()]
param(
    # 存放待检查产物的目录。
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,

    # 单个产物的大小限额，单位 MB（1 MB = 1000 * 1000 字节）。默认 25。
    [Parameter()]
    [double]$LimitMB = 25,

    # 警告线，按限额的百分比计算。默认 90。
    [Parameter()]
    [double]$WarnPercent = 90
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

if ($LimitMB -le 0) {
    Write-Error ("限额必须大于 0 MB，实际为 {0}" -f $LimitMB)
    exit 2
}
if ($WarnPercent -le 0 -or $WarnPercent -gt 100) {
    Write-Error ("警告百分比必须在 (0, 100] 内，实际为 {0}" -f $WarnPercent)
    exit 2
}

# 与 check-size.sh 一致：十进制 MB，避免 1024 与 1000 两套口径。
$bytesPerMb = 1000000.0
$limitBytes = [int64][Math]::Floor($LimitMB * $bytesPerMb)
if ($limitBytes -lt 1) {
    Write-Error ("限额换算后不足 1 字节：{0} MB" -f $LimitMB)
    exit 2
}
$warnBytes = [int64][Math]::Floor($limitBytes * $WarnPercent / 100.0)

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error ("路径不存在：{0}" -f $Path)
    exit 2
}

$item = Get-Item -LiteralPath $Path
if (-not $item.PSIsContainer) {
    Write-Error ("路径不是目录：{0}" -f $item.FullName)
    exit 2
}

$files = @(Get-ChildItem -LiteralPath $item.FullName -File | Sort-Object Name)
if ($files.Count -eq 0) {
    Write-Error ("目录为空（没有普通文件）：{0}" -f $item.FullName)
    exit 2
}

$over = New-Object System.Collections.Generic.List[string]
$warned = 0

foreach ($file in $files) {
    $size = [int64]$file.Length
    $sizeMb = [Math]::Round($size / $bytesPerMb, 3)
    $limitMbText = [Math]::Round($limitBytes / $bytesPerMb, 3)
    if ($size -gt $limitBytes) {
        $line = ("超过限额：{0}  实际 {1} 字节（{2} MB），限额 {3} 字节（{4} MB）" -f `
                $file.FullName, $size, $sizeMb, $limitBytes, $limitMbText)
        Write-Error $line
        $over.Add($file.FullName) | Out-Null
    }
    elseif ($size -ge $warnBytes) {
        $warnMbText = [Math]::Round($warnBytes / $bytesPerMb, 3)
        Write-Warning ("接近限额（≥{0}%）：{1}  实际 {2} 字节（{3} MB），限额 {4} 字节（{5} MB），警告线 {6} 字节（{7} MB）" -f `
                $WarnPercent, $file.FullName, $size, $sizeMb, $limitBytes, $limitMbText, $warnBytes, $warnMbText)
        $warned++
    }
    else {
        Write-Host ("通过：{0}  {1} 字节（{2} MB）" -f $file.Name, $size, $sizeMb)
    }
}

if ($over.Count -gt 0) {
    Write-Error ("失败：{0} 个文件超过限额 {1} MB" -f $over.Count, $LimitMB)
    exit 1
}

if ($warned -gt 0) {
    Write-Host ("完成：{0} 个文件，{1} 个达到警告线（限额的 {2}%），均未超过限额 {3} MB" -f `
            $files.Count, $warned, $WarnPercent, $LimitMB)
}
else {
    Write-Host ("完成：{0} 个文件均低于限额 {1} MB" -f $files.Count, $LimitMB)
}
exit 0

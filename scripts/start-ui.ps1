# 双击启动 AgentWatch 的本机预览界面。
#
# 做的事：
#   1. 若 release 版 daemon 不存在，先编译一次（界面已在 ui/dist 里时会嵌进去）。
#   2. 若 7456 上还没有 daemon，用 .aw-preview 配置在后台启动一个。
#   3. 等 /health 有响应后，用系统浏览器打开 http://127.0.0.1:7456/ 。
#
# 只有配置里 debug.preview_ui = true 时，daemon 才会在首页发一次性票据，
# 浏览器才能越过登录页。这个开关只该出现在本机预览配置里。
# 停止用 scripts/restart-ui.ps1，或在数据目录里放一个 agentwatchd.stop。

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$config = Join-Path $root ".aw-preview\agentwatchd.toml"
$dataDir = Join-Path $root ".aw-preview\data"
$exe = Join-Path $root "target\release\agentwatchd.exe"
$url = "http://127.0.0.1:7456/"

if (-not (Test-Path -LiteralPath $config)) {
    # 配置含本机数据目录，不入库。缺失时按当前仓库位置生成，换机器不用手改。
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $config) | Out-Null
    $dataDirToml = $dataDir -replace "\\", "/"
    @"
[storage]
data_dir = "$dataDirToml"

[debug]
# 本机预览用。打开后浏览器访问首页会拿到一次性票据，才能进入界面。
# 不要把这个开关放进正式部署的配置。
preview_ui = true
"@ | Set-Content -LiteralPath $config -Encoding utf8
    Write-Host "已生成本机预览配置：$config"
}

if (-not (Test-Path -LiteralPath $exe)) {
    Write-Host "还没有 release 版 daemon，开始编译（第一次会比较久）..."
    & cargo build -p aw-daemon --release --bin agentwatchd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "编译失败，退出码 $LASTEXITCODE。"
        Read-Host "按回车关闭"
        exit $LASTEXITCODE
    }
}

# /health 不需要票据。能连上就说明 daemon 已经在跑，不再启动第二个。
$running = $false
try {
    $health = Invoke-WebRequest -Uri "http://127.0.0.1:7456/health" -UseBasicParsing -TimeoutSec 3
    $running = $health.StatusCode -eq 200
} catch {
    $running = $false
}

if (-not $running) {
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    # 上次留下的停止标记会让新进程一启动就退出。
    $stop = Join-Path $dataDir "agentwatchd.stop"
    if (Test-Path -LiteralPath $stop) {
        Remove-Item -LiteralPath $stop -Force
    }
    Write-Host "启动 daemon..."
    Start-Process -FilePath $exe -ArgumentList @("--foreground", "--config", $config) -WorkingDirectory $root -WindowStyle Hidden

    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        try {
            $health = Invoke-WebRequest -Uri "http://127.0.0.1:7456/health" -UseBasicParsing -TimeoutSec 3
            if ($health.StatusCode -eq 200) { $running = $true; break }
        } catch {
            $running = $false
        }
    }
}

if (-not $running) {
    Write-Host "daemon 没有在 30 秒内开始响应。日志在 $dataDir\agentwatchd.log"
    Read-Host "按回车关闭"
    exit 1
}

Write-Host "打开 $url"
Start-Process $url

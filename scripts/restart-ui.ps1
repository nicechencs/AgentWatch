# 双击重启 AgentWatch 的本机预览界面。
#
# 先在数据目录放一个 agentwatchd.stop，daemon 检测到后会自己退出；
# 等端口放开，再调用 start-ui.ps1 重新启动并打开浏览器。
# 不杀进程，也不动证书库和系统代理。

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$dataDir = Join-Path $root ".aw-preview\data"
$stop = Join-Path $dataDir "agentwatchd.stop"

$wasRunning = $false
try {
    $health = Invoke-WebRequest -Uri "http://127.0.0.1:7456/health" -UseBasicParsing -TimeoutSec 3
    $wasRunning = $health.StatusCode -eq 200
} catch {
    $wasRunning = $false
}

if ($wasRunning) {
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    # daemon 每 50ms 看一次这个文件，看到就按自己的流程退出。
    New-Item -ItemType File -Force -Path $stop | Out-Null
    Write-Host "已通知 daemon 停止，等待端口放开..."

    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        try {
            Invoke-WebRequest -Uri "http://127.0.0.1:7456/health" -UseBasicParsing -TimeoutSec 3 | Out-Null
        } catch {
            $wasRunning = $false
            break
        }
    }
    if ($wasRunning) {
        Write-Host "daemon 在 20 秒内没有退出。日志在 $dataDir\agentwatchd.log"
        Read-Host "按回车关闭"
        exit 1
    }
} else {
    Write-Host "7456 上没有正在运行的 daemon，直接启动。"
}

& (Join-Path $PSScriptRoot "start-ui.ps1")
exit $LASTEXITCODE

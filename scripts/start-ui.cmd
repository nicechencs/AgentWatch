@echo off
rem 双击启动 AgentWatch 本机预览界面。逻辑在 start-ui.ps1。
cd /d "%~dp0.."
pwsh -NoProfile -File "%~dp0start-ui.ps1"
if errorlevel 1 (
    echo.
    echo 启动失败，见上面的提示。
    pause
)

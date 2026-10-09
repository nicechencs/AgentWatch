@echo off
rem 双击重启 AgentWatch 本机预览界面。逻辑在 restart-ui.ps1。
cd /d "%~dp0.."
pwsh -NoProfile -File "%~dp0restart-ui.ps1"
if errorlevel 1 (
    echo.
    echo 重启失败，见上面的提示。
    pause
)

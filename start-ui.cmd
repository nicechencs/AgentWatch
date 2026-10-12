@echo off
rem Double-click launcher for the local preview UI. Logic is in scripts\start-ui.ps1.
rem This file is pure ASCII on purpose: cmd.exe reads batch files in the system
rem code page (GBK on Chinese Windows), so UTF-8 Chinese here would swallow the
rem line breaks and the following commands.
cd /d "%~dp0"
pwsh -NoProfile -File "%~dp0scripts\start-ui.ps1"
if errorlevel 1 (
    echo.
    echo start-ui.ps1 failed. See the messages above.
    pause
)

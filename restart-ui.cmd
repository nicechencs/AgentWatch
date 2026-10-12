@echo off
rem Double-click restart for the local preview UI. Logic is in scripts\restart-ui.ps1.
rem Pure ASCII: cmd.exe reads batch files in the system code page, and UTF-8
rem Chinese in this file would be split into bogus commands.
cd /d "%~dp0"
pwsh -NoProfile -File "%~dp0scripts\restart-ui.ps1"
if errorlevel 1 (
    echo.
    echo restart-ui.ps1 failed. See the messages above.
    pause
)

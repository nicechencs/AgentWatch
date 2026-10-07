# Static checks for packaging units (P1-DAEMON-05).
#
# Reads the unit files and compares strings. Does not query SCM, systemd, or
# launchd, and does not call sc.exe, net.exe, systemctl, or launchctl.
# Run from the repository root:
#   pwsh packaging/tests/check-units.ps1

$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')

function Read-Unit {
    param([string]$Relative)
    $path = Join-Path $root $Relative
    if (-not (Test-Path -LiteralPath $path)) {
        throw "missing unit file: $path"
    }
    # Keep newlines as LF so the check matches the renderer on every OS.
    $text = [System.IO.File]::ReadAllText($path)
    return ($text -replace "`r`n", "`n" -replace "`r", "`n")
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if (-not $Text.Contains($Needle)) {
        throw "$Name is missing required text: $Needle"
    }
    Write-Output "ok  $Name contains: $Needle"
}

$failed = $false
try {
    $systemd = Read-Unit 'systemd/agentwatchd.service'
    Assert-Contains 'agentwatchd.service' $systemd 'Group=agentwatch'
    Assert-Contains 'agentwatchd.service' $systemd 'SupplementaryGroups=agentwatch'
    Assert-Contains 'agentwatchd.service' $systemd 'Restart=on-failure'
    Assert-Contains 'agentwatchd.service' $systemd 'User=root'
    Assert-Contains 'agentwatchd.service' $systemd 'Slice=agentwatch.slice'
    Assert-Contains 'agentwatchd.service' $systemd 'agentwatch.slice'
    Assert-Contains 'agentwatchd.service' $systemd 'groupadd --system'

    $windows = Read-Unit 'windows/AgentWatch.service.txt'
    Assert-Contains 'AgentWatch.service.txt' $windows 'service_name=AgentWatch'
    Assert-Contains 'AgentWatch.service.txt' $windows 'account=LocalSystem'
    Assert-Contains 'AgentWatch.service.txt' $windows 'obj=LocalSystem'
    Assert-Contains 'AgentWatch.service.txt' $windows 'users_group=AgentWatch Users'
    Assert-Contains 'AgentWatch.service.txt' $windows 'etw_session_prefix=AgentWatch-'
    Assert-Contains 'AgentWatch.service.txt' $windows 'failure.0.action=restart'
    Assert-Contains 'AgentWatch.service.txt' $windows 'failure.1.action=restart'
    Assert-Contains 'AgentWatch.service.txt' $windows 'failure.2.action=restart'
    Assert-Contains 'AgentWatch.service.txt' $windows 'actions= restart/5000/restart/10000/restart/30000'
    Assert-Contains 'AgentWatch.service.txt' $windows 'P1 has no proxy CA'

    $plist = Read-Unit 'launchd/dev.agentwatch.daemon.plist'
    Assert-Contains 'dev.agentwatch.daemon.plist' $plist '<key>Label</key>'
    Assert-Contains 'dev.agentwatch.daemon.plist' $plist '<string>dev.agentwatch.daemon</string>'
    Assert-Contains 'dev.agentwatch.daemon.plist' $plist '/Library/LaunchDaemons/dev.agentwatch.daemon.plist'
    Assert-Contains 'dev.agentwatch.daemon.plist' $plist '<string>root</string>'
    Assert-Contains 'dev.agentwatch.daemon.plist' $plist 'Unsigned and not notarized'

    # Idempotence of the check itself: reading twice yields the same bytes.
    $again = Read-Unit 'systemd/agentwatchd.service'
    if ($systemd -ne $again) {
        throw 'reading agentwatchd.service twice produced different text'
    }
    Write-Output 'ok  agentwatchd.service reads twice identically'

    Write-Output 'check-units: all static checks passed'
}
catch {
    Write-Error $_
    $failed = $true
}

if ($failed) {
    exit 1
}
exit 0

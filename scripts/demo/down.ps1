#Requires -Version 7.0
# scripts/demo/down.ps1 — M17-E Session 17.8.1 (ADR-084).
#
# Windows equivalent of down.sh — see that file's header for the full
# reasoning (reverse start order, logs preserved, database left as-is for
# up.sh's own next reset).
#
# [REF: ADR-084; build_M17E.md Phase 17.8 Session 17.8.1; scripts/demo/down.sh]

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

$StateDir = if ($env:VYOMANAUT_DEMO_STATE_DIR) { $env:VYOMANAUT_DEMO_STATE_DIR } else { Join-Path $env:TEMP "vyomanaut-demo" }
$PidFile = Join-Path $StateDir "pids"
$LogDir = Join-Path $StateDir "logs"

function Write-Log($msg) { Write-Host "[down.ps1] $msg" }

if (-not (Test-Path $PidFile)) {
    Write-Log "no $PidFile found — nothing appears to be up (or up.ps1 was never run)"
    exit 0
}

$pids = Get-Content $PidFile | Where-Object { $_.Trim() -ne "" }

# Reverse order: providers were appended after the microservice in
# up.ps1, so reversing the file's line order stops them before it.
[array]::Reverse($pids)

# [Changed — confirmed, not just flagged, this session] The previous version
# of this script attempted CloseMainWindow() here as a "graceful" first
# step, with its own comment already admitting it was unconfirmed and
# needed a real Windows rig to check. Now checked, against Microsoft's own
# documented behavior (Process.CloseMainWindow: "returns false if the
# associated process does not have a main window"): every process this
# script can ever encounter is one up.ps1 itself started, and up.ps1 starts
# every one of them with -WindowStyle Hidden plus redirected
# stdout/stderr — neither has a GUI window to send a close message to, so
# CloseMainWindow() was returning false and doing nothing on every single
# call, every time, unconditionally. The 6-second "grace period" that
# followed it was therefore pure wasted wait on Windows specifically —
# down.sh's SIGTERM genuinely reaches cmd/microservice's own signal
# handler on macOS/Linux; this script's equivalent attempt never had a
# mechanism to reach anything. Going straight to Stop-Process -Force:
# still a real, unconditional teardown (that part was never in question —
# only the pretense of a grace period before it was), just without paying
# 6 seconds for an attempt that could not have worked. If a real graceful
# stop is ever wanted here, it needs a P/Invoke GenerateConsoleCtrlEvent
# helper (no built-in PowerShell equivalent exists) — out of scope for
# this fix.
foreach ($pidStr in $pids) {
    $procId = [int]$pidStr
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Log "stopping pid $procId (force)"
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
}

Set-Content -Path $PidFile -Value ""
Write-Log "down. Logs preserved under $LogDir"

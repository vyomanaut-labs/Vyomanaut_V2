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

foreach ($pidStr in $pids) {
    $procId = [int]$pidStr
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($proc) {
        # [Flagged] Windows has no direct scriptable equivalent to POSIX
        # SIGTERM for an arbitrary console process short of a native
        # GenerateConsoleCtrlEvent call, which PowerShell does not expose
        # without a compiled helper. CloseMainWindow() is a best-effort
        # attempt at the same "ask nicely first" shutdown down.sh's SIGTERM
        # step performs — it is NOT confirmed equivalent to how
        # cmd/microservice/main.go's own signal.Notify(os.Interrupt,
        # syscall.SIGTERM) behaves under a Windows console-control event,
        # only exercised and confirmed by Karma on an actual Windows rig.
        # Stop-Process -Force below is the mechanism this script actually
        # relies on for a guaranteed teardown either way.
        Write-Log "stopping pid $procId (graceful close attempt)"
        $proc.CloseMainWindow() | Out-Null
    }
}

# Give every process a real chance at a clean shutdown (the microservice's
# own shutdownTimeout is 5s, cmd/microservice/main.go) before escalating.
Start-Sleep -Seconds 6

foreach ($pidStr in $pids) {
    $procId = [int]$pidStr
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Log "pid $procId still alive — forcing stop"
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
}

Set-Content -Path $PidFile -Value ""
Write-Log "down. Logs preserved under $LogDir"

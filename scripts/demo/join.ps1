#Requires -Version 7.0
# scripts/demo/join.ps1 — M17-E Session 17.8.1 (ADR-084 requirement 2,
# F-D-2, F-D-4).
#
# Windows equivalent of join.sh — the single command a volunteer runs on
# their own Windows desktop. See join.sh's header for the full reasoning
# (two-party OTP exchange, no database access, F-D-4's genuinely-different-
# machine requirement); this script mirrors its behaviour exactly.
#
# [REF: ADR-084 D-2, D-3, D-4, requirement 2, F-D-2, F-D-4; build_M17E.md
# Phase 17.8 Session 17.8.1; scripts/demo/join.sh]

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$MicroserviceUrl,

    [int]$ListenPort = 30303,
    [string]$AdvertiseAddr = "",
    [string]$DataDir = (Join-Path $env:USERPROFILE ".vyomanaut"),

    # [Added, M18 Stage 3] Passed straight through to `provider run`.
    # Empty (default) = this machine's daemon metrics stay loopback-only,
    # matching every prior run of this script. Only set this if the
    # network operator has asked you to, and only ever to 0.0.0.0:9091 on
    # this project's own isolated lab mesh — see join.sh's usage text for
    # the full warning (same flag, same daemon, same caveat either OS).
    [string]$MetricsAddr = ""
)

$ErrorActionPreference = "Stop"

function Write-Log($msg) { Write-Host "[join.ps1] $msg" }

function Assert-Tool($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Error "[join.ps1] required tool not found on PATH: $name"
        exit 1
    }
}
Assert-Tool go

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")

# Build (or reuse a cached) provider binary from THIS checkout — a
# volunteer's own desktop, F-D-4, so this build necessarily happens on the
# genuinely different machine the demo requires, not on the coordinator.
$BinDir = if ($env:VYOMANAUT_JOIN_BIN_DIR) { $env:VYOMANAUT_JOIN_BIN_DIR } else { Join-Path $RepoRoot ".vyomanaut-bin" }
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$ProviderBin = Join-Path $BinDir "provider.exe"

if (-not (Test-Path $ProviderBin)) {
    Write-Log "building the provider binary (first run on this desktop)"
    Push-Location $RepoRoot
    try {
        go build -o $ProviderBin ./cmd/provider/
        if ($LASTEXITCODE -ne 0) { throw "go build provider failed" }
    } finally {
        Pop-Location
    }
} else {
    Write-Log "reusing already-built provider binary at $ProviderBin (delete it to force a rebuild)"
}

$advertiseArgs = @()
if ($AdvertiseAddr) { $advertiseArgs = @("--advertise-addr", $AdvertiseAddr) }

$metricsArgs = @()
if ($MetricsAddr) { $metricsArgs = @("--metrics-addr", $MetricsAddr) }

# [Added — clock-skew preflight, evidence: a real college-lab desktop run
# over ZeroTier where the join itself, the OTP exchange, and onboarding all
# succeeded cleanly, yet every single heartbeat afterward came back
# "400: timestamp skew exceeds 5 minutes" (internal/api/provider.go,
# heartbeatTimestampSkew) until the provider was marked DEPARTED having
# never actually left. None of onboard/OTP/join check timestamps at all —
# only heartbeat (5 min, hardcoded) and the other provider-signed endpoints
# repair-download/vetting-gc (2 min, NetworkProfile.AuthRequestFreshnessWindow,
# ADR-036) do — so a clock problem is invisible through the entire happy
# path and only shows up minutes later as an unexplained DEPARTED.
#
# [Replaced — dedicated time endpoint] Previously this parsed the
# coordinator's HTTP `Date` response header off /.well-known/jwks.json — an
# endpoint that was only unauthenticated as a side effect of what it's
# actually for, never designed as a clock source, and required
# DateTime.Parse with an explicit invariant-culture/AssumeUniversal
# incantation just to turn an HTTP-date string back into a comparable
# instant. GET /api/v1/time (internal/api/servertime.go) is a
# purpose-built, unauthenticated endpoint that returns unix_epoch
# directly, so this block now does plain integer subtraction — no
# date-string parsing at all. Same trust model and same reason it still
# works on networks that filter outbound NTP (UDP 123) the same way this
# project has already seen campus Wi-Fi filter other unexpected outbound
# traffic (see provider guide §2.5): it's a plain HTTPS/TCP request to
# the coordinator, not UDP. A probe failure just warns and lets the
# script continue unchanged.
# [FLAGGED — logic only, not yet run against a live coordinator + real
# clock-skewed Windows machine; confirm empirically before relying on it.]
try {
    $probe = Invoke-RestMethod -Uri "$MicroserviceUrl/api/v1/time" -TimeoutSec 10
    if ($probe.unix_epoch) {
        $serverEpoch = [int64]$probe.unix_epoch
        $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $skewSeconds = [Math]::Abs($nowEpoch - $serverEpoch)
        if ($skewSeconds -gt 120) {
            Write-Host ""
            Write-Host "[join.ps1] WARNING: this machine's clock is $([Math]::Round($skewSeconds))s off from the coordinator's." -ForegroundColor Yellow
            Write-Host "[join.ps1] Past 120s, provider-signed requests (repair-download, vetting-gc) start getting rejected;" -ForegroundColor Yellow
            Write-Host "[join.ps1] past 300s, EVERY heartbeat is rejected and you'll eventually show DEPARTED without ever leaving." -ForegroundColor Yellow
            Write-Host "[join.ps1] Fix: as administrator, try 'w32tm /resync /force'." -ForegroundColor Yellow
            Write-Host "[join.ps1] If this network blocks NTP, set the clock manually instead — as administrator:" -ForegroundColor Yellow
            Write-Host "[join.ps1]   Set-Date -Date ([DateTimeOffset]::FromUnixTimeSeconds($serverEpoch).UtcDateTime).ToLocalTime()" -ForegroundColor Yellow
            Write-Host ""
            $proceed = Read-Host "Continue anyway? [y/N]"
            if ($proceed -notmatch '^[Yy]') { exit 1 }
        }
    }
} catch {
    Write-Log "warning: could not preflight-check clock skew against the coordinator ($($_.Exception.Message)) — continuing anyway"
}

$RegistrationRecord = Join-Path $DataDir "registration.json"
if (Test-Path $RegistrationRecord) {
    Write-Log "found an existing registration under $DataDir — skipping onboard, going straight to run"
} else {
    # [Added — parity gap found alongside the --mode=demo fix above]
    # join.sh validates E.164 format here in a re-prompt loop before ever
    # calling onboard; this script had no such loop — a mistyped number
    # (missing +, wrong digit count) fell straight through to onboard.go's
    # own validation, which does catch it, but only after this script had
    # already printed onboarding instructions referencing the bad number,
    # and the failure then terminated the whole script (`if ($LASTEXITCODE
    # -ne 0) { throw ... }` below) rather than giving an immediate,
    # specific re-prompt the way join.sh does. Not the heartbeat bug —
    # this one just makes a fat-fingered phone number a harsher retry
    # (re-run the whole script) instead of a same-terminal re-prompt.
    do {
        $Phone = Read-Host "Your phone number, E.164 format (e.g. +919876500001)"
        if ($Phone -notmatch '^\+[0-9]{8,15}$') {
            Write-Host "  not E.164 format (need a leading + then 8-15 digits) — try again." -ForegroundColor Yellow
        }
    } while ($Phone -notmatch '^\+[0-9]{8,15}$')

    Write-Log "onboarding — you'll be asked how much storage to share, then for the"
    Write-Log "6-digit code. Ask the network operator to read it back to you (they"
    Write-Log "get it by running: operator otp --otp-delivery-log=<path to their otp.log> $Phone"
    Write-Log "-- or with VYOMANAUT_OTP_DELIVERY_LOG set instead of the flag. Flags"
    Write-Log "must come before the phone number, or cmd/operator's flag parser stops"
    Write-Log "parsing at the phone number and drops every flag after it.)"

    $onboardArgs = @(
        "onboard",
        "--microservice-url=$MicroserviceUrl",
        "--phone=$Phone",
        "--data-dir=$DataDir",
        "--listen-port=$ListenPort"
    ) + $advertiseArgs
    & $ProviderBin @onboardArgs
    if ($LASTEXITCODE -ne 0) { throw "provider onboard failed" }
}

Write-Log "starting provider run (normal mode). Ctrl-C to stop sharing."
$DeclaredStorageGB = 10
if (Test-Path $RegistrationRecord) {
    try {
        $rec = Get-Content $RegistrationRecord -Raw | ConvertFrom-Json
        if ($rec.declared_storage_gb -gt 0) { $DeclaredStorageGB = $rec.declared_storage_gb }
    } catch {
        Write-Log "warning: could not parse $RegistrationRecord; defaulting --declared-storage-gb=$DeclaredStorageGB"
    }
}

# [Fixed, ADR-089 follow-up — confirmed live against a real Windows provider,
# Stage 3] `provider onboard` has no -mode-equivalent flag at all (a
# one-shot HTTP registration call, mode-independent — see onboard.go's own
# flag set), but `provider run` genuinely needs --mode=demo, and it was
# missing here. Omitting it defaults this daemon to PROD's own
# NetworkProfile (config/profiles.go: HeartbeatInterval 4h,
# DepartureThreshold 72h) while heartbeating against a microservice
# enforcing DEMO's much faster ones (30s heartbeat / 180s departure
# threshold, ADR-089 addendum) — RunHeartbeat
# (internal/p2p/heartbeat.go) starts its timer BEFORE the first send, so
# under the wrong profile no heartbeat is sent for the first ~4 hours,
# full stop. Observed symptom, exactly reproduced: the provider registers
# (PENDING_ONBOARDING appears on the console — `onboard` succeeded, being
# mode-independent) but never sends a heartbeat the server recognizes as
# timely, and the departure detector eventually marks it DEPARTED, having
# genuinely never heartbeat even once.
# join.sh already carries this exact fix, with this same explanation, from
# an earlier real-Mac run; it was never ported to this script until now —
# the two scripts had silently diverged on a correctness-critical flag.
$runArgs = @(
    "run",
    "--mode=demo",
    "--microservice-url=$MicroserviceUrl",
    "--data-dir=$DataDir",
    "--declared-storage-gb=$DeclaredStorageGB",
    "--listen-port=$ListenPort"
) + $advertiseArgs + $metricsArgs
& $ProviderBin @runArgs
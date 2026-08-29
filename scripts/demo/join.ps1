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
    [string]$DataDir = (Join-Path $env:USERPROFILE ".vyomanaut")
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

$RegistrationRecord = Join-Path $DataDir "registration.json"
if (Test-Path $RegistrationRecord) {
    Write-Log "found an existing registration under $DataDir — skipping onboard, going straight to run"
} else {
    $Phone = Read-Host "Your phone number, E.164 format (e.g. +919876500001)"

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

$runArgs = @(
    "run",
    "--microservice-url=$MicroserviceUrl",
    "--data-dir=$DataDir",
    "--declared-storage-gb=$DeclaredStorageGB",
    "--listen-port=$ListenPort"
) + $advertiseArgs
& $ProviderBin @runArgs

#Requires -Version 7.0
# scripts/demo/up.ps1 — M17-E Session 17.8.1 (ADR-084, F-D-2/F-D-3/F-D-4).
#
# Windows equivalent of up.sh. Windows is the primary demo-rig platform
# (ADR-010, ADR-041) — cmd/provider is pure Go and runs natively here, so a
# bash-only runner would make the easiest target the hardest to start.
# Mirrors up.sh's own sequence exactly: Postgres reset, demo migration,
# fresh binaries, microservice start, then N local normal-mode provider
# processes onboarded via the same operator-otp-reads-the-delivery-log
# automation up.sh uses — see that file's header for the full reasoning,
# not repeated here.
#
# [REF: ADR-084 D-2/D-3/D-4, F-D-2, F-D-3, F-D-4; build_M17E.md Phase 17.8
# Session 17.8.1; scripts/demo/up.sh (this script's bash counterpart, kept
# in lockstep intentionally)]

[CmdletBinding()]
param(
    [int]$Providers = 7,
    [int]$StorageGB = 10,
    [string]$AdvertiseAddr = "",
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

# ── locate the repo ──────────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
Set-Location $RepoRoot

function Write-Log($msg) { Write-Host "[up.ps1] $msg" }

function Assert-Tool($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Error "[up.ps1] required tool not found on PATH: $name"
        exit 1
    }
}
Assert-Tool go
Assert-Tool psql

# ── state directory ───────────────────────────────────────────────────────
$StateDir = if ($env:VYOMANAUT_DEMO_STATE_DIR) { $env:VYOMANAUT_DEMO_STATE_DIR } else { Join-Path $env:TEMP "vyomanaut-demo" }
$BinDir = Join-Path $StateDir "bin"
$LogDir = Join-Path $StateDir "logs"
$DataDir = Join-Path $StateDir "data"
$PidFile = Join-Path $StateDir "pids"
$EnvFile = Join-Path $StateDir "env"

New-Item -ItemType Directory -Force -Path $BinDir, $LogDir, $DataDir | Out-Null
Set-Content -Path $PidFile -Value ""

# ── Postgres connection (mirrors .github/workflows/ci.yml check-07) ───────
$PgHost = if ($env:PGHOST) { $env:PGHOST } else { "localhost" }
$PgPort = if ($env:PGPORT) { $env:PGPORT } else { "5432" }
$PgMigratorUser = if ($env:PGMIGRATORUSER) { $env:PGMIGRATORUSER } else { "vyomanaut_migrator" }
$PgMigratorPassword = if ($env:PGMIGRATORPASSWORD) { $env:PGMIGRATORPASSWORD } else { "devpass" }
$PgDatabase = if ($env:PGDATABASE) { $env:PGDATABASE } else { "vyomanaut_demo" }
$PgAppPassword = if ($env:PGAPPPASSWORD) { $env:PGAPPPASSWORD } else { "devpass" }

$env:PGPASSWORD = $PgMigratorPassword

Write-Log "resetting Postgres database '$PgDatabase' on ${PgHost}:${PgPort} as $PgMigratorUser"
psql -v ON_ERROR_STOP=1 -h $PgHost -p $PgPort -U $PgMigratorUser -d postgres `
    -c "DROP DATABASE IF EXISTS `"$PgDatabase`";" `
    -c "CREATE DATABASE `"$PgDatabase`" OWNER `"$PgMigratorUser`";"
if ($LASTEXITCODE -ne 0) { throw "psql: database reset failed" }

psql -v ON_ERROR_STOP=1 -h $PgHost -p $PgPort -U $PgMigratorUser -d $PgDatabase `
    -c "CREATE EXTENSION IF NOT EXISTS btree_gist;"
if ($LASTEXITCODE -ne 0) { throw "psql: btree_gist failed" }

Write-Log "generating and applying the demo schema (migrations/generator.go --profile=demo)"
$DemoSql = Join-Path $StateDir "001_demo.sql"
go run migrations/generator.go --profile=demo | Out-File -Encoding utf8 $DemoSql
if ($LASTEXITCODE -ne 0) { throw "migrations/generator.go failed" }
psql -v ON_ERROR_STOP=1 -h $PgHost -p $PgPort -U $PgMigratorUser -d $PgDatabase -f $DemoSql
if ($LASTEXITCODE -ne 0) { throw "psql: schema apply failed" }

psql -v ON_ERROR_STOP=1 -h $PgHost -p $PgPort -U $PgMigratorUser -d $PgDatabase -c `
    "ALTER ROLE vyomanaut_app WITH PASSWORD '$PgAppPassword'; ALTER ROLE vyomanaut_gc WITH PASSWORD '$PgAppPassword';"
if ($LASTEXITCODE -ne 0) { throw "psql: role passwords failed" }

# ── build fresh binaries ────────────────────────────────────────────────
Write-Log "building cmd/microservice, cmd/provider, cmd/operator"
go build -o (Join-Path $BinDir "microservice.exe") ./cmd/microservice/
if ($LASTEXITCODE -ne 0) { throw "go build microservice failed" }
go build -o (Join-Path $BinDir "provider.exe") ./cmd/provider/
if ($LASTEXITCODE -ne 0) { throw "go build provider failed" }
go build -o (Join-Path $BinDir "operator.exe") ./cmd/operator/
if ($LASTEXITCODE -ne 0) { throw "go build operator failed" }

# ── start the microservice ────────────────────────────────────────────────
function New-RandomHex([int]$bytes) {
    $buf = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buf)
    -join ($buf | ForEach-Object { $_.ToString("x2") })
}
function New-RandomBase64([int]$bytes) {
    $buf = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buf)
    [Convert]::ToBase64String($buf)
}

$AdminApiKey = New-RandomHex 32
$SigningSeed = New-RandomHex 32
$ClusterSeed = New-RandomBase64 32
$OtpLog = Join-Path $StateDir "otp.log"
Set-Content -Path $OtpLog -Value ""

Write-Log "starting microservice on port $Port (mode=demo, departure-threshold=90s)"
# Start-Process has no -Environment parameter that accepts a hashtable —
# the child process inherits the CURRENT process's environment instead, so
# these are set directly on $env: here (this script's only purpose is to
# launch the demo, so no restore-afterward is needed).
$env:PGHOST = $PgHost
$env:PGPORT = $PgPort
$env:PGDATABASE = $PgDatabase
$env:PGUSER = "vyomanaut_app"
$env:PGPASSWORD = $PgAppPassword
$env:PGMIGRATORUSER = $PgMigratorUser
$env:PGMIGRATORPASSWORD = $PgMigratorPassword
$env:VYOMANAUT_ADMIN_API_KEY = $AdminApiKey
$env:VYOMANAUT_MICROSERVICE_SIGNING_SEED = $SigningSeed
$env:VYOMANAUT_CLUSTER_MASTER_SEED = $ClusterSeed
$env:VYOMANAUT_HTTP_LISTEN_ADDR = ":$Port"
$msLog = Join-Path $LogDir "microservice.log"
$msProc = Start-Process -FilePath (Join-Path $BinDir "microservice.exe") `
    -ArgumentList "--mode=demo", "--otp-delivery-log=$OtpLog", "--departure-threshold=90s" `
    -RedirectStandardOutput $msLog -RedirectStandardError "$msLog.err" `
    -PassThru -WindowStyle Hidden
Add-Content -Path $PidFile -Value $msProc.Id

# ── detect a LAN-reachable address for join.ps1's volunteer ──────────────
function Get-LanIp {
    try {
        $addr = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq "Up" } | Select-Object -First 1).IPv4Address.IPAddress
        return $addr
    } catch { return $null }
}
$LanIp = Get-LanIp
if (-not $LanIp) {
    Write-Log "warning: could not autodetect a LAN IP; the URL below defaults to 127.0.0.1 (unreachable from another desktop) — pass one explicitly if you have volunteers on other machines"
    $LanIp = "127.0.0.1"
}
$MicroserviceUrl = "http://${LanIp}:$Port"

Write-Log "waiting for the microservice to answer /api/v1/admin/readiness"
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/admin/readiness" -Headers @{ "X-Admin-API-Key" = $AdminApiKey } -UseBasicParsing -TimeoutSec 2 | Out-Null
        $ready = $true
        break
    } catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) {
    Write-Error "[up.ps1] microservice never became reachable — see $msLog"
    exit 1
}

Set-Content -Path $EnvFile -Value @"
MICROSERVICE_URL=$MicroserviceUrl
ADMIN_API_KEY=$AdminApiKey
OTP_LOG=$OtpLog
BIN_DIR=$BinDir
PGHOST=$PgHost
PGPORT=$PgPort
PGDATABASE=$PgDatabase
"@

# ── start N local normal-mode providers (rehearsal fleet, F-D-3) ─────────
$NextPort = $Port + 1
for ($i = 1; $i -le $Providers; $i++) {
    $Phone = "+9197{0:D8}" -f (90000000 + $i)
    $ProviderDataDir = Join-Path $DataDir "provider-$i"
    $ProviderPort = $NextPort + $i - 1
    New-Item -ItemType Directory -Force -Path $ProviderDataDir | Out-Null

    $advertiseArgs = @()
    if ($AdvertiseAddr) { $advertiseArgs = @("--advertise-addr", $AdvertiseAddr) }

    Write-Log "onboarding local provider $i/$Providers (phone=$Phone, port=$ProviderPort)"
    $onboardLog = Join-Path $LogDir "onboard-$i.log"

    # PowerShell has no direct FIFO-with-nonblocking-open equivalent to
    # up.sh's approach; a piped .NET StandardInput stream on the child
    # process gives the same "write the code once the real onboard process
    # is already blocked reading stdin" property without a filesystem FIFO.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $BinDir "provider.exe"
    $onboardArgList = @(
        "onboard",
        "--microservice-url=$MicroserviceUrl",
        "--phone=$Phone",
        "--storage-gb=$StorageGB",
        "--data-dir=$ProviderDataDir",
        "--listen-port=$ProviderPort"
    ) + $advertiseArgs
    $psi.ArgumentList.Clear()
    foreach ($a in $onboardArgList) { $psi.ArgumentList.Add($a) }
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $onboardProc = [System.Diagnostics.Process]::Start($psi)

    $code = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $otpOut = & (Join-Path $BinDir "operator.exe") otp $Phone --mode=demo --otp-delivery-log=$OtpLog 2>$null
        if ($LASTEXITCODE -eq 0 -and $otpOut) {
            $code = ($otpOut -split '\s+')[0]
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $code) {
        $onboardProc.Kill()
        Write-Error "[up.ps1] provider ${i}: never saw an OTP for $Phone in $OtpLog"
        exit 1
    }

    $onboardProc.StandardInput.WriteLine($code)
    $onboardProc.StandardInput.Close()
    $stdout = $onboardProc.StandardOutput.ReadToEnd()
    $stderr = $onboardProc.StandardError.ReadToEnd()
    $onboardProc.WaitForExit()
    Set-Content -Path $onboardLog -Value ($stdout + "`n" + $stderr)
    if ($onboardProc.ExitCode -ne 0) {
        Write-Error "[up.ps1] provider ${i}: onboarding failed — see $onboardLog"
        exit 1
    }

    Write-Log "starting local provider $i/$Providers (run, normal mode)"
    $providerLog = Join-Path $LogDir "provider-$i.log"
    $runArgList = @(
        "run",
        "--mode=demo",
        "--microservice-url=$MicroserviceUrl",
        "--data-dir=$ProviderDataDir",
        "--declared-storage-gb=$StorageGB",
        "--listen-port=$ProviderPort"
    ) + $advertiseArgs
    $runProc = Start-Process -FilePath (Join-Path $BinDir "provider.exe") `
        -ArgumentList $runArgList `
        -RedirectStandardOutput $providerLog -RedirectStandardError "$providerLog.err" `
        -PassThru -WindowStyle Hidden
    Add-Content -Path $PidFile -Value $runProc.Id
}

Write-Log "up. Logs under $LogDir. Try:"
Write-Log "  $(Join-Path $BinDir 'operator.exe') watch --microservice-url=$MicroserviceUrl --admin-api-key=$AdminApiKey"

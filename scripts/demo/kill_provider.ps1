#Requires -Version 7.0
# scripts/demo/kill_provider.ps1 — Windows equivalent of kill_provider.sh.
#
# [Added, M18 Stage 2 — Windows demo run] Mirrors kill_provider.sh's own
# reasoning exactly (see that file's header for the full incident this
# script exists to prevent): a demo procedure that requires arithmetic on
# a pid-file line number to hit the right process WILL eventually kill the
# coordinator instead of a provider. This script takes the PROVIDER ID the
# operator already has in front of them from `operator shards` or the
# console's own Provider Fleet panel, resolves it to a rehearsal index by
# reading that index's own registration.json (never by asking the operator
# to count), and refuses to act on anything it cannot positively identify.
#
# Windows has no POSIX SIGTERM. Stop-Process -Force is an immediate,
# ungraceful termination — which is exactly the "a volunteer's PC lost
# power" semantic this script is for (kill_provider.sh's own doc comment
# calls it "ungraceful: SIGTERM, no notice"; on Windows there is no
# "notice" step to skip in the first place, so this is not a weaker
# analog, it is the same outcome by the only mechanism this platform has).
#
# Usage:
#   scripts/demo/kill_provider.ps1 <provider_id>   # by the id operator shards/watch shows
#   scripts/demo/kill_provider.ps1 -Index 5        # by rehearsal index
#
# Prints the resolved index and data directory before acting, so the next
# command (`provider.exe inspect --data-dir=...`) can be copied from the
# output instead of reassembled by hand.
#
# [REF: scripts/demo/kill_provider.sh (this script's bash counterpart, kept
# in lockstep intentionally); scripts/demo/down.ps1 (Get-Content/pid-file
# conventions this script reuses verbatim)]

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$ProviderId,

    [int]$Index = -1
)

$ErrorActionPreference = "Stop"

function Write-Die($msg) {
    Write-Error "kill_provider: $msg"
    exit 1
}

function Show-Usage {
    @"
Usage:
  scripts/demo/kill_provider.ps1 <provider_id>
  scripts/demo/kill_provider.ps1 -Index <N>

Stops exactly one local rehearsal provider daemon (Stop-Process -Force, no
departure announcement) — the "a volunteer's PC lost power" path. It will
never touch the microservice.
"@ | Write-Host
    exit 2
}

if (-not $ProviderId -and $Index -lt 0) { Show-Usage }
if ($ProviderId -and $Index -ge 0) { Write-Die "pass either <provider_id> or -Index, not both" }

$StateDir = if ($env:VYOMANAUT_DEMO_STATE_DIR) { $env:VYOMANAUT_DEMO_STATE_DIR } else { Join-Path $env:TEMP "vyomanaut-demo" }
$PidFile = Join-Path $StateDir "pids"
$DataDir = Join-Path $StateDir "data"

# ── resolve the rehearsal index ──────────────────────────────────────────
if ($Index -ge 0) {
    # -Index passed directly; still validated below like every other path.
} else {
    if (-not (Test-Path $DataDir)) { Write-Die "no data directory at $DataDir — is the demo running?" }

    # Resolve the provider ID to its rehearsal directory. Select-String -List
    # over the registration records is the same lookup kill_provider.sh's
    # own grep -l performs, but the result is used directly rather than
    # transcribed by a human.
    $registrationMatches = @(Get-ChildItem -Path (Join-Path $DataDir "provider-*\registration.json") -ErrorAction SilentlyContinue |
        Where-Object { (Select-String -Path $_.FullName -Pattern ([regex]::Escape($ProviderId)) -List -Quiet) })

    if (-not $registrationMatches -or $registrationMatches.Count -eq 0) {
        Write-Die "provider $ProviderId is not one of this machine's rehearsal providers (it may be a join.ps1 volunteer — stop those with Ctrl-C in their own terminal)"
    }
    if ($registrationMatches.Count -gt 1) {
        Write-Die "provider $ProviderId matched more than one data directory; refusing to guess"
    }

    # .../data/provider-5/registration.json -> 5
    $providerDirName = Split-Path -Leaf (Split-Path -Parent $registrationMatches[0].FullName)
    $regexMatch = [regex]::Match($providerDirName, '^provider-(\d+)$')
    if (-not $regexMatch.Success) {
        Write-Die "could not derive a rehearsal index from $($registrationMatches[0].FullName)"
    }
    $Index = [int]$regexMatch.Groups[1].Value
}

if ($Index -lt 1) { Write-Die "rehearsal index must be 1 or greater, got $Index (index 0 would resolve to the microservice)" }

$ProviderDir = Join-Path $DataDir "provider-$Index"
if (-not (Test-Path $ProviderDir)) { Write-Die "no such rehearsal provider: $ProviderDir" }
if (-not (Test-Path $PidFile)) { Write-Die "no pid file at $PidFile — is the demo running?" }

# ── resolve the pid ───────────────────────────────────────────────────────
# up.ps1 writes one Add-Content line per process, microservice first
# (array index 0), then provider 1..N in order (array indices 1..N) — so a
# rehearsal index maps directly to its own array index, with no +1/-1
# arithmetic anywhere in this script. Contrast kill_provider.sh, where
# sed -n "Np" is 1-indexed and does need a LINE = INDEX + 1 step; the
# difference is PowerShell array indexing, not a different pid-file
# layout — the two files are written in the same order.
$pidLines = @(Get-Content $PidFile | Where-Object { $_.Trim() -ne "" })
if ($Index -ge $pidLines.Count) {
    Write-Die "rehearsal index $Index has no corresponding pid-file entry, but the file only has $($pidLines.Count) lines (index 0 is the microservice)"
}

$targetPid = [int]$pidLines[$Index]
$msPid = [int]$pidLines[0]

if ($targetPid -eq $msPid) {
    Write-Die "refusing to kill pid $targetPid — that is the microservice (this is the exact mistake this script exists to prevent)"
}

$proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Host "kill_provider: provider-$Index (pid $targetPid) is already stopped."
} else {
    Stop-Process -Id $targetPid -Force
    Write-Host "kill_provider: sent a forceful stop to provider-$Index (pid $targetPid)."
}

Write-Host ""
Write-Host "  rehearsal index: $Index"
Write-Host "  data directory:  $ProviderDir"
Write-Host ""
Write-Host "Its storage lock is now free, so you can look inside what it was holding:"
Write-Host ""
# Single-quoted literal for the $env:BIN_DIR half (deliberately NOT
# interpolated — the operator's own shell has BIN_DIR set from sourcing
# env.ps1, this script does not, so it prints the reference unresolved for
# them to copy-paste into that shell), then -f formats in the one part
# this script DOES know: the just-resolved data directory.
$inspectLine = '  & "$env:BIN_DIR\provider.exe" inspect --data-dir="{0}" --hex --compare="<your original file>"' -f $ProviderDir
Write-Host $inspectLine
Write-Host ""
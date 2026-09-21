#Requires -Version 7.0
# scripts/demo/watch_rss.ps1 - Windows equivalent of watch_rss.sh.
#
# [Added, Stage 3 final report] Same purpose as watch_rss.sh: turn Sec
# 5.3's one-point-per-rung memory screenshot into a curve. Run one
# instance per target, in its own terminal tab, for the duration of a
# rung; it writes one CSV row per second for that target's whole run.
#
# Usage:
#   scripts/demo/watch_rss.ps1 -Name <process_name> -OutCsv <output_csv_path>
#   scripts/demo/watch_rss.ps1 -Name microservice -OutCsv C:\stage3\rss_coordinator.csv   # start BEFORE up.ps1
#   scripts/demo/watch_rss.ps1 -Name client       -OutCsv C:\stage3\rss_client_L100MB.csv # one file per rung
#
# Matches by process NAME every sample (Get-Process -Name), so it survives
# a restart of the target mid-sample, the same as watch_rss.sh's pgrep -x.
# Ctrl-C to stop.
#
# CPU is not a single Get-Process field on Windows the way ps -o %cpu is
# on macOS/Linux: TotalProcessorTime is a cumulative counter, not a rate.
# This script converts it to a rate itself, from the delta between
# consecutive samples of the SAME process id -- and resets that baseline
# whenever the resolved id changes (first sample, or a restart), so a
# restart never produces a bogus spike or a negative reading.
#
# A single-shot cross-check against this sampler's own peak, for comparing
# against whatever Task Manager showed at the same moment:
#
#   Get-Process client | Select-Object WorkingSet64, Id

param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string]$OutCsv
)

"epoch,iso8601,pid,rss_kb,cpu_pct" | Out-File -FilePath $OutCsv -Encoding utf8

$prevPid = $null
$prevCpuSeconds = $null
$prevSampleTime = $null

while ($true) {
    $proc = Get-Process -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) {
        if ($proc.Id -ne $prevPid) {
            # First sample, or the target restarted under the same name:
            # no valid prior sample to diff against yet this round.
            $prevCpuSeconds = $null
            $prevSampleTime = $null
            $prevPid = $proc.Id
        }

        $now = Get-Date
        $cpuSeconds = $proc.TotalProcessorTime.TotalSeconds
        $cpuPct = 0
        if ($null -ne $prevCpuSeconds -and $null -ne $prevSampleTime) {
            $elapsed = ($now - $prevSampleTime).TotalSeconds
            if ($elapsed -gt 0) {
                $cpuPct = [math]::Round((($cpuSeconds - $prevCpuSeconds) / $elapsed) * 100, 1)
            }
        }
        $prevCpuSeconds = $cpuSeconds
        $prevSampleTime = $now

        $rssKb = [math]::Round($proc.WorkingSet64 / 1KB)
        $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $iso = $now.ToString("yyyy-MM-ddTHH:mm:sszzz")
        "$epoch,$iso,$($proc.Id),$rssKb,$cpuPct" | Out-File -FilePath $OutCsv -Append -Encoding utf8
    }
    Start-Sleep -Seconds 1
}

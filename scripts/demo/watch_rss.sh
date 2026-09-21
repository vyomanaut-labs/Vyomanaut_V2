#!/usr/bin/env bash
# scripts/demo/watch_rss.sh -- sample a process's RSS and CPU once a second.
#
# [Added, Stage 3 final report] Sec 5.3's memory figure was one point per
# rung, read off an Activity Monitor screenshot at the top of each ladder
# step. This turns that into a curve: run one instance per target, in its
# own terminal tab, for the duration of a rung, and it writes one CSV row
# per second for that target's whole run.
#
# Usage:
#   scripts/demo/watch_rss.sh <process_name> <output_csv_path>
#   scripts/demo/watch_rss.sh microservice ~/stage3/rss_coordinator.csv   # start BEFORE up.sh
#   scripts/demo/watch_rss.sh client       ~/stage3/rss_client_L100MB.csv # one file per rung
#
# Matches by process NAME (not a fixed PID), so it survives a restart of
# the target mid-sample. Ctrl-C to stop.
#
# bash 3.2 compatible (macOS's shipped bash): no associative arrays, no
# mapfile, no [[ =~ ]] capture groups -- see ways-of-working's bash 3.2
# constraint for join.sh/up.sh/down.sh, which this script shares a
# directory with.
#
# A single-shot cross-check against this sampler's own peak, for comparing
# against whatever Activity Monitor / Task Manager showed at the same
# moment (macOS/Linux only -- /usr/bin/time -l is a BSD/macOS flag; GNU
# time uses -v instead):
#
#   /usr/bin/time -l "$BIN_DIR/client" upload --mode=demo \
#     --microservice-url="$MSURL" --data-dir="$OWNER_DIR" \
#     ~/ladder/L100MB.bin 2>&1 | tail -20   # "maximum resident set size"
set -euo pipefail

NAME="${1:?process name, e.g. client}"
OUT="${2:?output csv path}"

echo "epoch,iso8601,pid,rss_kb,cpu_pct" > "$OUT"

while true; do
  PID="$(pgrep -x "$NAME" | head -1 || true)"
  if [ -n "$PID" ]; then
    read -r RSS CPU <<< "$(ps -o rss=,%cpu= -p "$PID" | awk '{print $1, $2}')"
    printf '%s,%s,%s,%s,%s\n' "$(date +%s)" "$(date -Iseconds)" "$PID" "$RSS" "$CPU" >> "$OUT"
  fi
  sleep 1
done

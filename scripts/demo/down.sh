#!/usr/bin/env bash
# scripts/demo/down.sh — M17-E Session 17.8.1 (ADR-084).
#
# Stops every process up.sh started (microservice + local rehearsal
# providers), by PID, in reverse start order — providers before the
# microservice they depend on. Logs are left in place under
# $VYOMANAUT_DEMO_STATE_DIR/logs (default /tmp/vyomanaut-demo/logs); this
# script's job is process teardown, not log rotation or deletion. The
# Postgres database itself is left as-is too — up.sh's own next run does a
# full DROP/CREATE, so down.sh doing it a second time here would be
# redundant, not safer.
#
# [REF: ADR-084; build_M17E.md Phase 17.8 Session 17.8.1]
set -euo pipefail

STATE_DIR="${VYOMANAUT_DEMO_STATE_DIR:-/tmp/vyomanaut-demo}"
PID_FILE="$STATE_DIR/pids"
LOG_DIR="$STATE_DIR/logs"

log() { echo "[down.sh] $*"; }

if [[ ! -f "$PID_FILE" ]]; then
  log "no $PID_FILE found — nothing appears to be up (or up.sh was never run)"
  exit 0
fi

# Reverse order: providers were appended after the microservice in
# up.sh, so reversing the file's line order stops them before it.
mapfile -t PIDS < "$PID_FILE"
for (( idx=${#PIDS[@]}-1; idx>=0; idx-- )); do
  pid="${PIDS[$idx]}"
  [[ -z "$pid" ]] && continue
  if kill -0 "$pid" 2>/dev/null; then
    log "stopping pid $pid (SIGTERM)"
    kill -TERM "$pid" 2>/dev/null || true
  fi
done

# Give every process a real chance at a clean shutdown (the microservice's
# own shutdownTimeout is 5s, cmd/microservice/main.go) before escalating.
sleep 6

for (( idx=${#PIDS[@]}-1; idx>=0; idx-- )); do
  pid="${PIDS[$idx]}"
  [[ -z "$pid" ]] && continue
  if kill -0 "$pid" 2>/dev/null; then
    log "pid $pid still alive after SIGTERM — sending SIGKILL"
    kill -KILL "$pid" 2>/dev/null || true
  fi
done

: > "$PID_FILE"
log "down. Logs preserved under $LOG_DIR"

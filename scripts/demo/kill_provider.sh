#!/usr/bin/env bash
# scripts/demo/kill_provider.sh — stop ONE local rehearsal provider, safely.
#
# [Added, Session 18.1.4] This exists because of a real incident, not a
# hypothetical one. The operator guide's ungraceful-departure step read:
#
#     grep -l "<provider_id>" "$STATE_DIR"/data/provider-*/registration.json
#     kill -TERM "$(sed -n "$((N+1))p" "$STATE_DIR/pids")"
#
# and left N as something the reader was supposed to notice and set. With N
# unset, bash evaluates $((N+1)) as 0+1 = 1 — silently, no error, no unbound
# variable warning even under `set -u`, because arithmetic context treats an
# empty name as zero. Line 1 of the pids file is the MICROSERVICE. So the
# step that was meant to kill one provider killed the coordinator instead,
# and every downstream symptom (connection refused, the whole fleet going
# OVERDUE, the console showing fetch errors) followed from that.
#
# The lesson is not "set N more carefully." It is that a demo procedure
# should not require arithmetic on a line number to hit the right process.
# This script takes the PROVIDER ID the operator already has in front of
# them from `operator shards`, resolves it to a data directory, reads that
# directory's own recorded index, and refuses to act on anything it cannot
# positively identify as a provider.
#
# Usage:
#   scripts/demo/kill_provider.sh <provider_id>     # ungraceful: SIGTERM, no notice
#   scripts/demo/kill_provider.sh --index 5         # same, by rehearsal index
#
# Prints the resolved index and data directory before acting, so the next
# command (`provider inspect --data-dir=...`) can be copied from the output
# instead of reassembled by hand.
set -euo pipefail

STATE_DIR="${VYOMANAUT_DEMO_STATE_DIR:-${STATE_DIR:-/tmp/vyomanaut-demo}}"
PID_FILE="$STATE_DIR/pids"
DATA_DIR="$STATE_DIR/data"

die() { echo "kill_provider: $*" >&2; exit 1; }

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/demo/kill_provider.sh <provider_id>
  scripts/demo/kill_provider.sh --index <N>

Stops exactly one local rehearsal provider daemon (SIGTERM, no departure
announcement) — the "a volunteer's PC lost power" path. It will never touch
the microservice.
USAGE
  exit 2
}

[[ $# -ge 1 ]] || usage

INDEX=""
case "$1" in
  --index)
    [[ $# -eq 2 ]] || usage
    INDEX="$2"
    [[ "$INDEX" =~ ^[0-9]+$ ]] || die "--index must be a whole number, got '$INDEX'"
    ;;
  -h|--help) usage ;;
  -*) usage ;;
  *)
    PROVIDER_ID="$1"
    [[ -d "$DATA_DIR" ]] || die "no data directory at $DATA_DIR — is the demo running?"
    # Resolve the provider ID to its rehearsal directory. grep -l over the
    # registration records is the same lookup the guide already documents,
    # but the result is used directly rather than transcribed by a human.
    match="$(grep -l -- "$PROVIDER_ID" "$DATA_DIR"/provider-*/registration.json 2>/dev/null || true)"
    [[ -n "$match" ]] || die "provider $PROVIDER_ID is not one of this machine's rehearsal providers (it may be a join.sh volunteer — stop those with Ctrl-C in their own terminal)"
    [[ "$(printf '%s\n' "$match" | wc -l)" -eq 1 ]] || die "provider $PROVIDER_ID matched more than one data directory; refusing to guess"
    # .../data/provider-5/registration.json -> 5
    INDEX="$(basename "$(dirname "$match")")"
    INDEX="${INDEX#provider-}"
    [[ "$INDEX" =~ ^[0-9]+$ ]] || die "could not derive a rehearsal index from $match"
    ;;
esac

[[ "$INDEX" -ge 1 ]] || die "rehearsal index must be 1 or greater, got $INDEX (index 0 would resolve to the microservice)"

PROVIDER_DIR="$DATA_DIR/provider-$INDEX"
[[ -d "$PROVIDER_DIR" ]] || die "no such rehearsal provider: $PROVIDER_DIR"
[[ -f "$PID_FILE" ]] || die "no pid file at $PID_FILE — is the demo running?"

# Line 1 is the microservice; providers 1..N are lines 2..N+1. The +1 is
# done here, once, on a value already proven to be a positive integer —
# never on an unset shell variable.
LINE=$((INDEX + 1))
TOTAL_LINES="$(wc -l < "$PID_FILE" | tr -d ' ')"
[[ "$LINE" -le "$TOTAL_LINES" ]] || die "rehearsal index $INDEX maps to pid-file line $LINE, but the file only has $TOTAL_LINES lines"

PID="$(sed -n "${LINE}p" "$PID_FILE")"
[[ "$PID" =~ ^[0-9]+$ ]] || die "pid-file line $LINE is not a pid: '$PID'"

MS_PID="$(sed -n '1p' "$PID_FILE")"
[[ "$PID" != "$MS_PID" ]] || die "refusing to kill pid $PID — that is the microservice (this is the exact mistake this script exists to prevent)"

if ! kill -0 "$PID" 2>/dev/null; then
  echo "kill_provider: provider-$INDEX (pid $PID) is already stopped."
else
  kill -TERM "$PID"
  echo "kill_provider: sent SIGTERM to provider-$INDEX (pid $PID)."
fi

cat <<INFO

  rehearsal index: $INDEX
  data directory:  $PROVIDER_DIR

Its storage lock is now free, so you can look inside what it was holding:

  "\$BIN_DIR/provider" inspect --data-dir="$PROVIDER_DIR" --hex --compare="<your original file>"

INFO

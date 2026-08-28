#!/usr/bin/env bash
# scripts/demo/join.sh — M17-E Session 17.8.1 (ADR-084 requirement 2, F-D-2,
# F-D-4).
#
# The single command a volunteer runs on THEIR OWN desktop — a genuinely
# different machine from wherever up.sh's microservice is running (F-D-4).
# Builds (or reuses) the provider binary from this checkout, runs
# `provider onboard` interactively — the volunteer answers two prompts on
# their own terminal: how much storage to share, and the 6-digit code the
# network operator reads back to them from cmd/microservice's OTP delivery
# log (requirement 2's actual two-party flow, ADR-084 D-3) — then starts
# `provider run` in the foreground.
#
# No database access of any kind happens on this path (F-D-2): the only
# network calls this script or the binary it runs ever make are to
# --microservice-url, over the same admin-free HTTPS/HTTP API surface
# ADR-084's operator console itself is limited to reading — a volunteer
# needs no credential this project considers privileged.
#
# [REF: ADR-084 D-2, D-3, D-4, requirement 2, F-D-2, F-D-4; build_M17E.md
# Phase 17.8 Session 17.8.1; cmd/provider/onboard.go (the interactive flow
# this script drives, unmodified — never scripted around)]
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/demo/join.sh <microservice-url> [--listen-port PORT] [--advertise-addr ADDR] [--data-dir DIR]

  <microservice-url>     Required. The URL the network operator gave you,
                          e.g. http://192.168.1.42:8080 — printed by up.sh.
  --listen-port PORT     Inbound port this desktop advertises (default 30303).
  --advertise-addr ADDR  This desktop's own reachable IPv4 address. Empty =
                          autodetect (F-D-4) — only override this if
                          autodetection picks the wrong interface.
  --data-dir DIR         Where this provider's identity and storage live
                          (default ~/.vyomanaut). Re-running join.sh with the
                          same --data-dir resumes an already-onboarded provider
                          instead of onboarding again.
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi

MICROSERVICE_URL="$1"
shift

LISTEN_PORT=30303
ADVERTISE_ADDR=""
DATA_DIR="${HOME:-.}/.vyomanaut"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --listen-port) LISTEN_PORT="$2"; shift 2 ;;
    --advertise-addr) ADVERTISE_ADDR="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage; exit 2 ;;
  esac
done

log() { echo "[join.sh] $*"; }

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[join.sh] required tool not found on PATH: $1" >&2
    exit 1
  fi
}
require_tool go

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." >/dev/null 2>&1 && pwd)"

# Build (or reuse a cached) provider binary from THIS checkout — a
# volunteer's own desktop, F-D-4, so this build necessarily happens on the
# genuinely different machine the demo requires, not on the coordinator.
BIN_DIR="${VYOMANAUT_JOIN_BIN_DIR:-$REPO_ROOT/.vyomanaut-bin}"
mkdir -p "$BIN_DIR"
PROVIDER_BIN="$BIN_DIR/provider"

if [[ ! -x "$PROVIDER_BIN" ]]; then
  log "building the provider binary (first run on this desktop)"
  ( cd "$REPO_ROOT" && go build -o "$PROVIDER_BIN" ./cmd/provider/ )
else
  log "reusing already-built provider binary at $PROVIDER_BIN (delete it to force a rebuild)"
fi

# [Third bash-3.2 landmine found in this project's scripts/demo/ — see
# up.sh's own history] An empty array expanded bare as
# "${ADVERTISE_FLAG[@]}" under `set -u` throws "unbound variable" on bash
# 3.2 through 4.3 (fixed in 4.4+) — macOS's system /bin/bash is 3.2.57,
# confirmed live on a real Mac run of up.sh. Every use of this array below
# is written as "${ADVERTISE_FLAG[@]+"${ADVERTISE_FLAG[@]}"}" (BashFAQ
# 112's portable idiom) instead of a bare "${ADVERTISE_FLAG[@]}",
# specifically so an empty --advertise-addr (the common case) doesn't
# crash this script on the exact machine a volunteer is most likely to run
# it on.
ADVERTISE_FLAG=()
if [[ -n "$ADVERTISE_ADDR" ]]; then
  ADVERTISE_FLAG=(--advertise-addr "$ADVERTISE_ADDR")
fi

REGISTRATION_RECORD="$DATA_DIR/registration.json"
if [[ -f "$REGISTRATION_RECORD" ]]; then
  log "found an existing registration under $DATA_DIR — skipping onboard, going straight to run"
else
  read -r -p "Your phone number, E.164 format (e.g. +919876500001): " PHONE

  log "onboarding — you'll be asked how much storage to share, then for the"
  log "6-digit code. Ask the network operator to read it back to you — on"
  log "the coordinator machine (wherever up.sh is running), they get it by"
  log "running: operator otp $PHONE --otp-delivery-log=<path to their otp.log>"
  log "(or with VYOMANAUT_OTP_DELIVERY_LOG set instead of the flag)."
  "$PROVIDER_BIN" onboard \
    --microservice-url="$MICROSERVICE_URL" \
    --phone="$PHONE" \
    --data-dir="$DATA_DIR" \
    --listen-port="$LISTEN_PORT" \
    "${ADVERTISE_FLAG[@]+"${ADVERTISE_FLAG[@]}"}"
fi

log "starting provider run (normal mode). Ctrl-C to stop sharing."
# Portable extraction from onboard's own single-line JSON record
# (registrationRecord, onboard.go) — grep/sed rather than a JSON tool, since
# nothing beyond a POSIX toolchain and Go itself should be required on a
# volunteer's desktop (ADR-010/ADR-041's Windows-primary-rig point applies
# here just as much as to the daemon itself).
DECLARED_STORAGE_GB="$(grep -o '"declared_storage_gb":[0-9]*' "$REGISTRATION_RECORD" 2>/dev/null | grep -o '[0-9]*$' || true)"
if [[ -z "$DECLARED_STORAGE_GB" || "$DECLARED_STORAGE_GB" -le 0 ]]; then
  DECLARED_STORAGE_GB=10
  log "warning: could not read declared storage from $REGISTRATION_RECORD; defaulting --declared-storage-gb=$DECLARED_STORAGE_GB"
fi

exec "$PROVIDER_BIN" run \
  --microservice-url="$MICROSERVICE_URL" \
  --data-dir="$DATA_DIR" \
  --declared-storage-gb="$DECLARED_STORAGE_GB" \
  --listen-port="$LISTEN_PORT" \
  "${ADVERTISE_FLAG[@]+"${ADVERTISE_FLAG[@]}"}"

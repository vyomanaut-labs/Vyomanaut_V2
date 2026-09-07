#!/usr/bin/env bash
# scripts/demo/up.sh — M17-E Session 17.8.1 (ADR-084, F-D-2/F-D-3/F-D-4).
#
# Resets Postgres, applies the demo migration, builds cmd/microservice,
# cmd/provider, cmd/operator, and cmd/client fresh, starts the microservice,
# then starts N *normal-mode* providers as N distinct OS processes on distinct
# ports (F-D-3: none of the simulation-mode flags appear anywhere in this
# directory) so the coordinator
# side of the demo exercises the exact code path the physical rig runs.
#
# [Extended, Session 18.1.1 — Operator Guide upgrade] cmd/client (the data
# owner's own CLI: register/deposit/upload/retrieve/ls/rm/balance) has no
# dependency on internal/storage and therefore no RocksDB/CGO requirement —
# unlike microservice/provider, it never needs the CGO_CFLAGS/CGO_LDFLAGS
# environment this script's own callers export before running it. It is
# built here purely so a data-owner demo walkthrough never needs a second,
# separate build step: everything up.sh's own printed BIN_DIR already
# promises ("Freshly built each up.sh run") now actually includes it.
#
# The N providers this script starts are the rehearsal/smoke fleet run
# locally alongside the microservice — real, separate normal-mode processes,
# but on this one host. They are NOT a substitute for the physical rig:
# join.sh is the actual volunteer-desktop path (F-D-4, a genuinely different
# machine). This script automates each local provider's OTP step by reading
# cmd/microservice's own delivery log via the just-built `operator otp`
# command — the same tool a human network operator would run by hand for a
# real join.sh volunteer, just invoked non-interactively here because both
# halves of the two-party OTP exchange happen to be colocated on this host.
#
# [REF: ADR-084 D-2/D-3/D-4, F-D-2, F-D-3, F-D-4; build_M17E.md Phase 17.8
# Session 17.8.1; scripts/test/helpers_test.go's startMicroserviceWithFlags
# (the live-test convention this script mirrors for a human-run demo);
# .github/workflows/ci.yml check-07 (the migration-apply sequence this
# script mirrors for a fresh Postgres)]
set -euo pipefail

# ── locate the repo ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." >/dev/null 2>&1 && pwd)"
cd -- "$REPO_ROOT"

# ── flags ─────────────────────────────────────────────────────────────────
# Default 7, not the demo profile's own MinActiveProviders floor of 5:
# ADR-075's own finding is that the demo topology sits at *exactly* full
# ASN-cap occupancy at 7 providers (floor(5 x 0.20) = 1 headroom) — the
# canonical rehearsal fleet size this project already treats as "the
# demo," not an arbitrary round number.
PROVIDERS=7
STORAGE_GB=10
ADVERTISE_ADDR=""
ADVERTISE_HOST=""
PORT=8080

usage() {
  cat <<'EOF'
Usage: scripts/demo/up.sh [--providers N] [--storage-gb N] [--advertise-addr ADDR]
                           [--advertise-host HOST] [--port PORT]

  --providers N        Number of local normal-mode provider processes to start (default 7).
  --storage-gb N       Storage each local provider declares, in GB (default 10).
  --advertise-addr ADDR  IPv4 address the LOCAL REHEARSAL providers this script itself
                          starts advertise. Empty = autodetect (F-D-4). Irrelevant to a
                          real multi-machine rig, where every volunteer sets their OWN
                          address via join.sh/join.ps1's own --advertise-addr instead.
  --advertise-host HOST  The address THIS MACHINE (the coordinator) prints as
                          MICROSERVICE_URL for every other machine to dial — e.g. an
                          overlay-mesh IP (ADR-089). Empty = autodetect a LAN address
                          (best-effort; wrong or absent on a machine with more than one
                          active network interface, which an overlay mesh adapter plus a
                          Wi-Fi/Ethernet adapter both being up always is). ALWAYS pass
                          this explicitly outside a single-NIC machine — see ADR-089 and
                          guides/operator_and_client_guide.md.
  --port PORT          Microservice HTTP port (default 8080).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --providers) PROVIDERS="$2"; shift 2 ;;
    --storage-gb) STORAGE_GB="$2"; shift 2 ;;
    --advertise-addr) ADVERTISE_ADDR="$2"; shift 2 ;;
    --advertise-host) ADVERTISE_HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage; exit 2 ;;
  esac
done

# ── state directory (down.sh and join.sh's own printed URL both read this) ─
STATE_DIR="${VYOMANAUT_DEMO_STATE_DIR:-/tmp/vyomanaut-demo}"
BIN_DIR="$STATE_DIR/bin"
LOG_DIR="$STATE_DIR/logs"
DATA_DIR="$STATE_DIR/data"
PID_FILE="$STATE_DIR/pids"
ENV_FILE="$STATE_DIR/env"

mkdir -p "$BIN_DIR" "$LOG_DIR" "$DATA_DIR"
: > "$PID_FILE"

log() { echo "[up.sh] $*"; }

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[up.sh] required tool not found on PATH: $1" >&2
    exit 1
  fi
}
require_tool go
require_tool psql
require_tool openssl
require_tool curl

# ── Postgres connection (mirrors .github/workflows/ci.yml check-07) ───────
PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGMIGRATORUSER="${PGMIGRATORUSER:-vyomanaut_migrator}"
PGMIGRATORPASSWORD="${PGMIGRATORPASSWORD:-devpass}"
PGDATABASE="${PGDATABASE:-vyomanaut_demo}"
PGAPPPASSWORD="${PGAPPPASSWORD:-devpass}"

export PGPASSWORD="$PGMIGRATORPASSWORD"

log "resetting Postgres database '$PGDATABASE' on $PGHOST:$PGPORT as $PGMIGRATORUSER"
psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" -U "$PGMIGRATORUSER" -d postgres \
  -c "DROP DATABASE IF EXISTS \"$PGDATABASE\";" \
  -c "CREATE DATABASE \"$PGDATABASE\" OWNER \"$PGMIGRATORUSER\";"

psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" -U "$PGMIGRATORUSER" -d "$PGDATABASE" \
  -c "CREATE EXTENSION IF NOT EXISTS btree_gist;"

log "generating and applying the demo schema (migrations/generator.go --profile=demo)"
DEMO_SQL="$STATE_DIR/001_demo.sql"
go run migrations/generator.go --profile=demo > "$DEMO_SQL"
psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" -U "$PGMIGRATORUSER" -d "$PGDATABASE" -f "$DEMO_SQL"

psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" -U "$PGMIGRATORUSER" -d "$PGDATABASE" -c \
  "ALTER ROLE vyomanaut_app WITH PASSWORD '$PGAPPPASSWORD';
   ALTER ROLE vyomanaut_gc  WITH PASSWORD '$PGAPPPASSWORD';"

# ── build fresh binaries — never a stale prior run's copy ─────────────────
log "building cmd/microservice, cmd/provider, cmd/operator, cmd/client"
go build -o "$BIN_DIR/microservice" ./cmd/microservice/
go build -o "$BIN_DIR/provider" ./cmd/provider/
go build -o "$BIN_DIR/operator" ./cmd/operator/
go build -o "$BIN_DIR/client" ./cmd/client/

# ── start the microservice ─────────────────────────────────────────────────
ADMIN_API_KEY="$(openssl rand -hex 32)"
SIGNING_SEED="$(openssl rand -hex 32)"
CLUSTER_SEED="$(openssl rand -base64 32)"
OTP_LOG="$STATE_DIR/otp.log"
: > "$OTP_LOG"

# [Changed, ADR-089 addendum — Stage 3 first real run] departure-threshold
# raised from 90s to 180s. Margin analysis against a real (not same-LAN)
# link: heartbeatHTTPTimeout (internal/p2p/heartbeat.go) bounds one stalled
# heartbeat POST at 15s, and RunHeartbeat does not retry within a cycle —
# a fully-timed-out attempt is simply followed by the next jittered
# ~30s±5s interval. Two consecutive failed attempts (a plausible cost of
# one Tailscale relay reconnect or Wi-Fi blip, not a departure) can
# therefore consume up to ~100s before a third attempt even starts, which
# left only ~10s of margin under the old LAN-tuned 90s value — a same-LAN
# run never stresses this because a stalled attempt there is near-instant,
# not 15s. 180s survives two consecutive full-timeout misses with room
# for a third attempt to land before crossing the threshold, at the cost
# of a genuine departure taking up to ~3 minutes to detect instead of
# ~1.5 — an acceptable trade for a scripted demo. Still demo-mode only and
# still validated against departureThresholdFloor (cmd/microservice/
# main.go) at startup; still far below DemoProfile's own 10-minute
# default.
log "starting microservice on port $PORT (mode=demo, departure-threshold=180s)"
PGHOST="$PGHOST" PGPORT="$PGPORT" PGDATABASE="$PGDATABASE" \
PGUSER=vyomanaut_app PGPASSWORD="$PGAPPPASSWORD" \
PGMIGRATORUSER="$PGMIGRATORUSER" PGMIGRATORPASSWORD="$PGMIGRATORPASSWORD" \
VYOMANAUT_ADMIN_API_KEY="$ADMIN_API_KEY" \
VYOMANAUT_MICROSERVICE_SIGNING_SEED="$SIGNING_SEED" \
VYOMANAUT_CLUSTER_MASTER_SEED="$CLUSTER_SEED" \
VYOMANAUT_HTTP_LISTEN_ADDR=":$PORT" \
  "$BIN_DIR/microservice" --mode=demo --otp-delivery-log="$OTP_LOG" --departure-threshold=180s \
  > "$LOG_DIR/microservice.log" 2>&1 &
MS_PID=$!
echo "$MS_PID" >> "$PID_FILE"

# ── decide the address the URL join.sh's volunteer needs ──────────────────
# [Changed, ADR-089] Three sources, in order, matching advertise.go's own
# explicit-beats-autodetect-beats-fallback shape (resolveAdvertiseHost):
#   1. --advertise-host, if given — the operator's choice always wins
#      outright and autodetection is not attempted at all. Required on any
#      machine running an overlay-mesh client (Tailscale/ZeroTier/etc.):
#      autodetection below has no way to prefer a mesh adapter over a
#      simultaneously-active Wi-Fi/Ethernet adapter, and picking the wrong
#      one is silent until the first volunteer tries to connect.
#   2. autodetection (detect_lan_ip) — best-effort, single-adapter LAN case.
#   3. 127.0.0.1 with a loud warning, exactly as before.
#
# detect_lan_ip itself previously shelled out to `ip route get`, which does
# not exist on macOS — it silently returned empty on the exact machine
# (Karma's Mac) most likely to run this script as the coordinator, and
# every run fell straight to the 127.0.0.1 warning. Added a macOS/BSD
# branch using `route` + `ipconfig getifaddr`, the standard macOS idiom for
# "what is my default-route interface's IPv4 address" (there is no `ip`
# command on macOS to begin with). Still best-effort only, and still
# irrelevant once --advertise-host is passed.
detect_lan_ip() {
  if command -v ip >/dev/null 2>&1; then
    ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' | head -n1
    return
  fi
  if command -v route >/dev/null 2>&1 && command -v ipconfig >/dev/null 2>&1; then
    local iface
    iface="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')"
    if [[ -n "$iface" ]]; then
      ipconfig getifaddr "$iface" 2>/dev/null
    fi
  fi
}
if [[ -n "$ADVERTISE_HOST" ]]; then
  LAN_IP="$ADVERTISE_HOST"
else
  LAN_IP="$(detect_lan_ip || true)"
  if [[ -z "$LAN_IP" ]]; then
    log "warning: could not autodetect a LAN IP; join.sh's URL below defaults to 127.0.0.1 (unreachable from another desktop) — pass --advertise-host explicitly (ADR-089) if you have volunteers on other machines"
    LAN_IP="127.0.0.1"
  fi
fi
MICROSERVICE_URL="http://$LAN_IP:$PORT"

log "waiting for the microservice to answer /api/v1/admin/readiness"
for _ in $(seq 1 60); do
  if curl -sf -o /dev/null "http://127.0.0.1:$PORT/api/v1/admin/readiness" -H "X-Admin-API-Key: $ADMIN_API_KEY"; then
    break
  fi
  sleep 1
done
if ! curl -sf -o /dev/null "http://127.0.0.1:$PORT/api/v1/admin/readiness" -H "X-Admin-API-Key: $ADMIN_API_KEY"; then
  echo "[up.sh] microservice never became reachable — see $LOG_DIR/microservice.log" >&2
  exit 1
fi

# ── persist state for down.sh / a human re-running join.sh by hand ────────
# [Extended, Session 18.1.4] STATE_DIR, DATA_DIR, OWNER_DIR and PID_FILE are
# exported too. Every one of them was previously something the operator had
# to redefine by hand in each new terminal, and a mistyped or unset one is
# not a harmless typo: `kill "$(sed -n "$((N+1))p" "$STATE_DIR/pids")"` with
# N unset evaluates to line 1, which is the MICROSERVICE, so a hand-set
# variable going missing takes the whole coordinator down mid-demo. Shipping
# them in the env file removes the class of mistake rather than documenting
# around it. OWNER_DIR does not exist until `client register` creates it —
# it is a path, not a promise that the directory is there.
cat > "$ENV_FILE" <<EOF
MICROSERVICE_URL=$MICROSERVICE_URL
ADMIN_API_KEY=$ADMIN_API_KEY
OTP_LOG=$OTP_LOG
BIN_DIR=$BIN_DIR
STATE_DIR=$STATE_DIR
DATA_DIR=$DATA_DIR
OWNER_DIR=$DATA_DIR/owner
PID_FILE=$PID_FILE
PGHOST=$PGHOST
PGPORT=$PGPORT
PGDATABASE=$PGDATABASE
EOF

# ── start N local normal-mode providers (rehearsal fleet, F-D-3) ──────────
NEXT_PORT=$((PORT + 1))
for i in $(seq 1 "$PROVIDERS"); do
  PHONE="$(printf '+9197%08d' "$((90000000 + i))")"
  PROVIDER_DATA_DIR="$DATA_DIR/provider-$i"
  PROVIDER_PORT=$((NEXT_PORT + i - 1))
  mkdir -p "$PROVIDER_DATA_DIR"

  # [Third bash-3.2 landmine in this file — see up.sh's own history] An
  # empty array expanded bare as "${ADVERTISE_FLAG[@]}" under `set -u`
  # throws "unbound variable" on bash 3.2 through 4.3 (fixed in 4.4+) —
  # macOS's system /bin/bash is 3.2.57, confirmed live on a real Mac run.
  # Every use of this array below is written as
  # "${ADVERTISE_FLAG[@]+"${ADVERTISE_FLAG[@]}"}" (BashFAQ 112's portable
  # idiom) instead of a bare "${ADVERTISE_FLAG[@]}", specifically so an
  # empty ADVERTISE_ADDR (the common case — most volunteers have exactly
  # one usable interface) doesn't crash this script on its most common
  # target platform.
  ADVERTISE_FLAG=()
  if [[ -n "$ADVERTISE_ADDR" ]]; then
    ADVERTISE_FLAG=(--advertise-addr "$ADVERTISE_ADDR")
  fi

  log "onboarding local provider $i/$PROVIDERS (phone=$PHONE, port=$PROVIDER_PORT)"
  onboard_log="$LOG_DIR/onboard-$i.log"

  # `provider onboard` blocks on stdin for the OTP code after sending it
  # (onboard.go's promptOTPCode) — the real, single-writer wire flow, not a
  # scripted double-send. A FIFO opened read-write on its own fd (rather
  # than a plain `< "$FIFO"` redirect, which would block the shell's own
  # open() until a writer appears) lets this script start the real onboard
  # process, let it actually send the OTP, THEN read the code back off
  # cmd/microservice's delivery log via the just-built `operator otp`
  # command, and hand it to the still-waiting onboard process exactly once.
  #
  # Fixed fd 3, not bash 4.1+'s `exec {name}<>file` automatic fd-name
  # allocation: macOS ships bash 3.2.57 as /bin/bash (Apple's last GPLv2
  # release, frozen there for licensing reasons) and /usr/bin/env bash
  # resolves to that system bash unless a newer one is explicitly first on
  # PATH — confirmed live, not hypothetically: `exec {FIFO_FD}<>"$FIFO"`
  # failed on a real Mac run of this script with "exec: {FIFO_FD}: not
  # found", bash 3.2 parsing the unrecognized `{FIFO_FD}` fd-name token as
  # a literal command word instead. Fd 3 is closed at the end of every loop
  # iteration below before the next provider opens it again, so reusing the
  # same fixed number across iterations is safe — this loop is strictly
  # sequential, never concurrent.
  FIFO="$STATE_DIR/onboard-fifo-$i"
  rm -f "$FIFO"
  mkfifo "$FIFO"
  exec 3<>"$FIFO"

  "$BIN_DIR/provider" onboard \
    --microservice-url="$MICROSERVICE_URL" \
    --phone="$PHONE" \
    --storage-gb="$STORAGE_GB" \
    --data-dir="$PROVIDER_DATA_DIR" \
    --listen-port="$PROVIDER_PORT" \
    "${ADVERTISE_FLAG[@]+"${ADVERTISE_FLAG[@]}"}" \
    <&3 > "$onboard_log" 2>&1 &
  ONBOARD_PID=$!

  code=""
  for _ in $(seq 1 60); do
    # Flags BEFORE the positional phone argument, not after: Go's stdlib
    # flag package stops parsing at the first non-flag token, so
    # `operator otp "$PHONE" --mode=demo --otp-delivery-log=...` (phone
    # first) leaves --mode and --otp-delivery-log unparsed as extra
    # positional arguments, tripping otp.go's own `len(rest) != 1` usage
    # check on every single call — confirmed directly, not guessed: this
    # exact ordering reproducibly exits 2 with a usage error, while
    # swapping the order (flags first) exits 0 with the code. The original
    # ordering meant this loop never once succeeded, regardless of
    # whether cmd/microservice had actually written the OTP yet.
    if raw="$("$BIN_DIR/operator" otp --mode=demo --otp-delivery-log="$OTP_LOG" "$PHONE" 2>/dev/null)"; then
      code="$(awk '{print $1}' <<<"$raw")"
      break
    fi
    sleep 0.5
  done
  if [[ -z "$code" ]]; then
    exec 3<&-
    rm -f "$FIFO"
    echo "[up.sh] provider $i: never saw an OTP for $PHONE in $OTP_LOG — see $onboard_log" >&2
    exit 1
  fi

  echo "$code" >&3
  if ! wait "$ONBOARD_PID"; then
    exec 3<&-
    rm -f "$FIFO"
    echo "[up.sh] provider $i: onboarding failed — see $onboard_log" >&2
    exit 1
  fi
  exec 3<&-
  rm -f "$FIFO"

  log "starting local provider $i/$PROVIDERS (run, normal mode)"
  "$BIN_DIR/provider" run \
      --mode=demo \
      --microservice-url="$MICROSERVICE_URL" \
      --data-dir="$PROVIDER_DATA_DIR" \
      --declared-storage-gb="$STORAGE_GB" \
      --listen-port="$PROVIDER_PORT" \
      "${ADVERTISE_FLAG[@]+"${ADVERTISE_FLAG[@]}"}" \
      > "$LOG_DIR/provider-$i.log" 2>&1 &
  echo "$!" >> "$PID_FILE"
done

log "up. Logs under $LOG_DIR."
log ""
log "This run's actual values (also saved in $ENV_FILE):"
log "  MICROSERVICE_URL = $MICROSERVICE_URL"
log "  ADMIN_API_KEY    = $ADMIN_API_KEY"
log "  OTP_LOG          = $OTP_LOG"
log "  BIN_DIR          = $BIN_DIR"
log ""
log "In any NEW terminal, load them by sourcing that file:"
log "  source $ENV_FILE"
log ""
log "Then, to watch the live console (--mode=demo matters — without it the"
log "console computes its own readiness thresholds against the PROD profile"
log "instead of demo's, and every number on screen will look wrong even"
log "though the real system underneath is fine):"
log "  \$BIN_DIR/operator watch --mode=demo --microservice-url=\$MICROSERVICE_URL --admin-api-key=\$ADMIN_API_KEY"
log ""
log "To read a volunteer's OTP code (join.sh tells them to ask you for it):"
log "  \$BIN_DIR/operator otp --mode=demo --otp-delivery-log=\$OTP_LOG <their phone number>"
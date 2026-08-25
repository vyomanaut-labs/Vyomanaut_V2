// Command provider is the Vyomanaut V2 provider daemon entrypoint.
//
// Startup order (Session 13.1.1 TASK, IC §5.3 pre-condition chain):
//  1. Parse flags (MVP §8.3).
//  2. config.SelectProfile then config.ValidateStartupGuards.
//  3. RAM check (Session 13.6.1, A1) — before ChunkStore init.
//  4. Load/generate Ed25519 identity (internal/p2p/identity.go).
//  5. ChunkStore.RecoverFromCrash() before starting the writer goroutine.
//  6. Start the single writer goroutine (only caller of AppendChunk).
//  7. NewHost with responder-side 0-RTT rejection for every protocol in
//     zeroRTTProhibited (A7) — see the note below on what that means for
//     this codebase's transport substitution.
//  8. Register the four stream handlers (Phases 13.2-13.5).
//  9. Heartbeat goroutine + DHT republication (IC §3.1, §12.2); the DHT
//     custom validator from dht_namespace.go (IC §12) is registered
//     automatically by p2p.NewDHT.
//
// ONE-FLAG NOTE (build.md's own preamble to Milestone 13): ADR-038/ADR-047
// assume the tray process and the daemon logic are the same process,
// started in-process by a Task Scheduler logon trigger. This file is kept
// as a thin wrapper around package-level constructors (NewUploadHandler,
// NewAuditHandler, NewRepairDownloadHandler, NewVettingGCHandler,
// runRAMCheck, etc.) rather than owning the whole process lifecycle inline
// as unexported main()-local logic, so a future Wails app (Milestone 19)
// can call the same startup sequence in-process instead of exec-ing a
// separate binary.
//
// RESPONDER-SIDE 0-RTT (A7): IC §4's zeroRTTProhibited deny-list
// (internal/p2p/host.go) is enforced on the DIALING side only in this
// codebase's transport substitution — see handler_audit.go's header for the
// full account of why (this is crypto/tls session-ticket resumption over
// plain TCP, not real QUIC 0-RTT early data; there is nothing
// responder-observable to police at accept time before the protocol is even
// negotiated). For all four protocols this daemon registers handlers for,
// this daemon is exclusively the RESPONDER — it never calls Host.NewStream
// for chunk-upload/audit-challenge/repair-download/vetting-gc, so
// zeroRTTProhibited's enforcement point (the caller's NewStream) is
// correctly on the microservice/client side for every one of them; nothing
// further is required here beyond constructing the Host that already
// carries that enforcement.
//
// [REF: IC §3.1, IC §4, IC §12, IC §12.2, MVP §5.3, MVP §8.3, NFR-045,
// ARCH §27.5, build.md Sessions 13.1.1, 13.6.1]
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/metrics"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// daemonVersion is reported in the heartbeat payload (IC §3.1) and startup
// banner. Bumped manually; no build-stamping mechanism exists in this
// session's scope.
const daemonVersion = "v0.13.0"

// defaultProviderListenPort is the fixed inbound libp2p listen port for
// normal (non-simulation) mode. Not specified as a flag anywhere in MVP
// §8.3, so a single fixed default is used; simulation mode's
// --sim-base-port exists precisely to avoid collisions when many instances
// run in one process, which does not apply here since simulation mode is
// not implemented in this session (see the --sim-count guard below).
const defaultProviderListenPort = 4001

const (
	defaultSimBasePort = 4001
	defaultSimASNCount = 5
)

// providerFlags holds every parsed cmd/provider/main.go flag (MVP §8.3).
type providerFlags struct {
	mode              string
	microserviceURL   string
	dataDir           string
	declaredStorageGB int
	relayAddrs        string

	// listenPort/advertiseAddr (M17-E Session 17.4.1, ADR-084 D-7, F-D-3,
	// F-D-4): normal (non-simulation) mode only. listenPort lets two
	// providers share one host — simulation mode already has its own
	// independent port scheme (simBasePort) and never reads this field.
	// advertiseAddr is resolved into a concrete host once per instance by
	// resolveAdvertiseHost (advertise.go); empty means autodetect.
	listenPort    int
	advertiseAddr string

	simCount     int
	simBasePort  int
	simDataDir   string
	simASNCount  int
	simOnlyIndex *int // nil = run every instance (zero-value-safe: unlike an int sentinel, a directly-constructed providerFlags{} defaults to nil, not a misleading 0)

	// registrationBearerToken: the OTP-verify-issued registration bearer
	// token POST /api/v1/provider/register requires (router.go wraps it in
	// bearerAny — discovered live against a real microservice instance,
	// not anticipated when the earlier registerProviderWithMicroservice
	// addition was written). A provider daemon has no legitimate way to
	// obtain this itself — completing OTP verification requires either a
	// real phone number (out of scope) or direct database access to
	// recover the code (architecturally wrong for an untrusted provider
	// process) — so this is supplied externally, by whatever orchestrates
	// the daemon and legitimately holds that access (demo_timeline_test.go,
	// Session 16.1.1). Empty = skip registration entirely (logged, not
	// fatal) rather than attempt and fail noisily with HTTP 401.
	registrationBearerToken string
}

// defaultProviderDataDir returns the default --data-dir every provider
// subcommand (run, onboard, inspect, earnings, depart) falls back to when
// the flag is omitted — the SAME default across all of them, so a bare
// `provider onboard` followed later by a bare `provider run` naturally
// operate on the same directory without the operator having to remember
// --data-dir at all (M17-E Session 17.4.2).
func defaultProviderDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".vyomanaut")
}

// parseProviderFlags parses args (the "run" subcommand's own argv —
// dispatch.go's resolveSubcommand supplies either os.Args[1:] unchanged,
// for the pre-Session-17.4.1 bare-flags invocation shape, or the remainder
// after an explicit "run" word) into a providerFlags value.
//
// A fresh flag.FlagSet per call (M17-E Session 17.4.1), not the
// package-level flag.CommandLine this function used before: the prior form
// could only ever be invoked once per process (a second call panics with
// "flag redefined"), which was fine when this was main()'s only job but
// stops being fine now that cmd/provider has four sibling subcommands in
// the same binary. flag.ExitOnError preserves this function's original
// behavior on a malformed flag exactly — print usage, os.Exit(2).
func parseProviderFlags(args []string) providerFlags {
	defaultDataDir := defaultProviderDataDir()

	fs := flag.NewFlagSet("provider run", flag.ExitOnError)

	var f providerFlags
	fs.StringVar(&f.mode, "mode", "", "'demo' or 'prod'; overrides VYOMANAUT_MODE")
	fs.StringVar(&f.microserviceURL, "microservice-url", "", "Required. HTTPS base URL of the coordination microservice.")
	fs.StringVar(&f.dataDir, "data-dir", defaultDataDir, "Persistent data directory.")
	fs.IntVar(&f.declaredStorageGB, "declared-storage-gb", 0, "Required in normal mode.")
	fs.StringVar(&f.relayAddrs, "relay-addrs", "", "Comma-separated relay node multiaddrs.")
	fs.IntVar(&f.listenPort, "listen-port", defaultProviderListenPort, "Inbound libp2p listen port for normal (non-simulation) mode. Lets two providers share one host (M17-E F-D-3).")
	fs.StringVar(&f.advertiseAddr, "advertise-addr", "", "IPv4 host (or host:port — the port is ignored; --listen-port is authoritative) this daemon advertises to the network in its multiaddr. Empty = autodetect the first non-loopback, non-link-local interface address, falling back to 127.0.0.1 with a logged warning if none is found (M17-E F-D-4). A demo across separate desktops REQUIRES this to resolve to a real, reachable address.")
	fs.IntVar(&f.simCount, "sim-count", 0, "Simulation instances in a single process. 0 = normal mode.")
	fs.IntVar(&f.simBasePort, "sim-base-port", defaultSimBasePort, "Base libp2p listen port for simulation instances.")
	fs.StringVar(&f.simDataDir, "sim-data-dir", "/tmp/vyomanaut-sim", "Root directory for simulation instance data.")
	fs.IntVar(&f.simASNCount, "sim-asn-count", defaultSimASNCount, "Synthetic ASN count for simulation mode.")
	fs.StringVar(&f.registrationBearerToken, "registration-bearer-token", "", "OTP-verify-issued registration bearer token for POST /api/v1/provider/register (see providerFlags.registrationBearerToken doc comment for why this is supplied externally rather than obtained by this daemon). Empty = skip registration.")
	simOnlyIndexFlag := fs.Int("sim-only-index", -1, "If >= 0, run only this one instance index from the --sim-count group as its own OS process, computing the exact same dataDir/port/ASN it would have under a full single-process run. -1 (default) runs every instance in this process (original --sim-count behavior). Added post-Session-16.2.1: --sim-count's goroutines-in-one-process design has no way to terminate a single simulated instance without killing all of them, which demo_timeline_test.go's departure-detection check needs (Session 16.1.1).")
	_ = fs.Parse(args)
	if *simOnlyIndexFlag >= 0 {
		f.simOnlyIndex = simOnlyIndexFlag
	}
	return f
}

// ── RAM check (Session 13.6.1, A1) ────────────────────────────────────────

const bytesPerMiB = 1 << 20

// Placed before main() deliberately: main() calls runRAMCheck at Step 3,
// strictly before the ChunkStore/RecoverFromCrash sequence at Step 5 and
// the writer-goroutine start that immediately follows it — keeping this
// section's source text ahead of that sequence too, not just its runtime
// call order, keeps the file's physical layout matching its execution
// order for anyone reading top-to-bottom.

// runRAMCheck computes the required DHT-cache RAM for declaredStorageGB
// (storage.RequiredDHTCacheRAMMB) and compares it against currently free
// RAM (storage.AvailableRAMBytes). On shortfall: WARN (never halt — see IC
// §27.5), reduce the effective declared storage to the safe ceiling the
// available RAM actually supports, and report ram-constrained.
func runRAMCheck(declaredStorageGB int) (effectiveStorageGB int, constrained bool) {
	requiredMB := storage.RequiredDHTCacheRAMMB(uint64(declaredStorageGB))

	availableBytes, err := storage.AvailableRAMBytes()
	if err != nil {
		// Platform RAM query unsupported/failed: WARN and proceed
		// unconstrained (fail-open here is intentional — NFR-045's guard is
		// a courtesy warning, not a hard admission-control gate, and this
		// codebase's other platform-detection stubs (rotational_other.go)
		// follow the same "assume the common/safe case and proceed"
		// pattern when a platform query is unavailable).
		log.Printf("[WARN] RAM check unavailable on this platform (%v); proceeding without a RAM guard", err)
		return declaredStorageGB, false
	}
	availableMB := availableBytes / bytesPerMiB

	if availableMB >= requiredMB {
		return declaredStorageGB, false
	}

	safeGB := safeDeclaredStorageGB(availableMB)
	log.Printf("[WARN] Declared storage requires ~%d MB free RAM for DHT cache; only %d MB detected. Chunk assignment will be limited until RAM is freed.", requiredMB, availableMB)
	if safeGB < 1 {
		safeGB = 1 // never reduce to zero; DHTRecordSizeBytes(200B)/ChunksPerGB math floors near zero for tiny availableMB
	}
	return safeGB, true
}

// safeDeclaredStorageGB inverts RequiredDHTCacheRAMMB: the largest declared
// storage (GB) whose required RAM does not exceed availableMB.
func safeDeclaredStorageGB(availableMB uint64) int {
	// requiredMB = gb * ChunksPerGB * DHTRecordSizeBytes / (1<<20)
	// => gb = availableMB * (1<<20) / (ChunksPerGB * DHTRecordSizeBytes)
	denom := uint64(storage.ChunksPerGB) * uint64(storage.DHTRecordSizeBytes)
	gb := (availableMB * bytesPerMiB) / denom
	return int(gb)
}

const privateDirPermissions = 0700
const chunkWriteQueueSize = 64

// providerInstanceConfig is everything that varies between provider
// instances — the single real daemon in normal mode, or one of N goroutines
// under --sim-count (Session 16.2.1). runProviderInstance's own sequence
// never branches on which caller it is; every difference between "normal"
// and "simulated" is captured entirely in this struct.
type providerInstanceConfig struct {
	label string // "single" (normal mode) or "sim-0000".."sim-NNNN" (simulation mode, IC §10 zero-padded-4-digit convention)

	dataDir           string // identity root: owner-seed.bin + Ed25519 identity key (p2p.LoadOrGenerateIdentity)
	chunkStoreDir     string // storage.NewChunkStore's sole argument — normal mode: same as dataDir; simulation mode: dataDir/db, per this session's own naming convention
	listenPort        int
	declaredStorageGB int
	microserviceURL   string

	// advertiseAddr is providerFlags.advertiseAddr, threaded through
	// unchanged (M17-E Session 17.4.1, ADR-084 F-D-4). Resolved into a
	// concrete host exactly once per instance, inside runProviderInstance,
	// by resolveAdvertiseHost (advertise.go) — never re-resolved anywhere
	// else, so the registration and heartbeat multiaddrs always agree.
	advertiseAddr string

	// syntheticASN is non-empty only under --sim-count: SIM-AS{1..sim-asn-count},
	// cycling if sim-count > sim-asn-count. Sent as demo_asn in the
	// self-registration call below.
	syntheticASN string

	// registrationBearerToken: see providerFlags.registrationBearerToken's
	// doc comment. Empty = registration is skipped for this instance.
	registrationBearerToken string
}

// runCmd is the "run" subcommand's handler (dispatch.go) — this daemon's
// full startup sequence, unchanged in substance from this function's
// pre-Session-17.4.1 form as main() itself. args is the argv this
// subcommand owns: os.Args[1:] when invoked with bare flags and no
// subcommand word (the pre-existing, still-supported shape every
// integration test uses — resolveSubcommand, dispatch.go), or the
// remainder after an explicit "run" word.
func runCmd(args []string) {
	flags := parseProviderFlags(args)

	// ── Step 2: profile selection + startup guards ──────────────────────
	profile := config.SelectProfile(flags.mode)
	if err := config.ValidateStartupGuards(profile); err != nil {
		log.Fatalf("[STARTUP] FATAL guard rail: %v", err)
	}
	if flags.microserviceURL == "" {
		log.Fatalf("[STARTUP] FATAL: --microservice-url is required")
	}

	// ── daemon status/metrics server — process-wide singleton ───────────
	// Started exactly once regardless of --sim-count: daemonStatusAddr
	// (internal/metrics/daemon.go) is a single fixed 127.0.0.1:9091
	// address, and every metric it serves is registered once at
	// package-init via promauto — neither is scoped per-instance.
	// Simulated instances each still update DaemonRAMConstrained from
	// their own RAM check (runProviderInstance, below), but only one HTTP
	// listener for the whole process makes sense here; starting it once
	// per simulated instance would just fail every listener after the
	// first with an address-in-use error.
	if _, errCh := metrics.StartDaemonMetricsServer(); errCh != nil {
		go func() {
			if err := <-errCh; err != nil {
				log.Printf("[STARTUP] daemon status/metrics server error: %v", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		waitForShutdownSignal()
		log.Printf("[SHUTDOWN] signal received, shutting down")
		cancel()
	}()

	if flags.simCount > 0 {
		runSimulation(ctx, flags, profile)
		return
	}

	// ── normal (single-instance) mode ────────────────────────────────────
	if flags.declaredStorageGB <= 0 {
		log.Fatalf("[STARTUP] FATAL: --declared-storage-gb is required and must be > 0 in normal mode")
	}
	cfg := providerInstanceConfig{
		label:                   "single",
		dataDir:                 flags.dataDir,
		chunkStoreDir:           flags.dataDir,
		listenPort:              flags.listenPort,
		declaredStorageGB:       flags.declaredStorageGB,
		microserviceURL:         flags.microserviceURL,
		advertiseAddr:           flags.advertiseAddr,
		registrationBearerToken: flags.registrationBearerToken,
	}
	if err := runProviderInstance(ctx, profile, cfg); err != nil {
		log.Fatalf("[STARTUP] FATAL: %v", err)
	}
}

// syntheticASNForInstance returns the SIM-AS{N} value simulation instance
// index i (0-based) should receive, cycling through 1..asnCount when
// simCount exceeds asnCount — the "next available synthetic ASN from the
// pool" pattern internal/api/provider.go's resolveASN already documents
// server-side for demo mode. Extracted as its own function so it's directly
// unit-testable without spinning up a full simulated instance.
func syntheticASNForInstance(i, asnCount int) string {
	return fmt.Sprintf("SIM-AS%d", (i%asnCount)+1)
}

// formatSimOnlyIndex renders flags.simOnlyIndex for a log line: "all" when
// nil (every instance runs in this process), the index itself otherwise.
func formatSimOnlyIndex(idx *int) string {
	if idx == nil {
		return "all"
	}
	return strconv.Itoa(*idx)
}

// runSimulation implements --sim-count (closes A-8, Session 16.2.1): spawns
// flags.simCount goroutines, each running an independent
// runProviderInstance under flags.simDataDir/{zero-padded-4-digit instance
// index} (IC §10 naming convention), with a distinct libp2p listen port
// (flags.simBasePort + index) and a synthetic ASN cycling through
// SIM-AS1..SIM-AS{flags.simASNCount}.
//
// Every instance shares the caller's ctx — cancelling it (main()'s
// shutdown goroutine, on SIGINT/SIGTERM) stops every simulated instance
// together. runSimulation blocks until all of them have returned.
//
// Each instance's storage.ChunkStore is opened via the exact same
// storage.NewChunkStore call normal mode uses (runProviderInstance is
// literally the same function either way); which storage backend runs
// underneath — selected per-platform by internal/storage's own //go:build
// tags (ADR-046, Phase 16.0) — is resolved entirely inside that package.
// Nothing in this file names an engine-specific type or checks GOOS; see
// engine-selection note on runProviderInstance below for the same point in
// more detail. With the default --sim-data-dir, an instance's ChunkStore
// root is a path like /tmp/vyomanaut-sim/0000/db/ (IC §10 convention).
//
// [REF: MVP §8.3 --sim-count flag, IC §10 naming conventions, ADR-046,
// build.md Session 16.2.1]
func runSimulation(ctx context.Context, flags providerFlags, profile config.NetworkProfile) {
	if flags.simASNCount <= 0 {
		log.Fatalf("[STARTUP] FATAL: --sim-asn-count must be > 0")
	}
	if flags.declaredStorageGB <= 0 {
		log.Fatalf("[STARTUP] FATAL: --declared-storage-gb is required and must be > 0 in simulation mode")
	}
	if flags.simOnlyIndex != nil && *flags.simOnlyIndex >= flags.simCount {
		log.Fatalf("[STARTUP] FATAL: --sim-only-index=%d is out of range for --sim-count=%d", *flags.simOnlyIndex, flags.simCount)
	}

	log.Printf("[STARTUP] simulation mode: sim-count=%d sim-asn-count=%d sim-data-dir=%s sim-base-port=%d sim-only-index=%s",
		flags.simCount, flags.simASNCount, flags.simDataDir, flags.simBasePort, formatSimOnlyIndex(flags.simOnlyIndex))

	var wg sync.WaitGroup
	for i := 0; i < flags.simCount; i++ {
		// --sim-only-index (post-Session-16.2.1 addition, see its own flag
		// help text): run every index's identity/port/ASN math exactly as
		// a full-group run would, but skip actually starting every index
		// except the one requested — so a caller running N separate OS
		// processes, one per index, gets byte-for-byte the same per-instance
		// values a single N-goroutine process would have produced.
		if flags.simOnlyIndex != nil && i != *flags.simOnlyIndex {
			continue
		}

		// IC §10 naming convention: {instance_id} zero-padded to 4 digits.
		instanceID := fmt.Sprintf("%04d", i)
		instanceRoot := filepath.Join(flags.simDataDir, instanceID)

		// SIM-AS{1..sim-asn-count}, cycling if simCount > simASNCount — the
		// same "next available synthetic ASN from the pool" pattern
		// internal/api/provider.go's resolveASN already documents
		// server-side for demo mode.
		syntheticASN := syntheticASNForInstance(i, flags.simASNCount)

		cfg := providerInstanceConfig{
			label:                   "sim-" + instanceID,
			dataDir:                 instanceRoot,
			chunkStoreDir:           filepath.Join(instanceRoot, "db"),
			listenPort:              flags.simBasePort + i,
			declaredStorageGB:       flags.declaredStorageGB,
			microserviceURL:         flags.microserviceURL,
			syntheticASN:            syntheticASN,
			advertiseAddr:           flags.advertiseAddr,
			registrationBearerToken: flags.registrationBearerToken,
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runProviderInstance(ctx, profile, cfg); err != nil {
				log.Printf("[STARTUP][%s] FATAL: %v", cfg.label, err)
			}
		}()
	}
	wg.Wait()
}

// runProviderInstance runs one provider daemon's full startup sequence
// (file header Steps 3-9: RAM check through heartbeat goroutine) against
// cfg, then blocks until ctx is cancelled before releasing its resources in
// the same order every instance always has (writer channel, then host,
// then store). Called once, synchronously, by normal mode; called
// concurrently, one goroutine per instance, by runSimulation
// (--sim-count, Session 16.2.1) — this function itself never branches on
// which caller it is.
//
// PROVIDER-REGISTRATION GAP: cfg.syntheticASN (set only under --sim-count)
// is logged here but not transmitted anywhere. internal/api/provider.go's
// ProviderRegisterHandler is the microservice-side endpoint that accepts an
// ASN — including the exact SIM-AS{N} demo-mode pattern this function
// produces (demoASNPattern) — but no client-side call to it exists
// anywhere in cmd/provider, in this session's scope or any prior one.
// Flagged rather than silently worked around; wiring an actual
// registration call is a separate session's work.
func runProviderInstance(ctx context.Context, profile config.NetworkProfile, cfg providerInstanceConfig) error {
	logTag := "[" + cfg.label + "]"

	if err := os.MkdirAll(cfg.dataDir, privateDirPermissions); err != nil {
		return fmt.Errorf("create data-dir %s: %w", cfg.dataDir, err)
	}

	asnSuffix := ""
	if cfg.syntheticASN != "" {
		asnSuffix = fmt.Sprintf(" synthetic-asn=%s", cfg.syntheticASN)
	}
	log.Printf("[STARTUP]%s Vyomanaut provider %s — mode=%s data-dir=%s declared-storage-gb=%d listen-port=%d%s",
		logTag, daemonVersion, profile.Mode, cfg.dataDir, cfg.declaredStorageGB, cfg.listenPort, asnSuffix)

	// ── Step 3: RAM check — BEFORE ChunkStore init (A1) ─────────────────
	effectiveStorageGB, ramConstrained := runRAMCheck(cfg.declaredStorageGB)
	metrics.DaemonRAMConstrained.Set(boolToFloat(ramConstrained))

	// ── Step 4: load/generate Ed25519 identity ──────────────────────────
	// GAP (flagged — see build report IDENTITY-SEED-GAP): LoadOrGenerateIdentity
	// requires a masterSecret+ownerID pair, normally derived from a data
	// owner's passphrase (IC §5.1). No provider registration/OTP flow that
	// would yield an equivalent for a PROVIDER is in this session's scope
	// (MVP §8.3's flag table has no such flag). loadOrGenerateOwnerSeed
	// below generates and locally persists a random masterSecret+ownerID
	// pair on first run so the identity is at least STABLE across restarts
	// (the functional requirement this session needs); it is deliberately
	// NOT passphrase-recoverable the way a data owner's account is — that
	// is a real gap for a future registration-flow session to close.
	//
	// Under --sim-count, cfg.dataDir is a distinct directory per instance
	// (runSimulation), so this alone gives every simulated instance its own
	// separate, stable Ed25519 identity — nothing further is needed for
	// this session's "Separate Ed25519 identity" requirement.
	masterSecret, ownerID, err := loadOrGenerateOwnerSeed(cfg.dataDir)
	if err != nil {
		return fmt.Errorf("owner seed: %w", err)
	}
	providerSigningKey, peerID, err := p2p.LoadOrGenerateIdentity(cfg.dataDir, masterSecret, ownerID[:])
	if err != nil {
		return fmt.Errorf("load/generate identity: %w", err)
	}
	log.Printf("[STARTUP]%s Peer ID: %s", logTag, peerID)

	// ── advertised address (F-D-4, ADR-084, M17-E Session 17.4.1) ───────
	// Resolved exactly ONCE per instance startup. Both places this daemon
	// publishes an address to the network — the registration multiaddr
	// below and the heartbeat/DHT multiaddr further down — build from
	// THIS SAME advertiseHost value, never a second independently-computed
	// one. Before this session both call sites hardcoded 127.0.0.1
	// directly and in fact already agreed with each other for that reason
	// alone; a divergence was never actually possible, which is exactly
	// why the daemon advertising itself as unreachable from every other
	// host stayed invisible until read directly — every test to date runs
	// every peer on one host, where loopback happens to be correct
	// regardless of whether the two sites are truly wired together.
	advertiseHost, advertiseWarning := resolveAdvertiseHost(cfg.advertiseAddr)
	if advertiseWarning != "" {
		log.Printf("[STARTUP]%s WARNING: %s", logTag, advertiseWarning)
	}
	log.Printf("[STARTUP]%s advertising %s:%d to the network", logTag, advertiseHost, cfg.listenPort)

	// ── provider self-registration (closes PROVIDER-REGISTRATION GAP) ───
	// Flagged, not silently worked around, in Session 16.2.1: no client-side
	// call to POST /api/v1/provider/register existed anywhere in cmd/provider
	// before this. Without it, simulated providers never appear as
	// active_vetted_providers/distinct_asns in the readiness evaluator
	// (internal/api/readiness.go), so demo_timeline_test.go's very first
	// assertion — "readiness gate passes within 60s" — could never pass no
	// matter how long the test waited. Closed here as unofficial
	// supplementary work outside Milestone 16's own FILES: scope, per
	// Karma's direction ahead of Sessions 16.1.1/16.1.2: get the actual
	// system working end-to-end, keep the fix clearly separate from the
	// two sessions' own official output.
	//
	// cfg.registrationBearerToken (see providerFlags.registrationBearerToken's
	// doc comment for why this daemon never obtains it itself) is REQUIRED
	// — router.go wraps POST /api/v1/provider/register in bearerAny,
	// discovered live against a real microservice, not anticipated when
	// this section was first written. Empty token = registration is
	// skipped cleanly (logged, not attempted-and-401'd).
	//
	// Registration tokens are single-use and tied to one phone-derived
	// subject (pending_registrations, deleted on first successful
	// registration) — this means a single --sim-count=N process sharing
	// ONE --registration-bearer-token value could only ever register its
	// FIRST instance to reach this point; every other instance would see
	// its token already consumed. Running N separate --sim-only-index
	// processes, each with its own token, is therefore not just what
	// makes per-instance kill/departure-testing possible (this flag's own
	// doc comment) — it is also the only way multiple simulated providers
	// can register at all.
	//
	// cfg.syntheticASN (only set under --sim-count) is sent as demo_asn;
	// real ASN detection is out of scope here — every registration in this
	// codebase's current form is a simulation-mode registration.
	// registeredProviderID / providerJWT: populated only on successful
	// registration below. Both are required for this instance's own
	// heartbeats to authenticate — POST /api/v1/provider/heartbeat is
	// bearerAuthRole("provider")-gated and its body's provider_id must
	// equal the JWT's sub claim exactly (internal/api/provider.go's
	// HandleHeartbeat). Left empty when registration is skipped or fails;
	// heartbeatCfg below is constructed accordingly either way.
	var registeredProviderID, providerJWT string

	// ── persisted registration (M17-E Session 17.4.2) ────────────────────
	// If `provider onboard` (onboard.go) already registered this data-dir's
	// identity, its record takes priority over --registration-bearer-token
	// outright: registration tokens are single-use (see
	// providerFlags.registrationBearerToken's doc comment) and onboard's
	// own token was already consumed at onboarding time — attempting the
	// HTTP registration flow again here would simply fail. A missing
	// record (recErr == nil, found == false) is the normal case for every
	// harness/--sim-count instance and for a --registration-bearer-token
	// invocation that has never run `onboard`; it falls through to the
	// exact pre-existing behavior below, unchanged.
	if rec, found, recErr := loadRegistrationRecord(cfg.dataDir); recErr != nil {
		log.Printf("[STARTUP]%s WARNING: read persisted registration: %v; falling back to --registration-bearer-token flow", logTag, recErr)
	} else if found {
		registeredProviderID, providerJWT = rec.ProviderID, rec.Token
		log.Printf("[STARTUP]%s using registration persisted by `provider onboard` (provider_id=%s)", logTag, registeredProviderID)
	}

	if registeredProviderID == "" {
		if cfg.registrationBearerToken == "" {
			log.Printf("[STARTUP]%s no persisted registration and no --registration-bearer-token supplied; skipping provider self-registration (this instance will not count toward readiness)", logTag)
		} else {
			// Trailing /p2p/<PeerID> is required — internal/client/upload's
			// transfer.go parses this segment to know which peer identity to
			// dial safely (a bare IP:port isn't sufficient in a
			// peer-authenticated P2P system). Missing here originally; found
			// live when the first real (post-ACTIVE) upload failed with "no
			// /p2p/<PeerID> segment found in any multiaddr" — see ADR-070
			// F-070-7's follow-up.
			//
			// F-D-4: advertiseHost (resolved once, above) replaces what was
			// previously a hardcoded 127.0.0.1 here — the same value the
			// heartbeat multiaddr below is built from.
			multiaddr := advertiseMultiaddr(advertiseHost, cfg.listenPort, peerID)
			var regErr error
			registeredProviderID, providerJWT, regErr = registerProviderWithMicroservice(ctx, cfg.microserviceURL, cfg.registrationBearerToken, providerSigningKey,
				cfg.declaredStorageGB, demoProviderCity, demoProviderRegion, cfg.syntheticASN, []string{multiaddr})
			if regErr != nil {
				// Non-fatal, matching the JWKS-fetch failure below: a transient
				// microservice outage at startup should not crash the daemon. The
				// provider simply will not count toward readiness until a future
				// heartbeat/retry path re-registers it — there is no retry loop
				// here yet (a real gap, distinct from the one this closes).
				log.Printf("[STARTUP]%s WARNING: provider registration failed (%v); this instance will not count toward readiness until registered", logTag, regErr)
			} else {
				log.Printf("[STARTUP]%s registered with microservice (provider_id=%s)", logTag, registeredProviderID)

				// [Fixed — F-17E-04, discovered live via
				// TestDepartureAfterUploadFileStillRetrievableGraceful]
				// Previously registeredProviderID/providerJWT lived only in
				// these local variables — never persisted via
				// saveRegistrationRecord (onboard.go), the ONLY thing
				// loadRegistrationRecord (depart.go, earnings.go) ever
				// reads. A provider started via --registration-bearer-token
				// (every --sim-count/--sim-only-index instance this
				// project's own test harness spawns, and any real
				// deployment choosing this flag over the interactive
				// `provider onboard` flow) could therefore never gracefully
				// depart at all: `provider depart --data-dir=<this
				// instance's own dataDir>` unconditionally failed with "no
				// registration found — run `provider onboard` first",
				// discovered running this exact command against a live
				// simulated instance. Persisting it here, exactly as
				// onboard.go's own successful path does, closes that gap
				// for both cases identically — this is not a
				// simulation-only workaround.
				if saveErr := saveRegistrationRecord(cfg.dataDir, registrationRecord{
					ProviderID:        registeredProviderID,
					Token:             providerJWT,
					DeclaredStorageGB: cfg.declaredStorageGB,
				}); saveErr != nil {
					log.Printf("[STARTUP]%s WARNING: persist registration record: %v; `provider depart` will not find it later", logTag, saveErr)
				}
			}
		}
	}

	// providerIDBytes: the microservice-assigned provider_id (parsed from
	// registeredProviderID) when registration succeeded — used for both
	// capability-token verification (handler_upload.go's
	// CAP-TOKEN-PROVIDER-ID-GAP, closed this session) and upload/audit
	// receipt signing (handler_upload.go/handler_audit.go). Falls back to
	// the old Peer-ID-derived stand-in (deriveLocalProviderIDBytes) when
	// registration was skipped or failed — strictly no worse than this
	// daemon's behavior before this session in that case, and receipts
	// stay at least internally self-consistent across restarts either way.
	providerIDBytes := deriveLocalProviderIDBytes(peerID)
	if registeredProviderID != "" {
		if parsed, parseErr := uuid.Parse(registeredProviderID); parseErr != nil {
			log.Printf("[STARTUP]%s WARNING: parse registered provider_id %q: %v; falling back to Peer-ID-derived value", logTag, registeredProviderID, parseErr)
		} else {
			providerIDBytes = [16]byte(parsed)
		}
	}

	// ── microservice public key (JWKS) + derived Peer ID ────────────────
	//
	// [Fixed — F-17E-11, live verification, M17-E Phase 17.7 departure-
	// matrix debugging] This was a single, un-retried HTTP call. Its own
	// comment already correctly diagnosed the failure mode ("a transient
	// microservice outage at startup should not prevent the daemon from
	// starting") but the code that followed didn't actually retry —
	// "and retrying" was aspirational, not implemented. The consequence is
	// much larger than a delayed capability check: MicroserviceAuthorizer
	// (handler_repair.go) is seeded ONCE, at startup, from this exact
	// value (main.go: "authorizer.Set([]p2p.PeerID{microservicePeerID})"
	// below, skipped entirely when this returns empty) and is never
	// refreshed afterwards. A provider that loses this one race — plausible
	// and apparently common, since main.go starts provider processes
	// concurrently with the microservice, which live verification shows
	// takes roughly 60-70s to report [READINESS] ready=true — has its
	// repair-download and vetting-gc authorization permanently, silently
	// fail-closed for its entire process lifetime, with every future
	// legitimate request from the real microservice rejected as
	// NOT_AUTHORISED (0x02). This was invisible until repair_jobs.
	// failure_reason (this same session) started surfacing
	// downloadShards' actual per-holder error text in test output — every
	// prior repair failure in this codebase's live-verification history
	// was diagnosed as generic timeout/contention because nothing
	// distinguished "every holder rejected as not authorised" from "every
	// holder was merely slow." TestViabilityRepairSucceedsWithTwoOfFiveOffline
	// is exactly the shape of test most likely to expose this: two
	// concurrent repairs draw on most of the remaining provider pool as
	// download candidates, so it needs correspondingly more of that pool
	// to have won its own startup race, not just one specific provider.
	//
	// Retried up to jwksFetchMaxAttempts times, jwksFetchRetryInterval
	// apart — comfortably longer than the ~60-70s window above, while
	// still bounded so a genuinely, durably unreachable microservice
	// doesn't hang provider startup indefinitely. Preserves the exact
	// same fail-closed behavior as before (nil key, empty authorizer, a
	// WARNING log) if every attempt is exhausted — this changes how long
	// the daemon tries before giving up, not what "giving up" means.
	var msPublicKey ed25519.PublicKey
fetchLoop:
	for attempt := 1; attempt <= jwksFetchMaxAttempts; attempt++ {
		msPublicKey, err = fetchMicroservicePublicKey(ctx, cfg.microserviceURL)
		if err == nil {
			break
		}
		if attempt < jwksFetchMaxAttempts {
			log.Printf("[STARTUP]%s fetch microservice public key (attempt %d/%d): %v; retrying in %s",
				logTag, attempt, jwksFetchMaxAttempts, err, jwksFetchRetryInterval)
			// Labeled break, deliberately not a bare one: a bare break
			// here would only break out of this select, not the
			// enclosing for loop, silently turning ctx cancellation
			// into "wait the rest of the interval, then try once more"
			// instead of "stop now."
			select {
			case <-ctx.Done():
				err = ctx.Err()
				break fetchLoop
			case <-time.After(jwksFetchRetryInterval):
			}
		}
	}
	if err != nil {
		// Fail-closed, not fatal: every handler treats a nil/absent
		// msPublicKey as "reject everything requiring verification"
		// (handler_upload.go's verifyCapabilityTokenFrame,
		// handler_repair.go/handler_vetting_gc.go's sig checks) rather than
		// crashing the daemon — a durable microservice outage should not
		// prevent the daemon from starting.
		log.Printf("[STARTUP]%s WARNING: could not fetch microservice public key after %d attempts (%v); all capability/audit/repair/GC verification will fail closed for this process's entire lifetime, not just until the microservice recovers — see this block's own F-17E-11 doc comment", logTag, jwksFetchMaxAttempts, err)
	}
	var microservicePeerID p2p.PeerID
	if msPublicKey != nil {
		microservicePeerID, err = p2p.PeerIDFromEd25519PublicKey(msPublicKey)
		if err != nil {
			log.Printf("[STARTUP]%s WARNING: derive microservice Peer ID from JWKS key: %v", logTag, err)
		}
	}

	// ── ChunkStore ────────────────────────────────────────────────────────
	// cfg.chunkStoreDir is the SOLE argument to storage.NewChunkStore — this
	// file never names an engine-specific type from internal/storage, or
	// checks GOOS, itself (IC §11; ADR-046 Phase 16.0). In simulation mode
	// this is flags.simDataDir/{instance}/db, satisfying this session's
	// "Separate storage.ChunkStore instance" requirement; whatever on-disk
	// shape the selected storage backend produces underneath that one path
	// is entirely internal/storage's own business — no simulation-specific
	// path branching by OS exists here or anywhere in this file.
	store, err := storage.NewChunkStore(cfg.chunkStoreDir)
	if err != nil {
		return fmt.Errorf("open chunk store: %w", err)
	}

	// ── Step 5: RecoverFromCrash BEFORE the writer goroutine ────────────
	if err := store.RecoverFromCrash(); err != nil {
		return fmt.Errorf("RecoverFromCrash: %w", err)
	}

	// ── Step 6: single writer goroutine (only caller of AppendChunk) ────
	writeCh := make(chan chunkWriteRequest, chunkWriteQueueSize)
	go runChunkStoreWriter(store, writeCh)

	// ── Step 7: NewHost ──────────────────────────────────────────────────
	listenAddr := fmt.Sprintf("0.0.0.0:%d", cfg.listenPort)
	host, err := p2p.NewHost(p2p.HostConfig{PrivateKey: providerSigningKey, ListenAddr: listenAddr})
	if err != nil {
		close(writeCh)
		return fmt.Errorf("NewHost: %w", err)
	}

	// ── Step 8: register the four stream handlers (IC §4) ───────────────
	// Each protocol ID's SOLE DEFINITION remains its own handler_*.go
	// const (mirroring dht_namespace.go's own "never inline the string
	// literal elsewhere" discipline, IC §12); the four lines below exist
	// for readability only, not as a second definition:
	//   /vyomanaut/chunk-upload/1.0.0
	//   /vyomanaut/audit-challenge/1.0.0
	//   /vyomanaut/repair-download/1.0.0
	//   /vyomanaut/vetting-gc/1.0.0
	statusHolder := newProviderStatusHolder(providerStatusActive)

	uploadHandler := NewUploadHandler(store, writeCh, msPublicKey, providerSigningKey, providerIDBytes, statusHolder)
	host.SetStreamHandler(chunkUploadProtocolID, uploadHandler.HandleStream)

	auditHandler := NewAuditHandler(store, providerSigningKey, providerIDBytes)
	host.SetStreamHandler(auditChallengeProtocolID, auditHandler.HandleStream)

	// The registered-microservice-replica authorizer shared by
	// repair-download and vetting-gc. Seeded with the single microservice
	// Peer ID derived from its JWKS key above — see the GAP note on
	// MicroserviceAuthorizer in handler_repair.go for why this assumes one
	// shared cluster identity rather than a discovered replica set (IC
	// §4.4.1's DHT/heartbeat-driven refresh is not wired in this session).
	authorizer := newStaticMicroserviceAuthorizer()
	if !microservicePeerID.Empty() {
		authorizer.Set([]p2p.PeerID{microservicePeerID})
	}

	repairHandler := NewRepairDownloadHandler(store, msPublicKey, authorizer, profile.AuthRequestFreshnessWindow, microservicePeerID)
	host.SetStreamHandler(repairDownloadProtocolID, repairHandler.HandleStream)

	vettingGCHandler := NewVettingGCHandler(store, msPublicKey, authorizer, profile.AuthRequestFreshnessWindow, microservicePeerID)
	host.SetStreamHandler(vettingGCProtocolID, vettingGCHandler.HandleStream)

	// chunkDownloadHandler (ADR-080) — the data owner's read counterpart
	// to uploadHandler above. Deliberately NOT wired through authorizer:
	// its caller set is arbitrary data owners, never pre-registered with
	// this provider, so there is nothing to allowlist — authorization is
	// entirely the download_token verification inside the handler itself
	// (see that file's own header for why this mirrors uploadHandler's
	// auth model, not repairHandler's).
	chunkDownloadHandler := NewChunkDownloadHandler(store, msPublicKey, providerIDBytes)
	host.SetStreamHandler(chunkDownloadProtocolID, chunkDownloadHandler.HandleStream)

	log.Printf("[STARTUP]%s registered stream handlers: %s %s %s %s %s",
		logTag, chunkUploadProtocolID, auditChallengeProtocolID, repairDownloadProtocolID, vettingGCProtocolID, chunkDownloadProtocolID)

	// ── Step 9: heartbeat goroutine + DHT republication ─────────────────
	// p2p.NewDHT registers the DHT custom validator (dht_namespace.go's
	// dhtKeyNamespace, IC §12) automatically via host.SetStreamHandler
	// internally — nothing further is required here to wire that up.
	dht, err := p2p.NewDHT(host, p2p.DHTConfig{RecordTTL: profile.DHTExpiryDuration})
	if err != nil {
		_ = host.Close()
		close(writeCh)
		return fmt.Errorf("NewDHT: %w", err)
	}

	// localMultiaddr: the SAME advertiseHost computed once above (F-D-4,
	// ADR-084) as registration's initial_multiaddrs — this daemon's own
	// resolved, network-reachable address, not merely its local one.
	// Heartbeat's CurrentAddrs previously always returned nil (documented
	// as a NAT/relay-discovery gap), which meant last_known_multiaddrs
	// stayed NULL for every provider even after heartbeat itself started
	// succeeding — and with no known address,
	// vettingchunk.Generator.GenerateChunk (cmd/microservice) had nowhere
	// to dial, blocking VETTING→ACTIVE just as completely as the earlier
	// heartbeat-auth gap did. Prior to M17-E Session 17.4.1 this always
	// reported 127.0.0.1, which was honest only for the single-host
	// simulation context every test to date runs in;
	// resolveAdvertiseHost now autodetects a real interface address (or
	// honors an explicit --advertise-addr) so the address genuinely
	// reaches this daemon from a separate desktop. Real NAT traversal /
	// relay address discovery for deployments NOT on one shared LAN
	// remains a genuine, separate, larger gap this does not attempt to
	// close (M19, ADR-084 Answers Q2).
	// Trailing /p2p/<PeerID> is required here too, for the same reason as
	// the registration multiaddr above — internal/client/upload's
	// transfer.go parses this segment from last_known_multiaddrs to know
	// which peer identity to dial. The vetting-chunk generator's own
	// dialing happened to work without it (it doesn't parse the multiaddr
	// this way), which is why this omission wasn't caught until the first
	// real (post-ACTIVE) upload attempt — see ADR-070 F-070-7's follow-up.
	//
	// F-D-4: advertiseHost here is the exact same value used to build the
	// registration multiaddr above — one resolution, two call sites.
	localMultiaddr, addrErr := p2p.ParseMultiaddr(advertiseMultiaddr(advertiseHost, cfg.listenPort, peerID))
	if addrErr != nil {
		log.Printf("[STARTUP]%s WARNING: parse local multiaddr: %v", logTag, addrErr)
	}

	heartbeatCfg := p2p.HeartbeatConfig{
		Profile: profile,
		CurrentAddrs: func() []p2p.Multiaddr {
			if localMultiaddr == nil {
				return nil
			}
			return []p2p.Multiaddr{localMultiaddr}
		},
		DHT:   dht,
		Store: nil, // GAP: ChunkDHTKeySource adapter over storage.ChunkStore not yet built (see heartbeat.go's own file comment)

		MicroserviceURL: cfg.microserviceURL,
		// ProviderID: the microservice-assigned UUID from registration, NOT
		// the libp2p Peer ID (peerID) — internal/api's HandleHeartbeat
		// compares this field against the JWT sub claim exactly, and a Peer
		// ID string could never match a UUID. An earlier version of this
		// config used string(peerID) here, silently guaranteeing every
		// heartbeat would be rejected even after the token/signature issues
		// below were fixed — caught only via live verification (build.md
		// Session 16.1.1), not visible from a code-only review.
		ProviderID:    registeredProviderID,
		DaemonVersion: daemonVersion,
		SigningKey:    providerSigningKey,

		// GetToken/RefreshToken: the OTHER previously-missing piece —
		// HeartbeatConfig declared these fields already, but nothing in
		// this file ever populated them, and (a separate bug, fixed in
		// internal/p2p/heartbeat.go itself) postHeartbeat never read
		// GetToken's value into an Authorization header at all. RefreshToken
		// is a deliberate no-op: providerJWTAssumedTTL mirrors
		// internal/api.ProviderTokenTTL (7 days) — far longer than any
		// single daemon run in this codebase's current scope (the demo
		// timeline is ~30-35 minutes, build.md Session 16.1.1) — so an
		// actual POST /api/v1/provider/token/refresh call is unneeded here
		// and left as a real gap for whoever builds long-running daemon
		// support. registeredProviderID/providerJWT are both empty when
		// registration was skipped or failed; GetToken then returns an
		// empty token, and every heartbeat gets the same 401 that already
		// existed before any of this — no new failure mode introduced.
		GetToken: func() (string, time.Time) {
			return providerJWT, time.Now().Add(providerJWTAssumedTTL)
		},
		RefreshToken: func(context.Context) error { return nil },
	}
	go p2p.RunHeartbeat(ctx, heartbeatCfg)

	log.Printf("[STARTUP]%s Vyomanaut provider daemon ready (effective-storage-gb=%d ram-constrained=%v)%s",
		logTag, effectiveStorageGB, ramConstrained, asnSuffix)

	<-ctx.Done()
	log.Printf("[SHUTDOWN]%s context cancelled, shutting down", logTag)
	close(writeCh)
	_ = host.Close()
	_ = store.Close()
	return nil
}

// waitForShutdownSignal blocks until SIGINT or SIGTERM.
func waitForShutdownSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// runChunkStoreWriter is the single designated writer goroutine
// (storage.ChunkStore.AppendChunk: "*** SINGLE WRITER ONLY — NOT
// goroutine-safe ***"). Every AppendChunk call in the whole daemon MUST
// route through this goroutine via writeCh — handler_upload.go's
// UploadHandler is the only caller, and it never calls AppendChunk
// directly (see that file's SINGLE_WRITER_RULE note). Started once from
// main() after crash recovery completes (IC §5.3 pre-condition, Step 5
// above), and stops when writeCh is closed at shutdown.
func runChunkStoreWriter(store storage.ChunkStore, writeCh <-chan chunkWriteRequest) {
	for req := range writeCh {
		offset, err := store.AppendChunk(req.chunkID, req.data)
		req.resultCh <- chunkWriteResult{vlogOffset: offset, err: err}
	}
}

// ── owner seed persistence (identity gap placeholder — see main()'s Step 4 note) ──

const ownerSeedFileName = "owner-seed.bin"
const ownerSeedFileSize = 32 + 16 // masterSecret || ownerID
const privateFilePermissions = 0600

func loadOrGenerateOwnerSeed(dataDir string) (masterSecret [32]byte, ownerID [16]byte, err error) {
	path := filepath.Join(dataDir, ownerSeedFileName)

	data, readErr := os.ReadFile(path)
	if readErr == nil {
		if len(data) != ownerSeedFileSize {
			return masterSecret, ownerID, fmt.Errorf("cmd/provider: owner seed file %s has wrong size (%d, want %d)", path, len(data), ownerSeedFileSize)
		}
		copy(masterSecret[:], data[0:32])
		copy(ownerID[:], data[32:48])
		return masterSecret, ownerID, nil
	}
	if !os.IsNotExist(readErr) {
		return masterSecret, ownerID, fmt.Errorf("cmd/provider: read owner seed: %w", readErr)
	}

	if _, err := rand.Read(masterSecret[:]); err != nil {
		return masterSecret, ownerID, fmt.Errorf("cmd/provider: generate owner seed: %w", err)
	}
	if _, err := rand.Read(ownerID[:]); err != nil {
		return masterSecret, ownerID, fmt.Errorf("cmd/provider: generate owner id: %w", err)
	}

	out := make([]byte, 0, ownerSeedFileSize)
	out = append(out, masterSecret[:]...)
	out = append(out, ownerID[:]...)
	if err := os.WriteFile(path, out, privateFilePermissions); err != nil {
		return masterSecret, ownerID, fmt.Errorf("cmd/provider: persist owner seed: %w", err)
	}
	return masterSecret, ownerID, nil
}

// ── provider self-registration (closes PROVIDER-REGISTRATION GAP, Session
// 16.2.1; wired here as unofficial supplementary work ahead of Sessions
// 16.1.1/16.1.2, per Karma's direction) ─────────────────────────────────
//
// demoProviderCity/demoProviderRegion are the fixed values every simulated
// instance registers with — reasonable simulation-mode defaults, not
// user-configurable anywhere else in this codebase's current scope.
// "Bangalore" is a member of internal/api's own validProviderRegions set
// (internal/api/provider.go), used here for both fields since no separate
// city input exists for --sim-count.
const (
	demoProviderCity   = "Bangalore"
	demoProviderRegion = "Bangalore"
)

const providerRegisterHTTPClientTimeout = 10 * time.Second
const maxErrorBodyBytes = 4096 // cap on error-response bytes read for diagnostics

// providerJWTAssumedTTL mirrors internal/api.ProviderTokenTTL (7 days) —
// duplicated rather than imported, since importing all of internal/api into
// cmd/provider just for one constant would couple two otherwise-separate
// binaries tightly for no real benefit. This value only informs
// maybeRefreshToken's (internal/p2p/heartbeat.go) decision of whether a
// refresh is due soon; RefreshToken itself is a no-op here (see
// heartbeatCfg's doc comment), so drift between this and the server's real
// TTL is low-risk, but keep them in sync manually if either changes.
const providerJWTAssumedTTL = 7 * 24 * time.Hour

// registrationSigningField / canonicalSigningObject / jstr / jstrArray below
// are a deliberate, byte-for-byte client-side mirror of
// internal/api/provider.go's identically-named unexported helpers and its
// canonicalRegisterSigningInput — the exact function this daemon's
// provider_sig must verify against server-side. Duplicated rather than
// imported: internal/api is not (and per IC §9's import table, cmd/provider
// has no business importing) a dependency of this package, and the
// signing-input construction itself is what's being tested/exercised here,
// not merely reused — copying it is what makes this a real integration
// exercise of the actual wire contract rather than a shared-code shortcut
// that could silently drift out of sync with the server on only one side.
type registrationSigningField struct {
	key   string
	value string // pre-encoded JSON value, e.g. `"Mumbai"` or `42` or `["a","b"]`
}

func registrationCanonicalSigningObject(fields ...registrationSigningField) []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, _ := json.Marshal(f.key) // string marshal never errors
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.WriteString(f.value)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

func registrationJstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func registrationJstrArray(ss []string) string {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, s := range ss {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(registrationJstr(s))
	}
	buf.WriteByte(']')
	return buf.String()
}

// providerRegisterRequestBody mirrors internal/api/provider.go's
// unexported providerRegisterRequestBody — the wire shape OAS's
// ProviderRegisterRequest schema defines.
type providerRegisterRequestBody struct {
	Ed25519PublicKey  string   `json:"ed25519_public_key"`
	DeclaredStorageGB int      `json:"declared_storage_gb"`
	City              string   `json:"city"`
	Region            string   `json:"region"`
	ASN               *string  `json:"asn"`
	DemoASN           *string  `json:"demo_asn"`
	InitialMultiaddrs []string `json:"initial_multiaddrs"`
	ProviderSig       string   `json:"provider_sig"`
}

type providerRegisterResponseBody struct {
	ProviderID string `json:"provider_id"`
	Status     string `json:"status"`
	Token      string `json:"token"`
}

// canonicalRegisterSigningInput mirrors internal/api/provider.go's function
// of the same name exactly — same field set, same alphabetical order, same
// jstr/jstrArray encoding — since provider_sig only verifies if both sides
// build byte-identical input.
func canonicalRegisterSigningInput(req providerRegisterRequestBody) []byte {
	var fields []registrationSigningField
	if req.ASN != nil {
		fields = append(fields, registrationSigningField{"asn", registrationJstr(*req.ASN)})
	}
	fields = append(fields, registrationSigningField{"city", registrationJstr(req.City)})
	fields = append(fields, registrationSigningField{"declared_storage_gb", strconv.Itoa(req.DeclaredStorageGB)})
	if req.DemoASN != nil {
		fields = append(fields, registrationSigningField{"demo_asn", registrationJstr(*req.DemoASN)})
	}
	fields = append(fields, registrationSigningField{"ed25519_public_key", registrationJstr(req.Ed25519PublicKey)})
	fields = append(fields, registrationSigningField{"initial_multiaddrs", registrationJstrArray(req.InitialMultiaddrs)})
	fields = append(fields, registrationSigningField{"region", registrationJstr(req.Region)})
	return registrationCanonicalSigningObject(fields...)
}

// registerProviderWithMicroservice calls POST /api/v1/provider/register
// (OAS registerProvider, internal/api/provider.go's ProviderRegisterHandler)
// so this instance actually shows up in the readiness evaluator's
// active_vetted_providers/distinct_asns conditions. demoASN is sent as
// demo_asn when non-empty (--sim-count instances); asn (production) is
// never sent from this codepath. bearerToken is the OTP-verify-issued
// registration token router.go's bearerAny middleware requires on this
// route — see providerFlags.registrationBearerToken's doc comment for why
// this daemon receives it externally rather than obtaining it itself.
//
// Fire-and-forget by design (see this function's caller): failure is
// logged, not fatal — a transient microservice outage at startup should
// not crash the daemon.
// registerProviderWithMicroservice calls POST /api/v1/provider/register
// (OAS registerProvider, internal/api/provider.go's ProviderRegisterHandler)
// so this instance actually shows up in the readiness evaluator's
// active_vetted_providers/distinct_asns conditions. demoASN is sent as
// demo_asn when non-empty (--sim-count instances); asn (production) is
// never sent from this codepath. bearerToken is the OTP-verify-issued
// registration token router.go's bearerAny middleware requires on this
// route — see providerFlags.registrationBearerToken's doc comment for why
// this daemon receives it externally rather than obtaining it itself.
//
// Returns the microservice-assigned provider_id (UUID) and provider JWT
// (role="provider") on success — both required for this instance's own
// heartbeats to authenticate (POST /api/v1/provider/heartbeat is
// bearerAuthRole("provider")-gated, and its body's provider_id must match
// the JWT's sub claim exactly; discovered via live verification that this
// daemon was previously discarding both values entirely).
//
// Fire-and-forget by design (see this function's caller): failure is
// logged, not fatal — a transient microservice outage at startup should
// not crash the daemon.
func registerProviderWithMicroservice(ctx context.Context, microserviceURL, bearerToken string, signingKey ed25519.PrivateKey,
	declaredStorageGB int, city, region, demoASN string, multiaddrs []string) (providerID, token string, err error) {
	pub, ok := signingKey.Public().(ed25519.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("cmd/provider: signing key has no Ed25519 public key")
	}

	req := providerRegisterRequestBody{
		Ed25519PublicKey:  hex.EncodeToString(pub),
		DeclaredStorageGB: declaredStorageGB,
		City:              city,
		Region:            region,
		InitialMultiaddrs: multiaddrs,
	}
	if demoASN != "" {
		req.DemoASN = &demoASN
	}

	// internal/crypto's SignBytes/VerifyBytes (IC §3.2) use a hash-then-sign
	// composition — SHA-256(inputBytes) first, then Ed25519.Sign on the
	// digest — NOT plain Ed25519.Sign on the raw canonical bytes. This
	// wasn't visible from comparing canonicalRegisterSigningInput alone
	// (that function's output is correct); it only surfaced by actually
	// registering against a live microservice and getting back
	// INVALID_BODY_SIGNATURE, then tracing into internal/crypto/ed25519.go
	// directly. An earlier version of this function signed the raw bytes
	// and would have made every real registration attempt fail silently.
	digest := sha256.Sum256(canonicalRegisterSigningInput(req))
	sig := ed25519.Sign(signingKey, digest[:])
	req.ProviderSig = hex.EncodeToString(sig)

	body, err := json.Marshal(req)
	if err != nil {
		return "", "", fmt.Errorf("cmd/provider: marshal provider register request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, microserviceURL+"/api/v1/provider/register", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("cmd/provider: build provider register request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+bearerToken)

	client := &http.Client{Timeout: providerRegisterHTTPClientTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", "", fmt.Errorf("cmd/provider: provider register request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		// Read the body for diagnostics — WriteError's JSON (error_code,
		// message, request_id) is far more actionable than a bare status
		// code alone (a gap that made an earlier live-debugging pass
		// slower than it needed to be).
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return "", "", fmt.Errorf("cmd/provider: provider register returned HTTP %d: %s", resp.StatusCode, errBody)
	}

	var respBody providerRegisterResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return "", "", fmt.Errorf("cmd/provider: decode provider register response: %w", err)
	}
	return respBody.ProviderID, respBody.Token, nil
}

// deriveLocalProviderIDBytes derives a stable, locally-computable 16-byte
// identifier from this daemon's own Peer ID, for use as the
// provider_id_bytes embedded in upload/audit receipt signing inputs (see
// handler_upload.go/handler_audit.go). This is NOT the microservice-
// assigned provider_id UUID (no registration flow supplies one in this
// session's scope — see handler_upload.go's file header) — it is a stable
// local stand-in so receipts are at least internally self-consistent across
// restarts.
func deriveLocalProviderIDBytes(peerID p2p.PeerID) [16]byte {
	digest := sha256.Sum256([]byte(peerID.String()))
	var out [16]byte
	copy(out[:], digest[:16])
	return out
}

// ── microservice JWKS fetch ────────────────────────────────────────────

const providerHTTPClientTimeout = 10 * time.Second

// [Added — F-17E-11] See the JWKS-fetch call site's own doc comment
// (main(), "microservice public key (JWKS) + derived Peer ID") for the
// full finding. 30 attempts * 3s = 90s of retry budget, comfortably
// longer than live verification's observed ~60-70s microservice
// [READINESS] startup window, while still bounded.
const (
	jwksFetchMaxAttempts   = 30
	jwksFetchRetryInterval = 3 * time.Second
)

type jwksKeyDTO struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type jwksResponseDTO struct {
	Keys []jwksKeyDTO `json:"keys"`
}

// fetchMicroservicePublicKey fetches GET {microserviceURL}/.well-known/jwks.json
// and decodes the first Ed25519 ("OKP"/"Ed25519") key found — mirroring
// internal/api/jwt.go's HandleJWKS response shape exactly.
func fetchMicroservicePublicKey(ctx context.Context, microserviceURL string) (ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, microserviceURL+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, fmt.Errorf("cmd/provider: build JWKS request: %w", err)
	}
	client := &http.Client{Timeout: providerHTTPClientTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cmd/provider: fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cmd/provider: JWKS endpoint returned %d", resp.StatusCode)
	}

	var body jwksResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("cmd/provider: decode JWKS response: %w", err)
	}
	for _, k := range body.Keys {
		if k.Kty == "OKP" && k.Crv == "Ed25519" {
			raw, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil {
				return nil, fmt.Errorf("cmd/provider: decode JWKS key x: %w", err)
			}
			if len(raw) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("cmd/provider: JWKS key wrong length (%d, want %d)", len(raw), ed25519.PublicKeySize)
			}
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, fmt.Errorf("cmd/provider: no Ed25519 OKP key found in JWKS response")
}

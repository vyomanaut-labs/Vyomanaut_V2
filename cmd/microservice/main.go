// Command microservice is the Vyomanaut V2 coordination microservice
// entrypoint (ARCH §18): provider registration, chunk assignment, audit
// challenge scheduling/dispatch, reliability scoring, repair queuing,
// payment release computation, and the HTTP API Milestone 11 built.
//
// This file (Session 12.1.1) wires every subsystem built across Milestones
// 1-11 together for the first time — the "one place internal/audit,
// internal/scoring, internal/repair, and internal/payment are all wired
// together" IC §9's closing paragraph names. See config_env.go,
// secrets_client.go, keys.go, payment_provider.go, adapters.go,
// scores_view.go, repair_loop.go, and background_loops.go for the pieces
// this file assembles; see audit_dispatch.go (Session 12.1.2) for the audit
// challenge dispatch loop step 16 starts.
//
// [REF: MVP §2.3, MVP §5.3, MVP §5.5, IC §2, IC §3.4, IC §4.2, IC §8, IC §9,
// ARCH §18, NFR-028, build.md Milestone 12 Phase 12.1]
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/api"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/audit"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/cluster"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/payment"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/repair"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/vettingchunk"
)

// gossipMinPeerAcks is this session's own step 6 requirement: "BLOCK until
// >= 2 peers ack membership (prevents split-brain false-ready on cold
// start)."
const gossipMinPeerAcks = 2

const shutdownTimeout = 5 * time.Second
const databasePingTimeout = 5 * time.Second

// app bundles every long-lived resource runMicroservice constructs, for
// graceful shutdown and so tests can inspect the result without re-running
// main().
type app struct {
	db            *sql.DB
	primaryDB     *sql.DB
	viewRefreshDB *sql.DB
	profile       config.NetworkProfile
	httpServer    *http.Server
	p2pHost       p2p.Host
	cancel        context.CancelFunc
}

// shutdown tears down every resource runMicroservice started, in reverse
// order. Best-effort: logs failures rather than returning them, since a
// shutdown-path error should never prevent the rest of shutdown from
// proceeding.
func (a *app) shutdown() {
	a.cancel()
	if a.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("[SHUTDOWN] http server: %v", err)
		}
	}
	if a.p2pHost != nil {
		if err := a.p2pHost.Close(); err != nil {
			log.Printf("[SHUTDOWN] p2p host: %v", err)
		}
	}
	if a.db != nil {
		if err := a.db.Close(); err != nil {
			log.Printf("[SHUTDOWN] db: %v", err)
		}
	}
	if a.primaryDB != nil && a.primaryDB != a.db {
		if err := a.primaryDB.Close(); err != nil {
			log.Printf("[SHUTDOWN] primary db: %v", err)
		}
	}
	if a.viewRefreshDB != nil {
		if err := a.viewRefreshDB.Close(); err != nil {
			log.Printf("[SHUTDOWN] view-refresh (migrator) db: %v", err)
		}
	}
}

func main() {
	modeFlag := flag.String("mode", "", "network profile: demo or prod (overrides VYOMANAUT_MODE)")
	flag.Parse()

	cfg := loadStartupConfigFromEnv()
	if *modeFlag != "" {
		cfg.ModeFlag = *modeFlag
	} else {
		cfg.ModeFlag = os.Getenv("VYOMANAUT_MODE")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a, err := runMicroservice(ctx, cfg)
	if err != nil {
		log.Fatalf("[STARTUP] FATAL: %v", err)
	}

	waitForShutdownSignal()
	a.shutdown()
}

// waitForShutdownSignal blocks until SIGINT or SIGTERM is received.
func waitForShutdownSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
}

// runMicroservice replaces the cmd/microservice/main.go stub with the
// fully-ordered startup sequence Session 12.1.1 describes. Each numbered
// step's prerequisites are the steps above it — do not reorder without
// re-checking the ordering notes inline in each step's own code below.
//
// Step 1: Select the network profile from cfg.ModeFlag (falling back to
//
//	VYOMANAUT_MODE) and print the startup banner (MVP §5.3).
//
// Step 2: Validate startup guard rails; refuse to start on any violation
//
//	(MVP §2.3).
//
// Step 3: Load the cluster secret from the secrets manager — the real
//
//	adapter in prod (pending Milestone 17 Session 17.1.1), the env-var
//	adapter in demo mode — and fail closed if it cannot be loaded (IC §8).
//
// Step 4: Open the PostgreSQL connection pool(s).
// Step 5: Drop and recreate mv_provider_scores using the profile's scoring
//
//	windows (DM §7, MVP §5.5) — an application-layer step, not a migration.
//
// Step 6: If profile.RequireQuorum, construct the gossip cluster from the
//
//	two seed node addresses and BLOCK until >= 2 peers ack membership
//	(prevents split-brain false-ready on cold start); otherwise use a
//	demo-mode healthy=1 stub with no wait. This step MUST complete before
//	step 7 starts.
//
// Step 7: Start the readiness gate evaluator goroutine (IC §3.4), now that
//
//	step 6 has resolved.
//
// Step 8: Start the HTTP server using the Milestone 11 router.
// Step 9: Construct the cluster-aware router for latency-sensitive dispatch
//
//	paths (ARCH §18) — a stub that always returns the load balancer's own
//	address until Milestone 17 provides the real gossip-aware
//	implementation (a no-op until M17, not the real membership-aware
//	routing logic).
//
// Step 10: Construct the real p2p.Host.
// Step 11: repairTransport wraps p2pHost via repairTransportAdapter, which
//
//	satisfies repair.RepairTransport (internal/repair never imports
//	internal/p2p — IC §9).
//
// Step 12: Construct the payment provider per profile.PaymentMode.
// Step 13: Start the departure detector, wiring paymentProvider.Penalise —
//
//	the exact site Milestone 9 Session 9.3.1 deferred payment.Penalise to.
//
// Step 14: Start the stale PRE_WARNING promotion ticker — nothing else in
//
//	the build plan drives repair.PromoteStalePreWarningJobs.
//
// Step 15: Start the repair executor loop — nothing else in the build plan
//
//	consumes the repair queue via repair.DequeueNextJob.
//
// Step 16: Start the audit challenge dispatch loop (Session 12.1.2).
// Step 17: Start the release computation loop. payment.RunReleaseComputationLoop
//
//	internally branches on profile.ReleaseComputationInterval (calendar
//	schedule in production, a plain ticker in demo) and calls
//	payment.ComputeMonthlyRelease on each cycle (internal/payment/release.go)
//	— reused here rather than re-implementing that branching logic, which
//	was already fully built in Milestone 10.
//
// Step 18: Start the background throttle goroutine (NFR-028): samples
//
//	foreground DB read p99 latency every 60s; reduces background
//	concurrency as it approaches 50ms, restores it below 30ms.
func runMicroservice(ctx context.Context, cfg startupConfig) (*app, error) {
	ctx, cancel := context.WithCancel(ctx)

	// ── Step 1 ────────────────────────────────────────────────────────────
	profile := config.SelectProfile(cfg.ModeFlag)

	// ── Step 2 ────────────────────────────────────────────────────────────
	if err := config.ValidateStartupGuards(profile); err != nil {
		cancel()
		return nil, fmt.Errorf("runMicroservice: startup guards: %w", err)
	}

	// ── Step 3 ────────────────────────────────────────────────────────────
	secretsClient, err := newSecretsClientForProfile(profile.RequireSecretsManager)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("runMicroservice: construct secrets client: %w", err)
	}
	cache := audit.NewClusterSecretCache(secretsClient)
	if err := loadClusterSecret(ctx, cache); err != nil {
		cancel()
		return nil, fmt.Errorf("runMicroservice: fail-closed on cluster secret (IC §8): %w", err)
	}

	// ── Step 4 ────────────────────────────────────────────────────────────
	db, err := openDBPool(cfg.DBDSN)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("runMicroservice: open db pool: %w", err)
	}
	primaryDB := db
	if cfg.PrimaryDBDSN != cfg.DBDSN {
		primaryDB, err = openDBPool(cfg.PrimaryDBDSN)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("runMicroservice: open primary db pool: %w", err)
		}
	}

	a := &app{db: db, primaryDB: primaryDB, profile: profile, cancel: cancel}

	// ── Step 5 ────────────────────────────────────────────────────────────
	// Uses a short-lived vyomanaut_migrator connection, not db — see
	// startupConfig.MigratorDBDSN's own doc comment on why the request-path
	// vyomanaut_app role cannot perform this DROP/CREATE MATERIALIZED VIEW
	// (ownership + FORCE-RLS visibility, ADR-032). Opened and closed within
	// this step: nothing else needs elevated privileges for the rest of the
	// process's lifetime — EXCEPT runBackgroundViewRefreshLoop (Step 22,
	// added M17 CLI debugging session), which needs the SAME elevated role
	// for the SAME ownership reason (REFRESH MATERIALIZED VIEW requires
	// owning the view object; vyomanaut_app's GRANT SELECT does not confer
	// this — ADR-032). Rather than open a second migrator connection later,
	// a.viewRefreshDB is opened here alongside this step's own migratorDB
	// and kept alive for the process's lifetime (closed in shutdown()),
	// while migratorDB itself is still closed immediately after this one-time
	// call exactly as before.
	migratorDB, err := openDBPool(cfg.MigratorDBDSN)
	if err != nil {
		a.shutdown()
		return nil, fmt.Errorf("runMicroservice: open migrator db pool: %w", err)
	}
	err = regenerateProviderScoresView(ctx, migratorDB, profile)
	_ = migratorDB.Close()
	if err != nil {
		a.shutdown()
		return nil, fmt.Errorf("runMicroservice: regenerate mv_provider_scores: %w", err)
	}
	viewRefreshDB, err := openDBPool(cfg.MigratorDBDSN)
	if err != nil {
		a.shutdown()
		return nil, fmt.Errorf("runMicroservice: open view-refresh (migrator) db pool: %w", err)
	}
	a.viewRefreshDB = viewRefreshDB

	// ── Step 6 — gossipCluster: MUST complete before step 7 starts ──────────
	clusterMembership, err := waitForGossipQuorum(ctx, profile, cfg.SeedNode1, cfg.SeedNode2)
	if err != nil {
		a.shutdown()
		return nil, fmt.Errorf("runMicroservice: gossip quorum: %w", err)
	}

	// ── Step 7 — readiness evaluator: only starts now that step 6 resolved ──
	readinessEvaluator := api.NewReadinessEvaluator(db, profile, cache, clusterMembership, api.StubRelayNodeCounter{})
	go startReadinessMonitorLoop(ctx, readinessEvaluator)

	// ── Microservice signing key + admin key (shared across steps 8-16) ────
	jwtPub, jwtPriv, err := loadOrGenerateMicroserviceSigningKey(profile.RequireSecretsManager, cfg.MicroserviceSigningSeedHex)
	if err != nil {
		a.shutdown()
		return nil, fmt.Errorf("runMicroservice: microservice signing key: %w", err)
	}
	adminAPIKey, err := loadOrGenerateAdminAPIKey(profile.RequireSecretsManager, cfg.AdminAPIKeyHex)
	if err != nil {
		a.shutdown()
		return nil, fmt.Errorf("runMicroservice: admin API key: %w", err)
	}
	jwtKeyID := cfg.JWTKeyID
	if jwtKeyID == "" {
		jwtKeyID = fmt.Sprintf("vyomanaut-ms-%s", cfg.ModeFlag)
	}

	paymentProviderForRouter := buildPaymentProvider(db, profile)

	// ── Step 8 ────────────────────────────────────────────────────────────
	router := api.NewRouter(api.RouterConfig{
		AdminAPIKey:        adminAPIKey,
		DB:                 db,
		JWTPublicKey:       jwtPub,
		JWTPrivateKey:      jwtPriv,
		JWTKeyID:           jwtKeyID,
		OtpSender:          api.NoopOtpSender{}, // real SMS delivery is not in scope for this session
		Readiness:          readinessEvaluator,
		Profile:            profile,
		PaymentProvider:    paymentProviderForRouter,
		InFlightUploads:    api.NoInFlightUploadChecker{},
		ClusterSecretCache: cache,
	})
	httpServer := &http.Server{Addr: cfg.HTTPListenAddr, Handler: router}
	a.httpServer = httpServer
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTP] ListenAndServe: %v", err)
		}
	}()

	// ── Step 9 ────────────────────────────────────────────────────────────
	// clusterRouter.ResponsibleReplica is a stub that always returns the
	// load balancer's own address until Milestone 17 provides the real
	// gossip-aware implementation — a no-op until M17, not the real
	// membership-aware routing logic (see cluster/router.go).
	clusterRouter := cluster.NewRouter(clusterMembership, cfg.HTTPListenAddr)
	_ = clusterRouter // constructed per this session's step 9; consulted by Milestone 17's real dispatch paths, not by this session's own loops

	// ── Step 10 ───────────────────────────────────────────────────────────
	p2pHost, err := p2p.NewHost(p2p.HostConfig{PrivateKey: jwtPriv, ListenAddr: cfg.P2PListenAddr})
	if err != nil {
		a.shutdown()
		return nil, fmt.Errorf("runMicroservice: construct p2p host: %w", err)
	}
	a.p2pHost = p2pHost

	// ── Step 11 ───────────────────────────────────────────────────────────
	// repairTransport := p2pHost, adapted — see adapters.go's header note on
	// why repairTransportAdapter (not a bare structural cast) is required.
	repairTransport := &repairTransportAdapter{db: db, host: p2pHost}

	// ── Step 12 ───────────────────────────────────────────────────────────
	paymentProvider := buildPaymentProvider(db, profile)

	// ── Step 13 ───────────────────────────────────────────────────────────
	departureDetector := repair.NewDepartureDetector(db, profile, paymentProvider.Penalise)
	go departureDetector.Run(ctx)

	// ── Step 14 ───────────────────────────────────────────────────────────
	go runPromotionTicker(ctx, db, profile)

	// ── Step 15 ───────────────────────────────────────────────────────────
	erasureEngine, err := erasure.NewEngine(profile)
	if err != nil {
		a.shutdown()
		return nil, fmt.Errorf("runMicroservice: construct erasure engine: %w", err)
	}
	go runRepairExecutorLoop(ctx, db, profile, repairTransport, erasureEngine, jwtPriv, p2pHost)

	// ── Step 16 ───────────────────────────────────────────────────────────
	go runAuditDispatchLoop(ctx, db, profile, cache, p2pHost, jwtPriv)

	// ── Step 17 ───────────────────────────────────────────────────────────
	go payment.RunReleaseComputationLoop(ctx, db, primaryDB, profile, paymentProvider)

	// ── Step 18 ───────────────────────────────────────────────────────────
	go runBackgroundThrottleLoop(ctx, db, foregroundReadP99)

	// ── Step 19 (added post-hoc — closes a gap found via live verification,
	// not part of the original 18-step sequence; appended rather than
	// renumbering Steps 1-18) ───────────────────────────────────────────
	go runVettingChunkGenerationLoop(ctx, db, vettingchunk.NewGenerator(db, p2pHost, jwtPriv))

	// ── Step 20 (added post-hoc, same session as Step 19) ────────────────
	go runClusterSecretRefreshLoop(ctx, cache)

	// ── Step 21 (added post-hoc, same session as Steps 19-20) ────────────
	go runVettingGCLoop(ctx, db, vettingchunk.NewGCDelivery(db, p2pHost, jwtPriv))

	// ── Step 22 (added post-hoc — M17 CLI debugging session; resolves the
	// build blocker found live: mv_owner_escrow_balance/
	// mv_provider_escrow_balance/mv_segment_shard_counts were never
	// refreshed by any code path, so owner/provider balance reads stayed
	// frozen at their initial (empty) state regardless of real deposits).
	// Uses a.viewRefreshDB (vyomanaut_migrator), NOT db (vyomanaut_app) —
	// see Step 5's own note: REFRESH MATERIALIZED VIEW requires owning the
	// view object, which vyomanaut_app's GRANT SELECT does not confer
	// (ADR-032), the exact same reason regenerateProviderScoresView above
	// already uses a migrator connection instead of db.
	// ──────────────────────────────────────────────────────────────────
	go runBackgroundViewRefreshLoop(ctx, a.viewRefreshDB, profile)

	return a, nil
}

// loadClusterSecret is this session's step 3 fail-closed wrapper (IC §8):
// "if the secrets manager is unreachable at startup, the replica must not
// start."
func loadClusterSecret(ctx context.Context, cache *audit.ClusterSecretCache) error {
	if err := cache.Load(ctx); err != nil {
		return err
	}
	return nil
}

// openDBPool opens a PostgreSQL connection pool and verifies it is actually
// reachable via PingContext before returning — a DSN that merely parses is
// not the same as a database that is actually reachable, and step 4 should
// fail loudly here rather than defer the discovery to the first query some
// later step issues.
func openDBPool(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), databasePingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return db, nil
}

// waitForGossipQuorum implements this session's step 6. In demo mode
// (profile.RequireQuorum == false), returns cluster.SoloMembership{}
// immediately — no gossip cluster is constructed and no wait occurs. In
// production, constructs cluster.GossipCluster from the two seed node
// addresses (fail-fast if either is absent — ARCH §18's "two seed node
// addresses... prevent the cluster from partitioning on restart" is not
// optional) and BLOCKS until >= 2 peers ack membership.
func waitForGossipQuorum(ctx context.Context, profile config.NetworkProfile, seedNode1, seedNode2 string) (cluster.Membership, error) {
	if !profile.RequireQuorum {
		return cluster.SoloMembership{}, nil
	}
	if seedNode1 == "" || seedNode2 == "" {
		return nil, fmt.Errorf("VYOMANAUT_SEED_NODE_1 and VYOMANAUT_SEED_NODE_2 are both required when profile.RequireQuorum")
	}
	gossipCluster := cluster.NewGossipCluster([]string{seedNode1, seedNode2})
	if err := gossipCluster.WaitForQuorum(ctx, gossipMinPeerAcks); err != nil {
		return nil, fmt.Errorf("wait for >= %d peer acks: %w", gossipMinPeerAcks, err)
	}
	return gossipCluster, nil
}

// foregroundReadP99 is the dbReadP99Prober runBackgroundThrottleLoop (step
// 18) uses in production. See background_loops.go's dbReadP99Prober doc
// comment for why this queries pg_stat_statements rather than a dedicated
// metrics subsystem (none exists in this codebase yet).
func foregroundReadP99(ctx context.Context, db *sql.DB) (time.Duration, error) {
	const query = `
SELECT COALESCE(
    (SELECT (mean_exec_time * 3) -- p99 approximation: pg_stat_statements exposes mean/stddev, not true percentiles
     FROM pg_stat_statements
     WHERE query ILIKE 'SELECT%'
     ORDER BY mean_exec_time DESC
     LIMIT 1),
    0)`
	var meanMs float64
	if err := db.QueryRowContext(ctx, query).Scan(&meanMs); err != nil {
		// pg_stat_statements may not be installed (it is an optional
		// extension) — treat as "no signal" rather than a fatal error, so
		// the throttle loop simply never throttles rather than crashing the
		// process over an observability extension being absent.
		return 0, nil //nolint:nilerr
	}
	return time.Duration(meanMs * float64(time.Millisecond)), nil
}

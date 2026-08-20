// cmd/microservice is the coordination microservice entrypoint (Milestone
// 12, Phase 12.1). This file collects every environment-variable-derived
// piece of startup configuration that is NOT already covered by
// config.NetworkProfile (MVP §5.1) — connection strings, credentials, and
// listen addresses, none of which differ between demo and prod in KIND, only
// in whether they may be safely defaulted.
//
// [Decision] No document in scope (MVP, ARCH, IC, DM) names these specific
// environment variables — they are wiring details this session (Milestone
// 12 Phase 12.1) must invent to actually start a process. Named following
// the existing VYOMANAUT_* / PG* conventions already established elsewhere
// in this codebase (config/guards.go's VYOMANAUT_CLUSTER_MASTER_SEED,
// VYOMANAUT_SEED_NODE_1/2 from this session's own task text, and the PGHOST/
// PGPORT/PGUSER/PGPASSWORD/PGDATABASE/PGSSLMODE convention internal/api's own
// tests already use — see internal/api/readiness_test.go's envOr/testDSN).
package main

import (
	"fmt"
	"os"
)

// startupConfig bundles every environment-variable-derived setting the
// startup sequence needs, beyond config.NetworkProfile itself.
type startupConfig struct {
	ModeFlag string // --mode CLI flag value; empty defers to VYOMANAUT_MODE (config.SelectProfile)

	DBDSN        string // pooled/possibly-replica-routed connection string
	PrimaryDBDSN string // forced-primary connection string (payment.RunReleaseComputationLoop)
	// MigratorDBDSN connects as vyomanaut_migrator (BYPASSRLS/superuser) —
	// required for regenerateProviderScoresView (step 5): the migration's
	// own role-model comment (migrations/001_initial_schema.sql, ADR-032)
	// says this role, not the request-path vyomanaut_app, "runs migrations,
	// refreshes materialised views... so maintenance and MV refresh can
	// read the FORCE-RLS tables." vyomanaut_app also lacks ownership of the
	// view object itself, so DROP/CREATE MATERIALIZED VIEW fails under it
	// with a permissions error, not just an RLS-visibility gap.
	MigratorDBDSN string

	SeedNode1 string // VYOMANAUT_SEED_NODE_1 (prod, RequireQuorum only)
	SeedNode2 string // VYOMANAUT_SEED_NODE_2 (prod, RequireQuorum only)

	AdminAPIKeyHex             string // VYOMANAUT_ADMIN_API_KEY, >=64 hex chars (OAS AdminApiKey scheme)
	MicroserviceSigningSeedHex string // VYOMANAUT_MICROSERVICE_SIGNING_SEED, 64 hex chars (32-byte Ed25519 seed)
	JWTKeyID                   string // VYOMANAUT_JWT_KEY_ID; defaults to "vyomanaut-ms-<mode>"

	HTTPListenAddr string // VYOMANAUT_HTTP_LISTEN_ADDR; default ":8080"
	P2PListenAddr  string // VYOMANAUT_P2P_LISTEN_ADDR; empty = outbound-only (HostConfig's own documented default for the microservice)

	// OtpDeliveryLogPath (M17-E Session 17.4.2, ADR-084 D-3): path to a
	// demo-mode OTP delivery log — set from --otp-delivery-log or
	// VYOMANAUT_OTP_DELIVERY_LOG. Empty (the default) preserves this
	// daemon's exact original behavior: api.NoopOtpSender, no file, no SMS
	// integration. Non-empty is FATAL outside demo mode (runMicroservice) —
	// a file-backed OTP gateway is a legitimate demo convenience and a
	// genuine incident waiting to happen in production.
	OtpDeliveryLogPath string

	// LoadBalancerAddr is the address cluster.NewRouter's ResponsibleReplica
	// stub reports as "the load balancer" (ARCH §18, Milestone 17 Phase
	// 17.2.1's eventual real target). VYOMANAUT_LOAD_BALANCER_ADDR;
	// defaults to HTTPListenAddr — see main.go step 9's own header note
	// (M12 audit corrections, Finding 11) on why that default is still
	// only a same-behaviour-as-before placeholder, not a real fix, until
	// this env var is actually set against a real load balancer.
	LoadBalancerAddr string
}

// envOr returns the value of the named environment variable, or def if unset
// or empty. Mirrors the same helper internal/api's tests already use
// (internal/api/readiness_test.go) — duplicated rather than imported since
// internal/api's test helpers are unexported and package-test-local.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// loadStartupConfigFromEnv reads every VYOMANAUT_*/PG* environment variable
// this entrypoint needs. Called once from main(); factored out so tests can
// construct a startupConfig directly without touching the process
// environment.
func loadStartupConfigFromEnv() startupConfig {
	pgHost := envOr("PGHOST", "localhost")
	pgPort := envOr("PGPORT", "5432")
	pgUser := envOr("PGUSER", "vyomanaut_app")
	pgPassword := envOr("PGPASSWORD", "devpass")
	pgDatabase := envOr("PGDATABASE", "vyomanaut_dev")
	pgSSLMode := envOr("PGSSLMODE", "disable")
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		pgHost, pgPort, pgUser, pgPassword, pgDatabase, pgSSLMode)

	// primaryDSN: no separate primary/replica topology is wired at the
	// connection-string level anywhere in this codebase yet (ARCH §18's
	// "primary + 2 replicas" is a PostgreSQL-managed topology, opaque to
	// the application layer per IC §2's own "what this diagram does not
	// show" note). PGPRIMARYHOST etc. let an operator point this at a
	// distinct primary if one exists; absent that, it is the same DSN —
	// correct today (a single Postgres instance in both demo and this
	// environment's own dev docker-compose).
	primaryHost := envOr("PGPRIMARYHOST", pgHost)
	primaryPort := envOr("PGPRIMARYPORT", pgPort)
	primaryDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		primaryHost, primaryPort, pgUser, pgPassword, pgDatabase, pgSSLMode)

	// migratorDSN: same database, but the vyomanaut_migrator role
	// (BYPASSRLS/superuser) — see MigratorDBDSN's own doc comment. Defaults
	// to the migration's own dev-docker-compose convention (vyomanaut_migrator);
	// PGMIGRATORUSER/PGMIGRATORPASSWORD let an operator override for prod,
	// where this credential should be scoped far more narrowly than a
	// blanket superuser.
	//
	// [Corrected — M12 audit corrections, Finding 6] Host/port previously
	// came from pgHost/pgPort (the general, possibly-replica-routed
	// values) rather than primaryHost/primaryPort the way PrimaryDBDSN
	// above already is. regenerateProviderScoresView's DROP/CREATE
	// MATERIALIZED VIEW is write-only DDL — categorically cannot run
	// against a replica, exactly like PrimaryDBDSN's own consumer
	// (payment.RunReleaseComputationLoop). Inert today only because
	// primaryHost == pgHost by default in this codebase's current
	// single-instance topology (see primaryDSN's own comment above); this
	// would otherwise silently break the fail-closed startup sequence the
	// moment a real primary/replica split is stood up (ARCH §18), unless
	// whoever wires that up happens to also remember to override
	// MigratorDBDSN's host explicitly.
	migratorUser := envOr("PGMIGRATORUSER", "vyomanaut_migrator")
	migratorPassword := envOr("PGMIGRATORPASSWORD", pgPassword)
	migratorDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		primaryHost, primaryPort, migratorUser, migratorPassword, pgDatabase, pgSSLMode)

	httpListenAddr := envOr("VYOMANAUT_HTTP_LISTEN_ADDR", ":8080")

	return startupConfig{
		ModeFlag: envOr("VYOMANAUT_MODE_FLAG", ""), // set from the --mode CLI flag in main(), not read directly here

		DBDSN:         dsn,
		PrimaryDBDSN:  primaryDSN,
		MigratorDBDSN: migratorDSN,

		SeedNode1: os.Getenv("VYOMANAUT_SEED_NODE_1"),
		SeedNode2: os.Getenv("VYOMANAUT_SEED_NODE_2"),

		AdminAPIKeyHex:             os.Getenv("VYOMANAUT_ADMIN_API_KEY"),
		MicroserviceSigningSeedHex: os.Getenv("VYOMANAUT_MICROSERVICE_SIGNING_SEED"),
		JWTKeyID:                   os.Getenv("VYOMANAUT_JWT_KEY_ID"),

		HTTPListenAddr: httpListenAddr,
		P2PListenAddr:  os.Getenv("VYOMANAUT_P2P_LISTEN_ADDR"), // empty = outbound-only (HostConfig doc comment)

		OtpDeliveryLogPath: os.Getenv("VYOMANAUT_OTP_DELIVERY_LOG"), // empty = NoopOtpSender (unchanged default)

		// LoadBalancerAddr: see this field's own doc comment (M12 audit
		// corrections, Finding 11) — defaults to this replica's own
		// HTTPListenAddr, preserving today's exact behaviour, until an
		// operator sets this against a real load balancer.
		LoadBalancerAddr: envOr("VYOMANAUT_LOAD_BALANCER_ADDR", httpListenAddr),
	}
}

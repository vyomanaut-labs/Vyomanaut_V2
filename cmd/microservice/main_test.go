package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/audit"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/cluster"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/repair"
)

// openTestDB opens a connection to the local test Postgres instance,
// mirroring the established testDSN convention (internal/api/readiness_test.go,
// internal/scoring/score_test.go) — including its vyomanaut_test default
// database name, not deployments/dev/docker-compose.yml's vyomanaut_dev,
// so a bare `go test` run without PGDATABASE explicitly set targets the
// same database as every other package's test suite rather than a
// same-named-but-different one. Skips the calling test if no database is
// reachable, rather than failing.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		envOr("PGHOST", "localhost"), envOr("PGPORT", "5432"), envOr("PGUSER", "vyomanaut_app"),
		envOr("PGPASSWORD", "devpass"), envOr("PGDATABASE", "vyomanaut_test"), envOr("PGSSLMODE", "disable"))
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("openTestDB: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("openTestDB: database unreachable: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// failingSecretsClient always reports the secrets manager as unreachable.
type failingSecretsClient struct{}

func (failingSecretsClient) GetSecret(context.Context, string) ([]byte, error) {
	return nil, audit.ErrSecretManagerUnavailable
}

func TestStartupFailsClosedOnUnreachableSecretsManager(t *testing.T) {
	cache := audit.NewClusterSecretCache(failingSecretsClient{})
	if err := loadClusterSecret(context.Background(), cache); err == nil {
		t.Fatal("loadClusterSecret: expected an error when the secrets manager is unreachable, got nil")
	}
}

func TestStartupDemoModeSkipsGossipWait(t *testing.T) {
	start := time.Now()
	membership, err := waitForGossipQuorum(context.Background(), config.DemoProfile, "", "")
	if err != nil {
		t.Fatalf("waitForGossipQuorum: unexpected error in demo mode: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("waitForGossipQuorum: expected an immediate return in demo mode, took %s", elapsed)
	}
	if _, ok := membership.(cluster.SoloMembership); !ok {
		t.Fatalf("waitForGossipQuorum: expected cluster.SoloMembership in demo mode, got %T", membership)
	}
	if got := membership.HealthyCount(); got != 1 {
		t.Fatalf("waitForGossipQuorum: expected HealthyCount()==1 in demo mode, got %d", got)
	}
}

func TestStartupProdModeBlocksUntilTwoPeerAck(t *testing.T) {
	membership, err := waitForGossipQuorum(context.Background(), config.ProductionProfile, "seed1.example:4001", "seed2.example:4001")
	if err != nil {
		t.Fatalf("waitForGossipQuorum: unexpected error: %v", err)
	}
	gc, ok := membership.(*cluster.GossipCluster)
	if !ok {
		t.Fatalf("waitForGossipQuorum: expected *cluster.GossipCluster in prod mode, got %T", membership)
	}
	if got := gc.HealthyCount(); got < gossipMinPeerAcks {
		t.Fatalf("waitForGossipQuorum: expected HealthyCount() >= %d (this session's own >=2 peer-ack requirement), got %d",
			gossipMinPeerAcks, got)
	}
}

func TestStartupProdModeRequiresSeedNodes(t *testing.T) {
	if _, err := waitForGossipQuorum(context.Background(), config.ProductionProfile, "", ""); err == nil {
		t.Fatal("waitForGossipQuorum: expected an error when seed nodes are unset in prod mode")
	}
}

// fakePenaliser records whether Penalise was invoked, standing in for a
// payment.PaymentProvider's Penalise method for wiring verification.
type fakePenaliser struct {
	called bool
}

func (f *fakePenaliser) Penalise(_ context.Context, _ uuid.UUID, _ int64, _ string) error {
	f.called = true
	return nil
}

func TestStartupWiresDepartureDetectorPenaliseCallback(t *testing.T) {
	db := openTestDB(t)
	fake := &fakePenaliser{}
	detector := repair.NewDepartureDetector(db, config.DemoProfile, fake.Penalise)
	if detector == nil {
		t.Fatal("repair.NewDepartureDetector returned nil")
	}
	// Exercises the exact construction this session's step 13 performs
	// (repair.NewDepartureDetector(db, profile, paymentProvider.Penalise));
	// with no departed providers present this should complete without
	// error and without invoking Penalise.
	if err := detector.DetectOnce(context.Background()); err != nil {
		t.Fatalf("DetectOnce: %v", err)
	}
}

func TestStartupRejectsProdModeWithEnvSecretPresent(t *testing.T) {
	t.Setenv("VYOMANAUT_CLUSTER_MASTER_SEED", "should-not-be-set-in-prod")
	profile := config.SelectProfile("prod")
	if err := config.ValidateStartupGuards(profile); err == nil {
		t.Fatal("config.ValidateStartupGuards: expected an error for prod mode with VYOMANAUT_CLUSTER_MASTER_SEED set (M1 Session 1.3.2's PROD_MODE_ENV_SECRET guard)")
	}
}

// openTestMigratorDB opens a connection as vyomanaut_migrator (BYPASSRLS) —
// required for regenerateProviderScoresView's DROP/CREATE MATERIALIZED VIEW
// (see config_env.go's MigratorDBDSN doc comment). Skips if unreachable,
// same convention as openTestDB.
//
// [Bug fix] This used to read PGMIGRATORUSER/PGMIGRATORPASSWORD — names
// invented for this file alone, distinct from the PGVERIFY_USER/
// PGVERIFY_PASSWORD convention internal/api and internal/scoring's own test
// helpers already established for exactly this purpose (a migrator-
// privileged connection for test setup/verification; see
// internal/scoring/score_test.go's openVerifyDB). Because the password had
// a silent fallback to PGPASSWORD (the vyomanaut_app password) whenever
// PGMIGRATORPASSWORD was unset, this connected with the WRONG password in
// any environment that (correctly) sets PGVERIFY_PASSWORD but has never
// heard of PGMIGRATORPASSWORD — which is every environment, since nothing
// else in this codebase ever used that name. The practical effect: this
// test silently t.Skip'd locally (dev's vyomanaut_migrator password is
// devpass; PGPASSWORD is testpass) while actually running in CI (CI
// happens to set every role's password to testpass, so the wrong fallback
// accidentally matched) — masking the shared-test-database side effect
// TestRegenerateProviderScoresView documents below in exactly the one
// environment (local) where it would have been caught before reaching CI.
// Now uses the same PGVERIFY_USER/PGVERIFY_PASSWORD names, with no
// PGPASSWORD fallback, matching testDSN's own established pattern
// (internal/api/readiness_test.go, internal/scoring/score_test.go) exactly.
func openTestMigratorDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		envOr("PGHOST", "localhost"), envOr("PGPORT", "5432"), envOr("PGVERIFY_USER", "postgres"),
		os.Getenv("PGVERIFY_PASSWORD"), envOr("PGDATABASE", "vyomanaut_test"), envOr("PGSSLMODE", "disable"))
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("openTestMigratorDB: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("openTestMigratorDB: database unreachable: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestRegenerateProviderScoresView verifies both that
// regenerateProviderScoresView succeeds (including safe re-runs) and that
// its interval substitution actually took effect, then restores the view
// to config.ProductionProfile's windows before returning.
//
// [Bug fix — shared-test-database pollution] This test's database
// (vyomanaut_test) is shared, unreset, across every package in the same
// `go test -p 1 ./...` run (CI; and any local run mirroring it) —
// cmd/microservice's own tests always run first (alphabetically before
// internal/*). Testing against config.DemoProfile and stopping there left
// the shared mv_provider_scores view permanently rebuilt with demo-scale
// windows (2min/6min/20min) for every package that ran afterward.
// internal/scoring's own pre-existing tests (predating this session) were
// written and tuned against the migration's original, PRODUCTION-scale
// placeholder windows (24h/7d/30d) baked into
// migrations/001_initial_schema*.sql — e.g. inserting a receipt "1 hour
// ago" and expecting it to land inside the (24h) short window. Once this
// test silently left the shared view at 2-MINUTE windows instead, "1 hour
// ago" no longer qualified, and internal/scoring's tests failed with
// unpopulated (zero) scores — not a permission error, so it was a distinct
// failure signature from the GRANT bug this file's other fix addresses,
// but with the same root cause: this file mutating shared, persistent
// database state beyond its own test's scope. Restoring
// config.ProductionProfile's windows afterward (matching what the
// migration originally provided) via t.Cleanup makes this test's effect on
// the shared database idempotent again, regardless of whether it fails
// partway through.
// durationAsPostgresIntervalText formats d the way Postgres's own
// pg_matviews.definition normalizes a "%f seconds" interval literal under
// 24 hours: HH:MM:SS. Only needs to handle sub-day durations — every
// interval regenerateProviderScoresView ever substitutes is either a demo
// (minutes) or production (hours/days) scoring window, and this test only
// checks the demo case.
func durationAsPostgresIntervalText(d time.Duration) string {
	total := int(d.Seconds())
	h := total / 3600
	m := (total % 3600) / 60
	s := total % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func TestRegenerateProviderScoresView(t *testing.T) {
	db := openTestMigratorDB(t)
	t.Cleanup(func() {
		if err := regenerateProviderScoresView(context.Background(), db, config.ProductionProfile); err != nil {
			t.Logf("TestRegenerateProviderScoresView cleanup: restore production-scale windows: %v", err)
		}
	})

	if err := regenerateProviderScoresView(context.Background(), db, config.DemoProfile); err != nil {
		t.Fatalf("regenerateProviderScoresView: %v", err)
	}

	// Verify the interval substitution actually happened, not just that
	// CREATE succeeded — pg_matviews.definition reflects the *effective*
	// SQL Postgres stored, with %[n]s already resolved. Postgres normalizes
	// interval literals to its own canonical HH:MM:SS text (e.g. "120.000000
	// seconds" becomes "00:02:00"), so the check below matches that
	// normalized form rather than intervalLiteral's own input format.
	var definition string
	if err := db.QueryRowContext(context.Background(),
		`SELECT definition FROM pg_matviews WHERE matviewname = 'mv_provider_scores'`,
	).Scan(&definition); err != nil {
		t.Fatalf("read mv_provider_scores definition: %v", err)
	}
	wantShort := durationAsPostgresIntervalText(config.DemoProfile.ScoreWindowShort)
	if !strings.Contains(definition, wantShort) {
		t.Fatalf("mv_provider_scores definition does not contain the demo-profile short window (%s); got:\n%s", wantShort, definition)
	}

	// The view must exist and be queryable (zero rows is fine — no audit
	// receipts exist in a fresh test database).
	rows, err := db.QueryContext(context.Background(), `SELECT provider_id, score_composite FROM mv_provider_scores`)
	if err != nil {
		t.Fatalf("query mv_provider_scores: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Fatalf("close mv_provider_scores rows: %v", err)
		}
	}()
	for rows.Next() {
		var id uuid.UUID
		var composite float64
		if err := rows.Scan(&id, &composite); err != nil {
			t.Fatalf("scan mv_provider_scores row: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate mv_provider_scores: %v", err)
	}

	// Regenerating again (as every startup does) must also succeed —
	// DROP MATERIALIZED VIEW IF EXISTS followed by CREATE must be safely
	// repeatable.
	if err := regenerateProviderScoresView(context.Background(), db, config.DemoProfile); err != nil {
		t.Fatalf("regenerateProviderScoresView (second run): %v", err)
	}
}

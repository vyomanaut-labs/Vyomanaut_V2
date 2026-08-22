// Package api is declared in doc.go.
// Unit and live-database integration tests for the readiness evaluator.
//
// providers accumulates VETTING/ACTIVE rows across this whole shared test
// database from every other package's tests built earlier in this session
// (scoring, repair, payment). Rather than assume a clean slate, these tests
// top up whatever already exists with a batch of freshly, uniquely-ASN'd
// providers guaranteed to push every count-based condition over
// config.DemoProfile's thresholds — the same "robust to shared-table
// accumulation" pattern used throughout this build (Milestones 8-10).
//
// Tests:
//   - TestReadinessAllSevenConditionsEvaluated
//   - TestReadinessAllConditionsMetWhenAllSatisfied
//   - TestReadinessDemoQuorumAlwaysSatisfiedWithoutQuery
//   - TestReadinessRazorpayIsLiveQueryNotCached
//   - TestReadinessModeFieldReflectsProfile
//   - TestReadinessMatchesOASDemoReadyExample
//
// [REF: OAS ReadinessResponse, IC §3.4, FR-053, FR-054, ADR-029,
// build.md Phase 11.2 Session 11.2.1]

package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // registers the "postgres" driver used by openTestDB

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/audit"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// ── DB fixture plumbing (reused across this package's test files, mirroring
// internal/scoring's, internal/repair's, and internal/payment's pattern) ──────

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return openAndPing(t, testDSN("PGUSER", "vyomanaut_app", "PGPASSWORD"))
}

func openVerifyDB(t *testing.T) *sql.DB {
	t.Helper()
	return openAndPing(t, testDSN("PGVERIFY_USER", "postgres", "PGVERIFY_PASSWORD"))
}

func openAndPing(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("sql.Open failed, skipping live-DB test: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("live Postgres not reachable, skipping live-DB test: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testDSN(userEnvKey, userFallback, passEnvKey string) string {
	host := envOr("PGHOST", "localhost")
	port := envOr("PGPORT", "5432")
	user := envOr(userEnvKey, userFallback)
	password := os.Getenv(passEnvKey)
	dbname := envOr("PGDATABASE", "vyomanaut_test")
	sslmode := envOr("PGSSLMODE", "disable")
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── fakeSecretsManager: a minimal audit.SecretsManagerClient for this package's own tests ──

type fakeSecretsManager struct {
	secret []byte
}

func (f *fakeSecretsManager) GetSecret(_ context.Context, path string) ([]byte, error) {
	if path == secretPathForTest(1) {
		return f.secret, nil
	}
	return nil, audit.ErrSecretNotFound
}

func secretPathForTest(version int) string {
	return fmt.Sprintf("/vyomanaut/audit-secret/v%d", version)
}

// loadedClusterSecretCache returns a real *audit.ClusterSecretCache whose
// Load() has already succeeded once, so IsLoaded() reports true.
func loadedClusterSecretCache(t *testing.T) *audit.ClusterSecretCache {
	t.Helper()
	var secret [32]byte
	_, _ = rand.Read(secret[:])
	cache := audit.NewClusterSecretCache(&fakeSecretsManager{secret: secret[:]})
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("loadedClusterSecretCache: Load: %v", err)
	}
	return cache
}

// unloadedClusterSecretCache returns a cache whose Load has never
// succeeded (IsLoaded() reports false).
func unloadedClusterSecretCache() *audit.ClusterSecretCache {
	return audit.NewClusterSecretCache(&fakeSecretsManager{})
}

// ── mock ClusterMembership that records whether it was ever called ───────────

type recordingClusterMembership struct {
	called bool
}

func (m *recordingClusterMembership) HealthyCount() int {
	m.called = true
	return 3
}

// ── DB fixtures ────────────────────────────────────────────────────────────────

func randPhoneForReadiness() string {
	var suffix [5]byte
	_, _ = rand.Read(suffix[:])
	return fmt.Sprintf("+91%x", suffix[:])
}

func randPubKeyForReadiness() []byte {
	var k [32]byte
	_, _ = rand.Read(k[:])
	return k[:]
}

// seedReadinessSatisfyingProviders inserts n freshly-ASN'd, freshly-regioned
// ACTIVE providers with razorpay_cooling_until already in the past and
// razorpay_linked_account_id set — enough to push active_vetted_providers,
// distinct_asns, distinct_metro_regions, and razorpay_accounts_ready over
// config.DemoProfile's thresholds regardless of whatever already exists in
// this shared test database from other packages' earlier tests.
//
// [Fixed — F-17E-01, same fix as this file's own
// TestReadinessRazorpayIsLiveQueryNotCached] razorpay_linked_account_id
// must be set, not just razorpay_cooling_until in the past — see
// evaluateRazorpayAccountsReady's own updated doc comment for why: it now
// mirrors internal/repair/assignment.go's drawTwoActiveCandidates
// predicate exactly, which upload_test.go's insertActiveProviderWithASN
// already discovered and fixed at the test-fixture level (its own "M11
// audit remediation, Finding 5 — extended" comment) well before this
// evaluator-level fix closed the same gap in the real, HTTP-driven
// registration path (provider.go).
func seedReadinessSatisfyingProviders(t *testing.T, db *sql.DB, n int) {
	t.Helper()
	past := time.Now().UTC().Add(-time.Hour)
	unique := uuid.New().String()[:8]
	for i := 0; i < n; i++ {
		asn := fmt.Sprintf("READY-ASN-%s-%d", unique, i)
		region := fmt.Sprintf("READY-REGION-%s-%d", unique, i)
		linkedAccountID := fmt.Sprintf("mock_acct_ready_%s_%d", unique, i)
		_, err := db.Exec(`
			INSERT INTO providers (
				provider_id, phone_number, ed25519_public_key, status,
				declared_storage_gb, city, region, asn, razorpay_cooling_until,
				razorpay_linked_account_id
			) VALUES ($1,$2,$3,'ACTIVE',50,'TestCity',$4,$5,$6,$7)`,
			uuid.New(), randPhoneForReadiness(), randPubKeyForReadiness(), region, asn, past, linkedAccountID,
		)
		if err != nil {
			t.Fatalf("seedReadinessSatisfyingProviders: %v", err)
		}
	}
}

// ── Tests ──────────────────────────────────────────────────────────────────────

func TestReadinessAllSevenConditionsEvaluated(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile
	evaluator := NewReadinessEvaluator(db, profile, unloadedClusterSecretCache(), MockClusterMembership{}, StubRelayNodeCounter{}, profile.DepartureThreshold)

	resp, err := evaluator.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	names := []string{
		resp.Conditions.ActiveVettedProviders.Name,
		resp.Conditions.DistinctASNs.Name,
		resp.Conditions.DistinctMetroRegions.Name,
		resp.Conditions.MicroserviceQuorum.Name,
		resp.Conditions.RazorpayAccountsReady.Name,
		resp.Conditions.RelayNodesDeployed.Name,
		resp.Conditions.ClusterAuditSecretLoaded.Name,
	}
	want := []string{
		"active_vetted_providers", "distinct_asns", "distinct_metro_regions",
		"microservice_quorum", "razorpay_accounts_ready", "relay_nodes_deployed",
		"cluster_audit_secret_loaded",
	}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("condition[%d].Name = %q, want %q", i, n, want[i])
		}
	}
}

// TestReadinessReportsEffectiveDepartureThreshold confirms
// effective_departure_threshold_seconds (M17-E Session 17.7.1, ADR-084
// §D-4) reports EXACTLY the duration threaded into NewReadinessEvaluator's
// own effectiveDepartureThreshold parameter — never
// profile.DepartureThreshold read directly (this file deliberately does
// not read that field at all; see ReadinessEvaluator's own struct field
// doc comment on why) — proven by passing a value that deliberately
// DISAGREES with profile.DepartureThreshold and confirming the response
// reflects the passed-in value, not the profile's own compiled constant.
func TestReadinessReportsEffectiveDepartureThreshold(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile // profile.DepartureThreshold = 10 minutes

	const overrideSeconds = 90 // deliberately disagrees with the 10-minute profile constant
	evaluator := NewReadinessEvaluator(db, profile, unloadedClusterSecretCache(), MockClusterMembership{}, StubRelayNodeCounter{}, overrideSeconds*time.Second)

	resp, err := evaluator.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if resp.EffectiveDepartureThresholdSeconds != overrideSeconds {
		t.Errorf("effective_departure_threshold_seconds = %d, want %d (the value passed to NewReadinessEvaluator, not profile.DepartureThreshold's %d seconds)",
			resp.EffectiveDepartureThresholdSeconds, overrideSeconds, int64(profile.DepartureThreshold.Seconds()))
	}
}

func TestReadinessAllConditionsMetWhenAllSatisfied(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile
	seedReadinessSatisfyingProviders(t, db, profile.MinDistinctASNs) // 5 in demo; also satisfies MinActiveProviders(5), MinMetroRegions(1), MinCooledAccounts(5)

	evaluator := NewReadinessEvaluator(db, profile, loadedClusterSecretCache(t), MockClusterMembership{}, StubRelayNodeCounter{}, profile.DepartureThreshold)
	resp, err := evaluator.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !resp.AllConditionsMet {
		t.Errorf("AllConditionsMet = false, want true: %+v", resp.Conditions)
	}
}

func TestReadinessDemoQuorumAlwaysSatisfiedWithoutQuery(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile // RequireQuorum = false
	membership := &recordingClusterMembership{}
	evaluator := NewReadinessEvaluator(db, profile, unloadedClusterSecretCache(), membership, StubRelayNodeCounter{}, profile.DepartureThreshold)

	resp, err := evaluator.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if membership.called {
		t.Error("clusterMembership.HealthyCount() was called despite RequireQuorum=false — demo mode must short-circuit without querying")
	}
	if !resp.Conditions.MicroserviceQuorum.Satisfied {
		t.Error("microservice_quorum.Satisfied = false in demo mode, want true (always satisfied without a query)")
	}
	if resp.Conditions.MicroserviceQuorum.CurrentValue != 1 || resp.Conditions.MicroserviceQuorum.RequiredValue != 1 {
		t.Errorf("microservice_quorum current/required = %d/%d, want 1/1 in demo mode",
			resp.Conditions.MicroserviceQuorum.CurrentValue, resp.Conditions.MicroserviceQuorum.RequiredValue)
	}
}

func TestReadinessRazorpayIsLiveQueryNotCached(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile
	evaluator := NewReadinessEvaluator(db, profile, unloadedClusterSecretCache(), MockClusterMembership{}, StubRelayNodeCounter{}, profile.DepartureThreshold)

	resp1, err := evaluator.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate (first): %v", err)
	}
	before := resp1.Conditions.RazorpayAccountsReady.CurrentValue

	// Add one more cooled provider directly, then re-evaluate. Includes
	// razorpay_linked_account_id — F-17E-01's own fix requires it non-NULL
	// for this condition to count a provider, matching
	// drawTwoActiveCandidates' real eligibility predicate exactly.
	if _, err := verify.Exec(`
		INSERT INTO providers (provider_id, phone_number, ed25519_public_key, status, declared_storage_gb, city, region, asn, razorpay_cooling_until, razorpay_linked_account_id)
		VALUES ($1,$2,$3,'ACTIVE',50,'TestCity','TestRegion','SIM-AS1',NOW() - INTERVAL '1 hour','mock_acct_test')`,
		uuid.New(), randPhoneForReadiness(), randPubKeyForReadiness()); err != nil {
		t.Fatalf("insert additional cooled provider: %v", err)
	}

	resp2, err := evaluator.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate (second): %v", err)
	}
	after := resp2.Conditions.RazorpayAccountsReady.CurrentValue

	if after != before+1 {
		t.Errorf("razorpay_accounts_ready.CurrentValue went from %d to %d, want exactly +1 — "+
			"a cached value would not reflect the newly-cooled provider", before, after)
	}
}

func TestReadinessModeFieldReflectsProfile(t *testing.T) {
	db := openTestDB(t)
	for _, tc := range []struct {
		name    string
		profile config.NetworkProfile
		want    string
	}{
		{"demo", config.DemoProfile, "demo"},
		{"production", config.ProductionProfile, "prod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := NewReadinessEvaluator(db, tc.profile, unloadedClusterSecretCache(), MockClusterMembership{}, StubRelayNodeCounter{}, tc.profile.DepartureThreshold)
			resp, err := evaluator.Evaluate(context.Background())
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if resp.Mode != tc.want {
				t.Errorf("Mode = %q, want %q", resp.Mode, tc.want)
			}
		})
	}
}

// TestReadinessMatchesOASDemoReadyExample verifies a ReadinessResponse
// round-trips through JSON with the exact field names OAS's DemoReady
// example uses.
func TestReadinessMatchesOASDemoReadyExample(t *testing.T) {
	fixture := ReadinessResponse{
		AllConditionsMet: true,
		EvaluatedAt:      time.Now().UTC(),
		Mode:             "demo",
		Conditions: ReadinessConditions{
			ActiveVettedProviders:    ReadinessCondition{Name: "active_vetted_providers", Satisfied: true, CurrentValue: 5, RequiredValue: 5, DemoValue: intPtrForTest(5)},
			DistinctASNs:             ReadinessCondition{Name: "distinct_asns", Satisfied: true, CurrentValue: 5, RequiredValue: 5, DemoValue: intPtrForTest(5)},
			DistinctMetroRegions:     ReadinessCondition{Name: "distinct_metro_regions", Satisfied: true, CurrentValue: 1, RequiredValue: 1, DemoValue: intPtrForTest(1)},
			MicroserviceQuorum:       ReadinessCondition{Name: "microservice_quorum", Satisfied: true, CurrentValue: 1, RequiredValue: 1, DemoValue: intPtrForTest(1)},
			RazorpayAccountsReady:    ReadinessCondition{Name: "razorpay_accounts_ready", Satisfied: true, CurrentValue: 5, RequiredValue: 5, DemoValue: intPtrForTest(5)},
			RelayNodesDeployed:       ReadinessCondition{Name: "relay_nodes_deployed", Satisfied: true, CurrentValue: 0, RequiredValue: 0, DemoValue: intPtrForTest(0)},
			ClusterAuditSecretLoaded: ReadinessCondition{Name: "cluster_audit_secret_loaded", Satisfied: true, CurrentValue: 1, RequiredValue: 1, DemoValue: intPtrForTest(1)},
		},
	}

	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"all_conditions_met", "evaluated_at", "mode", "conditions"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("round-tripped JSON missing top-level key %q", key)
		}
	}
	conditions, ok := decoded["conditions"].(map[string]any)
	if !ok {
		t.Fatal("conditions is not an object")
	}
	for _, key := range []string{
		"active_vetted_providers", "distinct_asns", "distinct_metro_regions",
		"microservice_quorum", "razorpay_accounts_ready", "relay_nodes_deployed",
		"cluster_audit_secret_loaded",
	} {
		if _, ok := conditions[key]; !ok {
			t.Errorf("conditions missing key %q", key)
		}
	}

	var roundTripped ReadinessResponse
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatalf("unmarshal into ReadinessResponse: %v", err)
	}
	if roundTripped.Mode != "demo" || !roundTripped.AllConditionsMet {
		t.Errorf("round-tripped struct = %+v, want a match for the DemoReady fixture", roundTripped)
	}
}

func intPtrForTest(v int) *int {
	return &v
}

// TestReadinessDemoValueIgnoresModeString is the audit's Finding 7 (CR-01)
// regression test for readiness.go's side of the fix, mirroring
// provider_test.go's TestProviderRegisterIgnoresModeStringForASNRules and
// internal/config/guards_test.go's TestGuardRailsIgnoreModeString: proves
// demoValue keys off profile.IsDemoMode, not the profile.Mode string.
func TestReadinessDemoValueIgnoresModeString(t *testing.T) {
	db := openTestDB(t)

	t.Run("IsDemoMode=true returns a value even when Mode != \"demo\"", func(t *testing.T) {
		profile := config.DemoProfile
		profile.Mode = "staging" // synthetic: neither "demo" nor "prod"
		profile.IsDemoMode = true
		e := NewReadinessEvaluator(db, profile, nil, MockClusterMembership{}, StubRelayNodeCounter{}, profile.DepartureThreshold)

		got := e.demoValue(5)
		if got == nil || *got != 5 {
			t.Errorf("demoValue(5) = %v, want a pointer to 5 (IsDemoMode=true, Mode=%q)", got, profile.Mode)
		}
	})

	t.Run("IsDemoMode=false returns nil even when Mode != \"prod\"", func(t *testing.T) {
		profile := config.ProductionProfile
		profile.Mode = "staging" // synthetic: neither "demo" nor "prod"
		profile.IsDemoMode = false
		e := NewReadinessEvaluator(db, profile, nil, MockClusterMembership{}, StubRelayNodeCounter{}, profile.DepartureThreshold)

		got := e.demoValue(5)
		if got != nil {
			t.Errorf("demoValue(5) = %v, want nil (IsDemoMode=false, Mode=%q)", got, profile.Mode)
		}
	})
}

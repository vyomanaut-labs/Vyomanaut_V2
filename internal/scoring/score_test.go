// Package scoring is declared in doc.go.
// Unit and live-database integration tests for GetScore and
// GetScoreFromPrimary (Session 8.1.1). This file also declares the shared DB
// fixture plumbing (openTestDB/openVerifyDB/envOr/testDSN/insertTestProvider/
// insertTestAuditReceipt/refreshProviderScores) that passes_test.go (Session
// 8.2.1) and rto_test.go (Session 8.3.1) reuse rather than redeclaring,
// mirroring internal/audit's receipt_test.go fixture pattern.
//
// Session 8.4.1 (Phase 8.4, "Scoring Package Tests") later APPENDS its own
// cross-cutting tests (dual-window flag against the real view, VETTING→ACTIVE
// race guard) to the bottom of this same file — mvp.md §8.2 names
// score_test.go as the file covering those two behaviours, the same way
// audit_test.go was the single cross-cutting file mvp.md named for M7. Unlike
// audit_test.go, that name happens to collide with score.go's own natural
// X.go/X_test.go unit-test file, so rather than invent a second, unlisted
// filename, this session's own GetScore unit tests and Session 8.4.1's later
// integration tests simply accumulate in the one file mvp.md actually names —
// exactly how errors.go accumulates sentinels across sessions instead of each
// session getting its own errors file.
//
// insertTestAuditReceipt and refreshProviderScores both use the privileged
// verify connection rather than the vyomanaut_app-authenticated db, since
// internal/scoring must not import internal/audit (IC §9) — these fixtures
// write directly to audit_receipts/refresh the view rather than going through
// WriteReceiptPhase1/Phase2.
//
// Tests:
//   - TestGetScoreReturnsAllThreeWindows      all three windows populated for a fresh PASS
//   - TestGetScoreDualWindowFlagTrue           score30d - score7d > 0.20 -> DualWindowFlag true
//   - TestGetScoreDualWindowFlagFalse          similar recent/historical performance -> false
//   - TestGetScoreNotFound                     unknown providerID -> ErrProviderNotFound
//   - TestGetScoreFromPrimaryUsesGivenHandle    matches GetScore's result against the same handle
//   - TestGetScoreExposesScoresAsOf             ScoresAsOf is populated and recent
//
// [REF: IC §5.6, DM §7, ADR-008, ADR-024, FR-050, build.md Phase 8.1 Session 8.1.1]

package scoring

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // registers the "postgres" driver used by openTestDB

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// ── DB fixture plumbing (reused by passes_test.go, rto_test.go) ───────────────

// openTestDB returns a *sql.DB connected to a live Postgres instance,
// authenticated as vyomanaut_app — the same role every scoring function runs
// as in production. If no live database is reachable within a short timeout,
// the calling test is skipped.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return openAndPing(t, testDSN("PGUSER", "vyomanaut_app", "PGPASSWORD"))
}

// openVerifyDB returns a second *sql.DB, authenticated as a privileged role
// (default: the postgres superuser), used only for fixture setup (seeding
// providers/audit_receipts rows, refreshing mv_provider_scores) and
// independent verification — never passed to the functions under test.
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

// testDSN builds a connection string from PG*-style environment variables,
// matching scripts/ci/migration_check.sh's convention (PGHOST, PGPORT,
// PGDATABASE, PGSSLMODE shared; userEnvKey/passEnvKey select which
// user/password pair to read).
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

// testProviderSpec configures the subset of providers columns scoring's tests
// need to control per row. Unlike audit's ensureTestProvider (a single
// sync.Once-created shared row reused by every test), scoring's tests each
// need distinctly configured providers — different status, pass counts, RTO
// stats — so insertTestProvider creates a fresh row every call instead of
// reusing one singleton.
type testProviderSpec struct {
	status                 string // "" defaults to "VETTING"
	consecutiveAuditPasses int
	firstChunkAssignmentAt *time.Time // nil -> SQL NULL
	avgRTTMs               *float64   // nil -> SQL NULL
	varRTTMs               float64    // schema default is 0; Go zero value matches
	rtoSampleCount         int
	p95ThroughputKbps      *float64 // nil -> SQL NULL
}

// insertTestProvider inserts a throwaway providers row via db (not verify) —
// ordinary provider registration is exactly the kind of write the
// vyomanaut_app role performs in production, unlike the audit_receipts
// fixture helpers below.
func insertTestProvider(t *testing.T, db *sql.DB, spec testProviderSpec) uuid.UUID {
	t.Helper()
	status := spec.status
	if status == "" {
		status = "VETTING"
	}

	var pubKey [32]byte
	_, _ = rand.Read(pubKey[:])
	var phoneSuffix [5]byte
	_, _ = rand.Read(phoneSuffix[:])
	phone := fmt.Sprintf("+91%x", phoneSuffix[:])

	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO providers (
			provider_id, phone_number, ed25519_public_key, status,
			declared_storage_gb, city, region, asn,
			consecutive_audit_passes, first_chunk_assignment_at,
			avg_rtt_ms, var_rtt_ms, rto_sample_count, p95_throughput_kbps
		) VALUES ($1,$2,$3,$4,50,'TestCity','TestRegion','SIM-AS1',$5,$6,$7,$8,$9,$10)`,
		id, phone, pubKey[:], status,
		spec.consecutiveAuditPasses, spec.firstChunkAssignmentAt,
		spec.avgRTTMs, spec.varRTTMs, spec.rtoSampleCount, spec.p95ThroughputKbps,
	)
	if err != nil {
		t.Fatalf("insertTestProvider: %v", err)
	}
	return id
}

// insertTestAuditReceipt inserts a single terminal audit_receipts row directly
// (bypassing internal/audit, which internal/scoring must not import — IC §9)
// via the privileged verify connection, since this fixture just needs raw
// rows for mv_provider_scores to aggregate over, not audit's own two-phase
// write semantics.
//
// audit_receipts_response_consistency (DM §4.7) requires response_hash and
// provider_sig to both be non-NULL for audit_result IN ('PASS','FAIL'), and
// both NULL for 'TIMEOUT' — unlike internal/audit's WriteReceiptPhase1/
// WriteReceiptPhase2, which have no parameters for these columns (a gap
// receipt_test.go documents for that package), this fixture writes raw SQL
// directly and so simply populates well-shaped dummy values for the
// PASS/FAIL case rather than being blocked by it.
func insertTestAuditReceipt(t *testing.T, verify *sql.DB, providerID uuid.UUID, challengeTS time.Time, result string) {
	t.Helper()
	insertTestAuditReceiptFull(t, verify, providerID, challengeTS, result, false)
}

// insertTestAuditReceiptJIT is insertTestAuditReceipt with jit_flag = TRUE —
// added in the Milestone 8 corrections session alongside mv_provider_scores'
// new JIT weight-penalty logic (ARCH §20). A separate function rather than
// widening insertTestAuditReceipt's own signature, so the 12 existing call
// sites across this file that don't care about jit_flag stay untouched.
func insertTestAuditReceiptJIT(t *testing.T, verify *sql.DB, providerID uuid.UUID, challengeTS time.Time, result string) {
	t.Helper()
	insertTestAuditReceiptFull(t, verify, providerID, challengeTS, result, true)
}

func insertTestAuditReceiptFull(t *testing.T, verify *sql.DB, providerID uuid.UUID, challengeTS time.Time, result string, jitFlag bool) {
	t.Helper()
	var chunkID [32]byte
	_, _ = rand.Read(chunkID[:])
	var nonce [33]byte
	_, _ = rand.Read(nonce[:])

	var responseHash, providerSig interface{} // nil (SQL NULL) unless PASS/FAIL
	if result == "PASS" || result == "FAIL" {
		var h [32]byte
		_, _ = rand.Read(h[:])
		var s [64]byte
		_, _ = rand.Read(s[:])
		responseHash = h[:]
		providerSig = s[:]
	}

	_, err := verify.Exec(`
		INSERT INTO audit_receipts (
			chunk_id, provider_id, challenge_nonce, server_challenge_ts,
			audit_result, response_hash, provider_sig, jit_flag
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		chunkID[:], providerID, nonce[:], challengeTS, result, responseHash, providerSig, jitFlag,
	)
	if err != nil {
		t.Fatalf("insertTestAuditReceiptFull: %v", err)
	}
}

// refreshProviderScores forces mv_provider_scores to reflect whatever
// audit_receipts rows fixtures have just inserted — materialised views do not
// update automatically (DM §7: "refreshed asynchronously by the
// microservice"); every test that seeds receipts must refresh explicitly
// before calling GetScore/GetScoreFromPrimary.
func refreshProviderScores(t *testing.T, verify *sql.DB) {
	t.Helper()
	if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW CONCURRENTLY mv_provider_scores`); err != nil {
		t.Fatalf("refreshProviderScores: %v", err)
	}
}

// floatsClose reports whether a and b are within a small tolerance of each
// other — window scores are ratios of small integers computed independently
// by Postgres and by this test's own expected-value arithmetic, so exact
// float equality is not assumed.
func floatsClose(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

// ── GetScore / GetScoreFromPrimary ────────────────────────────────────────────

// TestGetScoreReturnsAllThreeWindows verifies a single recent PASS (within
// 24h, and therefore also within 7d and 30d) produces a populated,
// all-perfect score across all three windows.
func TestGetScoreReturnsAllThreeWindows(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	insertTestAuditReceipt(t, verify, providerID, time.Now().UTC().Add(-1*time.Hour), "PASS")
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !floatsClose(score.Score24h, 1.0) {
		t.Errorf("Score24h = %v, want 1.0", score.Score24h)
	}
	if !floatsClose(score.Score7d, 1.0) {
		t.Errorf("Score7d = %v, want 1.0", score.Score7d)
	}
	if !floatsClose(score.Score30d, 1.0) {
		t.Errorf("Score30d = %v, want 1.0", score.Score30d)
	}
	if !floatsClose(score.Composite, 1.0) {
		t.Errorf("Composite = %v, want 1.0", score.Composite)
	}
}

// TestGetScoreDualWindowFlagTrue seeds a provider whose 30-day history is
// mostly historical passes (8 PASS, 8-24 days ago — outside the 7-day window)
// with a recent, entirely-failing week (2 FAIL, 1-2 days ago — inside both
// windows): score_30d = 8/10 = 0.8, score_7d = 0/2 = 0.0, a 0.8 gap, well
// past the 0.20 dual-window threshold (FR-050, ADR-024 §3).
func TestGetScoreDualWindowFlagTrue(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	now := time.Now().UTC()
	for _, daysAgo := range []int{8, 12, 16, 20, 22, 23, 24, 24} {
		insertTestAuditReceipt(t, verify, providerID, now.Add(-time.Duration(daysAgo)*24*time.Hour), "PASS")
	}
	for _, daysAgo := range []int{1, 2} {
		insertTestAuditReceipt(t, verify, providerID, now.Add(-time.Duration(daysAgo)*24*time.Hour), "FAIL")
	}
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !floatsClose(score.Score30d, 0.8) {
		t.Fatalf("Score30d = %v, want 0.8 (test setup assumption)", score.Score30d)
	}
	if !floatsClose(score.Score7d, 0.0) {
		t.Fatalf("Score7d = %v, want 0.0 (test setup assumption)", score.Score7d)
	}
	if !score.DualWindowFlag {
		t.Errorf("DualWindowFlag = false, want true (score30d %v - score7d %v = %v > 0.20)",
			score.Score30d, score.Score7d, score.Score30d-score.Score7d)
	}
}

// TestGetScoreDualWindowFlagFalse seeds a provider with similar performance
// recently and historically (4 PASS + 1 FAIL in the last week, another 4
// PASS + 1 FAIL the week before that): score_7d = 4/5 = 0.8, score_30d =
// 8/10 = 0.8, a 0.0 gap — no degradation signal, DualWindowFlag must stay
// false.
func TestGetScoreDualWindowFlagFalse(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	now := time.Now().UTC()
	// Last 7 days: 4 PASS + 1 FAIL.
	for _, daysAgo := range []int{1, 2, 3, 4} {
		insertTestAuditReceipt(t, verify, providerID, now.Add(-time.Duration(daysAgo)*24*time.Hour), "PASS")
	}
	insertTestAuditReceipt(t, verify, providerID, now.Add(-5*24*time.Hour), "FAIL")
	// 8-14 days ago (within 30d, outside 7d): another 4 PASS + 1 FAIL.
	for _, daysAgo := range []int{9, 10, 11, 12} {
		insertTestAuditReceipt(t, verify, providerID, now.Add(-time.Duration(daysAgo)*24*time.Hour), "PASS")
	}
	insertTestAuditReceipt(t, verify, providerID, now.Add(-13*24*time.Hour), "FAIL")
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !floatsClose(score.Score7d, 0.8) {
		t.Fatalf("Score7d = %v, want 0.8 (test setup assumption)", score.Score7d)
	}
	if !floatsClose(score.Score30d, 0.8) {
		t.Fatalf("Score30d = %v, want 0.8 (test setup assumption)", score.Score30d)
	}
	if score.DualWindowFlag {
		t.Errorf("DualWindowFlag = true, want false (score30d %v - score7d %v = %v, not > 0.20)",
			score.Score30d, score.Score7d, score.Score30d-score.Score7d)
	}
}

// ── Milestone 8 corrections session: NULL-window handling ────────────────────

// TestGetScoreNullWindowNotTreatedAsZero is the regression test for the
// Milestone 8 corrections session's root-cause fix: a provider with real
// 30-day history but ZERO terminal results in the last 7 days (e.g. audited
// heavily a few weeks ago, then simply not re-challenged this week — no
// PASS, no FAIL, no TIMEOUT at all in that window) must NOT have that
// silence collapsed into score_7d = 0.0 for DualWindowFlag's purposes.
// Before this fix, HasScore7d did not exist and queryProviderScore fed the
// same 0.0 fallback used for Composite straight into the DualWindowFlag
// comparison — indistinguishable from "audited every day this week and
// failed every time," which would incorrectly raise a false degradation
// signal for a provider that has simply gone quiet, not gotten worse.
func TestGetScoreNullWindowNotTreatedAsZero(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	now := time.Now().UTC()
	// Real 30-day history, well above the 0.20 dual-window threshold if
	// compared against a naive score7d = 0.0 — entirely OUTSIDE the 7-day
	// window (8+ days ago), so score_7d itself has zero terminal rows to
	// aggregate over.
	for _, daysAgo := range []int{8, 10, 12, 14, 16, 18, 20, 22} {
		insertTestAuditReceipt(t, verify, providerID, now.Add(-time.Duration(daysAgo)*24*time.Hour), "PASS")
	}
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !floatsClose(score.Score30d, 1.0) {
		t.Fatalf("Score30d = %v, want 1.0 (test setup assumption)", score.Score30d)
	}
	if score.HasScore7d {
		t.Fatalf("HasScore7d = true, want false (zero terminal results in the 7-day window; test setup assumption)")
	}
	if !score.HasScore30d {
		t.Errorf("HasScore30d = false, want true (real 30-day history exists)")
	}
	if score.DualWindowFlag {
		t.Errorf("DualWindowFlag = true, want false — score_7d has NO DATA (not a real 0.0), "+
			"so it must not be compared against score_30d %v at all", score.Score30d)
	}
}

// TestGetScoreHasScoreFlagsAllPresent is the sanity-check counterpart to
// TestGetScoreNullWindowNotTreatedAsZero: when a provider DOES have real
// terminal results in all three windows, all three Has* flags must be true
// (the fix must not make a genuinely-present window look absent).
func TestGetScoreHasScoreFlagsAllPresent(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	insertTestAuditReceipt(t, verify, providerID, time.Now().UTC().Add(-1*time.Hour), "PASS")
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !score.HasScore24h || !score.HasScore7d || !score.HasScore30d {
		t.Errorf("HasScore24h=%v HasScore7d=%v HasScore30d=%v, want all true (one recent PASS falls inside all three windows)",
			score.HasScore24h, score.HasScore7d, score.HasScore30d)
	}
}

// ── Milestone 8 corrections session: JIT weight penalty (ARCH §20) ───────────

// TestJITPenaltyAppliesToScore24hOnly verifies ARCH §20's "3+ JIT flags in a
// rolling 7-day window -> 0.5x weight penalty on the 24h scoring window"
// rule, and specifically that 7d/30d are UNAFFECTED — ARCH §20 names the
// 24h window only.
func TestJITPenaltyAppliesToScore24hOnly(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	now := time.Now().UTC()
	// Exactly 3 JIT-flagged PASS receipts, all within the last 3 hours (well
	// within both the 24h window and a qualifying 7-day span of each other).
	for _, hoursAgo := range []int{1, 2, 3} {
		insertTestAuditReceiptJIT(t, verify, providerID, now.Add(-time.Duration(hoursAgo)*time.Hour), "PASS")
	}
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	// pass_24h=3, total_24h=3 -> (3*0.5)/3 = 0.5, not 1.0.
	if !floatsClose(score.Score24h, 0.5) {
		t.Errorf("Score24h = %v, want 0.5 (3 PASS, all JIT-flagged, weighted 0.5x)", score.Score24h)
	}
	if !floatsClose(score.Score7d, 1.0) {
		t.Errorf("Score7d = %v, want 1.0 — the JIT penalty must not touch the 7d window", score.Score7d)
	}
	if !floatsClose(score.Score30d, 1.0) {
		t.Errorf("Score30d = %v, want 1.0 — the JIT penalty must not touch the 30d window", score.Score30d)
	}
}

// TestJITPenaltyBelowThresholdNoEffect verifies exactly 2 JIT flags (one
// short of ARCH §20's 3-flag trigger) has NO weighting effect at all —
// confirming the boundary is >= 3, not >= 2 or "any."
func TestJITPenaltyBelowThresholdNoEffect(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	now := time.Now().UTC()
	insertTestAuditReceiptJIT(t, verify, providerID, now.Add(-1*time.Hour), "PASS")
	insertTestAuditReceiptJIT(t, verify, providerID, now.Add(-2*time.Hour), "PASS")
	insertTestAuditReceipt(t, verify, providerID, now.Add(-3*time.Hour), "PASS") // not JIT-flagged
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !floatsClose(score.Score24h, 1.0) {
		t.Errorf("Score24h = %v, want 1.0 — only 2 JIT flags, below the 3-flag ARCH §20 threshold", score.Score24h)
	}
}

// TestJITPenaltyPersistsWithin30Days verifies the "stateless equivalent
// framing" this session's mv_provider_scores change relies on: 3 JIT flags
// clustered together 10 days ago (well outside the 7-day window as measured
// from NOW, but the qualifying window is evaluated as of THOSE receipts' own
// timestamps, per the view's jit_penalized CTE) must still apply the penalty
// today, since ARCH §20's 30-day penalty period has not yet elapsed.
func TestJITPenaltyPersistsWithin30Days(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	now := time.Now().UTC()
	// 3 JIT-flagged receipts clustered within a few hours of each other,
	// 10 days ago -- a qualifying 7-day window at THAT point in time.
	for _, hoursAgo := range []int{240, 241, 242} { // ~10 days ago, +/- 2h
		insertTestAuditReceiptJIT(t, verify, providerID, now.Add(-time.Duration(hoursAgo)*time.Hour), "PASS")
	}
	// A separate, recent, non-JIT PASS to actually populate the 24h window.
	insertTestAuditReceipt(t, verify, providerID, now.Add(-1*time.Hour), "PASS")
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	// pass_24h=1 (the recent one), weighted 0.5x since the provider is still
	// under the 30-day penalty from the cluster 10 days ago -> 0.5/1 = 0.5.
	if !floatsClose(score.Score24h, 0.5) {
		t.Errorf("Score24h = %v, want 0.5 — the 30-day penalty from the cluster 10 days ago is still active", score.Score24h)
	}
}

// TestJITPenaltyExpiresAfter30Days verifies the mirror image: 3 JIT flags
// clustered 35 days ago — outside ARCH §20's 30-day penalty period — must
// NOT apply any weighting today.
func TestJITPenaltyExpiresAfter30Days(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	now := time.Now().UTC()
	for _, hoursAgo := range []int{840, 841, 842} { // ~35 days ago, +/- 2h
		insertTestAuditReceiptJIT(t, verify, providerID, now.Add(-time.Duration(hoursAgo)*time.Hour), "PASS")
	}
	insertTestAuditReceipt(t, verify, providerID, now.Add(-1*time.Hour), "PASS")
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !floatsClose(score.Score24h, 1.0) {
		t.Errorf("Score24h = %v, want 1.0 — the JIT cluster is 35 days old, past ARCH §20's 30-day penalty period", score.Score24h)
	}
}

// TestGetScoreNotFound verifies a providerID with zero audit history (no row
// in mv_provider_scores) returns ErrProviderNotFound.
func TestGetScoreNotFound(t *testing.T) {
	db := openTestDB(t)
	unknownProviderID := uuid.New() // never inserted anywhere

	_, err := GetScore(context.Background(), db, unknownProviderID)
	if !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("GetScore(unknown providerID): got %v, want ErrProviderNotFound", err)
	}
}

// TestGetScoreFromPrimaryUsesGivenHandle verifies GetScoreFromPrimary queries
// whatever *sql.DB handle it is given — in this test environment there is
// only one database, so GetScore(db, id) and GetScoreFromPrimary(db, id) must
// agree exactly on every score field. ScoresAsOf is deliberately excluded
// from the comparison: it is NOW() evaluated independently by each of the two
// separate queries below, so the two calls' timestamps may legitimately
// differ by a few microseconds even though every other field must match.
func TestGetScoreFromPrimaryUsesGivenHandle(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	insertTestAuditReceipt(t, verify, providerID, time.Now().UTC().Add(-1*time.Hour), "PASS")
	refreshProviderScores(t, verify)

	viaGetScore, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	viaPrimary, err := GetScoreFromPrimary(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScoreFromPrimary: %v", err)
	}

	if !floatsClose(viaGetScore.Score24h, viaPrimary.Score24h) ||
		!floatsClose(viaGetScore.Score7d, viaPrimary.Score7d) ||
		!floatsClose(viaGetScore.Score30d, viaPrimary.Score30d) ||
		!floatsClose(viaGetScore.Composite, viaPrimary.Composite) ||
		viaGetScore.DualWindowFlag != viaPrimary.DualWindowFlag {
		t.Errorf("GetScoreFromPrimary(db) = %+v, want matching score fields to GetScore(db) = %+v",
			viaPrimary, viaGetScore)
	}
}

// TestGetScoreExposesScoresAsOf verifies ScoresAsOf is populated from the
// view's own NOW()-at-refresh-time column and reflects roughly the current
// time, not a zero value.
func TestGetScoreExposesScoresAsOf(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	insertTestAuditReceipt(t, verify, providerID, time.Now().UTC().Add(-1*time.Hour), "PASS")

	before := time.Now().UTC()
	refreshProviderScores(t, verify)
	score, err := GetScore(context.Background(), db, providerID)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}

	if score.ScoresAsOf.IsZero() {
		t.Fatal("ScoresAsOf is zero, want a populated timestamp from mv_provider_scores.scores_as_of")
	}
	if score.ScoresAsOf.Before(before.Add(-time.Second)) || score.ScoresAsOf.After(after.Add(time.Second)) {
		t.Errorf("ScoresAsOf = %v, want within [%v, %v] (the refresh's own NOW())", score.ScoresAsOf, before, after)
	}
}

// ── Phase 8.4 cross-cutting tests (Session 8.4.1) ─────────────────────────────
//
// mvp.md §8.2 names this file for two behaviours specifically — the
// dual-window flag exercised against the real materialised view, and the
// VETTING→ACTIVE race guard — at the integration level, spanning score.go +
// passes.go + rto.go together rather than re-running each file's own unit
// tests. TestDemoAndProductionProfilesBothReachActive is grouped alongside
// them per build.md Phase 8.4 Session 8.4.1's own test table.

// TestDualWindowFlagAgainstRealView seeds audit_receipts so the 7-day pass
// rate is deliberately worse than the 30-day rate by more than 0.20 (6 PASS
// 10-20 days ago, only within the 30-day window; 3 FAIL in the last 3 days,
// within both windows: score_30d = 6/9 ≈ 0.667, score_7d = 0/3 = 0.0), then
// refreshes mv_provider_scores and confirms GetScore reports
// DualWindowFlag == true — exercising the real materialised view end to end,
// not a mocked ProviderScore struct.
func TestDualWindowFlagAgainstRealView(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})

	now := time.Now().UTC()
	for _, daysAgo := range []int{10, 13, 15, 17, 19, 20} {
		insertTestAuditReceipt(t, verify, providerID, now.Add(-time.Duration(daysAgo)*24*time.Hour), "PASS")
	}
	for _, daysAgo := range []int{1, 2, 3} {
		insertTestAuditReceipt(t, verify, providerID, now.Add(-time.Duration(daysAgo)*24*time.Hour), "FAIL")
	}
	refreshProviderScores(t, verify)

	score, err := GetScore(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !floatsClose(score.Score30d, 6.0/9.0) {
		t.Fatalf("Score30d = %v, want %v (test setup assumption)", score.Score30d, 6.0/9.0)
	}
	if !floatsClose(score.Score7d, 0.0) {
		t.Fatalf("Score7d = %v, want 0.0 (test setup assumption)", score.Score7d)
	}
	if !score.DualWindowFlag {
		t.Errorf("DualWindowFlag = false, want true against the real mv_provider_scores view (score30d %v - score7d %v = %v > 0.20)",
			score.Score30d, score.Score7d, score.Score30d-score.Score7d)
	}
}

// TestVettingActiveTransitionRaceGuard seeds a provider at exactly
// profile.VettingMinPasses-1 remaining passes, then launches n concurrent
// IncrementConsecutivePasses calls all racing for the SAME final increment
// (Phase 1). The SELECT ... FOR UPDATE lock must resolve this race so exactly
// one call wins (transitions the provider to ACTIVE) and every other call
// observes the already-ACTIVE row and returns ErrProviderNotVetting — no
// double-transition, no lost update. Phase 2 goes further: once ACTIVE, a
// second concurrent batch of m calls must ALL be rejected uniformly, with the
// pass counter left completely unchanged, proving the post-transition no-op
// is itself race-safe rather than merely correct on the very first call.
func TestVettingActiveTransitionRaceGuard(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)

	profile := config.DemoProfile // fast VettingMinDuration keeps this test quick
	past := time.Now().UTC().Add(-2 * profile.VettingMinDuration)
	providerID := insertTestProvider(t, db, testProviderSpec{status: "VETTING", consecutiveAuditPasses: profile.VettingMinPasses - 1, firstChunkAssignmentAt: &past})

	const n, m = 10, 5
	errs, errs2 := make([]error, n), make([]error, m)
	var wg, wg2 sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			errs[i] = IncrementConsecutivePasses(context.Background(), db, providerID, profile)
		}()
	}
	wg.Wait()
	wg2.Add(m)
	for i := 0; i < m; i++ {
		i := i
		go func() {
			defer wg2.Done()
			errs2[i] = IncrementConsecutivePasses(context.Background(), db, providerID, profile)
		}()
	}
	wg2.Wait()

	// Phase 1 assertions: exactly one winner among n racers for the final increment.
	var succeeded, rejected int
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrProviderNotVetting):
			rejected++
		default:
			t.Errorf("phase 1: unexpected error racing for the final increment: %v", err)
		}
	}
	if succeeded != 1 {
		t.Errorf("phase 1: succeeded = %d, want exactly 1 (no double-transition, no lost update)", succeeded)
	}
	if rejected != n-1 {
		t.Errorf("phase 1: rejected (ErrProviderNotVetting) = %d, want %d", rejected, n-1)
	}

	var status string
	var passes int
	if err := verify.QueryRow(`SELECT status, consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).
		Scan(&status, &passes); err != nil {
		t.Fatalf("query state after phase 1: %v", err)
	}
	if status != "ACTIVE" {
		t.Fatalf("status after phase 1 = %q, want ACTIVE", status)
	}
	if passes != profile.VettingMinPasses {
		t.Fatalf("consecutive_audit_passes after phase 1 = %d, want %d", passes, profile.VettingMinPasses)
	}

	// Phase 2 assertions: every post-transition racer is rejected, uniformly.
	for i, err := range errs2 {
		if !errors.Is(err, ErrProviderNotVetting) {
			t.Errorf("phase 2: call %d: got %v, want ErrProviderNotVetting", i, err)
		}
	}

	var finalPasses int
	if err := verify.QueryRow(`SELECT consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).
		Scan(&finalPasses); err != nil {
		t.Fatalf("query final state after phase 2: %v", err)
	}
	if finalPasses != profile.VettingMinPasses {
		t.Errorf("consecutive_audit_passes after phase 2 = %d, want unchanged at %d", finalPasses, profile.VettingMinPasses)
	}
}

// TestDemoAndProductionProfilesBothReachActive runs the full pass sequence —
// every call from 0 through the threshold, not a seeded shortcut — once with
// config.DemoProfile (expect transition at 5 passes) and once with
// config.ProductionProfile (expect transition at 80 passes), against two
// separate providers in the same schema, confirming the profile parameter —
// not a hardcoded literal — drives the outcome in both directions.
func TestDemoAndProductionProfilesBothReachActive(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)

	t.Run("demo", func(t *testing.T) {
		runFullVettingSequence(t, db, verify, config.DemoProfile)
	})
	t.Run("production", func(t *testing.T) {
		runFullVettingSequence(t, db, verify, config.ProductionProfile)
	})
}

// runFullVettingSequence drives IncrementConsecutivePasses from 0 all the way
// to profile.VettingMinPasses, one call at a time, and asserts the provider
// lands on ACTIVE with exactly that many recorded passes. Shared by both
// subtests of TestDemoAndProductionProfilesBothReachActive above.
func runFullVettingSequence(t *testing.T, db *sql.DB, verify *sql.DB, profile config.NetworkProfile) {
	t.Helper()
	past := time.Now().UTC().Add(-2 * profile.VettingMinDuration)
	providerID := insertTestProvider(t, db, testProviderSpec{
		status:                 "VETTING",
		consecutiveAuditPasses: 0,
		firstChunkAssignmentAt: &past,
	})

	for i := 0; i < profile.VettingMinPasses; i++ {
		if err := IncrementConsecutivePasses(context.Background(), db, providerID, profile); err != nil {
			t.Fatalf("IncrementConsecutivePasses call %d/%d: %v", i+1, profile.VettingMinPasses, err)
		}
	}

	var status string
	var passes int
	if err := verify.QueryRow(`SELECT status, consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).
		Scan(&status, &passes); err != nil {
		t.Fatalf("query final state: %v", err)
	}
	if passes != profile.VettingMinPasses {
		t.Errorf("consecutive_audit_passes = %d, want %d", passes, profile.VettingMinPasses)
	}
	if status != "ACTIVE" {
		t.Errorf("status = %q, want ACTIVE after %d full passes", status, profile.VettingMinPasses)
	}
}

// TestProviderScoreBasisPoints verifies the scale-and-round conversion added
// for internal/payment (build.md Milestone 10) — a pure unit test, no
// database needed.
func TestProviderScoreBasisPoints(t *testing.T) {
	for _, tc := range []struct {
		name   string
		score  ProviderScore
		want30 int64
		want7  int64
	}{
		{"exact", ProviderScore{Score30d: 0.95, Score7d: 0.80}, 9500, 8000},
		{"rounds up", ProviderScore{Score30d: 0.94999, Score7d: 0.65001}, 9500, 6500},
		{"zero", ProviderScore{Score30d: 0, Score7d: 0}, 0, 0},
		{"one", ProviderScore{Score30d: 1.0, Score7d: 1.0}, 10000, 10000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.score.Score30dBasisPoints(); got != tc.want30 {
				t.Errorf("Score30dBasisPoints() = %d, want %d", got, tc.want30)
			}
			if got := tc.score.Score7dBasisPoints(); got != tc.want7 {
				t.Errorf("Score7dBasisPoints() = %d, want %d", got, tc.want7)
			}
		})
	}
}

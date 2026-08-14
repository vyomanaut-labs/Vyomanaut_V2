// Package scoring is declared in doc.go.
// Unit and live-database integration tests for IncrementConsecutivePasses and
// ResetConsecutivePasses (Session 8.2.1). Reuses the DB fixture plumbing
// (openTestDB/openVerifyDB/insertTestProvider/testProviderSpec) declared in
// score_test.go rather than redeclaring it.
//
// Tests:
//   - TestIncrementConsecutivePassesUsesDemoProfile         config.DemoProfile transitions at 5, not 80
//   - TestIncrementConsecutivePassesUsesProductionProfile    config.ProductionProfile does not transition before 80
//   - TestIncrementConsecutivePassesRequiresDurationToo       pass threshold met, duration not elapsed -> stays VETTING
//   - TestIncrementConsecutivePassesRejectsNonVettingProvider status=ACTIVE -> ErrProviderNotVetting, no-op
//   - TestIncrementConsecutivePassesConcurrentSafe             N goroutines -> exactly one ACTIVE transition, race-clean
//   - TestResetConsecutivePassesZeroesCounter                  any non-PASS -> counter back to 0
//
// [REF: IC §5.6, DM §4.2, FR-026, MVP §3.4, MVP §5.4, ADR-005, build.md Phase 8.2 Session 8.2.1]

package scoring

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// TestIncrementConsecutivePassesUsesDemoProfile verifies the VETTING->ACTIVE
// transition fires at config.DemoProfile.VettingMinPasses (5), not the
// production value of 80.
func TestIncrementConsecutivePassesUsesDemoProfile(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)

	past := time.Now().UTC().Add(-2 * config.DemoProfile.VettingMinDuration) // duration condition comfortably satisfied
	providerID := insertTestProvider(t, db, testProviderSpec{
		status:                 "VETTING",
		consecutiveAuditPasses: config.DemoProfile.VettingMinPasses - 1,
		firstChunkAssignmentAt: &past,
	})

	if err := IncrementConsecutivePasses(context.Background(), db, providerID, config.DemoProfile); err != nil {
		t.Fatalf("IncrementConsecutivePasses: %v", err)
	}

	var status string
	var passes int
	if err := verify.QueryRow(`SELECT status, consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).
		Scan(&status, &passes); err != nil {
		t.Fatalf("query final state: %v", err)
	}
	if passes != config.DemoProfile.VettingMinPasses {
		t.Errorf("consecutive_audit_passes = %d, want %d", passes, config.DemoProfile.VettingMinPasses)
	}
	if status != "ACTIVE" {
		t.Errorf("status = %q, want ACTIVE (demo profile requires only %d passes)", status, config.DemoProfile.VettingMinPasses)
	}
}

// TestIncrementConsecutivePassesUsesProductionProfile verifies the same
// function, given config.ProductionProfile, does NOT transition before 80
// passes — seeded two shy of the threshold, one increment lands at 79, which
// must stay VETTING.
func TestIncrementConsecutivePassesUsesProductionProfile(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)

	past := time.Now().UTC().Add(-2 * config.ProductionProfile.VettingMinDuration) // duration comfortably satisfied
	providerID := insertTestProvider(t, db, testProviderSpec{
		status:                 "VETTING",
		consecutiveAuditPasses: config.ProductionProfile.VettingMinPasses - 2,
		firstChunkAssignmentAt: &past,
	})

	if err := IncrementConsecutivePasses(context.Background(), db, providerID, config.ProductionProfile); err != nil {
		t.Fatalf("IncrementConsecutivePasses: %v", err)
	}

	var status string
	var passes int
	if err := verify.QueryRow(`SELECT status, consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).
		Scan(&status, &passes); err != nil {
		t.Fatalf("query final state: %v", err)
	}
	wantPasses := config.ProductionProfile.VettingMinPasses - 1
	if passes != wantPasses {
		t.Errorf("consecutive_audit_passes = %d, want %d", passes, wantPasses)
	}
	if status != "VETTING" {
		t.Errorf("status = %q, want VETTING (only %d of %d production passes recorded)",
			status, passes, config.ProductionProfile.VettingMinPasses)
	}
}

// TestIncrementConsecutivePassesRequiresDurationToo verifies that meeting
// VettingMinPasses alone is not sufficient — first_chunk_assignment_at set to
// "just now" means the VettingMinDuration condition (FR-026) has not elapsed,
// so the provider must stay VETTING even though the pass count reaches the
// threshold.
func TestIncrementConsecutivePassesRequiresDurationToo(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)

	justNow := time.Now().UTC()
	providerID := insertTestProvider(t, db, testProviderSpec{
		status:                 "VETTING",
		consecutiveAuditPasses: config.DemoProfile.VettingMinPasses - 1,
		firstChunkAssignmentAt: &justNow,
	})

	if err := IncrementConsecutivePasses(context.Background(), db, providerID, config.DemoProfile); err != nil {
		t.Fatalf("IncrementConsecutivePasses: %v", err)
	}

	var status string
	var passes int
	if err := verify.QueryRow(`SELECT status, consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).
		Scan(&status, &passes); err != nil {
		t.Fatalf("query final state: %v", err)
	}
	if passes != config.DemoProfile.VettingMinPasses {
		t.Errorf("consecutive_audit_passes = %d, want %d (the pass count itself must still increment)",
			passes, config.DemoProfile.VettingMinPasses)
	}
	if status != "VETTING" {
		t.Errorf("status = %q, want VETTING — pass threshold met but VettingMinDuration (%v) has not elapsed since first_chunk_assignment_at",
			status, config.DemoProfile.VettingMinDuration)
	}
}

// TestIncrementConsecutivePassesRejectsNonVettingProvider verifies a provider
// already past VETTING (status = ACTIVE) is rejected with ErrProviderNotVetting
// and left completely unmodified.
func TestIncrementConsecutivePassesRejectsNonVettingProvider(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)

	providerID := insertTestProvider(t, db, testProviderSpec{
		status:                 "ACTIVE",
		consecutiveAuditPasses: 10,
	})

	err := IncrementConsecutivePasses(context.Background(), db, providerID, config.DemoProfile)
	if !errors.Is(err, ErrProviderNotVetting) {
		t.Fatalf("IncrementConsecutivePasses(ACTIVE provider): got %v, want ErrProviderNotVetting", err)
	}

	var passes int
	if err := verify.QueryRow(`SELECT consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).
		Scan(&passes); err != nil {
		t.Fatalf("query: %v", err)
	}
	if passes != 10 {
		t.Errorf("consecutive_audit_passes = %d, want unchanged at 10 (rejection must be a true no-op)", passes)
	}
}

// TestIncrementConsecutivePassesConcurrentSafe launches config.DemoProfile.
// VettingMinPasses+5 goroutines concurrently against the same freshly-VETTING
// provider (starting at 0 passes, duration already satisfied). Without the
// SELECT ... FOR UPDATE row lock, concurrent transactions could all read the
// same pre-increment count and produce a lost update; with it, exactly
// VettingMinPasses of the N calls must succeed (reaching the threshold once,
// transitioning to ACTIVE), and the remainder must observe the already-ACTIVE
// row and return ErrProviderNotVetting.
func TestIncrementConsecutivePassesConcurrentSafe(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)

	past := time.Now().UTC().Add(-2 * config.DemoProfile.VettingMinDuration)
	providerID := insertTestProvider(t, db, testProviderSpec{
		status:                 "VETTING",
		consecutiveAuditPasses: 0,
		firstChunkAssignmentAt: &past,
	})

	n := config.DemoProfile.VettingMinPasses + 5
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			errs[i] = IncrementConsecutivePasses(context.Background(), db, providerID, config.DemoProfile)
		}()
	}
	wg.Wait()

	var succeeded, rejected int
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrProviderNotVetting):
			rejected++
		default:
			t.Errorf("unexpected error from concurrent IncrementConsecutivePasses: %v", err)
		}
	}
	if succeeded != config.DemoProfile.VettingMinPasses {
		t.Errorf("succeeded = %d, want exactly %d — a mismatch means either a lost update or a redundant transition",
			succeeded, config.DemoProfile.VettingMinPasses)
	}
	if rejected != n-config.DemoProfile.VettingMinPasses {
		t.Errorf("rejected (ErrProviderNotVetting) = %d, want %d", rejected, n-config.DemoProfile.VettingMinPasses)
	}

	var finalStatus string
	var finalPasses int
	if err := verify.QueryRow(`SELECT status, consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).
		Scan(&finalStatus, &finalPasses); err != nil {
		t.Fatalf("query final state: %v", err)
	}
	if finalStatus != "ACTIVE" {
		t.Errorf("final status = %q, want ACTIVE", finalStatus)
	}
	if finalPasses != config.DemoProfile.VettingMinPasses {
		t.Errorf("final consecutive_audit_passes = %d, want exactly %d (no lost updates)",
			finalPasses, config.DemoProfile.VettingMinPasses)
	}
}

// TestResetConsecutivePassesZeroesCounter verifies any call unconditionally
// resets the counter to 0 (ADR-005 — a FAIL or TIMEOUT resets vetting
// progress regardless of how many consecutive passes preceded it).
func TestResetConsecutivePassesZeroesCounter(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)

	providerID := insertTestProvider(t, db, testProviderSpec{
		status:                 "VETTING",
		consecutiveAuditPasses: 42,
	})

	if err := ResetConsecutivePasses(context.Background(), db, providerID); err != nil {
		t.Fatalf("ResetConsecutivePasses: %v", err)
	}

	var passes int
	if err := verify.QueryRow(`SELECT consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).
		Scan(&passes); err != nil {
		t.Fatalf("query: %v", err)
	}
	if passes != 0 {
		t.Errorf("consecutive_audit_passes = %d, want 0", passes)
	}
}

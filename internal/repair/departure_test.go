// Package repair is declared in doc.go.
// Unit and live-database integration tests for the departure detector.
//
// Tests:
//   - TestDepartureDetectorCatchesActiveProviders
//   - TestDepartureDetectorCatchesVettingProviders
//   - TestDepartureDetectorIgnoresRecentHeartbeats
//   - TestDepartureDetectorNeverPhysicallyDeletesRow
//   - TestDepartureDetectorCallsPenaliseWithSeizureIdempotencyKey
//
// [REF: IC §3.1, IC §6, DM §3 Invariant 3, FR-035, FR-065, ARCH §12,
// build.md Phase 9.3 Session 9.3.1]

package repair

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
)

// penaliseCall records one invocation of a recordingPenalise mock.
type penaliseCall struct {
	providerID     uuid.UUID
	amountPaise    int64
	idempotencyKey string
}

// recordingPenalise returns a PenaliseFunc that appends every call to calls
// and always succeeds — DetectOnce in these tests runs candidates
// sequentially (no concurrency), so no locking is needed around the slice.
func recordingPenalise(calls *[]penaliseCall) PenaliseFunc {
	return func(ctx context.Context, providerID uuid.UUID, amountPaise int64, idempotencyKey string) error {
		*calls = append(*calls, penaliseCall{providerID, amountPaise, idempotencyKey})
		return nil
	}
}

func staleHeartbeat(profile config.NetworkProfile) *time.Time {
	t := time.Now().UTC().Add(-2 * profile.DepartureThreshold)
	return &t
}

func freshHeartbeat() *time.Time {
	t := time.Now().UTC()
	return &t
}

func TestDepartureDetectorCatchesActiveProviders(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile

	providerID := insertTestProvider(t, db, testProviderSpec{status: "ACTIVE", lastHeartbeatTs: staleHeartbeat(profile)})
	segmentID := insertTestSegmentChain(t, db)
	shardIndex := 0
	chunkID := randChunkID()
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:    chunkID,
		segmentID:  &segmentID,
		shardIndex: &shardIndex,
		providerID: providerID,
		status:     "ACTIVE",
	})
	// [M10 corrections review Finding #3] penalise is only invoked when
	// sealedBalance > 0 (see processDeparture) — seed a real DEPOSIT so this
	// test's own "penalise was called" assertion below stays meaningful
	// under the corrected, guarded behavior rather than exercising the
	// (now-skipped) zero-balance path. TestDepartureDetectorSkipsPenaliseForZeroBalance
	// covers the zero-balance case directly.
	if _, err := verify.Exec(`
		INSERT INTO escrow_events (provider_id, event_type, amount_paise, idempotency_key)
		VALUES ($1, 'DEPOSIT', $2, $3)`,
		providerID, 25000, uuid.New().String()); err != nil {
		t.Fatalf("seed DEPOSIT: %v", err)
	}

	var calls []penaliseCall
	detector := NewDepartureDetector(db, profile, recordingPenalise(&calls))
	if err := detector.DetectOnce(context.Background()); err != nil {
		t.Fatalf("DetectOnce: %v", err)
	}

	var status string
	var frozen bool
	var departedAt sql.NullTime
	if err := verify.QueryRow(`SELECT status, frozen, departed_at FROM providers WHERE provider_id = $1`, providerID).
		Scan(&status, &frozen, &departedAt); err != nil {
		t.Fatalf("query provider: %v", err)
	}
	if status != "DEPARTED" {
		t.Errorf("status = %q, want DEPARTED", status)
	}
	if !frozen {
		t.Error("frozen = false, want true")
	}
	if !departedAt.Valid {
		t.Error("departed_at is NULL, want set")
	}

	var jobCount int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM repair_jobs WHERE chunk_id = $1 AND trigger_type = 'SILENT_DEPARTURE'`,
		chunkID[:]).Scan(&jobCount); err != nil {
		t.Fatalf("count repair_jobs: %v", err)
	}
	if jobCount != 1 {
		t.Errorf("repair_jobs rows for this chunk with trigger SILENT_DEPARTURE = %d, want 1", jobCount)
	}

	found := false
	for _, c := range calls {
		if c.providerID == providerID {
			found = true
		}
	}
	if !found {
		t.Error("penalise was not called for the departed ACTIVE provider")
	}
}

func TestDepartureDetectorCatchesVettingProviders(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile

	providerID := insertTestProvider(t, db, testProviderSpec{status: "VETTING", lastHeartbeatTs: staleHeartbeat(profile)})
	chunkID := randChunkID()
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:        chunkID,
		isVettingChunk: true,
		providerID:     providerID,
		status:         "ACTIVE",
	})
	// [M10 corrections review Finding #3] penalise is only invoked when
	// sealedBalance > 0 (see processDeparture) — seed a real DEPOSIT so this
	// test's own "penalise was called" assertion below stays meaningful
	// under the corrected, guarded behavior. A VETTING provider's chunks are
	// synthetic, but its escrow ledger is not.
	if _, err := verify.Exec(`
		INSERT INTO escrow_events (provider_id, event_type, amount_paise, idempotency_key)
		VALUES ($1, 'DEPOSIT', $2, $3)`,
		providerID, 25000, uuid.New().String()); err != nil {
		t.Fatalf("seed DEPOSIT: %v", err)
	}

	var calls []penaliseCall
	detector := NewDepartureDetector(db, profile, recordingPenalise(&calls))
	if err := detector.DetectOnce(context.Background()); err != nil {
		t.Fatalf("DetectOnce: %v", err)
	}

	var status string
	if err := verify.QueryRow(`SELECT status FROM providers WHERE provider_id = $1`, providerID).Scan(&status); err != nil {
		t.Fatalf("query provider: %v", err)
	}
	if status != "DEPARTED" {
		t.Errorf("provider status = %q, want DEPARTED", status)
	}

	var assignmentStatus string
	var deletedAt sql.NullTime
	if err := verify.QueryRow(`SELECT status, deleted_at FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], providerID).Scan(&assignmentStatus, &deletedAt); err != nil {
		t.Fatalf("query chunk_assignments: %v", err)
	}
	if assignmentStatus != "DELETED" {
		t.Errorf("chunk_assignments.status = %q, want DELETED", assignmentStatus)
	}
	if !deletedAt.Valid {
		t.Error("deleted_at is NULL, want set")
	}

	var jobCount int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM repair_jobs WHERE chunk_id = $1`, chunkID[:]).Scan(&jobCount); err != nil {
		t.Fatalf("count repair_jobs: %v", err)
	}
	if jobCount != 0 {
		t.Errorf("repair_jobs rows for this vetting chunk = %d, want 0 (FR-065: zero repair jobs for a vetting departure)", jobCount)
	}

	found := false
	for _, c := range calls {
		if c.providerID == providerID {
			found = true
		}
	}
	if !found {
		t.Error("penalise was not called for the departed VETTING provider (escrow seizure still applies)")
	}
}

func TestDepartureDetectorIgnoresRecentHeartbeats(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile

	providerID := insertTestProvider(t, db, testProviderSpec{status: "ACTIVE", lastHeartbeatTs: freshHeartbeat()})

	var calls []penaliseCall
	detector := NewDepartureDetector(db, profile, recordingPenalise(&calls))
	if err := detector.DetectOnce(context.Background()); err != nil {
		t.Fatalf("DetectOnce: %v", err)
	}

	var status string
	if err := verify.QueryRow(`SELECT status FROM providers WHERE provider_id = $1`, providerID).Scan(&status); err != nil {
		t.Fatalf("query provider: %v", err)
	}
	if status != "ACTIVE" {
		t.Errorf("status = %q, want unchanged ACTIVE (heartbeat is recent)", status)
	}

	for _, c := range calls {
		if c.providerID == providerID {
			t.Error("penalise was called for a provider with a recent heartbeat")
		}
	}
}

func TestDepartureDetectorNeverPhysicallyDeletesRow(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile

	insertTestProvider(t, db, testProviderSpec{status: "ACTIVE", lastHeartbeatTs: staleHeartbeat(profile)})
	insertTestProvider(t, db, testProviderSpec{status: "VETTING", lastHeartbeatTs: staleHeartbeat(profile)})

	var before int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM providers`).Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}

	var calls []penaliseCall
	detector := NewDepartureDetector(db, profile, recordingPenalise(&calls))
	if err := detector.DetectOnce(context.Background()); err != nil {
		t.Fatalf("DetectOnce: %v", err)
	}

	var after int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM providers`).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != before {
		t.Errorf("providers row count changed from %d to %d, want unchanged (DM §3 Invariant 3: never physically deleted)",
			before, after)
	}
}

func TestDepartureDetectorCallsPenaliseWithSeizureIdempotencyKey(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile

	providerID := insertTestProvider(t, db, testProviderSpec{status: "ACTIVE", lastHeartbeatTs: staleHeartbeat(profile)})

	const depositPaise = 50000
	if _, err := verify.Exec(`
		INSERT INTO escrow_events (provider_id, event_type, amount_paise, idempotency_key)
		VALUES ($1, 'DEPOSIT', $2, $3)`,
		providerID, depositPaise, uuid.New().String()); err != nil {
		t.Fatalf("seed escrow_events: %v", err)
	}

	var calls []penaliseCall
	detector := NewDepartureDetector(db, profile, recordingPenalise(&calls))
	if err := detector.DetectOnce(context.Background()); err != nil {
		t.Fatalf("DetectOnce: %v", err)
	}

	var call *penaliseCall
	for i := range calls {
		if calls[i].providerID == providerID {
			call = &calls[i]
		}
	}
	if call == nil {
		t.Fatal("penalise was never called for this provider")
	}
	if call.amountPaise != depositPaise {
		t.Errorf("amountPaise = %d, want %d (the provider's full current escrow balance)", call.amountPaise, depositPaise)
	}
	if len(call.idempotencyKey) != 64 {
		t.Errorf("idempotencyKey length = %d, want 64 (SHA-256 as hex)", len(call.idempotencyKey))
	}
}

// ledgerBackedPenalise returns a PenaliseFunc that inserts a row into
// escrow_events exactly the way internal/payment.MockProvider.Penalise and
// internal/payment.RazorpayProvider.Penalise both do (INSERT ... event_type
// = 'SEIZURE') — reproducing the real escrow_events.amount_paise CHECK
// (amount_paise > 0) constraint those implementations are bound by, without
// this package importing internal/payment (IC §9 forbids
// internal/repair -> internal/payment; see this file's header and
// departure.go's PenaliseFunc doc comment). This is the closest a test
// inside this package can get to exercising the real failure mode Finding
// #3 describes; the payment package's own tests separately cover
// MockProvider.Penalise/RazorpayProvider.Penalise's defense-in-depth
// zero-amount guard directly.
func ledgerBackedPenalise(db *sql.DB) PenaliseFunc {
	return func(ctx context.Context, providerID uuid.UUID, amountPaise int64, idempotencyKey string) error {
		_, err := db.ExecContext(ctx, `
			INSERT INTO escrow_events (provider_id, event_type, amount_paise, idempotency_key)
			VALUES ($1, 'SEIZURE', $2, $3)`,
			providerID, amountPaise, idempotencyKey)
		return err
	}
}

// TestDepartureDetectorSkipsPenaliseForZeroBalance is the regression test
// for Finding #3 (M10 corrections review): a silently-departing provider
// with no escrow deposits has sealedBalance = 0. escrow_events.amount_paise
// has CHECK (amount_paise > 0) (DM §4.8), and neither
// MockProvider.Penalise nor RazorpayProvider.Penalise guarded against this
// before insertion — so, prior to this fix, processDeparture's unconditional
// call to d.penalise(...) would surface that CHECK violation as a real
// error out of DetectOnce for the overwhelmingly common case (Finding #1:
// balances are structurally 0 in production today). This test uses
// ledgerBackedPenalise (see its own doc comment) to reproduce that exact
// constraint against a live database, and asserts DetectOnce now succeeds
// with zero SEIZURE rows written for a zero-balance departure — the
// escrow-seizure step is skipped entirely rather than attempted with a
// worthless zero amount, mirroring the existing "if releaseAmountPaise > 0"
// guard pattern already used in release.go and provider.go.
func TestDepartureDetectorSkipsPenaliseForZeroBalance(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile

	// No escrow_events seeded at all for this provider -> sealedBalance
	// computes to exactly 0.
	providerID := insertTestProvider(t, db, testProviderSpec{status: "ACTIVE", lastHeartbeatTs: staleHeartbeat(profile)})

	detector := NewDepartureDetector(db, profile, ledgerBackedPenalise(db))
	if err := detector.DetectOnce(context.Background()); err != nil {
		t.Fatalf("DetectOnce: %v (a zero-balance departure must not surface the escrow_events "+
			"amount_paise CHECK constraint as an error — see Finding #3)", err)
	}

	var status string
	if err := verify.QueryRow(`SELECT status FROM providers WHERE provider_id = $1`, providerID).Scan(&status); err != nil {
		t.Fatalf("query provider: %v", err)
	}
	if status != "DEPARTED" {
		t.Errorf("status = %q, want DEPARTED (the rest of departure processing must still complete "+
			"even when the escrow seizure step is skipped)", status)
	}

	var seizureRows int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM escrow_events WHERE provider_id = $1 AND event_type = 'SEIZURE'`,
		providerID).Scan(&seizureRows); err != nil {
		t.Fatalf("count escrow_events: %v", err)
	}
	if seizureRows != 0 {
		t.Errorf("SEIZURE rows for a zero-balance departure = %d, want 0 (penalise must not be called at all "+
			"when there is nothing to seize)", seizureRows)
	}
}

// TestComputeSealedBalanceTreatsReversalAsAdditive is the regression test
// for Finding #2 (M10 corrections review): computeSealedBalance must treat
// REVERSAL the same way the canonical mv_provider_escrow_balance view does
// (DM §7: "REVERSAL increases balance (refund of a reversed payout)") —
// SUM(DEPOSIT + REVERSAL) - SUM(RELEASE + SEIZURE), never subtracting
// REVERSAL. Scenario: a provider deposits X, the full X is later released
// (balance 0), then that release is reversed (HandlePayoutReversed) —
// refunding X back to the provider. The canonical formula and
// computeSealedBalance must agree exactly: balance = X, not 0.
func TestComputeSealedBalanceTreatsReversalAsAdditive(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)

	providerID := insertTestProvider(t, db, testProviderSpec{})

	const depositPaise = 80000
	if _, err := verify.Exec(`
		INSERT INTO escrow_events (provider_id, event_type, amount_paise, idempotency_key)
		VALUES ($1, 'DEPOSIT', $2, $3)`,
		providerID, depositPaise, uuid.New().String()); err != nil {
		t.Fatalf("seed DEPOSIT: %v", err)
	}
	if _, err := verify.Exec(`
		INSERT INTO escrow_events (provider_id, event_type, amount_paise, idempotency_key)
		VALUES ($1, 'RELEASE', $2, $3)`,
		providerID, depositPaise, uuid.New().String()); err != nil {
		t.Fatalf("seed RELEASE: %v", err)
	}
	if _, err := verify.Exec(`
		INSERT INTO escrow_events (provider_id, event_type, amount_paise, idempotency_key)
		VALUES ($1, 'REVERSAL', $2, $3)`,
		providerID, depositPaise, uuid.New().String()); err != nil {
		t.Fatalf("seed REVERSAL: %v", err)
	}

	got, err := computeSealedBalance(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("computeSealedBalance: %v", err)
	}
	if got != depositPaise {
		t.Errorf("computeSealedBalance = %d, want %d (REVERSAL must be additive, matching "+
			"mv_provider_escrow_balance's canonical formula exactly — a reversed payout refunds the "+
			"provider; under the pre-fix subtractive formula this under-seizes by double the reversed "+
			"amount)", got, depositPaise)
	}

	var canonical int64
	if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW mv_provider_escrow_balance`); err != nil {
		t.Fatalf("refresh mv_provider_escrow_balance: %v", err)
	}
	if err := verify.QueryRow(`SELECT balance_paise FROM mv_provider_escrow_balance WHERE provider_id = $1`, providerID).
		Scan(&canonical); err != nil {
		t.Fatalf("query canonical view: %v", err)
	}
	if got != canonical {
		t.Errorf("computeSealedBalance = %d, canonical mv_provider_escrow_balance = %d — the two formulas "+
			"must never disagree (this is exactly the class of bug Finding #2 describes)", got, canonical)
	}
}
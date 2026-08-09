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

	// [Added, M9 review Finding #1 — required test #1] Mirrors
	// TestDepartureDetectorCatchesVettingProviders' existing assertion below:
	// the departed provider's OLD chunk_assignments row for this real shard
	// must be soft-deleted, freeing idx_chunk_assignments_one_active_per_shard
	// for the replacement provider ExecuteRepairJob will pre-register next.
	var oldAssignmentStatus string
	var oldAssignmentDeletedAt sql.NullTime
	if err := verify.QueryRow(`SELECT status, deleted_at FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], providerID).Scan(&oldAssignmentStatus, &oldAssignmentDeletedAt); err != nil {
		t.Fatalf("query old chunk_assignments row: %v", err)
	}
	if oldAssignmentStatus != "DELETED" {
		t.Errorf("old chunk_assignments.status = %q, want DELETED (a stale ACTIVE row here blocks repair's replacement INSERT)", oldAssignmentStatus)
	}
	if !oldAssignmentDeletedAt.Valid {
		t.Error("old chunk_assignments.deleted_at is NULL, want set")
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

// insertTestEscrowEvent inserts one escrow_events row directly (bypassing
// internal/payment, which internal/repair must not import — IC §9), for
// computeSealedBalance's own regression coverage below.
func insertTestEscrowEvent(t *testing.T, db *sql.DB, providerID uuid.UUID, eventType string, amountPaise int64) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO escrow_events (provider_id, event_type, amount_paise, idempotency_key)
		VALUES ($1, $2, $3, $4)`,
		providerID, eventType, amountPaise, uuid.New().String())
	if err != nil {
		t.Fatalf("insertTestEscrowEvent(%s, %d): %v", eventType, amountPaise, err)
	}
}

// TestComputeSealedBalanceCreditsReversal is the regression test for M9
// review Finding #2: computeSealedBalance was debiting REVERSAL
// (SUM(DEPOSIT) - SUM(RELEASE+SEIZURE+REVERSAL)) instead of crediting it
// (SUM(DEPOSIT+REVERSAL) - SUM(RELEASE+SEIZURE)) per DM §7's amended
// mv_provider_escrow_balance formula — the same formula
// internal/payment/ledger.go and provider.go already implement correctly.
//
// Seeded: DEPOSIT 100000, RELEASE 20000, SEIZURE 10000, REVERSAL 15000.
// Correct balance:   (100000 + 15000) - (20000 + 10000) = 85000.
// Bug's balance:      100000 - (20000 + 10000 + 15000)  = 55000.
// The two diverge by exactly 2x the REVERSAL amount (30000), so this test
// fails loudly — not by a rounding-adjacent margin — if the sign regresses.
//
// [REF: DM §4.8, DM §7, M9 review Finding #2]
func TestComputeSealedBalanceCreditsReversal(t *testing.T) {
	db := openTestDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{status: "ACTIVE"})

	insertTestEscrowEvent(t, db, providerID, "DEPOSIT", 100000)
	insertTestEscrowEvent(t, db, providerID, "RELEASE", 20000)
	insertTestEscrowEvent(t, db, providerID, "SEIZURE", 10000)
	insertTestEscrowEvent(t, db, providerID, "REVERSAL", 15000)

	got, err := computeSealedBalance(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("computeSealedBalance: %v", err)
	}

	const want = (100000 + 15000) - (20000 + 10000)
	if got != want {
		t.Errorf("computeSealedBalance = %d, want %d (REVERSAL must credit the balance, not debit it — got the "+
			"bug's value of %d if this regresses)", got, want, int64(100000-(20000+10000+15000)))
	}
}
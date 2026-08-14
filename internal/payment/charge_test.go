// Package payment is declared in doc.go.
// Unit and live-database integration tests for the charge/distribution
// engine (ADR-061, M10 corrections review Finding #1).
//
// Tests:
//   - TestFileMonthlyCostPaiseRoundsHalfUp
//   - TestSplitByLargestRemainderSumsExactly
//   - TestSplitByLargestRemainderDeterministicTieBreak
//   - TestSplitByLargestRemainderEmptyCounts
//   - TestShouldRunChargeFiresAcrossYearBoundary
//   - TestShouldRunChargeIsArrears
//   - TestComputeMonthlyChargesChargesOwnerAndCreditsProvidersProportionally
//   - TestComputeMonthlyChargesIdempotentOnRetry
//   - TestComputeMonthlyChargesSkipsFileWithNoActiveHolders
//   - TestComputeMonthlyChargesSkipsDeletedFile
//   - TestComputeMonthlyChargesPartialFailureIsRetrySafe
//   - TestComputeMonthlyChargesFullCycleFundsRelease
//
// [REF: ADR-061, DM §4.3-4.9, build.md Phase 10.6]

package payment

import (
	"context"
	"crypto/rand"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// ── Pure function tests (no database needed) ──────────────────────────────────

func TestFileMonthlyCostPaiseRoundsHalfUp(t *testing.T) {
	// A synthetic 2-paise-per-GB profile, chosen so fractional-GB cases land
	// on clean half-paise boundaries — DemoProfile/ProductionProfile's real
	// rate (100) makes hand-verified .5 boundaries awkward to construct.
	profile := config.NetworkProfile{StorageRatePaisePerGBPerMonth: 2}
	for _, tc := range []struct {
		name      string
		sizeBytes int64
		want      int64
	}{
		{"exactly 1 GB -> 2 paise exactly", bytesPerGB, 2},
		{"exactly 0.5 GB -> 1 paise exactly", bytesPerGB / 2, 1},
		{"exactly 0.25 GB -> 0.5 paise, rounds UP to 1", bytesPerGB / 4, 1},
		{"just under 0.25 GB -> just under 0.5 paise, rounds DOWN to 0", bytesPerGB/4 - 1, 0},
		{"zero bytes", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fileMonthlyCostPaise(tc.sizeBytes, profile); got != tc.want {
				t.Errorf("fileMonthlyCostPaise(%d) = %d, want %d", tc.sizeBytes, got, tc.want)
			}
		})
	}
}

func TestSplitByLargestRemainderSumsExactly(t *testing.T) {
	for _, tc := range []struct {
		name       string
		totalPaise int64
		counts     map[uuid.UUID]int64
	}{
		{"divides evenly", 300, map[uuid.UUID]int64{uuid.New(): 1, uuid.New(): 1, uuid.New(): 1}},
		{"does not divide evenly", 100, map[uuid.UUID]int64{uuid.New(): 1, uuid.New(): 1, uuid.New(): 1}},
		{"single holder", 12345, map[uuid.UUID]int64{uuid.New(): 1}},
		{"uneven shard counts", 10007, map[uuid.UUID]int64{uuid.New(): 3, uuid.New(): 1, uuid.New(): 52}},
		{"many holders, prime total", 9973, map[uuid.UUID]int64{
			uuid.New(): 1, uuid.New(): 1, uuid.New(): 1, uuid.New(): 1, uuid.New(): 1,
			uuid.New(): 1, uuid.New(): 1, uuid.New(): 1, uuid.New(): 1, uuid.New(): 1,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shares := splitByLargestRemainder(tc.totalPaise, tc.counts)
			var sum int64
			for id, c := range tc.counts {
				amount, ok := shares[id]
				if !ok {
					t.Fatalf("no share computed for provider holding %d shards", c)
				}
				sum += amount
			}
			if sum != tc.totalPaise {
				t.Errorf("sum(shares) = %d, want %d (ADR-061: must sum exactly, never short or over)", sum, tc.totalPaise)
			}
			for id, amount := range shares {
				if amount < 0 {
					t.Errorf("negative share %d for provider %s", amount, id)
				}
			}
		})
	}
}

// TestSplitByLargestRemainderDeterministicTieBreak verifies ADR-061's
// explicit tie-break rule (provider_id ascending) so a retried computation
// against unchanged inputs always redistributes the leftover paise
// identically — a nondeterministic tie-break would silently violate the
// per-provider DEPOSIT idempotency key's retry-safety guarantee.
func TestSplitByLargestRemainderDeterministicTieBreak(t *testing.T) {
	// 3 providers, 1 shard each, totalPaise=10: base share floor(10/3)=3
	// each (9 total), 1 leftover paise. All three fractional remainders are
	// identical (10*1 mod 3 = 1 for every provider), so the tie-break rule
	// alone decides who gets the extra paise.
	lo := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	mid := uuid.MustParse("50000000-0000-0000-0000-000000000001")
	hi := uuid.MustParse("f0000000-0000-0000-0000-000000000001")
	counts := map[uuid.UUID]int64{hi: 1, lo: 1, mid: 1}

	for i := 0; i < 5; i++ {
		shares := splitByLargestRemainder(10, counts)
		if shares[lo] != 4 {
			t.Errorf("run %d: shares[lo] = %d, want 4 (lowest provider_id gets the tie-broken leftover paise)", i, shares[lo])
		}
		if shares[mid] != 3 || shares[hi] != 3 {
			t.Errorf("run %d: shares[mid]=%d shares[hi]=%d, want 3 and 3", i, shares[mid], shares[hi])
		}
	}
}

func TestSplitByLargestRemainderEmptyCounts(t *testing.T) {
	if got := splitByLargestRemainder(500, map[uuid.UUID]int64{}); got != nil {
		t.Errorf("splitByLargestRemainder(500, {}) = %v, want nil", got)
	}
}

// TestShouldRunChargeFiresAcrossYearBoundary mirrors
// TestShouldRunReleaseFiresAcrossYearBoundary (release.go, Finding #6) —
// this charge scheduler reuses that fix from day one (ADR-061 Decision
// §4) rather than reintroducing the annual-rollover bug class in a second
// scheduler.
func TestShouldRunChargeFiresAcrossYearBoundary(t *testing.T) {
	first := time.Date(2026, time.February, chargeComputationDayOfMonth, 9, 0, 0, 0, time.UTC)
	run, lastRun := shouldRunCharge(first, "")
	if !run {
		t.Fatalf("shouldRunCharge(%v, \"\") run = false, want true (first-ever run on the 1st)", first)
	}
	if lastRun != "2026-01" {
		t.Fatalf("billingPeriod = %q, want %q (arrears: January, not February)", lastRun, "2026-01")
	}

	sameDayLater := first.Add(3 * time.Hour)
	if run, _ := shouldRunCharge(sameDayLater, lastRun); run {
		t.Errorf("shouldRunCharge(%v, %q) run = true, want false (already ran this month)", sameDayLater, lastRun)
	}

	secondYear := time.Date(2027, time.February, chargeComputationDayOfMonth, 9, 0, 0, 0, time.UTC)
	run2, lastRun2 := shouldRunCharge(secondYear, lastRun)
	if !run2 {
		t.Errorf("shouldRunCharge(%v, %q) run = false, want true (a full year has passed since the last run)", secondYear, lastRun)
	}
	if lastRun2 != "2027-01" {
		t.Errorf("billingPeriod = %q, want %q", lastRun2, "2027-01")
	}

	notThe1st := time.Date(2027, time.March, 15, 0, 0, 0, 0, time.UTC)
	if run, _ := shouldRunCharge(notThe1st, lastRun2); run {
		t.Errorf("shouldRunCharge(%v, %q) run = true, want false (not the 1st)", notThe1st, lastRun2)
	}
}

// TestShouldRunChargeIsArrears confirms the billing period returned is
// always the month BEFORE now, not the current month — ADR-061's explicit
// "charge in arrears for the month just elapsed" decision.
func TestShouldRunChargeIsArrears(t *testing.T) {
	for _, tc := range []struct {
		now  time.Time
		want string
	}{
		{time.Date(2026, time.March, chargeComputationDayOfMonth, 0, 0, 0, 0, time.UTC), "2026-02"},
		{time.Date(2026, time.January, chargeComputationDayOfMonth, 0, 0, 0, 0, time.UTC), "2025-12"}, // year rollback too
	} {
		_, got := shouldRunCharge(tc.now, "")
		if got != tc.want {
			t.Errorf("shouldRunCharge(%v, \"\") billingPeriod = %q, want %q", tc.now, got, tc.want)
		}
	}
}

// ── Live-database fixtures ──────────────────────────────────────────────────────

func insertTestFileForCharge(t *testing.T, db *sql.DB, ownerID uuid.UUID, sizeBytes int64, status string) uuid.UUID {
	t.Helper()
	if status == "" {
		status = "ACTIVE"
	}
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	var tag [16]byte
	_, _ = rand.Read(tag[:])
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO files (file_id, owner_id, pointer_ciphertext, pointer_nonce, pointer_tag, original_size_bytes, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, ownerID, []byte("test-ciphertext"), nonce[:], tag[:], sizeBytes, status)
	if err != nil {
		t.Fatalf("insertTestFileForCharge: %v", err)
	}
	return id
}

func insertTestSegmentForCharge(t *testing.T, db *sql.DB, fileID uuid.UUID, index int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`INSERT INTO segments (segment_id, file_id, segment_index) VALUES ($1,$2,$3)`, id, fileID, index)
	if err != nil {
		t.Fatalf("insertTestSegmentForCharge: %v", err)
	}
	return id
}

func insertTestChunkAssignmentForCharge(t *testing.T, db *sql.DB, segmentID uuid.UUID, shardIndex int, providerID uuid.UUID, status string) {
	t.Helper()
	if status == "" {
		status = "ACTIVE"
	}
	var chunkID [32]byte
	_, _ = rand.Read(chunkID[:])
	_, err := db.Exec(`
		INSERT INTO chunk_assignments (chunk_id, is_vetting_chunk, segment_id, shard_index, provider_id, status)
		VALUES ($1,FALSE,$2,$3,$4,$5)`,
		chunkID[:], segmentID, shardIndex, providerID, status)
	if err != nil {
		t.Fatalf("insertTestChunkAssignmentForCharge: %v", err)
	}
}

// ── Live-database tests ─────────────────────────────────────────────────────────

func TestComputeMonthlyChargesChargesOwnerAndCreditsProvidersProportionally(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.NetworkProfile{StorageRatePaisePerGBPerMonth: 100}
	ownerID := insertTestOwner(t, db, "")
	fileID := insertTestFileForCharge(t, db, ownerID, bytesPerGB, "ACTIVE") // cost = 100 paise
	segmentID := insertTestSegmentForCharge(t, db, fileID, 0)

	providerA := insertTestProvider(t, db, testProviderSpec{})
	providerB := insertTestProvider(t, db, testProviderSpec{})
	// A holds 3 shards, B holds 1 -> A should get 3x B's credit.
	insertTestChunkAssignmentForCharge(t, db, segmentID, 0, providerA, "ACTIVE")
	insertTestChunkAssignmentForCharge(t, db, segmentID, 1, providerA, "ACTIVE")
	insertTestChunkAssignmentForCharge(t, db, segmentID, 2, providerA, "ACTIVE")
	insertTestChunkAssignmentForCharge(t, db, segmentID, 3, providerB, "ACTIVE")

	billingPeriod := "2026-08"
	if err := ComputeMonthlyCharges(context.Background(), db, profile, billingPeriod); err != nil {
		t.Fatalf("ComputeMonthlyCharges: %v", err)
	}

	var chargeAmount int64
	var chargeKey string
	if err := verify.QueryRow(`SELECT amount_paise, idempotency_key FROM owner_escrow_events WHERE owner_id=$1 AND event_type='CHARGE'`,
		ownerID).Scan(&chargeAmount, &chargeKey); err != nil {
		t.Fatalf("query owner_escrow_events: %v", err)
	}
	if chargeAmount != 100 {
		t.Errorf("charge amount = %d, want 100", chargeAmount)
	}
	if chargeKey != ChargeIdempotencyKey(ownerID, fileID, billingPeriod) {
		t.Errorf("charge idempotency_key does not match ChargeIdempotencyKey's own formula")
	}

	var amountA, amountB int64
	if err := verify.QueryRow(`SELECT amount_paise FROM escrow_events WHERE provider_id=$1 AND event_type='DEPOSIT'`, providerA).Scan(&amountA); err != nil {
		t.Fatalf("query provider A deposit: %v", err)
	}
	if err := verify.QueryRow(`SELECT amount_paise FROM escrow_events WHERE provider_id=$1 AND event_type='DEPOSIT'`, providerB).Scan(&amountB); err != nil {
		t.Fatalf("query provider B deposit: %v", err)
	}
	if amountA != 75 || amountB != 25 {
		t.Errorf("amountA=%d amountB=%d, want 75 and 25 (A holds 3/4 of the shards, B holds 1/4, of a 100 paise charge)", amountA, amountB)
	}
	if amountA+amountB != chargeAmount {
		t.Errorf("amountA+amountB = %d, want exactly %d (the owner's charge)", amountA+amountB, chargeAmount)
	}
}

func TestComputeMonthlyChargesIdempotentOnRetry(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.NetworkProfile{StorageRatePaisePerGBPerMonth: 100}
	ownerID := insertTestOwner(t, db, "")
	fileID := insertTestFileForCharge(t, db, ownerID, bytesPerGB, "ACTIVE")
	segmentID := insertTestSegmentForCharge(t, db, fileID, 0)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	insertTestChunkAssignmentForCharge(t, db, segmentID, 0, providerID, "ACTIVE")

	billingPeriod := "2026-07"
	for i := 0; i < 2; i++ {
		if err := ComputeMonthlyCharges(context.Background(), db, profile, billingPeriod); err != nil {
			t.Fatalf("ComputeMonthlyCharges call #%d: %v", i+1, err)
		}
	}

	var chargeRows, depositRows int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM owner_escrow_events WHERE owner_id=$1 AND event_type='CHARGE'`, ownerID).Scan(&chargeRows); err != nil {
		t.Fatalf("count charges: %v", err)
	}
	if err := verify.QueryRow(`SELECT COUNT(*) FROM escrow_events WHERE provider_id=$1 AND event_type='DEPOSIT'`, providerID).Scan(&depositRows); err != nil {
		t.Fatalf("count deposits: %v", err)
	}
	if chargeRows != 1 {
		t.Errorf("CHARGE rows after 2 identical runs = %d, want 1", chargeRows)
	}
	if depositRows != 1 {
		t.Errorf("DEPOSIT rows after 2 identical runs = %d, want 1", depositRows)
	}
}

func TestComputeMonthlyChargesSkipsFileWithNoActiveHolders(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.NetworkProfile{StorageRatePaisePerGBPerMonth: 100}
	ownerID := insertTestOwner(t, db, "")
	fileID := insertTestFileForCharge(t, db, ownerID, bytesPerGB, "ACTIVE")
	// No chunk_assignments at all for this file.

	if err := ComputeMonthlyCharges(context.Background(), db, profile, "2026-06"); err != nil {
		t.Fatalf("ComputeMonthlyCharges: %v", err)
	}

	var rows int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM owner_escrow_events WHERE owner_id=$1 AND file_id=$2`, ownerID, fileID).Scan(&rows); err != nil {
		t.Fatalf("query: %v", err)
	}
	if rows != 0 {
		t.Errorf("CHARGE rows for a file with no active shard holders = %d, want 0 (do not charge for nobody to credit)", rows)
	}
}

func TestComputeMonthlyChargesSkipsDeletedFile(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.NetworkProfile{StorageRatePaisePerGBPerMonth: 100}
	ownerID := insertTestOwner(t, db, "")
	fileID := insertTestFileForCharge(t, db, ownerID, bytesPerGB, "DELETED")
	segmentID := insertTestSegmentForCharge(t, db, fileID, 0)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	// Even if a DELETED file still has stale ACTIVE assignments somehow,
	// files.status = 'DELETED' alone must exclude it from chargeableFiles.
	insertTestChunkAssignmentForCharge(t, db, segmentID, 0, providerID, "ACTIVE")

	if err := ComputeMonthlyCharges(context.Background(), db, profile, "2026-05"); err != nil {
		t.Fatalf("ComputeMonthlyCharges: %v", err)
	}

	var rows int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM owner_escrow_events WHERE owner_id=$1 AND file_id=$2`, ownerID, fileID).Scan(&rows); err != nil {
		t.Fatalf("query: %v", err)
	}
	if rows != 0 {
		t.Errorf("CHARGE rows for a DELETED file = %d, want 0 (DM §4.3: owner is not billed after deletion)", rows)
	}
}

// TestComputeMonthlyChargesPartialFailureIsRetrySafe simulates a run that
// charged the owner but was interrupted before crediting any provider
// (e.g. a crash between the two steps) by manually seeding the CHARGE row
// with the exact key computeChargeForFile would derive, then running
// ComputeMonthlyCharges and confirming the provider still gets credited —
// the fall-through behavior computeChargeForFile's own doc comment
// describes.
func TestComputeMonthlyChargesPartialFailureIsRetrySafe(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.NetworkProfile{StorageRatePaisePerGBPerMonth: 100}
	ownerID := insertTestOwner(t, db, "")
	fileID := insertTestFileForCharge(t, db, ownerID, bytesPerGB, "ACTIVE")
	segmentID := insertTestSegmentForCharge(t, db, fileID, 0)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	insertTestChunkAssignmentForCharge(t, db, segmentID, 0, providerID, "ACTIVE")

	billingPeriod := "2026-04"
	preExistingKey := ChargeIdempotencyKey(ownerID, fileID, billingPeriod)
	if err := InsertOwnerEscrowEvent(context.Background(), db, ownerID, OwnerCharge, 100, preExistingKey, &fileID); err != nil {
		t.Fatalf("seed pre-existing charge: %v", err)
	}

	if err := ComputeMonthlyCharges(context.Background(), db, profile, billingPeriod); err != nil {
		t.Fatalf("ComputeMonthlyCharges: %v", err)
	}

	var depositRows int
	var amount int64
	if err := verify.QueryRow(`SELECT COUNT(*), COALESCE(MAX(amount_paise),0) FROM escrow_events WHERE provider_id=$1 AND event_type='DEPOSIT'`,
		providerID).Scan(&depositRows, &amount); err != nil {
		t.Fatalf("query deposits: %v", err)
	}
	if depositRows != 1 {
		t.Errorf("DEPOSIT rows after a retry against an already-charged owner = %d, want 1 (a partially-failed "+
			"run must still be completable by a retry, not permanently stuck)", depositRows)
	}
	if amount != 100 {
		t.Errorf("deposit amount = %d, want 100", amount)
	}
}

// TestComputeMonthlyChargesFullCycleFundsRelease is the exact test the M10
// contributor audit review required for Finding #1: "a full-cycle test
// that charges an owner, credits N providers, refreshes
// mv_provider_escrow_balance, and confirms ComputeMonthlyRelease now
// actually releases a non-zero amount end-to-end — this is the test that
// would have caught the fact that nothing currently funds the ledger."
//
// Before this file existed, this was impossible to write: EscrowDeposit
// was never constructed by any non-test code (Finding #1), so
// mv_provider_escrow_balance was structurally always 0 for every real
// provider, and ComputeMonthlyRelease always computed releaseAmountPaise =
// 0 * multiplier = 0 in production.
func TestComputeMonthlyChargesFullCycleFundsRelease(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	drainPendingReleaseCandidates(t, verify)
	profile := config.DemoProfile

	ownerID := insertTestOwner(t, db, "")
	// A 4 GB file at DemoProfile's real rate (100 paise/GB/month) -> 400
	// paise charged, split across 2 providers holding 2 shards each.
	fileID := insertTestFileForCharge(t, db, ownerID, 4*bytesPerGB, "ACTIVE")
	segmentID := insertTestSegmentForCharge(t, db, fileID, 0)
	providerA := insertTestProvider(t, db, testProviderSpec{})
	providerB := insertTestProvider(t, db, testProviderSpec{})
	insertTestChunkAssignmentForCharge(t, db, segmentID, 0, providerA, "ACTIVE")
	insertTestChunkAssignmentForCharge(t, db, segmentID, 1, providerA, "ACTIVE")
	insertTestChunkAssignmentForCharge(t, db, segmentID, 2, providerB, "ACTIVE")
	insertTestChunkAssignmentForCharge(t, db, segmentID, 3, providerB, "ACTIVE")

	// Step 1: run the charge/distribution engine — this is the step that,
	// before this session, did not exist anywhere in production code.
	if err := ComputeMonthlyCharges(context.Background(), db, profile, "2026-08"); err != nil {
		t.Fatalf("ComputeMonthlyCharges: %v", err)
	}

	var depositRowsA, depositRowsB int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM escrow_events WHERE provider_id=$1 AND event_type='DEPOSIT'`, providerA).Scan(&depositRowsA); err != nil {
		t.Fatalf("count provider A deposits: %v", err)
	}
	if err := verify.QueryRow(`SELECT COUNT(*) FROM escrow_events WHERE provider_id=$1 AND event_type='DEPOSIT'`, providerB).Scan(&depositRowsB); err != nil {
		t.Fatalf("count provider B deposits: %v", err)
	}
	if depositRowsA != 1 || depositRowsB != 1 {
		t.Fatalf("depositRowsA=%d depositRowsB=%d, want 1 and 1 (both providers must be credited)", depositRowsA, depositRowsB)
	}

	// Step 2: refresh the balance view, exactly as a real deployment's
	// M12 refresh loop would (Finding #5 — not built here, simulated
	// directly, since this test's job is to prove the funding path works
	// once refresh happens, not to build the refresh loop itself).
	if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW mv_provider_escrow_balance`); err != nil {
		t.Fatalf("refresh mv_provider_escrow_balance: %v", err)
	}

	balanceA, err := providerBalance(context.Background(), db, providerA)
	if err != nil {
		t.Fatalf("providerBalance A: %v", err)
	}
	if balanceA == 0 {
		t.Fatal("providerBalance(A) = 0 after charge+distribute+refresh — the funding path is still not working (Finding #1)")
	}

	// Step 3: give provider A a fresh, strong score and a pending audit
	// period, then run the REAL release computation — proving the money
	// this session's engine deposited can actually be released.
	auditPeriodID := insertTestAuditPeriod(t, db, providerA)
	now := time.Now().UTC()
	for _, daysAgo := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		insertTestAuditReceiptForRelease(t, verify, providerA, now.Add(-time.Duration(daysAgo)*24*time.Hour), "PASS")
	}
	refreshProviderScoresForRelease(t, verify)

	mock := NewMockProvider(db)
	if err := ComputeMonthlyRelease(context.Background(), db, db, profile, mock); err != nil {
		t.Fatalf("ComputeMonthlyRelease: %v", err)
	}

	var releasedAmount int64
	if err := verify.QueryRow(`SELECT COALESCE(SUM(amount_paise),0) FROM escrow_events WHERE provider_id=$1 AND event_type='RELEASE' AND audit_period_id=$2`,
		providerA, auditPeriodID).Scan(&releasedAmount); err != nil {
		t.Fatalf("query RELEASE rows: %v", err)
	}
	if releasedAmount == 0 {
		t.Fatal("ComputeMonthlyRelease released 0 paise for a provider with a real, freshly-deposited balance and " +
			"a full-pass score — this is exactly the gap Finding #1 identified: without the charge engine, " +
			"the payment system cannot pay anyone. It must be funded now.")
	}
	t.Logf("full cycle verified: charged owner -> credited providers -> released %d paise end-to-end", releasedAmount)
}

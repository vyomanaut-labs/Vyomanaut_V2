// Package repair is declared in doc.go.
// Unit and live-database integration tests for SelectReplacementProvider.
//
// SelectReplacementProvider draws two RANDOM ACTIVE candidates from the
// entire providers table — correct for production Power of Two Choices, but
// it means a test wanting a DETERMINISTIC outcome (e.g. "the higher-scored
// of these two specific candidates wins") must ensure no other ACTIVE
// provider from an earlier test can also be drawn. Every test below achieves
// this by passing allActiveProviderIDs(t, verify) — every ACTIVE provider
// that already exists at the moment the test starts — as part of
// excludeProviderIDs, alongside whatever it additionally wants excluded for
// its own reasons. This leaves only the test's own freshly-inserted
// candidates eligible for the random draw.
//
// Tests:
//   - TestSelectReplacementProviderPicksHigherScored
//   - TestSelectReplacementProviderRejectsASNCapViolation
//   - TestSelectReplacementProviderExcludesCurrentHolders
//   - TestSelectReplacementProviderReturnsErrAfterBoundedRetries
//
// [REF: FR-045, ADR-005, ADR-014, build.md Phase 9.4 Session 9.4.1]

package repair

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// allActiveProviderIDs returns every provider_id currently in status =
// 'ACTIVE' — used to exclude pre-existing providers so a test's own
// freshly-inserted candidates are the only ones eligible for
// SelectReplacementProvider's random draw.
func allActiveProviderIDs(t *testing.T, verify *sql.DB) []uuid.UUID {
	t.Helper()
	rows, err := verify.Query(`SELECT provider_id FROM providers WHERE status = 'ACTIVE'`)
	if err != nil {
		t.Fatalf("allActiveProviderIDs: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("allActiveProviderIDs: scan: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("allActiveProviderIDs: %v", err)
	}
	return ids
}

// insertTestAuditReceiptForScore inserts a single terminal audit_receipts row
// directly (internal/repair must not import internal/audit — IC §9),
// mirroring internal/scoring's own test fixture of the same shape.
func insertTestAuditReceiptForScore(t *testing.T, verify *sql.DB, providerID uuid.UUID, challengeTS time.Time, result string) {
	t.Helper()
	var chunkID [32]byte
	_, _ = rand.Read(chunkID[:])
	var nonce [33]byte
	_, _ = rand.Read(nonce[:])
	var respHash [32]byte
	_, _ = rand.Read(respHash[:])
	var sig [64]byte
	_, _ = rand.Read(sig[:])

	_, err := verify.Exec(`
		INSERT INTO audit_receipts (
			chunk_id, provider_id, challenge_nonce, server_challenge_ts,
			audit_result, response_hash, provider_sig
		) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		chunkID[:], providerID, nonce[:], challengeTS, result, respHash[:], sig[:],
	)
	if err != nil {
		t.Fatalf("insertTestAuditReceiptForScore: %v", err)
	}
}

// seedProviderScore gives providerID a clean, unambiguous pass rate (either
// "all PASS" or "all FAIL", set via allPass) so its mv_provider_scores
// composite is clearly near 1.0 or 0.0 — enough separation that Power of Two
// Choices' outcome is never ambiguous.
func seedProviderScore(t *testing.T, verify *sql.DB, providerID uuid.UUID, allPass bool) {
	t.Helper()
	result := "FAIL"
	if allPass {
		result = "PASS"
	}
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		insertTestAuditReceiptForScore(t, verify, providerID, now.Add(-time.Duration(i)*time.Hour), result)
	}
}

func refreshProviderScoresForAssignment(t *testing.T, verify *sql.DB) {
	t.Helper()
	if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW CONCURRENTLY mv_provider_scores`); err != nil {
		t.Fatalf("refreshProviderScoresForAssignment: %v", err)
	}
}

func TestSelectReplacementProviderPicksHigherScored(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	segmentID := insertTestSegmentChain(t, db)
	lowScore := insertTestProvider(t, db, testProviderSpec{})
	highScore := insertTestProvider(t, db, testProviderSpec{})
	seedProviderScore(t, verify, lowScore, false)
	seedProviderScore(t, verify, highScore, true)
	refreshProviderScoresForAssignment(t, verify)

	got, err := SelectReplacementProvider(context.Background(), db, config.ProductionProfile, segmentID, exclude)
	if err != nil {
		t.Fatalf("SelectReplacementProvider: %v", err)
	}
	if got != highScore {
		t.Errorf("SelectReplacementProvider = %v, want the higher-scored candidate %v (low-scored was %v)",
			got, highScore, lowScore)
	}
}

func TestSelectReplacementProviderRejectsASNCapViolation(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	// DemoProfile: TotalShards=5, ASNCapFraction=0.20 -> maxPerASN = 1. One
	// existing live assignment on capASN already saturates that ASN's cap for
	// this segment.
	const capASN = "CAP-TEST-ASN"
	profile := config.DemoProfile
	segmentID := insertTestSegmentChain(t, db)
	existingHolder := insertTestProvider(t, db, testProviderSpec{asn: capASN})
	shardIndex := 0
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:    randChunkID(),
		segmentID:  &segmentID,
		shardIndex: &shardIndex,
		providerID: existingHolder,
		status:     "ACTIVE",
	})

	highScoreSameASN := insertTestProvider(t, db, testProviderSpec{asn: capASN})
	lowScoreOtherASN := insertTestProvider(t, db, testProviderSpec{asn: "SIM-AS1"})
	seedProviderScore(t, verify, highScoreSameASN, true)
	seedProviderScore(t, verify, lowScoreOtherASN, false)
	refreshProviderScoresForAssignment(t, verify)

	exclude = append(exclude, existingHolder)
	got, err := SelectReplacementProvider(context.Background(), db, profile, segmentID, exclude)
	if err != nil {
		t.Fatalf("SelectReplacementProvider: %v", err)
	}
	if got != lowScoreOtherASN {
		t.Errorf("SelectReplacementProvider = %v, want the lower-scored but ASN-cap-compliant candidate %v "+
			"(higher-scored candidate %v shares capASN with the existing holder and must be rejected)",
			got, lowScoreOtherASN, highScoreSameASN)
	}
}

func TestSelectReplacementProviderExcludesCurrentHolders(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	segmentID := insertTestSegmentChain(t, db)
	currentHolder := insertTestProvider(t, db, testProviderSpec{})
	freeCandidate := insertTestProvider(t, db, testProviderSpec{})

	exclude = append(exclude, currentHolder)
	got, err := SelectReplacementProvider(context.Background(), db, config.ProductionProfile, segmentID, exclude)
	if err != nil {
		t.Fatalf("SelectReplacementProvider: %v", err)
	}
	if got == currentHolder {
		t.Errorf("SelectReplacementProvider returned the excluded current holder %v", currentHolder)
	}
	if got != freeCandidate {
		t.Errorf("SelectReplacementProvider = %v, want the only eligible candidate %v", got, freeCandidate)
	}
}

func TestSelectReplacementProviderReturnsErrAfterBoundedRetries(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	// DemoProfile maxPerASN = 1. Saturate capASN, then make every remaining
	// eligible candidate also sit on capASN, so no candidate can ever pass
	// the cap check no matter how many bounded retries are attempted.
	const capASN = "CAP-EXHAUSTED-ASN"
	profile := config.DemoProfile
	segmentID := insertTestSegmentChain(t, db)
	existingHolder := insertTestProvider(t, db, testProviderSpec{asn: capASN})
	shardIndex := 0
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:    randChunkID(),
		segmentID:  &segmentID,
		shardIndex: &shardIndex,
		providerID: existingHolder,
		status:     "ACTIVE",
	})
	exclude = append(exclude, existingHolder)

	for i := 0; i < 3; i++ {
		insertTestProvider(t, db, testProviderSpec{asn: capASN})
	}

	_, err := SelectReplacementProvider(context.Background(), db, profile, segmentID, exclude)
	if !errors.Is(err, ErrNoEligibleReplacement) {
		t.Errorf("SelectReplacementProvider: got %v, want ErrNoEligibleReplacement", err)
	}
}

// TestSelectReplacementProviderExcludesUnlinkedRazorpayProvider is the
// audit's Finding 5 regression test: an ACTIVE provider with
// razorpay_linked_account_id = NULL must be excluded from candidate
// selection (DM §8.2/§8.3, ADR-024, FR-025). Before this fix,
// drawTwoActiveCandidates filtered on status = 'ACTIVE' alone, so a
// provider that reached ACTIVE via scoring.IncrementConsecutivePasses
// (audit-pass and vetting-duration criteria only, no Razorpay check) was
// just as eligible as a fully payment-ready one.
func TestSelectReplacementProviderExcludesUnlinkedRazorpayProvider(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	segmentID := insertTestSegmentChain(t, db)
	unlinked := insertTestProvider(t, db, testProviderSpec{razorpayNotLinked: true})
	linked := insertTestProvider(t, db, testProviderSpec{})
	// Give the unlinked (ineligible) candidate the higher score, so if it
	// were still eligible Power of Two Choices would prefer it over
	// `linked` — isolating this test from Finding 5's fix rather than
	// happening to pass because the eligible candidate also won on score.
	seedProviderScore(t, verify, unlinked, true)
	seedProviderScore(t, verify, linked, false)
	refreshProviderScoresForAssignment(t, verify)

	got, err := SelectReplacementProvider(context.Background(), db, config.ProductionProfile, segmentID, exclude)
	if err != nil {
		t.Fatalf("SelectReplacementProvider: %v", err)
	}
	if got == unlinked {
		t.Errorf("SelectReplacementProvider returned %v, an ACTIVE provider with no Razorpay linked account", got)
	}
	if got != linked {
		t.Errorf("SelectReplacementProvider = %v, want the only Razorpay-eligible candidate %v", got, linked)
	}
}

// TestSelectReplacementProviderExcludesStillCoolingRazorpayProvider mirrors
// the test above for the other half of DM §8.2/§8.3's condition: a linked
// account still inside its cooling window is equally ineligible.
func TestSelectReplacementProviderExcludesStillCoolingRazorpayProvider(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	segmentID := insertTestSegmentChain(t, db)
	stillCooling := insertTestProvider(t, db, testProviderSpec{razorpayNotLinked: true})
	acc := "acc_test_still_cooling"
	coolingUntil := time.Now().Add(24 * time.Hour) // not yet elapsed
	if _, err := db.Exec(`UPDATE providers SET razorpay_linked_account_id = $1, razorpay_cooling_until = $2 WHERE provider_id = $3`,
		acc, coolingUntil, stillCooling); err != nil {
		t.Fatalf("set still-cooling provider: %v", err)
	}
	linked := insertTestProvider(t, db, testProviderSpec{})
	seedProviderScore(t, verify, stillCooling, true)
	seedProviderScore(t, verify, linked, false)
	refreshProviderScoresForAssignment(t, verify)

	got, err := SelectReplacementProvider(context.Background(), db, config.ProductionProfile, segmentID, exclude)
	if err != nil {
		t.Fatalf("SelectReplacementProvider: %v", err)
	}
	if got == stillCooling {
		t.Errorf("SelectReplacementProvider returned %v, a provider still inside its Razorpay cooling window", got)
	}
	if got != linked {
		t.Errorf("SelectReplacementProvider = %v, want the only cooled-and-eligible candidate %v", got, linked)
	}
}

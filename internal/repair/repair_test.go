// Package repair is declared in doc.go.
// Cross-cutting integration tests closing the MVP §8.2 gap: priority
// ordering, ASN cap, emergency floor, vetting exclusion — each exercising
// multiple sessions' code together rather than re-running any single
// session's own unit tests.
//
// Tests:
//   - TestPriorityOrderingEndToEnd
//   - TestASNCapAcrossRepairAndOriginalAssignment
//   - TestEmergencyFloorBypassesQueueOrder
//   - TestVettingExclusionEndToEnd
//   - TestDepartureToRepairFullPipelineNoUniqueViolation (M9 review Finding #1,
//     required test #2 — drives detection through to a completed repair via
//     the real code paths, not a hand-built fixture)
//
// [REF: MVP §8.2, ADR-004, ADR-014, ADR-030, FR-045, FR-065,
// build.md Phase 9.5 Session 9.5.1, M9 review Finding #1]

package repair

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
)

// TestPriorityOrderingEndToEnd enqueues one job of each trigger type in
// REVERSE priority order (PRE_WARNING first, PERMANENT_DEPARTURE next,
// EMERGENCY last) and confirms three successive DequeueNextJob calls drain
// them EMERGENCY -> PERMANENT_DEPARTURE -> PRE_WARNING regardless of
// insertion order — the specific bug this revision fixed (Priority
// originally had only two values, with EMERGENCY_FLOOR falling through to
// PRE_WARNING instead of front-of-queue).
func TestPriorityOrderingEndToEnd(t *testing.T) {
	db := openTestDB(t)
	drainQueue(t, db)

	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	profile := config.DemoProfile

	preWarningChunk := randChunkID()
	if err := EnqueueJob(context.Background(), db, profile, preWarningChunk, segmentID, &providerID,
		TriggerThresholdWarning, profile.DataShards+profile.LazyRepairR0); err != nil {
		t.Fatalf("EnqueueJob(PRE_WARNING): %v", err)
	}
	departureChunk := randChunkID()
	if err := EnqueueJob(context.Background(), db, profile, departureChunk, segmentID, &providerID,
		TriggerAnnouncedDeparture, profile.TotalShards); err != nil {
		t.Fatalf("EnqueueJob(PERMANENT_DEPARTURE): %v", err)
	}
	emergencyChunk := randChunkID()
	if err := EnqueueJob(context.Background(), db, profile, emergencyChunk, segmentID, &providerID,
		TriggerEmergencyFloor, profile.DataShards); err != nil {
		t.Fatalf("EnqueueJob(EMERGENCY): %v", err)
	}

	wantOrder := []struct {
		chunkID  [32]byte
		priority Priority
		name     string
	}{
		{emergencyChunk, PriorityEmergency, "EMERGENCY"},
		{departureChunk, PriorityPermanentDeparture, "PERMANENT_DEPARTURE"},
		{preWarningChunk, PriorityPreWarning, "PRE_WARNING"},
	}
	for i, want := range wantOrder {
		job, err := DequeueNextJob(context.Background(), db)
		if err != nil {
			t.Fatalf("DequeueNextJob #%d: %v", i+1, err)
		}
		if job == nil {
			t.Fatalf("DequeueNextJob #%d returned nil, want the %s job", i+1, want.name)
		}
		if job.ChunkID != want.chunkID || job.Priority != want.priority {
			t.Errorf("DequeueNextJob #%d returned chunk %x (priority %v), want the %s job %x",
				i+1, job.ChunkID, job.Priority, want.name, want.chunkID)
		}
	}
}

// TestASNCapAcrossRepairAndOriginalAssignment simulates a segment already at
// the ASN cap BOUNDARY (DemoProfile: TotalShards=5, ASNCapFraction=0.20 ->
// maxPerASN=1) and confirms SelectReplacementProvider both (a) allows a
// candidate that would land EXACTLY at the cap, and (b) rejects one that
// would exceed it — never pushing any ASN's share of the segment above
// floor(TotalShards * ASNCapFraction), matching FR-045's "same cap as
// original assignment."
func TestASNCapAcrossRepairAndOriginalAssignment(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	profile := config.DemoProfile // maxPerASN = floor(5*0.20) = 1
	const capASN = "E2E-CAP-ASN"
	const otherASN = "E2E-OTHER-ASN"

	segmentID := insertTestSegmentChain(t, db)
	// Segment currently has zero assignments — capASN is at 0/1, exactly one
	// below the cap boundary.
	atBoundary := insertTestProvider(t, db, testProviderSpec{asn: capASN})
	fallback := insertTestProvider(t, db, testProviderSpec{asn: otherASN})

	// Case (a): capASN is empty for this segment, so a candidate on capASN
	// landing at exactly 0+1=1=maxPerASN must be ACCEPTED.
	got, err := SelectReplacementProvider(context.Background(), db, profile, segmentID,
		append(append([]uuid.UUID{}, exclude...), fallback))
	if err != nil {
		t.Fatalf("SelectReplacementProvider (at boundary): %v", err)
	}
	if got != atBoundary {
		t.Fatalf("SelectReplacementProvider = %v, want the only eligible candidate %v (landing exactly at the cap)",
			got, atBoundary)
	}

	// Now record that assignment as live, saturating capASN's single slot.
	shardIndex := 0
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:    randChunkID(),
		segmentID:  &segmentID,
		shardIndex: &shardIndex,
		providerID: atBoundary,
		status:     "ACTIVE",
	})

	// Case (b): a second candidate on the now-saturated capASN must be
	// rejected in favour of the otherASN candidate. Reuse the ORIGINAL
	// pre-existing exclude baseline (captured before this test inserted any
	// of its own providers) plus atBoundary specifically — re-querying
	// allActiveProviderIDs here would also exclude fallback and
	// secondCapASNCandidate (both now ACTIVE), leaving zero eligible
	// candidates.
	secondCapASNCandidate := insertTestProvider(t, db, testProviderSpec{asn: capASN})
	exclude2 := append(append([]uuid.UUID{}, exclude...), atBoundary)
	got2, err := SelectReplacementProvider(context.Background(), db, profile, segmentID, exclude2)
	if err != nil {
		t.Fatalf("SelectReplacementProvider (over cap): %v", err)
	}
	if got2 == secondCapASNCandidate {
		t.Errorf("SelectReplacementProvider returned %v, which would push capASN to 2 shards for this segment "+
			"(maxPerASN=1) — the 20%% ASN cap was violated", got2)
	}
	if got2 != fallback {
		t.Errorf("SelectReplacementProvider = %v, want the ASN-cap-compliant fallback %v", got2, fallback)
	}
}

// TestEmergencyFloorBypassesQueueOrder queues a PRE_WARNING job first, then
// enqueues an EMERGENCY job for a different chunk afterward, and confirms
// DequeueNextJob returns the EMERGENCY job first despite arriving later —
// this is the exact scenario ADR-004's "immediate, front of queue" rule
// describes for the reconstruction floor, and the exact scenario the
// original two-value Priority enum got backwards.
func TestEmergencyFloorBypassesQueueOrder(t *testing.T) {
	// Assertion below expects PriorityEmergency ('EMERGENCY') specifically —
	// not PriorityPreWarning, which is what the original two-value Priority
	// enum produced for TriggerEmergencyFloor before this revision's fix.
	db := openTestDB(t)
	drainQueue(t, db)

	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	profile := config.DemoProfile

	preWarningChunk := randChunkID()
	if err := EnqueueJob(context.Background(), db, profile, preWarningChunk, segmentID, &providerID,
		TriggerThresholdWarning, profile.DataShards+profile.LazyRepairR0); err != nil {
		t.Fatalf("EnqueueJob(PRE_WARNING, queued first): %v", err)
	}

	// Enqueued SECOND (arrives later) but must still drain FIRST.
	emergencyChunk := randChunkID()
	if err := EnqueueJob(context.Background(), db, profile, emergencyChunk, segmentID, &providerID,
		TriggerEmergencyFloor, profile.DataShards); err != nil {
		t.Fatalf("EnqueueJob(EMERGENCY, queued second): %v", err)
	}

	job, err := DequeueNextJob(context.Background(), db)
	if err != nil {
		t.Fatalf("DequeueNextJob: %v", err)
	}
	if job == nil {
		t.Fatal("DequeueNextJob returned nil, want the EMERGENCY job")
	}
	if job.ChunkID != emergencyChunk || job.Priority != PriorityEmergency {
		t.Errorf("DequeueNextJob returned chunk %x (priority %v), want the 'EMERGENCY' job %x — "+
			"a later-arriving EMERGENCY_FLOOR job must bypass an already-queued PRE_WARNING job",
			job.ChunkID, job.Priority, emergencyChunk)
	}
}

// TestVettingExclusionEndToEnd exercises Sessions 9.1.3 and 9.3.1 together:
// a VETTING provider holding only synthetic chunks crosses
// profile.DepartureThreshold; the departure detector must mark it DEPARTED,
// soft-delete every one of its chunk_assignments, and — the FR-065
// property under test — leave repair_jobs with ZERO new rows.
func TestVettingExclusionEndToEnd(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile

	var repairJobsBefore int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM repair_jobs`).Scan(&repairJobsBefore); err != nil {
		t.Fatalf("count repair_jobs before: %v", err)
	}

	providerID := insertTestProvider(t, db, testProviderSpec{status: "VETTING", lastHeartbeatTs: staleHeartbeat(profile)})
	const numVettingChunks = 5
	chunkIDs := make([][32]byte, numVettingChunks)
	for i := range chunkIDs {
		chunkIDs[i] = randChunkID()
		insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
			chunkID:        chunkIDs[i],
			isVettingChunk: true,
			providerID:     providerID,
			status:         "ACTIVE",
		})
	}

	var calls []penaliseCall
	detector := NewDepartureDetector(db, profile, recordingPenalise(&calls))
	if err := detector.DetectOnce(context.Background()); err != nil {
		t.Fatalf("DetectOnce: %v", err)
	}

	var providerStatus string
	if err := verify.QueryRow(`SELECT status FROM providers WHERE provider_id = $1`, providerID).
		Scan(&providerStatus); err != nil {
		t.Fatalf("query provider status: %v", err)
	}
	if providerStatus != "DEPARTED" {
		t.Errorf("provider status = %q, want DEPARTED", providerStatus)
	}

	for _, chunkID := range chunkIDs {
		var status string
		if err := verify.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
			chunkID[:], providerID).Scan(&status); err != nil {
			t.Fatalf("query chunk_assignments: %v", err)
		}
		if status != "DELETED" {
			t.Errorf("chunk %x: status = %q, want DELETED", chunkID, status)
		}
	}

	var repairJobsAfter int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM repair_jobs`).Scan(&repairJobsAfter); err != nil {
		t.Fatalf("count repair_jobs after: %v", err)
	}
	if repairJobsAfter != repairJobsBefore {
		t.Errorf("repair_jobs count changed from %d to %d, want ZERO new rows (FR-065: a VETTING departure "+
			"— all synthetic chunks — must never trigger repair)", repairJobsBefore, repairJobsAfter)
	}
}

// TestDepartureToRepairFullPipelineNoUniqueViolation is the required
// end-to-end regression test for M9 review Finding #1 (required test #2). It
// reproduces the exact scenario the review's own reproduction steps
// describe — a real ACTIVE provider with one live shard assignment, driven
// through DepartureDetector.DetectOnce -> DequeueNextJob -> ExecuteRepairJob
// using the REAL code paths (not a hand-built fixture, unlike
// setupFullPipelineFixture in executor_test.go, which starts from an
// already-dequeued synthetic job and never exercises EnqueueRepairForRealChunks
// at all) — and asserts the whole pipeline completes with no error: the old
// assignment ends DELETED, the new one ends ACTIVE.
//
// Before Fix 1, this test failed at the ExecuteRepairJob step with exactly
// the error the review predicted:
//
//	pq: duplicate key value violates unique constraint
//	"idx_chunk_assignments_one_active_per_shard"
//
// because the departed provider's old row was still status='ACTIVE' when
// preRegisterChunkAssignment tried to INSERT the replacement's row for the
// same (segment_id, shard_index) slot.
//
// Shard content is deterministic filler (randShardDataStable), not genuine
// Reed-Solomon-consistent data — matching executor_test.go's own documented
// choice: RS correctness is erasure package's own Milestone 3 concern; this
// test exercises departure-to-repair database sequencing and the unique-index
// collision specifically.
//
// [REF: ARCH §12, DM §4.5, IC §6, M9 review Finding #1]
func TestDepartureToRepairFullPipelineNoUniqueViolation(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	drainQueue(t, db)

	profile := config.DemoProfile // DataShards=3, TotalShards=5 — small, fast
	engine, err := erasure.NewEngine(profile)
	if err != nil {
		t.Fatalf("erasure.NewEngine: %v", err)
	}

	exclude := allActiveProviderIDs(t, verify)
	segmentID := insertTestSegmentChain(t, db)

	// The provider about to silently depart, holding one ACTIVE real shard —
	// the exact precondition Finding #1's collision requires.
	const departingIndex = 4
	departing := insertTestProvider(t, db, testProviderSpec{status: "ACTIVE", lastHeartbeatTs: staleHeartbeat(profile)})
	departingShardIndex := departingIndex
	chunkID := randChunkID()
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:    chunkID,
		segmentID:  &segmentID,
		shardIndex: &departingShardIndex,
		providerID: departing,
		status:     "ACTIVE",
	})
	exclude = append(exclude, departing)

	// Mocked surviving holders for every OTHER shard index (no real
	// chunk_assignments rows needed for these — ExecuteRepairJob receives
	// them as a caller-supplied SurvivingHolder list, exactly as
	// executor_test.go's own fixtures do). Each is excluded from replacement
	// selection so the test's replacement-provider assertion below is
	// unambiguous.
	holders := make([]SurvivingHolder, 0, profile.TotalShards-1)
	shardsByPeer := map[string][]byte{}
	for i := 0; i < profile.TotalShards; i++ {
		if i == departingIndex {
			continue
		}
		holderProviderID := insertTestProvider(t, db, testProviderSpec{})
		peerID := "peer-" + holderProviderID.String()
		holders = append(holders, SurvivingHolder{ProviderID: holderProviderID, PeerID: peerID, ShardIndex: i, ChunkID: randChunkID()})
		shardsByPeer[peerID] = randShardDataStable(i)
		exclude = append(exclude, holderProviderID)
	}

	// A single fresh, eligible candidate for SelectReplacementProvider to draw.
	insertTestProvider(t, db, testProviderSpec{})

	// ── 1. Detection: DetectOnce must mark departing DEPARTED, soft-delete
	// its old chunk_assignments row (Fix 1), and enqueue exactly one real
	// repair job via EnqueueRepairForRealChunks.
	var calls []penaliseCall
	detector := NewDepartureDetector(db, profile, recordingPenalise(&calls))
	if err := detector.DetectOnce(context.Background()); err != nil {
		t.Fatalf("DetectOnce: %v", err)
	}

	var oldStatusAfterDetect string
	if err := verify.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], departing).Scan(&oldStatusAfterDetect); err != nil {
		t.Fatalf("query old assignment after DetectOnce: %v", err)
	}
	if oldStatusAfterDetect != "DELETED" {
		t.Fatalf("old assignment status = %q immediately after DetectOnce, want DELETED (Fix 1) — "+
			"the replacement INSERT below would otherwise collide", oldStatusAfterDetect)
	}

	// ── 2. Dequeue the real job DetectOnce enqueued.
	job, err := DequeueNextJob(context.Background(), db)
	if err != nil {
		t.Fatalf("DequeueNextJob: %v", err)
	}
	if job == nil || job.ChunkID != chunkID {
		t.Fatalf("DequeueNextJob did not return the freshly-enqueued departure job (queue contention from another test?)")
	}

	// ── 3. Mock transport for the repair-download / chunk-upload round trips.
	var uploadedTo string
	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			switch protocolID {
			case repairDownloadProtocolID:
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, shardsByPeer[peerID]))}, nil
			case chunkUploadProtocolID:
				uploadedTo = peerID
				return &mockStream{resp: bytes.NewReader(encodeUploadResponse(uploadStatusOK))}, nil
			default:
				return nil, fmt.Errorf("unexpected protocol %q", protocolID)
			}
		},
	}
	signingKey := genTestSigningKey(t)

	// ── 4. Run the real pipeline. Before Fix 1, this is the exact step that
	// failed with the unique-constraint violation.
	if err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, holders, exclude); err != nil {
		t.Fatalf("ExecuteRepairJob: %v (this is exactly the failure Finding #1's fix closes)", err)
	}

	// ── 5. Final state: old row still DELETED, new row ACTIVE, job COMPLETED.
	var finalOldStatus string
	if err := verify.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], departing).Scan(&finalOldStatus); err != nil {
		t.Fatalf("query old assignment (final): %v", err)
	}
	if finalOldStatus != "DELETED" {
		t.Errorf("old assignment status = %q after full repair, want DELETED", finalOldStatus)
	}

	var newStatus string
	var newProviderID uuid.UUID
	if err := verify.QueryRow(`SELECT status, provider_id FROM chunk_assignments WHERE chunk_id = $1 AND status = 'ACTIVE'`,
		chunkID[:]).Scan(&newStatus, &newProviderID); err != nil {
		t.Fatalf("query new assignment: %v", err)
	}
	if newProviderID == departing {
		t.Error("the new ACTIVE assignment is still on the departed provider — replacement never took")
	}
	if uploadedTo == "" {
		t.Error("chunk-upload was never invoked")
	}

	var jobStatus string
	if err := verify.QueryRow(`SELECT status FROM repair_jobs WHERE job_id = $1`, job.JobID).Scan(&jobStatus); err != nil {
		t.Fatalf("query repair_jobs: %v", err)
	}
	if jobStatus != "COMPLETED" {
		t.Errorf("repair_jobs.status = %q, want COMPLETED", jobStatus)
	}
}

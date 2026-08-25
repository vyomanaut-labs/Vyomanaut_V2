// Package repair is declared in doc.go.
// Unit and live-database integration tests for the repair job queue.
// This file also declares the shared DB fixture plumbing (openTestDB/
// openVerifyDB/envOr/testDSN/insertTestOwner/insertTestFile/
// insertTestSegment/insertTestSegmentChain/insertTestProvider/
// insertTestChunkAssignment/randChunkID) that executor_test.go,
// departure_test.go, and assignment_test.go reuse rather than redeclaring,
// mirroring internal/audit's and internal/scoring's fixture pattern.
//
// Session 9.1.1 tests (EnqueueJob):
//   - TestEnqueueJobEmergencyFloorGetsEmergencyPriority
//   - TestEnqueueJobDepartureGetsPermanentDeparturePriority
//   - TestEnqueueJobThresholdGetsPreWarningPriority
//   - TestEnqueueJobRejectsOutOfRangeShardCountDemo
//   - TestEnqueueJobRejectsOutOfRangeShardCountProd
//   - TestEnqueueJobPanicsOnVettingChunkInDebugBuild (skips unless built with -tags debug)
//
// [REF: IC §5.7, DM §4.10, ADR-004, ADR-030, build.md Phase 9.1 Session 9.1.1]

package repair

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // registers the "postgres" driver used by openTestDB

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// ── DB fixture plumbing (reused by executor_test.go, departure_test.go, assignment_test.go) ──

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

func randChunkID() [32]byte {
	var id [32]byte
	_, _ = rand.Read(id[:])
	return id
}

func randPhone() string {
	var suffix [5]byte
	_, _ = rand.Read(suffix[:])
	return fmt.Sprintf("+91%x", suffix[:])
}

func randPubKey() []byte {
	var k [32]byte
	_, _ = rand.Read(k[:])
	return k[:]
}

// insertTestOwner inserts a throwaway owners row and returns its owner_id.
func insertTestOwner(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`INSERT INTO owners (owner_id, phone_number, ed25519_public_key) VALUES ($1,$2,$3)`,
		id, randPhone(), randPubKey())
	if err != nil {
		t.Fatalf("insertTestOwner: %v", err)
	}
	return id
}

// insertTestFile inserts a throwaway files row for ownerID and returns its file_id.
func insertTestFile(t *testing.T, db *sql.DB, ownerID uuid.UUID) uuid.UUID {
	t.Helper()
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	var tag [16]byte
	_, _ = rand.Read(tag[:])
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO files (file_id, owner_id, pointer_ciphertext, pointer_nonce, pointer_tag, original_size_bytes)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		id, ownerID, []byte("test-ciphertext"), nonce[:], tag[:], 1024)
	if err != nil {
		t.Fatalf("insertTestFile: %v", err)
	}
	return id
}

// insertTestSegment inserts a throwaway segments row for fileID at index and
// returns its segment_id.
func insertTestSegment(t *testing.T, db *sql.DB, fileID uuid.UUID, index int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`INSERT INTO segments (segment_id, file_id, segment_index) VALUES ($1,$2,$3)`,
		id, fileID, index)
	if err != nil {
		t.Fatalf("insertTestSegment: %v", err)
	}
	return id
}

// insertTestSegmentChain creates a fresh owner + file + segment (index 0) in
// one call, for tests that just need *a* valid segment_id to satisfy
// repair_jobs' foreign key and don't care about the file/owner otherwise.
func insertTestSegmentChain(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	ownerID := insertTestOwner(t, db)
	fileID := insertTestFile(t, db, ownerID)
	return insertTestSegment(t, db, fileID, 0)
}

// testProviderSpec configures the subset of providers columns repair's tests
// need to control per row (status, ASN, last heartbeat) — each call creates a
// fresh row, unlike a shared singleton, since tests need distinctly
// configured providers (VETTING vs ACTIVE, different ASNs, stale heartbeats).
type testProviderSpec struct {
	status          string     // "" defaults to "ACTIVE"
	asn             string     // "" defaults to "SIM-AS1"
	lastHeartbeatTs *time.Time // nil -> SQL NULL

	// razorpayNotLinked, when true, leaves razorpay_linked_account_id and
	// razorpay_cooling_until at their SQL NULL defaults instead of this
	// helper's usual pre-linked, already-cooled values.
	//
	// [M11 audit remediation, Finding 5] Every existing caller of this
	// helper wants a real, assignable candidate (that's what "ACTIVE" meant
	// before this finding), so the default (false) keeps every existing
	// call site producing an eligible provider without changes. Set this
	// true only to exercise the DM §8.2/§8.3 (ADR-024, FR-025) gate itself
	// — see TestSelectReplacementProviderExcludesUnlinkedRazorpayProvider
	// in assignment_test.go.
	razorpayNotLinked bool
}

func insertTestProvider(t *testing.T, db *sql.DB, spec testProviderSpec) uuid.UUID {
	t.Helper()
	status := spec.status
	if status == "" {
		status = "ACTIVE"
	}
	asn := spec.asn
	if asn == "" {
		asn = "SIM-AS1"
	}
	var linkedAccountID *string
	var coolingUntil *time.Time
	if !spec.razorpayNotLinked {
		acc := "acc_test0000000000"
		cooled := time.Now().Add(-24 * time.Hour)
		linkedAccountID = &acc
		coolingUntil = &cooled
	}
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO providers (
			provider_id, phone_number, ed25519_public_key, status,
			declared_storage_gb, city, region, asn, last_heartbeat_ts,
			razorpay_linked_account_id, razorpay_cooling_until
		) VALUES ($1,$2,$3,$4,50,'TestCity','TestRegion',$5,$6,$7,$8)`,
		id, randPhone(), randPubKey(), status, asn, spec.lastHeartbeatTs, linkedAccountID, coolingUntil,
	)
	if err != nil {
		t.Fatalf("insertTestProvider: %v", err)
	}
	return id
}

// testChunkAssignmentSpec configures a chunk_assignments row.
type testChunkAssignmentSpec struct {
	chunkID        [32]byte
	isVettingChunk bool
	segmentID      *uuid.UUID // nil for vetting chunks (chunk_assignments_segment_and_shard_null_iff_vetting)
	shardIndex     *int       // nil for vetting chunks
	providerID     uuid.UUID
	status         string // "" defaults to "ACTIVE"
}

func insertTestChunkAssignment(t *testing.T, db *sql.DB, spec testChunkAssignmentSpec) {
	t.Helper()
	status := spec.status
	if status == "" {
		status = "ACTIVE"
	}
	_, err := db.Exec(`
		INSERT INTO chunk_assignments (chunk_id, is_vetting_chunk, segment_id, shard_index, provider_id, status)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		spec.chunkID[:], spec.isVettingChunk, spec.segmentID, spec.shardIndex, spec.providerID, status,
	)
	if err != nil {
		t.Fatalf("insertTestChunkAssignment: %v", err)
	}
}

// ── EnqueueJob ─────────────────────────────────────────────────────────────────

func fetchJobPriority(t *testing.T, verify *sql.DB, chunkID [32]byte) string {
	t.Helper()
	var priority string
	if err := verify.QueryRow(`SELECT priority FROM repair_jobs WHERE chunk_id = $1`, chunkID[:]).Scan(&priority); err != nil {
		t.Fatalf("fetchJobPriority: %v", err)
	}
	return priority
}

func TestEnqueueJobEmergencyFloorGetsEmergencyPriority(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	chunkID := randChunkID()

	profile := config.DemoProfile
	err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &providerID,
		TriggerEmergencyFloor, profile.DataShards)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	if got := fetchJobPriority(t, verify, chunkID); got != "EMERGENCY" {
		t.Errorf("priority = %q, want EMERGENCY (this is the core bug fix under test)", got)
	}
}

func TestEnqueueJobDepartureGetsPermanentDeparturePriority(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trigger TriggerType
	}{
		{"silent", TriggerSilentDeparture},
		{"announced", TriggerAnnouncedDeparture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDB(t)
			verify := openVerifyDB(t)
			segmentID := insertTestSegmentChain(t, db)
			providerID := insertTestProvider(t, db, testProviderSpec{})
			chunkID := randChunkID()

			profile := config.DemoProfile
			err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &providerID,
				tc.trigger, profile.TotalShards)
			if err != nil {
				t.Fatalf("EnqueueJob: %v", err)
			}

			if got := fetchJobPriority(t, verify, chunkID); got != "PERMANENT_DEPARTURE" {
				t.Errorf("priority = %q, want PERMANENT_DEPARTURE", got)
			}
		})
	}
}

func TestEnqueueJobThresholdGetsPreWarningPriority(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	chunkID := randChunkID()

	profile := config.DemoProfile
	err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &providerID,
		TriggerThresholdWarning, profile.DataShards+profile.LazyRepairR0)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	if got := fetchJobPriority(t, verify, chunkID); got != "PRE_WARNING" {
		t.Errorf("priority = %q, want PRE_WARNING", got)
	}
}

func TestEnqueueJobRejectsOutOfRangeShardCountDemo(t *testing.T) {
	db := openTestDB(t)
	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	chunkID := randChunkID()

	profile := config.DemoProfile // DataShards=3, TotalShards=5
	err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &providerID,
		TriggerThresholdWarning, profile.TotalShards+1) // 6, out of [3,5]
	if !errors.Is(err, ErrShardCountOutOfRange) {
		t.Errorf("EnqueueJob(count=6, demo): got %v, want ErrShardCountOutOfRange", err)
	}
}

func TestEnqueueJobRejectsOutOfRangeShardCountProd(t *testing.T) {
	db := openTestDB(t)
	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	chunkID := randChunkID()

	profile := config.ProductionProfile // DataShards=16, TotalShards=56
	err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &providerID,
		TriggerThresholdWarning, profile.DataShards-1) // 15, out of [16,56]
	if !errors.Is(err, ErrShardCountOutOfRange) {
		t.Errorf("EnqueueJob(count=15, prod): got %v, want ErrShardCountOutOfRange", err)
	}
}

// TestEnqueueJobPanicsOnVettingChunkInDebugBuild only exercises anything when
// this test binary is built with -tags debug (`go test -tags debug ...`); in
// an ordinary build buildDebug is false and the panic is unreachable
// (compiled-away) code, so the test skips rather than failing.
func TestEnqueueJobPanicsOnVettingChunkInDebugBuild(t *testing.T) {
	if !buildDebug {
		t.Skip("only meaningful when built with -tags debug")
	}

	db := openTestDB(t)
	segmentID := insertTestSegmentChain(t, db) // unused by the vetting chunk itself, but keeps fixtures uniform
	_ = segmentID
	providerID := insertTestProvider(t, db, testProviderSpec{status: "VETTING"})
	chunkID := randChunkID()
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:        chunkID,
		isVettingChunk: true,
		providerID:     providerID,
	})

	defer func() {
		if r := recover(); r == nil {
			t.Error("EnqueueJob did not panic for is_vetting_chunk = TRUE in a debug build")
		}
	}()

	profile := config.DemoProfile
	_ = EnqueueJob(context.Background(), db, profile, chunkID, insertTestSegmentChain(t, db), &providerID,
		TriggerThresholdWarning, profile.DataShards)
	t.Error("unreachable: EnqueueJob should have panicked before returning")
}

// ── DequeueNextJob ─────────────────────────────────────────────────────────────

// drainQueue repeatedly calls DequeueNextJob until it returns nil, nil,
// discarding results — used to give a test a known-empty queue before
// seeding its own rows, since repair_jobs accumulates across this whole test
// binary (earlier EnqueueJob tests leave QUEUED rows behind that they never
// dequeue themselves).
func drainQueue(t *testing.T, db *sql.DB) {
	t.Helper()
	for {
		job, err := DequeueNextJob(context.Background(), db)
		if err != nil {
			t.Fatalf("drainQueue: %v", err)
		}
		if job == nil {
			return
		}
	}
}

func TestDequeueNextJobDrainsEmergencyFirst(t *testing.T) {
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
		TriggerSilentDeparture, profile.TotalShards); err != nil {
		t.Fatalf("EnqueueJob(PERMANENT_DEPARTURE): %v", err)
	}
	// Enqueued LAST, must still be dequeued FIRST.
	emergencyChunk := randChunkID()
	if err := EnqueueJob(context.Background(), db, profile, emergencyChunk, segmentID, &providerID,
		TriggerEmergencyFloor, profile.DataShards); err != nil {
		t.Fatalf("EnqueueJob(EMERGENCY): %v", err)
	}

	job, err := DequeueNextJob(context.Background(), db)
	if err != nil {
		t.Fatalf("DequeueNextJob: %v", err)
	}
	if job == nil {
		t.Fatal("DequeueNextJob returned nil, want the EMERGENCY job")
	}
	if job.ChunkID != emergencyChunk {
		t.Errorf("DequeueNextJob returned chunk %x, want the EMERGENCY chunk %x — priority ordering is broken",
			job.ChunkID, emergencyChunk)
	}
	if job.Priority != PriorityEmergency {
		t.Errorf("Priority = %v, want PriorityEmergency", job.Priority)
	}
}

func TestDequeueNextJobFIFOWithinTier(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	drainQueue(t, db)

	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	profile := config.DemoProfile

	olderChunk := randChunkID()
	if err := EnqueueJob(context.Background(), db, profile, olderChunk, segmentID, &providerID,
		TriggerThresholdWarning, profile.DataShards+profile.LazyRepairR0); err != nil {
		t.Fatalf("EnqueueJob(older): %v", err)
	}
	newerChunk := randChunkID()
	if err := EnqueueJob(context.Background(), db, profile, newerChunk, segmentID, &providerID,
		TriggerThresholdWarning, profile.DataShards+profile.LazyRepairR0); err != nil {
		t.Fatalf("EnqueueJob(newer): %v", err)
	}

	// Force olderChunk's created_at earlier so FIFO ordering is unambiguous
	// regardless of how close together the two EnqueueJob calls landed.
	if _, err := verify.Exec(`UPDATE repair_jobs SET created_at = NOW() - INTERVAL '1 hour' WHERE chunk_id = $1`,
		olderChunk[:]); err != nil {
		t.Fatalf("backdate older job: %v", err)
	}

	job, err := DequeueNextJob(context.Background(), db)
	if err != nil {
		t.Fatalf("DequeueNextJob: %v", err)
	}
	if job == nil {
		t.Fatal("DequeueNextJob returned nil, want the older job")
	}
	if job.ChunkID != olderChunk {
		t.Errorf("DequeueNextJob returned chunk %x, want the older-created_at chunk %x (FIFO within tier)",
			job.ChunkID, olderChunk)
	}
}

func TestDequeueNextJobEmptyQueueReturnsNilNil(t *testing.T) {
	db := openTestDB(t)
	drainQueue(t, db)

	job, err := DequeueNextJob(context.Background(), db)
	if err != nil {
		t.Fatalf("DequeueNextJob (empty queue): %v", err)
	}
	if job != nil {
		t.Errorf("DequeueNextJob (empty queue) = %+v, want nil (empty queue is not an error)", job)
	}
}

func TestDequeueNextJobConcurrentWorkersNoDoubleDequeue(t *testing.T) {
	db := openTestDB(t)
	drainQueue(t, db)

	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	profile := config.DemoProfile

	const n = 10
	seeded := make(map[[32]byte]bool, n)
	for i := 0; i < n; i++ {
		chunkID := randChunkID()
		if err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &providerID,
			TriggerThresholdWarning, profile.DataShards+profile.LazyRepairR0); err != nil {
			t.Fatalf("EnqueueJob(seed %d): %v", i, err)
		}
		seeded[chunkID] = true
	}

	results := make([]*RepairJob, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			// [Fixed — live verification, -race surfaced this] SELECT ... FOR
			// UPDATE SKIP LOCKED is a non-blocking dequeue by design: with n
			// concurrent transactions racing n rows, it is entirely possible
			// (and something -race's scheduling perturbation makes easier to
			// hit, not causes) for one transaction's SELECT to run at the
			// exact instant every remaining unclaimed row is momentarily
			// locked by other still-uncommitted peers. That transaction
			// correctly, harmlessly gets DequeueNextJob's documented "nil,
			// nil" empty-queue result — even though the queue is not
			// actually empty a few milliseconds later. This is not a
			// double-dequeue risk (SKIP LOCKED's actual correctness
			// property, and the one this test exists to prove, is
			// unaffected either way) — it is exactly the race
			// DequeueNextJob's own real, only caller
			// (cmd/microservice/repair_loop.go's runRepairExecutorLoop)
			// already retries on, and exactly what this file's own
			// drainQueue helper already loops on. A single-shot attempt per
			// goroutine was never a guarantee this pattern makes; retrying
			// here matches how DequeueNextJob is actually meant to be
			// called, rather than asserting a stronger single-call
			// guarantee than SKIP LOCKED provides.
			// [Bumped — live verification] This retry budget was
			// originally 20 attempts * 25ms = 500ms fixed interval. Live
			// runs still showed 2 of 10 goroutines exhausting every
			// attempt. Two changes: (1) a substantially larger budget
			// (60 * 100ms = 6s worst case) — this is a unit test with no
			// external dependency once seeded, so paying a few extra
			// seconds on the rare occasion contention is this tight costs
			// nothing real; (2) backoff staggered by goroutine index,
			// not a fixed interval — a fixed interval means every
			// still-competing goroutine wakes and retries at the exact
			// same instant every round, so if the same handful of
			// goroutines are still racing for the same handful of
			// remaining rows, a synchronized retry pattern can keep
			// reproducing the same winners and losers round after round
			// instead of converging quickly. Staggering by i breaks that
			// lockstep without needing a math/rand import.
			const maxAttempts = 60
			const retryBackoffBase = 100 * time.Millisecond
			for attempt := 0; attempt < maxAttempts; attempt++ {
				results[i], errs[i] = DequeueNextJob(context.Background(), db)
				if errs[i] != nil || results[i] != nil {
					return
				}
				time.Sleep(retryBackoffBase + time.Duration(i%7)*15*time.Millisecond)
			}
		}()
	}
	wg.Wait()

	seen := make(map[[32]byte]bool, n)
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: DequeueNextJob error: %v", i, err)
			continue
		}
		if results[i] == nil {
			t.Errorf("goroutine %d: DequeueNextJob returned nil, want a job (exactly %d were seeded)", i, n)
			continue
		}
		if seen[results[i].ChunkID] {
			t.Errorf("goroutine %d: chunk %x dequeued more than once — SKIP LOCKED did not prevent double-dequeue",
				i, results[i].ChunkID)
		}
		seen[results[i].ChunkID] = true
		if !seeded[results[i].ChunkID] {
			t.Errorf("goroutine %d: dequeued an unexpected chunk %x", i, results[i].ChunkID)
		}
	}
	if len(seen) != n {
		t.Errorf("distinct chunks dequeued = %d, want %d (no double-dequeue, none missed)", len(seen), n)
	}
}

// ── IsVettingChunk ─────────────────────────────────────────────────────────────

func TestIsVettingChunkTrueForSynthetic(t *testing.T) {
	db := openTestDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{status: "VETTING"})
	chunkID := randChunkID()
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:        chunkID,
		isVettingChunk: true,
		providerID:     providerID,
	})

	got, err := IsVettingChunk(context.Background(), db, chunkID, providerID)
	if err != nil {
		t.Fatalf("IsVettingChunk: %v", err)
	}
	if !got {
		t.Error("IsVettingChunk = false, want true for a synthetic vetting chunk")
	}
}

func TestIsVettingChunkFalseForReal(t *testing.T) {
	db := openTestDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	segmentID := insertTestSegmentChain(t, db)
	shardIndex := 0
	chunkID := randChunkID()
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:        chunkID,
		isVettingChunk: false,
		segmentID:      &segmentID,
		shardIndex:     &shardIndex,
		providerID:     providerID,
	})

	got, err := IsVettingChunk(context.Background(), db, chunkID, providerID)
	if err != nil {
		t.Fatalf("IsVettingChunk: %v", err)
	}
	if got {
		t.Error("IsVettingChunk = true, want false for a real chunk assignment")
	}
}

// ── DeleteVettingChunksOnDeparture ─────────────────────────────────────────────

func TestDeleteVettingChunksOnDepartureZeroRepairJobs(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{status: "VETTING"})
	for i := 0; i < 3; i++ {
		insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
			chunkID:        randChunkID(),
			isVettingChunk: true,
			providerID:     providerID,
		})
	}

	var before int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM repair_jobs`).Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}

	if err := DeleteVettingChunksOnDeparture(context.Background(), db, providerID); err != nil {
		t.Fatalf("DeleteVettingChunksOnDeparture: %v", err)
	}

	var after int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM repair_jobs`).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != before {
		t.Errorf("repair_jobs count changed from %d to %d, want unchanged (zero repair jobs on vetting departure, FR-065)",
			before, after)
	}
}

func TestDeleteVettingChunksOnDepartureSoftDeletesAll(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	providerID := insertTestProvider(t, db, testProviderSpec{status: "VETTING"})
	const n = 4
	chunkIDs := make([][32]byte, n)
	for i := range chunkIDs {
		chunkIDs[i] = randChunkID()
		insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
			chunkID:        chunkIDs[i],
			isVettingChunk: true,
			providerID:     providerID,
		})
	}

	if err := DeleteVettingChunksOnDeparture(context.Background(), db, providerID); err != nil {
		t.Fatalf("DeleteVettingChunksOnDeparture: %v", err)
	}

	for _, chunkID := range chunkIDs {
		var status string
		var deletedAt sql.NullTime
		if err := verify.QueryRow(`SELECT status, deleted_at FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
			chunkID[:], providerID).Scan(&status, &deletedAt); err != nil {
			t.Fatalf("query chunk_assignments: %v", err)
		}
		if status != "DELETED" {
			t.Errorf("chunk %x: status = %q, want DELETED", chunkID, status)
		}
		if !deletedAt.Valid {
			t.Errorf("chunk %x: deleted_at is NULL, want set", chunkID)
		}
	}
}

// ── MarkJobComplete ────────────────────────────────────────────────────────────

// enqueueAndDequeueOne creates one repair job and immediately dequeues it (so
// started_at is set), returning its job_id — the natural precondition for a
// job that can legally be marked complete.
func enqueueAndDequeueOne(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	drainQueue(t, db) // avoid returning an unrelated stale job below
	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	chunkID := randChunkID()
	profile := config.DemoProfile
	if err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &providerID,
		TriggerThresholdWarning, profile.DataShards+profile.LazyRepairR0); err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	job, err := DequeueNextJob(context.Background(), db)
	if err != nil {
		t.Fatalf("DequeueNextJob: %v", err)
	}
	if job == nil || job.ChunkID != chunkID {
		t.Fatalf("DequeueNextJob did not return the freshly-enqueued job (queue contention from another test?)")
	}
	return job.JobID
}

func TestMarkJobCompleteSuccess(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	jobID := enqueueAndDequeueOne(t, db)

	if err := MarkJobComplete(context.Background(), db, jobID, true, ""); err != nil {
		t.Fatalf("MarkJobComplete(success=true): %v", err)
	}

	var status string
	var completedAt sql.NullTime
	if err := verify.QueryRow(`SELECT status, completed_at FROM repair_jobs WHERE job_id = $1`, jobID).
		Scan(&status, &completedAt); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "COMPLETED" {
		t.Errorf("status = %q, want COMPLETED", status)
	}
	if !completedAt.Valid {
		t.Error("completed_at is NULL, want set")
	}
}

func TestMarkJobCompleteFailure(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	jobID := enqueueAndDequeueOne(t, db)

	// [Extended — failure_reason, live verification, M17-E Phase 17.7]
	// Asserts the new column directly, not just status/completed_at — this
	// is the exact persistence path that replaces catching a transient
	// log.Printf("[REPAIR] ...") line with a durable, queryable record.
	const wantReason = "download: exhausted 3 attempts, last error: dial tcp: connection refused"
	if err := MarkJobComplete(context.Background(), db, jobID, false, wantReason); err != nil {
		t.Fatalf("MarkJobComplete(success=false): %v", err)
	}

	var status string
	var completedAt sql.NullTime
	var failureReason sql.NullString
	if err := verify.QueryRow(`SELECT status, completed_at, failure_reason FROM repair_jobs WHERE job_id = $1`, jobID).
		Scan(&status, &completedAt, &failureReason); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "FAILED" {
		t.Errorf("status = %q, want FAILED", status)
	}
	if !completedAt.Valid {
		t.Error("completed_at is NULL, want set")
	}
	if !failureReason.Valid || failureReason.String != wantReason {
		t.Errorf("failure_reason = %+v, want %q", failureReason, wantReason)
	}
}

func TestMarkJobCompleteRejectsUnstartedJob(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	chunkID := randChunkID()
	profile := config.DemoProfile
	if err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &providerID,
		TriggerThresholdWarning, profile.DataShards+profile.LazyRepairR0); err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	var jobID uuid.UUID
	if err := verify.QueryRow(`SELECT job_id FROM repair_jobs WHERE chunk_id = $1`, chunkID[:]).Scan(&jobID); err != nil {
		t.Fatalf("lookup job_id: %v", err)
	}

	// started_at is still NULL — never dequeued.
	if err := MarkJobComplete(context.Background(), db, jobID, true, ""); err == nil {
		t.Error("MarkJobComplete on an unstarted (QUEUED) job returned nil error, " +
			"want the repair_jobs_completed_after_started CHECK to reject it")
	}
}

// ── RepairPromotionTimeout / PromoteStalePreWarningJobs ────────────────────────

func TestRepairPromotionTimeoutReturnsProfileValue(t *testing.T) {
	if got := RepairPromotionTimeout(config.DemoProfile); got != config.DemoProfile.RepairPromotionTimeout {
		t.Errorf("RepairPromotionTimeout(demo) = %v, want %v", got, config.DemoProfile.RepairPromotionTimeout)
	}
	if got := RepairPromotionTimeout(config.ProductionProfile); got != config.ProductionProfile.RepairPromotionTimeout {
		t.Errorf("RepairPromotionTimeout(prod) = %v, want %v", got, config.ProductionProfile.RepairPromotionTimeout)
	}
	// Sanity check against the documented values (MVP §3.4, ADR-031): 3
	// minutes in demo, 6 hours in production.
	if config.DemoProfile.RepairPromotionTimeout != 3*time.Minute {
		t.Errorf("config.DemoProfile.RepairPromotionTimeout = %v, want 3m", config.DemoProfile.RepairPromotionTimeout)
	}
	if config.ProductionProfile.RepairPromotionTimeout != 6*time.Hour {
		t.Errorf("config.ProductionProfile.RepairPromotionTimeout = %v, want 6h", config.ProductionProfile.RepairPromotionTimeout)
	}
}

// enqueueThresholdJob enqueues a single THRESHOLD_WARNING (PRE_WARNING
// priority) job and returns its chunk_id, for the promotion tests below.
func enqueueThresholdJob(t *testing.T, db *sql.DB) [32]byte {
	t.Helper()
	segmentID := insertTestSegmentChain(t, db)
	providerID := insertTestProvider(t, db, testProviderSpec{})
	chunkID := randChunkID()
	profile := config.DemoProfile
	if err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &providerID,
		TriggerThresholdWarning, profile.DataShards+profile.LazyRepairR0); err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	return chunkID
}

func TestPromoteStalePreWarningJobsPromotesOldOnes(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile // RepairPromotionTimeout = 3 minutes

	chunkID := enqueueThresholdJob(t, db)
	// Backdate created_at well past the 3-minute promotion timeout.
	if _, err := verify.Exec(`UPDATE repair_jobs SET created_at = NOW() - INTERVAL '1 hour' WHERE chunk_id = $1`,
		chunkID[:]); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	promoted, err := PromoteStalePreWarningJobs(context.Background(), db, profile)
	if err != nil {
		t.Fatalf("PromoteStalePreWarningJobs: %v", err)
	}
	if promoted < 1 {
		t.Errorf("promoted = %d, want >= 1 (this test's own stale job at minimum)", promoted)
	}

	if got := fetchJobPriority(t, verify, chunkID); got != "PERMANENT_DEPARTURE" {
		t.Errorf("priority = %q, want PERMANENT_DEPARTURE (promoted after exceeding RepairPromotionTimeout)", got)
	}
}

func TestPromoteStalePreWarningJobsLeavesFreshOnes(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile

	chunkID := enqueueThresholdJob(t, db) // created_at = NOW(), well within the 3-minute timeout

	if _, err := PromoteStalePreWarningJobs(context.Background(), db, profile); err != nil {
		t.Fatalf("PromoteStalePreWarningJobs: %v", err)
	}

	if got := fetchJobPriority(t, verify, chunkID); got != "PRE_WARNING" {
		t.Errorf("priority = %q, want unchanged PRE_WARNING (job is not yet stale)", got)
	}
}

func TestPromoteStalePreWarningJobsIgnoresNonQueued(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile

	chunkID := enqueueThresholdJob(t, db)
	// Move the job out of QUEUED (as DequeueNextJob would) and backdate it,
	// so it looks stale but must not be touched because it is no longer QUEUED.
	if _, err := verify.Exec(
		`UPDATE repair_jobs SET status = 'IN_PROGRESS', started_at = NOW(), created_at = NOW() - INTERVAL '1 hour' WHERE chunk_id = $1`,
		chunkID[:]); err != nil {
		t.Fatalf("move to IN_PROGRESS: %v", err)
	}

	if _, err := PromoteStalePreWarningJobs(context.Background(), db, profile); err != nil {
		t.Fatalf("PromoteStalePreWarningJobs: %v", err)
	}

	if got := fetchJobPriority(t, verify, chunkID); got != "PRE_WARNING" {
		t.Errorf("priority = %q, want unchanged PRE_WARNING (IN_PROGRESS jobs must not be promoted)", got)
	}
}

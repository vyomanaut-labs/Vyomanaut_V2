// Package repair is declared in doc.go.
// Unit and live-database integration tests for the repair executor pipeline.
// There is no real libp2p network in this test environment (see executor.go's
// own header comment on the p2p substitution) — mockTransport/mockStream
// simulate provider responses in-memory, encoding real IC §4.4.1/§4.1 wire
// frames so the actual parsing code in executor.go is genuinely exercised,
// not bypassed.
//
// Tests:
//   - TestRepairExecutorDownloadsMinimumShards
//   - TestRepairExecutorFallsBackOnHolderFailure
//   - TestRepairExecutorReconstructsCorrectShardIndex
//   - TestRepairExecutorMissingIndexNotDerivedFromHolderCount (F-16-5)
//   - TestRepairExecutorPreRegistersBeforeUpload
//   - TestRepairExecutorMarksCompleteOnSuccess
//   - TestRepairExecutorMarksFailedOnExhaustedRetries
//   - TestRepairExecutorRetriesOnStorageFullThenSucceeds (M9 review Optional
//     Fix A)
//   - TestRepairExecutorFailsAfterExhaustingStorageFullRetries (M9 review
//     Optional Fix A)
//
// [REF: IC §4.1, IC §4.4.1, IC §4.4.2, build.md Phase 9.2 Session 9.2.1,
// M9 review Optional Fix A]

package repair

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
)

// ── Mock RepairTransport / RepairStream ────────────────────────────────────────

// mockStream is an in-memory RepairStream: reads come from resp (a
// pre-built, correctly-framed response), writes go to written (captured for
// assertions).
type mockStream struct {
	resp    *bytes.Reader
	written bytes.Buffer
	closed  bool
}

func (m *mockStream) Read(p []byte) (int, error)  { return m.resp.Read(p) }
func (m *mockStream) Write(p []byte) (int, error) { return m.written.Write(p) }
func (m *mockStream) Close() error                { m.closed = true; return nil }
func (m *mockStream) SetDeadline(time.Time) error { return nil }

// mockTransport dispatches NewStream calls to a caller-supplied function,
// recording every call for assertions (e.g. "did we stop after DataShards
// downloads", "did we never contact holder X").
type mockTransport struct {
	mu    sync.Mutex
	calls []mockCall
	fn    func(peerID, protocolID string) (RepairStream, error)
}

type mockCall struct {
	peerID     string
	protocolID string
}

func (m *mockTransport) NewStream(_ context.Context, peerID string, protocolID string) (RepairStream, error) {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{peerID, protocolID})
	m.mu.Unlock()
	return m.fn(peerID, protocolID)
}

func (m *mockTransport) callCount(protocolID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c.protocolID == protocolID {
			n++
		}
	}
	return n
}

func (m *mockTransport) contacted(peerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.calls {
		if c.peerID == peerID {
			return true
		}
	}
	return false
}

// ── Wire-frame builders (mirror executor.go's own encoding, IC §4.4.1 / IC §4.1) ──

func encodeRepairDownloadResponse(status byte, chunkData []byte) []byte {
	var body []byte
	if status == repairDownloadStatusOK {
		body = append([]byte{status}, chunkData...)
	} else {
		body = []byte{status}
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(body)))
	copy(frame[4:], body)
	return frame
}

func encodeUploadResponse(status byte) []byte {
	body := []byte{status}
	if status == uploadStatusOK {
		var sig [64]byte
		body = append(body, sig[:]...)
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(body)))
	copy(frame[4:], body)
	return frame
}

// randShardDataStable returns deterministic ShardSize-length filler bytes
// keyed by index, so different holders in a test serve distinguishable
// payloads. These tests do not need RS-consistent shard content — erasure's
// own test suite (Milestone 3) covers DecodeSegment/EncodeSegment
// correctness; these tests exercise the executor's wire-protocol and
// database-sequencing logic, which only needs *some* ShardSize-length bytes
// per holder to flow through.
func randShardDataStable(index int) []byte {
	b := make([]byte, erasure.ShardSize)
	for i := range b {
		b[i] = byte(index)
	}
	return b
}

func genTestSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return priv
}

// ── downloadShards-level tests (exercise the unexported helper directly) ──────

// TestRepairDownloadRequestFrameMatchesHandlerRepairWireFormat is a direct
// regression guard for F-16-3: cmd/provider/handler_repair.go's Frame 1
// requires exactly chunk_id(32) || request_ts_ms(8) || repair_auth_sig(64)
// = 104 bytes (its own "WIRE-FORMAT CORRECTION" header note explains why —
// repair_auth_sig is signed over request_ts_ms, so the responder cannot
// verify it, or freshness-check it per ADR-036 §2, without also receiving
// that field). mockStream's canned response never validates what was
// written to it, which is exactly why the original 96-byte-frame bug
// (request_ts_ms computed for signing but never actually transmitted)
// passed every existing test in this file — this test captures and
// inspects the real written bytes instead.
func TestRepairDownloadRequestFrameMatchesHandlerRepairWireFormat(t *testing.T) {
	signingKey := genTestSigningKey(t)
	chunkID := randChunkID()
	var capturedStream *mockStream

	transport := &mockTransport{fn: func(peerID, protocolID string) (RepairStream, error) {
		capturedStream = &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, randShardDataStable(0)))}
		return capturedStream, nil
	}}

	before := time.Now().UnixMilli()
	if _, err := downloadOneShard(context.Background(), transport, signingKey, "microservice-peer", chunkID, "holder-peer"); err != nil {
		t.Fatalf("downloadOneShard: %v", err)
	}
	after := time.Now().UnixMilli()

	written := capturedStream.written.Bytes()
	const wantTotalLen = lengthPrefixSize + chunkIDFieldSize + repairRequestTsSize + repairAuthSigSize // 4 + 104 = 108
	if len(written) != wantTotalLen {
		t.Fatalf("wrote %d bytes, want %d (length prefix + chunk_id(32) + request_ts_ms(8) + repair_auth_sig(64) — handler_repair.go's corrected Frame 1 shape)",
			len(written), wantTotalLen)
	}

	gotLengthField := binary.BigEndian.Uint32(written[0:lengthPrefixSize])
	const wantLengthField = chunkIDFieldSize + repairRequestTsSize + repairAuthSigSize // 104
	if gotLengthField != wantLengthField {
		t.Fatalf("length prefix = %d, want %d", gotLengthField, wantLengthField)
	}

	tsOffset := lengthPrefixSize + chunkIDFieldSize
	gotTs := int64(binary.BigEndian.Uint64(written[tsOffset : tsOffset+repairRequestTsSize]))
	if gotTs < before || gotTs > after {
		t.Fatalf("request_ts_ms = %d, want between %d and %d — actually transmitted on the wire, not just used locally to compute the signature",
			gotTs, before, after)
	}
}

func TestRepairExecutorDownloadsMinimumShards(t *testing.T) {
	profile := config.DemoProfile // DataShards=3
	signingKey := genTestSigningKey(t)

	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, randShardDataStable(0)))}, nil
		},
	}

	// Offer 5 holders; only the first profile.DataShards (3) should ever be
	// contacted. Each holder gets its own distinct ChunkID — F-16-4: a
	// shared chunk_id across holders is exactly the bug this fixed.
	holders := []SurvivingHolder{
		{ProviderID: uuid.New(), PeerID: "peer-0", ShardIndex: 0, ChunkID: randChunkID()},
		{ProviderID: uuid.New(), PeerID: "peer-1", ShardIndex: 1, ChunkID: randChunkID()},
		{ProviderID: uuid.New(), PeerID: "peer-2", ShardIndex: 2, ChunkID: randChunkID()},
		{ProviderID: uuid.New(), PeerID: "peer-3", ShardIndex: 3, ChunkID: randChunkID()},
		{ProviderID: uuid.New(), PeerID: "peer-4", ShardIndex: 4, ChunkID: randChunkID()},
	}

	shards, err := downloadShards(context.Background(), transport, profile, signingKey, "microservice-peer", holders)
	if err != nil {
		t.Fatalf("downloadShards: %v", err)
	}
	if got := transport.callCount(repairDownloadProtocolID); got != profile.DataShards {
		t.Errorf("repair-download stream opened %d times, want exactly %d (profile.DataShards)", got, profile.DataShards)
	}
	if transport.contacted("peer-3") || transport.contacted("peer-4") {
		t.Error("downloadShards contacted holders beyond profile.DataShards — did not stop early")
	}
	for i := 0; i < profile.DataShards; i++ {
		if shards[i] == nil {
			t.Errorf("shards[%d] is nil, want a downloaded shard", i)
		}
	}
}

func TestRepairExecutorFallsBackOnHolderFailure(t *testing.T) {
	profile := config.DemoProfile // DataShards=3
	signingKey := genTestSigningKey(t)

	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			if peerID == "peer-bad" {
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusNotFound, nil))}, nil
			}
			return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, randShardDataStable(1)))}, nil
		},
	}

	// peer-bad (offered first) fails; downloadShards must fall back to the
	// remaining candidates rather than aborting. Each holder gets its own
	// distinct ChunkID — F-16-4.
	holders := []SurvivingHolder{
		{ProviderID: uuid.New(), PeerID: "peer-bad", ShardIndex: 0, ChunkID: randChunkID()},
		{ProviderID: uuid.New(), PeerID: "peer-ok-1", ShardIndex: 1, ChunkID: randChunkID()},
		{ProviderID: uuid.New(), PeerID: "peer-ok-2", ShardIndex: 2, ChunkID: randChunkID()},
		{ProviderID: uuid.New(), PeerID: "peer-ok-3", ShardIndex: 3, ChunkID: randChunkID()},
	}

	shards, err := downloadShards(context.Background(), transport, profile, signingKey, "microservice-peer", holders)
	if err != nil {
		t.Fatalf("downloadShards: %v (must fall back to the next candidate, not abort)", err)
	}
	collected := 0
	for _, s := range shards {
		if s != nil {
			collected++
		}
	}
	if collected != profile.DataShards {
		t.Errorf("collected %d shards, want %d", collected, profile.DataShards)
	}
	if shards[0] != nil {
		t.Error("shards[0] is non-nil, but peer-bad (holder for index 0) returned NOT_FOUND")
	}
}

// ── Full-pipeline tests (real erasure coding via config.DemoProfile) ──────────

// setupFullPipelineFixture builds a real AONT package, encodes it with a real
// erasure.Engine, and returns everything needed to drive ExecuteRepairJob end
// to end with one shard (missingIndex) deliberately withheld from
// survivingHolders, simulating that shard's holder having departed.
func setupFullPipelineFixture(t *testing.T, db *sql.DB, missingIndex int) (
	profile config.NetworkProfile, engine *erasure.Engine, job *RepairJob, holders []SurvivingHolder,
) {
	t.Helper()
	profile = config.DemoProfile // DataShards=3, TotalShards=5 — small AONT package, fast test

	eng, err := erasure.NewEngine(profile)
	if err != nil {
		t.Fatalf("erasure.NewEngine: %v", err)
	}
	engine = eng

	segmentID := insertTestSegmentChain(t, db)

	holders = make([]SurvivingHolder, 0, profile.TotalShards-1)
	for i := 0; i < profile.TotalShards; i++ {
		if i == missingIndex {
			continue
		}
		holderProviderID := insertTestProvider(t, db, testProviderSpec{})
		holders = append(holders, SurvivingHolder{
			ProviderID: holderProviderID,
			PeerID:     "peer-" + holderProviderID.String(),
			ShardIndex: i,
			ChunkID:    randChunkID(), // F-16-4 — each holder's own shard has its own distinct chunk_id
		})
	}

	// Enqueue and dequeue a real repair job so job.JobID has started_at set
	// (MarkJobComplete's CHECK constraint requires this — Session 9.1.3).
	// repair_jobs.provider_id has a foreign key to providers, so the
	// "departed" provider must be a real row, not just a fresh random UUID.
	// drainQueue first: repair_jobs accumulates across this whole test
	// binary and other test files' relative execution order is not
	// guaranteed, so without this, DequeueNextJob below could return an
	// unrelated stale job instead of the one this fixture just enqueued.
	drainQueue(t, db)
	departedProviderID := insertTestProvider(t, db, testProviderSpec{status: "DEPARTED"})
	chunkID := randChunkID()
	if err := EnqueueJob(context.Background(), db, profile, chunkID, segmentID, &departedProviderID,
		TriggerSilentDeparture, profile.TotalShards-1); err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	// [Added — F-16-5] Mirrors departure.go's real soft-delete ordering
	// (EnqueueJob first, then this): ExecuteRepairJob now derives
	// missingIndex via lookupShardIndexForChunk, a direct chunk_id lookup
	// against chunk_assignments, not by elimination against holders. Without
	// this row, that lookup would find nothing for a chunk_id no assignment
	// row was ever created for, and every setupFullPipelineFixture-based
	// test below would fail at that step instead of exercising what they're
	// actually meant to test.
	insertTestChunkAssignment(t, db, testChunkAssignmentSpec{
		chunkID:    chunkID,
		segmentID:  &segmentID,
		shardIndex: &missingIndex,
		providerID: departedProviderID,
		status:     "DELETED",
	})
	dequeued, err := DequeueNextJob(context.Background(), db)
	if err != nil {
		t.Fatalf("DequeueNextJob: %v", err)
	}
	if dequeued == nil || dequeued.ChunkID != chunkID {
		t.Fatalf("DequeueNextJob did not return the freshly-enqueued job (queue contention from another test?)")
	}
	job = dequeued
	return
}

func TestRepairExecutorReconstructsCorrectShardIndex(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	const missingIndex = 3
	profile, engine, job, holders := setupFullPipelineFixture(t, db, missingIndex)

	shardsByPeer := map[string][]byte{}
	for _, h := range holders {
		shardsByPeer[h.PeerID] = randShardDataStable(h.ShardIndex)
	}

	var uploadStream *mockStream
	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			switch protocolID {
			case repairDownloadProtocolID:
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, shardsByPeer[peerID]))}, nil
			case chunkUploadProtocolID:
				uploadStream = &mockStream{resp: bytes.NewReader(encodeUploadResponse(uploadStatusOK))}
				return uploadStream, nil
			default:
				return nil, fmt.Errorf("unexpected protocol %q", protocolID)
			}
		},
	}

	signingKey := genTestSigningKey(t)
	if err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, holders, exclude); err != nil {
		t.Fatalf("ExecuteRepairJob: %v", err)
	}

	if uploadStream == nil {
		t.Fatal("upload stream was never opened")
	}
	written := uploadStream.written.Bytes()
	if len(written) < 40 {
		t.Fatalf("captured upload frame too short: %d bytes", len(written))
	}
	var uploadedChunkID [32]byte
	copy(uploadedChunkID[:], written[4:36])
	uploadedIndex := binary.BigEndian.Uint32(written[36:40])

	if int(uploadedIndex) != missingIndex {
		t.Errorf("uploaded shard_index = %d, want %d (the missing index)", uploadedIndex, missingIndex)
	}
	if uploadedChunkID != job.ChunkID {
		t.Errorf("uploaded chunk_id = %x, want job.ChunkID = %x (RS re-encoding is deterministic; repair re-creates the same chunk)",
			uploadedChunkID, job.ChunkID)
	}
}

// TestRepairExecutorMissingIndexNotDerivedFromHolderCount is a direct
// regression guard for F-16-5, live-verification session 16.1.1(cont'd).
//
// cmd/microservice/repair_loop.go's findSurvivingHolders queries
// `WHERE status = 'ACTIVE'`, so it returns fewer than profile.TotalShards-1
// holders whenever a SECOND shard of the same segment is also concurrently
// non-ACTIVE — exactly what TestViabilityRepairSucceedsWithTwoOfFiveOffline
// (mvp.md §7.2) exercises live: two providers departing close together,
// each independently spawning its own repair job, each seeing only
// TotalShards-2 present shard indices instead of TotalShards-1. The old
// findMissingShardIndex inferred its answer by elimination against
// whatever holders list it was handed, and errored — "want exactly one
// missing index ... found 2" — the moment a second shard vanished from
// that count, even though THIS job only ever needs ONE specific index
// (missingIndex, its own target) and has no logical need to know anything
// about whichever OTHER shard also happens to be missing right now.
//
// This test reproduces that exact holder count (profile.DataShards, one
// fewer than setupFullPipelineFixture's normal profile.TotalShards-1) by
// dropping an extra, unrelated holder before calling ExecuteRepairJob, and
// asserts repair still succeeds and uploads to the correct index.
func TestRepairExecutorMissingIndexNotDerivedFromHolderCount(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	const missingIndex = 3
	profile, engine, job, holders := setupFullPipelineFixture(t, db, missingIndex)

	// Drop exactly one more holder (any shard index other than
	// missingIndex) — simulating findSurvivingHolders having excluded it
	// too, because ITS OWN provider is also, independently, non-ACTIVE
	// right now. profile.DataShards of the original profile.TotalShards-1
	// remain: still enough to reconstruct, but no longer "exactly one" gap
	// against profile.TotalShards.
	var trimmed []SurvivingHolder
	dropped := false
	for _, h := range holders {
		if !dropped {
			dropped = true // drop exactly one, whichever comes first
			continue
		}
		trimmed = append(trimmed, h)
	}
	if len(trimmed) != profile.DataShards {
		t.Fatalf("test setup: trimmed to %d holders, want exactly profile.DataShards (%d)", len(trimmed), profile.DataShards)
	}

	shardsByPeer := map[string][]byte{}
	for _, h := range trimmed {
		shardsByPeer[h.PeerID] = randShardDataStable(h.ShardIndex)
	}

	var uploadStream *mockStream
	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			switch protocolID {
			case repairDownloadProtocolID:
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, shardsByPeer[peerID]))}, nil
			case chunkUploadProtocolID:
				uploadStream = &mockStream{resp: bytes.NewReader(encodeUploadResponse(uploadStatusOK))}
				return uploadStream, nil
			default:
				return nil, fmt.Errorf("unexpected protocol %q", protocolID)
			}
		},
	}

	signingKey := genTestSigningKey(t)
	if err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, trimmed, exclude); err != nil {
		t.Fatalf("ExecuteRepairJob: %v (a second, unrelated missing shard in the same segment must not block repair of THIS shard — F-16-5)", err)
	}

	if uploadStream == nil {
		t.Fatal("upload stream was never opened")
	}
	written := uploadStream.written.Bytes()
	if len(written) < 40 {
		t.Fatalf("captured upload frame too short: %d bytes", len(written))
	}
	uploadedIndex := binary.BigEndian.Uint32(written[36:40])
	if int(uploadedIndex) != missingIndex {
		t.Errorf("uploaded shard_index = %d, want %d (this job's own missing index, independent of how many OTHER shards are also currently missing)",
			uploadedIndex, missingIndex)
	}
}

func TestRepairExecutorPreRegistersBeforeUpload(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	const missingIndex = 1
	profile, engine, job, holders := setupFullPipelineFixture(t, db, missingIndex)

	shardsByPeer := map[string][]byte{}
	for _, h := range holders {
		shardsByPeer[h.PeerID] = randShardDataStable(h.ShardIndex)
	}

	var sawRepairingBeforeUpload bool
	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			switch protocolID {
			case repairDownloadProtocolID:
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, shardsByPeer[peerID]))}, nil
			case chunkUploadProtocolID:
				// At the moment the upload stream opens, the chunk_assignments
				// row for job.ChunkID must already exist with status='REPAIRING'.
				// ... chunk_id alone doesn't pin a single row: repair
				// re-uploads under job.ChunkID unchanged, so the fixture's
				// original, now-DELETED assignment for the departed provider
				// shares this chunk_id too — query by provider_id as well.
				candidateID, err := uuid.Parse(peerID)
				if err != nil {
					t.Fatalf("upload peerID %q is not a valid provider UUID: %v", peerID, err)
				}
				var status string
				if err := verify.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
					job.ChunkID[:], candidateID).Scan(&status); err == nil && status == "REPAIRING" {
					sawRepairingBeforeUpload = true
				}
				return &mockStream{resp: bytes.NewReader(encodeUploadResponse(uploadStatusOK))}, nil
			default:
				return nil, fmt.Errorf("unexpected protocol %q", protocolID)
			}
		},
	}

	signingKey := genTestSigningKey(t)
	if err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, holders, exclude); err != nil {
		t.Fatalf("ExecuteRepairJob: %v", err)
	}
	if !sawRepairingBeforeUpload {
		t.Error("chunk_assignments row was not REPAIRING at the moment the upload stream opened — " +
			"pre-registration did not happen before upload (IC §4.4.2)")
	}
}

func TestRepairExecutorMarksCompleteOnSuccess(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	const missingIndex = 2
	profile, engine, job, holders := setupFullPipelineFixture(t, db, missingIndex)
	shardsByPeer := map[string][]byte{}
	for _, h := range holders {
		shardsByPeer[h.PeerID] = randShardDataStable(h.ShardIndex)
	}
	var replacementPeerID string
	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			if protocolID == repairDownloadProtocolID {
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, shardsByPeer[peerID]))}, nil
			}
			replacementPeerID = peerID
			return &mockStream{resp: bytes.NewReader(encodeUploadResponse(uploadStatusOK))}, nil
		},
	}

	signingKey := genTestSigningKey(t)
	if err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, holders, exclude); err != nil {
		t.Fatalf("ExecuteRepairJob: %v", err)
	}

	var status string
	var completedAt sql.NullTime
	if err := verify.QueryRow(`SELECT status, completed_at FROM repair_jobs WHERE job_id = $1`, job.JobID).
		Scan(&status, &completedAt); err != nil {
		t.Fatalf("query repair_jobs: %v", err)
	}
	if status != "COMPLETED" {
		t.Errorf("repair_jobs.status = %q, want COMPLETED", status)
	}
	if !completedAt.Valid {
		t.Error("completed_at is NULL, want set")
	}

	if replacementPeerID == "" {
		t.Fatal("upload stream was never opened — no replacement provider observed")
	}
	replacementID, err := uuid.Parse(replacementPeerID)
	if err != nil {
		t.Fatalf("upload peerID %q is not a valid provider UUID: %v", replacementPeerID, err)
	}
	var assignmentStatus string
	if err := verify.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		job.ChunkID[:], replacementID).Scan(&assignmentStatus); err != nil {
		t.Fatalf("query chunk_assignments: %v", err)
	}
	if assignmentStatus != "ACTIVE" {
		t.Errorf("chunk_assignments.status = %q, want ACTIVE (REPAIRING -> ACTIVE on confirmation)", assignmentStatus)
	}
}

func TestRepairExecutorMarksFailedOnExhaustedRetries(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	const missingIndex = 0
	profile, engine, job, holders := setupFullPipelineFixture(t, db, missingIndex)

	// Every holder fails (NOT_FOUND) — downloadShards can never collect
	// enough shards, so ExecuteRepairJob must fail fast and mark the job FAILED.
	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusNotFound, nil))}, nil
		},
	}

	signingKey := genTestSigningKey(t)
	err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, holders, exclude)
	if err == nil {
		t.Fatal("ExecuteRepairJob succeeded despite every holder failing, want an error")
	}

	var status string
	if err := verify.QueryRow(`SELECT status FROM repair_jobs WHERE job_id = $1`, job.JobID).Scan(&status); err != nil {
		t.Fatalf("query repair_jobs: %v", err)
	}
	if status != "FAILED" {
		t.Errorf("repair_jobs.status = %q, want FAILED", status)
	}
}

// ── STORAGE_FULL retry (M9 review Optional Fix A) ──────────────────────────────

// TestRepairExecutorRetriesOnStorageFullThenSucceeds verifies that when the
// first replacement candidate reports STORAGE_FULL (IC §4.1 status 0x04),
// ExecuteRepairJob abandons that candidate's pre-registered assignment,
// excludes it, and successfully completes against a second candidate — all
// within one call, with no error surfaced to the caller.
func TestRepairExecutorRetriesOnStorageFullThenSucceeds(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	const missingIndex = 2
	profile, engine, job, holders := setupFullPipelineFixture(t, db, missingIndex)
	shardsByPeer := map[string][]byte{}
	for _, h := range holders {
		shardsByPeer[h.PeerID] = randShardDataStable(h.ShardIndex)
	}

	var mu sync.Mutex
	var fullCandidate string // first peer we see on the upload protocol; gets STORAGE_FULL exactly once
	var uploadAttempts []string

	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			switch protocolID {
			case repairDownloadProtocolID:
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, shardsByPeer[peerID]))}, nil
			case chunkUploadProtocolID:
				mu.Lock()
				defer mu.Unlock()
				uploadAttempts = append(uploadAttempts, peerID)
				if fullCandidate == "" {
					fullCandidate = peerID
					return &mockStream{resp: bytes.NewReader(encodeUploadResponse(uploadStatusStorageFull))}, nil
				}
				return &mockStream{resp: bytes.NewReader(encodeUploadResponse(uploadStatusOK))}, nil
			default:
				return nil, fmt.Errorf("unexpected protocol %q", protocolID)
			}
		},
	}

	signingKey := genTestSigningKey(t)
	if err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, holders, exclude); err != nil {
		t.Fatalf("ExecuteRepairJob: %v (a single STORAGE_FULL from one candidate must not fail the job)", err)
	}

	mu.Lock()
	attempts := append([]string(nil), uploadAttempts...)
	mu.Unlock()
	if len(attempts) < 2 {
		t.Fatalf("expected at least 2 upload attempts (one STORAGE_FULL, one success), got %d: %v", len(attempts), attempts)
	}

	fullCandidateID, err := uuid.Parse(fullCandidate)
	if err != nil {
		t.Fatalf("parse fullCandidate peer ID as UUID: %v", err)
	}

	// The abandoned candidate's REPAIRING row must have been soft-deleted —
	// otherwise it would permanently block this shard slot.
	var abandonedStatus string
	if err := verify.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		job.ChunkID[:], fullCandidateID).Scan(&abandonedStatus); err != nil {
		t.Fatalf("query abandoned candidate's row: %v", err)
	}
	if abandonedStatus != "DELETED" {
		t.Errorf("abandoned candidate's chunk_assignments.status = %q, want DELETED", abandonedStatus)
	}

	var finalStatus string
	var finalProviderID uuid.UUID
	if err := verify.QueryRow(`SELECT status, provider_id FROM chunk_assignments WHERE chunk_id = $1 AND status = 'ACTIVE'`,
		job.ChunkID[:]).Scan(&finalStatus, &finalProviderID); err != nil {
		t.Fatalf("query final ACTIVE assignment: %v", err)
	}
	if finalProviderID == fullCandidateID {
		t.Error("final ACTIVE assignment is still on the candidate that reported STORAGE_FULL")
	}

	var jobStatus string
	if err := verify.QueryRow(`SELECT status FROM repair_jobs WHERE job_id = $1`, job.JobID).Scan(&jobStatus); err != nil {
		t.Fatalf("query repair_jobs: %v", err)
	}
	if jobStatus != "COMPLETED" {
		t.Errorf("repair_jobs.status = %q, want COMPLETED", jobStatus)
	}
}

// TestRepairExecutorRetriesOnUnreachableCandidateThenSucceeds is the
// ErrReplacementUnreachable sibling of TestRepairExecutorRetriesOnStorageFullThenSucceeds
// (design council verdict on TestReplacementProviderDepartsMidRepair, live
// evidence: a chunk-upload stream reset by a replacement killed mid-transfer).
// A candidate that cannot be reached at all — transport.NewStream itself
// failing, never a wire response — must be retried exactly like a
// STORAGE_FULL candidate: abandon its slot, try another, do not fail the
// whole job on one unlucky draw.
func TestRepairExecutorRetriesOnUnreachableCandidateThenSucceeds(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	const missingIndex = 2
	profile, engine, job, holders := setupFullPipelineFixture(t, db, missingIndex)
	shardsByPeer := map[string][]byte{}
	for _, h := range holders {
		shardsByPeer[h.PeerID] = randShardDataStable(h.ShardIndex)
	}

	var mu sync.Mutex
	var unreachableCandidate string // first peer we see on the upload protocol; connection fails exactly once
	var uploadAttempts []string

	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			switch protocolID {
			case repairDownloadProtocolID:
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, shardsByPeer[peerID]))}, nil
			case chunkUploadProtocolID:
				mu.Lock()
				defer mu.Unlock()
				uploadAttempts = append(uploadAttempts, peerID)
				if unreachableCandidate == "" {
					unreachableCandidate = peerID
					// Simulates exactly what killing a replacement
					// mid-transfer produced live: transport.NewStream
					// itself fails, never a wire response.
					return nil, fmt.Errorf("read tcp: connection reset by peer")
				}
				return &mockStream{resp: bytes.NewReader(encodeUploadResponse(uploadStatusOK))}, nil
			default:
				return nil, fmt.Errorf("unexpected protocol %q", protocolID)
			}
		},
	}

	signingKey := genTestSigningKey(t)
	if err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, holders, exclude); err != nil {
		t.Fatalf("ExecuteRepairJob: %v (one unreachable candidate must not fail the job)", err)
	}

	mu.Lock()
	attempts := append([]string(nil), uploadAttempts...)
	mu.Unlock()
	if len(attempts) < 2 {
		t.Fatalf("expected at least 2 upload attempts (one unreachable, one success), got %d: %v", len(attempts), attempts)
	}

	unreachableCandidateID, err := uuid.Parse(unreachableCandidate)
	if err != nil {
		t.Fatalf("parse unreachableCandidate peer ID as UUID: %v", err)
	}

	// The abandoned candidate's REPAIRING row must have been soft-deleted —
	// otherwise it would permanently block this shard slot.
	var abandonedStatus string
	if err := verify.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		job.ChunkID[:], unreachableCandidateID).Scan(&abandonedStatus); err != nil {
		t.Fatalf("query abandoned candidate's row: %v", err)
	}
	if abandonedStatus != "DELETED" {
		t.Errorf("abandoned candidate's chunk_assignments.status = %q, want DELETED", abandonedStatus)
	}

	var finalStatus string
	var finalProviderID uuid.UUID
	if err := verify.QueryRow(`SELECT status, provider_id FROM chunk_assignments WHERE chunk_id = $1 AND status = 'ACTIVE'`,
		job.ChunkID[:]).Scan(&finalStatus, &finalProviderID); err != nil {
		t.Fatalf("query final ACTIVE assignment: %v", err)
	}
	if finalProviderID == unreachableCandidateID {
		t.Error("final ACTIVE assignment is still on the candidate that was unreachable")
	}

	var jobStatus string
	if err := verify.QueryRow(`SELECT status FROM repair_jobs WHERE job_id = $1`, job.JobID).Scan(&jobStatus); err != nil {
		t.Fatalf("query repair_jobs: %v", err)
	}
	if jobStatus != "COMPLETED" {
		t.Errorf("repair_jobs.status = %q, want COMPLETED", jobStatus)
	}
}

// TestRepairExecutorFailsAfterExhaustingUnreachableRetries is the
// ErrReplacementUnreachable sibling of
// TestRepairExecutorFailsAfterExhaustingStorageFullRetries: if EVERY
// candidate is unreachable, ExecuteRepairJob must still give up after
// exactly maxRepairReplacementRetries attempts, mark the job FAILED, and
// wrap ErrReplacementUnreachable — the bounded retry mitigates, it does not
// guarantee (see errors.go's own doc comment on ErrReplacementUnreachable
// for why the residual gap is tracked as an open LTS research question).
func TestRepairExecutorFailsAfterExhaustingUnreachableRetries(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	const missingIndex = 1
	profile, engine, job, holders := setupFullPipelineFixture(t, db, missingIndex)
	shardsByPeer := map[string][]byte{}
	for _, h := range holders {
		shardsByPeer[h.PeerID] = randShardDataStable(h.ShardIndex)
	}

	var uploadAttempts int32
	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			switch protocolID {
			case repairDownloadProtocolID:
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, shardsByPeer[peerID]))}, nil
			case chunkUploadProtocolID:
				atomic.AddInt32(&uploadAttempts, 1)
				return nil, fmt.Errorf("read tcp: connection reset by peer")
			default:
				return nil, fmt.Errorf("unexpected protocol %q", protocolID)
			}
		},
	}

	signingKey := genTestSigningKey(t)
	err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, holders, exclude)
	if err == nil {
		t.Fatal("ExecuteRepairJob succeeded despite every candidate being unreachable, want an error")
	}
	if !errors.Is(err, ErrReplacementUnreachable) {
		t.Errorf("got %v, want an error wrapping ErrReplacementUnreachable", err)
	}

	if got := atomic.LoadInt32(&uploadAttempts); got != maxRepairReplacementRetries {
		t.Errorf("upload attempts = %d, want exactly %d (the bounded retry budget)", got, maxRepairReplacementRetries)
	}

	var jobStatus string
	if err := verify.QueryRow(`SELECT status FROM repair_jobs WHERE job_id = $1`, job.JobID).Scan(&jobStatus); err != nil {
		t.Fatalf("query repair_jobs: %v", err)
	}
	if jobStatus != "FAILED" {
		t.Errorf("repair_jobs.status = %q, want FAILED", jobStatus)
	}
}

// TestRepairExecutorFailsAfterExhaustingStorageFullRetries verifies that
// when EVERY candidate reports STORAGE_FULL, ExecuteRepairJob gives up after
// exactly maxRepairReplacementRetries attempts, marks the job FAILED, wraps
// ErrReplacementStorageFull in the returned error, and leaves no dangling
// ACTIVE/REPAIRING chunk_assignments row for the shard behind — every
// attempted candidate's row must have been abandoned, not left to block a
// future repair attempt at this slot.
func TestRepairExecutorFailsAfterExhaustingStorageFullRetries(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := allActiveProviderIDs(t, verify)

	const missingIndex = 1
	profile, engine, job, holders := setupFullPipelineFixture(t, db, missingIndex)
	shardsByPeer := map[string][]byte{}
	for _, h := range holders {
		shardsByPeer[h.PeerID] = randShardDataStable(h.ShardIndex)
	}

	var uploadAttempts int32
	transport := &mockTransport{
		fn: func(peerID, protocolID string) (RepairStream, error) {
			switch protocolID {
			case repairDownloadProtocolID:
				return &mockStream{resp: bytes.NewReader(encodeRepairDownloadResponse(repairDownloadStatusOK, shardsByPeer[peerID]))}, nil
			case chunkUploadProtocolID:
				atomic.AddInt32(&uploadAttempts, 1)
				return &mockStream{resp: bytes.NewReader(encodeUploadResponse(uploadStatusStorageFull))}, nil
			default:
				return nil, fmt.Errorf("unexpected protocol %q", protocolID)
			}
		},
	}

	signingKey := genTestSigningKey(t)
	err := ExecuteRepairJob(context.Background(), db, profile, transport, engine, signingKey, "microservice-peer",
		job, holders, exclude)
	if err == nil {
		t.Fatal("ExecuteRepairJob succeeded despite every candidate reporting STORAGE_FULL, want an error")
	}
	if !errors.Is(err, ErrReplacementStorageFull) {
		t.Errorf("got %v, want an error wrapping ErrReplacementStorageFull", err)
	}

	if got := atomic.LoadInt32(&uploadAttempts); got != maxRepairReplacementRetries {
		t.Errorf("upload attempts = %d, want exactly %d (the bounded retry budget)", got, maxRepairReplacementRetries)
	}

	var jobStatus string
	if err := verify.QueryRow(`SELECT status FROM repair_jobs WHERE job_id = $1`, job.JobID).Scan(&jobStatus); err != nil {
		t.Fatalf("query repair_jobs: %v", err)
	}
	if jobStatus != "FAILED" {
		t.Errorf("repair_jobs.status = %q, want FAILED", jobStatus)
	}

	var danglingCount int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM chunk_assignments WHERE chunk_id = $1 AND status IN ('ACTIVE', 'REPAIRING')`,
		job.ChunkID[:]).Scan(&danglingCount); err != nil {
		t.Fatalf("count dangling assignments: %v", err)
	}
	if danglingCount != 0 {
		t.Errorf("dangling ACTIVE/REPAIRING chunk_assignments rows for this chunk = %d, want 0 after exhausted retries", danglingCount)
	}
}

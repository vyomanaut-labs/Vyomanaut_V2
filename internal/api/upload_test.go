// Package api is declared in doc.go.
// Tests for upload.go: Session 11.7.1.

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/repair"
)

// ── Shared fixtures ────────────────────────────────────────────────────────

// insertTestOwnerWithEscrow creates an owner and, if depositPaise > 0, a
// matching DEPOSIT event, then refreshes mv_owner_escrow_balance. The owner
// row and deposit event are written on db (whatever connection the caller
// passed, ordinarily openTestDB's vyomanaut_app — both are unprotected by
// RLS, so this works fine there); the REFRESH is done on a separate,
// privileged openVerifyDB connection, since vyomanaut_app does not own this
// materialized view (see refreshEscrowBalance in provider_test.go for the
// same reasoning, applied there to mv_provider_escrow_balance).
func insertTestOwnerWithEscrow(t *testing.T, db *sql.DB, depositPaise int64) uuid.UUID {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	var id uuid.UUID
	if err := db.QueryRow(`INSERT INTO owners (phone_number, ed25519_public_key) VALUES ($1, $2) RETURNING owner_id`,
		randPhoneForOwner(), []byte(pub)).Scan(&id); err != nil {
		t.Fatalf("insert test owner: %v", err)
	}
	if depositPaise > 0 {
		if _, err := db.Exec(`INSERT INTO owner_escrow_events (owner_id, event_type, amount_paise, idempotency_key) VALUES ($1, 'DEPOSIT', $2, $3)`,
			id, depositPaise, uuid.New().String()); err != nil {
			t.Fatalf("insert owner escrow deposit: %v", err)
		}
		verify := openVerifyDB(t)
		if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW mv_owner_escrow_balance`); err != nil {
			t.Fatalf("refresh mv_owner_escrow_balance: %v", err)
		}
	}
	return id
}

// [M11 audit remediation, Finding 5 — extended] razorpay_linked_account_id
// must be set (not just razorpay_cooling_until in the past) for this
// provider to clear the DM §8.2/§8.3 (ADR-024, FR-025) gate that
// repair.SelectReplacementProvider now applies — and, since ADR-072/073,
// that function is also what upload.assignSegment calls for the *initial*
// shard assignment this whole test file exercises. Before this gate
// existed, razorpay_cooling_until in the past was already sufficient for
// "eligible"; now both columns are checked, and every caller of this helper
// was silently failing with INSUFFICIENT_ASN_DIVERSITY (all candidates
// filtered out) until this fix.
func insertActiveProviderWithASN(t *testing.T, db *sql.DB, asn string) uuid.UUID {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}
	var id uuid.UUID
	err = db.QueryRow(`
		INSERT INTO providers (phone_number, ed25519_public_key, declared_storage_gb, city, region, asn,
		                        status, razorpay_linked_account_id, razorpay_cooling_until, last_known_multiaddrs)
		VALUES ($1, $2, 100, 'Mumbai', 'Mumbai', $3, 'ACTIVE', 'acc_test0000000000', NOW() - interval '1 day',
		        '["/ip4/198.51.100.1/udp/4001/quic-v1/p2p/testupload"]'::jsonb)
		RETURNING provider_id`,
		randPhoneForOwner(), []byte(pub), asn,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert active provider: %v", err)
	}
	return id
}

// newReadyEvaluator builds a ReadinessEvaluator using this package's own
// existing readiness_test.go helpers (loadedClusterSecretCache,
// MockClusterMembership, StubRelayNodeCounter) — reused rather than
// reimplemented.
func newReadyEvaluator(t *testing.T, db *sql.DB, profile config.NetworkProfile) *ReadinessEvaluator {
	t.Helper()
	return NewReadinessEvaluator(db, profile, loadedClusterSecretCache(t), MockClusterMembership{}, StubRelayNodeCounter{})
}

// seedReadyDemoProviderPool seeds exactly profile.MinDistinctASNs ACTIVE
// providers, one per distinct ASN, one region — enough to satisfy
// DemoProfile's readiness gate (MinActiveProviders=5, MinDistinctASNs=5,
// MinMetroRegions=1, MinCooledAccounts=5) and, not coincidentally, exactly
// enough for one demo segment's 5 shards at demo's 1-shard-per-ASN cap.
//
// quarantineOtherActiveProviders runs first because openTestDB's
// accumulating database (see otherActiveProviderIDs below) means earlier
// tests' leftover ACTIVE providers don't just make "only 5 ASNs exist"
// false — repair.SelectReplacementProvider's Power-of-Two-Choices draw
// (bounded to maxReplacementSelectionAttempts=5 attempts of 2 random
// candidates each) can fail outright against a large, ASN-skewed
// accumulated pool, well before this test's own 5-ASN cap is anywhere
// near exhausted. Confirmed in CI: "Current distinct ASNs: 13" — far more
// than this test seeds itself.
func seedReadyDemoProviderPool(t *testing.T, db *sql.DB) {
	t.Helper()
	quarantineOtherActiveProviders(t, db)
	for i := 1; i <= config.DemoProfile.MinDistinctASNs; i++ {
		insertActiveProviderWithASN(t, db, fmt.Sprintf("SIM-AS%d", i))
	}
}

// quarantineOtherActiveProviders marks every currently-ACTIVE provider as
// DEPARTED so this test's own freshly-seeded pool is the only one
// repair.SelectReplacementProvider's random candidate draw can select
// from — the same "isolate against the accumulating test DB" need
// otherActiveProviderIDs exists for, applied here via status flip since
// HandleAssign (unlike a direct SelectReplacementProvider call) offers no
// exclude-list injection point. Safe because every test in this file
// seeds its own fresh ACTIVE providers rather than depending on another
// test's leftover ones remaining ACTIVE — confirmed DemoProfile.
// MinActiveProviders (5) exactly matches MinDistinctASNs (5), so this
// test's own 5 still satisfy the readiness gate on their own.
func quarantineOtherActiveProviders(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`UPDATE providers SET status = 'DEPARTED' WHERE status = 'ACTIVE'`); err != nil {
		t.Fatalf("quarantineOtherActiveProviders: %v", err)
	}
}

func decodeUploadAssignResponse(t *testing.T, body []byte) uploadAssignResponseBody {
	t.Helper()
	var resp uploadAssignResponseBody
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode upload assign response: %v (body: %s)", err, body)
	}
	return resp
}

// fakeSegmentChunkIDs builds one segment's worth of client-submitted,
// content-hash-shaped chunk_ids for a HandleAssign request (ADR-073) — one
// random 32-byte value per shard, matching what internal/client/upload's
// orchestrator would compute via sha256.Sum256(shard) in real use. Tests
// in this file don't need the values to actually be real content hashes
// of anything (HandleAssign only validates shape: length and hex
// encoding), so randChunkID's existing helper (provider_test.go) is reused
// directly rather than duplicated.
func fakeSegmentChunkIDs(t *testing.T, segIdx, totalShards int) segmentChunkIDsRequestBody {
	t.Helper()
	ids := make([]string, totalShards)
	for i := range ids {
		id := randChunkID(t)
		ids[i] = fmt.Sprintf("%x", id)
	}
	return segmentChunkIDsRequestBody{SegmentIndex: segIdx, ChunkIDs: ids}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.7.1 — Upload Assign
// ═══════════════════════════════════════════════════════════════════════

func TestUploadAssignRejectsWhenNetworkNotReady(t *testing.T) {
	db := openTestDB(t)
	ownerID := insertTestOwnerWithEscrow(t, db, 100_000_00) // plenty of escrow; readiness is what should fail
	// No providers seeded at all -> readiness must fail.
	evaluator := NewReadinessEvaluator(db, config.DemoProfile, unloadedClusterSecretCache(), MockClusterMembership{}, StubRelayNodeCounter{})

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)

	reqBody := uploadAssignRequestBody{
		FileID: uuid.New(), NumSegments: 1, OriginalSizeBytes: 1024,
		Segments: []segmentChunkIDsRequestBody{fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)},
	}
	body, _ := json.Marshal(reqBody)
	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w := httptest.NewRecorder()

	h.HandleAssign(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body = %s", w.Code, w.Body.String())
	}
	var errResp networkNotReadyErrorBody
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errResp.RetryAfter != 60 {
		t.Fatalf("retry_after = %d, want 60", errResp.RetryAfter)
	}
	if errResp.ErrorCode != ErrNetworkNotReady {
		t.Fatalf("error_code = %q, want %q", errResp.ErrorCode, ErrNetworkNotReady)
	}
}

func TestUploadAssignRejectsInsufficientEscrow(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerID := insertTestOwnerWithEscrow(t, db, 1) // 1 paise: nowhere near 30 days of storage
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)

	reqBody := uploadAssignRequestBody{
		FileID: uuid.New(), NumSegments: 1, OriginalSizeBytes: 10 * 1024 * 1024 * 1024, // 10 GB
		Segments: []segmentChunkIDsRequestBody{fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)},
	}
	body, _ := json.Marshal(reqBody)
	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w := httptest.NewRecorder()

	h.HandleAssign(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", w.Code, w.Body.String())
	}
}

func TestUploadAssignIdempotentOnFileID(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerID := insertTestOwnerWithEscrow(t, db, 100_000_00)
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)
	fileID := uuid.New()
	reqBody := uploadAssignRequestBody{
		FileID: fileID, NumSegments: 1, OriginalSizeBytes: 1024,
		Segments: []segmentChunkIDsRequestBody{fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)},
	}
	body, _ := json.Marshal(reqBody)

	r1 := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w1 := httptest.NewRecorder()
	h.HandleAssign(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first call: status = %d, body = %s", w1.Code, w1.Body.String())
	}
	first := decodeUploadAssignResponse(t, w1.Body.Bytes())

	r2 := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w2 := httptest.NewRecorder()
	h.HandleAssign(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second call: status = %d, body = %s", w2.Code, w2.Body.String())
	}
	second := decodeUploadAssignResponse(t, w2.Body.Bytes())

	if len(first.Assignments) != 1 || len(second.Assignments) != 1 {
		t.Fatalf("expected exactly 1 segment in both responses, got %d and %d", len(first.Assignments), len(second.Assignments))
	}
	firstShards, secondShards := first.Assignments[0].Providers, second.Assignments[0].Providers
	if len(firstShards) != len(secondShards) {
		t.Fatalf("shard count changed between calls: %d vs %d", len(firstShards), len(secondShards))
	}
	for i := range firstShards {
		if firstShards[i].ProviderID != secondShards[i].ProviderID {
			t.Fatalf("shard %d provider changed between calls: %v vs %v", i, firstShards[i].ProviderID, secondShards[i].ProviderID)
		}
		if firstShards[i].ChunkID != secondShards[i].ChunkID {
			t.Fatalf("shard %d chunk_id changed between calls: %v vs %v", i, firstShards[i].ChunkID, secondShards[i].ChunkID)
		}
		if firstShards[i].CapabilityToken == secondShards[i].CapabilityToken {
			t.Fatalf("shard %d capability_token did not change between idempotent calls (must be refreshed with a new expiry)", i)
		}
	}
}

func TestUploadAssignShardIndexRangeDemo(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerID := insertTestOwnerWithEscrow(t, db, 100_000_00)
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)
	reqBody := uploadAssignRequestBody{
		FileID: uuid.New(), NumSegments: 1, OriginalSizeBytes: 1024,
		Segments: []segmentChunkIDsRequestBody{fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)},
	}
	body, _ := json.Marshal(reqBody)
	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w := httptest.NewRecorder()

	h.HandleAssign(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeUploadAssignResponse(t, w.Body.Bytes())
	if len(resp.Assignments) != 1 {
		t.Fatalf("segments = %d, want 1", len(resp.Assignments))
	}
	shards := resp.Assignments[0].Providers
	if len(shards) != config.DemoProfile.TotalShards {
		t.Fatalf("shards = %d, want %d (profile.TotalShards)", len(shards), config.DemoProfile.TotalShards)
	}
	seen := make(map[int]bool)
	for _, s := range shards {
		if s.ShardIndex < 0 || s.ShardIndex >= config.DemoProfile.TotalShards {
			t.Fatalf("shard_index %d out of range [0, %d)", s.ShardIndex, config.DemoProfile.TotalShards)
		}
		seen[s.ShardIndex] = true
	}
	if len(seen) != config.DemoProfile.TotalShards {
		t.Fatalf("distinct shard_index values = %d, want %d (0..DataShards-1 data, DataShards..TotalShards-1 parity, profile.DataShards=%d)",
			len(seen), config.DemoProfile.TotalShards, config.DemoProfile.DataShards)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// ADR-073 — client-submitted, per-segment content-hash chunk_id
// ═══════════════════════════════════════════════════════════════════════

// TestUploadAssignPersistsSubmittedChunkIDVerbatim is this decision's core
// guarantee: the chunk_id returned (and, transitively, the one
// capability_token is bound to via respondWithFreshTokens) is exactly what
// the client submitted — never a server-generated value. Directly guards
// against a regression back to the rand.Read behavior ADR-073 replaced.
func TestUploadAssignPersistsSubmittedChunkIDVerbatim(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerID := insertTestOwnerWithEscrow(t, db, 100_000_00)
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)

	submitted := fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)
	reqBody := uploadAssignRequestBody{
		FileID: uuid.New(), NumSegments: 1, OriginalSizeBytes: 1024,
		Segments: []segmentChunkIDsRequestBody{submitted},
	}
	body, _ := json.Marshal(reqBody)
	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w := httptest.NewRecorder()

	h.HandleAssign(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeUploadAssignResponse(t, w.Body.Bytes())
	if len(resp.Assignments) != 1 {
		t.Fatalf("segments = %d, want 1", len(resp.Assignments))
	}
	gotByShard := make(map[int]string, len(resp.Assignments[0].Providers))
	for _, s := range resp.Assignments[0].Providers {
		gotByShard[s.ShardIndex] = s.ChunkID
	}
	for shardIdx, wantChunkID := range submitted.ChunkIDs {
		got, ok := gotByShard[shardIdx]
		if !ok {
			t.Fatalf("no assignment returned for shard %d", shardIdx)
		}
		if got != wantChunkID {
			t.Fatalf("shard %d: chunk_id = %s, want %s (submitted verbatim, not server-generated)", shardIdx, got, wantChunkID)
		}
	}
}

// TestUploadAssignAcceptsSegmentsIncrementally exercises ADR-073's actual
// shape change: a 2-segment file assigned via two separate calls, segment
// 0 first (as internal/client/upload's orchestrator now does — see that
// package's own tests), segment 1 once the client has finished encoding
// it. The second call must not re-run readiness/escrow (asserted
// indirectly: no provider pool re-seed, no escrow re-deposit between
// calls, yet the second call still succeeds) and the final response must
// contain both segments.
func TestUploadAssignAcceptsSegmentsIncrementally(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerID := insertTestOwnerWithEscrow(t, db, 100_000_00)
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)
	fileID := uuid.New()

	seg0 := fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)
	req1 := uploadAssignRequestBody{FileID: fileID, NumSegments: 2, OriginalSizeBytes: 2048, Segments: []segmentChunkIDsRequestBody{seg0}}
	body1, _ := json.Marshal(req1)
	r1 := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body1)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w1 := httptest.NewRecorder()
	h.HandleAssign(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first call (segment 0 only): status = %d, body = %s", w1.Code, w1.Body.String())
	}
	first := decodeUploadAssignResponse(t, w1.Body.Bytes())
	if len(first.Assignments) != 1 {
		t.Fatalf("first call: segments = %d, want 1 (only segment 0 submitted so far)", len(first.Assignments))
	}

	seg1 := fakeSegmentChunkIDs(t, 1, config.DemoProfile.TotalShards)
	req2 := uploadAssignRequestBody{FileID: fileID, NumSegments: 2, OriginalSizeBytes: 2048, Segments: []segmentChunkIDsRequestBody{seg1}}
	body2, _ := json.Marshal(req2)
	r2 := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body2)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w2 := httptest.NewRecorder()
	h.HandleAssign(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second call (segment 1 only): status = %d, body = %s", w2.Code, w2.Body.String())
	}
	second := decodeUploadAssignResponse(t, w2.Body.Bytes())
	if len(second.Assignments) != 2 {
		t.Fatalf("second call: segments = %d, want 2 (segment 0 persisted + segment 1 newly assigned)", len(second.Assignments))
	}

	bySegIdx := make(map[int]segmentAssignmentBody, len(second.Assignments))
	for _, seg := range second.Assignments {
		bySegIdx[seg.SegmentIndex] = seg
	}
	if _, ok := bySegIdx[0]; !ok {
		t.Fatalf("segment 0 missing from second call's response")
	}
	if _, ok := bySegIdx[1]; !ok {
		t.Fatalf("segment 1 missing from second call's response")
	}
	// Segment 0's chunk_ids must be unchanged from the first call — the
	// second call's ASN pool exhaustion (or any other segment-0-only
	// state) must never re-derive segment 0.
	seg0Shards := bySegIdx[0].Providers
	firstSeg0Shards := first.Assignments[0].Providers
	if len(seg0Shards) != len(firstSeg0Shards) {
		t.Fatalf("segment 0 shard count changed: %d vs %d", len(firstSeg0Shards), len(seg0Shards))
	}
	firstByShard := make(map[int]string, len(firstSeg0Shards))
	for _, s := range firstSeg0Shards {
		firstByShard[s.ShardIndex] = s.ChunkID
	}
	for _, s := range seg0Shards {
		if firstByShard[s.ShardIndex] != s.ChunkID {
			t.Fatalf("segment 0 shard %d chunk_id changed across calls: %s vs %s", s.ShardIndex, firstByShard[s.ShardIndex], s.ChunkID)
		}
	}
}

// TestUploadAssignRejectsEmptySegments confirms the request-shape
// validation ADR-073 introduces: a call naming zero segments is a 400,
// never silently accepted or treated as a readiness/escrow-only probe.
func TestUploadAssignRejectsEmptySegments(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerID := insertTestOwnerWithEscrow(t, db, 100_000_00)
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)

	reqBody := uploadAssignRequestBody{FileID: uuid.New(), NumSegments: 1, OriginalSizeBytes: 1024}
	body, _ := json.Marshal(reqBody)
	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w := httptest.NewRecorder()

	h.HandleAssign(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

// TestUploadAssignRejectsWrongChunkIDCount confirms a segment whose
// chunk_ids length doesn't equal profile.TotalShards is rejected, not
// silently truncated or padded.
func TestUploadAssignRejectsWrongChunkIDCount(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerID := insertTestOwnerWithEscrow(t, db, 100_000_00)
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)

	short := fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards-1) // one too few
	reqBody := uploadAssignRequestBody{
		FileID: uuid.New(), NumSegments: 1, OriginalSizeBytes: 1024,
		Segments: []segmentChunkIDsRequestBody{short},
	}
	body, _ := json.Marshal(reqBody)
	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w := httptest.NewRecorder()

	h.HandleAssign(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

// TestUploadAssignRejectsMalformedChunkIDHex confirms a chunk_id that
// doesn't decode to exactly 32 bytes of hex is rejected before any DB
// write, rather than persisted as garbage or silently truncated.
func TestUploadAssignRejectsMalformedChunkIDHex(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerID := insertTestOwnerWithEscrow(t, db, 100_000_00)
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)

	seg := fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)
	seg.ChunkIDs[0] = "not-hex-and-also-not-32-bytes"
	reqBody := uploadAssignRequestBody{
		FileID: uuid.New(), NumSegments: 1, OriginalSizeBytes: 1024,
		Segments: []segmentChunkIDsRequestBody{seg},
	}
	body, _ := json.Marshal(reqBody)
	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w := httptest.NewRecorder()

	h.HandleAssign(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

// TestUploadAssignRejectsDuplicateSegmentIndex confirms two entries naming
// the same segment_index within one request is a 400, not a silent
// last-write-wins or an attempted (and FK/unique-constraint-failing)
// double INSERT.
func TestUploadAssignRejectsDuplicateSegmentIndex(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerID := insertTestOwnerWithEscrow(t, db, 100_000_00)
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)

	seg0a := fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)
	seg0b := fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)
	reqBody := uploadAssignRequestBody{
		FileID: uuid.New(), NumSegments: 1, OriginalSizeBytes: 1024,
		Segments: []segmentChunkIDsRequestBody{seg0a, seg0b},
	}
	body, _ := json.Marshal(reqBody)
	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerID, Role: "owner"})
	w := httptest.NewRecorder()

	h.HandleAssign(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

// otherActiveProviderIDs returns every currently-ACTIVE provider_id not
// among excludeASNs — used to seed SelectReplacementProvider's exclude list
// so a test's own small, concentrated ASN set is the only eligible pool.
// Needed because openTestDB (readiness_test.go) opens the same accumulating
// database for every test in the run, with no per-test isolation or
// rollback: without this, leftover providers seeded by earlier tests (many
// distinct ASNs) would make an "only N ASNs exist" assumption false.
func otherActiveProviderIDs(t *testing.T, db *sql.DB, excludeASNs ...string) []uuid.UUID {
	t.Helper()
	rows, err := db.Query(`SELECT provider_id FROM providers WHERE status = 'ACTIVE' AND asn != ALL($1)`, pq.Array(excludeASNs))
	if err != nil {
		t.Fatalf("query other active providers: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Fatalf("close rows: %v", err)
		}
	}()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan provider id: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

// selectAndPersist calls repair.SelectReplacementProvider and, on success,
// immediately inserts the resulting chunk_assignments row — required
// because asnWithinCap's cap check counts EXISTING chunk_assignments rows
// for segmentID; a test that only calls SelectReplacementProvider in a loop
// without persisting each pick would never accumulate any per-ASN count, so
// the cap could never actually trigger (this was the actual bug behind this
// test's first two failed attempts — not a production-code issue).
func selectAndPersist(t *testing.T, db *sql.DB, profile config.NetworkProfile, segmentID uuid.UUID, shardIndex int, exclude []uuid.UUID) (uuid.UUID, error) {
	t.Helper()
	providerID, err := repair.SelectReplacementProvider(context.Background(), db, profile, segmentID, exclude)
	if err != nil {
		return uuid.UUID{}, err
	}
	chunkID := randChunkID(t)
	if _, err := db.Exec(`
		INSERT INTO chunk_assignments (chunk_id, is_vetting_chunk, segment_id, shard_index, provider_id, status)
		VALUES ($1, FALSE, $2, $3, $4, 'ACTIVE')`,
		chunkID[:], segmentID, shardIndex, providerID); err != nil {
		t.Fatalf("persist chunk assignment: %v", err)
	}
	return providerID, nil
}

func TestUploadAssignRejectsASNDiversityDemo(t *testing.T) {
	db := openTestDB(t)
	// Only 2 distinct ASNs, well under DemoProfile's cap-per-ASN=1 needing
	// 5 distinct ASNs for 5 shards. Every other currently-ACTIVE provider
	// (from other tests sharing this database) is pre-excluded so this
	// test's own 2-ASN pool is the only one SelectReplacementProvider can
	// actually draw from.
	exclude := otherActiveProviderIDs(t, db, "AS100", "AS200")
	for i := 0; i < 3; i++ {
		insertActiveProviderWithASN(t, db, "AS100")
		insertActiveProviderWithASN(t, db, "AS200")
	}

	ownerID := insertTestOwnerWithEscrow(t, db, 0)
	fileID := uuid.New()
	insertPlaceholderFile(t, db, fileID, ownerID, 1024)
	var segmentID uuid.UUID
	if err := db.QueryRow(`INSERT INTO segments (file_id, segment_index) VALUES ($1, 0) RETURNING segment_id`, fileID).Scan(&segmentID); err != nil {
		t.Fatalf("insert segment: %v", err)
	}

	var lastErr error
	for i := 0; i < config.DemoProfile.TotalShards; i++ {
		providerID, err := selectAndPersist(t, db, config.DemoProfile, segmentID, i, exclude)
		if err != nil {
			lastErr = err
			break
		}
		exclude = append(exclude, providerID)
	}
	if !errors.Is(lastErr, repair.ErrNoEligibleReplacement) {
		t.Fatalf("err = %v, want repair.ErrNoEligibleReplacement (2 ASNs x cap 1 = 2 max, needed %d)", lastErr, config.DemoProfile.TotalShards)
	}
}

// TestUploadAssignRejectsASNDiversityProd verifies ProductionProfile's ASN
// cap value itself (11 = floor(56*0.20)), rather than exercising the full
// cap-exhaustion path via live inserts the way
// TestUploadAssignRejectsASNDiversityDemo does. Inserting real
// chunk_assignments rows past shard_index=4 requires a database migrated
// with the prod schema, but this project's live-DB test convention
// (openTestDB, PGDATABASE) always targets a demo-schema database — see
// internal/repair's own tests, which use config.ProductionProfile only for
// pure SelectReplacementProvider calls that never INSERT a row, and reserve
// DemoProfile for every test that does. The demo-scale exhaustion test
// above already proves the underlying SelectReplacementProvider/ASN-cap
// mechanism this handler depends on correctly returns
// repair.ErrNoEligibleReplacement when placement is infeasible; this test
// exists to additionally pin the specific numeric cap value production
// mode computes, without requiring a prod-schema database.
func TestUploadAssignRejectsASNDiversityProd(t *testing.T) {
	const wantCap = 11 // floor(56 * 0.20)
	got := int(math.Floor(float64(config.ProductionProfile.TotalShards) * config.ProductionProfile.ASNCapFraction))
	if got != wantCap {
		t.Fatalf("floor(TotalShards * ASNCapFraction) = %d, want %d (3 ASNs at this cap would allow at most 33 of the 56 required shards)", got, wantCap)
	}
}

// ── M11 audit remediation, Finding 2 (redesigned against ADR-072/073) ──────

// TestAssignSegmentRollsBackOnPartialFailure exercises assignSegment
// directly (not through HandleAssign) so it can force ErrNoEligibleReplacement
// partway through the shard loop — 2 distinct ASNs at cap-per-ASN=1 can place
// only 2 of DemoProfile's 5 shards — and then check, via a separate
// connection, that the segment left behind by the failed call has ZERO
// chunk_assignments rows, not the 2 that placed before the pool ran out.
// Before assignSegment wrapped its writes in a transaction, those 2 would
// have stayed committed individually, leaving a permanently under-replicated
// segment that HandleAssign's idempotency check (now segment-complete-aware,
// see its own comment) would otherwise be able to observe and never retry.
func TestAssignSegmentRollsBackOnPartialFailure(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	exclude := otherActiveProviderIDs(t, db, "AS100", "AS200")
	insertActiveProviderWithASN(t, db, "AS100")
	insertActiveProviderWithASN(t, db, "AS200")

	ownerID := insertTestOwnerWithEscrow(t, db, 0)
	fileID := uuid.New()
	insertPlaceholderFile(t, db, fileID, ownerID, 1024)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, nil)
	chunkIDs := make([][32]byte, config.DemoProfile.TotalShards)
	for i := range chunkIDs {
		chunkIDs[i] = randChunkID(t)
	}

	_, err := h.assignSegment(context.Background(), fileID, 0, chunkIDs, exclude)
	if !errors.Is(err, repair.ErrNoEligibleReplacement) {
		t.Fatalf("assignSegment err = %v, want repair.ErrNoEligibleReplacement (2 ASNs x cap 1 = 2 max, needed %d)", err, config.DemoProfile.TotalShards)
	}

	var segmentCount, shardCount int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM segments WHERE file_id = $1`, fileID).Scan(&segmentCount); err != nil {
		t.Fatalf("count segments: %v", err)
	}
	if err := verify.QueryRow(`
		SELECT COUNT(*) FROM chunk_assignments ca JOIN segments s ON s.segment_id = ca.segment_id
		WHERE s.file_id = $1`, fileID).Scan(&shardCount); err != nil {
		t.Fatalf("count chunk_assignments: %v", err)
	}
	if segmentCount != 0 || shardCount != 0 {
		t.Fatalf("after rollback: segments = %d, chunk_assignments = %d, want 0 and 0 (partial write leaked past the failed transaction)", segmentCount, shardCount)
	}
}

// TestUploadAssignCreatePlaceholderFileSurvivesRetry confirms
// createPlaceholderFile's ON CONFLICT DO NOTHING lets a second call with the
// same (file_id, owner_id) succeed instead of hitting files_pkey — the
// retry path a client takes after an earlier call got past this insert but
// failed a later check in the same request (e.g. Check 2.5, provider
// capacity) before any segment was written.
func TestUploadAssignCreatePlaceholderFileSurvivesRetry(t *testing.T) {
	db := openTestDB(t)
	ownerID := insertTestOwnerWithEscrow(t, db, 0)
	fileID := uuid.New()

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, nil)

	if err := h.createPlaceholderFile(context.Background(), fileID, ownerID, 1024); err != nil {
		t.Fatalf("first createPlaceholderFile: %v", err)
	}
	if err := h.createPlaceholderFile(context.Background(), fileID, ownerID, 1024); err != nil {
		t.Fatalf("retry createPlaceholderFile (same file_id) should be a no-op, not an error: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM files WHERE file_id = $1`, fileID).Scan(&count); err != nil {
		t.Fatalf("count files: %v", err)
	}
	if count != 1 {
		t.Fatalf("files rows for file_id = %d, want exactly 1", count)
	}
}

// TestUploadAssignRejectsMismatchedOwnerOnExistingFile is the regression
// test for the cross-owner authorization gap found while fixing Finding 2:
// req.FileID is entirely client-chosen (ADR-073), and before HandleAssign's
// new ownership check, a second owner submitting the SAME file_id as an
// existing one — whether that file already has assigned segments or is
// still an empty placeholder from a first owner's failed attempt — would
// fall through the idempotency path onto the FIRST owner's file, either
// reading back their live capability tokens or writing new segments onto a
// files row it does not own.
func TestUploadAssignRejectsMismatchedOwnerOnExistingFile(t *testing.T) {
	db := openTestDB(t)
	seedReadyDemoProviderPool(t, db)
	ownerA := insertTestOwnerWithEscrow(t, db, 100_000_00)
	ownerB := insertTestOwnerWithEscrow(t, db, 100_000_00)
	evaluator := newReadyEvaluator(t, db, config.DemoProfile)

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewUploadAssignHandler(db, config.DemoProfile, msPriv, evaluator)
	fileID := uuid.New()
	reqBody := uploadAssignRequestBody{
		FileID: fileID, NumSegments: 1, OriginalSizeBytes: 1024,
		Segments: []segmentChunkIDsRequestBody{fakeSegmentChunkIDs(t, 0, config.DemoProfile.TotalShards)},
	}
	body, _ := json.Marshal(reqBody)

	// Owner A creates and fully assigns fileID.
	rA := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerA, Role: "owner"})
	wA := httptest.NewRecorder()
	h.HandleAssign(wA, rA)
	if wA.Code != http.StatusOK {
		t.Fatalf("owner A call: status = %d, body = %s", wA.Code, wA.Body.String())
	}

	// Owner B submits the identical file_id.
	rB := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/upload/assign", bytes.NewReader(body)),
		VerifiedClaims{Subject: ownerB, Role: "owner"})
	wB := httptest.NewRecorder()
	h.HandleAssign(wB, rB)
	if wB.Code != http.StatusForbidden {
		t.Fatalf("owner B call: status = %d, body = %s, want 403 RESOURCE_OWNER_MISMATCH", wB.Code, wB.Body.String())
	}
	var errBody errorBody
	if err := json.Unmarshal(wB.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errBody.ErrorCode != ErrResourceOwnerMismatch {
		t.Fatalf("error_code = %q, want %q", errBody.ErrorCode, ErrResourceOwnerMismatch)
	}
}

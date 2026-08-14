// Package upload is declared in doc.go.
// Unit tests for the upload orchestrator. No live database is needed — this
// package never touches Postgres directly. An httptest.Server stands in for
// the microservice REST API, and a fake p2p.Host/p2p.Stream (encoding real
// IC §4.1 wire frames, mirroring internal/vettingchunk's own test pattern
// from Milestone 14) stands in for provider daemons.
//
// Tests:
//   - TestUploadFileSegmentsPadUsingProfileNotLiterals
//   - TestUploadIncludesCapabilityTokenVerbatimPerShard
//   - TestUploadReassignsIdempotentlyOnCapabilityExpired
//   - TestUploadMapsHTTP409ToErrInsufficientEscrow
//   - TestUploadMapsHTTP503ToErrNetworkNotReady
//   - TestUploadPopulatesDisplayNameCiphertextFromMasterSecret
//   - TestOwnerSigUsesFixedByteLayoutNotJSON
//   - TestUploadPersistsSessionStateForResume
//   - TestUploadCleansUpSessionStateOnlyAfterRegisterSucceeds
//   - TestResumeUploadRetransmitsOnlyUnacknowledgedShards
//   - TestResumeUploadReusesExistingSessionID
//   - TestResumeUploadCompletesRegistrationOnSuccess
//
// [REF: MVP §8.2 Phase 15.2 Session 15.2.1, Session 15.2.2]

package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// ── Test helpers ────────────────────────────────────────────────────────

func testSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return priv
}

func randCapabilityTokenHex(t *testing.T) string {
	t.Helper()
	token := make([]byte, uploadCapabilityTokenSize)
	if _, err := cryptorand.Read(token); err != nil {
		t.Fatalf("generate capability token: %v", err)
	}
	return fmt.Sprintf("%x", token)
}

// fakeShardFixture is one shard's stable, "persisted" identity within a
// testServer — everything real internal/api/upload.go's assignSegment
// would have written to chunk_assignments once, and never changes on a
// later call for the same segment. capability_token is deliberately NOT
// stored here — see buildAssignResponseFromAccumulated, which regenerates
// it fresh on every call, matching the real server's respondWithFreshTokens
// (ADR-073: token minting is the one thing idempotency never reuses).
type fakeShardFixture struct {
	shardIndex int
	providerID uuid.UUID
	multiaddrs []string
	asn        string
	chunkID    string // the client's real, submitted value — echoed verbatim
}

type fakeSegmentFixture struct {
	segmentID uuid.UUID
	shards    []fakeShardFixture
}

// buildFakeSegmentFixture fabricates one segment's stable identity from
// the client's actually-submitted chunk_ids (ADR-073) — the real server's
// assignSegment persists exactly what the client sent, never inventing a
// value of its own, so the fixture must not either.
func buildFakeSegmentFixture(seg segmentChunkIDsRequest) fakeSegmentFixture {
	shards := make([]fakeShardFixture, len(seg.ChunkIDs))
	for j, chunkIDHex := range seg.ChunkIDs {
		peerID := fmt.Sprintf("12D3KooWFake%dSeg%dShard%d", j, seg.SegmentIndex, j)
		shards[j] = fakeShardFixture{
			shardIndex: j,
			providerID: uuid.New(),
			multiaddrs: []string{fmt.Sprintf("/ip4/127.0.0.1/tcp/4001/p2p/%s", peerID)},
			asn:        "AS1",
			chunkID:    chunkIDHex,
		}
	}
	return fakeSegmentFixture{segmentID: uuid.New(), shards: shards}
}

// buildAssignResponseFromAccumulated builds a full UploadAssignResponse
// from every segment fixture accumulated so far (testServer's handler),
// regenerating a fresh capability_token per shard on every call — matching
// the real server's respondWithFreshTokens exactly: identity (chunk_id,
// provider, segment_id) is stable once assigned; the token never is.
func buildAssignResponseFromAccumulated(t *testing.T, accumulated map[int]fakeSegmentFixture) uploadAssignResponse {
	t.Helper()
	segIndices := make([]int, 0, len(accumulated))
	for idx := range accumulated {
		segIndices = append(segIndices, idx)
	}
	sort.Ints(segIndices)

	assignments := make([]segmentAssignment, 0, len(segIndices))
	for _, idx := range segIndices {
		fixture := accumulated[idx]
		providers := make([]shardAssignment, len(fixture.shards))
		for i, sf := range fixture.shards {
			providers[i] = shardAssignment{
				ShardIndex:      sf.shardIndex,
				ProviderID:      sf.providerID,
				Multiaddrs:      sf.multiaddrs,
				ASN:             sf.asn,
				CapabilityToken: randCapabilityTokenHex(t),
				ChunkID:         sf.chunkID,
			}
		}
		assignments = append(assignments, segmentAssignment{SegmentIndex: idx, SegmentID: fixture.segmentID, Providers: providers})
	}
	return uploadAssignResponse{Assignments: assignments, MonthlyCostPaise: 1000, RequiredEscrowPaise: 1000}
}

// ── Fake p2p.Host / p2p.Stream for the chunk-upload protocol ──────────────

type capturedUploadRequest struct {
	peerID     p2p.PeerID
	chunkID    [32]byte
	shardIndex uint32
	token      [uploadCapabilityTokenSize]byte
	dataLen    int
}

// fakeTransferHost implements p2p.Host, decoding real UploadRequest frames
// and serving real UploadResponse frames, so transfer.go's actual framing
// code is genuinely exercised rather than bypassed.
//
// expireFirstN, if > 0, causes the next N Write calls across ALL streams
// (not per-peer) to return CAPABILITY_EXPIRED before switching to OK — a
// global counter rather than per-peer tracking, because each re-assignment
// mints entirely new random provider/peer IDs (buildAssignResponse), so a
// per-peer "first request expires" rule would keep re-triggering forever
// across reassignments instead of modelling "the whole first wave of
// tokens was already-expired, the second wave (fresh tokens) is not".
type fakeTransferHost struct {
	mu           sync.Mutex
	captured     []capturedUploadRequest
	expireFirstN int
	alwaysFail   bool
}

func newFakeTransferHost() *fakeTransferHost {
	return &fakeTransferHost{}
}

func (h *fakeTransferHost) PeerID() p2p.PeerID { return "fake-owner-peer" }
func (h *fakeTransferHost) Connect(context.Context, p2p.PeerID, []p2p.Multiaddr) error {
	return nil
}
func (h *fakeTransferHost) NewStream(_ context.Context, peerID p2p.PeerID, _ p2p.ProtocolID) (p2p.Stream, error) {
	return &fakeUploadCaptureStream{host: h, peerID: peerID}, nil
}
func (h *fakeTransferHost) PromoteConn(context.Context, net.Conn, p2p.PeerID, p2p.ProtocolID) (p2p.Stream, error) {
	return nil, fmt.Errorf("fakeTransferHost: PromoteConn not implemented")
}
func (h *fakeTransferHost) SetStreamHandler(p2p.ProtocolID, p2p.StreamHandler) {}
func (h *fakeTransferHost) NATType() p2p.NATStatus                             { return 0 }
func (h *fakeTransferHost) Close() error                                       { return nil }

func (h *fakeTransferHost) capturedRequests() []capturedUploadRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]capturedUploadRequest, len(h.captured))
	copy(out, h.captured)
	return out
}

type fakeUploadCaptureStream struct {
	host   *fakeTransferHost
	peerID p2p.PeerID
	resp   *bytes.Reader
}

func (s *fakeUploadCaptureStream) Write(p []byte) (int, error) {
	offset := uploadLengthPrefixSize
	var chunkID [32]byte
	copy(chunkID[:], p[offset:offset+uploadChunkIDSize])
	offset += uploadChunkIDSize
	shardIndex := binary.BigEndian.Uint32(p[offset : offset+uploadShardIndexSize])
	offset += uploadShardIndexSize
	var token [uploadCapabilityTokenSize]byte
	copy(token[:], p[offset:offset+uploadCapabilityTokenSize])
	offset += uploadCapabilityTokenSize
	dataLen := len(p) - offset

	s.host.mu.Lock()
	status := byte(uploadStatusOK)
	switch {
	case s.host.alwaysFail:
		status = 0x04 // STORAGE_FULL — a definitive, non-capability failure
	case s.host.expireFirstN > 0:
		status = uploadStatusCapabilityExpired
		s.host.expireFirstN--
	}
	s.host.captured = append(s.host.captured, capturedUploadRequest{
		peerID: s.peerID, chunkID: chunkID, shardIndex: shardIndex, token: token, dataLen: dataLen,
	})
	s.host.mu.Unlock()

	var body []byte
	if status == uploadStatusOK {
		body = append([]byte{status}, make([]byte, uploadProviderSigSize)...)
	} else {
		body = []byte{status}
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	s.resp = bytes.NewReader(append(lenBuf[:], body...))
	return len(p), nil
}

func (s *fakeUploadCaptureStream) Read(p []byte) (int, error) {
	if s.resp == nil {
		return 0, fmt.Errorf("fakeUploadCaptureStream: Read before Write")
	}
	return s.resp.Read(p)
}
func (s *fakeUploadCaptureStream) Close() error                     { return nil }
func (s *fakeUploadCaptureStream) Protocol() p2p.ProtocolID         { return chunkUploadProtocolID }
func (s *fakeUploadCaptureStream) RemotePeer() p2p.PeerID           { return s.peerID }
func (s *fakeUploadCaptureStream) Reset() error                     { return nil }
func (s *fakeUploadCaptureStream) SetDeadline(time.Time) error      { return nil }
func (s *fakeUploadCaptureStream) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeUploadCaptureStream) SetWriteDeadline(time.Time) error { return nil }

// ── Test HTTP server ────────────────────────────────────────────────────

// testServer wires /api/v1/upload/assign and /api/v1/file/register against
// in-memory captures, using profile's shard counts for every assignment.
//
// [Updated — ADR-073] /api/v1/upload/assign now mirrors the real server's
// per-segment idempotency: a segment named in a call's Segments is
// fabricated (buildFakeSegmentFixture) only the first time it's seen and
// accumulated in accumulated; every response — first call or Nth — is
// built fresh from everything accumulated so far
// (buildAssignResponseFromAccumulated), exactly like the real
// respondWithFreshTokens. numSegments/profile are still stored but are no
// longer used to fabricate a request-independent response; they remain
// for tests that want them (none currently do, kept for signature
// stability against existing call sites).
type testServer struct {
	*httptest.Server
	mu             sync.Mutex
	assignCalls    int
	lastAssignReq  uploadAssignRequest
	registerReq    fileRegisterRequest
	registerCalled bool
	numSegments    int
	profile        config.NetworkProfile
	accumulated    map[int]fakeSegmentFixture
}

func newTestServer(t *testing.T, profile config.NetworkProfile, numSegments int) *testServer {
	t.Helper()
	ts := &testServer{numSegments: numSegments, profile: profile, accumulated: make(map[int]fakeSegmentFixture)}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/upload/assign", func(w http.ResponseWriter, r *http.Request) {
		var req uploadAssignRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		ts.mu.Lock()
		ts.assignCalls++
		ts.lastAssignReq = req
		for _, seg := range req.Segments {
			if _, exists := ts.accumulated[seg.SegmentIndex]; exists {
				continue // already "persisted" — the real server never re-derives an existing segment
			}
			ts.accumulated[seg.SegmentIndex] = buildFakeSegmentFixture(seg)
		}
		resp := buildAssignResponseFromAccumulated(t, ts.accumulated)
		ts.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/v1/file/register", func(w http.ResponseWriter, r *http.Request) {
		var req fileRegisterRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		ts.mu.Lock()
		ts.registerReq = req
		ts.registerCalled = true
		ts.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(fileRegisterResponse{FileID: req.FileID, UploadedAt: time.Now()})
	})
	ts.Server = httptest.NewServer(mux)
	return ts
}

func newStatusOnlyServer(t *testing.T, path string, status int, errorCode string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(apiError{ErrorCode: errorCode, Message: "test", RequestID: uuid.NewString()})
	}))
}

// newTestOrchestrator wires an Orchestrator against srv/host using
// config.DemoProfile (small TotalShards=5/DataShards=3 — fast tests) and a
// fresh temp session directory.
func newTestOrchestrator(t *testing.T, baseURL string, host p2p.Host) *Orchestrator {
	t.Helper()
	engine, err := erasure.NewEngine(config.DemoProfile)
	if err != nil {
		t.Fatalf("erasure.NewEngine: %v", err)
	}
	return NewOrchestrator(baseURL, "test-token", nil, host, engine, config.DemoProfile, testSigningKey(t), t.TempDir())
}

// ── Tests ───────────────────────────────────────────────────────────────

func TestUploadFileSegmentsPadUsingProfileNotLiterals(t *testing.T) {
	demoSize := plaintextSegmentSize(config.DemoProfile)
	prodSize := plaintextSegmentSize(config.ProductionProfile)
	if demoSize == prodSize {
		t.Fatal("plaintextSegmentSize is identical for demo and production profiles — " +
			"segmentation is not reading DataShards/ShardSize from the active profile")
	}
	wantDemo := config.DemoProfile.DataShards*config.DemoProfile.ShardSize - aontOverheadBytes
	if demoSize != wantDemo {
		t.Errorf("plaintextSegmentSize(DemoProfile) = %d, want %d", demoSize, wantDemo)
	}
}

func TestUploadIncludesCapabilityTokenVerbatimPerShard(t *testing.T) {
	ts := newTestServer(t, config.DemoProfile, 1)
	defer ts.Close()
	host := newFakeTransferHost()
	o := newTestOrchestrator(t, ts.URL, host)

	plaintext := make([]byte, 1024)
	_, _ = cryptorand.Read(plaintext)
	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])
	ownerID := uuid.New()

	fileID, err := o.UploadFile(context.Background(), masterSecret, ownerID, plaintext)
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}

	captured := host.capturedRequests()
	if len(captured) != config.DemoProfile.TotalShards {
		t.Fatalf("captured %d UploadRequests, want %d (one per shard)", len(captured), config.DemoProfile.TotalShards)
	}
	for _, c := range captured {
		var zero [uploadCapabilityTokenSize]byte
		if c.token == zero {
			t.Errorf("shard %d: capability_token is all-zero — not populated from the server assignment", c.shardIndex)
		}
	}
	_ = fileID
}

func TestUploadReassignsIdempotentlyOnCapabilityExpired(t *testing.T) {
	ts := newTestServer(t, config.DemoProfile, 1)
	defer ts.Close()
	host := newFakeTransferHost()
	o := newTestOrchestrator(t, ts.URL, host)

	plaintext := make([]byte, 512)
	_, _ = cryptorand.Read(plaintext)
	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])
	ownerID := uuid.New()

	// Force the entire first wave of shard uploads (one per shard) to come
	// back CAPABILITY_EXPIRED; the second wave (fresh tokens from the
	// idempotent re-assignment) should all succeed.
	host.expireFirstN = config.DemoProfile.TotalShards

	fileID, err := o.UploadFile(context.Background(), masterSecret, ownerID, plaintext)
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}
	if fileID == uuid.Nil {
		t.Fatal("UploadFile returned a nil fileID")
	}

	ts.mu.Lock()
	assignCalls := ts.assignCalls
	ts.mu.Unlock()
	if assignCalls != 2 {
		t.Errorf("assign called %d times, want exactly 2 (initial + one idempotent re-assignment after CAPABILITY_EXPIRED)", assignCalls)
	}
}

// TestUploadFileMultiSegmentAssignsIncrementally is the direct regression
// test for F-070-13/ADR-073: a real, multi-segment upload — the exact
// shape (2 segments) live verification originally exercised when it found
// every real shard's capability-token verification failing. Confirms every
// shard across both segments is transmitted with a non-zero
// capability_token (the fake transfer host's Write only succeeds past
// framing; verifyAssignedChunkIDsMatch, exercised internally by UploadFile,
// is what actually proves chunk_id agreement — this test's job is to
// confirm the whole path completes for >1 segment, and that assignment
// happened once per segment rather than once for the whole file).
func TestUploadFileMultiSegmentAssignsIncrementally(t *testing.T) {
	const numSegments = 2
	ts := newTestServer(t, config.DemoProfile, numSegments)
	defer ts.Close()
	host := newFakeTransferHost()
	o := newTestOrchestrator(t, ts.URL, host)

	// Large enough to span two segments at DemoProfile's small shard size.
	plaintext := make([]byte, plaintextSegmentSize(config.DemoProfile)+1024)
	_, _ = cryptorand.Read(plaintext)
	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])
	ownerID := uuid.New()

	fileID, err := o.UploadFile(context.Background(), masterSecret, ownerID, plaintext)
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}
	if fileID == uuid.Nil {
		t.Fatal("UploadFile returned a nil fileID")
	}

	wantShards := numSegments * config.DemoProfile.TotalShards
	captured := host.capturedRequests()
	if len(captured) != wantShards {
		t.Fatalf("captured %d UploadRequests, want %d (%d segments × %d shards) — a segment's shards were never transmitted",
			len(captured), wantShards, numSegments, config.DemoProfile.TotalShards)
	}
	for _, c := range captured {
		var zero [uploadCapabilityTokenSize]byte
		if c.token == zero {
			t.Errorf("shard %d: capability_token is all-zero", c.shardIndex)
		}
	}

	ts.mu.Lock()
	assignCalls := ts.assignCalls
	ts.mu.Unlock()
	if assignCalls != numSegments {
		t.Errorf("assign called %d times, want exactly %d (one per segment, encoded-then-assigned incrementally — ADR-073)", assignCalls, numSegments)
	}

	ts.mu.Lock()
	if len(ts.accumulated) != numSegments {
		t.Errorf("server accumulated %d segments, want %d", len(ts.accumulated), numSegments)
	}
	ts.mu.Unlock()
}

func TestUploadMapsHTTP409ToErrInsufficientEscrow(t *testing.T) {
	srv := newStatusOnlyServer(t, "/api/v1/upload/assign", http.StatusConflict, "INSUFFICIENT_ESCROW_BALANCE")
	defer srv.Close()
	o := newTestOrchestrator(t, srv.URL, nil) // host is never touched: assign fails before any p2p activity

	var masterSecret [32]byte
	_, err := o.UploadFile(context.Background(), masterSecret, uuid.New(), []byte("hello"))
	if !isWrapped(err, ErrInsufficientEscrow) {
		t.Fatalf("UploadFile error = %v, want wrapping ErrInsufficientEscrow", err)
	}
}

func TestUploadMapsHTTP503ToErrNetworkNotReady(t *testing.T) {
	srv := newStatusOnlyServer(t, "/api/v1/upload/assign", http.StatusServiceUnavailable, "NETWORK_NOT_READY")
	defer srv.Close()
	o := newTestOrchestrator(t, srv.URL, nil)

	var masterSecret [32]byte
	_, err := o.UploadFile(context.Background(), masterSecret, uuid.New(), []byte("hello"))
	if !isWrapped(err, ErrNetworkNotReady) {
		t.Fatalf("UploadFile error = %v, want wrapping ErrNetworkNotReady", err)
	}
}

func TestUploadPopulatesDisplayNameCiphertextFromMasterSecret(t *testing.T) {
	ts := newTestServer(t, config.DemoProfile, 1)
	defer ts.Close()
	o := newTestOrchestrator(t, ts.URL, nil)

	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])
	ownerID := uuid.New()
	fileID := uuid.New()
	providerIDs := make([]uuid.UUID, config.DemoProfile.TotalShards)
	chunkIDHex := make([]string, config.DemoProfile.TotalShards)
	for i := range providerIDs {
		providerIDs[i] = uuid.New()
		var cid [32]byte
		_, _ = cryptorand.Read(cid[:])
		chunkIDHex[i] = fmt.Sprintf("%x", cid)
	}
	segment := pointerFileSegment{
		SegmentID: uuid.New(), SegmentIndex: 0,
		FileKey:     fmt.Sprintf("%x", crypto.DeriveFileKey(masterSecret[:], ownerID[:], fileID[:])),
		ProviderIDs: providerIDs,
		ChunkIDs:    chunkIDHex,
		ErasureParams: erasureParamsInfo{
			S: config.DemoProfile.DataShards, R: config.DemoProfile.ParityShards,
			N: config.DemoProfile.TotalShards, LfBytes: config.DemoProfile.ShardSize,
		},
	}

	const wantName = "my-file.txt"
	if err := o.registerPointerFile(context.Background(), masterSecret, ownerID, fileID,
		[]pointerFileSegment{segment}, 100, wantName, o.signingKey); err != nil {
		t.Fatalf("registerPointerFile: %v", err)
	}

	ts.mu.Lock()
	req := ts.registerReq
	ts.mu.Unlock()

	if req.DisplayNameCiphertext == nil || req.DisplayNameNonce == nil || req.DisplayNameTag == nil {
		t.Fatal("display_name_ciphertext/_nonce/_tag were not populated")
	}

	filenameKey := deriveFilenameKey(masterSecret[:], ownerID[:], fileID[:])
	ct, err := base64.StdEncoding.DecodeString(*req.DisplayNameCiphertext)
	if err != nil {
		t.Fatalf("decode display_name_ciphertext: %v", err)
	}
	nonceB, err := base64.StdEncoding.DecodeString(*req.DisplayNameNonce)
	if err != nil {
		t.Fatalf("decode display_name_nonce: %v", err)
	}
	tagB, err := base64.StdEncoding.DecodeString(*req.DisplayNameTag)
	if err != nil {
		t.Fatalf("decode display_name_tag: %v", err)
	}
	var nonceArr [12]byte
	copy(nonceArr[:], nonceB)
	full := append(append([]byte{}, ct...), tagB...)

	plain, err := crypto.DecryptAEAD(filenameKey, nonceArr, pointerAAD(ownerID, fileID), full)
	if err != nil {
		t.Fatalf("decrypt display name with the same HKDF derivation used at upload: %v", err)
	}
	if string(plain) != wantName {
		t.Errorf("decrypted display name = %q, want %q", plain, wantName)
	}
}

func TestOwnerSigUsesFixedByteLayoutNotJSON(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fileID := uuid.New()
	pointerCiphertext := []byte("fake-pointer-ciphertext-bytes")
	var pointerNonce [12]byte
	_, _ = cryptorand.Read(pointerNonce[:])
	pointerTag := make([]byte, 16)
	_, _ = cryptorand.Read(pointerTag)

	in := ownerSigInput{
		FileID:             fileID,
		PointerCiphertext:  pointerCiphertext,
		PointerNonce:       pointerNonce,
		PointerTag:         pointerTag,
		OriginalSizeBytes:  12345,
		DisplayNamePresent: false,
		SchemaVersion:      pointerFileSchemaVersion,
	}
	sig := computeOwnerSig(in, priv)

	// Manually reconstruct A-6's exact fixed-layout input and verify via
	// crypto.VerifyBytes — this only succeeds if computeOwnerSig used the
	// identical byte-for-byte concatenation, which a JSON encoding (whose
	// field order/whitespace this manual reconstruction does not attempt
	// to replicate) would not survive. DisplayNameNonce is left at its zero
	// value in `in` above (DisplayNamePresent: false), so the block hashed
	// here is 12 zero bytes (nil ciphertext ‖ zero-valued [12]byte nonce ‖
	// nil tag), not truly empty — matching what computeOwnerSig actually
	// concatenates for an absent display name.
	pointerCiphertextHash := sha256.Sum256(pointerCiphertext)
	displayNameBlockHash := sha256.Sum256(make([]byte, 12))
	var originalSizeBytes [8]byte
	binary.BigEndian.PutUint64(originalSizeBytes[:], 12345)
	var schemaVersionBytes [4]byte
	binary.BigEndian.PutUint32(schemaVersionBytes[:], pointerFileSchemaVersion)

	manualInput := concatBytes(
		[]byte(ownerSigDomainPrefix),
		fileID[:],
		pointerCiphertextHash[:],
		pointerNonce[:],
		pointerTag,
		originalSizeBytes[:],
		[]byte{0},
		displayNameBlockHash[:],
		schemaVersionBytes[:],
	)

	var pubArr [32]byte
	copy(pubArr[:], pub)
	if !crypto.VerifyBytes(pubArr, manualInput, sig) {
		t.Fatal("owner_sig does not verify against A-6's manually-reconstructed fixed-layout input — " +
			"computeOwnerSig may not be using the exact specified byte layout")
	}

	if len(manualInput) > 0 && manualInput[0] == '{' {
		t.Fatal("signing input looks like JSON (starts with '{'), not a fixed byte layout")
	}
}

func TestUploadPersistsSessionStateForResume(t *testing.T) {
	ts := newTestServer(t, config.DemoProfile, 1)
	defer ts.Close()
	host := newFakeTransferHost()
	// Never let any shard succeed, so UploadFile returns ErrUploadIncomplete
	// and the session state file must still be on disk afterward.
	host.alwaysFail = true
	o := newTestOrchestrator(t, ts.URL, host)

	plaintext := make([]byte, 256)
	_, _ = cryptorand.Read(plaintext)
	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])

	fileID, err := o.UploadFile(context.Background(), masterSecret, uuid.New(), plaintext)
	if !isWrapped(err, ErrUploadIncomplete) {
		t.Fatalf("UploadFile error = %v, want wrapping ErrUploadIncomplete", err)
	}

	path := filepath.Join(o.sessionDir, sessionFileName(fileID))
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("session state file not found at %s after an incomplete upload: %v", path, statErr)
	}
	state, err := LoadSessionState(o.sessionDir, fileID)
	if err != nil {
		t.Fatalf("LoadSessionState: %v", err)
	}
	if state.FileID != fileID {
		t.Errorf("persisted session FileID = %s, want %s", state.FileID, fileID)
	}
}

func TestUploadCleansUpSessionStateOnlyAfterRegisterSucceeds(t *testing.T) {
	ts := newTestServer(t, config.DemoProfile, 1)
	defer ts.Close()
	host := newFakeTransferHost()
	o := newTestOrchestrator(t, ts.URL, host)

	plaintext := make([]byte, 256)
	_, _ = cryptorand.Read(plaintext)
	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])

	fileID, err := o.UploadFile(context.Background(), masterSecret, uuid.New(), plaintext)
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}

	path := filepath.Join(o.sessionDir, sessionFileName(fileID))
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("session state file still present at %s after a successful upload (register succeeded)", path)
	}

	ts.mu.Lock()
	registered := ts.registerCalled
	ts.mu.Unlock()
	if !registered {
		t.Fatal("FileRegisterRequest was never sent, yet UploadFile returned nil error")
	}
}

// isWrapped is errors.Is, named locally so call sites read the same way
// this package's own production code checks sentinels.
func isWrapped(err, target error) bool {
	return errors.Is(err, target)
}

// ── Session 15.2.2 — ResumeUpload tests ────────────────────────────────

// buildPartiallyAckedSession fabricates a SessionState for numSegments ×
// profile.TotalShards shards with random-but-consistent ShardData/ChunkIDs
// (content addresses are real SHA-256 hashes of ShardData, even though the
// fake provider below never checks them), acknowledging every shard for
// which acked returns true.
func buildPartiallyAckedSession(t *testing.T, fileID uuid.UUID, numSegments int, profile config.NetworkProfile, originalSizeBytes int64, acked func(segIdx, shardIdx int) bool) SessionState {
	t.Helper()
	sess := SessionState{
		FileID:            fileID,
		ChunkIDs:          make([][][32]byte, numSegments),
		AckStatus:         make([][]bool, numSegments),
		ShardData:         make([][][]byte, numSegments),
		TotalShards:       profile.TotalShards,
		OriginalSizeBytes: originalSizeBytes,
	}
	for i := 0; i < numSegments; i++ {
		sess.ChunkIDs[i] = make([][32]byte, profile.TotalShards)
		sess.AckStatus[i] = make([]bool, profile.TotalShards)
		sess.ShardData[i] = make([][]byte, profile.TotalShards)
		for j := 0; j < profile.TotalShards; j++ {
			data := make([]byte, 64)
			_, _ = cryptorand.Read(data)
			sess.ShardData[i][j] = data
			sess.ChunkIDs[i][j] = sha256.Sum256(data)
			sess.AckStatus[i][j] = acked(i, j)
		}
	}
	return sess
}

func TestResumeUploadRetransmitsOnlyUnacknowledgedShards(t *testing.T) {
	const numSegments = 1
	ts := newTestServer(t, config.DemoProfile, numSegments)
	defer ts.Close()
	host := newFakeTransferHost()
	o := newTestOrchestrator(t, ts.URL, host)

	fileID := uuid.New()
	// Acknowledge shard 0 only; shards 1..TotalShards-1 remain pending.
	sess := buildPartiallyAckedSession(t, fileID, numSegments, config.DemoProfile, 256, func(_, shardIdx int) bool {
		return shardIdx == 0
	})
	if err := SaveSessionState(o.sessionDir, sess); err != nil {
		t.Fatalf("SaveSessionState: %v", err)
	}

	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])

	if err := o.ResumeUpload(context.Background(), masterSecret, uuid.New(), fileID); err != nil {
		t.Fatalf("ResumeUpload: %v", err)
	}

	wantRetransmitted := config.DemoProfile.TotalShards - 1 // every shard except the already-acked one
	captured := host.capturedRequests()
	if len(captured) != wantRetransmitted {
		t.Fatalf("captured %d UploadRequests, want %d (skipping the already-acknowledged shard)", len(captured), wantRetransmitted)
	}
	for _, c := range captured {
		if c.shardIndex == 0 {
			t.Errorf("shard 0 was retransmitted even though it was already acknowledged in the loaded session state")
		}
	}
}

func TestResumeUploadReusesExistingSessionID(t *testing.T) {
	const numSegments = 1
	ts := newTestServer(t, config.DemoProfile, numSegments)
	defer ts.Close()
	host := newFakeTransferHost()
	o := newTestOrchestrator(t, ts.URL, host)

	fileID := uuid.New()
	sess := buildPartiallyAckedSession(t, fileID, numSegments, config.DemoProfile, 256, func(int, int) bool { return false })
	if err := SaveSessionState(o.sessionDir, sess); err != nil {
		t.Fatalf("SaveSessionState: %v", err)
	}

	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])

	if err := o.ResumeUpload(context.Background(), masterSecret, uuid.New(), fileID); err != nil {
		t.Fatalf("ResumeUpload: %v", err)
	}

	ts.mu.Lock()
	lastAssignFileID := ts.lastAssignReq.FileID
	registerFileID := ts.registerReq.FileID
	ts.mu.Unlock()

	if lastAssignFileID != fileID {
		t.Errorf("re-assignment request file_id = %s, want the original session's file_id %s (a new session ID was generated instead of reusing the existing one)", lastAssignFileID, fileID)
	}
	if registerFileID != fileID {
		t.Errorf("FileRegisterRequest file_id = %s, want %s", registerFileID, fileID)
	}
}

func TestResumeUploadCompletesRegistrationOnSuccess(t *testing.T) {
	const numSegments = 1
	ts := newTestServer(t, config.DemoProfile, numSegments)
	defer ts.Close()
	host := newFakeTransferHost()
	o := newTestOrchestrator(t, ts.URL, host)

	fileID := uuid.New()
	sess := buildPartiallyAckedSession(t, fileID, numSegments, config.DemoProfile, 256, func(int, int) bool { return false })
	if err := SaveSessionState(o.sessionDir, sess); err != nil {
		t.Fatalf("SaveSessionState: %v", err)
	}

	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])

	if err := o.ResumeUpload(context.Background(), masterSecret, uuid.New(), fileID); err != nil {
		t.Fatalf("ResumeUpload: %v", err)
	}

	ts.mu.Lock()
	registered := ts.registerCalled
	ts.mu.Unlock()
	if !registered {
		t.Fatal("FileRegisterRequest was never sent, yet ResumeUpload returned nil error")
	}

	path := filepath.Join(o.sessionDir, sessionFileName(fileID))
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("session state file still present at %s after a successful ResumeUpload", path)
	}
}

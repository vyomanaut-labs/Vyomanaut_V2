// Package retrieve is declared in doc.go.
// Unit tests for the retrieval orchestrator. No live database is needed —
// this package never touches Postgres directly. An httptest.Server stands
// in for the microservice REST API (including the two PROPOSED endpoints
// this package's download.go documents — see that file's header comment),
// and a fake p2p.Host/p2p.Stream stands in for provider daemons, encoding
// the PROPOSED chunk-download wire frames so the actual framing code is
// genuinely exercised.
//
// Tests:
//   - TestRetrieveTagMismatchReturnsNoPlaintext
//   - TestRetrieveCancelsAfterProfileDataShardsValidResponses
//   - TestRetrieveVerifiesContentAddressBeforeDecode
//   - TestRetrieveCanaryMismatchZeroesBufferAndReturnsSentinel
//   - TestRetrieveTooFewShardsReturnsSentinel
//   - TestRetrieveConcatenatesSegmentsInOrder
//   - TestRetrieveStripsPaddingToOriginalSizeBytes
//
// [REF: MVP §8.2 Phase 15.3 Session 15.3.1]

package retrieve

import (
	"bytes"
	"context"
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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// ── Fixture: real AONT+RS encoding, mirroring what upload/orchestrator.go
// actually produces, so this package's decode path is tested against real
// data, not synthetic stand-ins. ──────────────────────────────────────────

const testAONTOverheadBytes = 48 // mirrors upload/orchestrator.go's aontOverheadBytes

type testSegmentFixture struct {
	segment       pointerFileSegment
	shardsByChunk map[string][]byte // chunk_id hex -> real encoded shard bytes
	plainSegment  []byte            // the padded plaintext this segment encodes
}

// buildTestSegment AONT-encodes and RS-encodes a segment's worth of random
// plaintext under profile, builds a real pointerFileSegment (random
// provider IDs — this package's fake host never checks their real
// identity), and returns a lookup table of chunk_id → real shard bytes for
// the fake host to serve.
func buildTestSegment(t *testing.T, profile config.NetworkProfile, segmentIndex int) testSegmentFixture {
	t.Helper()
	engine, err := erasure.NewEngine(profile)
	if err != nil {
		t.Fatalf("erasure.NewEngine: %v", err)
	}
	plainSize := profile.DataShards*profile.ShardSize - testAONTOverheadBytes
	plain := make([]byte, plainSize)
	if _, err := cryptorand.Read(plain); err != nil {
		t.Fatalf("generate plaintext: %v", err)
	}

	aontPkg, err := crypto.AONTEncodeSegment(plain, crypto.DetectAESNI())
	if err != nil {
		t.Fatalf("AONTEncodeSegment: %v", err)
	}
	shards, err := engine.EncodeSegment(aontPkg)
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}

	providerIDs := make([]uuid.UUID, profile.TotalShards)
	chunkIDHex := make([]string, profile.TotalShards)
	shardsByChunk := make(map[string][]byte, profile.TotalShards)
	for i, shard := range shards {
		providerIDs[i] = uuid.New()
		id := sha256.Sum256(shard)
		hex := fmt.Sprintf("%x", id)
		chunkIDHex[i] = hex
		shardsByChunk[hex] = shard
	}

	seg := pointerFileSegment{
		SegmentID:    uuid.New(),
		SegmentIndex: segmentIndex,
		FileKey:      fmt.Sprintf("%x", sha256.Sum256([]byte("test-file-key"))),
		ProviderIDs:  providerIDs,
		ChunkIDs:     chunkIDHex,
		ErasureParams: erasureParamsInfo{
			S: profile.DataShards, R: profile.ParityShards,
			N: profile.TotalShards, LfBytes: profile.ShardSize,
		},
	}
	return testSegmentFixture{segment: seg, shardsByChunk: shardsByChunk, plainSegment: plain}
}

// marshalPointerFilePlaintextForTest is the exact inverse of
// unmarshalPointerFilePlaintext (pointer.go) — a test-local re-derivation
// of upload/pointer.go's marshalPointerFilePlaintext, needed because that
// function is unexported in a sibling package (see pointer.go's own header
// comment on this duplication).
func marshalPointerFilePlaintextForTest(t *testing.T, p pointerFilePlaintext) []byte {
	t.Helper()
	buf := make([]byte, 0, 4+len(p.Segments)*128)
	var numSegBytes [4]byte
	binary.BigEndian.PutUint32(numSegBytes[:], uint32(len(p.Segments)))
	buf = append(buf, numSegBytes[:]...)
	for _, seg := range p.Segments {
		buf = append(buf, seg.SegmentID[:]...)
		var idxBytes [4]byte
		binary.BigEndian.PutUint32(idxBytes[:], uint32(seg.SegmentIndex))
		buf = append(buf, idxBytes[:]...)
		fileKeyBytes := mustHexDecode(t, seg.FileKey)
		if len(fileKeyBytes) != 32 {
			t.Fatalf("test file_key must decode to 32 bytes")
		}
		buf = append(buf, fileKeyBytes...)
		var paramsBytes [16]byte
		binary.BigEndian.PutUint32(paramsBytes[0:4], uint32(seg.ErasureParams.S))
		binary.BigEndian.PutUint32(paramsBytes[4:8], uint32(seg.ErasureParams.R))
		binary.BigEndian.PutUint32(paramsBytes[8:12], uint32(seg.ErasureParams.N))
		binary.BigEndian.PutUint32(paramsBytes[12:16], uint32(seg.ErasureParams.LfBytes))
		buf = append(buf, paramsBytes[:]...)
		for _, pid := range seg.ProviderIDs {
			buf = append(buf, pid[:]...)
		}
		for _, cidHex := range seg.ChunkIDs {
			buf = append(buf, mustHexDecode(t, cidHex)...)
		}
	}
	return buf
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		var v byte
		_, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &v)
		if err != nil {
			t.Fatalf("hex decode %q: %v", s, err)
		}
		b[i] = v
	}
	return b
}

// ── Fake p2p.Host / p2p.Stream for the PROPOSED chunk-download protocol ───

// fakeDownloadHost serves real shard bytes for known chunk_ids (from
// shardsByChunk), optionally corrupting or failing specific ones per
// corruptChunks/failChunks (both keyed by chunk_id hex).
type fakeDownloadHost struct {
	shardsByChunk map[string][]byte
	corruptChunks map[string]bool
	failChunks    map[string]bool
	mu            sync.Mutex
	requested     []string
}

func newFakeDownloadHost(shardsByChunk map[string][]byte) *fakeDownloadHost {
	return &fakeDownloadHost{shardsByChunk: shardsByChunk, corruptChunks: map[string]bool{}, failChunks: map[string]bool{}}
}

func (h *fakeDownloadHost) PeerID() p2p.PeerID { return "fake-owner-peer" }
func (h *fakeDownloadHost) Connect(context.Context, p2p.PeerID, []p2p.Multiaddr) error {
	return nil
}
func (h *fakeDownloadHost) NewStream(context.Context, p2p.PeerID, p2p.ProtocolID) (p2p.Stream, error) {
	return &fakeDownloadStream{host: h}, nil
}
func (h *fakeDownloadHost) PromoteConn(context.Context, net.Conn, p2p.PeerID, p2p.ProtocolID) (p2p.Stream, error) {
	return nil, fmt.Errorf("fakeDownloadHost: PromoteConn not implemented")
}
func (h *fakeDownloadHost) SetStreamHandler(p2p.ProtocolID, p2p.StreamHandler) {}
func (h *fakeDownloadHost) NATType() p2p.NATStatus                             { return 0 }
func (h *fakeDownloadHost) Close() error                                       { return nil }

type fakeDownloadStream struct {
	host *fakeDownloadHost
	resp *bytes.Reader
}

func (s *fakeDownloadStream) Write(p []byte) (int, error) {
	offset := downloadLengthPrefixSize
	chunkIDHex := fmt.Sprintf("%x", p[offset:offset+downloadChunkIDSize])

	s.host.mu.Lock()
	s.host.requested = append(s.host.requested, chunkIDHex)
	s.host.mu.Unlock()

	var body []byte
	switch {
	case s.host.failChunks[chunkIDHex]:
		body = []byte{downloadStatusNotFound}
	case s.host.corruptChunks[chunkIDHex]:
		corrupted := make([]byte, len(s.host.shardsByChunk[chunkIDHex]))
		_, _ = cryptorand.Read(corrupted) // wrong content on purpose
		body = append([]byte{downloadStatusOK}, corrupted...)
	default:
		data, ok := s.host.shardsByChunk[chunkIDHex]
		if !ok {
			body = []byte{downloadStatusNotFound}
		} else {
			body = append([]byte{downloadStatusOK}, data...)
		}
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	s.resp = bytes.NewReader(append(lenBuf[:], body...))
	return len(p), nil
}

func (s *fakeDownloadStream) Read(p []byte) (int, error) {
	if s.resp == nil {
		return 0, fmt.Errorf("fakeDownloadStream: Read before Write")
	}
	return s.resp.Read(p)
}
func (s *fakeDownloadStream) Close() error                     { return nil }
func (s *fakeDownloadStream) Protocol() p2p.ProtocolID         { return chunkDownloadProtocolID }
func (s *fakeDownloadStream) RemotePeer() p2p.PeerID           { return "fake-provider-peer" }
func (s *fakeDownloadStream) Reset() error                     { return nil }
func (s *fakeDownloadStream) SetDeadline(time.Time) error      { return nil }
func (s *fakeDownloadStream) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeDownloadStream) SetWriteDeadline(time.Time) error { return nil }

// ── Test HTTP server (pointer fetch + PROPOSED providers/resolve) ─────────

type retrieveTestServer struct {
	*httptest.Server
	pointerResp pointerFileResponse
}

func newRetrieveTestServer(t *testing.T, pointerResp pointerFileResponse) *retrieveTestServer {
	t.Helper()
	ts := &retrieveTestServer{pointerResp: pointerResp}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/file/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(ts.pointerResp)
	})
	mux.HandleFunc("/api/v1/providers/resolve", func(w http.ResponseWriter, r *http.Request) {
		var req resolveProvidersRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := resolveProvidersResponse{Providers: make([]providerAddress, len(req.ProviderIDs))}
		for i, pid := range req.ProviderIDs {
			resp.Providers[i] = providerAddress{
				ProviderID: pid,
				Multiaddrs: []string{fmt.Sprintf("/ip4/127.0.0.1/tcp/4001/p2p/fake-peer-%s", pid)},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
	ts.Server = httptest.NewServer(mux)
	return ts
}

// buildEncryptedPointerResponse encrypts segments the same way
// upload/pointer.go would and returns a ready-to-serve pointerFileResponse.
func buildEncryptedPointerResponse(t *testing.T, masterSecret [32]byte, ownerID, fileID uuid.UUID, segments []pointerFileSegment, originalSizeBytes int64) pointerFileResponse {
	t.Helper()
	plaintext := marshalPointerFilePlaintextForTest(t, pointerFilePlaintext{Segments: segments})
	key := crypto.DerivePointerEncKey(masterSecret[:], ownerID[:], fileID[:])
	var nonce [12]byte
	nonce[len(nonce)-1] = 1
	full, err := crypto.EncryptPointerFile(key, nonce, pointerAAD(ownerID, fileID), plaintext)
	if err != nil {
		t.Fatalf("EncryptPointerFile: %v", err)
	}
	ciphertext := full[:len(full)-16]
	tag := full[len(full)-16:]
	return pointerFileResponse{
		FileID:            fileID,
		PointerCiphertext: base64.StdEncoding.EncodeToString(ciphertext),
		PointerNonce:      base64.StdEncoding.EncodeToString(nonce[:]),
		PointerTag:        base64.StdEncoding.EncodeToString(tag),
		SchemaVersion:     pointerFileSchemaVersion,
		OriginalSizeBytes: originalSizeBytes,
	}
}

func newTestRetrieveOrchestrator(t *testing.T, baseURL string, host p2p.Host, profile config.NetworkProfile) *Orchestrator {
	t.Helper()
	engine, err := erasure.NewEngine(profile)
	if err != nil {
		t.Fatalf("erasure.NewEngine: %v", err)
	}
	return NewOrchestrator(baseURL, "test-token", nil, host, engine, profile)
}

// ── Tests ───────────────────────────────────────────────────────────────

func TestRetrieveTagMismatchReturnsNoPlaintext(t *testing.T) {
	profile := config.DemoProfile
	fx := buildTestSegment(t, profile, 0)
	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])
	ownerID, fileID := uuid.New(), uuid.New()

	resp := buildEncryptedPointerResponse(t, masterSecret, ownerID, fileID, []pointerFileSegment{fx.segment}, int64(len(fx.plainSegment)))
	// Corrupt the tag so decryption fails.
	badTag := make([]byte, 16)
	_, _ = cryptorand.Read(badTag)
	resp.PointerTag = base64.StdEncoding.EncodeToString(badTag)

	ts := newRetrieveTestServer(t, resp)
	defer ts.Close()
	host := newFakeDownloadHost(fx.shardsByChunk)
	o := newTestRetrieveOrchestrator(t, ts.URL, host, profile)

	plaintext, err := o.RetrieveFile(context.Background(), masterSecret, ownerID, fileID)
	if !errors.Is(err, ErrPointerTagMismatch) {
		t.Fatalf("RetrieveFile error = %v, want ErrPointerTagMismatch", err)
	}
	if plaintext != nil {
		t.Errorf("RetrieveFile returned non-nil plaintext (%d bytes) alongside ErrPointerTagMismatch", len(plaintext))
	}
}

func TestRetrieveCancelsAfterProfileDataShardsValidResponses(t *testing.T) {
	profile := config.DemoProfile // TotalShards=5, DataShards=3
	fx := buildTestSegment(t, profile, 0)
	ts := newRetrieveTestServer(t, pointerFileResponse{})
	defer ts.Close()
	host := newFakeDownloadHost(fx.shardsByChunk) // every provider succeeds
	o := newTestRetrieveOrchestrator(t, ts.URL, host, profile)

	shards, err := o.downloadSegment(context.Background(), fx.segment)
	if err != nil {
		t.Fatalf("downloadSegment: %v", err)
	}

	nonNil := 0
	for _, s := range shards {
		if s != nil {
			nonNil++
		}
	}
	if nonNil != profile.DataShards {
		t.Errorf("downloadSegment returned %d non-nil shards, want exactly %d (profile.DataShards) "+
			"even though all %d providers would have succeeded — remaining dials should be cancelled at k",
			nonNil, profile.DataShards, profile.TotalShards)
	}
}

func TestRetrieveVerifiesContentAddressBeforeDecode(t *testing.T) {
	profile := config.DemoProfile
	fx := buildTestSegment(t, profile, 0)
	ts := newRetrieveTestServer(t, pointerFileResponse{})
	defer ts.Close()
	host := newFakeDownloadHost(fx.shardsByChunk)
	// Corrupt every provider's data so none can pass content-address
	// verification — forces downloadSegment to fail with ErrTooFewShards
	// rather than silently accepting mismatched data.
	for _, chunkID := range fx.segment.ChunkIDs {
		host.corruptChunks[chunkID] = true
	}
	o := newTestRetrieveOrchestrator(t, ts.URL, host, profile)

	_, err := o.downloadSegment(context.Background(), fx.segment)
	if !errors.Is(err, ErrTooFewShards) {
		t.Fatalf("downloadSegment with every shard corrupted: error = %v, want ErrTooFewShards "+
			"(corrupted data must be rejected before ever reaching RS decode)", err)
	}
}

func TestRetrieveCanaryMismatchZeroesBufferAndReturnsSentinel(t *testing.T) {
	profile := config.DemoProfile
	engine, err := erasure.NewEngine(profile)
	if err != nil {
		t.Fatalf("erasure.NewEngine: %v", err)
	}
	plainSize := profile.DataShards*profile.ShardSize - testAONTOverheadBytes
	plain := make([]byte, plainSize)
	_, _ = cryptorand.Read(plain)

	aontPkg, err := crypto.AONTEncodeSegment(plain, crypto.DetectAESNI())
	if err != nil {
		t.Fatalf("AONTEncodeSegment: %v", err)
	}
	// Flip a bit inside the ciphertext portion (not the trailing key block)
	// so the canary check fails after a structurally valid decode attempt.
	aontPkg[0] ^= 0xFF

	shards, err := engine.EncodeSegment(aontPkg)
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}

	o := &Orchestrator{engine: engine, aesNI: crypto.DetectAESNI()}
	plaintext, err := o.decodeSegment(shards)
	if !errors.Is(err, ErrCanaryMismatch) {
		t.Fatalf("decodeSegment error = %v, want ErrCanaryMismatch", err)
	}
	if plaintext != nil {
		t.Errorf("decodeSegment returned non-nil plaintext (%d bytes) alongside ErrCanaryMismatch", len(plaintext))
	}
}

func TestRetrieveTooFewShardsReturnsSentinel(t *testing.T) {
	profile := config.DemoProfile
	fx := buildTestSegment(t, profile, 0)
	ts := newRetrieveTestServer(t, pointerFileResponse{})
	defer ts.Close()
	host := newFakeDownloadHost(fx.shardsByChunk)
	// Fail every provider but one — fewer than profile.DataShards (3)
	// succeed.
	failed := 0
	for _, chunkID := range fx.segment.ChunkIDs {
		if failed < profile.TotalShards-1 {
			host.failChunks[chunkID] = true
			failed++
		}
	}
	o := newTestRetrieveOrchestrator(t, ts.URL, host, profile)

	_, err := o.downloadSegment(context.Background(), fx.segment)
	if !errors.Is(err, ErrTooFewShards) {
		t.Fatalf("downloadSegment error = %v, want ErrTooFewShards", err)
	}
}

func TestRetrieveConcatenatesSegmentsInOrder(t *testing.T) {
	profile := config.DemoProfile
	fx0 := buildTestSegment(t, profile, 0)
	fx1 := buildTestSegment(t, profile, 1)

	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])
	ownerID, fileID := uuid.New(), uuid.New()

	originalSize := int64(len(fx0.plainSegment) + len(fx1.plainSegment))
	// Store segments OUT OF index order in the pointer file to prove
	// RetrieveFile sorts by segment_index rather than trusting array order.
	resp := buildEncryptedPointerResponse(t, masterSecret, ownerID, fileID,
		[]pointerFileSegment{fx1.segment, fx0.segment}, originalSize)

	ts := newRetrieveTestServer(t, resp)
	defer ts.Close()
	shardsByChunk := map[string][]byte{}
	for k, v := range fx0.shardsByChunk {
		shardsByChunk[k] = v
	}
	for k, v := range fx1.shardsByChunk {
		shardsByChunk[k] = v
	}
	host := newFakeDownloadHost(shardsByChunk)
	o := newTestRetrieveOrchestrator(t, ts.URL, host, profile)

	plaintext, err := o.RetrieveFile(context.Background(), masterSecret, ownerID, fileID)
	if err != nil {
		t.Fatalf("RetrieveFile: %v", err)
	}

	want := append(append([]byte{}, fx0.plainSegment...), fx1.plainSegment...)
	if !bytes.Equal(plaintext, want) {
		t.Errorf("RetrieveFile did not concatenate segments in segment_index order (segment 0 then segment 1), " +
			"even though they were stored in the pointer file as [segment 1, segment 0]")
	}
}

func TestRetrieveStripsPaddingToOriginalSizeBytes(t *testing.T) {
	profile := config.DemoProfile
	fx := buildTestSegment(t, profile, 0)
	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])
	ownerID, fileID := uuid.New(), uuid.New()

	// original_size_bytes deliberately shorter than the full padded segment.
	const wantSize = 100
	if wantSize >= len(fx.plainSegment) {
		t.Fatalf("test fixture too small for a meaningful padding-strip check")
	}
	resp := buildEncryptedPointerResponse(t, masterSecret, ownerID, fileID, []pointerFileSegment{fx.segment}, wantSize)

	ts := newRetrieveTestServer(t, resp)
	defer ts.Close()
	host := newFakeDownloadHost(fx.shardsByChunk)
	o := newTestRetrieveOrchestrator(t, ts.URL, host, profile)

	plaintext, err := o.RetrieveFile(context.Background(), masterSecret, ownerID, fileID)
	if err != nil {
		t.Fatalf("RetrieveFile: %v", err)
	}
	if len(plaintext) != wantSize {
		t.Fatalf("RetrieveFile returned %d bytes, want exactly original_size_bytes = %d", len(plaintext), wantSize)
	}
	if !bytes.Equal(plaintext, fx.plainSegment[:wantSize]) {
		t.Errorf("stripped plaintext does not match the first %d bytes of the original padded segment", wantSize)
	}
}

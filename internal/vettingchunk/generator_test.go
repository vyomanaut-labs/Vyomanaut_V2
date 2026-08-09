// Package vettingchunk is declared in doc.go.
// Unit and live-database tests for Generator. There is no real libp2p
// network in this test environment — fakeUploadHost/fakeUploadStream
// simulate a provider's chunk-upload responder in-memory, encoding real
// IC §4.1 wire frames so the actual framing code in generator.go is
// genuinely exercised, not bypassed. Mirrors the repair package's own
// executor_test.go mockTransport/mockStream pattern.
//
// Tests:
//   - TestGenerateChunkProduces256KBRandom
//   - TestGeneratedRowIsVettingWithNullSegmentAndShard
//   - TestCapIsFloorGBTimes400
//
// [REF: IC §5.10, IC §4.1, build.md Milestone 14 Phase 14.1 Session 14.1.1]

package vettingchunk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/masamasaowl/Vyomanaut_V2/internal/p2p"
	"github.com/masamasaowl/Vyomanaut_V2/internal/storage"
)

// ── Mock p2p.Stream / p2p.Host for the chunk-upload protocol ──────────────

// fakeUploadStream captures every byte written to it (the UploadRequest
// frame this package's own generator.go builds) and serves a canned,
// well-formed UploadResponse Frame 2 on Read.
type fakeUploadStream struct {
	written bytes.Buffer
	resp    *bytes.Reader
}

func (s *fakeUploadStream) Read(p []byte) (int, error)       { return s.resp.Read(p) }
func (s *fakeUploadStream) Write(p []byte) (int, error)      { return s.written.Write(p) }
func (s *fakeUploadStream) Close() error                     { return nil }
func (s *fakeUploadStream) Protocol() p2p.ProtocolID         { return chunkUploadProtocolID }
func (s *fakeUploadStream) RemotePeer() p2p.PeerID           { return "fake-provider-peer" }
func (s *fakeUploadStream) Reset() error                     { return nil }
func (s *fakeUploadStream) SetDeadline(time.Time) error      { return nil }
func (s *fakeUploadStream) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeUploadStream) SetWriteDeadline(time.Time) error { return nil }

// okUploadResponse builds a well-formed IC §4.1 UploadResponse Frame 2:
// status = 0x00 plus a dummy 64-byte provider_sig.
func okUploadResponse() *bytes.Reader {
	body := append([]byte{uploadStatusOK}, make([]byte, uploadProviderSigSize)...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	return bytes.NewReader(append(lenBuf[:], body...))
}

// fakeUploadHost implements p2p.Host, handing back a single fakeUploadStream
// whose written bytes the test inspects afterward.
type fakeUploadHost struct {
	stream *fakeUploadStream
}

func newFakeUploadHost() *fakeUploadHost {
	return &fakeUploadHost{stream: &fakeUploadStream{resp: okUploadResponse()}}
}

func (h *fakeUploadHost) PeerID() p2p.PeerID { return "fake-microservice-peer" }
func (h *fakeUploadHost) Connect(context.Context, p2p.PeerID, []p2p.Multiaddr) error {
	return nil
}
func (h *fakeUploadHost) NewStream(context.Context, p2p.PeerID, p2p.ProtocolID) (p2p.Stream, error) {
	return h.stream, nil
}
func (h *fakeUploadHost) PromoteConn(context.Context, net.Conn, p2p.PeerID, p2p.ProtocolID) (p2p.Stream, error) {
	return nil, fmt.Errorf("fakeUploadHost: PromoteConn not implemented")
}
func (h *fakeUploadHost) SetStreamHandler(p2p.ProtocolID, p2p.StreamHandler) {}
func (h *fakeUploadHost) NATType() p2p.NATStatus                             { return 0 }
func (h *fakeUploadHost) Close() error                                       { return nil }

// ── Cap ─────────────────────────────────────────────────────────────────

func TestCapIsFloorGBTimes400(t *testing.T) {
	gen := NewGenerator(nil, nil, nil)
	tests := []struct {
		gb   int
		want int
	}{
		{0, 0},
		{1, 400},
		{10, 4000},
		{50, 20000},
		{100000, 40000000},
	}
	for _, tc := range tests {
		if got := gen.Cap(tc.gb); got != tc.want {
			t.Errorf("Cap(%d) = %d, want %d", tc.gb, got, tc.want)
		}
	}
}

// ── GenerateChunk ───────────────────────────────────────────────────────

func TestGenerateChunkProduces256KBRandom(t *testing.T) {
	db := openTestDB(t)
	_, msSigningKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate microservice signing key: %v", err)
	}
	providerID := insertTestVettingProvider(t, db, 50)

	host := newFakeUploadHost()
	gen := NewGenerator(db, host, msSigningKey)

	chunkID, err := gen.GenerateChunk(context.Background(), providerID)
	if err != nil {
		t.Fatalf("GenerateChunk: %v", err)
	}

	written := host.stream.written.Bytes()
	wantLen := uploadLengthPrefixSize + uploadChunkIDSize + uploadShardIndexSize + uploadCapabilityTokenSize + storage.ChunkDataSize
	if len(written) != wantLen {
		t.Fatalf("written UploadRequest frame length = %d, want %d", len(written), wantLen)
	}

	dataOffset := uploadLengthPrefixSize + uploadChunkIDSize + uploadShardIndexSize + uploadCapabilityTokenSize
	chunkData := written[dataOffset:]
	if len(chunkData) != storage.ChunkDataSize {
		t.Fatalf("chunk_data length = %d, want %d", len(chunkData), storage.ChunkDataSize)
	}
	if sha256.Sum256(chunkData) != chunkID {
		t.Errorf("returned chunkID does not match SHA-256 of the uploaded chunk_data")
	}

	sentChunkID := written[uploadLengthPrefixSize : uploadLengthPrefixSize+uploadChunkIDSize]
	if !bytes.Equal(sentChunkID, chunkID[:]) {
		t.Errorf("chunk_id field on the wire does not match returned chunkID")
	}
}

func TestGeneratedRowIsVettingWithNullSegmentAndShard(t *testing.T) {
	db := openTestDB(t)
	_, msSigningKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate microservice signing key: %v", err)
	}
	providerID := insertTestVettingProvider(t, db, 50)

	host := newFakeUploadHost()
	gen := NewGenerator(db, host, msSigningKey)

	chunkID, err := gen.GenerateChunk(context.Background(), providerID)
	if err != nil {
		t.Fatalf("GenerateChunk: %v", err)
	}

	var (
		isVetting  bool
		segmentID  *string
		shardIndex *int
		status     string
	)
	err = db.QueryRow(`
		SELECT is_vetting_chunk, segment_id, shard_index, status
		FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], providerID,
	).Scan(&isVetting, &segmentID, &shardIndex, &status)
	if err != nil {
		t.Fatalf("query chunk_assignments: %v", err)
	}
	if !isVetting {
		t.Errorf("is_vetting_chunk = false, want true")
	}
	if segmentID != nil {
		t.Errorf("segment_id = %v, want NULL", *segmentID)
	}
	if shardIndex != nil {
		t.Errorf("shard_index = %v, want NULL", *shardIndex)
	}
	if status != "ACTIVE" {
		t.Errorf("status = %q, want ACTIVE", status)
	}

	// CurrentCount should now see exactly this one row.
	count, err := gen.CurrentCount(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("CurrentCount: %v", err)
	}
	if count != 1 {
		t.Errorf("CurrentCount = %d, want 1", count)
	}
}
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// mockDeleteFailureStore wraps a real storage.ChunkStore and forces
// DeleteChunk to fail for a configured set of chunk IDs, so partial-failure
// paths can be exercised deterministically (the real RocksDB-backed
// DeleteChunk is idempotent and essentially never fails in a unit test).
type mockDeleteFailureStore struct {
	storage.ChunkStore
	failIDs map[[32]byte]bool
}

func (m *mockDeleteFailureStore) DeleteChunk(chunkID [32]byte) error {
	if m.failIDs[chunkID] {
		return fmt.Errorf("mockDeleteFailureStore: simulated delete failure")
	}
	return m.ChunkStore.DeleteChunk(chunkID)
}

func newVettingGCTestFixture(t *testing.T, h *VettingGCHandler, authz *staticMicroserviceAuthorizer, authorizeClient bool) p2p.Stream {
	t.Helper()

	port := pickFreeLoopbackPort(t)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverHost, err := p2p.NewHost(p2p.HostConfig{PrivateKey: serverPriv, ListenAddr: listenAddr})
	if err != nil {
		t.Fatalf("NewHost server: %v", err)
	}
	t.Cleanup(func() { _ = serverHost.Close() })
	serverHost.SetStreamHandler(vettingGCProtocolID, h.HandleStream)

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientHost, err := p2p.NewHost(p2p.HostConfig{PrivateKey: clientPriv})
	if err != nil {
		t.Fatalf("NewHost client: %v", err)
	}
	t.Cleanup(func() { _ = clientHost.Close() })

	if authorizeClient {
		authz.Set([]p2p.PeerID{clientHost.PeerID()})
	}

	ma, err := p2p.ParseMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	ctx := context.Background()
	if err := clientHost.Connect(ctx, serverHost.PeerID(), []p2p.Multiaddr{ma}); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	stream, err := clientHost.NewStream(ctx, serverHost.PeerID(), vettingGCProtocolID)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	return stream
}

func signGCAuth(t *testing.T, priv ed25519.PrivateKey, chunkIDsBytes []byte, requestTsMs int64, msPeerID p2p.PeerID) [64]byte {
	t.Helper()
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(requestTsMs))
	peerIDBytes := []byte(msPeerID.String())
	input := make([]byte, 0, len(chunkIDsBytes)+len(tsBytes)+len(peerIDBytes))
	input = append(input, chunkIDsBytes...)
	input = append(input, tsBytes[:]...)
	input = append(input, peerIDBytes...)
	return signWithKey(priv, input)
}

func encodeVettingGCFrame1(chunkIDs [][32]byte, requestTsMs int64, sig [64]byte) []byte {
	chunkIDsBytes := make([]byte, 0, len(chunkIDs)*32)
	for _, id := range chunkIDs {
		chunkIDsBytes = append(chunkIDsBytes, id[:]...)
	}

	payload := make([]byte, 0, vettingGCChunkCountSize+len(chunkIDsBytes)+vettingGCRequestTsSize+vettingGCAuthSigSize)
	var countBytes [4]byte
	binary.BigEndian.PutUint32(countBytes[:], uint32(len(chunkIDs)))
	payload = append(payload, countBytes[:]...)
	payload = append(payload, chunkIDsBytes...)
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(requestTsMs))
	payload = append(payload, tsBytes[:]...)
	payload = append(payload, sig[:]...)

	frame := make([]byte, 0, vettingGCLengthPrefixSize+len(payload))
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(payload)))
	frame = append(frame, lenBytes[:]...)
	frame = append(frame, payload...)
	return frame
}

func readVettingGCFrame2(t *testing.T, s p2p.Stream) (status byte, rest []byte) {
	t.Helper()
	var lenBuf [4]byte
	if _, err := readStreamFull(s, lenBuf[:]); err != nil {
		t.Fatalf("read frame2 length: %v", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	payload := make([]byte, length)
	if length > 0 {
		if _, err := readStreamFull(s, payload); err != nil {
			t.Fatalf("read frame2 payload (%d bytes): %v", length, err)
		}
	}
	if len(payload) == 0 {
		t.Fatalf("frame2 payload is empty")
	}
	return payload[0], payload[1:]
}

func randomChunkIDsGC(n int) [][32]byte {
	ids := make([][32]byte, n)
	for i := range ids {
		_, _ = rand.Read(ids[i][:])
	}
	return ids
}

func TestVettingGCPartialFailureBitmap(t *testing.T) {
	realStore := newTestChunkStore(t)
	chunkIDs := randomChunkIDsGC(4)
	failIDs := map[[32]byte]bool{chunkIDs[1]: true, chunkIDs[3]: true}
	store := &mockDeleteFailureStore{ChunkStore: realStore, failIDs: failIDs}

	msPub, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer()
	h := NewVettingGCHandler(store, msPub, authz, 120*time.Second, msPeerID)
	stream := newVettingGCTestFixture(t, h, authz, true)

	chunkIDsBytes := make([]byte, 0, 4*32)
	for _, id := range chunkIDs {
		chunkIDsBytes = append(chunkIDsBytes, id[:]...)
	}
	ts := time.Now().UnixMilli()
	sig := signGCAuth(t, msPriv, chunkIDsBytes, ts, msPeerID)

	if _, err := stream.Write(encodeVettingGCFrame1(chunkIDs, ts, sig)); err != nil {
		t.Fatalf("write frame1: %v", err)
	}
	status, rest := readVettingGCFrame2(t, stream)
	if status != vettingGCStatusPartialFailure {
		t.Fatalf("status = 0x%02x, want 0x01 partial failure", status)
	}
	wantBitmapLen := (4 + 7) / 8
	if len(rest) != wantBitmapLen {
		t.Fatalf("bitmap length = %d, want %d", len(rest), wantBitmapLen)
	}
	bitmap := rest[0]
	if bitmap&(1<<0) != 0 {
		t.Errorf("bit 0 (chunkIDs[0], should succeed) unexpectedly set")
	}
	if bitmap&(1<<1) == 0 {
		t.Errorf("bit 1 (chunkIDs[1], should fail) not set")
	}
	if bitmap&(1<<2) != 0 {
		t.Errorf("bit 2 (chunkIDs[2], should succeed) unexpectedly set")
	}
	if bitmap&(1<<3) == 0 {
		t.Errorf("bit 3 (chunkIDs[3], should fail) not set")
	}
}

func TestVettingGCRejectsOver10kIDs(t *testing.T) {
	store := newTestChunkStore(t)
	msPub, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer()
	h := NewVettingGCHandler(store, msPub, authz, 120*time.Second, msPeerID)
	stream := newVettingGCTestFixture(t, h, authz, true)

	// Hand-craft a Frame 1 declaring chunk_count = 10,001 without actually
	// sending that many IDs — the handler must reject on the count alone,
	// before attempting to read a body that large.
	var countBytes [4]byte
	binary.BigEndian.PutUint32(countBytes[:], vettingGCMaxChunksPerFrame+1)
	var lenBytes [4]byte
	// Declared length is irrelevant once chunk_count itself is rejected.
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(countBytes)))
	frame := append(append([]byte{}, lenBytes[:]...), countBytes[:]...)

	if _, err := stream.Write(frame); err != nil {
		// A reset stream may refuse the write itself, which also
		// demonstrates the over-10k rejection.
		_ = msPriv
		return
	}

	buf := make([]byte, 4)
	_, err := readStreamFull(stream, buf)
	if err == nil {
		t.Fatalf("expected the stream to be reset for chunk_count > 10,000, got a readable response")
	}
}

func TestVettingGCMultipleSequentialFrames(t *testing.T) {
	realStore := newTestChunkStore(t)
	writeCh := startTestChunkWriter(t, realStore)
	store := &mockDeleteFailureStore{ChunkStore: realStore, failIDs: map[[32]byte]bool{}}

	msPub, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer()
	h := NewVettingGCHandler(store, msPub, authz, 120*time.Second, msPeerID)
	stream := newVettingGCTestFixture(t, h, authz, true)

	// Two batches of real, stored chunks, sent as two sequential frames on
	// the SAME stream (IC §4.5).
	for batch := 0; batch < 2; batch++ {
		ids := make([][32]byte, 3)
		for i := range ids {
			data := make([]byte, uploadChunkDataSize)
			_, _ = rand.Read(data)
			id := sha256.Sum256(data)
			resultCh := make(chan chunkWriteResult, 1)
			writeCh <- chunkWriteRequest{chunkID: id, data: data, resultCh: resultCh}
			if res := <-resultCh; res.err != nil {
				t.Fatalf("AppendChunk: %v", res.err)
			}
			ids[i] = id
		}

		idsBytes := make([]byte, 0, len(ids)*32)
		for _, id := range ids {
			idsBytes = append(idsBytes, id[:]...)
		}
		ts := time.Now().UnixMilli()
		sig := signGCAuth(t, msPriv, idsBytes, ts, msPeerID)

		if _, err := stream.Write(encodeVettingGCFrame1(ids, ts, sig)); err != nil {
			t.Fatalf("batch %d: write frame1: %v", batch, err)
		}
		status, _ := readVettingGCFrame2(t, stream)
		if status != vettingGCStatusOK {
			t.Fatalf("batch %d: status = 0x%02x, want 0x00 OK", batch, status)
		}

		for _, id := range ids {
			if _, err := realStore.LookupChunk(id); err == nil {
				t.Fatalf("batch %d: chunk %x still present after GC", batch, id)
			}
		}
	}
}

func TestVettingGCRejectsUnauthorizedPeer(t *testing.T) {
	store := newTestChunkStore(t)
	msPub, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer() // deliberately empty
	h := NewVettingGCHandler(store, msPub, authz, 120*time.Second, msPeerID)
	stream := newVettingGCTestFixture(t, h, authz, false) // NOT authorized

	ids := randomChunkIDsGC(1)
	idsBytes := ids[0][:]
	ts := time.Now().UnixMilli()
	sig := signGCAuth(t, msPriv, idsBytes, ts, msPeerID)

	if _, err := stream.Write(encodeVettingGCFrame1(ids, ts, sig)); err != nil {
		t.Fatalf("write frame1: %v", err)
	}
	status, _ := readVettingGCFrame2(t, stream)
	if status != vettingGCStatusNotAuthorised {
		t.Fatalf("status = 0x%02x, want 0x03 NOT_AUTHORISED", status)
	}
}

func TestVettingGCRejectsForgedSig(t *testing.T) {
	store := newTestChunkStore(t)
	msPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer()
	h := NewVettingGCHandler(store, msPub, authz, 120*time.Second, msPeerID)
	stream := newVettingGCTestFixture(t, h, authz, true)

	ids := randomChunkIDsGC(1)
	idsBytes := ids[0][:]
	ts := time.Now().UnixMilli()
	badSig := signGCAuth(t, wrongPriv, idsBytes, ts, msPeerID)

	if _, err := stream.Write(encodeVettingGCFrame1(ids, ts, badSig)); err != nil {
		t.Fatalf("write frame1: %v", err)
	}
	status, _ := readVettingGCFrame2(t, stream)
	if status != vettingGCStatusNotAuthorised {
		t.Fatalf("status = 0x%02x, want 0x03 NOT_AUTHORISED", status)
	}
}

func TestVettingGCRejectsStaleRequest(t *testing.T) {
	store := newTestChunkStore(t)
	msPub, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer()
	h := NewVettingGCHandler(store, msPub, authz, 1*time.Millisecond, msPeerID)
	stream := newVettingGCTestFixture(t, h, authz, true)

	ids := randomChunkIDsGC(1)
	idsBytes := ids[0][:]
	staleTs := time.Now().Add(-time.Hour).UnixMilli()
	sig := signGCAuth(t, msPriv, idsBytes, staleTs, msPeerID)

	if _, err := stream.Write(encodeVettingGCFrame1(ids, staleTs, sig)); err != nil {
		t.Fatalf("write frame1: %v", err)
	}
	status, _ := readVettingGCFrame2(t, stream)
	if status != vettingGCStatusStaleRequest {
		t.Fatalf("status = 0x%02x, want 0x04 STALE_REQUEST", status)
	}
}

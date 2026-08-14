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
)

// repairTestFixture bundles a connected server/client host pair with a
// RepairDownloadHandler registered, plus the authorizer so tests can
// register (or deliberately withhold) the client's real Peer ID.
type repairTestFixture struct {
	serverHost p2p.Host
	clientHost p2p.Host
	stream     p2p.Stream
	authz      *staticMicroserviceAuthorizer
}

func newRepairTestFixture(t *testing.T, h *RepairDownloadHandler, authz *staticMicroserviceAuthorizer, authorizeClient bool) *repairTestFixture {
	t.Helper()

	port := pickFreeLoopbackPort(t)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverHost, err := p2p.NewHost(p2p.HostConfig{PrivateKey: serverPriv, ListenAddr: listenAddr})
	if err != nil {
		t.Fatalf("NewHost server: %v", err)
	}
	t.Cleanup(func() { _ = serverHost.Close() })
	serverHost.SetStreamHandler(repairDownloadProtocolID, h.HandleStream)

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
	stream, err := clientHost.NewStream(ctx, serverHost.PeerID(), repairDownloadProtocolID)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	return &repairTestFixture{serverHost: serverHost, clientHost: clientHost, stream: stream, authz: authz}
}

func signRepairAuth(t *testing.T, priv ed25519.PrivateKey, chunkID [32]byte, requestTsMs int64, msPeerID p2p.PeerID) [64]byte {
	t.Helper()
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(requestTsMs))
	peerIDBytes := []byte(msPeerID.String())
	input := make([]byte, 0, len(chunkID)+len(tsBytes)+len(peerIDBytes))
	input = append(input, chunkID[:]...)
	input = append(input, tsBytes[:]...)
	input = append(input, peerIDBytes...)
	return signWithKey(priv, input)
}

func encodeRepairFrame1(chunkID [32]byte, requestTsMs int64, sig [64]byte) []byte {
	payload := make([]byte, 0, repairFrame1PayloadBytes)
	payload = append(payload, chunkID[:]...)
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(requestTsMs))
	payload = append(payload, tsBytes[:]...)
	payload = append(payload, sig[:]...)

	frame := make([]byte, 0, repairLengthPrefixSize+len(payload))
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(payload)))
	frame = append(frame, lenBytes[:]...)
	frame = append(frame, payload...)
	return frame
}

func readRepairFrame2(t *testing.T, s p2p.Stream) (status byte, rest []byte) {
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

func TestRepairRejectsUnregisteredPeerBeforeLookup(t *testing.T) {
	store := newTestChunkStore(t)
	msPub, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer() // deliberately left empty

	h := NewRepairDownloadHandler(store, msPub, authz, 120*time.Second, msPeerID)
	fx := newRepairTestFixture(t, h, authz, false) // NOT authorized

	var chunkID [32]byte
	_, _ = rand.Read(chunkID[:])
	ts := time.Now().UnixMilli()
	sig := signRepairAuth(t, msPriv, chunkID, ts, msPeerID)

	if _, err := fx.stream.Write(encodeRepairFrame1(chunkID, ts, sig)); err != nil {
		t.Fatalf("write frame1: %v", err)
	}
	status, _ := readRepairFrame2(t, fx.stream)
	if status != repairStatusNotAuthorised {
		t.Fatalf("status = 0x%02x, want 0x02 NOT_AUTHORISED", status)
	}
}

func TestRepairRejectsInvalidAuthSig(t *testing.T) {
	store := newTestChunkStore(t)
	msPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader) // signer uses a DIFFERENT key than msPub
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer()

	h := NewRepairDownloadHandler(store, msPub, authz, 120*time.Second, msPeerID)
	fx := newRepairTestFixture(t, h, authz, true) // peer IS authorized; signature is not

	var chunkID [32]byte
	_, _ = rand.Read(chunkID[:])
	ts := time.Now().UnixMilli()
	badSig := signRepairAuth(t, wrongPriv, chunkID, ts, msPeerID)

	if _, err := fx.stream.Write(encodeRepairFrame1(chunkID, ts, badSig)); err != nil {
		t.Fatalf("write frame1: %v", err)
	}
	status, _ := readRepairFrame2(t, fx.stream)
	if status != repairStatusNotAuthorised {
		t.Fatalf("status = 0x%02x, want 0x02 NOT_AUTHORISED", status)
	}
}

func TestRepairReturnsChunkDataOnSuccess(t *testing.T) {
	store := newTestChunkStore(t)
	writeCh := startTestChunkWriter(t, store)
	msPub, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer()

	h := NewRepairDownloadHandler(store, msPub, authz, 120*time.Second, msPeerID)
	fx := newRepairTestFixture(t, h, authz, true)

	chunkData := make([]byte, repairChunkDataSize)
	_, _ = rand.Read(chunkData)
	chunkID := sha256.Sum256(chunkData)
	resultCh := make(chan chunkWriteResult, 1)
	writeCh <- chunkWriteRequest{chunkID: chunkID, data: chunkData, resultCh: resultCh}
	if res := <-resultCh; res.err != nil {
		t.Fatalf("AppendChunk: %v", res.err)
	}

	ts := time.Now().UnixMilli()
	sig := signRepairAuth(t, msPriv, chunkID, ts, msPeerID)
	if _, err := fx.stream.Write(encodeRepairFrame1(chunkID, ts, sig)); err != nil {
		t.Fatalf("write frame1: %v", err)
	}
	status, rest := readRepairFrame2(t, fx.stream)
	if status != repairStatusOK {
		t.Fatalf("status = 0x%02x, want 0x00 OK", status)
	}
	if len(rest) != repairChunkDataSize {
		t.Fatalf("payload length = %d, want %d", len(rest), repairChunkDataSize)
	}
	if string(rest) != string(chunkData) {
		t.Fatalf("returned chunk data does not match what was stored")
	}
}

func TestRepairRejectsStaleRequest(t *testing.T) {
	store := newTestChunkStore(t)
	msPub, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPeerID := p2p.PeerID("test-microservice-peer")
	authz := newStaticMicroserviceAuthorizer()

	// Freshness window intentionally tiny so a request timestamped even a
	// moment in the past reliably exceeds it.
	h := NewRepairDownloadHandler(store, msPub, authz, 1*time.Millisecond, msPeerID)
	fx := newRepairTestFixture(t, h, authz, true)

	var chunkID [32]byte
	_, _ = rand.Read(chunkID[:])
	staleTs := time.Now().Add(-time.Hour).UnixMilli()
	sig := signRepairAuth(t, msPriv, chunkID, staleTs, msPeerID)

	if _, err := fx.stream.Write(encodeRepairFrame1(chunkID, staleTs, sig)); err != nil {
		t.Fatalf("write frame1: %v", err)
	}
	status, _ := readRepairFrame2(t, fx.stream)
	if status != repairStatusNotAuthorised {
		t.Fatalf("status = 0x%02x, want 0x02 NOT_AUTHORISED (stale request)", status)
	}
}

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/masamasaowl/Vyomanaut_V2/internal/p2p"
	"github.com/masamasaowl/Vyomanaut_V2/internal/storage"
)

// ── shared test scaffolding ──────────────────────────────────────────────

// pickFreeLoopbackPort finds an OS-assigned free TCP port on 127.0.0.1.
// p2p.Host (unlike its in-package tests) does not expose the bound address
// of a ":0" listener to callers outside the p2p package, so tests here pick
// a concrete port up front instead. A brief bind/close race is inherent to
// this pattern but is standard practice for Go test suites.
func pickFreeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pickFreeLoopbackPort: %v", err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		t.Fatalf("pickFreeLoopbackPort: listener address is not *net.TCPAddr")
	}
	port := addr.Port
	if err := ln.Close(); err != nil {
		t.Fatalf("pickFreeLoopbackPort: close listener: %v", err)
	}
	return port
}

// startTestChunkWriter spins up a minimal stand-in for main.go's
// runChunkStoreWriter (Session 13.1.1) — the single goroutine permitted to
// call store.AppendChunk — so this file's tests do not depend on main.go
// having been written yet. Mirrors runChunkStoreWriter exactly.
func startTestChunkWriter(t *testing.T, store storage.ChunkStore) chan chunkWriteRequest {
	t.Helper()
	ch := make(chan chunkWriteRequest, 8)
	go func() {
		for req := range ch {
			offset, err := store.AppendChunk(req.chunkID, req.data)
			req.resultCh <- chunkWriteResult{vlogOffset: offset, err: err}
		}
	}()
	t.Cleanup(func() { close(ch) })
	return ch
}

func newTestChunkStore(t *testing.T) storage.ChunkStore {
	t.Helper()
	store, err := storage.NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewChunkStore: %v", err)
	}
	if err := store.RecoverFromCrash(); err != nil {
		t.Fatalf("RecoverFromCrash: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// buildValidCapabilityToken mints a 72-byte token using the zero provider_id
// this file's test handlers are consistently constructed with (see each
// NewUploadHandler call site in this file) — file_id is no longer part of
// the signing input at all (ADR-072).
func buildValidCapabilityToken(t *testing.T, msPriv ed25519.PrivateKey, chunkID [32]byte, expiry time.Time) [uploadCapabilityTokenSize]byte {
	t.Helper()
	expiryMs := expiry.UnixMilli()
	signingInput := capabilityTokenSigningInput(chunkID, [16]byte{}, expiryMs)
	sig := signWithKey(msPriv, signingInput)

	var token [uploadCapabilityTokenSize]byte
	binary.BigEndian.PutUint64(token[0:8], uint64(expiryMs))
	copy(token[8:], sig[:])
	return token
}

func signWithKey(priv ed25519.PrivateKey, input []byte) [64]byte {
	digest := sha256.Sum256(input)
	raw := ed25519.Sign(priv, digest[:])
	var sig [64]byte
	copy(sig[:], raw)
	return sig
}

// encodeUploadFrame1 builds a raw wire Frame 1 exactly per IC §4.1.
func encodeUploadFrame1(chunkID [32]byte, shardIndex uint32, token [uploadCapabilityTokenSize]byte, chunkData []byte) []byte {
	payload := make([]byte, 0, uploadFrame1PayloadMaxBytes)
	payload = append(payload, chunkID[:]...)
	var shardIndexBytes [4]byte
	binary.BigEndian.PutUint32(shardIndexBytes[:], shardIndex)
	payload = append(payload, shardIndexBytes[:]...)
	payload = append(payload, token[:]...)
	payload = append(payload, chunkData...)

	frame := make([]byte, 0, uploadLengthPrefixSize+len(payload))
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(payload)))
	frame = append(frame, lenBytes[:]...)
	frame = append(frame, payload...)
	return frame
}

// setupUploadTestPair starts a server host with an UploadHandler registered
// and a client host connected to it, returning an open stream ready for the
// test to write a Frame 1 on.
func setupUploadTestPair(t *testing.T, h *UploadHandler) p2p.Stream {
	t.Helper()

	port := pickFreeLoopbackPort(t)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverHost, err := p2p.NewHost(p2p.HostConfig{PrivateKey: serverPriv, ListenAddr: listenAddr})
	if err != nil {
		t.Fatalf("NewHost server: %v", err)
	}
	t.Cleanup(func() { _ = serverHost.Close() })
	serverHost.SetStreamHandler(chunkUploadProtocolID, h.HandleStream)

	ma, err := p2p.ParseMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientHost, err := p2p.NewHost(p2p.HostConfig{PrivateKey: clientPriv})
	if err != nil {
		t.Fatalf("NewHost client: %v", err)
	}
	t.Cleanup(func() { _ = clientHost.Close() })

	ctx := context.Background()
	if err := clientHost.Connect(ctx, serverHost.PeerID(), []p2p.Multiaddr{ma}); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	stream, err := clientHost.NewStream(ctx, serverHost.PeerID(), chunkUploadProtocolID)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	return stream
}

// ── individual handler-behaviour tests ───────────────────────────────────

func TestUploadRejectsExpiredCapabilityToken(t *testing.T) {
	store := newTestChunkStore(t)
	writeCh := startTestChunkWriter(t, store)
	_, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, providerPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(msPub, msPriv[ed25519.SeedSize:])

	h := NewUploadHandler(store, writeCh, msPub, providerPriv, [16]byte{}, newProviderStatusHolder(providerStatusActive))
	stream := setupUploadTestPair(t, h)

	chunkData := make([]byte, uploadChunkDataSize)
	_, _ = rand.Read(chunkData)
	chunkID := sha256.Sum256(chunkData)

	// Expired well beyond the 30s grace window.
	token := buildValidCapabilityToken(t, msPriv, chunkID, time.Now().Add(-2*time.Hour))

	frame := encodeUploadFrame1(chunkID, 0, token, chunkData)
	if _, err := stream.Write(frame); err != nil {
		t.Fatalf("write frame1: %v", err)
	}

	status, _ := readUploadFrame2(t, stream)
	if status != uploadStatusCapabilityExpired {
		t.Fatalf("status = 0x%02x, want 0x07 CAPABILITY_EXPIRED", status)
	}
}

func TestUploadRejectsContentHashMismatchBeforeWrite(t *testing.T) {
	store := newTestChunkStore(t)
	writeCh := startTestChunkWriter(t, store)
	_, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, providerPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(msPub, msPriv[ed25519.SeedSize:])

	h := NewUploadHandler(store, writeCh, msPub, providerPriv, [16]byte{}, newProviderStatusHolder(providerStatusActive))
	stream := setupUploadTestPair(t, h)

	chunkData := make([]byte, uploadChunkDataSize)
	_, _ = rand.Read(chunkData)
	// chunkID does NOT match SHA-256(chunkData) — a different random value.
	var wrongChunkID [32]byte
	_, _ = rand.Read(wrongChunkID[:])

	token := buildValidCapabilityToken(t, msPriv, wrongChunkID, time.Now().Add(time.Hour))
	frame := encodeUploadFrame1(wrongChunkID, 0, token, chunkData)
	if _, err := stream.Write(frame); err != nil {
		t.Fatalf("write frame1: %v", err)
	}

	status, _ := readUploadFrame2(t, stream)
	if status != uploadStatusChunkIDMismatch {
		t.Fatalf("status = 0x%02x, want 0x02 CHUNK_ID_MISMATCH", status)
	}

	// No disk write must have occurred.
	if _, err := store.LookupChunk(wrongChunkID); err == nil {
		t.Fatalf("LookupChunk unexpectedly found a chunk for a rejected upload")
	}
}

func TestUploadIdempotentAlreadyStored(t *testing.T) {
	store := newTestChunkStore(t)
	writeCh := startTestChunkWriter(t, store)
	_, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, providerPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(msPub, msPriv[ed25519.SeedSize:])

	h := NewUploadHandler(store, writeCh, msPub, providerPriv, [16]byte{}, newProviderStatusHolder(providerStatusActive))

	chunkData := make([]byte, uploadChunkDataSize)
	_, _ = rand.Read(chunkData)
	chunkID := sha256.Sum256(chunkData)

	// First upload: expect 0x00 OK.
	stream1 := setupUploadTestPair(t, h)
	token1 := buildValidCapabilityToken(t, msPriv, chunkID, time.Now().Add(time.Hour))
	if _, err := stream1.Write(encodeUploadFrame1(chunkID, 0, token1, chunkData)); err != nil {
		t.Fatalf("write frame1 (first): %v", err)
	}
	status1, sig1 := readUploadFrame2(t, stream1)
	if status1 != uploadStatusOK {
		t.Fatalf("first upload status = 0x%02x, want 0x00 OK", status1)
	}
	if len(sig1) != uploadProviderSigSize {
		t.Fatalf("first upload provider_sig length = %d, want %d", len(sig1), uploadProviderSigSize)
	}

	// Second, identical upload: expect 0x06 ALREADY_STORED, with a receipt.
	stream2 := setupUploadTestPair(t, h)
	token2 := buildValidCapabilityToken(t, msPriv, chunkID, time.Now().Add(time.Hour))
	if _, err := stream2.Write(encodeUploadFrame1(chunkID, 0, token2, chunkData)); err != nil {
		t.Fatalf("write frame1 (second): %v", err)
	}
	status2, sig2 := readUploadFrame2(t, stream2)
	if status2 != uploadStatusAlreadyStored {
		t.Fatalf("second upload status = 0x%02x, want 0x06 ALREADY_STORED", status2)
	}
	if len(sig2) != uploadProviderSigSize {
		t.Fatalf("second upload provider_sig length = %d, want %d", len(sig2), uploadProviderSigSize)
	}
}

func TestUploadRejectsDepartedProvider(t *testing.T) {
	store := newTestChunkStore(t)
	writeCh := startTestChunkWriter(t, store)
	_, msPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, providerPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(msPub, msPriv[ed25519.SeedSize:])

	h := NewUploadHandler(store, writeCh, msPub, providerPriv, [16]byte{}, newProviderStatusHolder(providerStatusDeparted))
	stream := setupUploadTestPair(t, h)

	chunkData := make([]byte, uploadChunkDataSize)
	_, _ = rand.Read(chunkData)
	chunkID := sha256.Sum256(chunkData)
	token := buildValidCapabilityToken(t, msPriv, chunkID, time.Now().Add(time.Hour))

	if _, err := stream.Write(encodeUploadFrame1(chunkID, 0, token, chunkData)); err != nil {
		// A reset stream may already refuse the write itself; that also
		// demonstrates the DEPARTED short-circuit.
		return
	}

	buf := make([]byte, 4)
	_, err := readStreamFull(stream, buf)
	if err == nil {
		t.Fatalf("expected the stream to be reset for a DEPARTED provider, got a readable response")
	}
}

// ── low-level test helpers ────────────────────────────────────────────────

// readUploadFrame2 reads and parses a Frame 2 response: a 4-byte length
// prefix followed by a 1-byte status and, for 0x00/0x06, a 64-byte
// provider_sig.
func readUploadFrame2(t *testing.T, s io.Reader) (status byte, providerSig []byte) {
	t.Helper()
	var lenBuf [4]byte
	if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
		t.Fatalf("read frame2 length: %v", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	payload := make([]byte, length)
	if _, err := io.ReadFull(s, payload); err != nil {
		t.Fatalf("read frame2 payload (%d bytes): %v", length, err)
	}
	if len(payload) == 0 {
		t.Fatalf("frame2 payload is empty")
	}
	return payload[0], payload[1:]
}

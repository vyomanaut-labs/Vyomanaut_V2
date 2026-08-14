// Command provider is the Vyomanaut V2 provider daemon entrypoint.
// This file implements the /vyomanaut/repair-download/1.0.0 stream handler
// (IC §4.4.1, Session 13.4.1) WITH the ADR-036 security addendum applied
// directly — ADR-036's Status is Accepted (confirmed against
// Vyomanaut_Research/docs/decisions/ADR-036-authenticated-provider-mutation-protocols.md
// before writing this file), so this is not the deferred "base" handler the
// milestone text describes for a not-yet-accepted ADR; it is the final
// authorized form.
//
// 0-RTT policy: PROHIBITED (IC §4.4.1) — deny-list membership, responder
// side; see handler_audit.go's header for the full account of why this
// codebase's transport substitute enforces that exclusively on the dialing
// (microservice) side.
//
// WIRE-FORMAT CORRECTION (flagged, necessary, not optional — see the build
// report's REPAIR-AUTH-TS-GAP finding): IC §4.4.1's original Frame 1
// (chunk_id(32) || repair_auth_sig(64) = 96 bytes) has no request_ts_ms
// field, yet repair_auth_sig's own signing formula is
// SHA-256(chunk_id ‖ request_ts_ms ‖ microservice_peer_id) — a value the
// responder cannot verify, nor freshness-check per ADR-036 §2, without
// possessing request_ts_ms. ADR-036 §2 says "the field is already signed",
// which is only true if it is also transmitted. This handler therefore
// extends Frame 1 with an explicit request_ts_ms(8) field
// (chunk_id(32) || request_ts_ms(8) || repair_auth_sig(64) = 104 bytes).
// This is the same class of gap as handler_upload.go's capability-token
// file_id note — a spec correction driven by the signing formula itself
// being unambiguous, not a guess.
//
// [REF: IC §4.4.1, IC §11, ADR-021, ADR-036, build.md Session 13.4.1]
package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	localcrypto "github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// ── Protocol ID (IC §4.4.1) ──────────────────────────────────────────────

const repairDownloadProtocolID = p2p.ProtocolID("/vyomanaut/repair-download/1.0.0")

// ── Wire-format field sizes ───────────────────────────────────────────────
// Frame 1 is extended per this file's header note: chunk_id(32) ||
// request_ts_ms(8) || repair_auth_sig(64) = 104 bytes.
const (
	repairLengthPrefixSize   = 4
	repairChunkIDSize        = 32
	repairRequestTsSize      = 8 // ADDED — see file header
	repairAuthSigSize        = 64
	repairFrame1PayloadBytes = repairChunkIDSize + repairRequestTsSize + repairAuthSigSize // 104
	repairChunkDataSize      = storage.ChunkDataSize                                       // 262144
)

// ── Frame 2 status codes (IC §4.4.1) ─────────────────────────────────────
const (
	repairStatusOK            = 0x00
	repairStatusNotFound      = 0x01
	repairStatusNotAuthorised = 0x02
	repairStatusCorruption    = 0x03
	repairStatusInternalError = 0x04
)

// repairDownloadTimeout is the IC §4.4.1 timeout (10,000 ms — longer than
// the upload timeout to account for cold disk reads).
const repairDownloadTimeout = 10 * time.Second

// ── MicroserviceAuthorizer ────────────────────────────────────────────────

// MicroserviceAuthorizer answers whether a Peer ID is currently registered
// as a legitimate microservice replica (IC §4.4.1: "refreshed via DHT and
// heartbeat acknowledgements"). Shared by handler_repair.go and
// handler_vetting_gc.go — both mutation protocols ADR-036 places behind the
// same authorization pattern.
//
// GAP (flagged): no session in scope for M13 wires the actual DHT/heartbeat
// refresh mechanism IC §4.4.1 describes; staticMicroserviceAuthorizer below
// is a minimal, explicit, settable set with no automatic population. main.go
// constructs it empty by default, which is fail-closed (every repair-
// download/vetting-gc request is rejected as NOT_AUTHORISED until something
// populates it) rather than fail-open.
type MicroserviceAuthorizer interface {
	IsRegisteredMicroservicePeer(peerID p2p.PeerID) bool
}

// staticMicroserviceAuthorizer is a goroutine-safe, explicitly-settable
// MicroserviceAuthorizer. See the interface doc for the populate-mechanism
// gap this stands in for.
type staticMicroserviceAuthorizer struct {
	mu    sync.RWMutex
	peers map[p2p.PeerID]struct{}
}

func newStaticMicroserviceAuthorizer() *staticMicroserviceAuthorizer {
	return &staticMicroserviceAuthorizer{peers: make(map[p2p.PeerID]struct{})}
}

func (a *staticMicroserviceAuthorizer) IsRegisteredMicroservicePeer(peerID p2p.PeerID) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.peers[peerID]
	return ok
}

// Set replaces the registered-peer set wholesale (e.g. from a future
// heartbeat-ack or DHT-driven refresh — not wired in this session).
func (a *staticMicroserviceAuthorizer) Set(peers []p2p.PeerID) {
	next := make(map[p2p.PeerID]struct{}, len(peers))
	for _, p := range peers {
		next[p] = struct{}{}
	}
	a.mu.Lock()
	a.peers = next
	a.mu.Unlock()
}

// ── RepairDownloadHandler ─────────────────────────────────────────────────

// RepairDownloadHandler implements the /vyomanaut/repair-download/1.0.0
// responder (IC §4.4.1, ADR-036).
type RepairDownloadHandler struct {
	store              storage.ChunkStore
	msPublicKey        ed25519.PublicKey
	authorizer         MicroserviceAuthorizer
	freshnessWindow    time.Duration
	microservicePeerID p2p.PeerID // embedded in the repair_auth_sig signing input
}

// NewRepairDownloadHandler constructs a RepairDownloadHandler.
// freshnessWindow is expected to be config.NetworkProfile.AuthRequestFreshnessWindow
// (ADR-036) — callers must never hardcode this value.
func NewRepairDownloadHandler(
	store storage.ChunkStore,
	msPublicKey ed25519.PublicKey,
	authorizer MicroserviceAuthorizer,
	freshnessWindow time.Duration,
	microservicePeerID p2p.PeerID,
) *RepairDownloadHandler {
	return &RepairDownloadHandler{
		store:              store,
		msPublicKey:        msPublicKey,
		authorizer:         authorizer,
		freshnessWindow:    freshnessWindow,
		microservicePeerID: microservicePeerID,
	}
}

// HandleStream implements p2p.StreamHandler.
func (h *RepairDownloadHandler) HandleStream(s p2p.Stream) {
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(repairDownloadTimeout))

	// ── Step 1: peer authorization, BEFORE any lookup ───────────────────
	remotePeer := s.RemotePeer()
	if h.authorizer == nil || !h.authorizer.IsRegisteredMicroservicePeer(remotePeer) {
		h.writeStatusOnly(s, repairStatusNotAuthorised)
		return
	}

	var lenBuf [repairLengthPrefixSize]byte
	if _, err := readStreamFull(s, lenBuf[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length != repairFrame1PayloadBytes {
		_ = s.Reset()
		return
	}
	payload := make([]byte, length)
	if _, err := readStreamFull(s, payload); err != nil {
		return
	}

	var chunkID [32]byte
	copy(chunkID[:], payload[0:repairChunkIDSize])
	tsOffset := repairChunkIDSize
	requestTsMs := int64(binary.BigEndian.Uint64(payload[tsOffset : tsOffset+repairRequestTsSize]))
	sigOffset := tsOffset + repairRequestTsSize
	var sig [64]byte
	copy(sig[:], payload[sigOffset:sigOffset+repairAuthSigSize])

	// ── Step 2: verify repair_auth_sig ───────────────────────────────────
	if h.msPublicKey == nil || !h.verifyRepairAuthSig(chunkID, requestTsMs, sig) {
		h.writeStatusOnly(s, repairStatusNotAuthorised)
		return
	}

	// ── ADR-036 addendum (between steps 2 and 3): freshness check ────────
	if abs(time.Now().UnixMilli()-requestTsMs) > h.freshnessWindow.Milliseconds() {
		h.writeStatusOnly(s, repairStatusNotAuthorised)
		return
	}

	// ── Step 3: LookupChunk ───────────────────────────────────────────────
	chunkData, err := h.store.LookupChunk(chunkID)
	switch {
	case errors.Is(err, storage.ErrChunkNotFound):
		h.writeStatusOnly(s, repairStatusNotFound)
		return
	case errors.Is(err, storage.ErrContentHashMismatch):
		h.writeStatusOnly(s, repairStatusCorruption)
		return
	case err != nil:
		h.writeStatusOnly(s, repairStatusInternalError)
		return
	}

	// ── Step 4: Frame 2 success ──────────────────────────────────────────
	h.writeSuccessFrame(s, chunkData)
}

// verifyRepairAuthSig verifies:
//
//	repair_auth_sig = Ed25519(digest(chunk_id ‖ request_ts_ms ‖ microservice_peer_id))
func (h *RepairDownloadHandler) verifyRepairAuthSig(chunkID [32]byte, requestTsMs int64, sig [64]byte) bool {
	var pub [32]byte
	copy(pub[:], h.msPublicKey)

	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(requestTsMs))

	peerIDBytes := []byte(h.microservicePeerID.String())
	input := make([]byte, 0, len(chunkID)+len(tsBytes)+len(peerIDBytes))
	input = append(input, chunkID[:]...)
	input = append(input, tsBytes[:]...)
	input = append(input, peerIDBytes...)

	return localcrypto.VerifyBytes(pub, input, sig)
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// ── framing helpers ────────────────────────────────────────────────────

func (h *RepairDownloadHandler) writeStatusOnly(s p2p.Stream, status byte) {
	frame := make([]byte, repairLengthPrefixSize+1)
	binary.BigEndian.PutUint32(frame[0:repairLengthPrefixSize], 1)
	frame[repairLengthPrefixSize] = status
	_, _ = s.Write(frame)
}

// writeSuccessFrame writes the 1+262144=262145-byte Frame 2 for status
// 0x00 (IC §4.4.1).
func (h *RepairDownloadHandler) writeSuccessFrame(s p2p.Stream, chunkData []byte) {
	payloadLen := 1 + len(chunkData)
	frame := make([]byte, repairLengthPrefixSize+payloadLen)
	binary.BigEndian.PutUint32(frame[0:repairLengthPrefixSize], uint32(payloadLen))
	frame[repairLengthPrefixSize] = repairStatusOK
	copy(frame[repairLengthPrefixSize+1:], chunkData)
	_, _ = s.Write(frame)
}

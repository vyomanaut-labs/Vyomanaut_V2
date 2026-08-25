// Command provider is the Vyomanaut V2 provider daemon entrypoint.
// This file implements the /vyomanaut/vetting-gc/1.0.0 stream handler
// (IC §4.5, Session 13.5.1) WITH the ADR-036 security addendum applied
// directly — ADR-036 is Accepted (confirmed against
// Vyomanaut_Research/docs/decisions/ADR-036-authenticated-provider-mutation-protocols.md
// before writing this file), so this is the final authorized form, not the
// unauthenticated "base" handler the milestone text describes for a
// not-yet-accepted ADR. Shipping the base form to any network carrying real
// data was explicitly called out as unsafe by the milestone text itself.
//
// 0-RTT policy: PROHIBITED (IC §4.5) — deny-list membership, responder
// side; see handler_audit.go's header for the transport-substitution
// account of why this is enforced client-side only in this codebase.
//
// [REF: IC §4.5, IC §11, ADR-021, ADR-030, ADR-036, build.md Session 13.5.1]
package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"time"

	localcrypto "github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// ── Protocol ID (IC §4.5) ────────────────────────────────────────────────

const vettingGCProtocolID = p2p.ProtocolID("/vyomanaut/vetting-gc/1.0.0")

// ── Wire-format field sizes ───────────────────────────────────────────────
// Frame 1 (ADR-036-extended): chunk_count(4) || chunk_ids(chunk_count×32) ||
// request_ts_ms(8) || gc_auth_sig(64).
const (
	vettingGCLengthPrefixSize  = 4
	vettingGCChunkCountSize    = 4
	vettingGCChunkIDSize       = 32
	vettingGCRequestTsSize     = 8
	vettingGCAuthSigSize       = 64
	vettingGCMaxChunksPerFrame = 10_000
)

// ── Frame 2 status codes ──────────────────────────────────────────────────
// IC §4.5 base (0x00, 0x01) plus ADR-036's addendum: 0x03 NOT_AUTHORISED
// and 0x04 STALE_REQUEST are new; INTERNAL_ERROR is renumbered 0x02 → 0x05.
const (
	vettingGCStatusOK             = 0x00
	vettingGCStatusPartialFailure = 0x01
	vettingGCStatusNotAuthorised  = 0x03 // ADR-036
	vettingGCStatusStaleRequest   = 0x04 // ADR-036
	vettingGCStatusInternalError  = 0x05 // ADR-036 renumber (was 0x02)
)

// vettingGCFrameTimeout is the IC §4.5 per-frame timeout (30,000 ms).
const vettingGCFrameTimeout = 30 * time.Second

// ── VettingGCHandler ───────────────────────────────────────────────────

// VettingGCHandler implements the /vyomanaut/vetting-gc/1.0.0 responder
// (IC §4.5, ADR-036). One stream may carry multiple sequential
// VettingGCRequest/VettingGCResponse frame pairs (IC §4.5: "the microservice
// sends multiple sequential frames on the same stream ... waiting for
// VettingGCResponse after each before sending the next") — HandleStream
// loops until the initiator closes the stream.
type VettingGCHandler struct {
	store              storage.ChunkStore
	msPublicKey        ed25519.PublicKey
	authorizer         MicroserviceAuthorizer // shared with handler_repair.go
	freshnessWindow    time.Duration          // config.NetworkProfile.AuthRequestFreshnessWindow (ADR-036)
	microservicePeerID p2p.PeerID
}

// NewVettingGCHandler constructs a VettingGCHandler.
func NewVettingGCHandler(
	store storage.ChunkStore,
	msPublicKey ed25519.PublicKey,
	authorizer MicroserviceAuthorizer,
	freshnessWindow time.Duration,
	microservicePeerID p2p.PeerID,
) *VettingGCHandler {
	return &VettingGCHandler{
		store:              store,
		msPublicKey:        msPublicKey,
		authorizer:         authorizer,
		freshnessWindow:    freshnessWindow,
		microservicePeerID: microservicePeerID,
	}
}

// HandleStream implements p2p.StreamHandler.
func (h *VettingGCHandler) HandleStream(s p2p.Stream) {
	defer func() { _ = s.Close() }()

	for {
		if !h.handleOneFrame(s) {
			return
		}
	}
}

const bitsPerByte = 8

// handleOneFrame processes exactly one VettingGCRequest/VettingGCResponse
// pair. It returns false when the stream should end (clean EOF between
// frames, a fatal parse error, or a fatal auth failure), true when the
// caller should loop and read another frame.
func (h *VettingGCHandler) handleOneFrame(s p2p.Stream) bool {
	_ = s.SetDeadline(time.Now().Add(vettingGCFrameTimeout))

	// ── (a) peer authorization, BEFORE any delete ────────────────────────
	// [Added — live verification, M17-E Phase 17.7, same reasoning as
	// handler_repair.go's identical fix] This handler already
	// distinguishes freshness failures from authorization failures at the
	// wire level (vettingGCStatusStaleRequest vs vettingGCStatusNotAuthorised
	// below) — better than repair-download's handler, which uses one code
	// for all three checks — but still collapses "no msPublicKey" (JWKS
	// fetch never succeeded) and "signature doesn't verify" (a genuine
	// key-mismatch or signing-input bug) into the same status and, until
	// now, no log line at all. These log lines close that gap without
	// changing the wire protocol.
	remotePeer := s.RemotePeer()
	if h.authorizer == nil || !h.authorizer.IsRegisteredMicroservicePeer(remotePeer) {
		// [Extended — live verification, same reasoning as
		// handler_repair.go's identical line] Print BOTH the actual
		// dialing peer and this provider's own expected value, so the
		// two can be compared directly instead of inferred.
		log.Printf("[VETTING-GC] rejected (not authorised): remote peer %s does not match this provider's expected microservice peer %q (authorizer populated: %v)",
			remotePeer, h.microservicePeerID, h.authorizer != nil)
		h.writeStatusOnly(s, vettingGCStatusNotAuthorised)
		return false
	}

	var lenBuf [vettingGCLengthPrefixSize]byte
	n, err := io.ReadFull(s, lenBuf[:])
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			// Clean end of stream between frames — normal termination.
			return false
		}
		return false
	}
	declaredLength := binary.BigEndian.Uint32(lenBuf[:])

	var countBuf [vettingGCChunkCountSize]byte
	if _, err := readStreamFull(s, countBuf[:]); err != nil {
		return false
	}
	chunkCount := binary.BigEndian.Uint32(countBuf[:])
	if chunkCount > vettingGCMaxChunksPerFrame {
		_ = s.Reset()
		return false
	}

	expectedLength := uint32(vettingGCChunkCountSize) + chunkCount*vettingGCChunkIDSize +
		vettingGCRequestTsSize + vettingGCAuthSigSize
	if declaredLength != expectedLength {
		_ = s.Reset()
		return false
	}

	chunkIDsBytes := make([]byte, chunkCount*vettingGCChunkIDSize)
	if chunkCount > 0 {
		if _, err := readStreamFull(s, chunkIDsBytes); err != nil {
			return false
		}
	}
	var tsBuf [vettingGCRequestTsSize]byte
	if _, err := readStreamFull(s, tsBuf[:]); err != nil {
		return false
	}
	requestTsMs := int64(binary.BigEndian.Uint64(tsBuf[:]))
	var sig [vettingGCAuthSigSize]byte
	if _, err := readStreamFull(s, sig[:]); err != nil {
		return false
	}

	// ── (b) freshness (ADR-036) ────────────────────────────────────────
	if delta := abs(time.Now().UnixMilli() - requestTsMs); delta > h.freshnessWindow.Milliseconds() {
		log.Printf("[VETTING-GC] rejected (stale): request timestamp %d outside freshness window %s (now=%d, delta=%dms)",
			requestTsMs, h.freshnessWindow, time.Now().UnixMilli(), delta)
		h.writeStatusOnly(s, vettingGCStatusStaleRequest)
		return false
	}

	// ── (c) verify gc_auth_sig (ADR-036) ─────────────────────────────────
	if h.msPublicKey == nil {
		log.Printf("[VETTING-GC] rejected (not authorised): no microservice public key available — JWKS fetch never succeeded for this process's lifetime (see F-17E-11)")
		h.writeStatusOnly(s, vettingGCStatusNotAuthorised)
		return false
	}
	if !h.verifyGCAuthSig(chunkIDsBytes, requestTsMs, sig) {
		log.Printf("[VETTING-GC] rejected (not authorised): gc_auth_sig verification failed for %d chunk(s) requestTsMs=%d", chunkCount, requestTsMs)
		h.writeStatusOnly(s, vettingGCStatusNotAuthorised)
		return false
	}

	// ── Only now: delete ──────────────────────────────────────────────────
	// Classification note: storage.ChunkStore.DeleteChunk delegates to
	// RocksDB's DeleteCF, which is idempotent for missing keys (no distinct
	// "not found" error surfaces from a real delete) — so there is no
	// natural per-call signal distinguishing "this one key's delete failed
	// for an isolated reason" from "the whole batch is broken". Absent such
	// a signal, this handler uses the only structurally available one: if
	// every single deletion in a non-empty batch failed, that is treated as
	// a systemic failure (0x05 INTERNAL_ERROR, full-batch retry per IC
	// §4.5); if only some failed, it is a partial, per-ID failure (0x01,
	// targeted retry via failure_bitmap).
	// failureBitmap size: ceil(chunk_count / 8) bytes (IC §4.5 Frame 2).
	failureBitmap := make([]byte, (chunkCount+bitsPerByte-1)/bitsPerByte)
	failCount := uint32(0)
	for i := uint32(0); i < chunkCount; i++ {
		var id [32]byte
		copy(id[:], chunkIDsBytes[i*vettingGCChunkIDSize:(i+1)*vettingGCChunkIDSize])
		if delErr := h.store.DeleteChunk(id); delErr != nil {
			failCount++
			failureBitmap[i/bitsPerByte] |= 1 << uint(i%bitsPerByte)
		}
	}

	switch {
	case chunkCount > 0 && failCount == chunkCount:
		h.writeStatusOnly(s, vettingGCStatusInternalError)
	case failCount > 0:
		h.writePartialFailureFrame(s, failureBitmap)
	default:
		h.writeStatusOnly(s, vettingGCStatusOK)
	}
	return true
}

// verifyGCAuthSig verifies:
//
//	gc_auth_sig = Ed25519(digest(chunk_ids ‖ request_ts_ms ‖ microservice_peer_id))
func (h *VettingGCHandler) verifyGCAuthSig(chunkIDsBytes []byte, requestTsMs int64, sig [vettingGCAuthSigSize]byte) bool {
	var pub [32]byte
	copy(pub[:], h.msPublicKey)

	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(requestTsMs))
	peerIDBytes := []byte(h.microservicePeerID.String())

	input := make([]byte, 0, len(chunkIDsBytes)+len(tsBytes)+len(peerIDBytes))
	input = append(input, chunkIDsBytes...)
	input = append(input, tsBytes[:]...)
	input = append(input, peerIDBytes...)

	return localcrypto.VerifyBytes(pub, input, sig)
}

// ── framing helpers ────────────────────────────────────────────────────

func (h *VettingGCHandler) writeStatusOnly(s p2p.Stream, status byte) {
	frame := make([]byte, vettingGCLengthPrefixSize+1)
	binary.BigEndian.PutUint32(frame[0:vettingGCLengthPrefixSize], 1)
	frame[vettingGCLengthPrefixSize] = status
	_, _ = s.Write(frame)
}

// writePartialFailureFrame writes the status=0x01 Frame 2, carrying the
// failure_bitmap (IC §4.5: length = 1 + ceil(chunk_count/8)).
func (h *VettingGCHandler) writePartialFailureFrame(s p2p.Stream, bitmap []byte) {
	payloadLen := 1 + len(bitmap)
	frame := make([]byte, vettingGCLengthPrefixSize+payloadLen)
	binary.BigEndian.PutUint32(frame[0:vettingGCLengthPrefixSize], uint32(payloadLen))
	frame[vettingGCLengthPrefixSize] = vettingGCStatusPartialFailure
	copy(frame[vettingGCLengthPrefixSize+1:], bitmap)
	_, _ = s.Write(frame)
}

// Command provider is the Vyomanaut V2 provider daemon entrypoint.
// This file implements the /vyomanaut/audit-challenge/1.0.0 stream handler
// (IC §4.2, Session 13.3.1).
//
// 0-RTT policy: PROHIBITED for this protocol (IC §4.2). Enforcement is by
// explicit deny-list membership (zeroRTTProhibited, internal/p2p/host.go),
// never by a "-challenge" protocol-ID suffix match — the same rule Session
// 13.1.1's main.go documents. internal/p2p's Host applies this automatically
// on the dialing (microservice) side whenever it opens a stream for this
// protocol ID; this responder-side handler performs no additional
// early-data logic of its own because this codebase's transport substitute
// (crypto/tls over TCP, not QUIC — see internal/p2p/doc.go) has no
// responder-observable "early data" distinct from ordinary application
// bytes to police at accept time. See main.go's own header comment for the
// full account of why zeroRTTProhibited enforcement is necessarily
// client-side in this substituted transport.
//
// KNOWN GAP — challenge_nonce version-byte validation (flagged, not fully
// resolvable this session; see the build report's NONCE-VERSION-GAP
// finding): IC §4.2's pre-condition text asks the provider to "verify that
// challenge_nonce[0] ... corresponds to a currently-valid server_secret_vN",
// but ADR-027 §1 is explicit that server_secret_vN is derived from
// cluster_master_seed and lives only in the microservice's secrets-manager
// cache (internal/audit.ClusterSecretCache) — a provider daemon never
// receives it, and cannot recompute or look up which versions are
// currently valid. This handler cannot perform ADR-027's actual
// authorization check (it has no secret to check against — the HMAC itself
// is never verified provider-side; only the microservice, which holds
// server_secret_vN, can do that when it later validates response_hash).
// What IS implementable with only locally-observable information is the
// SPIRIT of the check: reject a version byte that looks like a downgrade
// replay of a long-retired version, using this daemon's own observation
// history rather than the (unavailable) secret. See
// auditNonceVersionTracker below. This is a deliberate, documented
// substitution, not a guess dressed up as spec compliance.
//
// [REF: IC §4.2, IC §11, ADR-021, ADR-027, build.md Session 13.3.1]
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	localcrypto "github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/metrics"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// ── Protocol ID (IC §4.2) ────────────────────────────────────────────────

const auditChallengeProtocolID = p2p.ProtocolID("/vyomanaut/audit-challenge/1.0.0")

// ── Wire-format field sizes (IC §4.2 Frame 1) ────────────────────────────
const (
	auditLengthPrefixSize   = 4
	auditChunkIDSize        = 32
	auditChallengeNonceSize = 33 // 1-byte version prefix || 32-byte HMAC-SHA256 (Invariant 5) — NEVER [32]byte
	auditServerTsSize       = 8
	auditFrame1PayloadBytes = auditChunkIDSize + auditChallengeNonceSize + auditServerTsSize // 73 (IC §4.2)
	auditResponseHashSize   = 32
	auditProviderSigSize    = 64
)

// ── Frame 2 status codes (IC §4.2) ───────────────────────────────────────
const (
	auditStatusOK             = 0x00 // PASS
	auditStatusFailNotFound   = 0x01
	auditStatusFailCorruption = 0x02
	auditStatusInvalidNonce   = 0x03
	auditStatusInternalError  = 0x04
)

// auditStreamTimeout bounds this handler's own read/write I/O — not
// separately specified by IC §4.2 for the responder side (the RTO governs
// the microservice/initiator's own wait), chosen for parity with the
// upload handler's defensive deadline.
const auditStreamTimeout = 5 * time.Second

// auditVersionRetirementWindow mirrors ADR-027's 24-hour rotation-overlap
// window — see this file's header note on why this handler tracks version
// staleness locally rather than validating against the (unavailable)
// server_secret_vN itself.
const auditVersionRetirementWindow = 24 * time.Hour

// ── auditNonceVersionTracker ──────────────────────────────────────────────

// auditNonceVersionTracker implements the locally-observable substitute for
// IC §4.2's "reject a retired secret version" pre-condition — see this
// file's header. It remembers the highest challenge_nonce version byte this
// daemon has ever seen and when it was first seen; a version byte lower
// than the current high-water mark is accepted only within
// auditVersionRetirementWindow of that high-water mark's first sighting,
// mirroring ADR-027's own 24-hour overlap.
type auditNonceVersionTracker struct {
	mu             sync.Mutex
	highest        uint8
	highestFirstAt time.Time
}

func newAuditNonceVersionTracker() *auditNonceVersionTracker {
	return &auditNonceVersionTracker{}
}

// Accept reports whether version is currently acceptable, and records it as
// the new high-water mark if it exceeds the current one.
func (t *auditNonceVersionTracker) Accept(version uint8) bool {
	if version == 0 {
		// ADR-027 §1: versions start at 1 at cluster bootstrap; 0 is never
		// a valid version_byte.
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.highest == 0 {
		t.highest = version
		t.highestFirstAt = time.Now()
		return true
	}
	if version >= t.highest {
		if version > t.highest {
			t.highest = version
			t.highestFirstAt = time.Now()
		}
		return true
	}
	// version < t.highest: still acceptable within the overlap window.
	return time.Since(t.highestFirstAt) <= auditVersionRetirementWindow
}

// ── AuditHandler ───────────────────────────────────────────────────────

// AuditHandler implements the /vyomanaut/audit-challenge/1.0.0 responder
// (IC §4.2).
type AuditHandler struct {
	store              storage.ChunkStore
	providerSigningKey ed25519.PrivateKey
	providerIDBytes    [16]byte // see handler_upload.go's identical field for provenance

	versions *auditNonceVersionTracker
}

// NewAuditHandler constructs an AuditHandler.
func NewAuditHandler(store storage.ChunkStore, providerSigningKey ed25519.PrivateKey, providerIDBytes [16]byte) *AuditHandler {
	return &AuditHandler{
		store:              store,
		providerSigningKey: providerSigningKey,
		providerIDBytes:    providerIDBytes,
		versions:           newAuditNonceVersionTracker(),
	}
}

// HandleStream implements p2p.StreamHandler. Handles at least 32 concurrent
// challenge streams without queuing delay (IC §4.2 concurrency
// requirement) simply by being what it already is: a per-stream handler
// invoked in its own goroutine by internal/p2p's Host (IC §4 rule 3), with
// no handler-level lock or shared mutable state on the hot path other than
// the version tracker's brief, uncontended mutex section and
// storage.ChunkStore.LookupChunk, both documented goroutine-safe.
func (h *AuditHandler) HandleStream(s p2p.Stream) {
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(auditStreamTimeout))

	var lenBuf [auditLengthPrefixSize]byte
	if _, err := readStreamFull(s, lenBuf[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length != auditFrame1PayloadBytes {
		// Includes the "nonce is not 33 bytes" case (Invariant 5): any
		// frame whose total declared length does not match the fixed
		// chunk_id(32)+challenge_nonce(33)+server_challenge_ts_ms(8) layout
		// cannot carry a well-formed 33-byte nonce.
		h.writeStatusOnly(s, auditStatusInvalidNonce)
		return
	}

	payload := make([]byte, length)
	if _, err := readStreamFull(s, payload); err != nil {
		return
	}

	var chunkID [32]byte
	copy(chunkID[:], payload[0:auditChunkIDSize])
	var nonce [auditChallengeNonceSize]byte
	copy(nonce[:], payload[auditChunkIDSize:auditChunkIDSize+auditChallengeNonceSize])
	tsOffset := auditChunkIDSize + auditChallengeNonceSize
	serverChallengeTsMs := int64(binary.BigEndian.Uint64(payload[tsOffset : tsOffset+auditServerTsSize]))

	if !h.versions.Accept(nonce[0]) {
		h.writeStatusOnly(s, auditStatusInvalidNonce)
		return
	}

	chunkData, err := h.store.LookupChunk(chunkID)
	switch {
	case errors.Is(err, storage.ErrChunkNotFound):
		sig := h.signFailReceipt(auditStatusFailNotFound, nonce, serverChallengeTsMs)
		h.writeFailFrame(s, auditStatusFailNotFound, sig)
		return
	case errors.Is(err, storage.ErrContentHashMismatch):
		metrics.DaemonContentHashFailuresTotal.Inc()
		sig := h.signFailReceipt(auditStatusFailCorruption, nonce, serverChallengeTsMs)
		h.writeFailFrame(s, auditStatusFailCorruption, sig)
		return
	case err != nil:
		// ErrVLogRead or any other I/O failure not covered above.
		h.writeStatusOnly(s, auditStatusInternalError)
		return
	}

	start := time.Now()
	responseHash := sha256.Sum256(append(append([]byte{}, chunkData...), nonce[:]...))
	sig := h.signOKReceipt(responseHash, nonce, serverChallengeTsMs)
	h.writeOKFrame(s, responseHash, sig)

	metrics.DaemonAuditResponsesSentTotal.Inc()
	metrics.DaemonAuditResponseLatencyMilliseconds.Observe(float64(time.Since(start).Milliseconds()))
}

// signOKReceipt computes the status=0x00 provider_sig (IC §4.2):
//
//	Ed25519(digest(response_hash ‖ challenge_nonce ‖ server_challenge_ts_ms ‖ provider_id))
func (h *AuditHandler) signOKReceipt(responseHash [auditResponseHashSize]byte, nonce [auditChallengeNonceSize]byte, serverChallengeTsMs int64) [64]byte {
	input := h.auditSigningInputPrefix(nonce, serverChallengeTsMs, responseHash[:])
	return localcrypto.SignBytes(h.providerSigningKey, input)
}

// signFailReceipt computes the status=0x01/0x02 provider_sig (IC §4.2):
//
//	Ed25519(digest(status_byte ‖ challenge_nonce ‖ server_challenge_ts_ms ‖ provider_id))
func (h *AuditHandler) signFailReceipt(status byte, nonce [auditChallengeNonceSize]byte, serverChallengeTsMs int64) [64]byte {
	input := h.auditSigningInputPrefix(nonce, serverChallengeTsMs, []byte{status})
	return localcrypto.SignBytes(h.providerSigningKey, input)
}

// auditSigningInputPrefix builds leading || challenge_nonce ||
// server_challenge_ts_ms || provider_id — the common tail shared by both
// the OK and FAIL signing inputs (IC §4.2), with leading being either
// response_hash(32) or a single status byte.
func (h *AuditHandler) auditSigningInputPrefix(nonce [auditChallengeNonceSize]byte, serverChallengeTsMs int64, leading []byte) []byte {
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(serverChallengeTsMs))

	input := make([]byte, 0, len(leading)+len(nonce)+len(tsBytes)+len(h.providerIDBytes))
	input = append(input, leading...)
	input = append(input, nonce[:]...)
	input = append(input, tsBytes[:]...)
	input = append(input, h.providerIDBytes[:]...)
	return input
}

// ── framing helpers ────────────────────────────────────────────────────

func (h *AuditHandler) writeStatusOnly(s p2p.Stream, status byte) {
	frame := make([]byte, auditLengthPrefixSize+1)
	binary.BigEndian.PutUint32(frame[0:auditLengthPrefixSize], 1)
	frame[auditLengthPrefixSize] = status
	_, _ = s.Write(frame)
}

// writeFailFrame writes a 1+64=65-byte Frame 2 for status 0x01/0x02 (IC
// §4.2: "Error frames 0x01/0x02 are 1 + 64 = 65 bytes, not 1 byte").
func (h *AuditHandler) writeFailFrame(s p2p.Stream, status byte, sig [64]byte) {
	payloadLen := 1 + auditProviderSigSize
	frame := make([]byte, auditLengthPrefixSize+payloadLen)
	binary.BigEndian.PutUint32(frame[0:auditLengthPrefixSize], uint32(payloadLen))
	frame[auditLengthPrefixSize] = status
	copy(frame[auditLengthPrefixSize+1:], sig[:])
	_, _ = s.Write(frame)
}

// writeOKFrame writes the 1+32+64=97-byte Frame 2 for status 0x00.
func (h *AuditHandler) writeOKFrame(s p2p.Stream, responseHash [auditResponseHashSize]byte, sig [64]byte) {
	payloadLen := 1 + auditResponseHashSize + auditProviderSigSize
	frame := make([]byte, auditLengthPrefixSize+payloadLen)
	binary.BigEndian.PutUint32(frame[0:auditLengthPrefixSize], uint32(payloadLen))
	frame[auditLengthPrefixSize] = auditStatusOK
	copy(frame[auditLengthPrefixSize+1:], responseHash[:])
	copy(frame[auditLengthPrefixSize+1+auditResponseHashSize:], sig[:])
	_, _ = s.Write(frame)
}

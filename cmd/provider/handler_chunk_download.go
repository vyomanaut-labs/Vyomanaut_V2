// Command provider is the Vyomanaut V2 provider daemon entrypoint.
// This file implements the /vyomanaut/chunk-download/1.0.0 stream handler
// (ADR-080 §3) — the data owner's read counterpart to handler_upload.go's
// write path.
//
// AUTH MODEL — deliberately NOT handler_repair.go's pattern. Repair
// download authorizes by checking the CALLING PEER against a microservice
// allowlist, then verifies a signature — because its caller set is a
// small, fixed group (microservice replicas) known in advance. This
// protocol's caller set is arbitrary data owners, never pre-registered
// with any provider, so there is nothing to allowlist. Authorization here
// comes ENTIRELY from possessing a valid download_token: the microservice
// signed exactly this (chunk_id, provider_id) pair with exactly this
// expiry. This is the SAME shape handler_upload.go already uses for
// capability_token — no caller-identity check there either, and this file
// mirrors that verification code directly, not handler_repair.go's.
//
// STATUS-CODE SEMANTICS (ADR-080 §4, security-relevant, not mechanical):
// a token that fails to verify (bad signature, expired, wrong provider)
// returns 0x02 NOT_AUTHORISED unconditionally — BEFORE any storage
// lookup — regardless of whether this provider actually holds the chunk.
// Only once a token verifies does an absent chunk return 0x01 NOT_FOUND.
// An unauthenticated prober with a guessed chunk_id therefore learns
// nothing about this provider's holder-set from the status code alone; a
// valid token is itself proof the microservice already told the caller
// this provider holds this chunk, so NOT_FOUND leaks nothing new to them.
//
// [REF: ADR-080, IC §4.1 (capability_token model mirrored here), IC
// §4.4.1 (frame/status template), cmd/provider/handler_upload.go
// (verifyCapabilityTokenFrame — the direct precedent for this file's
// verification logic)]
package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"time"

	localcrypto "github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// ── Protocol ID (ADR-080 §3) ─────────────────────────────────────────────

const chunkDownloadProtocolID = p2p.ProtocolID("/vyomanaut/chunk-download/1.0.0")

// ── Wire-format field sizes (ADR-080 §3) ─────────────────────────────────
// Frame 1: chunk_id(32) || expiry_unix_ms(8) || cap_sig(64) = 104 bytes.
// Every signed field is transmitted — the REPAIR-AUTH-TS-GAP discipline
// handler_repair.go's own header explains; this protocol was designed
// against that finding from the start, not corrected into compliance
// after the fact.
const (
	downloadLengthPrefixSize   = 4
	downloadChunkIDSize        = 32
	downloadExpirySize         = 8
	downloadCapSigSize         = 64
	downloadFrame1PayloadBytes = downloadChunkIDSize + downloadExpirySize + downloadCapSigSize // 104
	downloadChunkDataSize      = storage.ChunkDataSize                                         // 262144
)

// ── Frame 2 status codes — mirrors IC §4.4.1 exactly ─────────────────────
const (
	downloadStatusOK            = 0x00
	downloadStatusNotFound      = 0x01
	downloadStatusNotAuthorised = 0x02
	downloadStatusCorruption    = 0x03
	downloadStatusInternalError = 0x04
)

// downloadCapabilityTokenExpiryGraceMs mirrors handler_upload.go's
// capabilityTokenExpiryGraceMs exactly — the same 30-second clock-skew
// tolerance, for the same reason (the daemon's and microservice's clocks
// are never perfectly synchronised).
const downloadCapabilityTokenExpiryGraceMs = 30_000

// chunkDownloadTimeout matches IC §4.4.1's repair-download timeout
// (10,000 ms, not the shorter upload timeout) — the same cold-disk-read
// justification applies equally here.
const chunkDownloadTimeout = 10 * time.Second

// downloadCapabilityTokenDomainPrefix MUST match
// internal/api/retrieve.go's downloadCapabilityTokenDomainPrefix exactly,
// and MUST differ from handler_upload.go's own capabilityTokenDomainPrefix
// — that difference is the entire domain-separation guarantee ADR-080 §1
// specifies. Changing this string on one side without the other is a
// silent wire break: every token would fail to verify.
const downloadCapabilityTokenDomainPrefix = "vyomanaut-chunk-download-cap-v1"

// ── ChunkDownloadHandler ──────────────────────────────────────────────────

// ChunkDownloadHandler implements the /vyomanaut/chunk-download/1.0.0
// responder (ADR-080 §3).
type ChunkDownloadHandler struct {
	store       storage.ChunkStore
	msPublicKey ed25519.PublicKey
	providerID  [16]byte // this daemon's own provider_id, part of the signing input
}

// NewChunkDownloadHandler constructs a ChunkDownloadHandler. providerID is
// this daemon's own provider_id (the same bytes handler_upload.go's
// providerIDBytes already carries) — a token minted for a DIFFERENT
// provider must not verify here, which is exactly what including it in
// the signing input guarantees.
func NewChunkDownloadHandler(store storage.ChunkStore, msPublicKey ed25519.PublicKey, providerID [16]byte) *ChunkDownloadHandler {
	return &ChunkDownloadHandler{store: store, msPublicKey: msPublicKey, providerID: providerID}
}

// HandleStream implements p2p.StreamHandler.
func (h *ChunkDownloadHandler) HandleStream(s p2p.Stream) {
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(chunkDownloadTimeout))

	var lenBuf [downloadLengthPrefixSize]byte
	if _, err := readStreamFull(s, lenBuf[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length != downloadFrame1PayloadBytes {
		_ = s.Reset()
		return
	}
	payload := make([]byte, length)
	if _, err := readStreamFull(s, payload); err != nil {
		return
	}

	var chunkID [32]byte
	copy(chunkID[:], payload[0:downloadChunkIDSize])
	expiryOffset := downloadChunkIDSize
	expiryUnixMs := int64(binary.BigEndian.Uint64(payload[expiryOffset : expiryOffset+downloadExpirySize]))
	sigOffset := expiryOffset + downloadExpirySize
	var sig [64]byte
	copy(sig[:], payload[sigOffset:sigOffset+downloadCapSigSize])

	// ── Step 1: verify the token BEFORE any storage lookup (ADR-080 §4:
	//    NOT_AUTHORISED must never depend on whether the chunk exists). ──
	if !h.verifyDownloadToken(chunkID, expiryUnixMs, sig) {
		h.writeStatusOnly(s, downloadStatusNotAuthorised)
		return
	}

	// ── Step 2: LookupChunk — only reached once the token verifies. ────
	chunkData, err := h.store.LookupChunk(chunkID)
	switch {
	case errors.Is(err, storage.ErrChunkNotFound):
		h.writeStatusOnly(s, downloadStatusNotFound)
		return
	case errors.Is(err, storage.ErrContentHashMismatch):
		h.writeStatusOnly(s, downloadStatusCorruption)
		return
	case err != nil:
		h.writeStatusOnly(s, downloadStatusInternalError)
		return
	}

	// ── Step 3: Frame 2 success. ────────────────────────────────────────
	h.writeSuccessFrame(s, chunkData)
}

// verifyDownloadToken mirrors handler_upload.go's
// verifyCapabilityTokenFrame field-for-field, differing only in the
// domain prefix (downloadCapabilityTokenDomainPrefix, not upload's) and
// in taking expiry/signature as already-parsed arguments rather than a
// fixed-size token array (this protocol's Frame 1 lays them out directly
// rather than packing them into an opaque token blob first).
func (h *ChunkDownloadHandler) verifyDownloadToken(chunkID [32]byte, expiryUnixMs int64, sig [64]byte) bool {
	nowMs := time.Now().UnixMilli()
	if expiryUnixMs <= nowMs-downloadCapabilityTokenExpiryGraceMs {
		return false
	}
	if h.msPublicKey == nil {
		return false
	}

	var expiryBytes [8]byte
	binary.BigEndian.PutUint64(expiryBytes[:], uint64(expiryUnixMs))

	input := make([]byte, 0, len(downloadCapabilityTokenDomainPrefix)+len(chunkID)+len(h.providerID)+len(expiryBytes))
	input = append(input, []byte(downloadCapabilityTokenDomainPrefix)...)
	input = append(input, chunkID[:]...)
	input = append(input, h.providerID[:]...)
	input = append(input, expiryBytes[:]...)

	var pub [32]byte
	copy(pub[:], h.msPublicKey)
	return localcrypto.VerifyBytes(pub, input, sig)
}

// ── framing helpers — identical shape to handler_repair.go's ────────────

func (h *ChunkDownloadHandler) writeStatusOnly(s p2p.Stream, status byte) {
	frame := make([]byte, downloadLengthPrefixSize+1)
	binary.BigEndian.PutUint32(frame[0:downloadLengthPrefixSize], 1)
	frame[downloadLengthPrefixSize] = status
	_, _ = s.Write(frame)
}

func (h *ChunkDownloadHandler) writeSuccessFrame(s p2p.Stream, chunkData []byte) {
	payloadLen := 1 + len(chunkData)
	frame := make([]byte, downloadLengthPrefixSize+payloadLen)
	binary.BigEndian.PutUint32(frame[0:downloadLengthPrefixSize], uint32(payloadLen))
	frame[downloadLengthPrefixSize] = downloadStatusOK
	copy(frame[downloadLengthPrefixSize+1:], chunkData)
	_, _ = s.Write(frame)
}

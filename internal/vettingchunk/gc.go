// Package vettingchunk is declared in doc.go.
// This file implements GCDelivery (IC §5.10): delivery of the vetting GC
// instruction over /vyomanaut/vetting-gc/1.0.0 on a provider's VETTING →
// ACTIVE transition (IC §4.5, ADR-030).
//
// SECURITY ADDENDUM APPLIED DIRECTLY, not gated behind a flag: ADR-036 —
// Authenticated, Freshness-Bound Provider-Mutation Protocols — is Accepted
// (confirmed against Vyomanaut_Research/docs/decisions/ADR-036-...md before
// writing this file; that ADR explicitly names Session 14.2.1 as "the GC
// client" this addendum lands in). cmd/provider/handler_vetting_gc.go
// (Session 13.5.1) already implements ONLY the ADR-036-extended responder —
// there is no unauthenticated "base" responder left anywhere in this
// codebase to interoperate with, so writing this file to the pasted
// milestone text's unauthenticated "base" form first, with the addendum
// as a later toggle, would produce a client that cannot complete a single
// exchange against the real responder. This file is therefore written
// directly to the addendum: VettingGCRequest carries request_ts_ms +
// gc_auth_sig, and VettingGCResponse handling covers the renumbered status
// set (0x00, 0x01, 0x03 NOT_AUTHORISED, 0x04 STALE_REQUEST,
// 0x05 INTERNAL_ERROR — the original 0x02 is retired by ADR-036).
//
// [Flagged, not silently resolved] Vyomanaut_Research's own IC §4.5 text is
// stale — it still shows the pre-ADR-036 wire format (chunk_count(4) ||
// chunk_ids only, and 0x02 INTERNAL_ERROR unrenumbered). This file matches
// the on-disk, already-Accepted ADR-036 text and the already-built
// responder instead of the stale doc, consistent with this project's
// standing practice of flagging cross-document discrepancies rather than
// silently picking one.
//
// [Decision — PENDING_DELETION staged before delivery is attempted]
// DM §4.5's chunk_assignments.status comment describes PENDING_DELETION as
// covering "owner deleted file (or ACTIVE transition GC in progress)" —
// which only makes sense if every synthetic row is moved out of ACTIVE
// before the GC stream even opens. This also reconciles IC §4.5's
// otherwise-confusing failure-handling text ("status = 0x02: ... they
// remain PENDING_DELETION until the batch succeeds" — remain implies they
// were already there). DeliverGCInstruction below stages ACTIVE →
// PENDING_DELETION for every synthetic row up front, so the audit scheduler
// (active_chunk_assignments only selects status = 'ACTIVE') stops
// challenging these chunks immediately regardless of how delivery below
// turns out.
//
// [REF: IC §4.5, IC §9, DM §4.5, ADR-030, ADR-036,
// build.md Milestone 14 Phase 14.2 Session 14.2.1]

package vettingchunk

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	localcrypto "github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
	"github.com/masamasaowl/Vyomanaut_V2/internal/p2p"
)

// GCDelivery manages the delivery of vetting GC instructions on ACTIVE
// transition (IC §5.10).
type GCDelivery interface {
	// DeliverGCInstruction sends the vetting GC instruction list to the
	// provider daemon via the /vyomanaut/vetting-gc/1.0.0 libp2p protocol.
	// If the provider is offline, marks all synthetic chunk_assignments as
	// 'PENDING_DELETION' and queues retry.
	//
	// Pre-conditions:
	//   - providerID has just transitioned to status = 'ACTIVE'
	//   - providerID had status = 'VETTING' immediately before the transition
	// Post-conditions (on nil error):
	//   - All synthetic chunk_assignments for providerID are marked 'DELETED'
	//   - The provider's vLog no longer contains any synthetic chunk data
	// Error semantics:
	//   - ErrProviderOffline: provider not reachable; rows set to
	//     'PENDING_DELETION'; caller must retry on next heartbeat connection
	//
	// Goroutine-safe: yes.
	DeliverGCInstruction(ctx context.Context, providerID uuid.UUID) error
}

// vettingGCProtocolID is IC §4.5's protocol ID.
const vettingGCProtocolID = p2p.ProtocolID("/vyomanaut/vetting-gc/1.0.0")

// Wire-format field sizes (IC §4.5, ADR-036 addendum) — named rather than
// inlined so no raw byte-count literal appears in the framing arithmetic
// below (this codebase's "no magic numbers" standard).
const (
	gcLengthPrefixSize  = 4
	gcChunkCountSize    = 4
	gcChunkIDSize       = 32
	gcRequestTsSize     = 8  // ADR-036
	gcAuthSigSize       = 64 // ADR-036
	gcMaxChunksPerFrame = 10_000
	gcBitsPerByte       = 8
)

// VettingGCResponse status codes. IC §4.5's original 0x02 INTERNAL_ERROR is
// renumbered to 0x05 by ADR-036; 0x03/0x04 are new.
const (
	gcStatusOK             = 0x00
	gcStatusPartialFailure = 0x01
	gcStatusNotAuthorised  = 0x03 // ADR-036
	gcStatusStaleRequest   = 0x04 // ADR-036
	gcStatusInternalError  = 0x05 // ADR-036 renumber (was 0x02)
)

// vettingGCFrameTimeout is IC §4.5's per-frame timeout.
const vettingGCFrameTimeout = 30 * time.Second

// gcDelivery implements GCDelivery.
type gcDelivery struct {
	db         *sql.DB
	host       p2p.Host
	signingKey ed25519.PrivateKey // microservice signing key; signs gc_auth_sig (ADR-036)
}

// NewGCDelivery constructs a GCDelivery.
func NewGCDelivery(db *sql.DB, host p2p.Host, signingKey ed25519.PrivateKey) GCDelivery {
	return &gcDelivery{db: db, host: host, signingKey: signingKey}
}

// GCRetryBackoffDelay returns how long a caller should wait before retrying
// DeliverGCInstruction for the Nth time (attempt starting at 0) after an
// ErrProviderOffline failure (IC §4.5: "Retries use exponential backoff:
// 5 min → 15 min → 60 min → next heartbeat"). attempt is clamped to the
// last configured step (profile.GCRetryBackoff[len-1]); reaching that step
// means the caller's own heartbeat-triggered retry (IC §4.5 point 2) takes
// over — this function covers only the fixed timed-backoff portion of the
// schedule, never the "next heartbeat" event itself. A standalone function
// of profile (not a gcDelivery method): it is pure arithmetic over
// NetworkProfile and needs no db/host state.
func GCRetryBackoffDelay(profile config.NetworkProfile, attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	last := len(profile.GCRetryBackoff) - 1
	if attempt > last {
		attempt = last
	}
	return profile.GCRetryBackoff[attempt]
}

// DeliverGCInstruction implements GCDelivery.
func (g *gcDelivery) DeliverGCInstruction(ctx context.Context, providerID uuid.UUID) error {
	chunkIDs, err := loadActiveSyntheticChunkIDs(ctx, g.db, providerID)
	if err != nil {
		return fmt.Errorf("vettingchunk: DeliverGCInstruction: %w", err)
	}
	if len(chunkIDs) == 0 {
		return nil
	}

	// Stage every row PENDING_DELETION before attempting delivery — see
	// this file's header comment for why.
	if err := setChunkAssignmentsStatus(ctx, g.db, chunkIDs, providerID, "PENDING_DELETION"); err != nil {
		return fmt.Errorf("vettingchunk: DeliverGCInstruction: stage PENDING_DELETION: %w", err)
	}

	peerID, addrs, err := resolveProviderPeer(ctx, g.db, providerID)
	if err != nil {
		return fmt.Errorf("vettingchunk: DeliverGCInstruction: resolve provider %s: %w: %v", providerID, ErrProviderOffline, err)
	}
	if err := g.host.Connect(ctx, peerID, addrs); err != nil {
		return fmt.Errorf("vettingchunk: DeliverGCInstruction: connect to provider %s: %w: %v", providerID, ErrProviderOffline, err)
	}
	stream, err := g.host.NewStream(ctx, peerID, vettingGCProtocolID)
	if err != nil {
		return fmt.Errorf("vettingchunk: DeliverGCInstruction: open vetting-gc stream to provider %s: %w: %v", providerID, ErrProviderOffline, err)
	}
	defer func() { _ = stream.Close() }()

	microservicePeerID := g.host.PeerID()
	for start := 0; start < len(chunkIDs); start += gcMaxChunksPerFrame {
		end := start + gcMaxChunksPerFrame
		if end > len(chunkIDs) {
			end = len(chunkIDs)
		}
		if err := g.deliverBatch(ctx, stream, providerID, chunkIDs[start:end], microservicePeerID); err != nil {
			return fmt.Errorf("vettingchunk: DeliverGCInstruction: %w", err)
		}
	}
	return nil
}

// deliverBatch sends exactly one VettingGCRequest frame for batch (≤
// gcMaxChunksPerFrame chunk IDs) and processes the matching
// VettingGCResponse frame, updating chunk_assignments accordingly.
func (g *gcDelivery) deliverBatch(ctx context.Context, stream p2p.Stream, providerID uuid.UUID, batch [][32]byte, microservicePeerID p2p.PeerID) error {
	if err := stream.SetDeadline(time.Now().Add(vettingGCFrameTimeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	requestTsMs := time.Now().UnixMilli()
	chunkIDsBytes := make([]byte, 0, len(batch)*gcChunkIDSize)
	for _, id := range batch {
		chunkIDsBytes = append(chunkIDsBytes, id[:]...)
	}
	sig := signGCAuthSig(g.signingKey, chunkIDsBytes, requestTsMs, microservicePeerID)

	if err := writeVettingGCRequest(stream, chunkIDsBytes, uint32(len(batch)), requestTsMs, sig); err != nil {
		return fmt.Errorf("write VettingGCRequest: %w", err)
	}

	status, failureBitmap, err := readVettingGCResponse(stream, uint32(len(batch)))
	if err != nil {
		return fmt.Errorf("read VettingGCResponse: %w", err)
	}

	switch status {
	case gcStatusOK:
		return setChunkAssignmentsStatus(ctx, g.db, batch, providerID, chunkAssignmentStatusDeleted)
	case gcStatusPartialFailure:
		// Failed IDs remain PENDING_DELETION (already staged) for retry on
		// next connection (IC §4.5); only confirmed deletions flip to
		// DELETED.
		succeeded := succeededChunkIDs(batch, failureBitmap)
		if len(succeeded) == 0 {
			return nil
		}
		return setChunkAssignmentsStatus(ctx, g.db, succeeded, providerID, chunkAssignmentStatusDeleted)
	case gcStatusNotAuthorised:
		return fmt.Errorf("provider rejected request: NOT_AUTHORISED (0x%02x)", status)
	case gcStatusStaleRequest:
		return fmt.Errorf("provider rejected request: STALE_REQUEST (0x%02x)", status)
	case gcStatusInternalError:
		// Full-batch retry next connection (IC §4.5); rows already
		// PENDING_DELETION from the staging step above, so no further
		// status change here.
		return fmt.Errorf("provider reported INTERNAL_ERROR (0x%02x)", status)
	default:
		return fmt.Errorf("unrecognised VettingGCResponse status 0x%02x", status)
	}
}

// signGCAuthSig computes ADR-036's gc_auth_sig:
//
//	gc_auth_sig = Ed25519(microservice_signing_key,
//	    SHA-256(chunk_ids ‖ request_ts_ms ‖ microservice_peer_id))
//
// No domain-separation prefix (unlike generator.go's capability_token) —
// matching cmd/provider/handler_vetting_gc.go's verifyGCAuthSig exactly;
// any divergence here would make every gc_auth_sig fail verification.
func signGCAuthSig(signingKey ed25519.PrivateKey, chunkIDsBytes []byte, requestTsMs int64, microservicePeerID p2p.PeerID) [gcAuthSigSize]byte {
	var tsBytes [gcRequestTsSize]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(requestTsMs))
	peerIDBytes := []byte(microservicePeerID.String())

	input := make([]byte, 0, len(chunkIDsBytes)+len(tsBytes)+len(peerIDBytes))
	input = append(input, chunkIDsBytes...)
	input = append(input, tsBytes[:]...)
	input = append(input, peerIDBytes...)

	return localcrypto.SignBytes(signingKey, input)
}

// writeVettingGCRequest writes one VettingGCRequest frame (IC §4.5,
// ADR-036 addendum):
//
//	length(4) || chunk_count(4) || chunk_ids(chunk_count×32) ||
//	request_ts_ms(8) || gc_auth_sig(64)
//
// length = 4 + (chunk_count×32) + 8 + 64 (ADR-036), matching
// cmd/provider/handler_vetting_gc.go's expectedLength exactly.
func writeVettingGCRequest(s p2p.Stream, chunkIDsBytes []byte, chunkCount uint32, requestTsMs int64, sig [gcAuthSigSize]byte) error {
	payloadLen := gcChunkCountSize + len(chunkIDsBytes) + gcRequestTsSize + gcAuthSigSize
	frame := make([]byte, gcLengthPrefixSize+payloadLen)
	binary.BigEndian.PutUint32(frame[0:gcLengthPrefixSize], uint32(payloadLen))
	offset := gcLengthPrefixSize
	binary.BigEndian.PutUint32(frame[offset:offset+gcChunkCountSize], chunkCount)
	offset += gcChunkCountSize
	copy(frame[offset:offset+len(chunkIDsBytes)], chunkIDsBytes)
	offset += len(chunkIDsBytes)
	binary.BigEndian.PutUint64(frame[offset:offset+gcRequestTsSize], uint64(requestTsMs))
	offset += gcRequestTsSize
	copy(frame[offset:offset+gcAuthSigSize], sig[:])
	_, err := s.Write(frame)
	return err
}

// readVettingGCResponse reads one VettingGCResponse frame (IC §4.5):
// length(4) || status(1) || failure_bitmap(ceil(chunk_count/8), present
// only when status = 0x01).
func readVettingGCResponse(s p2p.Stream, chunkCount uint32) (status byte, failureBitmap []byte, err error) {
	var lengthBuf [gcLengthPrefixSize]byte
	if _, err := io.ReadFull(s, lengthBuf[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	body := make([]byte, length)
	if _, err := io.ReadFull(s, body); err != nil {
		return 0, nil, err
	}
	if len(body) < 1 {
		return 0, nil, fmt.Errorf("empty VettingGCResponse body")
	}
	status = body[0]
	if status == gcStatusPartialFailure {
		wantBitmapLen := (int(chunkCount) + gcBitsPerByte - 1) / gcBitsPerByte
		if len(body)-1 != wantBitmapLen {
			return 0, nil, fmt.Errorf("status 0x01 but failure_bitmap length %d, want %d", len(body)-1, wantBitmapLen)
		}
		failureBitmap = body[1:]
	}
	return status, failureBitmap, nil
}

// succeededChunkIDs returns the subset of batch NOT marked failed in
// failureBitmap (IC §4.5: "Bit N is set if deletion of chunk_ids[N] failed").
func succeededChunkIDs(batch [][32]byte, failureBitmap []byte) [][32]byte {
	succeeded := make([][32]byte, 0, len(batch))
	for i, id := range batch {
		byteIdx := i / gcBitsPerByte
		bitIdx := uint(i % gcBitsPerByte)
		if byteIdx < len(failureBitmap) && failureBitmap[byteIdx]&(1<<bitIdx) != 0 {
			continue // failed; leave PENDING_DELETION for retry
		}
		succeeded = append(succeeded, id)
	}
	return succeeded
}

// loadActiveSyntheticChunkIDs returns every synthetic vetting chunk ID
// currently ACTIVE for providerID (IC §4.5: "all synthetic vetting chunk
// IDs where is_vetting_chunk = TRUE AND provider_id = $1 AND
// status = 'ACTIVE'"), ordered by chunk_id for deterministic batching.
func loadActiveSyntheticChunkIDs(ctx context.Context, db *sql.DB, providerID uuid.UUID) ([][32]byte, error) {
	const query = `
SELECT chunk_id FROM chunk_assignments
WHERE is_vetting_chunk = TRUE AND provider_id = $1 AND status = 'ACTIVE'
ORDER BY chunk_id`
	rows, err := db.QueryContext(ctx, query, providerID)
	if err != nil {
		return nil, fmt.Errorf("loadActiveSyntheticChunkIDs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out [][32]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("loadActiveSyntheticChunkIDs: scan: %w", err)
		}
		var id [32]byte
		copy(id[:], raw)
		out = append(out, id)
	}
	return out, rows.Err()
}

// chunkAssignmentStatusDeleted is the terminal status set on confirmed
// deletion (DM §4.5).
const chunkAssignmentStatusDeleted = "DELETED"

// setChunkAssignmentsStatus updates chunk_assignments.status for exactly
// the given chunk IDs and providerID. When status is DELETED, deleted_at is
// set to NOW() in the same statement (DM §4.5: "Set when status transitions
// to DELETED") — required by the schema's own RLS WITH CHECK on this
// UPDATE (chunk_assignments_status_update: status <> 'DELETED' OR
// deleted_at IS NOT NULL), not merely documentation; an UPDATE that set
// status = 'DELETED' without deleted_at would be rejected by Postgres at
// the vyomanaut_app role, not merely non-conformant.
func setChunkAssignmentsStatus(ctx context.Context, db *sql.DB, chunkIDs [][32]byte, providerID uuid.UUID, status string) error {
	ids := make([][]byte, len(chunkIDs))
	for i, id := range chunkIDs {
		idCopy := id
		ids[i] = idCopy[:]
	}

	update := `
UPDATE chunk_assignments SET status = $1
WHERE provider_id = $2 AND chunk_id = ANY($3::bytea[])`
	if status == chunkAssignmentStatusDeleted {
		update = `
UPDATE chunk_assignments SET status = $1, deleted_at = NOW()
WHERE provider_id = $2 AND chunk_id = ANY($3::bytea[])`
	}
	if _, err := db.ExecContext(ctx, update, status, providerID, pq.Array(ids)); err != nil {
		return fmt.Errorf("setChunkAssignmentsStatus: %w", err)
	}
	return nil
}
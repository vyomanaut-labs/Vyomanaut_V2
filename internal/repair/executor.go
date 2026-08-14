// Package repair is declared in doc.go.
// This file implements the repair download/decode/re-encode/upload pipeline
// (IC §4.4.1, IC §4.4.2, IC §4.1) and declares RepairTransport/RepairStream,
// the narrow transport abstraction this package needs.
//
// [Decision, build.md Phase 9.2 Session 9.2.1 — confirmed with the user:
// "build it up from scratch... document your decision in the code"]
// The milestone text's own flagged resolution for avoiding an internal/p2p
// import was: "internal/repair declares its own narrow, package-local
// transport interface; internal/p2p.Host satisfies it structurally without
// either package importing the other" — mirroring IC §5.4's
// peer.ID/protocol.ID/network.Stream (from github.com/libp2p/go-libp2p).
// That mirroring doesn't hold in THIS codebase: internal/p2p/doc.go records
// a deliberate, environment-forced substitution (no network access to
// proxy.golang.org/golang.org to pull the real go-libp2p dependency tree —
// see that file for the full account), so p2p.PeerID / p2p.ProtocolID /
// p2p.Stream are p2p-package-LOCAL named types, not shared third-party ones.
// Go requires exact type identity for interface satisfaction; a
// RepairTransport declared in terms of p2p.PeerID etc. could only be
// satisfied by p2p.Host if this package imported internal/p2p to name those
// types, defeating the whole point of the interface.
//
// Resolution: RepairTransport.NewStream and RepairStream are declared using
// ONLY stdlib-compatible types — plain strings for peer/protocol identifiers,
// and a stream interface built purely from io.Reader/io.Writer/io.Closer plus
// a stdlib-typed SetDeadline. p2p.Stream (types.go) already has all of those
// methods among its larger method set, so it satisfies RepairStream
// structurally with zero changes on either side. This is the exact same
// technique internal/audit already uses for SecretsManagerClient
// (secrets_iface.go: "GetSecret(ctx, path string) ([]byte, error)" — composed
// entirely of stdlib types for the same reason). The microservice entrypoint
// (Milestone 12) is expected to supply a small adapter converting
// string<->p2p.PeerID / string<->p2p.ProtocolID (trivial, since both are
// underlying strings) rather than passing *p2p.Host directly — that adapter
// is wiring code, not part of either package.
//
// [REF: IC §4.1, IC §4.4.1, IC §4.4.2, FR-042-FR-045, ADR-004,
// build.md Phase 9.2 Session 9.2.1]

package repair

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
)

// RepairTransport is the narrow subset of a libp2p-style host this package
// needs to open download/upload streams — see this file's header comment for
// why it is declared entirely in terms of stdlib-compatible types.
type RepairTransport interface {
	NewStream(ctx context.Context, peerID string, protocolID string) (RepairStream, error)
}

// RepairStream is the narrow subset of a stream this package needs: raw byte
// read/write, close, and a single deadline setter for the fixed 10s
// repair-download timeout (IC §4.4.1) / 5s upload timeout (IC §4.1).
type RepairStream interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(t time.Time) error
}

// SurvivingHolder identifies one provider currently holding a live shard for
// the segment being repaired. Supplied by the caller (Milestone 12's
// orchestration), which already has this from chunk_assignments plus
// whatever provider_id -> dialable peer identifier resolution the
// microservice entrypoint wires up — internal/repair itself never resolves a
// provider_id to a libp2p peer identity, since that derivation (from
// providers.ed25519_public_key) is p2p-package territory this package must
// not import (see RepairTransport's doc comment above).
type SurvivingHolder struct {
	ProviderID uuid.UUID
	PeerID     string
	ShardIndex int
}

// Protocol IDs (IC §4.4.1, IC §4.1).
const (
	repairDownloadProtocolID = "/vyomanaut/repair-download/1.0.0"
	chunkUploadProtocolID    = "/vyomanaut/chunk-upload/1.0.0"
)

// Timeouts (IC §4.4.1, IC §4.1).
const (
	repairDownloadTimeout = 10 * time.Second
	chunkUploadTimeout    = 5 * time.Second
	capabilityTokenTTL    = 1 * time.Hour
)

// maxRepairReplacementRetries bounds how many different replacement
// candidates ExecuteRepairJob will try before giving up, when a candidate
// reports STORAGE_FULL (IC §4.1 status 0x04) rather than succeeding.
// [Added, M9 review Optional Fix A] Mirrors the same "bounded retries, not
// unbounded spinning" philosophy as assignment.go's own
// maxReplacementSelectionAttempts (for the ASN-cap loser case) — a distinct
// constant because the two retry loops bound different failure domains
// (a candidate rejected before ever being asked, vs. one that was asked and
// declined at capacity) and there is no reason their budgets need to match.
const maxRepairReplacementRetries = 3

// Wire-format field sizes (IC §4.4.1 Frame 1, IC §4.1 Frame 1) — named
// rather than inlined so no raw byte-count literal appears in the framing
// arithmetic below (this codebase's "no magic numbers" standard, mnd linter).
const (
	lengthPrefixSize      = 4  // uint32 big-endian frame length prefix (every frame)
	chunkIDFieldSize      = 32 // SHA-256 content address
	repairRequestTsSize   = 8  // [Added — F-16-3] see downloadOneShard's doc comment: cmd/provider/handler_repair.go's own "WIRE-FORMAT CORRECTION" note extended Frame 1 with this field; this file was never updated to match
	repairAuthSigSize     = 64 // Ed25519 signature (RepairDownloadRequest)
	shardIndexFieldSize   = 4  // uint32 big-endian (UploadRequest)
	capabilityTokenSize   = 72 // expiry_unix_ms(8) || Ed25519 signature(64) (UploadRequest)
	uploadProviderSigSize = 64 // Ed25519 signature (UploadResponse, present on 0x00)
)

// Repair-download status codes (IC §4.4.1 Frame 2).
const (
	repairDownloadStatusOK            = 0x00
	repairDownloadStatusNotFound      = 0x01
	repairDownloadStatusNotAuthorised = 0x02
	repairDownloadStatusCorruption    = 0x03
	repairDownloadStatusInternalError = 0x04
)

// Chunk-upload status codes (IC §4.1 Frame 2).
const (
	uploadStatusOK                = 0x00
	uploadStatusFrameTooLarge     = 0x01
	uploadStatusChunkIDMismatch   = 0x02
	uploadStatusNotAssigned       = 0x03
	uploadStatusStorageFull       = 0x04
	uploadStatusInternalError     = 0x05
	uploadStatusAlreadyStored     = 0x06 // idempotent; treat as OK
	uploadStatusCapabilityExpired = 0x07
)

// ExecuteRepairJob runs the full repair pipeline for one dequeued job:
//
//  1. Download. Contact profile.DataShards (16 in production, 3 in demo)
//     surviving shard holders in order, stopping as soon as enough have
//     succeeded. 0-RTT is PROHIBITED on the repair-download stream (IC
//     §4.4.1); RepairStream exposes no early-data control surface of its own
//     (deliberately — see this file's header comment), so DisableEarlyData
//     enforcement lives in the concrete p2p.Host the caller injects as
//     RepairTransport, not here.
//  2. Reconstruct. Once profile.DataShards valid shards are collected,
//     RS-decode to the AONT package, then RE-ENCODE THE FULL
//     profile.TotalShards-shard set. The shard index needing replacement can
//     be any index from 0 to profile.TotalShards-1 — a data shard or a
//     parity shard; it is not necessarily parity-only.
//  3. Pre-register, then upload. The new chunk_assignments row (status =
//     REPAIRING) is INSERTed for the replacement provider BEFORE the upload
//     stream opens — the replacement's own NOT_ASSIGNED check (IC §4.1
//     status 0x03) would otherwise reject the frame. A capability_token
//     (expiry_unix_ms(8B) || Ed25519 signature, 1-hour TTL) is minted and the
//     shard is uploaded via the standard /vyomanaut/chunk-upload/1.0.0
//     protocol — identical wire format to a normal client upload; the
//     replacement provider cannot and must not be able to distinguish a
//     repair upload from a normal one.
//  4. Confirm. On UploadResponse status 0x00 (or 0x06 ALREADY_STORED,
//     idempotent): mark the job COMPLETED and flip the new assignment from
//     REPAIRING to ACTIVE. On failure: mark the job FAILED.
//
// job.ChunkID is used unchanged as the re-uploaded chunk's identity: RS
// re-encoding is deterministic given the same AONT package, so the
// regenerated shard at the missing index is byte-identical to the original
// (same SHA-256 chunk_id) — repair recreates the exact lost shard, it does
// not mint a new one.
//
// Goroutine-safe: yes (no shared mutable package state; every parameter is
// caller-owned).
func ExecuteRepairJob(
	ctx context.Context,
	db *sql.DB,
	profile config.NetworkProfile,
	transport RepairTransport,
	engine *erasure.Engine,
	signingKey ed25519.PrivateKey,
	microservicePeerID string,
	job *RepairJob,
	survivingHolders []SurvivingHolder,
	excludeProviderIDs []uuid.UUID,
) error {
	// ── 1. Download ──────────────────────────────────────────────────────────
	shards, err := downloadShards(ctx, transport, profile, signingKey, microservicePeerID, job.ChunkID, survivingHolders)
	if err != nil {
		_ = MarkJobComplete(ctx, db, job.JobID, false)
		return fmt.Errorf("repair.ExecuteRepairJob: download: %w", err)
	}

	// ── 2. Reconstruct ───────────────────────────────────────────────────────
	aontPackage, err := engine.DecodeSegment(shards)
	if err != nil {
		_ = MarkJobComplete(ctx, db, job.JobID, false)
		return fmt.Errorf("repair.ExecuteRepairJob: decode: %w", err)
	}
	regenerated, err := engine.EncodeSegment(aontPackage)
	if err != nil {
		_ = MarkJobComplete(ctx, db, job.JobID, false)
		return fmt.Errorf("repair.ExecuteRepairJob: re-encode: %w", err)
	}

	missingIndex, err := findMissingShardIndex(survivingHolders, profile.TotalShards)
	if err != nil {
		_ = MarkJobComplete(ctx, db, job.JobID, false)
		return fmt.Errorf("repair.ExecuteRepairJob: %w", err)
	}
	replacementShard := regenerated[missingIndex]

	// ── 3. Select replacement, pre-register, THEN upload ────────────────────
	// [Added, M9 review Optional Fix A] Bounded retry on STORAGE_FULL
	// (IC §4.1 status 0x04): uploadShard's status switch previously treated
	// every non-OK/ALREADY_STORED code identically as a hard failure. A
	// single unlucky Power-of-Two-Choices draw landing on a candidate that
	// is momentarily full shouldn't fail the whole job — SelectReplacementProvider
	// already gives the same self-healing treatment to an ASN-cap loser
	// (assignment.go); this extends the same philosophy to a capacity
	// loser. Each failed attempt's pre-registered REPAIRING row is soft-
	// deleted before the next candidate is tried, so it never blocks
	// idx_chunk_assignments_one_active_per_shard for the next attempt —
	// the exact same soft-delete discipline Fix 1 established for departure
	// cleanup. Bounded by maxRepairReplacementRetries; any other upload
	// failure (not STORAGE_FULL) still fails the job immediately, unretried.
	replacementExcluded := append([]uuid.UUID{}, excludeProviderIDs...)
	var replacementProviderID uuid.UUID
	var uploadErr error

	for attempt := 0; attempt < maxRepairReplacementRetries; attempt++ {
		candidateID, selectErr := SelectReplacementProvider(ctx, db, profile, job.SegmentID, replacementExcluded)
		if selectErr != nil {
			_ = MarkJobComplete(ctx, db, job.JobID, false)
			return fmt.Errorf("repair.ExecuteRepairJob: select replacement: %w", selectErr)
		}

		if err := preRegisterChunkAssignment(ctx, db, job.ChunkID, job.SegmentID, missingIndex, candidateID); err != nil {
			_ = MarkJobComplete(ctx, db, job.JobID, false)
			return fmt.Errorf("repair.ExecuteRepairJob: pre-register: %w", err)
		}

		token := mintCapabilityToken(signingKey, job.ChunkID, candidateID, capabilityTokenTTL)

		// See SurvivingHolder's doc comment: provider_id -> peer-ID resolution is
		// out of this package's scope; Milestone 12's wiring supplies the real
		// value inside RepairTransport's concrete implementation.
		candidatePeerID := candidateID.String()

		uploadErr = uploadShard(ctx, transport, candidatePeerID, job.ChunkID, missingIndex, token, replacementShard)
		if uploadErr == nil {
			replacementProviderID = candidateID
			break
		}
		if !errors.Is(uploadErr, ErrReplacementStorageFull) {
			_ = MarkJobComplete(ctx, db, job.JobID, false)
			return fmt.Errorf("repair.ExecuteRepairJob: upload: %w", uploadErr)
		}

		// STORAGE_FULL: free the slot this candidate just claimed and never
		// draw it again this job, then loop to try another candidate.
		if cleanupErr := abandonFailedReplacementAssignment(ctx, db, job.ChunkID, candidateID); cleanupErr != nil {
			_ = MarkJobComplete(ctx, db, job.JobID, false)
			return fmt.Errorf("repair.ExecuteRepairJob: %w (cleaning up after STORAGE_FULL from %s)", cleanupErr, candidateID)
		}
		replacementExcluded = append(replacementExcluded, candidateID)
	}

	if uploadErr != nil {
		_ = MarkJobComplete(ctx, db, job.JobID, false)
		return fmt.Errorf("repair.ExecuteRepairJob: upload: exhausted %d replacement attempts, last error: %w",
			maxRepairReplacementRetries, uploadErr)
	}

	// ── 4. Confirm ───────────────────────────────────────────────────────────
	if err := activateChunkAssignment(ctx, db, job.ChunkID, replacementProviderID); err != nil {
		return fmt.Errorf("repair.ExecuteRepairJob: activate: %w", err)
	}
	if err := MarkJobComplete(ctx, db, job.JobID, true); err != nil {
		return fmt.Errorf("repair.ExecuteRepairJob: mark complete: %w", err)
	}
	return nil
}

// abandonFailedReplacementAssignment soft-deletes a replacement candidate's
// pre-registered REPAIRING row after that candidate's upload attempt failed
// with STORAGE_FULL — otherwise the row would permanently block
// idx_chunk_assignments_one_active_per_shard for every subsequent candidate
// this job tries. Mirrors departure.go's own soft-delete discipline (M9
// review Fix 1): never a hard DELETE, always status='DELETED' + deleted_at.
//
// [Added, M9 review Optional Fix A]
func abandonFailedReplacementAssignment(ctx context.Context, db *sql.DB, chunkID [32]byte, providerID uuid.UUID) error {
	const query = `
UPDATE chunk_assignments
SET status = 'DELETED', deleted_at = NOW()
WHERE chunk_id = $1 AND provider_id = $2 AND status = 'REPAIRING'`
	if _, err := db.ExecContext(ctx, query, chunkID[:], providerID); err != nil {
		return fmt.Errorf("abandon failed replacement assignment: %w", err)
	}
	return nil
}

// findMissingShardIndex returns the single shard index in [0, totalShards)
// not represented among holders' ShardIndex values. This package's repair
// pipeline handles exactly one missing shard per job (matching
// repair_jobs.provider_id identifying exactly one departed/failed holder for
// departure-triggered jobs); an error here signals the caller supplied a
// survivingHolders list inconsistent with that assumption.
func findMissingShardIndex(holders []SurvivingHolder, totalShards int) (int, error) {
	present := make(map[int]bool, len(holders))
	for _, h := range holders {
		present[h.ShardIndex] = true
	}
	missing := -1
	count := 0
	for i := 0; i < totalShards; i++ {
		if !present[i] {
			missing = i
			count++
		}
	}
	if count != 1 {
		return 0, fmt.Errorf("findMissingShardIndex: want exactly one missing index among %d shards (TotalShards=%d), found %d",
			len(holders), totalShards, count)
	}
	return missing, nil
}

// ── Download ───────────────────────────────────────────────────────────────────

// downloadShards contacts holders in order, stopping once profile.DataShards
// shards have been successfully collected. A holder that returns
// NOT_FOUND/CORRUPTION (IC §4.4.1 status 0x01/0x03) or fails at the
// transport level is skipped in favour of the next candidate — up to
// profile.ParityShards extra holders are available before running out —
// rather than aborting the whole job on a single failure.
func downloadShards(
	ctx context.Context,
	transport RepairTransport,
	profile config.NetworkProfile,
	signingKey ed25519.PrivateKey,
	microservicePeerID string,
	chunkID [32]byte,
	holders []SurvivingHolder,
) ([][]byte, error) {
	shards := make([][]byte, profile.TotalShards) // nil-filled; erasure.DecodeSegment treats nil entries as erasures
	collected := 0
	// [Added — repair pipeline investigation] attemptErrs preserves each
	// holder's actual failure reason for the aggregate error below.
	// Previously discarded entirely (bare `continue`) — correct as a
	// control-flow decision (one bad holder must not abort the whole
	// download), but it meant two consecutive live failures produced the
	// byte-for-byte identical top-level error message regardless of
	// whether the underlying cause was the same or had changed, since
	// nothing distinguished "frame rejected" from "not authorised" from
	// "corrupted" from "connection refused" at this level.
	attemptErrs := make([]string, 0, len(holders))
	for _, h := range holders {
		if collected >= profile.DataShards {
			break
		}
		data, err := downloadOneShard(ctx, transport, signingKey, microservicePeerID, chunkID, h.PeerID)
		if err != nil {
			attemptErrs = append(attemptErrs, fmt.Sprintf("%s: %v", h.PeerID, err))
			continue // try the next surviving holder
		}
		shards[h.ShardIndex] = data
		collected++
	}
	if collected < profile.DataShards {
		return nil, fmt.Errorf("downloadShards: only %d of %d required shards recovered from %d candidate holders: [%s]",
			collected, profile.DataShards, len(holders), strings.Join(attemptErrs, "; "))
	}
	return shards, nil
}

// downloadOneShard performs one complete /vyomanaut/repair-download/1.0.0
// round trip (IC §4.4.1) against holderPeerID.
func downloadOneShard(
	ctx context.Context,
	transport RepairTransport,
	signingKey ed25519.PrivateKey,
	microservicePeerID string,
	chunkID [32]byte,
	holderPeerID string,
) ([]byte, error) {
	stream, err := transport.NewStream(ctx, holderPeerID, repairDownloadProtocolID)
	if err != nil {
		return nil, fmt.Errorf("open repair-download stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	if err := stream.SetDeadline(time.Now().Add(repairDownloadTimeout)); err != nil {
		return nil, fmt.Errorf("set repair-download deadline: %w", err)
	}

	requestTsMs := time.Now().UnixMilli()
	sig := signRepairDownloadRequest(signingKey, chunkID, requestTsMs, microservicePeerID)

	// Frame 1 — RepairDownloadRequest: length(4) || chunk_id(32) ||
	// request_ts_ms(8) || repair_auth_sig(64).
	//
	// [Fixed — F-16-3] request_ts_ms must actually be transmitted, not
	// just used locally to compute repair_auth_sig — see
	// signRepairDownloadRequest's own doc comment and
	// cmd/provider/handler_repair.go's header note (its "WIRE-FORMAT
	// CORRECTION" flagging exactly this gap): the responder cannot verify
	// repair_auth_sig, which is signed over request_ts_ms, without also
	// receiving that value on the wire, and separately cannot freshness-
	// check the request per ADR-036 §2 without it either. This client
	// sent the original, pre-correction 96-byte frame (chunk_id ||
	// repair_auth_sig only) while the provider's handler required and
	// read the corrected 104-byte frame — every repair-download request
	// was rejected (length mismatch, stream reset) before Frame 2 was
	// ever sent, indistinguishable from every holder being unreachable.
	var frame1 [lengthPrefixSize + chunkIDFieldSize + repairRequestTsSize + repairAuthSigSize]byte
	binary.BigEndian.PutUint32(frame1[0:lengthPrefixSize], chunkIDFieldSize+repairRequestTsSize+repairAuthSigSize)
	offset := lengthPrefixSize
	copy(frame1[offset:offset+chunkIDFieldSize], chunkID[:])
	offset += chunkIDFieldSize
	binary.BigEndian.PutUint64(frame1[offset:offset+repairRequestTsSize], uint64(requestTsMs))
	offset += repairRequestTsSize
	copy(frame1[offset:], sig[:])
	if _, err := stream.Write(frame1[:]); err != nil {
		return nil, fmt.Errorf("write RepairDownloadRequest: %w", err)
	}

	// Frame 2 — RepairDownloadResponse: length(4) || status(1) [|| chunk_data(262144)].
	var lengthBuf [4]byte
	if _, err := io.ReadFull(stream, lengthBuf[:]); err != nil {
		return nil, fmt.Errorf("read RepairDownloadResponse length: %w", err)
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	body := make([]byte, length)
	if _, err := io.ReadFull(stream, body); err != nil {
		return nil, fmt.Errorf("read RepairDownloadResponse body: %w", err)
	}
	if len(body) < 1 {
		return nil, fmt.Errorf("RepairDownloadResponse: empty body")
	}

	status := body[0]
	switch status {
	case repairDownloadStatusOK:
		if len(body) != 1+erasure.ShardSize {
			return nil, fmt.Errorf("RepairDownloadResponse: status OK but body length %d, want %d", len(body), 1+erasure.ShardSize)
		}
		return body[1:], nil
	case repairDownloadStatusNotFound, repairDownloadStatusCorruption:
		return nil, fmt.Errorf("RepairDownloadResponse: status 0x%02x (try next holder)", status)
	case repairDownloadStatusNotAuthorised, repairDownloadStatusInternalError:
		return nil, fmt.Errorf("RepairDownloadResponse: status 0x%02x", status)
	default:
		return nil, fmt.Errorf("RepairDownloadResponse: unrecognised status 0x%02x", status)
	}
}

// signRepairDownloadRequest computes:
//
//	repair_auth_sig = Ed25519_sign(microservice_signing_key,
//	    SHA-256(chunk_id ‖ request_ts_ms ‖ microservice_peer_id))
//
// (IC §4.4.1).
func signRepairDownloadRequest(signingKey ed25519.PrivateKey, chunkID [32]byte, requestTsMs int64, microservicePeerID string) [64]byte {
	h := sha256.New()
	h.Write(chunkID[:])
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(requestTsMs))
	h.Write(tsBuf[:])
	h.Write([]byte(microservicePeerID))
	digest := h.Sum(nil)

	sig := ed25519.Sign(signingKey, digest)
	var out [64]byte
	copy(out[:], sig)
	return out
}

// ── Pre-registration, capability token, upload ────────────────────────────────

// preRegisterChunkAssignment INSERTs the new chunk_assignments row for the
// replacement provider with status='REPAIRING', BEFORE the upload stream
// opens (IC §4.4.2) — the provider's own NOT_ASSIGNED check (IC §4.1 status
// 0x03) requires the assignment to already exist by the time the
// UploadRequest frame arrives.
func preRegisterChunkAssignment(ctx context.Context, db *sql.DB, chunkID [32]byte, segmentID uuid.UUID, shardIndex int, providerID uuid.UUID) error {
	const insert = `
INSERT INTO chunk_assignments (chunk_id, is_vetting_chunk, segment_id, shard_index, provider_id, status)
VALUES ($1, FALSE, $2, $3, $4, 'REPAIRING')`
	if _, err := db.ExecContext(ctx, insert, chunkID[:], segmentID, shardIndex, providerID); err != nil {
		return fmt.Errorf("insert chunk_assignments (REPAIRING): %w", err)
	}
	return nil
}

// mintCapabilityToken builds the 72-byte capability_token (IC §4.1):
//
//	signing_input = SHA-256(
//	    "vyomanaut-chunk-upload-cap-v1"
//	    || chunk_id          (32 bytes)
//	    || provider_id       (16 bytes, UUID bytes, big-endian)
//	    || expiry_unix_ms    (8 bytes, int64 big-endian)
//	)
//	capability_token = expiry_unix_ms (8 B) || Ed25519_sign(microservice_signing_key, signing_input)
//
// file_id is deliberately NOT part of this signing input — Design Council
// verdict ("Capability Token: Drop file_id, Not Add It to the Wire
// Format", ADR-072): chunk_id is 256 bits of fresh, microservice-generated
// randomness minted once per assignment and never reused across files, so
// it already carries the exact binding file_id would have provided.
func mintCapabilityToken(signingKey ed25519.PrivateKey, chunkID [32]byte, providerID uuid.UUID, ttl time.Duration) [72]byte {
	expiryUnixMs := time.Now().Add(ttl).UnixMilli()

	h := sha256.New()
	h.Write([]byte("vyomanaut-chunk-upload-cap-v1"))
	h.Write(chunkID[:])
	h.Write(providerID[:]) // uuid.UUID is [16]byte in its natural (big-endian/network) byte order
	var expiryBuf [8]byte
	binary.BigEndian.PutUint64(expiryBuf[:], uint64(expiryUnixMs))
	h.Write(expiryBuf[:])
	signingInput := h.Sum(nil)

	sig := ed25519.Sign(signingKey, signingInput)

	var token [72]byte
	binary.BigEndian.PutUint64(token[0:8], uint64(expiryUnixMs))
	copy(token[8:72], sig)
	return token
}

// uploadShard performs one complete /vyomanaut/chunk-upload/1.0.0 round trip
// (IC §4.1) against replacementPeerID — identical wire format to a normal
// client upload.
func uploadShard(
	ctx context.Context,
	transport RepairTransport,
	replacementPeerID string,
	chunkID [32]byte,
	shardIndex int,
	token [72]byte,
	shardData []byte,
) error {
	stream, err := transport.NewStream(ctx, replacementPeerID, chunkUploadProtocolID)
	if err != nil {
		return fmt.Errorf("open chunk-upload stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	if err := stream.SetDeadline(time.Now().Add(chunkUploadTimeout)); err != nil {
		return fmt.Errorf("set chunk-upload deadline: %w", err)
	}

	// Frame 1 — UploadRequest: length(4) || chunk_id(32) || shard_index(4) || capability_token(72) || chunk_data(262144).
	payloadLen := chunkIDFieldSize + shardIndexFieldSize + capabilityTokenSize + erasure.ShardSize
	frame1 := make([]byte, lengthPrefixSize+payloadLen)
	binary.BigEndian.PutUint32(frame1[0:lengthPrefixSize], uint32(payloadLen))
	offset := lengthPrefixSize
	copy(frame1[offset:offset+chunkIDFieldSize], chunkID[:])
	offset += chunkIDFieldSize
	binary.BigEndian.PutUint32(frame1[offset:offset+shardIndexFieldSize], uint32(shardIndex))
	offset += shardIndexFieldSize
	copy(frame1[offset:offset+capabilityTokenSize], token[:])
	offset += capabilityTokenSize
	copy(frame1[offset:], shardData)
	if _, err := stream.Write(frame1); err != nil {
		return fmt.Errorf("write UploadRequest: %w", err)
	}

	var lengthBuf [4]byte
	if _, err := io.ReadFull(stream, lengthBuf[:]); err != nil {
		return fmt.Errorf("read UploadResponse length: %w", err)
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	body := make([]byte, length)
	if _, err := io.ReadFull(stream, body); err != nil {
		return fmt.Errorf("read UploadResponse body: %w", err)
	}
	if len(body) < 1 {
		return fmt.Errorf("UploadResponse: empty body")
	}

	switch status := body[0]; status {
	case uploadStatusOK, uploadStatusAlreadyStored:
		// [Flagged, M9 review Finding #6] On status 0x00, body also carries
		// a uploadProviderSigSize-byte provider_sig — IC §4.1 describes it
		// as "the upload receipt that the initiator must retain as proof of
		// acknowledged storage." It is read past (via the length-prefixed
		// body already consumed above) but never parsed out or persisted
		// here: no column exists anywhere in the schema to hold a repair
		// upload's receipt signature, and chunk_assignments' own columns
		// are fully accounted for elsewhere (see preRegisterChunkAssignment
		// and activateChunkAssignment). This is left as an explicit,
		// documented gap rather than a silent one — closing it needs a
		// product/schema decision (a new column, most likely) that is out
		// of this package's scope to make unilaterally.
		return nil
	case uploadStatusStorageFull:
		// [Added, M9 review Optional Fix A] Distinguished from the default
		// case below so ExecuteRepairJob's retry loop can catch exactly
		// this one recoverable condition and try a different candidate,
		// rather than failing the whole repair job on a single unlucky
		// capacity draw.
		return fmt.Errorf("%w", ErrReplacementStorageFull)
	default:
		return fmt.Errorf("UploadResponse: status 0x%02x", status)
	}
}

// activateChunkAssignment flips the new assignment from REPAIRING to ACTIVE
// after a successful upload confirmation (IC §4.4.2 post-repair confirmation).
func activateChunkAssignment(ctx context.Context, db *sql.DB, chunkID [32]byte, providerID uuid.UUID) error {
	const query = `
UPDATE chunk_assignments
SET status = 'ACTIVE'
WHERE chunk_id = $1 AND provider_id = $2 AND status = 'REPAIRING'`
	if _, err := db.ExecContext(ctx, query, chunkID[:], providerID); err != nil {
		return fmt.Errorf("update chunk_assignments (REPAIRING -> ACTIVE): %w", err)
	}
	return nil
}

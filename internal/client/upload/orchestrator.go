// Package upload is declared in doc.go.
// This file implements UploadFile() (TASK steps 1–2, 8) and, as of Session
// 15.2.2, ResumeUpload() — plus this package's exported interface and
// sentinel errors.
//
// [Design note — package split] IC §5.9 sketches a single "package client"
// with one UploadOrchestrator interface bundling UploadFile, ResumeUpload,
// AND RetrieveFile. mvp.md §8.2's actual file layout (A-7, authoritative
// for the per-file inventory) splits these into two separate packages —
// internal/client/upload and internal/client/retrieve — each with its own
// orchestrator.go. This file follows mvp.md's package split (the real
// build structure) while preserving IC §5.9's exact method signatures and
// sentinel error text verbatim, including the "client:" message prefix
// IC §5.9 gives even though this now lives in package upload, not client —
// changing the prefix to "upload:" would be a cosmetic improvement but
// would diverge from the literal contract text given; flagged here rather
// than silently done either way. RetrieveFile and its three sentinels
// (ErrPointerTagMismatch, ErrTooFewShards, ErrCanaryMismatch) belong to
// internal/client/retrieve (Phase 15.3), not this file.
//
// [Design note — no filename parameter] TASK step 6 (pointer.go) says to
// "populate display_name_ciphertext/_nonce/_tag from the locally-encrypted
// filename (FR-019)", but IC §5.9's UploadFile signature — preserved
// exactly below — has no filename parameter anywhere in ctx/masterSecret/
// ownerID/plaintext. This is a real signature/task mismatch, not resolved
// here: UploadFile calls registerPointerFile with an empty display name
// (the OAS's own display_name_* fields are nullable/optional), so the
// upload still succeeds and registers correctly; a future session adding a
// filename parameter to this package's public surface (which IC §5.9 does
// not currently allow for) is the real fix.
//
// [REF: IC §5.9, IC §4.1, IC §5.1, MVP §8.2 Phase 15.2 Session 15.2.1,
// FR-060, FR-013, FR-014]

package upload

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	"github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
	"github.com/masamasaowl/Vyomanaut_V2/internal/erasure"
	"github.com/masamasaowl/Vyomanaut_V2/internal/p2p"
)

// UploadOrchestrator manages the full upload lifecycle for one file (IC
// §5.9). See this file's header comment on the package split from IC
// §5.9's original single-package sketch.
//
// ERRATA: Each ShardAssignment in the UploadAssignResponse includes a
// capability_token field. The upload orchestrator must include this token
// verbatim in the capability_token field of the UploadRequest frame sent to
// that provider. Tokens are single-use per assignment and expire 1 hour
// after issuance. If a provider returns 0x07 (CAPABILITY_EXPIRED), the
// orchestrator must call POST /api/v1/upload/assign again with the same
// file_id to obtain fresh tokens. The assignment service returns the same
// provider set (idempotent on file_id) but generates new tokens with a
// fresh expiry.
type UploadOrchestrator interface {
	// UploadFile encodes, distributes, and registers a file.
	//
	// Pre-conditions:
	//   - masterSecret is the 32-byte Argon2id-derived master secret (in
	//     memory, not on disk)
	//   - ownerID is the data owner's UUID
	//   - plaintext is the raw file bytes (may be any size; orchestrator
	//     handles segmentation and padding internally)
	//   - The data owner's escrow balance must cover 30 days of storage for
	//     len(plaintext) (the orchestrator calls the assignment service
	//     which enforces this via HTTP 409)
	// Post-conditions (on nil error):
	//   - All TotalShards × num_segments shards are durably stored on
	//     provider daemons
	//   - The encrypted pointer file ciphertext is stored with the
	//     microservice
	//   - The local session state file is cleaned up
	//   - The fileID returned can be used with RetrieveFile
	//     (internal/client/retrieve)
	// Error semantics:
	//   - ErrInsufficientEscrow: balance check failed; data owner must
	//     deposit first
	//   - ErrNetworkNotReady: the microservice returned HTTP 503
	//     (readiness gate)
	//   - ErrUploadIncomplete: some shards failed after retries; session
	//     state is persisted to disk for a future resume attempt (FR-060)
	// Goroutine-safe: yes (constructs fresh goroutines per upload).
	UploadFile(ctx context.Context,
		masterSecret [32]byte, ownerID uuid.UUID,
		plaintext []byte) (fileID uuid.UUID, err error)

	// ResumeUpload resumes an interrupted upload using the persisted
	// session state (FR-060 — crash recovery without retransmitting
	// acknowledged shards). Implemented in Session 15.2.2.
	//
	// Pre-conditions:
	//   - A session state file for fileID exists on disk
	//   - masterSecret is the same master secret used for the original
	//     upload
	// Post-conditions: same as UploadFile on success.
	ResumeUpload(ctx context.Context,
		masterSecret [32]byte, ownerID, fileID uuid.UUID) error
}

var (
	ErrInsufficientEscrow = errors.New("client: escrow balance insufficient for 30-day storage")
	ErrNetworkNotReady    = errors.New("client: network readiness gate not satisfied (HTTP 503)")
	ErrUploadIncomplete   = errors.New("client: upload incomplete; session state saved for resume")
)

// aontOverheadBytes is crypto.AONTEncodeSegment's fixed expansion: its
// post-condition states the output is (s+3)*16 bytes where s = input/16 —
// i.e. output = input + 48 bytes (one 16-byte canary word plus a 32-byte
// key-embedding block). erasure.Engine.EncodeSegment demands its input be
// EXACTLY profile.DataShards*profile.ShardSize, so the plaintext fed into
// AONTEncodeSegment must be exactly that target size minus this overhead —
// TASK step 1's literal text ("padding to profile.DataShards × ShardSize
// minimum") does not itself account for this; recomputed from
// AONTEncodeSegment's and EncodeSegment's own stated pre/post-conditions
// before writing the segmentation logic below, per this project's standing
// practice of recomputing every numeric claim from its stated inputs rather
// than accepting task prose at face value.
const aontOverheadBytes = 48

// Orchestrator implements UploadOrchestrator.
type Orchestrator struct {
	api        *apiClient
	host       p2p.Host
	engine     *erasure.Engine
	profile    config.NetworkProfile
	signingKey ed25519.PrivateKey // owner's Ed25519 identity key; signs owner_sig
	sessionDir string
	aesNI      bool
}

var _ UploadOrchestrator = (*Orchestrator)(nil)

// NewOrchestrator constructs an Orchestrator. signingKey is the data
// owner's own Ed25519 identity key (internal/client/account.Identity.
// PrivateKey, typically loaded from account.Keystore) — IC §5.9's UploadFile
// signature has no room for a per-call signing key (see this file's header
// comment on the same gap for a filename parameter), so it is supplied once
// at construction time instead, matching internal/client/account's own
// "the master secret's only home is the caller's local variable" discipline
// applied here to the signing key.
func NewOrchestrator(
	baseURL, token string, httpClient *http.Client,
	host p2p.Host, engine *erasure.Engine, profile config.NetworkProfile,
	signingKey ed25519.PrivateKey, sessionDir string,
) *Orchestrator {
	return &Orchestrator{
		api:        newAPIClient(baseURL, token, httpClient),
		host:       host,
		engine:     engine,
		profile:    profile,
		signingKey: signingKey,
		sessionDir: sessionDir,
		aesNI:      crypto.DetectAESNI(),
	}
}

// plaintextSegmentSize returns the exact plaintext byte length
// AONTEncodeSegment must receive so its output (input + aontOverheadBytes)
// is exactly profile.DataShards×profile.ShardSize — erasure.Engine.
// EncodeSegment's own exact-length pre-condition. A standalone function so
// the profile-driven math is directly testable without exercising the full
// UploadFile network path.
func plaintextSegmentSize(profile config.NetworkProfile) int {
	return profile.DataShards*profile.ShardSize - aontOverheadBytes
}

// UploadFile implements UploadOrchestrator.
func (o *Orchestrator) UploadFile(ctx context.Context, masterSecret [32]byte, ownerID uuid.UUID, plaintext []byte) (fileID uuid.UUID, err error) {
	fileID, err = uuid.NewV7() // client-generated UUIDv7 per OAS UploadAssignRequest.file_id
	if err != nil {
		return uuid.Nil, fmt.Errorf("upload: UploadFile: generate file_id: %w", err)
	}

	// TASK step 1: pad to profile.DataShards × profile.ShardSize, adjusted
	// for AONT overhead (see aontOverheadBytes doc comment above). Never
	// hardcode the shard count or the fixed shard byte size — both are
	// read from the active profile.
	segSize := plaintextSegmentSize(o.profile)
	if segSize <= 0 {
		return fileID, fmt.Errorf("upload: UploadFile: profile.DataShards×profile.ShardSize too small to hold the AONT overhead")
	}
	numSegments := ceilDivInt(len(plaintext), segSize)
	if numSegments == 0 {
		numSegments = 1 // a zero-length file still uploads one fully-padded segment
	}

	// TASK step 3: request provider assignment before doing any encoding
	// work, so a closed readiness gate (503) or insufficient escrow (409)
	// fails fast.
	assignResp, err := o.requestAssignment(ctx, fileID, numSegments, int64(len(plaintext)))
	if err != nil {
		return fileID, fmt.Errorf("upload: UploadFile: %w", err)
	}

	// TASK step 2: AONT-encode each segment, then RS-encode via
	// erasure.Engine.EncodeSegment.
	shardData := make([][][]byte, numSegments)
	chunkIDs := make([][][32]byte, numSegments)
	for i := 0; i < numSegments; i++ {
		segPlain := make([]byte, segSize)
		start := i * segSize
		if start < len(plaintext) {
			end := start + segSize
			if end > len(plaintext) {
				end = len(plaintext)
			}
			copy(segPlain, plaintext[start:end])
		}

		aontPkg, err := crypto.AONTEncodeSegment(segPlain, o.aesNI)
		if err != nil {
			return fileID, fmt.Errorf("upload: UploadFile: AONT-encode segment %d: %w", i, err)
		}
		shards, err := o.engine.EncodeSegment(aontPkg)
		if err != nil {
			return fileID, fmt.Errorf("upload: UploadFile: RS-encode segment %d: %w", i, err)
		}
		shardData[i] = shards

		ids := make([][32]byte, len(shards))
		for j, shard := range shards {
			ids[j] = sha256.Sum256(shard)
		}
		chunkIDs[i] = ids
	}

	// TASK step 8: persist session state BEFORE transfer begins (FR-060) —
	// a crash after this point can always resume from disk. ShardData and
	// OriginalSizeBytes are persisted too — see SessionState's own doc
	// comment on why ResumeUpload needs them despite IC §5.9's fixed
	// signature giving it no plaintext parameter.
	sess := &SessionState{
		FileID:            fileID,
		ChunkIDs:          chunkIDs,
		AckStatus:         make([][]bool, numSegments),
		TotalShards:       o.profile.TotalShards,
		ShardData:         shardData,
		OriginalSizeBytes: int64(len(plaintext)),
	}
	for i := range sess.AckStatus {
		sess.AckStatus[i] = make([]bool, o.profile.TotalShards)
	}
	if err := SaveSessionState(o.sessionDir, *sess); err != nil {
		return fileID, fmt.Errorf("upload: UploadFile: %w", err)
	}

	// TASK steps 4–5: parallel shard transfer (transfer.go).
	if err := o.transferAll(ctx, fileID, assignResp, shardData, sess, o.sessionDir); err != nil {
		return fileID, fmt.Errorf("upload: UploadFile: %w", err)
	}

	// TASK steps 6–8: build/register the pointer file and clean up session
	// state (shared with ResumeUpload — see finishUpload).
	if err := o.finishUpload(ctx, masterSecret, ownerID, fileID, assignResp, chunkIDs, int64(len(plaintext))); err != nil {
		return fileID, fmt.Errorf("upload: UploadFile: %w", err)
	}
	return fileID, nil
}

// finishUpload implements TASK steps 6–8, shared by UploadFile and
// ResumeUpload (Session 15.2.2): build the pointer file, register it, and
// clean up session state only once registration succeeds.
func (o *Orchestrator) finishUpload(
	ctx context.Context, masterSecret [32]byte, ownerID, fileID uuid.UUID,
	assignResp *uploadAssignResponse, chunkIDs [][][32]byte, originalSizeBytes int64,
) error {
	numSegments := len(chunkIDs)
	segments := make([]pointerFileSegment, numSegments)
	for i := 0; i < numSegments; i++ {
		fileKey := crypto.DeriveFileKey(masterSecret[:], ownerID[:], fileID[:])
		providerIDs := make([]uuid.UUID, o.profile.TotalShards)
		for _, sa := range assignResp.Assignments[i].Providers {
			providerIDs[sa.ShardIndex] = sa.ProviderID
		}
		chunkIDHex := make([]string, o.profile.TotalShards)
		for j, id := range chunkIDs[i] {
			chunkIDHex[j] = fmt.Sprintf("%x", id)
		}
		segments[i] = pointerFileSegment{
			SegmentID:    assignResp.Assignments[i].SegmentID,
			SegmentIndex: i,
			FileKey:      fmt.Sprintf("%x", fileKey),
			ProviderIDs:  providerIDs,
			ChunkIDs:     chunkIDHex,
			ErasureParams: erasureParamsInfo{
				S:       o.profile.DataShards,
				R:       o.profile.ParityShards,
				N:       o.profile.TotalShards,
				LfBytes: o.profile.ShardSize,
			},
		}
	}

	// No filename parameter is available here — see this file's header
	// comment on the IC §5.9 signature/TASK-step-6 mismatch.
	if err := o.registerPointerFile(ctx, masterSecret, ownerID, fileID, segments, originalSizeBytes, "", o.signingKey); err != nil {
		return err
	}

	// Session state is removed only now that FileRegisterRequest has
	// succeeded — deleting it any earlier would strand an interrupted
	// upload with nothing to resume from.
	if err := DeleteSessionState(o.sessionDir, fileID); err != nil {
		return fmt.Errorf("succeeded but failed to clean up session state: %w", err)
	}
	return nil
}

// ResumeUpload implements UploadOrchestrator (TASK, Session 15.2.2): loads
// the persisted session state, retransmits only the shards
// ack_status marks unacknowledged (FR-060 — never retransmit acknowledged
// shards), and on completion follows the identical pointer-registration and
// cleanup path UploadFile uses (finishUpload).
//
// Re-requests assignment for the same file_id before transferring — the
// OAS's own "idempotent: repeated calls with the same file_id return the
// same assignments" guarantee means this returns the same provider set with
// fresh capability tokens, which resume needs anyway since the original
// tokens (1-hour expiry) may well have expired during whatever caused the
// interruption.
func (o *Orchestrator) ResumeUpload(ctx context.Context, masterSecret [32]byte, ownerID, fileID uuid.UUID) error {
	sess, err := LoadSessionState(o.sessionDir, fileID)
	if err != nil {
		return fmt.Errorf("upload: ResumeUpload: %w", err)
	}
	if sess.FileID != fileID {
		return fmt.Errorf("upload: ResumeUpload: loaded session state is for file_id %s, want %s", sess.FileID, fileID)
	}

	assignResp, err := o.requestAssignment(ctx, fileID, len(sess.ChunkIDs), sess.OriginalSizeBytes)
	if err != nil {
		return fmt.Errorf("upload: ResumeUpload: %w", err)
	}

	// Count remaining unacknowledged shards directly here, in addition to
	// transfer.go's own internal pendingTasks re-scan, so a resume that
	// finds nothing left to transfer — interrupted between "every shard
	// acknowledged" and "pointer file registered" — can skip the transfer
	// step entirely rather than paying for a goroutine-pool setup that
	// would immediately find zero pending tasks anyway.
	pending := 0
	for _, segAck := range sess.AckStatus {
		for _, acked := range segAck {
			if !acked {
				pending++
			}
		}
	}
	if pending > 0 {
		// pendingTasks (transfer.go) re-scans sess.AckStatus itself — every
		// already-true entry is skipped, so this retransmits only shards
		// still marked unacknowledged, exactly like a mid-flight
		// CAPABILITY_EXPIRED retry within a single UploadFile call.
		if err := o.transferAll(ctx, fileID, assignResp, sess.ShardData, &sess, o.sessionDir); err != nil {
			return fmt.Errorf("upload: ResumeUpload: %w", err)
		}
	}

	if err := o.finishUpload(ctx, masterSecret, ownerID, fileID, assignResp, sess.ChunkIDs, sess.OriginalSizeBytes); err != nil {
		return fmt.Errorf("upload: ResumeUpload: %w", err)
	}
	return nil
}

func ceilDivInt(a, b int) int {
	if a <= 0 {
		return 0
	}
	return (a + b - 1) / b
}
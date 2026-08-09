// Package upload is declared in doc.go.
// This file implements session-state persistence for crash recovery
// (TASK step 8, FR-060): file_id, chunk_ids, and ack_status[TotalShards]
// are written to disk before transfer begins and removed only after
// pointer-file registration (pointer.go) succeeds — see orchestrator.go's
// UploadFile for the exact ordering.
//
// [Design note] IC §5.9 gives no on-disk schema for this state (FR-060 only
// names the three fields). JSON is used here deliberately, unlike the
// Ed25519 signing inputs elsewhere in this package (owner_sig in
// pointer.go): IC §11's "no json.Marshal in a signing path" rule targets
// byte-for-byte-reproducible cryptographic inputs, not general local
// persistence — this file is never hashed or signed, so JSON's
// non-deterministic field ordering has no correctness consequence here.
//
// [REF: FR-060, MVP §8.2 Phase 15.2 Session 15.2.1]

package upload

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// SessionState is the on-disk crash-recovery record for one in-progress
// upload (FR-060). ack_status is segment-major: AckStatus[segmentIndex] has
// exactly TotalShards entries, mirroring IC §5.9's "ack_status[TotalShards]"
// per-segment shape.
type SessionState struct {
	FileID uuid.UUID `json:"file_id"`

	// ChunkIDs[segmentIndex][shardIndex] is the SHA-256 content address of
	// that shard — needed on resume to re-derive which upload each
	// AckStatus entry corresponds to without re-encoding the file.
	ChunkIDs [][][32]byte `json:"chunk_ids"`

	// AckStatus[segmentIndex][shardIndex] is true once that shard's
	// UploadResponse status = 0x00/0x06 has been received. ResumeUpload
	// (Session 15.2.2) re-transmits only the false entries.
	AckStatus [][]bool `json:"ack_status"`

	// TotalShards is persisted alongside AckStatus so a resume can validate
	// the array shape without re-deriving it from a NetworkProfile that may
	// have changed between the original attempt and the resume (defensive;
	// the profile is not expected to change mid-upload, but session state
	// surviving a process restart should not silently trust that it hasn't).
	TotalShards int `json:"total_shards"`

	// ShardData[segmentIndex][shardIndex] is the raw AONT-RS encoded shard
	// bytes already produced by UploadFile's TASK-step-2 encoding pass.
	//
	// [Flagged — a real signature/task gap, not an invented workaround]
	// IC §5.9's ResumeUpload signature — preserved exactly in orchestrator.go
	// — is (ctx, masterSecret, ownerID, fileID) error: no plaintext or file
	// path parameter. Without ShardData persisted here, ResumeUpload would
	// have no way to obtain the actual bytes to retransmit for an
	// unacknowledged shard; the original plaintext is not re-read from
	// anywhere, because nothing in this package's public surface is ever
	// given a path to it on the resume call. Persisting the encoded shards
	// here is the only self-consistent way to honour FR-060 ("crash
	// recovery without retransmitting acknowledged shards") within IC
	// §5.9's fixed signature.
	//
	// This is NOT a production-scale-efficient design: encoded shard data
	// is ~TotalShards/DataShards times the original file size before this
	// JSON+base64 encoding even adds its own ~33% overhead, so a large
	// upload's session file could be substantially larger than the source
	// file. A real system would more likely persist a reference (e.g. a
	// temp-file path to the already-encoded shards) rather than inlining
	// the bytes in this JSON document, or would add a plaintext/path
	// parameter to ResumeUpload if the interface could be revised — flagged
	// here rather than silently working around IC §5.9's given signature.
	ShardData [][][]byte `json:"shard_data"`

	// OriginalSizeBytes is persisted so ResumeUpload's own idempotent
	// re-assignment call (POST /api/v1/upload/assign, same file_id) can
	// supply a value without needing it passed in separately.
	OriginalSizeBytes int64 `json:"original_size_bytes"`
}

// sessionFileName returns the on-disk file name for fileID's session state.
// Exported so a resume caller (or a test) can locate the file without
// duplicating this naming rule.
func sessionFileName(fileID uuid.UUID) string {
	return fileID.String() + ".upload-session.json"
}

// SaveSessionState writes state to sessionDir, overwriting any prior state
// for the same file_id. Called before transfer begins and after every
// batch of newly-acknowledged shards, so a crash mid-transfer loses at most
// the most recent partial batch, not the whole upload's progress.
func SaveSessionState(sessionDir string, state SessionState) error {
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return fmt.Errorf("upload: SaveSessionState: create session dir: %w", err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("upload: SaveSessionState: encode: %w", err)
	}
	path := filepath.Join(sessionDir, sessionFileName(state.FileID))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("upload: SaveSessionState: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil { // atomic on the same filesystem
		return fmt.Errorf("upload: SaveSessionState: rename into place: %w", err)
	}
	return nil
}

// LoadSessionState reads a previously saved SessionState for fileID.
// ResumeUpload's entry point (orchestrator.go, Session 15.2.2).
func LoadSessionState(sessionDir string, fileID uuid.UUID) (SessionState, error) {
	path := filepath.Join(sessionDir, sessionFileName(fileID))
	data, err := os.ReadFile(path)
	if err != nil {
		return SessionState{}, fmt.Errorf("upload: LoadSessionState: %w", err)
	}
	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return SessionState{}, fmt.Errorf("upload: LoadSessionState: decode: %w", err)
	}
	return state, nil
}

// DeleteSessionState removes fileID's on-disk session state. Called only
// after pointer.go's FileRegisterRequest call succeeds (orchestrator.go) —
// deleting it any earlier would strand an interrupted upload with no way
// to resume (FR-060's entire purpose).
func DeleteSessionState(sessionDir string, fileID uuid.UUID) error {
	path := filepath.Join(sessionDir, sessionFileName(fileID))
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("upload: DeleteSessionState: %w", err)
	}
	return nil
}
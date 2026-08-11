// Package storage is declared in doc.go.
// This file defines the ChunkStore interface, layout constants, and NewChunkStore.
//
// IMPORT CONSTRAINT (IC §9): this package must NOT import internal/payment,
// internal/scoring, or internal/repair. The storage engine is unaware of
// network economics or topology. Only stdlib and the grocksdb binding are permitted.
//
// INVARIANT (DM §3 Invariant 6, ADR-030): The daemon cannot distinguish
// between synthetic vetting chunks and real file shards. Both use identical
// AppendChunk / LookupChunk / DeleteChunk code paths. The is_vetting_chunk
// flag exists only in the microservice's chunk_assignments table.
//
// [REF: IC §5.3, ARCH §16, ARCH §27.1, ADR-023, build.md Phase 5.1]

package storage

import (
	"context"
	"fmt"
	"os"
)

const (
	dirPerm  os.FileMode = 0700
	filePerm os.FileMode = 0600
)

// vLogEntrySize is the fixed byte size of every vLog entry (ARCH §16, ARCH §27.1).
//
//	Layout: chunk_id(32) + chunk_size(4) + chunk_data(262144) + content_hash(32)
//	      = 262212 bytes.
//
// Every read and write uses this exact size; no variable-length entries exist in V2.
// This constant is intentionally larger than the raw 256 KB chunk data (262144 bytes)
// to account for the 68-byte per-entry header and trailer fields.
const vLogEntrySize = 262212

// indexValueSize is the byte size of the RocksDB value per chunk index entry (ARCH §27.1).
//
//	Layout: vlog_offset(uint64=8) + chunk_size(uint32=4) = 12 bytes.
//
// The RocksDB key is the 32-byte chunk_id, so the total on-disk entry is
// approximately 44 bytes (32 key + 12 value). At 50 GB declared storage the
// entire index fits in ~8.8 MB of RocksDB block cache (ARCH §27.1).
const indexValueSize = 12

// ChunkDataSize is the fixed byte size of the raw chunk payload stored in the vLog.
// Equal to erasure.ShardSize = 256 KiB. Defined here separately (rather than
// importing internal/erasure) to satisfy the IC §9 import constraint
// (internal/storage must not import internal/erasure in production code).
// Exported — unlike most of this package's internal layout constants —
// specifically so the cross-package identity can be asserted from an
// external storage_test package: see shard_size_test.go's
// TestChunkDataSizeMatchesErasureShardSize, which mirrors the config_test
// trick internal/config/profiles_test.go already uses for the analogous
// config↔erasure check. (M3 review §3 — the previous version of this
// comment claimed that test already existed; it didn't.)
//
// [REF: ARCH §16, ARCH §27.1, DM §3 Invariant 7, IC §9, ADR-023]
const ChunkDataSize = 262144

// ChunkStore is the WiscKey key-value separated chunk storage engine (ARCH §16, ADR-023).
// The RocksDB index holds small 44-byte entries; the append-only vLog holds all
// 262 KB chunk data. Write amplification ≈ 1.0 at 256 KB values (ARCH §4.1, ARCH §27.1).
//
// Create with NewChunkStore.
//
// CONCURRENCY: Only AppendChunk and RecoverFromCrash are NOT goroutine-safe. All
// other methods are goroutine-safe. See each method's comment for details.
type ChunkStore interface {
	// AppendChunk writes a 256 KB chunk to the vLog and inserts the RocksDB index entry.
	//
	// *** SINGLE WRITER ONLY — NOT goroutine-safe ***
	//
	// All concurrent callers MUST submit write requests via a buffered channel to the
	// designated single writer goroutine. POSIX O_APPEND atomicity does not hold for
	// writes above ~4 KB; for 262212-byte vLog entries, goroutine serialisation is
	// mandatory to prevent interleaved writes and vLog corruption.
	// (ARCH §16 §Single writer goroutine, IC §11)
	//
	// Pre-conditions (panic in debug builds if violated):
	//   - len(chunkID)   == 32      (SHA-256 content address; fixed-size array enforces this)
	//   - len(chunkData) == 262144  (exactly one 256 KB shard; caller must pad if short)
	//   - SHA-256(chunkData) == chunkID  (caller MUST verify before calling;
	//     AppendChunk does NOT re-verify to avoid double SHA-256 overhead)
	//   - The vLog file handle is open and positioned at EOF
	//
	// Post-conditions (on nil error):
	//   - chunkData and its SHA-256 content_hash are durably fsync'd to the vLog.
	//   - RocksDB index entry (chunkID → vlog_offset, chunk_size) is inserted.
	//   - The returned vlogOffset is the byte offset where the 262212-byte entry
	//     begins in the vLog.
	//
	// Error semantics:
	//   - ErrVLogFsync    — fsync failed; daemon MUST halt; RecoverFromCrash repairs
	//                       the tail on next restart (ARCH §16 §Crash recovery).
	//   - ErrRocksDBInsert — index INSERT failed after a successful vLog write;
	//                        RecoverFromCrash re-inserts the missing entry on restart.
	//
	// Goroutine-safe: NO — single designated writer goroutine only.
	AppendChunk(chunkID [32]byte, chunkData []byte) (vlogOffset uint64, err error)

	// LookupChunk retrieves a chunk from the vLog by content address.
	// Internal path: Bloom filter → RocksDB block cache → vLog pread → SHA-256 verify.
	// (ARCH §16 §Audit lookup path)
	//
	// For an absent chunk the Bloom filter exits in memory — no disk I/O occurs.
	// For a present chunk: typically one SSD read (~1 ms) or HDD read (~12–15 ms)
	// for the 262212-byte vLog entry; the 44-byte RocksDB index entry is usually
	// in block cache (ARCH §27.1).
	//
	// Pre-conditions:
	//   - chunkID is a 32-byte SHA-256 content address (fixed-size array enforces this)
	//
	// Post-conditions (on nil error):
	//   - Returned slice is exactly 262144 bytes.
	//   - SHA-256(returned data) == chunkID — verified internally; caller need not re-check.
	//
	// Error semantics:
	//   - ErrChunkNotFound       — Bloom filter / RocksDB has no entry; return audit
	//                              status 0x01 (FAIL_NOT_FOUND). Expected for challenges
	//                              on chunks not assigned to this provider.
	//   - ErrContentHashMismatch — data present, hash wrong; silent disk corruption;
	//                              return audit status 0x02 (FAIL_CORRUPTION), IC §4.2.
	//   - ErrVLogRead            — fatal I/O error; treat as daemon halt.
	//
	// Goroutine-safe: yes (read-only via pread; concurrent with the writer goroutine).
	LookupChunk(chunkID [32]byte) ([]byte, error)

	// DeleteChunk removes the RocksDB index entry for chunkID. The corresponding
	// vLog entry remains on disk until the next GC cycle reclaims it (RunGC).
	//
	// Subsequent LookupChunk calls for this chunkID will return ErrChunkNotFound.
	//
	// VETTING GC PATH (ADR-030, IC §4.5): DeleteChunk is also called by the vetting
	// GC handler to retire synthetic vetting chunks on the ACTIVE provider transition.
	// The call semantics are identical for synthetic and real chunks — the daemon has
	// no visibility into which type is being deleted (DM §3 Invariant 6).
	//
	// Goroutine-safe: yes.
	DeleteChunk(chunkID [32]byte) error

	// RecoverFromCrash scans the vLog tail for entries that are present on disk but
	// missing from the RocksDB index, and re-inserts them. (ARCH §16 §Crash recovery,
	// ADR-023, NFR-024)
	//
	// MUST be called exactly once at daemon startup, BEFORE the writer goroutine is
	// started and BEFORE any AppendChunk call is made.
	//
	// Maximum scan cost: one RocksDB memtable flush interval of chunks (typically a
	// few hundred entries). Bounded recovery time is a design constraint of ADR-023.
	//
	// Pre-conditions:
	//   - No AppendChunk has been called since the store was opened.
	//   - No writer goroutine is running.
	//
	// Post-conditions (on nil error):
	//   - All vLog entries up to current EOF are reflected in the RocksDB index.
	//
	// Goroutine-safe: NO — must complete before the writer goroutine is launched.
	RecoverFromCrash() error

	// RunGC reclaims vLog disk space from entries whose RocksDB index entry has been
	// deleted (by DeleteChunk). Compacts the vLog to a temporary file, then atomically
	// renames it over the original. (ADR-023 §Garbage collection, ARCH §16)
	//
	// Runs in a background goroutine; ctx cancellation stops it cleanly without data loss.
	// GC uses a separate read file handle from the writer goroutine — no coordination
	// with AppendChunk is required during the scan phase.
	//
	// Goroutine-safe: yes.
	RunGC(ctx context.Context) error

	// Close flushes pending RocksDB writes and closes both the RocksDB instance and
	// the vLog file handle. After Close returns, all method calls on this ChunkStore
	// produce undefined behaviour and must not be made.
	//
	// Goroutine-safe: yes (safe to call concurrently with other methods, but only once).
	Close() error
}

// NewChunkStore opens or creates the platform-appropriate chunk store rooted
// at dataDir: RocksDB + hand-rolled vLog on Linux/macOS (engine_rocksdb.go,
// ADR-023), BadgerDB on Windows (engine_badger.go, ADR-046). This function is
// deliberately OS-agnostic — it only ensures dataDir exists, then dispatches
// to newEngineStore, whose implementation is selected at compile time by the
// //go:build tags on engine_rocksdb.go / engine_badger.go, never a runtime
// os.Getenv/GOOS-string branch (IC §11).
//
// The caller MUST call RecoverFromCrash() on the returned store and allow it to
// complete BEFORE starting the writer goroutine (NFR-024, ARCH §16 §Crash recovery,
// build.md Phase 5.1 Session 5.1.5). This contract is identical on both engines
// even though its RocksDB-path implementation performs a real tail-scan and its
// Badger-path implementation is a documented no-op (engine_badger.go).
//
// NewChunkStore intentionally does NOT call RecoverFromCrash — the caller (Session
// 13.1.1 daemon wiring) must do so explicitly to preserve the startup-sequence
// contract.
//
// Error semantics: returns a wrapped error if directory creation or engine
// construction fails. Treat as fatal — the daemon must not start without its
// chunk store.
//
// [REF: IC §5.3, ARCH §16, ADR-023, ADR-046, build.md Phase 5.1 Session
// 5.1.5, build.md Session 16.0.1]
func NewChunkStore(dataDir string) (ChunkStore, error) {
	if err := os.MkdirAll(dataDir, dirPerm); err != nil {
		return nil, fmt.Errorf("storage.NewChunkStore: create dataDir %q: %w", dataDir, err)
	}
	return newEngineStore(dataDir)
}
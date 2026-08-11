//go:build linux || darwin

// Package storage is declared in doc.go.
// This file defines the wiskeyStore concrete struct that implements ChunkStore,
// the two internal vLog I/O helpers, and all six ChunkStore method implementations.
//
// The RocksDB index and its operations are in index.go (Session 5.1.3).
//
// IMPORT CONSTRAINT (IC §9): no other internal/ package may be imported here.
//
// [REF: IC §5.3, ARCH §16, ARCH §27.1, ADR-023, build.md Phase 5.1]

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// vLog entry field byte offsets (ARCH §16, ARCH §27.1).
//
// On-disk layout per entry:
//
//	[chunk_id:32][chunk_size:4][chunk_data:262144][content_hash:32]
//	 ↑0           ↑32           ↑36                ↑262180
const (
	vlogOffChunkID     = 0
	vlogOffChunkSize   = 32
	vlogOffChunkData   = 36
	vlogOffContentHash = vlogOffChunkData + ChunkDataSize // 36 + 262144 = 262180
)

// wiskeyStore is the concrete, unexported implementation of ChunkStore.
// Callers always interact through the ChunkStore interface returned by NewChunkStore.
//
// Field access rules:
//   - index: goroutine-safe after construction (RocksDB operations are thread-safe).
//   - vlog, vlogHead: NOT goroutine-safe. The single designated writer goroutine
//     owns vlog for writes; all other goroutines use ReadAt (pread) which is
//     safe to call concurrently on the same *os.File on POSIX systems.
//   - isRotational: read-only after construction; goroutine-safe.
type wiskeyStore struct {
	// index is the RocksDB chunk index (defined in index.go).
	index *rocksDBIndex

	// vlog is the append-only value log file.
	// The single writer goroutine holds exclusive write access.
	// All goroutines may call ReadAt concurrently (POSIX pread semantics).
	vlog     *os.File
	vlogPath string

	// vlogHead is the byte offset at which the next AppendChunk write will
	// begin. Protected by the single-writer invariant — only the writer
	// goroutine reads or modifies this field.
	vlogHead uint64

	// isRotational is true for HDD-backed storage, false for SSD.
	// Captured at construction (via isRotationalDevice) for future GC I/O
	// scheduling / monitoring-metrics differentiation (ARCH §16); as of M5,
	// no code path in this package actually reads this field yet — see M5
	// review §5. Core vLog read/write paths are storage-medium-agnostic
	// regardless, so this is a forward-looking placeholder, not a
	// currently-enforced behavioural difference.
	isRotational bool
}

// ── Internal vLog I/O helpers ─────────────────────────────────────────────────

// appendToVLog writes one complete vLogEntrySize-byte vLog entry and fsyncs to disk.
//
// MUST be called only from the single designated writer goroutine (IC §5.3).
//
// Algorithm (ARCH §16):
//  1. Compute content_hash = SHA-256(chunkData).
//  2. Build a vLogEntrySize-byte buffer: [chunk_id][chunk_size][chunk_data][content_hash].
//  3. Write the complete buffer via os.File.Write.
//  4. Call Sync() — return ErrVLogFsync on either failure; daemon must halt.
//  5. Advance ws.vlogHead by vLogEntrySize.
//
// Returns the byte offset where the entry begins (= the pre-write vlogHead).
func (ws *wiskeyStore) appendToVLog(chunkID [32]byte, chunkData []byte) (offset uint64, err error) {
	contentHash := sha256.Sum256(chunkData)

	var buf [vLogEntrySize]byte
	copy(buf[vlogOffChunkID:], chunkID[:])
	binary.BigEndian.PutUint32(buf[vlogOffChunkSize:], ChunkDataSize)
	copy(buf[vlogOffChunkData:], chunkData)
	copy(buf[vlogOffContentHash:], contentHash[:])

	offset = ws.vlogHead
	if _, werr := ws.vlog.Write(buf[:]); werr != nil {
		return 0, fmt.Errorf("%w: write at offset %d: %v", ErrVLogFsync, offset, werr)
	}
	if serr := ws.vlog.Sync(); serr != nil {
		return 0, fmt.Errorf("%w: sync at offset %d: %v", ErrVLogFsync, offset, serr)
	}
	ws.vlogHead += vLogEntrySize
	return offset, nil
}

// readFromVLog reads the vLogEntrySize-byte entry at byteOffset and verifies
// that its chunk_data hashes to wantChunkID — the content-address key the
// caller looked up — not just the entry's own on-disk content_hash field.
//
// Goroutine-safe: uses ReadAt (POSIX pread semantics). Multiple goroutines
// may call readFromVLog concurrently; concurrent AppendChunk calls in the
// writer goroutine are also safe because pread does not move the file position.
//
// Algorithm (ARCH §16 §Audit lookup path, steps 4-5; corrected per M5 review §2):
//  1. ReadAt vLogEntrySize bytes from byteOffset into a fixed-size buffer.
//  2. Compute SHA-256(buf[vlogOffChunkData : vlogOffChunkData+ChunkDataSize]).
//  3. Compare against wantChunkID — the key the RocksDB index was looked up
//     under, supplied by the caller — NOT the entry's own internally-stored
//     content_hash field. Checking only content_hash proves the entry is
//     self-consistent with whatever it was paired with at AppendChunk time;
//     it does not prove that pairing was ever correct (AppendChunk documents
//     SHA-256(chunkData) == chunkID as a caller precondition it does NOT
//     re-verify). Checking wantChunkID closes that gap and also catches a
//     RocksDB index entry that points at the wrong vLog offset. Return
//     ErrContentHashMismatch on any mismatch (caller must set audit status
//     0x02, IC §4.2).
//  4. Return a fresh ChunkDataSize-byte slice copied from the data region.
//
// The returned slice is always freshly allocated so callers may retain it
// after this function returns without aliasing the I/O buffer.
//
// [REF: IC §5.3, ARCH §16, M5 review §2]
func (ws *wiskeyStore) readFromVLog(wantChunkID [32]byte, byteOffset uint64) ([]byte, error) {
	var buf [vLogEntrySize]byte
	if _, err := ws.vlog.ReadAt(buf[:], int64(byteOffset)); err != nil {
		return nil, fmt.Errorf("%w: ReadAt offset %d: %v", ErrVLogRead, byteOffset, err)
	}

	computed := sha256.Sum256(buf[vlogOffChunkData : vlogOffChunkData+ChunkDataSize])
	if computed != wantChunkID {
		return nil, ErrContentHashMismatch
	}

	data := make([]byte, ChunkDataSize)
	copy(data, buf[vlogOffChunkData:vlogOffChunkData+ChunkDataSize])
	return data, nil
}

// ── ChunkStore interface implementation ───────────────────────────────────────

// AppendChunk writes a 256 KB chunk to the vLog and inserts the RocksDB index entry.
//
// *** SINGLE WRITER ONLY — NOT goroutine-safe ***
//
// [REF: IC §5.3, ARCH §16 §Single writer goroutine, build.md Phase 5.1 Session 5.1.4]
func (ws *wiskeyStore) AppendChunk(chunkID [32]byte, chunkData []byte) (vlogOffset uint64, err error) {
	if len(chunkData) != ChunkDataSize {
		panic(fmt.Sprintf(
			"storage.AppendChunk: chunkData must be %d bytes, got %d",
			ChunkDataSize, len(chunkData)))
	}

	// Step 1: Write to vLog and fsync (ARCH §16).
	// On error the vLog may be partially written; daemon must halt and call
	// RecoverFromCrash on the next restart.
	offset, err := ws.appendToVLog(chunkID, chunkData)
	if err != nil {
		// err is already wrapped as ErrVLogFsync by appendToVLog.
		return 0, err
	}

	// Step 2: Insert into RocksDB index.
	// A failure here leaves the vLog entry durable — RecoverFromCrash will
	// re-insert the missing index entry on the next daemon restart (ARCH §16
	// §Crash recovery).
	if putErr := ws.index.put(chunkID, offset, ChunkDataSize); putErr != nil {
		// putErr is wrapped as ErrRocksDBInsert by index.put.
		return 0, putErr
	}

	return offset, nil
}

// LookupChunk retrieves a chunk from the vLog by content address and verifies integrity.
// Internal path: Bloom filter → RocksDB block cache → vLog pread → SHA-256 verify.
//
// Goroutine-safe: yes.
//
// [REF: IC §5.3, ARCH §16 §Audit lookup path, build.md Phase 5.1 Session 5.1.4]
func (ws *wiskeyStore) LookupChunk(chunkID [32]byte) ([]byte, error) {
	// Step 1 (ARCH §16 steps 2–3): Bloom filter + RocksDB index lookup.
	// ErrChunkNotFound exits via the in-memory Bloom filter — no disk I/O.
	vlogOffset, _, err := ws.index.get(chunkID)
	if err != nil {
		// Propagate ErrChunkNotFound or ErrVLogRead directly.
		return nil, err
	}

	// Step 2 (ARCH §16 steps 4–5): Read vLog entry and verify SHA-256(chunk_data)
	// against chunkID itself (M5 review §2), not just the entry's own stored
	// content_hash field. readFromVLog never returns partial data on
	// ErrContentHashMismatch.
	data, err := ws.readFromVLog(chunkID, vlogOffset)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// DeleteChunk removes the RocksDB index entry for chunkID.
// The vLog entry remains on disk until RunGC reclaims it.
//
// Goroutine-safe: yes.
//
// [REF: IC §5.3, ADR-023, build.md Phase 5.1 Session 5.1.5]
func (ws *wiskeyStore) DeleteChunk(chunkID [32]byte) error {
	return ws.index.del(chunkID)
}

// RecoverFromCrash scans the vLog from offset 0, re-inserting any RocksDB index entries
// that are missing. Stops at the first incomplete or corrupt entry (partial tail write
// from a pre-crash AppendChunk). Sets ws.vlogHead to the end of the last valid entry.
//
// MUST be called once at daemon startup BEFORE the writer goroutine starts.
// NOT goroutine-safe.
//
// [REF: IC §5.3, ARCH §16 §Crash recovery, ADR-023, NFR-024,
//
//	build.md Phase 5.1 Session 5.1.5]
func (ws *wiskeyStore) RecoverFromCrash() error {
	var currentOffset uint64
	for {
		var buf [vLogEntrySize]byte
		n, err := ws.vlog.ReadAt(buf[:], int64(currentOffset))
		if n < vLogEntrySize {
			// EOF or partial tail read — stop. The tail is incomplete.
			break
		}
		if err != nil && err != io.EOF {
			// Unexpected I/O error on a complete read — stop conservatively.
			break
		}

		// Extract chunk_id from the entry header.
		var chunkID [32]byte
		copy(chunkID[:], buf[vlogOffChunkID:vlogOffChunkID+sha256.Size])

		// Verify SHA-256(chunk_data) == stored content_hash.
		// A mismatch indicates a corrupt tail entry from an incomplete write.
		computed := sha256.Sum256(buf[vlogOffChunkData : vlogOffChunkData+ChunkDataSize])
		corrupt := false
		for i, b := range computed {
			if b != buf[vlogOffContentHash+i] {
				corrupt = true
				break
			}
		}
		if corrupt {
			// Corrupt entry — stop scan; don't re-insert beyond this point.
			break
		}

		// Check whether the entry is already in the RocksDB index.
		_, _, indexErr := ws.index.get(chunkID)
		switch indexErr {
		case nil:
			// Entry already indexed — no action needed.
		case ErrChunkNotFound:
			// Entry is in vLog but absent from index (post-crash gap) — re-insert.
			if putErr := ws.index.put(chunkID, currentOffset, ChunkDataSize); putErr != nil {
				return fmt.Errorf(
					"storage.RecoverFromCrash: re-insert entry at vLog offset %d: %w",
					currentOffset, putErr)
			}
		default:
			// RocksDB error during recovery — abort.
			return fmt.Errorf(
				"storage.RecoverFromCrash: index lookup at vLog offset %d: %w",
				currentOffset, indexErr)
		}

		currentOffset += vLogEntrySize
	}

	// Set vlogHead to the end of the last confirmed-valid entry.
	ws.vlogHead = currentOffset
	return nil
}

// RunGC compacts the vLog by copying live entries (those still in the RocksDB index)
// to a temporary file, then atomically renaming it over the original vLog. RocksDB
// offsets are updated to the new compacted positions during the scan.
//
// Runs in a background goroutine; ctx cancellation stops it cleanly without data loss.
// Uses a dedicated read handle so GC reads do not interfere with ws.vlog (the write
// handle used by AppendChunk).
//
// Goroutine-safe: yes.
//
// [REF: IC §5.3, ADR-023 §Garbage collection, ARCH §16, build.md Phase 5.1 Session 5.1.5]
func (ws *wiskeyStore) RunGC(ctx context.Context) error {
	// Snapshot the live set from the RocksDB index before compaction.
	liveIDs := ws.index.allChunkIDs()
	liveSet := make(map[[32]byte]struct{}, len(liveIDs))
	for _, id := range liveIDs {
		liveSet[id] = struct{}{}
	}

	// Open a dedicated read handle — separate from ws.vlog (write handle) so GC
	// reads do not require coordination with the single writer goroutine.
	readFile, err := os.Open(ws.vlogPath)
	if err != nil {
		return fmt.Errorf("storage.RunGC: open read handle: %w", err)
	}
	defer func() { _ = readFile.Close() }()

	// Create the compacted output file. Truncate if a previous GC left an orphan.
	tmpPath := ws.vlogPath + ".gc.tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return fmt.Errorf("storage.RunGC: create tmp vLog: %w", err)
	}

	var (
		newHead       uint64
		currentOffset uint64
		gcErr         error
	)

	for {
		// Check for cancellation between entries so the caller can stop GC cleanly.
		select {
		case <-ctx.Done():
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
			return ctx.Err()
		default:
		}

		var buf [vLogEntrySize]byte
		n, readErr := readFile.ReadAt(buf[:], int64(currentOffset))
		if n < vLogEntrySize {
			// EOF or partial tail — end of valid entries.
			break
		}
		if readErr != nil && readErr != io.EOF {
			// Unexpected I/O error — abort without renaming to preserve the original.
			gcErr = fmt.Errorf("storage.RunGC: read at offset %d: %w", currentOffset, readErr)
			break
		}

		var chunkID [32]byte
		copy(chunkID[:], buf[vlogOffChunkID:vlogOffChunkID+sha256.Size])

		if _, alive := liveSet[chunkID]; alive {
			// Write the live entry to the compacted file.
			if _, werr := tmpFile.Write(buf[:]); werr != nil {
				gcErr = fmt.Errorf("storage.RunGC: write tmp at offset %d: %w", newHead, werr)
				break
			}
			// Update the RocksDB index to point to the new compacted offset.
			if putErr := ws.index.put(chunkID, newHead, ChunkDataSize); putErr != nil {
				gcErr = fmt.Errorf("storage.RunGC: update index for offset %d: %w", newHead, putErr)
				break
			}
			newHead += vLogEntrySize
		}

		currentOffset += vLogEntrySize
	}

	// Fsync before rename to ensure the compacted data is durable.
	if gcErr == nil {
		if syncErr := tmpFile.Sync(); syncErr != nil {
			gcErr = fmt.Errorf("storage.RunGC: sync tmp vLog: %w", syncErr)
		}
	}
	if closeErr := tmpFile.Close(); closeErr != nil && gcErr == nil {
		gcErr = fmt.Errorf("storage.RunGC: close tmp vLog: %w", closeErr)
	}

	if gcErr != nil {
		_ = os.Remove(tmpPath)
		return gcErr
	}

	// Atomically replace the old vLog with the compacted one.
	if renameErr := os.Rename(tmpPath, ws.vlogPath); renameErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("storage.RunGC: rename tmp vLog: %w", renameErr)
	}

	// Reopen ws.vlog to point at the new compacted file.
	newVlog, err := os.OpenFile(ws.vlogPath, os.O_RDWR|os.O_APPEND, filePerm)
	if err != nil {
		return fmt.Errorf("storage.RunGC: reopen vLog after compaction: %w", err)
	}
	_ = ws.vlog.Close()
	ws.vlog = newVlog
	ws.vlogHead = newHead

	return nil
}

// Close flushes pending RocksDB writes and closes both the RocksDB instance and
// the vLog file handle. After Close returns, all method calls produce undefined behaviour.
//
// Goroutine-safe: yes (safe to call concurrently with other methods, but only once).
//
// [REF: IC §5.3, build.md Phase 5.1 Session 5.1.5]
func (ws *wiskeyStore) Close() error {
	ws.index.close()
	return ws.vlog.Close()
}

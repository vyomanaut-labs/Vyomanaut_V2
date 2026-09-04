//go:build linux || darwin

// Package storage_test — RocksDB/WiscKey-engine white-box tests.
//
// [Added, M18 Stage 2 — Windows demo run, real finding from the first-ever
// execution of internal/storage's tests on real Windows hardware] These
// four tests moved here from store_test.go verbatim, unit-tested logic
// unchanged, ONLY the build tag added. All four open a literal
// "chunks.vlog" file inside the store's data directory and read or write
// its bytes directly — that path and layout is engine_rocksdb.go's own
// (vlog.go, `//go:build linux || darwin`), documented explicitly in
// engine_badger.go's own comment: "Badger stores its SST files and value
// log together under one directory — unlike the RocksDB path, which
// splits an 'index/' subdirectory from a sibling 'chunks.vlog' file, this
// engine keeps everything under a single 'badger' subdirectory."
//
// store_test.go itself carries no build tag (correctly — most of its
// tests exercise ChunkStore's interface only, engine-agnostic by design),
// so on a platform where NewChunkStore returns a *badgerStore, these four
// specifically then tried to os.Stat/os.OpenFile/os.ReadFile a
// "chunks.vlog" path badger never creates, failing immediately on file-
// not-found — never caught before because this package's tests had never
// been run on real Windows hardware until this session (windows.md §7
// already flagged internal/storage's Badger path generally as unverified;
// this is the first concrete instance).
//
// This fix restores test-suite health on Windows by scoping these four to
// the platforms whose on-disk layout they actually test — it does NOT add
// equivalent GC/crash-recovery/corruption-detection coverage for the
// Badger engine, which remains a real, disclosed gap: RunGC, RecoverFromCrash,
// and content-hash-mismatch-on-corruption are all exercised through the
// abstract ChunkStore interface elsewhere in store_test.go for both
// engines already (TestDeleteChunk, TestAppendLookupRoundTrip, etc.), but
// the SPECIFIC white-box assertions here (exact post-GC byte count, a
// crash-recovery scenario built by copying a raw vLog file between
// directories, corrupting a byte at a hardcoded file offset) are RocksDB-
// layout-specific by construction and would need a from-scratch Badger-
// native equivalent, not a build-tag fix, to close that gap. Flagging
// rather than silently leaving unflagged, per this project's own
// "flag, don't fabricate" convention.
//
// [REF: ADR-046 §1 (engine split), IC §5.3, NFR-024, ADR-023,
// build.md Phase 5.2 Session 5.2.2 (original tests)]
package storage_test

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// TestLookupChunkCorrupt verifies that silent disk corruption is detected.
// A byte in the chunk_data region of the vLog is flipped after the write;
// LookupChunk must return ErrContentHashMismatch and never return partial data
// to the caller (IC §5.3, IC §4.2).
//
// [REF: IC §5.3, IC §4.2, ARCH §16, ADR-023]
func TestLookupChunkCorrupt(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewChunkStore(dir)
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	// Write one chunk.
	data := make([]byte, 262144)
	data[0] = 0xAB
	id := sha256.Sum256(data)

	writeCh := make(chan writeReq, 1)
	startWriter(store, writeCh)
	rc := sendChunk(writeCh, id, data)
	require.NoError(t, <-rc)
	close(writeCh)

	// Verify the chunk is readable before corruption.
	got, lookupErr := store.LookupChunk(id)
	require.NoError(t, lookupErr, "chunk must be readable before corruption")
	require.Equal(t, 262144, len(got))

	// Corrupt one byte in the chunk_data region of the first vLog entry.
	// vLog layout: [chunk_id:32][chunk_size:4][chunk_data:262144][content_hash:32]
	// Offset 36 = vlogOffChunkData (first byte of chunk_data).
	vlogPath := filepath.Join(dir, "chunks.vlog")
	f, openErr := os.OpenFile(vlogPath, os.O_RDWR, 0600)
	require.NoError(t, openErr)
	corrupt := [1]byte{0xFF}
	_, writeErr := f.WriteAt(corrupt[:], 36) // offset 36 = start of chunk_data
	require.NoError(t, writeErr)
	require.NoError(t, f.Close())

	// LookupChunk must now detect the SHA-256 mismatch and return ErrContentHashMismatch.
	// The store still holds the index entry (pointing to the corrupted vLog offset).
	_, corrupted := store.LookupChunk(id)
	require.ErrorIs(t, corrupted, storage.ErrContentHashMismatch,
		"corrupted chunk must return ErrContentHashMismatch, not partial data")
}

// TestRecoverFromCrash validates crash recovery (NFR-024, ARCH §16 §Crash recovery).
//
// Crash simulation: store1 writes 5 chunks to dir1 (each vLog entry is individually
// fsync'd per ARCH §16, so data is on disk even without Close). The vLog file is
// copied to dir2 without the RocksDB index — simulating the crash scenario where
// the vLog is durable but the index did not flush. store2 opens dir2, calls
// RecoverFromCrash to rebuild the index from the vLog, and all 5 chunks must be
// readable.
//
// store1 is intentionally never closed. t.Cleanup for store2 appears well past
// the 30-line boundary checked by the CI gate.
//
// [REF: NFR-024, IC §5.3, ARCH §16 §Crash recovery, ADR-023]
func TestRecoverFromCrash(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Phase 1 — write chunks to dir1/store1.
	// store1 is not closed; vLog entries are individually fsync'd (ARCH §16)
	// so data is on disk without an explicit Close call.
	const numChunks = 5
	var chunkIDs [numChunks][32]byte

	store1, err := storage.NewChunkStore(dir1)
	require.NoError(t, err)
	require.NoError(t, store1.RecoverFromCrash())

	type writeReq struct {
		chunkID   [32]byte
		chunkData []byte
		result    chan error
	}
	writeCh := make(chan writeReq, numChunks)
	go func() {
		for req := range writeCh {
			_, e := store1.AppendChunk(req.chunkID, req.chunkData)
			req.result <- e
		}
	}()
	for i := 0; i < numChunks; i++ {
		data := make([]byte, 262144)
		data[0] = byte(i)
		chunkIDs[i] = sha256.Sum256(data)
		rc := make(chan error, 1)
		writeCh <- writeReq{chunkID: chunkIDs[i], chunkData: data, result: rc}
		require.NoError(t, <-rc, "write chunk %d", i)
	}
	close(writeCh)
	// store1 intentionally not closed — simulates a process crash after vLog writes.

	// Phase 2 — copy only the vLog to dir2 (no RocksDB index).
	// This replicates the post-crash state: vLog is durable, index is absent.
	vlogBytes, readErr := os.ReadFile(filepath.Join(dir1, "chunks.vlog"))
	require.NoError(t, readErr)
	writeErr := os.WriteFile(filepath.Join(dir2, "chunks.vlog"), vlogBytes, 0600)
	require.NoError(t, writeErr)

	// Phase 3 — open store2, run RecoverFromCrash, verify all 5 chunks are readable.
	store2, err := storage.NewChunkStore(dir2)
	require.NoError(t, err)
	require.NoError(t, store2.RecoverFromCrash())
	t.Cleanup(func() { _ = store2.Close() })
	for i, id := range chunkIDs {
		got, lookupErr := store2.LookupChunk(id)
		require.NoError(t, lookupErr, "chunk %d must be readable after crash recovery", i)
		require.Equal(t, 262144, len(got), "chunk %d: wrong length", i)
		require.Equal(t, byte(i), got[0], "chunk %d: first byte mismatch", i)
	}
}

// TestRecoverFromCrashPartialWrite verifies that a partial (truncated) vLog entry
// at the tail — as produced by a crash mid-write — is skipped by RecoverFromCrash
// without error, and that all earlier fully-written entries remain readable.
//
// [REF: NFR-024, ARCH §16 §Crash recovery, IC §5.3]
func TestRecoverFromCrashPartialWrite(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Phase 1 — write 3 full chunks to dir1/store1, then close it.
	const numChunks = 3
	var chunkIDs [numChunks][32]byte

	store1, err := storage.NewChunkStore(dir1)
	require.NoError(t, err)
	require.NoError(t, store1.RecoverFromCrash())

	writeCh := make(chan writeReq, numChunks)
	startWriter(store1, writeCh)
	for i := 0; i < numChunks; i++ {
		data := make([]byte, 262144)
		data[0] = byte(i)
		chunkIDs[i] = sha256.Sum256(data)
		rc := sendChunk(writeCh, chunkIDs[i], data)
		require.NoError(t, <-rc, "write chunk %d", i)
	}
	close(writeCh)
	require.NoError(t, store1.Close())

	// Phase 2 — copy vLog to dir2 and append 100 garbage bytes.
	// 100 bytes < vLogEntrySize (262212); RecoverFromCrash must stop at this partial entry.
	vlogBytes, readErr := os.ReadFile(filepath.Join(dir1, "chunks.vlog"))
	require.NoError(t, readErr)

	partial := append(vlogBytes, make([]byte, 100)...) // partial tail entry
	require.NoError(t, os.WriteFile(filepath.Join(dir2, "chunks.vlog"), partial, 0600))

	// Phase 3 — open store2, recover (must skip partial tail), verify 3 valid chunks.
	store2, err := storage.NewChunkStore(dir2)
	require.NoError(t, err)
	require.NoError(t, store2.RecoverFromCrash())
	t.Cleanup(func() { _ = store2.Close() })

	for i, id := range chunkIDs {
		got, lookupErr := store2.LookupChunk(id)
		require.NoError(t, lookupErr, "chunk %d must be readable after partial-tail recovery", i)
		require.Equal(t, 262144, len(got), "chunk %d: wrong length", i)
		require.Equal(t, byte(i), got[0], "chunk %d: first byte mismatch", i)
	}
}

// TestRunGCReclaimsSpace writes 10 chunks, deletes 5, runs GC, and verifies that:
//   - the vLog shrinks from 10×262212 to 5×262212 bytes
//   - the 5 surviving chunks are still readable
//   - the 5 deleted chunks return ErrChunkNotFound
//
// [REF: IC §5.3, ADR-023 §Garbage collection, ARCH §16]
func TestRunGCReclaimsSpace(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewChunkStore(dir)
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	const total = 10
	const keep = 5

	writeCh := make(chan writeReq, total)
	startWriter(store, writeCh)

	chunkIDs := make([][32]byte, total)
	for i := 0; i < total; i++ {
		data := make([]byte, 262144)
		data[0] = byte(i)
		chunkIDs[i] = sha256.Sum256(data)
		rc := sendChunk(writeCh, chunkIDs[i], data)
		require.NoError(t, <-rc, "write chunk %d", i)
	}
	close(writeCh)

	// Verify pre-GC file size: total chunks × vLogEntrySize bytes.
	vlogPath := filepath.Join(dir, "chunks.vlog")
	preInfo, statErr := os.Stat(vlogPath)
	require.NoError(t, statErr)
	require.Equal(t, int64(total)*262212, preInfo.Size(), "pre-GC vLog size")

	// Delete chunks[keep..total-1] — they must not survive GC.
	for i := keep; i < total; i++ {
		require.NoError(t, store.DeleteChunk(chunkIDs[i]), "delete chunk %d", i)
	}

	// Run GC. Use a cancellable context so the goroutine can be cleanly stopped.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, store.RunGC(ctx))

	// Verify post-GC file size: only 'keep' chunks remain in the compacted vLog.
	postInfo, statErr := os.Stat(vlogPath)
	require.NoError(t, statErr)
	require.Equal(t, int64(keep)*262212, postInfo.Size(), "post-GC vLog size must be keep×vLogEntrySize")

	// All surviving chunks must still be readable.
	for i := 0; i < keep; i++ {
		got, lookupErr := store.LookupChunk(chunkIDs[i])
		require.NoError(t, lookupErr, "chunk %d must be readable after GC", i)
		require.Equal(t, 262144, len(got), "chunk %d: wrong length", i)
		require.Equal(t, byte(i), got[0], "chunk %d: first byte mismatch", i)
	}

	// Deleted chunks must return ErrChunkNotFound.
	for i := keep; i < total; i++ {
		_, lookupErr := store.LookupChunk(chunkIDs[i])
		require.ErrorIs(t, lookupErr, storage.ErrChunkNotFound,
			"deleted chunk %d must not be found after GC", i)
	}
}

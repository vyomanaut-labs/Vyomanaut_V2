// Package storage_test provides external black-box tests for internal/storage.
// This file covers the ChunkStore round-trip, error paths, crash recovery,
// and GC correctness tests (IC §5.3, NFR-024, ADR-023, build.md Phase 5.2 Session 5.2.2).
//
// All tests that write chunks use the channel-serialised writer pattern (IC §5.3):
// a single goroutine drains a buffered channel and is the only caller of AppendChunk.
//
// [REF: IC §5.3, NFR-024, ADR-023, ARCH §16, build.md Phase 5.2 Session 5.2.2]
package storage_test

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// writeReq is the message type for the channel-serialised writer goroutine pattern
// (IC §5.3 §Single-writer contract). Tests that need to write chunks send a writeReq
// to a dedicated writer goroutine, which is the sole caller of AppendChunk.
type writeReq struct {
	chunkID   [32]byte
	chunkData []byte
	result    chan error
}

// startWriter launches a single writer goroutine that drains ch and calls
// store.AppendChunk. The returned channel is closed when the caller closes ch.
// Callers must close ch before asserting on results to avoid goroutine leaks.
func startWriter(store storage.ChunkStore, ch <-chan writeReq) {
	go func() {
		for req := range ch {
			_, err := store.AppendChunk(req.chunkID, req.chunkData)
			req.result <- err
		}
	}()
}

// sendChunk sends one write request and waits for the result.
// Panics if the channel is full (caller must size ch appropriately).
func sendChunk(ch chan<- writeReq, id [32]byte, data []byte) chan error {
	rc := make(chan error, 1)
	ch <- writeReq{chunkID: id, chunkData: data, result: rc}
	return rc
}

// TestAppendLookupRoundTrip writes 10 chunks and reads each back, verifying
// that SHA-256(returned data) == chunkID for every chunk (IC §5.3 post-condition).
//
// [REF: IC §5.3, build.md Phase 5.2 Session 5.2.2]
func TestAppendLookupRoundTrip(t *testing.T) {
	store, err := storage.NewChunkStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	const numChunks = 10
	writeCh := make(chan writeReq, numChunks)
	startWriter(store, writeCh)

	chunkIDs := make([][32]byte, numChunks)
	for i := 0; i < numChunks; i++ {
		data := make([]byte, 262144)
		data[0] = byte(i)
		chunkIDs[i] = sha256.Sum256(data)
		rc := sendChunk(writeCh, chunkIDs[i], data)
		require.NoError(t, <-rc, "write chunk %d", i)
	}
	close(writeCh)

	for i, id := range chunkIDs {
		got, lookupErr := store.LookupChunk(id)
		require.NoError(t, lookupErr, "chunk %d must be found", i)
		require.Equal(t, 262144, len(got), "chunk %d: wrong length", i)

		// IC §5.3 post-condition: SHA-256(returned data) == chunkID.
		digest := sha256.Sum256(got)
		require.Equal(t, id, digest, "chunk %d: SHA-256 mismatch", i)
		require.Equal(t, byte(i), got[0], "chunk %d: first byte mismatch", i)
	}
}

// TestLookupChunkNotFound verifies that LookupChunk returns ErrChunkNotFound for a
// chunk ID that was never written. On this path the Bloom filter exits in memory —
// no disk I/O occurs (ARCH §16 §Audit lookup path step 2).
//
// [REF: IC §5.3, ARCH §16, ARCH §27.1]
func TestLookupChunkNotFound(t *testing.T) {
	store, err := storage.NewChunkStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	// Attempt to look up a chunk ID that was never written.
	var unknown [32]byte
	unknown[0] = 0xFF
	_, lookupErr := store.LookupChunk(unknown)
	require.ErrorIs(t, lookupErr, storage.ErrChunkNotFound)
}

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

// TestLookupChunkRejectsMismatchedWriteTimePairing verifies that LookupChunk
// never returns data for chunkID unless SHA-256(returned data) == chunkID,
// even when AppendChunk was itself called with a (chunkID, chunkData) pair
// that violates its own documented precondition (AppendChunk does not
// re-verify SHA-256(chunkData) == chunkID; verifying that pairing before
// calling AppendChunk is a caller obligation). Before this fix, LookupChunk
// only checked the vLog entry's own internally-stored content_hash field —
// which AppendChunk always writes as SHA-256 of whatever chunkData it was
// given, correct or not — so a caller bug upstream of AppendChunk was
// invisible to every read afterwards. This test calls AppendChunk directly
// with a deliberately wrong id, the same way a buggy caller would, and
// confirms LookupChunk(wrongID) now fails closed with
// ErrContentHashMismatch instead of returning data as if it were valid.
//
// [REF: IC §5.3, ARCH §16, M5 review §2]
func TestLookupChunkRejectsMismatchedWriteTimePairing(t *testing.T) {
	store, err := storage.NewChunkStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	data := make([]byte, 262144)
	data[0] = 0xCD
	var wrongID [32]byte
	wrongID[0] = 0x99 // deliberately NOT sha256.Sum256(data)

	writeCh := make(chan writeReq, 1)
	startWriter(store, writeCh)
	rc := sendChunk(writeCh, wrongID, data)
	require.NoError(t, <-rc, "AppendChunk itself does not re-verify the pairing and must not error here")
	close(writeCh)

	_, lookupErr := store.LookupChunk(wrongID)
	require.ErrorIs(t, lookupErr, storage.ErrContentHashMismatch,
		"LookupChunk must reject a chunk whose actual content does not hash to the "+
			"requested chunkID, not just a chunk whose content_hash field is internally self-consistent")
}

// TestDeleteChunk verifies that DeleteChunk removes the RocksDB index entry so
// that subsequent LookupChunk calls return ErrChunkNotFound. The vLog entry
// remains on disk until RunGC reclaims it (IC §5.3, ADR-023).
//
// [REF: IC §5.3, ADR-023, ADR-030]
func TestDeleteChunk(t *testing.T) {
	store, err := storage.NewChunkStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	data := make([]byte, 262144)
	data[0] = 0xCC
	id := sha256.Sum256(data)

	writeCh := make(chan writeReq, 1)
	startWriter(store, writeCh)
	rc := sendChunk(writeCh, id, data)
	require.NoError(t, <-rc)
	close(writeCh)

	// Chunk is readable before deletion.
	got, lookupErr := store.LookupChunk(id)
	require.NoError(t, lookupErr, "chunk must be readable before delete")
	require.Equal(t, data, got, "returned data must match written data")

	// Delete and verify the chunk is gone from the index.
	require.NoError(t, store.DeleteChunk(id))
	_, afterErr := store.LookupChunk(id)
	require.ErrorIs(t, afterErr, storage.ErrChunkNotFound,
		"deleted chunk must not be found via LookupChunk")
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

// ── ListChunks (M17-E Session 17.5.1) ──────────────────────────────────────
//
// Tests:
//   - TestListChunksReturnsEveryAppendedChunkID
//   - TestListChunksReturnsEmptySliceNotNilForEmptyStore
//   - TestListChunksOmitsDeletedChunks
//   - TestListChunksIsSafeConcurrentWithWriter

// TestListChunksReturnsEveryAppendedChunkID writes N chunks and verifies
// ListChunks returns exactly their IDs — order-independent, matching
// ChunkStore.ListChunks' own documented contract ("in unspecified order").
func TestListChunksReturnsEveryAppendedChunkID(t *testing.T) {
	store, err := storage.NewChunkStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	const numChunks = 10
	writeCh := make(chan writeReq, numChunks)
	startWriter(store, writeCh)

	want := make(map[[32]byte]bool, numChunks)
	for i := 0; i < numChunks; i++ {
		data := make([]byte, 262144)
		data[0] = byte(i)
		id := sha256.Sum256(data)
		rc := sendChunk(writeCh, id, data)
		require.NoError(t, <-rc, "write chunk %d", i)
		want[id] = true
	}
	close(writeCh)

	got, listErr := store.ListChunks()
	require.NoError(t, listErr)
	require.Len(t, got, numChunks, "ListChunks must return exactly the chunks appended")

	seen := make(map[[32]byte]bool, numChunks)
	for _, id := range got {
		require.True(t, want[id], "ListChunks returned an ID that was never appended: %x", id)
		require.False(t, seen[id], "ListChunks returned duplicate ID %x", id)
		seen[id] = true
	}
}

// TestListChunksReturnsEmptySliceNotNilForEmptyStore verifies the empty
// case returns a non-nil, zero-length slice — ChunkStore.ListChunks'
// documented post-condition (store.go): "never a nil slice with nil
// error, so callers need no special case."
func TestListChunksReturnsEmptySliceNotNilForEmptyStore(t *testing.T) {
	store, err := storage.NewChunkStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	got, listErr := store.ListChunks()
	require.NoError(t, listErr)
	require.NotNil(t, got, "ListChunks on an empty store must return a non-nil slice")
	require.Len(t, got, 0)
}

// TestListChunksOmitsDeletedChunks verifies a deleted chunk's ID does not
// reappear in a subsequent ListChunks call, and every surviving chunk
// still does.
func TestListChunksOmitsDeletedChunks(t *testing.T) {
	store, err := storage.NewChunkStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	const total = 6
	const deleteCount = 2

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

	for i := 0; i < deleteCount; i++ {
		require.NoError(t, store.DeleteChunk(chunkIDs[i]), "delete chunk %d", i)
	}

	got, listErr := store.ListChunks()
	require.NoError(t, listErr)
	require.Len(t, got, total-deleteCount, "ListChunks must omit deleted chunks")

	present := make(map[[32]byte]bool, len(got))
	for _, id := range got {
		present[id] = true
	}
	for i := 0; i < deleteCount; i++ {
		require.False(t, present[chunkIDs[i]], "deleted chunk %d must not appear in ListChunks", i)
	}
	for i := deleteCount; i < total; i++ {
		require.True(t, present[chunkIDs[i]], "surviving chunk %d must appear in ListChunks", i)
	}
}

// TestListChunksIsSafeConcurrentWithWriter runs ListChunks repeatedly on
// one goroutine while the writer goroutine appends chunks on another — the
// concurrency contract ChunkStore.ListChunks' own doc comment declares
// ("goroutine-safe; concurrent with the writer goroutine"), exercised
// under -race rather than merely asserted. require/t.Fatal are called only
// from this test's own goroutine (not the background reader) — Go's
// testing package requires that; the reader instead records any error into
// readErr, protected by mu, checked after both goroutines finish.
func TestListChunksIsSafeConcurrentWithWriter(t *testing.T) {
	store, err := storage.NewChunkStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	const numChunks = 30
	writeCh := make(chan writeReq, numChunks)
	startWriter(store, writeCh)

	var mu sync.Mutex
	var readErr error
	stopReading := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopReading:
				return
			default:
				if _, err := store.ListChunks(); err != nil {
					mu.Lock()
					if readErr == nil {
						readErr = err
					}
					mu.Unlock()
				}
			}
		}
	}()

	for i := 0; i < numChunks; i++ {
		data := make([]byte, 262144)
		data[0] = byte(i)
		id := sha256.Sum256(data)
		rc := sendChunk(writeCh, id, data)
		require.NoError(t, <-rc, "write chunk %d", i)
	}
	close(writeCh)
	close(stopReading)
	wg.Wait()

	mu.Lock()
	gotReadErr := readErr
	mu.Unlock()
	require.NoError(t, gotReadErr, "ListChunks must never error while concurrent with the writer goroutine")

	got, listErr := store.ListChunks()
	require.NoError(t, listErr)
	require.Len(t, got, numChunks, "every chunk must be visible once writing has finished")
}

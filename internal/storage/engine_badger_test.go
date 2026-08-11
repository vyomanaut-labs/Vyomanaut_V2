//go:build windows

// Package storage is declared in doc.go.
// Tests for badgerStore (engine_badger.go), the Windows-only ChunkStore
// backend. These run only on a windows-latest CI runner (ADR-046 §4) — a
// cross-compile proves the code compiles for Windows, not that it behaves
// correctly there.
//
// [REF: ADR-046, build.md Session 16.0.1]
package storage

import (
	"crypto/sha256"
	"errors"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
)

func newTestBadgerStore(t *testing.T) *badgerStore {
	t.Helper()
	store, err := newEngineStore(t.TempDir())
	if err != nil {
		t.Fatalf("newEngineStore: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})
	bs, ok := store.(*badgerStore)
	if !ok {
		t.Fatalf("newEngineStore returned %T, want *badgerStore", store)
	}
	return bs
}

// TestBadgerAppendLookupDeleteRoundTrip exercises AppendChunk → LookupChunk →
// DeleteChunk → LookupChunk against a real BadgerDB instance, mirroring the
// RocksDB path's own round-trip coverage (store_test.go) so both engines are
// held to the identical observable contract.
func TestBadgerAppendLookupDeleteRoundTrip(t *testing.T) {
	bs := newTestBadgerStore(t)

	chunkData := make([]byte, ChunkDataSize)
	for i := range chunkData {
		chunkData[i] = byte(i % 251)
	}
	chunkID := sha256.Sum256(chunkData)

	if _, err := bs.AppendChunk(chunkID, chunkData); err != nil {
		t.Fatalf("AppendChunk: %v", err)
	}

	got, err := bs.LookupChunk(chunkID)
	if err != nil {
		t.Fatalf("LookupChunk after AppendChunk: %v", err)
	}
	if len(got) != ChunkDataSize {
		t.Fatalf("LookupChunk returned %d bytes, want %d", len(got), ChunkDataSize)
	}
	for i := range got {
		if got[i] != chunkData[i] {
			t.Fatalf("LookupChunk data mismatch at byte %d", i)
		}
	}

	if err := bs.DeleteChunk(chunkID); err != nil {
		t.Fatalf("DeleteChunk: %v", err)
	}

	if _, err := bs.LookupChunk(chunkID); !errors.Is(err, ErrChunkNotFound) {
		t.Fatalf("LookupChunk after DeleteChunk: got %v, want ErrChunkNotFound", err)
	}
}

// TestBadgerContentHashVerifiedBeforeAuditResponse confirms LookupChunk
// verifies SHA-256(chunk_data) against the requested chunkID itself — not
// just trusting whatever BadgerDB returns for that key — matching
// vlog.go's readFromVLog discipline (M5 review §2) on the RocksDB path.
// Corruption is simulated by writing mismatched bytes directly through a
// raw badger.Txn, bypassing AppendChunk's own precondition entirely, since
// AppendChunk documents that it does NOT re-verify SHA-256(chunkData) ==
// chunkID (the caller's responsibility) — this test needs data that is
// already inconsistent with its key before LookupChunk ever sees it.
func TestBadgerContentHashVerifiedBeforeAuditResponse(t *testing.T) {
	bs := newTestBadgerStore(t)

	wrongData := make([]byte, ChunkDataSize)
	for i := range wrongData {
		wrongData[i] = 0xAA
	}
	// A key that does NOT hash to wrongData — the corruption scenario.
	var mismatchedKey [32]byte
	copy(mismatchedKey[:], []byte("not-the-real-sha256-of-the-data"))

	if err := bs.db.Update(func(txn *badger.Txn) error {
		return txn.Set(mismatchedKey[:], wrongData)
	}); err != nil {
		t.Fatalf("seeding mismatched entry: %v", err)
	}

	if _, err := bs.LookupChunk(mismatchedKey); !errors.Is(err, ErrContentHashMismatch) {
		t.Fatalf("LookupChunk on mismatched entry: got %v, want ErrContentHashMismatch", err)
	}
}

// TestBadgerAndRocksDBSatisfySameChunkStoreInterface documents that
// badgerStore satisfies ChunkStore identically to wiskeyStore. It cannot
// instantiate both in one test binary — engine_rocksdb.go and vlog.go carry
// //go:build linux || darwin and are not compiled into a windows test
// binary at all — so this is a compile-time-only check on this platform.
// The RocksDB-side half of this same assertion lives in engine_rocksdb.go
// itself (var _ ChunkStore = (*wiskeyStore)(nil)); this function exists
// mainly so the assertion has a named, independently-runnable test on the
// Windows side too, matching the session's VERIFY expectations.
func TestBadgerAndRocksDBSatisfySameChunkStoreInterface(t *testing.T) {
	var _ ChunkStore = (*badgerStore)(nil)
}

//go:build windows

// Package storage is declared in doc.go.
// This file implements badgerStore, the Windows-only ChunkStore backend
// (ADR-046). Unlike the Linux/macOS path — which splits the WiscKey design
// into a RocksDB index (engine_rocksdb.go) plus a hand-rolled append-only
// vLog (vlog.go) — Badger already implements the WiscKey pattern internally
// (Paper 27, cited by both ADR-023 and ADR-046). badgerStore therefore
// implements all six ChunkStore methods directly against badger.DB: full
// 256 KB chunk values flow through Badger's own value log, and its own
// crash-recovery, GC, and compaction machinery replace ADR-023's hand-rolled
// single-writer/tail-scan/GC code on this platform only (ADR-046 §3).
//
// Design Council verdict "Windows Storage Engine: Full-Adapter vs.
// Index-Only Badger Integration" (Session 16.0.1) is the resolution record
// for why this file is a full adapter rather than a drop-in replacement for
// just the RocksDB index component: an index-only substitution would leave
// Badger's value log, Bloom filter, and block cache config (below) entirely
// unexercised, and would make ADR-046's own required HDD compaction
// benchmark impossible to run against a realistic workload.
//
// IMPORT CONSTRAINT (IC §9): no other internal/ package may be imported here.
//
// [REF: IC §5.3, ARCH §16, ARCH §27.1, ADR-023, ADR-046, build.md Session
// 16.0.1]
package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
)

// badgerGCDiscardRatio is the fraction of a value-log file that must be
// reclaimable before Badger rewrites it during RunGC. 0.5 is Badger's own
// documented starting point for this knob; ADR-046's "open constraints"
// section flags all engine tuning values (this included) as starting
// values, not final — see ADR-046 §"Open constraints".
const badgerGCDiscardRatio = 0.5

// badgerStore is the concrete, unexported Windows implementation of
// ChunkStore. Callers always interact through the ChunkStore interface
// returned by NewChunkStore — identical to the Linux/macOS path (ADR-046 §1:
// "No caller-visible change").
type badgerStore struct {
	db *badger.DB
}

// newEngineStore opens the Windows storage engine: a single BadgerDB
// instance configured per ADR-046 §2 to reproduce the properties ADR-023's
// audit-latency budget depends on (Bloom filter false-positive rate, block
// cache size) rather than Badger's general-purpose defaults.
//
// NewChunkStore (store.go) dispatches here via a build-tag-selected function
// of the same name; engine_rocksdb.go provides the Linux/macOS counterpart.
//
// Badger stores its SST files and value log together under one directory —
// unlike the RocksDB path, which splits an "index/" subdirectory from a
// sibling "chunks.vlog" file, this engine keeps everything under a single
// "badger" subdirectory of dataDir so the two engines' on-disk layouts don't
// collide if dataDir is ever inspected by a human across platforms.
//
// [REF: ADR-046 §1, §2, build.md Session 16.0.1]
func newEngineStore(dataDir string) (ChunkStore, error) {
	dbPath := filepath.Join(dataDir, "badger")

	opts := badger.DefaultOptions(dbPath).
		WithValueThreshold(1024).     // route every 256 KB chunk to the value log — never inline in the LSM (ADR-046 §2)
		WithBloomFalsePositive(0.01). // matches ADR-023's 10-bits/key ≈ 1% target on the RocksDB path
		WithBlockCacheSize(64 << 20). // 64 MB — matches the RocksDB path's block cache size
		WithCompression(options.None) // chunk data is already encrypted + erasure-coded (ADR-019/ADR-022);
	// ciphertext does not compress; spending CPU trying violates the
	// ≤5% background CPU budget (ADR-009) for no benefit (ADR-046 §2).

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("storage.newEngineStore: open BadgerDB at %q: %w", dbPath, err)
	}

	return &badgerStore{db: db}, nil
}

// AppendChunk writes a 256 KB chunk directly through Badger's Txn API.
//
// *** SINGLE WRITER ONLY — NOT goroutine-safe ***
//
// This precondition is identical to the RocksDB path's, even though Badger's
// own transaction machinery is internally safe for concurrent writers — the
// daemon-level contract (one designated writer goroutine, IC §11) is a
// caller obligation enforced in cmd/provider, not something either engine
// enforces on its own (see wiskeyStore.AppendChunk's identical framing,
// vlog.go).
//
// Unlike the RocksDB path — which writes the vLog entry and inserts the
// index entry as two separate steps, each with its own documented failure
// mode (ErrVLogFsync vs. ErrRocksDBInsert) — a single badger.Txn commit is
// atomic: there is no window where the chunk data is durable but the index
// entry pointing to it is missing. ErrRocksDBInsert therefore never applies
// on this path; any write failure here is reported as ErrVLogFsync, which
// both engines' callers already treat identically ("daemon MUST halt;
// RecoverFromCrash repairs on next restart" — errors.go).
//
// The returned vlogOffset carries no meaning on this backend: Badger does
// not expose its internal value-log byte offsets through its public API, and
// no caller in cmd/provider reads this value beyond passing along the error
// (confirmed: chunkWriteResult.vlogOffset is set but never read downstream).
// Always 0 here — never a fabricated or partially-meaningful number.
//
// [REF: IC §5.3, ARCH §16 §Single writer goroutine, ADR-046 §3]
func (bs *badgerStore) AppendChunk(chunkID [32]byte, chunkData []byte) (vlogOffset uint64, err error) {
	if len(chunkData) != ChunkDataSize {
		panic(fmt.Sprintf(
			"storage.AppendChunk: chunkData must be %d bytes, got %d",
			ChunkDataSize, len(chunkData)))
	}

	if txErr := bs.db.Update(func(txn *badger.Txn) error {
		return txn.Set(chunkID[:], chunkData)
	}); txErr != nil {
		return 0, fmt.Errorf("%w: BadgerDB Set: %v", ErrVLogFsync, txErr)
	}

	return 0, nil
}

// LookupChunk retrieves a chunk from BadgerDB by content address and
// verifies integrity.
//
// Internal path: Badger's own Bloom filter and block cache (configured in
// newEngineStore to match the RocksDB path's parameters) → BadgerDB Get →
// SHA-256 verify against the requested chunkID itself — the same
// content-address-not-stored-hash discipline vlog.go's readFromVLog uses
// (M5 review §2), so a stale or corrupted value can never be returned as if
// it were valid on either engine.
//
// Goroutine-safe: yes — badger.DB.View uses Badger's own MVCC snapshot
// isolation, concurrent with any in-flight Update from the writer goroutine.
//
// [REF: IC §5.3, ARCH §16 §Audit lookup path]
func (bs *badgerStore) LookupChunk(chunkID [32]byte) ([]byte, error) {
	var data []byte

	err := bs.db.View(func(txn *badger.Txn) error {
		item, getErr := txn.Get(chunkID[:])
		if getErr != nil {
			if errors.Is(getErr, badger.ErrKeyNotFound) {
				return ErrChunkNotFound
			}
			return fmt.Errorf("%w: BadgerDB Get: %v", ErrVLogRead, getErr)
		}

		return item.Value(func(val []byte) error {
			computed := sha256.Sum256(val)
			if computed != chunkID {
				// Never return partial/unverified data on mismatch — identical
				// contract to vlog.go's readFromVLog (M5 review §2).
				return ErrContentHashMismatch
			}
			data = make([]byte, len(val))
			copy(data, val)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return data, nil
}

// DeleteChunk removes chunkID from BadgerDB. The underlying value-log space
// is reclaimed by Badger's own compaction the next time RunGC runs — there
// is no separate "index entry deleted, vLog entry still on disk" window to
// document here the way there is on the RocksDB path, since Badger owns
// both together.
//
// VETTING GC PATH (ADR-030, IC §4.5): identical semantics to the RocksDB
// path — this engine has no visibility into whether chunkID was a synthetic
// vetting chunk or a real shard (DM §3 Invariant 6).
//
// Goroutine-safe: yes.
func (bs *badgerStore) DeleteChunk(chunkID [32]byte) error {
	if err := bs.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(chunkID[:])
	}); err != nil {
		return fmt.Errorf("storage: badgerStore.DeleteChunk: %w", err)
	}
	return nil
}

// RecoverFromCrash is a documented no-op on the Badger backend.
//
// badger.Open (called from newEngineStore, above) already performs Badger's
// own crash recovery — replaying its value log and rebuilding its LSM state
// — as a synchronous part of opening the database, before newEngineStore
// ever returns a usable ChunkStore. By the time this method could be called,
// recovery has unconditionally already happened; there is no separate
// "tail scan" step for this engine the way there is for the hand-rolled vLog
// on Linux/macOS (vlog.go's RecoverFromCrash).
//
// This satisfies the documented ChunkStore precondition trivially rather
// than by coincidence: "no AppendChunk has been called since the store was
// opened; no writer goroutine is running" is guaranteed by cmd/provider's
// startup sequence (main.go Step 5, before Step 6 starts the writer
// goroutine) regardless of which engine is compiled in, so this call is safe
// to make unconditionally on both platforms even though it does real work on
// one and nothing on the other.
//
// [REF: ARCH §16 §Crash recovery, ADR-046 §3, NFR-024]
func (bs *badgerStore) RecoverFromCrash() error {
	return nil
}

// RunGC reclaims BadgerDB value-log disk space via Badger's own compaction,
// looping RunValueLogGC until it reports nothing left to reclaim
// (badger.ErrNoRewrite) or ctx is cancelled. This replaces ADR-023's
// hand-rolled compact-to-tmp-then-rename GC pass entirely on this platform
// (ADR-046 §3) — there is no separate "live set" snapshot to build here, as
// there is in vlog.go's RunGC, because Badger already knows which values are
// live from its own LSM state.
//
// Goroutine-safe: yes.
//
// [REF: ADR-023 §Garbage collection, ADR-046 §3]
func (bs *badgerStore) RunGC(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := bs.db.RunValueLogGC(badgerGCDiscardRatio); err != nil {
			if errors.Is(err, badger.ErrNoRewrite) {
				return nil
			}
			return fmt.Errorf("storage: badgerStore.RunGC: %w", err)
		}
		// A successful rewrite may have left more to reclaim — loop until
		// ErrNoRewrite, exactly as Badger's own documented GC pattern.
	}
}

// Close flushes and closes the BadgerDB instance. After Close returns, all
// method calls on this ChunkStore produce undefined behaviour and must not
// be made — identical contract to the RocksDB path's wiskeyStore.Close.
//
// Goroutine-safe: yes (safe to call concurrently with other methods, but only once).
func (bs *badgerStore) Close() error {
	if err := bs.db.Close(); err != nil {
		return fmt.Errorf("storage: badgerStore.Close: %w", err)
	}
	return nil
}

// Compile-time assertion that badgerStore satisfies ChunkStore.
var _ ChunkStore = (*badgerStore)(nil)
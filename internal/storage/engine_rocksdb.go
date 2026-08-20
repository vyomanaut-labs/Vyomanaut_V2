//go:build linux || darwin

// Package storage is declared in doc.go.
// This file implements rocksDBIndex, the RocksDB wrapper used as the WiscKey
// chunk index. It owns two column families:
//
//	"default"  — data index: chunk_id(32) → vlog_offset(uint64)+chunk_size(uint32) = 12 bytes
//	"dht-keys" — DHT key cache: chunk_id(32) → dht_key(32) (IC §12.2, ARCH §13)
//
// Configuration:
//   - Bloom filter: 10 bits/key, ~1% false-positive rate (ARCH §16, ARCH §27.1)
//   - Block cache: 64 MB LRU so the index stays warm after startup (ARCH §16)
//
// IMPORT CONSTRAINT (IC §9): no other internal/ package may be imported here.
// DHT key derivation belongs in internal/crypto; this package only stores the
// pre-computed value supplied by the caller.
//
// ENGINE SELECTION (ADR-046, Session 16.0.1, Design Council verdict
// "Windows Storage Engine: Full-Adapter vs. Index-Only Badger Integration"):
// this file also owns newEngineStore, the Linux/macOS half of the build-tag-
// selected constructor NewChunkStore (store.go) dispatches to. Its body is
// the exact code that used to live inline in store.go's NewChunkStore before
// ADR-046 added a Windows backend — moved here, not modified, so store.go can
// call the same function name on either platform and get back a fully
// constructed ChunkStore. See engine_badger.go for the Windows counterpart.
//
// wiskeyStore itself (vlog.go) is completely unchanged by this session: the
// council's resolution was to move the *call site* that constructs it, not
// its logic. The compile-time assertion at the bottom of this file confirms
// wiskeyStore still satisfies ChunkStore without editing vlog.go at all.
//
// [REF: IC §5.3, IC §12.2, ARCH §13, ARCH §16, ARCH §27.1, ADR-023, ADR-046,
//
//	build.md Phase 5.1 Session 5.1.3, build.md Session 16.0.1]
package storage

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/linxGnu/grocksdb"
)

// configuration constants for RocksDB index
const (
	bloomBits      = 10               // bits per key for Bloom filter (~1% FP)
	blockCacheSize = 64 * 1024 * 1024 // 64 MiB LRU block cache
)

// rocksDBIndex wraps the RocksDB instance used as the WiscKey chunk index.
//
// Column families:
//
//	"default"  — chunk_id (32-byte key) → vlog_offset(uint64) + chunk_size(uint32) = 12-byte value
//	             Total on-disk entry ≈ 44 bytes (ARCH §27.1: key=32, value=12).
//	"dht-keys" — chunk_id (32-byte key) → dht_key (32-byte value)
//	             Pre-computed DHT lookup keys stored at upload time (IC §12.2, ARCH §13).
//	             The heartbeat goroutine reads these for DHT republication without
//	             re-deriving from file_owner_key.
type rocksDBIndex struct {
	db       *grocksdb.DB
	cfData   *grocksdb.ColumnFamilyHandle // "default" CF — data index
	cfDHT    *grocksdb.ColumnFamilyHandle // "dht-keys" CF — cached DHT keys
	writeOps *grocksdb.WriteOptions
	readOps  *grocksdb.ReadOptions
}

// openRocksDBIndex opens (or creates) the RocksDB index at dbPath with two
// column families, a Bloom filter, and a 64 MB LRU block cache.
//
// Bloom filter: NewBloomFilter(10) — 10 bits/key ≈ 1% false-positive rate.
// An audit challenge on a chunk absent from this provider hits only the Bloom
// filter in memory; no disk I/O occurs (ARCH §16, ARCH §27.1).
//
// Block cache: 64 MB LRU. At 50 GB declared storage the full index fits in
// ~8.8 MB — the block cache keeps it warm so index lookups during audit
// challenges require no disk I/O (ARCH §16, ARCH §27.1).
func openRocksDBIndex(dbPath string) (*rocksDBIndex, error) {
	// Column-family options: shared Bloom filter + block cache for both CFs.
	bbto := grocksdb.NewDefaultBlockBasedTableOptions()
	bbto.SetFilterPolicy(grocksdb.NewBloomFilter(bloomBits)) // 10 bits/key ≈ 1% FP
	bbto.SetBlockCache(grocksdb.NewLRUCache(blockCacheSize))

	cfOpts := grocksdb.NewDefaultOptions()
	cfOpts.SetBlockBasedTableFactory(bbto)
	cfOpts.SetCreateIfMissing(true)

	// DB-level options: create the DB and any missing CFs if this is a first open.
	dbOpts := grocksdb.NewDefaultOptions()
	dbOpts.SetCreateIfMissing(true)
	dbOpts.SetCreateIfMissingColumnFamilies(true) // exact method name from options.go:2163

	cfNames := []string{"default", "dht-keys"}
	cfOptsList := []*grocksdb.Options{cfOpts, cfOpts}

	db, handles, err := grocksdb.OpenDbColumnFamilies(dbOpts, dbPath, cfNames, cfOptsList)
	if err != nil {
		return nil, fmt.Errorf("storage: openRocksDBIndex: %w", err)
	}
	return &rocksDBIndex{
		db:       db,
		cfData:   handles[0],
		cfDHT:    handles[1],
		writeOps: grocksdb.NewDefaultWriteOptions(),
		readOps:  grocksdb.NewDefaultReadOptions(),
	}, nil
}

// put inserts or updates the data index entry for chunkID in the "default" CF.
// Value layout: vlog_offset(uint64 big-endian, 8 bytes) + chunk_size(uint32 big-endian, 4 bytes)
// = indexValueSize (12) bytes total (ARCH §27.1).
func (idx *rocksDBIndex) put(chunkID [32]byte, vlogOffset uint64, chunkSize uint32) error {
	var val [indexValueSize]byte // indexValueSize = 12 (store.go)
	binary.BigEndian.PutUint64(val[0:8], vlogOffset)
	binary.BigEndian.PutUint32(val[8:12], chunkSize)
	if err := idx.db.PutCF(idx.writeOps, idx.cfData, chunkID[:], val[:]); err != nil {
		return fmt.Errorf("%w: chunkID %x: %v", ErrRocksDBInsert, chunkID, err)
	}
	return nil
}

// get retrieves vlog_offset and chunk_size for chunkID from the "default" CF.
// Returns ErrChunkNotFound when the key is absent.
//
// On the happy path, the result comes from the in-memory block cache — no
// disk I/O. On the first read after startup the SST file is read once, then
// cached. The Bloom filter screens absent keys before the block cache is
// consulted (ARCH §16 §Audit lookup path, step 2–3).
func (idx *rocksDBIndex) get(chunkID [32]byte) (vlogOffset uint64, chunkSize uint32, err error) {
	sl, err := idx.db.GetCF(idx.readOps, idx.cfData, chunkID[:])
	if err != nil {
		return 0, 0, fmt.Errorf("%w: RocksDB GetCF: %v", ErrVLogRead, err)
	}
	defer sl.Free()
	if !sl.Exists() {
		return 0, 0, ErrChunkNotFound
	}
	d := sl.Data()
	return binary.BigEndian.Uint64(d[0:8]), binary.BigEndian.Uint32(d[8:12]), nil
}

// del removes the data index entry for chunkID from the "default" CF.
// The vLog entry remains on disk until RunGC reclaims it.
func (idx *rocksDBIndex) del(chunkID [32]byte) error {
	return idx.db.DeleteCF(idx.writeOps, idx.cfData, chunkID[:])
}

// putDHTKey stores the pre-computed DHT lookup key for a chunk in the
// "dht-keys" CF. Called once per chunk at upload time by the upload
// orchestrator (Session 15.2.1).
//
// IMPORTANT: the dhtKey must be derived by internal/crypto.DeriveDHTKey before
// calling this function. This package never computes DHT keys (IC §9, IC §12.2).
// Commented out to avoid unused func error
// nolint:unused
// func (idx *rocksDBIndex) putDHTKey(chunkID [32]byte, dhtKey [32]byte) error {
// 	return idx.db.PutCF(idx.writeOps, idx.cfDHT, chunkID[:], dhtKey[:])
// }

// dhtKeyFor retrieves the cached DHT lookup key for chunkID from the "dht-keys" CF.
// Returns ok=false when no DHT key was stored for this chunk (e.g. the chunk
// was added before DHT integration was enabled, or the DB was freshly created).
//
// The heartbeat goroutine calls this during DHT republication (IC §12.2, ARCH §13).
// It must NEVER recompute dhtKey from file_owner_key — that derivation belongs
// exclusively in internal/crypto.
// Commented out to avoid unused func error
// nolint:unused
// func (idx *rocksDBIndex) dhtKeyFor(chunkID [32]byte) (dhtKey [32]byte, ok bool) {
// 	sl, err := idx.db.GetCF(idx.readOps, idx.cfDHT, chunkID[:])
// 	if err != nil || !sl.Exists() {
// 		if sl != nil {
// 			sl.Free()
// 		}
// 		return dhtKey, false
// 	}
// 	defer sl.Free()
// 	copy(dhtKey[:], sl.Data())
// 	return dhtKey, true
// }

// allChunkIDs returns every chunk_id present in the data index ("default" CF).
//
// Used by the DHT republication loop in the heartbeat goroutine to iterate
// over all locally stored chunks and republish their DHT entries (IC §12.2,
// Session 6.3.1).
//
// The iterator snapshot is consistent; concurrent writes do not affect it.
func (idx *rocksDBIndex) allChunkIDs() [][32]byte {
	it := idx.db.NewIteratorCF(idx.readOps, idx.cfData)
	defer it.Close()
	var ids [][32]byte
	for it.SeekToFirst(); it.Valid(); it.Next() {
		k := it.Key()
		var id [32]byte
		copy(id[:], k.Data())
		k.Free()
		ids = append(ids, id)
	}
	return ids
}

// listChunkIDs is allChunkIDs' counterpart for ChunkStore.ListChunks
// (M17-E Session 17.5.1) — a SEPARATE method, not a refactor of
// allChunkIDs above, deliberately: allChunkIDs has one existing caller
// (vlog.go's RunGC, outside this session's FILES: scope) with a
// long-standing signature ([][32]byte, no error) this session does not
// touch. ChunkStore.ListChunks's own contract returns an error, so this
// method — unlike allChunkIDs — checks Iterator.Err() after the scan: an
// interface that promises error reporting should not silently report
// success if RocksDB's C++ iterator actually hit one (e.g. a corrupted
// SST file), no matter how unlikely in practice.
//
// Returns a non-nil, zero-length slice for an empty CF — never nil with a
// nil error (ChunkStore.ListChunks' documented post-condition, store.go).
func (idx *rocksDBIndex) listChunkIDs() ([][32]byte, error) {
	it := idx.db.NewIteratorCF(idx.readOps, idx.cfData)
	defer it.Close()

	ids := make([][32]byte, 0)
	for it.SeekToFirst(); it.Valid(); it.Next() {
		k := it.Key()
		var id [32]byte
		copy(id[:], k.Data())
		k.Free()
		ids = append(ids, id)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("storage: rocksDBIndex.listChunkIDs: iteration: %w", err)
	}
	return ids, nil
}

// close releases all RocksDB handles in the correct order:
// CF handles before WriteOptions/ReadOptions before the DB itself.
func (idx *rocksDBIndex) close() {
	idx.cfData.Destroy()
	idx.cfDHT.Destroy()
	idx.writeOps.Destroy()
	idx.readOps.Destroy()
	idx.db.Close()
}

// newEngineStore opens the Linux/macOS storage engine: the RocksDB chunk
// index (this file) paired with the hand-rolled append-only vLog
// (wiskeyStore, vlog.go). NewChunkStore (store.go) dispatches here via a
// build-tag-selected function of the same name; engine_badger.go provides
// the Windows counterpart.
//
// This is exactly the body that used to live inline in store.go's
// NewChunkStore before ADR-046 added a second backend — relocated, not
// rewritten, so the already-CI-proven Linux/macOS path is byte-for-byte
// unchanged in behavior (Session 16.0.1, ADR-046 §1).
//
// [REF: IC §5.3, ARCH §16, ADR-023, ADR-046 §1, build.md Phase 5.1 Session
// 5.1.5, build.md Session 16.0.1]
func newEngineStore(dataDir string) (ChunkStore, error) {
	indexPath := filepath.Join(dataDir, "index")
	idx, err := openRocksDBIndex(indexPath)
	if err != nil {
		return nil, fmt.Errorf("storage.newEngineStore: open RocksDB index: %w", err)
	}

	vlogPath := filepath.Join(dataDir, "chunks.vlog")
	// O_RDWR: supports both ReadAt (pread, goroutine-safe) and Write (single writer).
	// O_APPEND: ensures writes always land at EOF even on Linux after a Seek.
	// O_CREATE: creates the file on first daemon start.
	vlogFile, err := os.OpenFile(vlogPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, filePerm)
	if err != nil {
		idx.close()
		return nil, fmt.Errorf("storage.newEngineStore: open vLog %q: %w", vlogPath, err)
	}

	// Initialise vlogHead from the current file size. The caller must invoke
	// the crash-recovery scan before starting the writer goroutine (NFR-024);
	// that scan corrects vlogHead if the tail holds entries not yet in RocksDB.
	info, err := vlogFile.Stat()
	if err != nil {
		_ = vlogFile.Close()
		idx.close()
		return nil, fmt.Errorf("storage.newEngineStore: stat vLog: %w", err)
	}

	return &wiskeyStore{
		index:        idx,
		vlog:         vlogFile,
		vlogPath:     vlogPath,
		vlogHead:     uint64(info.Size()),
		isRotational: isRotationalDevice(dataDir),
	}, nil
}

// Compile-time assertion that wiskeyStore (vlog.go, entirely untouched by
// this session) satisfies ChunkStore. Declared here rather than in vlog.go
// so vlog.go's diff for Session 16.0.1 is exactly zero (Design Council
// verdict, correction #2).
var _ ChunkStore = (*wiskeyStore)(nil)

// ListChunks satisfies ChunkStore.ListChunks (store.go, M17-E Session
// 17.5.1) for wiskeyStore. Defined here, not vlog.go, for the identical
// reason the compile-time assertion immediately above is: keeping
// vlog.go's diff at zero, the same precedent Session 16.0.1 (ADR-046 §1)
// already established for this exact file — a wiskeyStore method living
// in a file other than the one declaring the type is not a new pattern
// this session invents.
//
// A thin wrapper, not inline iteration logic: real work is
// rocksDBIndex.listChunkIDs (above), the same "ChunkStore-facing method +
// private rocksDBIndex helper" shape put/get/del/allChunkIDs already use
// throughout this file.
func (s *wiskeyStore) ListChunks() ([][32]byte, error) {
	return s.index.listChunkIDs()
}

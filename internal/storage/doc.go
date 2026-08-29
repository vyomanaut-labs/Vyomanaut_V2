/*
Package storage implements the ChunkStore interface behind two platform-selected engines
(NewChunkStore dispatches by GOOS, never by a runtime flag): the WiscKey key-value separated
engine on Linux/macOS — the vLog (value log) is an append-only file, the index is RocksDB
(engine_rocksdb.go, ADR-023) — and BadgerDB on Windows (engine_badger.go, ADR-046), which needs
no CGO toolchain at all.

CONCURRENCY CONTRACT: AppendChunk is NOT goroutine-safe. It must only be called from the single designated writer goroutine.

Versions:
rocksdb_version="10.10.1"
grocksDB = v1.10.8

All other exported functions are goroutine-safe (read-only paths).

ListChunks (M17-E Session 17.5.1, ADR-084 §D-2a, requirement 5) enumerates every chunk ID a
store currently holds, in unspecified order — an O(n) index scan, read-only, goroutine-safe,
requiring no coordination with the single writer goroutine. Implemented on BOTH engines
(engine_rocksdb.go's wiskeyStore, engine_badger.go's badgerStore) — the only ChunkStore interface
change M17-E makes. Intended purpose is local operator inspection only (cmd/provider's `inspect`
subcommand, Session 17.5.2): never called from any request-handling code path.

Ref: ADR-023, ADR-046, ADR-084 §D-2a, NFR-023
*/
package storage

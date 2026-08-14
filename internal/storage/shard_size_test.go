// Package storage_test is the external test package for internal/storage.
// This file exists so it can import internal/erasure without creating an
// import cycle in production code: internal/storage's own production files
// must not import internal/erasure (IC §9), but an external _test package
// may — exactly mirroring the trick internal/config/profiles_test.go
// already uses for the analogous config↔erasure check.
//
// [REF: IC §9, DM §3 Invariant 7, ADR-031, M3 review §3]
package storage_test

import (
	"testing"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// TestChunkDataSizeMatchesErasureShardSize closes a gap where
// storage.ChunkDataSize and erasure.ShardSize are two independently-
// hardcoded 262144 literals — required to be equal (a vLog entry holds
// exactly one erasure-coded shard) but, before this test, enforced by
// nothing except two engineers having typed the same number.
//
// [REF: IC §9, DM §3 Invariant 7, M3 review §3]
func TestChunkDataSizeMatchesErasureShardSize(t *testing.T) {
	if storage.ChunkDataSize != erasure.ShardSize {
		t.Errorf("storage.ChunkDataSize=%d != erasure.ShardSize=%d — these must be "+
			"identical: a vLog entry holds exactly one erasure-coded shard",
			storage.ChunkDataSize, erasure.ShardSize)
	}
}

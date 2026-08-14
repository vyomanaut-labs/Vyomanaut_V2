// Package erasure is declared in doc.go.
// This file defines the ShardSize constant, the Engine struct, and the
// profile consistency check executed by NewEngine at construction time.
//
// INVARIANT (DM §3 Invariant 7): ShardSize = 262,144 (256 KB) is a compile-time
// constant. It is identical in both demo and production profiles. Its value must
// never be taken from config.NetworkProfile at runtime. The runtime guard in
// profileConsistencyCheck is a defence-in-depth assertion, not the primary check;
// the primary check is TestProfileShardSizeIsConstant in the config package.
//
// [REF: DM §3 Invariant 7, ADR-003, ADR-031, IC §5.2,
//
//	build.md Phase 3.1 Session 3.1.1]
package erasure

import "github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"

// ShardSize is the fixed size of every erasure-coded shard in bytes.
// 256 KB; identical in both demo and production modes.
// Never mode-variable; never stored in config.NetworkProfile.
//
// [REF: DM §3 Invariant 7, ADR-003, ADR-031]
const ShardSize = 262144 // 2^18 = 256 KiB; identical in both profiles

// Engine holds the erasure-coding parameters derived from a NetworkProfile.
// Constructed once per process via NewEngine; all exported methods are goroutine-safe.
//
// [REF: IC §5.2, ADR-003]
type Engine struct {
	// DataShards is the reconstruction threshold (s). Production=16, Demo=3.
	// [REF: ADR-003]
	DataShards int
	// ParityShards is the number of redundancy shards (r). Production=40, Demo=2.
	// [REF: ADR-003]
	ParityShards int
	// TotalShards is DataShards + ParityShards (n). Production=56, Demo=5.
	// [REF: ADR-003]
	TotalShards int

	// enc is the underlying GF(2^8) Reed-Solomon encoder.
	// Unexported; callers interact only through EncodeSegment and DecodeSegment.
	enc *rsEncoder
}

// profileConsistencyCheck validates that the profile's erasure fields are
// internally consistent before NewEngine allocates the RS engine.
//
// Checks (in order):
//  1. DataShards >= 1
//  2. TotalShards == DataShards + ParityShards
//  3. ShardSize == compile-time ShardSize constant (defence-in-depth)
//
// NOTE: ParityShards >= 1 is also required for a usable RS code, but that
// floor is enforced one layer down, inside newRSEncoder (called from
// NewEngine right after this function returns), not here. Both checks run
// on every NewEngine call. (M3 review §5)
//
// [REF: IC §5.2, DM §3 Invariant 7]
func profileConsistencyCheck(p config.NetworkProfile) error {
	if p.DataShards < 1 {
		return ErrDataShardsZero
	}
	if p.TotalShards != p.DataShards+p.ParityShards {
		return ErrTotalShardsMismatch
	}
	// Runtime guard: profile.ShardSize must always equal the compile-time constant.
	// A mismatch means either DemoProfile or ProductionProfile has been misconfigured.
	// This is caught at startup; never silently ignored.
	// [REF: DM §3 Invariant 7, ADR-031]
	if p.ShardSize != ShardSize {
		return ErrShardSizeMismatch
	}
	return nil
}

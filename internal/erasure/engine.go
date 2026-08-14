// Package erasure is declared in doc.go.
// This file implements NewEngine, EncodeSegment, and DecodeSegment.
//
// NewEngine constructs an Engine from a NetworkProfile, running
// profileConsistencyCheck before allocating the GF(2^8) RS codec.
//
// EncodeSegment splits a DataShards×ShardSize AONT package into TotalShards
// independent shards, computing parity via the generator matrix.
//
// DecodeSegment reconstructs the AONT package from any DataShards of the
// TotalShards shards, filling nil entries in-place.
//
// All three functions are goroutine-safe after Engine construction.
//
// [REF: IC §5.2, ADR-003, ADR-031, build.md Phase 3.1 Session 3.1.2]

package erasure

import (
	"fmt"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// NewEngine constructs an erasure Engine from the active NetworkProfile.
//
// Pre-conditions:
//   - profile.DataShards >= 1
//   - profile.TotalShards == profile.DataShards + profile.ParityShards
//   - profile.ShardSize == ShardSize  (compile-time constant; guarded by TestProfileShardSizeIsConstant)
//
// Error semantics: returns a typed sentinel error on any pre-condition
// violation; returns a wrapped error if the underlying GF codec fails.
// Goroutine-safe: yes (pure construction; returned Engine is immutable).
//
// [REF: IC §5.2, build.md Phase 3.1 Session 3.1.2]
func NewEngine(profile config.NetworkProfile) (*Engine, error) {
	if err := profileConsistencyCheck(profile); err != nil {
		return nil, err
	}
	enc, err := newRSEncoder(profile.DataShards, profile.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("erasure: RS codec init failed: %w", err)
	}
	return &Engine{
		DataShards:   profile.DataShards,
		ParityShards: profile.ParityShards,
		TotalShards:  profile.TotalShards,
		enc:          enc,
	}, nil
}

// EncodeSegment splits an AONT package into e.TotalShards shards, each of
// exactly ShardSize bytes.
//
// Pre-conditions:
//   - len(aontPackage) == e.DataShards * ShardSize  (exactly)
//
// Post-conditions:
//   - returns exactly e.TotalShards byte slices, each len ShardSize
//   - any e.DataShards of the returned slices can reconstruct aontPackage
//   - the first e.DataShards returned slices ALIAS the caller's aontPackage
//     buffer (re-sliced views, not copies); only the remaining
//     e.ParityShards slices are freshly allocated. A caller that mutates or
//     reuses/pools aontPackage after this call returns will silently
//     corrupt the already-returned data shards. (M3 review §5)
//
// Error semantics: returns a descriptive error on pre-condition violation or
// internal GF failure; treat the latter as fatal.
// Goroutine-safe: yes (no shared mutable state).
//
// [REF: IC §5.2, build.md Phase 3.1 Session 3.1.2]
func (e *Engine) EncodeSegment(aontPackage []byte) ([][]byte, error) {
	want := e.DataShards * ShardSize
	if len(aontPackage) != want {
		return nil, fmt.Errorf(
			"erasure.EncodeSegment: aontPackage is %d bytes; want DataShards×ShardSize = %d×%d = %d",
			len(aontPackage), e.DataShards, ShardSize, want)
	}

	// Split into DataShards data shards; allocate ParityShards parity shards.
	shards := make([][]byte, e.TotalShards)
	for i := 0; i < e.DataShards; i++ {
		shards[i] = aontPackage[i*ShardSize : (i+1)*ShardSize]
	}
	for i := e.DataShards; i < e.TotalShards; i++ {
		shards[i] = make([]byte, ShardSize)
	}

	// Compute parity shards via the generator matrix.
	e.enc.encode(shards)
	return shards, nil
}

// DecodeSegment reconstructs an AONT package from any e.DataShards of the
// e.TotalShards shards. Nil entries are treated as erasures and filled
// in-place during reconstruction.
//
// Pre-conditions:
//   - len(shards) == e.TotalShards
//   - at least e.DataShards entries are non-nil
//   - every non-nil shard is exactly ShardSize bytes
//
// Post-conditions (on nil error):
//   - returns the reconstructed AONT package, len == e.DataShards * ShardSize
//   - nil data shard entries in the caller's slice are replaced in-place
//
// Error semantics:
//   - ErrTooFewShards: fewer than DataShards non-nil shards
//   - ErrShardSize:    a non-nil shard has wrong length
//   - wrapped error:   internal GF reconstruction failure; treat as fatal
//
// Goroutine-safe: yes (modifies the caller's shards slice in-place, but does
// not touch Engine state).
//
// [REF: IC §5.2, build.md Phase 3.1 Session 3.1.2]
func (e *Engine) DecodeSegment(shards [][]byte) ([]byte, error) {
	if len(shards) != e.TotalShards {
		return nil, fmt.Errorf(
			"erasure.DecodeSegment: got %d shards, want %d (TotalShards)",
			len(shards), e.TotalShards)
	}

	// Validate non-nil shard count and sizes.
	nonNil := 0
	for _, s := range shards {
		if s == nil {
			continue
		}
		if len(s) != ShardSize {
			return nil, ErrShardSize
		}
		nonNil++
	}
	if nonNil < e.DataShards {
		return nil, ErrTooFewShards
	}

	// Reconstruct missing data shards from available shards.
	if err := e.enc.reconstruct(shards); err != nil {
		return nil, fmt.Errorf("erasure.DecodeSegment: reconstruction failed: %w", err)
	}

	// Concatenate the DataShards data shards into the AONT package.
	result := make([]byte, 0, e.DataShards*ShardSize)
	for i := 0; i < e.DataShards; i++ {
		result = append(result, shards[i]...)
	}
	return result, nil
}

// Package erasure is declared in doc.go.
// Unit tests for NewEngine, EncodeSegment, and DecodeSegment.
//
// Tests:
//   - TestNewEngineErrors              — constructor rejects bad profiles, accepts good ones
//   - TestEncodeDecodeRoundTripDemo    — full encode→decode with demo profile
//   - TestEncodeDecodeRoundTripProd    — full encode→decode with production profile
//   - TestDecodeAnyKShards             — any DataShards of TotalShards suffice (demo)
//   - TestDecodeParityOnly             — parity shards can substitute for missing data shards (demo)
//   - TestDecodeErrTooFewShards        — DataShards-1 shards → ErrTooFewShards
//   - TestDecodeErrShardSize           — wrong-length shard → ErrShardSize
//   - TestEncodeSegmentWrongLength     — wrong-length AONT package → error
//   - TestShardSizeAssertion           — ShardSize constant == both profile fields
//
// The ShardSize assertion is the runtime complement to TestProfileShardSizeIsConstant
// in the config package (DM §3 Invariant 7, ADR-031).
//
// [REF: IC §5.2, ADR-003, ADR-031, build.md Phase 3.1 Session 3.1.2]

package erasure

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// testAONTPackage returns a deterministic synthetic AONT package of
// dataShards × ShardSize bytes. Byte at index i equals byte(i mod 256),
// giving a non-trivial, non-zero pattern that exposes XOR-only bugs.
func testAONTPackage(dataShards int) []byte {
	size := dataShards * ShardSize
	pkg := make([]byte, size)
	for i := range pkg {
		pkg[i] = byte(i)
	}
	return pkg
}

// ── TestNewEngineErrors ───────────────────────────────────────────────────────

// TestNewEngineErrors verifies all constructor error paths and the two
// accepting paths (DemoProfile and ProductionProfile).
//
// [REF: build.md Phase 3.1 Session 3.1.2 VERIFY: TestNewEngineErrors]
func TestNewEngineErrors(t *testing.T) {
	t.Run("TestNewEngineRejectsBadDataShards", func(t *testing.T) {
		p := config.DemoProfile
		p.DataShards = 0
		_, err := NewEngine(p)
		if !errors.Is(err, ErrDataShardsZero) {
			t.Errorf("DataShards=0: got %v, want ErrDataShardsZero", err)
		}
	})

	t.Run("TestNewEngineRejectsMismatchedTotal", func(t *testing.T) {
		p := config.DemoProfile
		p.TotalShards = p.DataShards + p.ParityShards + 1 // off by one
		_, err := NewEngine(p)
		if !errors.Is(err, ErrTotalShardsMismatch) {
			t.Errorf("TotalShards mismatch: got %v, want ErrTotalShardsMismatch", err)
		}
	})

	t.Run("TestNewEngineRejectsBadShardSize", func(t *testing.T) {
		p := config.DemoProfile
		p.ShardSize = 1 // must be 262144
		_, err := NewEngine(p)
		if !errors.Is(err, ErrShardSizeMismatch) {
			t.Errorf("ShardSize=1: got %v, want ErrShardSizeMismatch", err)
		}
	})

	t.Run("TestNewEngineAcceptsDemoProfile", func(t *testing.T) {
		eng, err := NewEngine(config.DemoProfile)
		if err != nil {
			t.Fatalf("NewEngine(DemoProfile): unexpected error: %v", err)
		}
		if eng.DataShards != config.DemoProfile.DataShards {
			t.Errorf("DataShards=%d, want %d", eng.DataShards, config.DemoProfile.DataShards)
		}
		if eng.TotalShards != config.DemoProfile.TotalShards {
			t.Errorf("TotalShards=%d, want %d", eng.TotalShards, config.DemoProfile.TotalShards)
		}
	})

	t.Run("TestNewEngineAcceptsProductionProfile", func(t *testing.T) {
		eng, err := NewEngine(config.ProductionProfile)
		if err != nil {
			t.Fatalf("NewEngine(ProductionProfile): unexpected error: %v", err)
		}
		if eng.DataShards != config.ProductionProfile.DataShards {
			t.Errorf("DataShards=%d, want %d", eng.DataShards, config.ProductionProfile.DataShards)
		}
	})
}

// ── Round-trip tests ──────────────────────────────────────────────────────────

// TestEncodeDecodeRoundTripDemo verifies full encode→decode with demo profile
// (DataShards=3, TotalShards=5, ShardSize=262144).
//
// [REF: IC §5.2, build.md Phase 3.1 Session 3.1.2]
func TestEncodeDecodeRoundTripDemo(t *testing.T) {
	eng, err := NewEngine(config.DemoProfile)
	if err != nil {
		t.Fatalf("NewEngine(DemoProfile): %v", err)
	}

	original := testAONTPackage(eng.DataShards)
	shards, err := eng.EncodeSegment(original)
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}

	// Each shard must be exactly ShardSize bytes.
	if len(shards) != eng.TotalShards {
		t.Errorf("EncodeSegment: got %d shards, want %d", len(shards), eng.TotalShards)
	}
	for i, s := range shards {
		if len(s) != ShardSize {
			t.Errorf("shards[%d] len=%d, want %d (ShardSize)", i, len(s), ShardSize)
		}
	}

	recovered, err := eng.DecodeSegment(shards)
	if err != nil {
		t.Fatalf("DecodeSegment: %v", err)
	}
	if !bytes.Equal(recovered, original) {
		t.Error("demo round-trip mismatch: recovered != original")
	}
}

// TestEncodeDecodeRoundTripProd verifies full encode→decode with production
// profile (DataShards=16, TotalShards=56, ShardSize=262144).
// Input size: 16 × 262144 = 4,194,304 bytes (4 MiB).
//
// [REF: IC §5.2, build.md Phase 3.1 Session 3.1.2]
func TestEncodeDecodeRoundTripProd(t *testing.T) {
	eng, err := NewEngine(config.ProductionProfile)
	if err != nil {
		t.Fatalf("NewEngine(ProductionProfile): %v", err)
	}

	original := testAONTPackage(eng.DataShards)
	shards, err := eng.EncodeSegment(original)
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}
	if len(shards) != eng.TotalShards {
		t.Errorf("EncodeSegment: got %d shards, want %d", len(shards), eng.TotalShards)
	}

	recovered, err := eng.DecodeSegment(shards)
	if err != nil {
		t.Fatalf("DecodeSegment: %v", err)
	}
	if !bytes.Equal(recovered, original) {
		t.Error("prod round-trip mismatch: recovered != original")
	}
}

// ── Any-k-shards tests (demo profile) ────────────────────────────────────────

// TestDecodeAnyKShards verifies that DataShards contiguous data shards
// (all parity shards nil) suffice for reconstruction.
//
// [REF: IC §5.2, ADR-003]
func TestDecodeAnyKShards(t *testing.T) {
	eng, err := NewEngine(config.DemoProfile)
	if err != nil {
		t.Fatalf("NewEngine(DemoProfile): %v", err)
	}

	original := testAONTPackage(eng.DataShards)
	allShards, err := eng.EncodeSegment(original)
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}

	// Keep only the first DataShards shards; nil out all parity shards.
	sparse := make([][]byte, eng.TotalShards)
	copy(sparse[:eng.DataShards], allShards[:eng.DataShards])

	recovered, err := eng.DecodeSegment(sparse)
	if err != nil {
		t.Fatalf("DecodeSegment (data shards only): %v", err)
	}
	if !bytes.Equal(recovered, original) {
		t.Error("any-k-shards (data only) mismatch")
	}
}

// TestDecodeParityOnly verifies that reconstruction works when exactly
// DataShards shards are available and some are parity shards.
//
// Demo profile: DataShards=3, ParityShards=2, TotalShards=5.
// We nil out the first two data shards, keeping data[2] and parity[0..1].
// That is still 3 shards (= DataShards), so reconstruction must succeed.
//
// [REF: IC §5.2, ADR-003]
func TestDecodeParityOnly(t *testing.T) {
	eng, err := NewEngine(config.DemoProfile)
	if err != nil {
		t.Fatalf("NewEngine(DemoProfile): %v", err)
	}
	// This test only makes sense when ParityShards >= DataShards-1 so that
	// we have enough total shards when data shards are erased.
	if eng.ParityShards < eng.DataShards-1 {
		t.Skip("ParityShards < DataShards-1; cannot erase enough data shards")
	}

	original := testAONTPackage(eng.DataShards)
	allShards, err := eng.EncodeSegment(original)
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}

	// Nil out all but the last data shard; keep all parity shards.
	// Demo: nil shards[0], shards[1] → 1 data + 2 parity = 3 = DataShards.
	mixed := make([][]byte, eng.TotalShards)
	copy(mixed, allShards)
	for i := 0; i < eng.DataShards-1; i++ {
		mixed[i] = nil
	}

	recovered, err := eng.DecodeSegment(mixed)
	if err != nil {
		t.Fatalf("DecodeSegment (parity-assisted): %v", err)
	}
	if !bytes.Equal(recovered, original) {
		t.Error("parity-assisted decode mismatch")
	}
}

// TestDecodeAnyKShardsExhaustive enumerates all C(5,3)=10 possible 3-of-5
// subsets for the demo profile and verifies each reconstructs the original
// AONT package. This is the exhaustive coverage build.md Session 3.2.3 asked
// for (as TestAnyKShardsReconstructsDemo). TestDecodeAnyKShards only
// exercises the trivial "all DataShards present" case, which reconstruct()'s
// allDataPresent early-return means never actually runs the matrix-
// inversion/Gauss-Jordan path at all — see rs_internal.go. This test forces
// every combination through real reconstruction math, including subsets
// that require parity shards standing in for missing data shards.
//
// Production combinatorics (C(56,16) ≈ 1.7×10^25) remain infeasible to
// enumerate — that's still correctly out of scope; see
// TestEncodeDecodeRoundTripProd and TestDecodeParityOnly for the targeted
// production coverage instead.
//
// [REF: build.md Phase 3.1 Session 3.2.3 — TestAnyKShardsReconstructsDemo, M3 review §2]
func TestDecodeAnyKShardsExhaustive(t *testing.T) {
	eng, err := NewEngine(config.DemoProfile)
	if err != nil {
		t.Fatalf("NewEngine(DemoProfile): %v", err)
	}
	if eng.TotalShards != 5 || eng.DataShards != 3 {
		t.Fatalf("test assumes DemoProfile is RS(3,5); got DataShards=%d TotalShards=%d — "+
			"update the hardcoded subsets below if DemoProfile's parameters ever change",
			eng.DataShards, eng.TotalShards)
	}

	original := testAONTPackage(eng.DataShards)
	allShards, err := eng.EncodeSegment(original)
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}

	// All C(5,3) = 10 three-element subsets of {0,1,2,3,4} — indices to KEEP.
	subsets := [][3]int{
		{0, 1, 2}, {0, 1, 3}, {0, 1, 4}, {0, 2, 3}, {0, 2, 4},
		{0, 3, 4}, {1, 2, 3}, {1, 2, 4}, {1, 3, 4}, {2, 3, 4},
	}

	for _, keep := range subsets {
		keep := keep
		t.Run(fmt.Sprintf("keep_%d_%d_%d", keep[0], keep[1], keep[2]), func(t *testing.T) {
			mixed := make([][]byte, eng.TotalShards)
			for _, idx := range keep {
				mixed[idx] = allShards[idx]
			}

			recovered, decErr := eng.DecodeSegment(mixed)
			if decErr != nil {
				t.Fatalf("DecodeSegment with shards %v present: %v", keep, decErr)
			}
			if !bytes.Equal(recovered, original) {
				t.Errorf("subset %v: reconstructed data does not match original", keep)
			}
		})
	}
}

// TestCrossProfileIncompatibility documents and verifies that different
// profiles produce structurally incompatible shard counts — not that
// cross-decoding silently produces wrong data, which is impossible by
// construction. Demo-encoded shards (5 total) fed to a production-configured
// Engine (expects 56) must fail at DecodeSegment's len(shards) !=
// e.TotalShards precondition, before any reconstruction math runs.
//
// [REF: build.md Phase 3.1 Session 3.2.3 — TestCrossProfileIncompatibility, M3 review §2]
func TestCrossProfileIncompatibility(t *testing.T) {
	demoEng, err := NewEngine(config.DemoProfile)
	if err != nil {
		t.Fatalf("NewEngine(DemoProfile): %v", err)
	}
	prodEng, err := NewEngine(config.ProductionProfile)
	if err != nil {
		t.Fatalf("NewEngine(ProductionProfile): %v", err)
	}

	demoInput := testAONTPackage(demoEng.DataShards)
	demoShards, err := demoEng.EncodeSegment(demoInput)
	if err != nil {
		t.Fatalf("demoEng.EncodeSegment: %v", err)
	}

	if len(demoShards) == prodEng.TotalShards {
		t.Fatalf("test setup invalid: DemoProfile.TotalShards (%d) == "+
			"ProductionProfile.TotalShards (%d) — profiles no longer differ "+
			"the way this test assumes", len(demoShards), prodEng.TotalShards)
	}

	if _, decErr := prodEng.DecodeSegment(demoShards); decErr == nil {
		t.Fatal("cross-profile decode (5 demo shards into a 56-shard production Engine) must fail, got nil error")
	}
}

// ── Error path tests ──────────────────────────────────────────────────────────

// TestDecodeErrTooFewShards verifies ErrTooFewShards when fewer than
// DataShards non-nil shards are supplied.
func TestDecodeErrTooFewShards(t *testing.T) {
	eng, err := NewEngine(config.DemoProfile)
	if err != nil {
		t.Fatalf("NewEngine(DemoProfile): %v", err)
	}

	allShards, err := eng.EncodeSegment(testAONTPackage(eng.DataShards))
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}

	// Keep only DataShards-1 shards.
	sparse := make([][]byte, eng.TotalShards)
	for i := 0; i < eng.DataShards-1; i++ {
		sparse[i] = allShards[i]
	}

	_, decErr := eng.DecodeSegment(sparse)
	if !errors.Is(decErr, ErrTooFewShards) {
		t.Errorf("expected ErrTooFewShards, got %v", decErr)
	}
}

// TestDecodeErrShardSize verifies ErrShardSize when a non-nil shard has the
// wrong length.
func TestDecodeErrShardSize(t *testing.T) {
	eng, err := NewEngine(config.DemoProfile)
	if err != nil {
		t.Fatalf("NewEngine(DemoProfile): %v", err)
	}

	allShards, err := eng.EncodeSegment(testAONTPackage(eng.DataShards))
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}

	// Replace the first shard with one that is one byte short.
	allShards[0] = make([]byte, ShardSize-1)

	_, decErr := eng.DecodeSegment(allShards)
	if !errors.Is(decErr, ErrShardSize) {
		t.Errorf("expected ErrShardSize, got %v", decErr)
	}
}

// TestEncodeSegmentWrongLength verifies that EncodeSegment returns an error
// when the input is not exactly DataShards×ShardSize bytes.
func TestEncodeSegmentWrongLength(t *testing.T) {
	eng, err := NewEngine(config.DemoProfile)
	if err != nil {
		t.Fatalf("NewEngine(DemoProfile): %v", err)
	}

	_, encErr := eng.EncodeSegment(make([]byte, eng.DataShards*ShardSize-1))
	if encErr == nil {
		t.Error("EncodeSegment: expected error for wrong-length input, got nil")
	}
}

// ── ShardSize invariant assertion ─────────────────────────────────────────────

// TestShardSizeAssertion verifies at runtime that the ShardSize constant equals
// the ShardSize field in both NetworkProfiles. This is the runtime complement
// to TestProfileShardSizeIsConstant in the config package.
//
// Both tests together enforce DM §3 Invariant 7.
//
// [REF: DM §3 Invariant 7, ADR-031]
func TestShardSizeAssertion(t *testing.T) {
	if config.ProductionProfile.ShardSize != ShardSize {
		t.Errorf("ProductionProfile.ShardSize=%d != erasure.ShardSize=%d",
			config.ProductionProfile.ShardSize, ShardSize)
	}
	if config.DemoProfile.ShardSize != ShardSize {
		t.Errorf("DemoProfile.ShardSize=%d != erasure.ShardSize=%d",
			config.DemoProfile.ShardSize, ShardSize)
	}
}

// BenchmarkEncodeSegmentProd benchmarks EncodeSegment at production
// parameters (DataShards=16, TotalShards=56) — the parameter set this
// package moved from an assumed-fast SIMD library to a scalar Go
// implementation without anyone re-checking against NFR-adjacent latency
// budgets. Run with: go test -bench BenchmarkEncodeSegmentProd -run ^$
// [REF: M3 review §8.3]
func BenchmarkEncodeSegmentProd(b *testing.B) {
	eng, err := NewEngine(config.ProductionProfile)
	if err != nil {
		b.Fatalf("NewEngine(ProductionProfile): %v", err)
	}
	input := testAONTPackage(eng.DataShards)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.EncodeSegment(input); err != nil {
			b.Fatalf("EncodeSegment: %v", err)
		}
	}
}

// BenchmarkDecodeSegmentProd benchmarks DecodeSegment at production
// parameters, reconstructing half the data shards from the other half plus
// an equal count of parity shards each iteration — forces real matrix-
// inversion work, not the allDataPresent early-return.
// Run with: go test -bench BenchmarkDecodeSegmentProd -run ^$
// [REF: M3 review §8.3]
func BenchmarkDecodeSegmentProd(b *testing.B) {
	eng, err := NewEngine(config.ProductionProfile)
	if err != nil {
		b.Fatalf("NewEngine(ProductionProfile): %v", err)
	}
	input := testAONTPackage(eng.DataShards)
	allShards, err := eng.EncodeSegment(input)
	if err != nil {
		b.Fatalf("EncodeSegment: %v", err)
	}
	half := eng.DataShards / 2

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sparse := make([][]byte, eng.TotalShards)
		copy(sparse[:half], allShards[:half])
		copy(sparse[eng.DataShards:eng.DataShards+(eng.DataShards-half)],
			allShards[eng.DataShards:eng.DataShards+(eng.DataShards-half)])

		if _, err := eng.DecodeSegment(sparse); err != nil {
			b.Fatalf("DecodeSegment: %v", err)
		}
	}
}

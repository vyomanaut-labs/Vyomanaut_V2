/*
── Updated internal/config/profiles_test.go ─────────────────────────────────
Changed to package config_test (external test) so it can import
internal/erasure without creating an import cycle
(erasure → config, so config non-test → erasure would cycle;
config_test → erasure is the canonical way to break the cycle).
*/

package config_test

// Package config_test is the external test package for internal/config.
// Using an external test package (suffix _test) allows this file to import
// internal/erasure without creating an import cycle: erasure imports config,
// so config non-test code must not import erasure, but config_test may.
//
// [REF: MVP §8.4 check-14/15, DM §3 Invariant 7, ADR-003, ADR-031]

import (
	"reflect"
	"testing"
	"time"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	"github.com/masamasaowl/Vyomanaut_V2/internal/erasure"
)

// TestProfileShardSizeIsConstant asserts that both NetworkProfile instances
// encode ShardSize as 262144 bytes (256 KiB) — the canonical shard size
// required for vLog entry sizing, audit challenge framing, and RocksDB index
// assumptions. It also cross-checks the profile field against the
// erasure.ShardSize compile-time constant (DM §3 Invariant 7, ADR-031).
//
// [REF: MVP §8.4 check-14, DM §3 Invariant 7, ADR-003, ADR-031]
func TestProfileShardSizeIsConstant(t *testing.T) {
	const canonicalShardSize = 262144 // 2^18 = 256 KiB; equals erasure.ShardSize

	if config.ProductionProfile.ShardSize != canonicalShardSize {
		t.Errorf("ProductionProfile.ShardSize = %d; want %d",
			config.ProductionProfile.ShardSize, canonicalShardSize)
	}
	if config.DemoProfile.ShardSize != canonicalShardSize {
		t.Errorf("DemoProfile.ShardSize = %d; want %d",
			config.DemoProfile.ShardSize, canonicalShardSize)
	}

	// Cross-check: compile-time constant must equal runtime profile field.
	// [REF: DM §3 Invariant 7, ADR-031]
	if config.ProductionProfile.ShardSize != erasure.ShardSize {
		t.Errorf("ProductionProfile.ShardSize=%d != erasure.ShardSize=%d",
			config.ProductionProfile.ShardSize, erasure.ShardSize)
	}
	if config.DemoProfile.ShardSize != erasure.ShardSize {
		t.Errorf("DemoProfile.ShardSize=%d != erasure.ShardSize=%d",
			config.DemoProfile.ShardSize, erasure.ShardSize)
	}
}

// TestProfileBothFullySpecified uses reflection to verify that every field in
// ProductionProfile and DemoProfile is non-zero, except for the small
// allowlist of fields where zero is explicitly the correct value per MVP §5.2.
//
// This catches any new NetworkProfile field added without a corresponding
// value in one or both profiles — Go struct literal syntax enforces
// completeness at compile time (OR-03), but a forgotten field in a future
// edit would silently receive its zero value. This test is the runtime
// complement to that compile-time guard.
//
// [REF: MVP §8.4 check-15, MVP §6.3 OR-03, ADR-031]
func TestProfileBothFullySpecified(t *testing.T) {
	type profileCase struct {
		name    string
		profile config.NetworkProfile
		// allowedZeroFields maps field names to the reason zero is intentionally
		// correct. Each entry cites the governing spec reference so a future
		// developer understands the rationale before changing it.
		allowedZeroFields map[string]string
	}

	cases := []profileCase{
		{
			name:    "ProductionProfile",
			profile: config.ProductionProfile,
			allowedZeroFields: map[string]string{
				// ReleaseComputationInterval = 0 means calendar-driven: the
				// release computation fires on the 23rd of each calendar month,
				// not on a ticker. Callers branch on
				// `profile.ReleaseComputationInterval == 0`.
				// Zero is correct per MVP §5.2, ADR-024, ADR-031.
				"ReleaseComputationInterval": "zero is correct: calendar-driven release fires on the 23rd (ADR-024, ADR-031)",

				// ChargeComputationInterval = 0 means calendar-driven: the
				// charge/distribution engine fires on the 1st of each
				// calendar month, in arrears, not on a ticker. Callers
				// branch on `profile.ChargeComputationInterval == 0`,
				// mirroring ReleaseComputationInterval's own pattern.
				// Zero is correct per ADR-059.
				"ChargeComputationInterval": "zero is correct: calendar-driven charge fires on the 1st, in arrears (ADR-059)",

				// SkipMnemonicConfirm = false means production always demands
				// the two-word mnemonic confirmation step.
				// Zero (false) is correct per MVP §5.2, MVP §3.5.
				"SkipMnemonicConfirm": "zero is correct: production always requires mnemonic confirmation (MVP §3.5)",
			},
		},
		{
			name:    "DemoProfile",
			profile: config.DemoProfile,
			allowedZeroFields: map[string]string{
				// RazorpayCoolingPeriod = 0 means instant: demo uses the mock
				// payment provider, so no Razorpay cooling wait applies.
				// Zero is correct per MVP §3.4.
				"RazorpayCoolingPeriod": "zero is correct: instant cooling in demo, mock payment provider (MVP §3.4)",

				// MinRelayNodes = 0 because demo runs on a single LAN where
				// NAT traversal is not exercised.
				// Zero is correct per MVP §3.3.
				"MinRelayNodes": "zero is correct: demo runs on LAN, no relay nodes required (MVP §3.3)",

				// RequireSecretsManager = false: demo reads the cluster master
				// seed from an environment variable.
				// Zero (false) is correct per MVP §3.3, MVP §6.3 CR-01.
				"RequireSecretsManager": "zero is correct: env var replaces secrets manager in demo (MVP §3.3)",

				// RequireQuorum = false: demo runs a single microservice
				// replica with quorum checks disabled.
				// Zero (false) is correct per MVP §3.3.
				"RequireQuorum": "zero is correct: single-instance microservice in demo, no quorum (MVP §3.3)",

				// AllowLivePayments = false: demo must never reach the live
				// Razorpay endpoint. This is the field Guard 2
				// (DEMO_MODE_REAL_PAYMENT) checks instead of profile.Mode.
				// Zero is correct and load-bearing — see guards.go.
				"AllowLivePayments": "zero is correct: demo must never use live payments; checked directly by Guard 2 (guards.go)",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rv := reflect.ValueOf(tc.profile)
			rt := rv.Type()
			for i := 0; i < rt.NumField(); i++ {
				field := rt.Field(i)
				value := rv.Field(i)
				if _, allowed := tc.allowedZeroFields[field.Name]; allowed {
					continue
				}
				if value.IsZero() {
					t.Errorf(
						"field %s is zero-value in %s — either set it explicitly or add it "+
							"to the allowedZeroFields map with a spec reference explaining why zero is correct",
						field.Name, tc.name,
					)
				}
			}
		})
	}
}

// TestDemoDiffersFromProduction documents the exact boundary between
// mode-variable parameters (must differ) and wire-format invariants
// (must be identical).
//
// "Must differ" fields come from MVP §3.2–§3.5.
// "Must be identical" fields are declared never-mode-variable in MVP §5.1:
// ShardSize, ASNCapFraction, VettingCapFraction, DualWindowDrop.
//
// [REF: MVP §3.2–§3.5, MVP §5.1, ADR-031]
func TestDemoDiffersFromProduction(t *testing.T) {
	prod := config.ProductionProfile
	demo := config.DemoProfile

	// ── Fields that must be IDENTICAL (wire-format / protocol invariants) ─────
	// NOTE: MinDistinctASNs is also identical across profiles (5 in both), but
	// for a different reason — ASN-cap arithmetic, not wire format. It's
	// checked separately in TestMinDistinctASNsInvariant, not here.
	t.Run("invariant_fields_are_identical", func(t *testing.T) {
		if prod.ShardSize != demo.ShardSize {
			t.Errorf("ShardSize must be identical: prod=%d demo=%d", prod.ShardSize, demo.ShardSize)
		}
		if prod.ASNCapFraction != demo.ASNCapFraction {
			t.Errorf("ASNCapFraction must be identical: prod=%v demo=%v", prod.ASNCapFraction, demo.ASNCapFraction)
		}
		if prod.VettingCapFraction != demo.VettingCapFraction {
			t.Errorf("VettingCapFraction must be identical: prod=%v demo=%v", prod.VettingCapFraction, demo.VettingCapFraction)
		}
		if prod.DualWindowDrop != demo.DualWindowDrop {
			t.Errorf("DualWindowDrop must be identical: prod=%v demo=%v", prod.DualWindowDrop, demo.DualWindowDrop)
		}
	})

	// ── Erasure coding parameters must differ (MVP §3.2) ─────────────────────
	t.Run("erasure_params_differ", func(t *testing.T) {
		if prod.DataShards == demo.DataShards {
			t.Errorf("DataShards must differ: both=%d", prod.DataShards)
		}
		if prod.DataShards <= demo.DataShards {
			t.Errorf("ProductionProfile.DataShards (%d) must be > DemoProfile.DataShards (%d)",
				prod.DataShards, demo.DataShards)
		}
		if prod.ParityShards == demo.ParityShards {
			t.Errorf("ParityShards must differ: both=%d", prod.ParityShards)
		}
		if prod.ParityShards <= demo.ParityShards {
			t.Errorf("ProductionProfile.ParityShards (%d) must be > DemoProfile.ParityShards (%d)",
				prod.ParityShards, demo.ParityShards)
		}
		if prod.TotalShards == demo.TotalShards {
			t.Errorf("TotalShards must differ: both=%d", prod.TotalShards)
		}
		if prod.TotalShards <= demo.TotalShards {
			t.Errorf("ProductionProfile.TotalShards (%d) must be > DemoProfile.TotalShards (%d)",
				prod.TotalShards, demo.TotalShards)
		}
		if prod.LazyRepairR0 == demo.LazyRepairR0 {
			t.Errorf("LazyRepairR0 must differ: both=%d", prod.LazyRepairR0)
		}
	})

	// ── Readiness gate parameters must differ (MVP §3.3) ─────────────────────
	t.Run("readiness_gate_differs", func(t *testing.T) {
		if prod.MinActiveProviders == demo.MinActiveProviders {
			t.Errorf("MinActiveProviders must differ: both=%d", prod.MinActiveProviders)
		}
		if prod.MinActiveProviders <= demo.MinActiveProviders {
			t.Errorf("ProductionProfile.MinActiveProviders (%d) must be > DemoProfile.MinActiveProviders (%d)",
				prod.MinActiveProviders, demo.MinActiveProviders)
		}
		if prod.MinMetroRegions == demo.MinMetroRegions {
			t.Errorf("MinMetroRegions must differ: both=%d", prod.MinMetroRegions)
		}
		if prod.MinRelayNodes == demo.MinRelayNodes {
			t.Errorf("MinRelayNodes must differ: prod=%d demo=%d", prod.MinRelayNodes, demo.MinRelayNodes)
		}
		if prod.MinCooledAccounts == demo.MinCooledAccounts {
			t.Errorf("MinCooledAccounts must differ: both=%d", prod.MinCooledAccounts)
		}
	})

	// ── Time windows must differ (MVP §3.4) ───────────────────────────────────
	t.Run("time_windows_differ", func(t *testing.T) {
		timeFields := []struct {
			name string
			p, d time.Duration
		}{
			{"HeartbeatInterval", prod.HeartbeatInterval, demo.HeartbeatInterval},
			{"HeartbeatJitter", prod.HeartbeatJitter, demo.HeartbeatJitter},
			{"PollingInterval", prod.PollingInterval, demo.PollingInterval},
			{"DHTRepublishInterval", prod.DHTRepublishInterval, demo.DHTRepublishInterval},
			{"DHTExpiryDuration", prod.DHTExpiryDuration, demo.DHTExpiryDuration},
			{"DepartureThreshold", prod.DepartureThreshold, demo.DepartureThreshold},
			{"PromisedDowntimeMaximum", prod.PromisedDowntimeMaximum, demo.PromisedDowntimeMaximum},
			{"AuditPeriodDuration", prod.AuditPeriodDuration, demo.AuditPeriodDuration},
			{"EscrowHoldWindow", prod.EscrowHoldWindow, demo.EscrowHoldWindow},
			{"VettingHoldWindow", prod.VettingHoldWindow, demo.VettingHoldWindow},
			{"PendingReceiptGCAge", prod.PendingReceiptGCAge, demo.PendingReceiptGCAge},
			{"RepairPromotionTimeout", prod.RepairPromotionTimeout, demo.RepairPromotionTimeout},
			{"ScoreWindowShort", prod.ScoreWindowShort, demo.ScoreWindowShort},
			{"ScoreWindowMedium", prod.ScoreWindowMedium, demo.ScoreWindowMedium},
			{"ScoreWindowLong", prod.ScoreWindowLong, demo.ScoreWindowLong},
			{"VettingMinDuration", prod.VettingMinDuration, demo.VettingMinDuration},
			// RazorpayCoolingPeriod: production 24h, demo 0 (instant). Prod > demo.
			{"RazorpayCoolingPeriod", prod.RazorpayCoolingPeriod, demo.RazorpayCoolingPeriod},
		}
		for _, tf := range timeFields {
			if tf.p == tf.d {
				t.Errorf("%s must differ between profiles: both=%v", tf.name, tf.p)
			}
			if tf.p <= tf.d {
				t.Errorf("%s: ProductionProfile (%v) must be strictly greater than DemoProfile (%v)",
					tf.name, tf.p, tf.d)
			}
		}
	})

	// ── Vetting pass count must differ (MVP §3.4) ─────────────────────────────
	t.Run("vetting_passes_differ", func(t *testing.T) {
		if prod.VettingMinPasses == demo.VettingMinPasses {
			t.Errorf("VettingMinPasses must differ: both=%d", prod.VettingMinPasses)
		}
		if prod.VettingMinPasses <= demo.VettingMinPasses {
			t.Errorf("ProductionProfile.VettingMinPasses (%d) must be > DemoProfile.VettingMinPasses (%d)",
				prod.VettingMinPasses, demo.VettingMinPasses)
		}
	})

	// ── Cryptographic cost parameters must differ (MVP §3.5) ─────────────────
	t.Run("crypto_params_differ", func(t *testing.T) {
		if prod.Argon2Time == demo.Argon2Time {
			t.Errorf("Argon2Time must differ: both=%d", prod.Argon2Time)
		}
		if prod.Argon2Time <= demo.Argon2Time {
			t.Errorf("ProductionProfile.Argon2Time (%d) must be > DemoProfile.Argon2Time (%d)",
				prod.Argon2Time, demo.Argon2Time)
		}
		if prod.Argon2Memory == demo.Argon2Memory {
			t.Errorf("Argon2Memory must differ: both=%d KiB", prod.Argon2Memory)
		}
		if prod.Argon2Memory <= demo.Argon2Memory {
			t.Errorf("ProductionProfile.Argon2Memory (%d KiB) must be > DemoProfile.Argon2Memory (%d KiB)",
				prod.Argon2Memory, demo.Argon2Memory)
		}
		if prod.Argon2Threads == demo.Argon2Threads {
			t.Errorf("Argon2Threads must differ: both=%d", prod.Argon2Threads)
		}
		if prod.Argon2Threads <= demo.Argon2Threads {
			t.Errorf("ProductionProfile.Argon2Threads (%d) must be > DemoProfile.Argon2Threads (%d)",
				prod.Argon2Threads, demo.Argon2Threads)
		}
	})

	// ── Infrastructure flags must differ ──────────────────────────────────────
	t.Run("infrastructure_differs", func(t *testing.T) {
		if prod.RequireSecretsManager == demo.RequireSecretsManager {
			t.Errorf("RequireSecretsManager must differ: both=%v", prod.RequireSecretsManager)
		}
		if prod.RequireQuorum == demo.RequireQuorum {
			t.Errorf("RequireQuorum must differ: both=%v", prod.RequireQuorum)
		}
		if prod.AllowLivePayments == demo.AllowLivePayments {
			t.Errorf("AllowLivePayments must differ: both=%v", prod.AllowLivePayments)
		}
		if prod.PaymentMode == demo.PaymentMode {
			t.Errorf("PaymentMode must differ: both=%q", prod.PaymentMode)
		}
		if prod.SkipMnemonicConfirm == demo.SkipMnemonicConfirm {
			t.Errorf("SkipMnemonicConfirm must differ: both=%v", prod.SkipMnemonicConfirm)
		}
		if prod.ReleaseComputationInterval == demo.ReleaseComputationInterval {
			t.Errorf("ReleaseComputationInterval must differ: both=%v", prod.ReleaseComputationInterval)
		}
		if prod.Mode == demo.Mode {
			t.Errorf("Mode must differ: both=%q", prod.Mode)
		}
		if prod.GCRetryBackoff[0] == demo.GCRetryBackoff[0] {
			t.Errorf("GCRetryBackoff[0] must differ: both=%v", prod.GCRetryBackoff[0])
		}
		if prod.GCRetryBackoff[0] <= demo.GCRetryBackoff[0] {
			t.Errorf("ProductionProfile.GCRetryBackoff[0] (%v) must be > DemoProfile.GCRetryBackoff[0] (%v)",
				prod.GCRetryBackoff[0], demo.GCRetryBackoff[0])
		}
	})
}

// TestMinDistinctASNsInvariant documents and verifies that MinDistinctASNs is
// identical (5) in both profiles — not because it is a wire-format constant
// like ShardSize, but because of ASN-cap arithmetic: floor(TotalShards ×
// ASNCapFraction) = floor(5 × 0.20) = 1 shard/ASN in demo, which requires
// exactly 5 distinct ASNs to place DemoProfile's 5 shards at all. Setting
// DemoProfile.MinDistinctASNs below 5 would make the ASN cap mathematically
// unsatisfiable in demo mode — this is the exact bug the pre-ADR analysis
// contained (it proposed MinDistinctASNs=2) before mvp.md §7.1 corrected it.
//
// [REF: mvp.md §7.1 "CORRECTED: ASN Cap vs MinDistinctASNs", requirements.md §5.10]
func TestMinDistinctASNsInvariant(t *testing.T) {
	const wantMinDistinctASNs = 5

	if config.ProductionProfile.MinDistinctASNs != wantMinDistinctASNs {
		t.Errorf("ProductionProfile.MinDistinctASNs = %d, want %d",
			config.ProductionProfile.MinDistinctASNs, wantMinDistinctASNs)
	}
	if config.DemoProfile.MinDistinctASNs != wantMinDistinctASNs {
		t.Errorf("DemoProfile.MinDistinctASNs = %d, want %d — floor(TotalShards×ASNCapFraction)=1 "+
			"shard/ASN requires exactly 5 distinct ASNs to place 5 shards (mvp.md §7.1)",
			config.DemoProfile.MinDistinctASNs, wantMinDistinctASNs)
	}
	if config.ProductionProfile.MinDistinctASNs != config.DemoProfile.MinDistinctASNs {
		t.Errorf("MinDistinctASNs must be equal across profiles (arithmetic coincidence, "+
			"not a wire-format invariant): prod=%d demo=%d",
			config.ProductionProfile.MinDistinctASNs, config.DemoProfile.MinDistinctASNs)
	}
}
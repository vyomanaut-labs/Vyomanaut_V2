// Package config is declared in doc.go.
// This file defines the two canonical NetworkProfile instances.
// 1. ProductionProfile (PROD)
// 2. DemoProfile (DEMO)
//
// INVARIANT (OR-03): Every field of NetworkProfile must appear explicitly in both struct literals below. Go's named-field literal syntax makes an omission visible at code review; a missing field silently receives its zero value which may be catastrophically wrong for production (e.g. a zero AuditPeriodDuration or a zero MinActiveProviders).
//
// [REF: MVP §5.2, MVP §6.3 OR-02, OR-03]

package config

import "time"

// ProductionProfile is the canonical NetworkProfile for live deployments.
// Passed to every subsystem constructor; never read globally.
//
// [REF: MVP §5.2]
var ProductionProfile = NetworkProfile{
	Mode: "prod",

	// ── Storage pricing (build.md Milestone 11) ───────────────────────────────
	// Identical to DemoProfile — pricing is profile-invariant (see
	// network_profile.go's own note on this field).
	StorageRatePaisePerGBPerMonth: 100,

	// ── Erasure coding (ADR-003) ──────────────────────────────────────────────
	DataShards:   16,
	ParityShards: 40,
	TotalShards:  56,
	ShardSize:    262144, // must equal DemoProfile.ShardSize; compiler-checked in M3 Session 3.1.1
	LazyRepairR0: 8,

	// ── Readiness gate (ADR-029) ──────────────────────────────────────────────
	MinActiveProviders: 56,
	MinDistinctASNs:    5,
	MinMetroRegions:    3,
	MinRelayNodes:      3,
	MinCooledAccounts:  56,

	// ── ASN cap (ADR-014) ─────────────────────────────────────────────────────
	// floor(56 * 0.20) = 11 shards per ASN in production.
	ASNCapFraction: 0.20,

	// ── Time windows ─────────────────────────────────────────────────────────
	HeartbeatInterval:       4 * time.Hour,
	HeartbeatJitter:         5 * time.Minute,
	PollingInterval:         24 * time.Hour,
	DHTRepublishInterval:    12 * time.Hour,
	DHTExpiryDuration:       24 * time.Hour,
	DepartureThreshold:      72 * time.Hour,
	PromisedDowntimeMaximum: 72 * time.Hour,
	AuditPeriodDuration:     30 * 24 * time.Hour,
	EscrowHoldWindow:        30 * 24 * time.Hour,
	VettingHoldWindow:       60 * 24 * time.Hour,
	PendingReceiptGCAge:     48 * time.Hour,
	RepairPromotionTimeout:  6 * time.Hour,

	// ── Scoring windows (ADR-008) ─────────────────────────────────────────────
	ScoreWindowShort:  24 * time.Hour,
	ScoreWindowMedium: 7 * 24 * time.Hour,
	ScoreWindowLong:   30 * 24 * time.Hour,
	DualWindowDrop:    0.20, // always 0.20; never mode-variable

	// ── Vetting (ADR-005) ─────────────────────────────────────────────────────
	VettingMinPasses:   80,
	VettingMinDuration: 120 * 24 * time.Hour,
	VettingCapFraction: 0.10, // always 0.10; never mode-variable

	// ── Cryptographic cost (ADR-020) ──────────────────────────────────────────
	Argon2Time:    3,
	Argon2Memory:  65536, // 64 MiB in KiB
	Argon2Threads: 4,

	// ── Infrastructure ────────────────────────────────────────────────────────
	RequireSecretsManager: true,
	RequireQuorum:         true,
	AllowLivePayments:     true,
	PaymentMode:           "razorpay_live",
	SkipMnemonicConfirm:   false,
	RazorpayCoolingPeriod: 24 * time.Hour,

	// ── Release computation cycle ─────────────────────────────────────────────
	// 0 = calendar-driven (23rd of each month). [REF: ADR-024, ADR-031]
	ReleaseComputationInterval: 0,

	// ── Charge computation cycle ──────────────────────────────────────────────
	// 0 = calendar-driven (1st of each month, in arrears). [REF: ADR-061]
	ChargeComputationInterval: 0,

	// ── GC retry backoff (IC §4.5) ────────────────────────────────────────────
	GCRetryBackoff: [3]time.Duration{
		5 * time.Minute,
		15 * time.Minute,
		60 * time.Minute,
	},
}

// DemoProfile is the canonical NetworkProfile for local demo and CI runs.
// Shrinks time windows to minutes so a full upload→audit→repair cycle
// completes in under 30 minutes on a laptop.
//
// ShardSize is IDENTICAL to ProductionProfile (see the ShardSize field below);
// this is the only wire-format field present in the profile. All other fields
// are mode-variable.
//
// [REF: MVP §5.2]
var DemoProfile = NetworkProfile{
	Mode: "demo",

	// ── Storage pricing (build.md Milestone 11) ───────────────────────────────
	// Identical to ProductionProfile — pricing is profile-invariant (see
	// network_profile.go's own note on this field).
	StorageRatePaisePerGBPerMonth: 100,

	// ── Erasure coding (ADR-003) ──────────────────────────────────────────────
	DataShards:   3,
	ParityShards: 2,
	TotalShards:  5,
	ShardSize:    262144, // IDENTICAL to ProductionProfile; wire-format invariant
	LazyRepairR0: 1,

	// ── Readiness gate (ADR-029) ──────────────────────────────────────────────
	MinActiveProviders: 5,
	MinDistinctASNs:    5, // 5 synthetic ASNs (SIM-AS1…SIM-AS5) satisfy this [REF: MVP §7.1]
	MinMetroRegions:    1,
	MinRelayNodes:      0,
	MinCooledAccounts:  5,

	// ── ASN cap (ADR-014) ─────────────────────────────────────────────────────
	// floor(5 * 0.20) = 1 shard per ASN; 5 synthetic ASNs satisfy this.
	ASNCapFraction: 0.20,

	// ── Time windows ─────────────────────────────────────────────────────────
	HeartbeatInterval:       30 * time.Second,
	HeartbeatJitter:         5 * time.Second,
	PollingInterval:         2 * time.Minute,
	DHTRepublishInterval:    2 * time.Minute,
	DHTExpiryDuration:       4 * time.Minute,
	DepartureThreshold:      10 * time.Minute,
	PromisedDowntimeMaximum: 10 * time.Minute,
	AuditPeriodDuration:     2 * time.Minute,
	EscrowHoldWindow:        1 * time.Minute,
	VettingHoldWindow:       2 * time.Minute,
	PendingReceiptGCAge:     5 * time.Minute,
	RepairPromotionTimeout:  3 * time.Minute,

	// ── Scoring windows (ADR-008) ─────────────────────────────────────────────
	ScoreWindowShort:  2 * time.Minute,
	ScoreWindowMedium: 6 * time.Minute,
	ScoreWindowLong:   20 * time.Minute,
	DualWindowDrop:    0.20, // always 0.20; never mode-variable

	// ── Vetting (ADR-005) ─────────────────────────────────────────────────────
	VettingMinPasses:   5,
	VettingMinDuration: 5 * time.Minute,
	VettingCapFraction: 0.10, // always 0.10; never mode-variable

	// ── Cryptographic cost (ADR-020) ──────────────────────────────────────────
	// Reduced parameters: fast Argon2id for demo/CI speed.
	Argon2Time:    1,
	Argon2Memory:  4096, // 4 MiB in KiB
	Argon2Threads: 1,

	// ── Infrastructure ────────────────────────────────────────────────────────
	RequireSecretsManager: false,
	RequireQuorum:         false,
	AllowLivePayments:     false,
	PaymentMode:           "mock",
	SkipMnemonicConfirm:   true,
	RazorpayCoolingPeriod: 0,

	// ── Release computation cycle ─────────────────────────────────────────────
	// Non-zero = ticker-driven (every 2 minutes). [REF: ADR-024, ADR-031]
	ReleaseComputationInterval: 2 * time.Minute,

	// ── Charge computation cycle ──────────────────────────────────────────────
	// Non-zero = ticker-driven (every 90 seconds — deliberately different from
	// ReleaseComputationInterval's 2 minutes so the two loops' log output and
	// idempotency-key collisions, if any, are distinguishable during demo
	// testing). [REF: ADR-061]
	ChargeComputationInterval: 90 * time.Second,

	// ── Authenticated mutation-protocol freshness (ADR-036) ──────────────────
	AuthRequestFreshnessWindow: 120 * time.Second,

	// ── GC retry backoff (IC §4.5) ────────────────────────────────────────────
	GCRetryBackoff: [3]time.Duration{
		10 * time.Second,
		30 * time.Second,
		2 * time.Minute,
	},
}

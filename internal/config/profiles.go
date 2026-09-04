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

	// [M11 audit remediation, Finding 7] See network_profile.go's IsDemoMode
	// doc comment — this is the typed field business logic should branch
	// on, never Mode's string value.
	IsDemoMode: false,

	// ── Storage pricing (build.md Milestone 11) ───────────────────────────────
	// [Changed, M18 Session 18.2] No longer identical to DemoProfile — see
	// DemoProfile's own comment on this field for why, and
	// network_profile.go's updated field comment for the invariant this no
	// longer falls under. This value (₹1/GB/month) remains the real
	// placeholder pending actual product pricing; DemoProfile's value is a
	// presentation-only demo figure, never meant to inform this one.
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
	HeartbeatInterval: 4 * time.Hour,
	HeartbeatJitter:   5 * time.Minute,
	PollingInterval:   24 * time.Hour,
	// 1h gives 72 samples across the 72h DepartureThreshold — prompt enough
	// detection without hammering the DB. [REF: M9 review Optional Fix B]
	DeparturePollingInterval: 1 * time.Hour,
	DHTRepublishInterval:     12 * time.Hour,
	DHTExpiryDuration:        24 * time.Hour,
	DepartureThreshold:       72 * time.Hour,
	PromisedDowntimeMaximum:  72 * time.Hour,
	AuditPeriodDuration:      30 * 24 * time.Hour,
	EscrowHoldWindow:         30 * 24 * time.Hour,
	VettingHoldWindow:        60 * 24 * time.Hour,
	PendingReceiptGCAge:      48 * time.Hour,
	RepairPromotionTimeout:   6 * time.Hour,

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

	// ── Authenticated mutation-protocol freshness (ADR-036) ──────────────────
	AuthRequestFreshnessWindow: 120 * time.Second,

	// ── GC retry backoff (IC §4.5) ────────────────────────────────────────────
	GCRetryBackoff: [3]time.Duration{
		5 * time.Minute,
		15 * time.Minute,
		60 * time.Minute,
	},

	// ── Background materialized-view refresh cycle ───────────────────────────
	// 60s matches build_part2.md's own "≤60s stale" figure for the owner-
	// balance endpoint read. [REF: M17 CLI debugging session]
	BackgroundViewRefreshInterval: 60 * time.Second,
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

	// [M11 audit remediation, Finding 7] See network_profile.go's IsDemoMode
	// doc comment — this is the typed field business logic should branch
	// on, never Mode's string value.
	IsDemoMode: true,

	// ── Storage pricing (build.md Milestone 11) ───────────────────────────────
	// [Changed, M18 Session 18.2 — demo-freeze pass, Karma's own direction]
	// 100000 paise (₹1000) per GB per month, NOT ProductionProfile's ₹1 —
	// this field is deliberately no longer profile-invariant (see
	// network_profile.go's updated field comment). A real charge cycle
	// (payment.RunChargeComputationLoop, wired into cmd/microservice/main.go
	// Step 23 this same session) now actually runs against whatever files
	// are ACTIVE during a demo, and at ₹1/GB/month the live 117544938-byte
	// demo video costs 11 paise a month split across up to 8 holders —
	// correct, but a payout table of ₹0.01/₹0.02 rows does not read as
	// money to a live audience. At ₹1000/GB/month the same file costs
	// ₹109.47/month, which splits into legible per-provider rupee amounts
	// in `operator payout` and `provider earnings` — see
	// internal/payment/charge_test.go for the split-by-largest-remainder
	// guarantee that makes the split exact regardless of rate. This number
	// is a demo-legibility choice, not a pricing decision: it says nothing
	// about what ProductionProfile's real rate should be once one exists,
	// which is why it does not touch ProductionProfile's own value above.
	StorageRatePaisePerGBPerMonth: 100000,

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
	HeartbeatInterval: 30 * time.Second,
	HeartbeatJitter:   5 * time.Second,
	PollingInterval:   2 * time.Minute,
	// 30s gives 20 samples across the 10-minute DepartureThreshold — fast
	// enough for demo/CI cycles. [REF: M9 review Optional Fix B]
	DeparturePollingInterval: 30 * time.Second,
	DHTRepublishInterval:     2 * time.Minute,
	DHTExpiryDuration:        4 * time.Minute,
	DepartureThreshold:       10 * time.Minute,
	PromisedDowntimeMaximum:  10 * time.Minute,
	AuditPeriodDuration:      2 * time.Minute,
	EscrowHoldWindow:         1 * time.Minute,
	VettingHoldWindow:        2 * time.Minute,
	PendingReceiptGCAge:      5 * time.Minute,
	RepairPromotionTimeout:   3 * time.Minute,

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
	// 120s in demo too — ADR-036 specifies the same value for both profiles
	// (generous enough for clock skew + relay latency regardless of mode).
	AuthRequestFreshnessWindow: 120 * time.Second,

	// ── GC retry backoff (IC §4.5) ────────────────────────────────────────────
	GCRetryBackoff: [3]time.Duration{
		10 * time.Second,
		30 * time.Second,
		2 * time.Minute,
	},

	// ── Background materialized-view refresh cycle ───────────────────────────
	// 5s — fast enough that TestDemoCLIFullLifecycle's deposit (at t=0) is
	// reflected in mv_owner_escrow_balance well before its balance assertion
	// runs several minutes later (upload+retrieve dominate the wall-clock
	// time between them), without refreshing so often that three
	// REFRESH MATERIALIZED VIEW CONCURRENTLY statements meaningfully compete
	// with foreground demo-scale traffic. [REF: M17 CLI debugging session]
	BackgroundViewRefreshInterval: 5 * time.Second,
}

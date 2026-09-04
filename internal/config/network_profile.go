// Package config is declared in doc.go.
// This file defines the NetworkProfile struct — the single authoritative container for all parameters that differ between DEMO and PROD mode.
//
// [REF: MVP §5.1].
// [REF: ADR-001, ADR-003, ADR-004, ADR-005, ADR-006, ADR-007, ADR-008,ADR-014, ADR-015, ADR-016, ADR-020, ADR-024, ADR-028, ADR-029, ADR-031].

package config

import "time"

// NetworkProfile is the single authoritative container for all parameters that
// differ between DEMO and PROD mode.
//
// It is constructed once at startup (see select.go) and passed via dependency injection to every subsystem. No subsystem may read VYOMANAUT_MODE directly; all mode-variable behaviour must be derived from the fields of this struct.
//
// INVARIANT: Every field that affects wire format, cryptographic output, or database schema (ShardSize, challenge nonce length, amount_paise type) must be identical in both profiles. Only performance thresholds, time windows, and infrastructure scale parameters are mode-variable.
//
// [REF: MVP §5.1]
// [REF: MVP §6.3 OR-03 — struct literal syntax enforces both profiles are complete]
type NetworkProfile struct {

	// ── Erasure coding ────────────────────────────────────────────────────────
	// [REF: ADR-003]
	DataShards   int // s — data shard count
	ParityShards int // r — parity shard count
	TotalShards  int // n = s + r — total shard count
	// ShardSize is present in the struct solely for Go compiler completeness
	// enforcement via struct literal syntax (MVP §6.3 OR-03). Its value MUST
	// equal the canonical shard byte length (2^18 = 262,144) in both profiles.
	// The cross-package assertion against the erasure package constant is
	// deferred to M3 Session 3.1.1. [REF: ADR-003, INV-7]
	ShardSize    int
	LazyRepairR0 int // r0 — minimum shards required before lazy repair triggers

	// ── Readiness gate ────────────────────────────────────────────────────────
	// Minimum conditions that must be satisfied before the assignment service
	// accepts upload requests.
	// [REF: ADR-029]
	MinActiveProviders int
	MinDistinctASNs    int
	MinMetroRegions    int
	MinRelayNodes      int
	MinCooledAccounts  int

	// ── ASN cap ───────────────────────────────────────────────────────────────
	// MaxShardsPerASN = floor(TotalShards * ASNCapFraction).
	// Production: floor(56 * 0.20) = 11 shards per ASN.
	// Demo:       floor(5  * 0.20) = 1 shard per ASN (5 synthetic ASNs satisfy).
	// [REF: ADR-014]
	ASNCapFraction float64

	// ── Time windows ──────────────────────────────────────────────────────────
	HeartbeatInterval time.Duration // provider → microservice liveness signal interval [REF: ADR-028]
	HeartbeatJitter   time.Duration // random jitter added to each heartbeat interval   [REF: ADR-028]
	PollingInterval   time.Duration // audit-scheduler polling cadence                  [REF: ADR-006]
	// DeparturePollingInterval is how often the departure detector
	// (internal/repair.DepartureDetector.Run) scans for silently-departed
	// providers. A dedicated field, not a reuse of PollingInterval — see
	// [Added, M9 review Optional Fix B] on DepartureDetector.Run for why
	// reusing the audit-scheduler's own cadence was flagged as an inference
	// with a self-acknowledged mismatched detection-latency-to-threshold
	// ratio (production PollingInterval:DepartureThreshold was 24h:72h =
	// 1:3; demo was 2min:10min = 1:5 — the same field meant two different
	// things at two different scales). No ADR or FR gives a concrete
	// figure for this cadence either; the values chosen here keep a
	// comparable samples-before-threshold count across both profiles
	// (~72 prod, ~20 demo) rather than reusing an unrelated cadence.
	DeparturePollingInterval time.Duration
	DHTRepublishInterval     time.Duration // DHT key republication interval                   [REF: ADR-001]
	DHTExpiryDuration        time.Duration // DHT record TTL                                   [REF: ADR-001]
	DepartureThreshold       time.Duration // silence duration before a provider is DEPARTED   [REF: ADR-006, ADR-007]

	// PromisedDowntimeMaximum is the maximum duration a provider may declare as
	// planned maintenance before the network treats the absence as a departure.
	// [REF: ADR-007]
	PromisedDowntimeMaximum time.Duration

	AuditPeriodDuration    time.Duration // length of a single audit billing period          [REF: ADR-016]
	EscrowHoldWindow       time.Duration // lookback window used by the release computation  [REF: ADR-024]
	VettingHoldWindow      time.Duration // minimum time funds are held during vetting        [REF: ADR-024]
	PendingReceiptGCAge    time.Duration // age at which un-responded challenges are GC'd     [REF: ADR-015]
	RepairPromotionTimeout time.Duration // PRE_WARNING jobs older than this become PERMANENT [REF: ADR-004, FR-043]

	// ── Scoring windows ───────────────────────────────────────────────────────
	// The three windows used to compute the provider reliability score.
	// DualWindowDrop is always 0.20 (20%) regardless of mode.
	// [REF: ADR-008]
	ScoreWindowShort  time.Duration
	ScoreWindowMedium time.Duration
	ScoreWindowLong   time.Duration
	DualWindowDrop    float64 // always 0.20; never mode-variable

	// ── Vetting ───────────────────────────────────────────────────────────────
	// VettingCapFraction is always 0.10 (10% of declared_storage_gb) regardless
	// of mode.
	// [REF: ADR-005]
	VettingMinPasses   int
	VettingMinDuration time.Duration
	VettingCapFraction float64 // always 0.10; never mode-variable

	// ── Cryptographic cost ────────────────────────────────────────────────────
	// Argon2id parameters passed to the crypto package's DeriveMasterSecret.
	// [REF: ADR-020]
	Argon2Time    uint32
	Argon2Memory  uint32 // in KiB
	Argon2Threads uint8

	// ── Infrastructure ────────────────────────────────────────────────────────
	RequireSecretsManager bool   // if false, read VYOMANAUT_CLUSTER_MASTER_SEED env var
	RequireQuorum         bool   // if false, gossip cluster allows N=1 with quorum disabled
	AllowLivePayments     bool   // gates Guard 2 (DEMO_MODE_REAL_PAYMENT); true only for ProductionProfile today
	PaymentMode           string // "razorpay_live" | "razorpay_test" | "mock"
	SkipMnemonicConfirm   bool   // if true, client skips two-word mnemonic confirmation step
	RazorpayCoolingPeriod time.Duration

	// [M11 audit remediation, Finding 7 (CR-01)] IsDemoMode is the typed
	// field Mode's own doc comment below says to use instead of runtime
	// string branching. Mirrors RequireQuorum/AllowLivePayments exactly:
	// true only in DemoProfile, false only in ProductionProfile, both
	// explicit per OR-03's invariant that every field appear in both struct
	// literals. Four call sites in provider.go and readiness.go previously
	// branched on `profile.Mode != "demo"` directly — there was no
	// purpose-built bool field for "is this demo mode" in general before
	// this one, which is presumably why they reached for Mode.
	IsDemoMode bool

	// ── Release computation cycle ─────────────────────────────────────────────
	// 0 means calendar-driven (production: computed on the 23rd of each month).
	// Non-zero means ticker-driven (demo: computed every ReleaseComputationInterval).
	// Callers branch on `profile.ReleaseComputationInterval == 0`.
	// [REF: ADR-024, ADR-031]
	ReleaseComputationInterval time.Duration

	// ── Charge computation cycle ──────────────────────────────────────────────
	// 0 means calendar-driven (production: computed on the 1st of each month,
	// in arrears for the month just elapsed). Non-zero means ticker-driven
	// (demo: computed every ChargeComputationInterval). Callers branch on
	// `profile.ChargeComputationInterval == 0`, mirroring
	// ReleaseComputationInterval exactly — a deliberately separate field, not
	// a shared one, so charge and release cadences can be tuned independently
	// (ADR-061: the charge job has no audit-period-closed precondition to
	// wait for, unlike release, so nothing requires them to share a cadence).
	// [REF: ADR-061]
	ChargeComputationInterval time.Duration

	// ── Authenticated mutation-protocol freshness ────────────────────────────
	// AuthRequestFreshnessWindow bounds the age of a signed request_ts_ms on
	// the two provider-mutation protocols with irreversible/exfiltrating side
	// effects: /vyomanaut/repair-download/1.0.0 (returns raw shard bytes) and
	// /vyomanaut/vetting-gc/1.0.0 (permanently deletes chunks). A request
	// older than this window is rejected even with a structurally valid
	// signature. [REF: ADR-036]
	AuthRequestFreshnessWindow time.Duration

	// ── GC retry backoff ─────────────────────────────────────────────────────
	// Fixed 3-step back-off schedule for vetting GC delivery retries. An array,
	// not a slice: both canonical profiles always declare exactly 3 steps, and
	// arrays copy by value — this removes the last reference-type field from
	// NetworkProfile, so a plain struct copy (profile := DemoProfile) can never
	// alias the package-level profile's backing storage.
	// Access via profile.GCRetryBackoff[attempt] (bounds-checked by caller).
	// [REF: IC §4.5]
	GCRetryBackoff [3]time.Duration

	// ── Mode identifier ───────────────────────────────────────────────────────
	// Printed in full at startup (MVP §6.3 OR-01). MUST NOT be used for
	// runtime branching inside business logic — use the typed fields above.
	Mode string // "demo" | "prod"

	// ── Background materialized-view refresh cycle ───────────────────────────
	// mv_owner_escrow_balance, mv_provider_escrow_balance, and
	// mv_segment_shard_counts (DM §7) are materialized views, not live
	// queries — every write path that changes their underlying tables
	// (InsertOwnerEscrowEvent, InsertEscrowEvent, chunk_assignments status
	// UPDATEs) appends/updates the source rows but never refreshes the view
	// itself. Each view's own DM §7 comment documents an intended refresh
	// trigger ("≤60s stale" for the two escrow views per build_part2.md's
	// owner-balance TASK text; "after each chunk_assignment status change"
	// for the shard-count view) but no session ever assigned a file to
	// implement it. This is background_loops.go's own header comment's
	// "view refresh" — one of the three categories of background work
	// NFR-028 names (alongside repair queuing and Merkle log compaction,
	// both already wired). One ticker-driven cadence for all three views,
	// the same shape as ReleaseComputationInterval/ChargeComputationInterval
	// above, rather than refreshing inline inside every writer (which would
	// serialize unrelated callers against REFRESH MATERIALIZED VIEW
	// CONCURRENTLY's own lock and couple internal/payment and internal/repair
	// to a schedule neither has any other reason to know about).
	// [Added, M17 CLI debugging session — no ADR/FR gives a concrete figure]
	BackgroundViewRefreshInterval time.Duration

	// ── Storage pricing ────────────────────────────────────────────────────────
	// [Added, build.md Milestone 11 Phase 11.5/11.8] FR-057 and FileListItem's
	// monthly_cost_paise both need a concrete storage rate, but ADR-024 only
	// describes it as "a product decision, set at contract creation" — no ADR
	// or FR anywhere in scope gives an actual figure. 100 paise (₹1) per GB
	// per month remains ProductionProfile's placeholder, pending real product
	// pricing — flagged here rather than left unimplemented.
	//
	// [Changed, M18 Session 18.2 — demo-freeze pass] NO LONGER
	// profile-invariant. DemoProfile deliberately diverges from
	// ProductionProfile here — see DemoProfile's own field comment
	// (profiles.go) for the reasoning — which supersedes this struct's own
	// general INVARIANT note above for this one field. Every other field
	// that note covers (ShardSize, ASNCapFraction, VettingCapFraction,
	// DualWindowDrop) is still a genuine wire-format/protocol invariant and
	// remains identical across both profiles; pricing was never a wire
	// format, so nothing else in this codebase assumes the two profiles'
	// rates match (payment.ComputeMonthlyCharges reads whichever profile it
	// is passed; nothing reads both and compares them).
	StorageRatePaisePerGBPerMonth int64
}

// Package payment is declared in doc.go.
// This file implements the charge/distribution engine (M10 corrections
// review Finding #1, Phase 10.6; ADR-059): computes each ACTIVE file's
// monthly storage cost, debits the owner via a CHARGE event, and credits
// that file's current shard-holding providers via DEPOSIT events, split
// evenly by shard count held. ADR-059's flat per-shard model was chosen
// over audit-pass weighting after two design-council sessions — weighting
// was considered and explicitly deferred, not overlooked (see ADR-059
// Consequences / Open constraints for what would need to be true before
// revisiting that).
//
// [Engineering Review] ComputeMonthlyCharges does not take a PaymentProvider
// parameter, unlike ComputeMonthlyRelease: charging and distributing are
// pure internal-ledger bookkeeping (InsertOwnerEscrowEvent /
// InsertEscrowEvent only) — no external gateway call happens here, since
// the owner's actual money already moved into escrow earlier via
// InitiateEscrow/HandleDepositCaptured. Likewise no primaryDB parameter:
// ComputeMonthlyRelease needs one because scoring.GetScoreFromPrimary reads
// a freshness-critical value (DM §7); this engine never reads
// mv_provider_scores at all under the flat model.
//
// [REF: ADR-059, DM §4.3-4.9, build.md Phase 10.6]

package payment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
)

// bytesPerGB matches internal/api's identical constant. Duplicated here
// rather than imported — internal/payment cannot import internal/api
// (IC §9) — and internal/payment must never use float64/float32 anywhere
// (IC §11), so the cost formula below is reimplemented with pure integer
// arithmetic rather than reusing internal/api's float64-based
// fileMonthlyCostPaiseForBytes directly.
const bytesPerGB = 1024 * 1024 * 1024

// roundingHalfBytes is bytesPerGB/2, the round-half-up offset for
// fileMonthlyCostPaise's integer division — named so the arithmetic below
// reads as "round half up," not a bare magic number (IC §11: no magic
// numbers).
const roundingHalfBytes = bytesPerGB / 2

// fileMonthlyCostPaise computes the monthly storage cost for sizeBytes at
// profile.StorageRatePaisePerGBPerMonth, using round-half-up integer
// division: floor((sizeBytes*rate + bytesPerGB/2) / bytesPerGB) — the
// integer equivalent of internal/api's float64-based
// fileMonthlyCostPaiseForBytes (int64(gb*rate + 0.5)), acceptable there
// only because that call site produces a user-facing estimate, never a
// value actually debited.
//
// sizeBytes*rate cannot overflow int64 for any realistic file size: even
// at 1 PB (10^15 bytes) and a 3-figure paise rate, the product is ~10^17,
// three orders of magnitude below int64's ~9.2*10^18 ceiling.
func fileMonthlyCostPaise(sizeBytes int64, profile config.NetworkProfile) int64 {
	return (sizeBytes*profile.StorageRatePaisePerGBPerMonth + roundingHalfBytes) / bytesPerGB
}

// ChargeIdempotencyKey computes SHA-256(ownerID || fileID || billingPeriod)
// as 64 lowercase hex characters — the CHARGE-side key, exactly as
// owner_escrow_events' own migration comment specifies (DM §4.9).
// billingPeriod is a "YYYY-MM" string (time.Format("2006-01")), matching
// shouldRunRelease's existing convention (release.go). Exported so any
// future caller needing to look up or reconcile a specific charge event —
// mirroring why ReleaseIdempotencyKey (Finding #8) is exported — derives
// the identical key this engine uses.
func ChargeIdempotencyKey(ownerID, fileID uuid.UUID, billingPeriod string) string {
	h := sha256.New()
	h.Write(ownerID[:])
	h.Write(fileID[:])
	h.Write([]byte(billingPeriod))
	return hex.EncodeToString(h.Sum(nil))
}

// chargeDepositIdempotencyKey computes SHA-256(providerID || fileID ||
// billingPeriod) as 64 lowercase hex characters — the DEPOSIT-side key for
// this engine's distribution step (ADR-059 Decision §3). Named distinctly
// from razorpay.go's depositIdempotencyKey(ownerID, paymentID) — that one
// keys an owner's Razorpay-webhook-driven deposit; this one keys a
// provider's charge-engine-driven credit. Different event, different
// inputs, deliberately different name. One row per provider per file per
// billing period, so a partially-failed run (owner charged, only some
// providers credited) is safely retryable — the exact property the M10
// audit review required of this key.
func chargeDepositIdempotencyKey(providerID, fileID uuid.UUID, billingPeriod string) string {
	h := sha256.New()
	h.Write(providerID[:])
	h.Write(fileID[:])
	h.Write([]byte(billingPeriod))
	return hex.EncodeToString(h.Sum(nil))
}

// chargeableFile is one row from the ACTIVE-files scan.
type chargeableFile struct {
	fileID            uuid.UUID
	ownerID           uuid.UUID
	originalSizeBytes int64
}

// chargeableFiles returns every currently-ACTIVE file (files.status =
// 'ACTIVE' — DM §4.3: "ACTIVE: all chunk assignments live; owner is
// billed"). DELETED files are excluded — per the same schema comment, an
// owner is not billed after deletion.
func chargeableFiles(ctx context.Context, db *sql.DB) ([]chargeableFile, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT file_id, owner_id, original_size_bytes
		FROM files
		WHERE status = 'ACTIVE'`)
	if err != nil {
		return nil, fmt.Errorf("query files: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []chargeableFile
	for rows.Next() {
		var f chargeableFile
		if err := rows.Scan(&f.fileID, &f.ownerID, &f.originalSizeBytes); err != nil {
			return nil, fmt.Errorf("scan file: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate files: %w", err)
	}
	return out, nil
}

// shardHolderCounts returns, for fileID, each currently-ACTIVE shard
// holder's provider_id and how many of that file's ACTIVE chunk_assignments
// they hold — across ALL of the file's segments, not just one (DM §4.4: a
// file larger than 14 MB has multiple independent segments, each with its
// own TotalShards chunk_assignments; a provider may hold shards in more
// than one). Only status = 'ACTIVE' counts, matching the
// active_chunk_assignments view already granted to vyomanaut_app (DM
// §4.5) — a REPAIRING assignment belongs to a holder already on its way
// out and is not credited further here (ADR-059 Decision §5).
func shardHolderCounts(ctx context.Context, db *sql.DB, fileID uuid.UUID) (map[uuid.UUID]int64, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ca.provider_id, COUNT(*)
		FROM chunk_assignments ca
		JOIN segments s ON s.segment_id = ca.segment_id
		WHERE s.file_id = $1
		  AND ca.status = 'ACTIVE'
		  AND ca.is_vetting_chunk = FALSE
		GROUP BY ca.provider_id`,
		fileID)
	if err != nil {
		return nil, fmt.Errorf("query shard holders: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[uuid.UUID]int64)
	for rows.Next() {
		var providerID uuid.UUID
		var count int64
		if err := rows.Scan(&providerID, &count); err != nil {
			return nil, fmt.Errorf("scan shard holder: %w", err)
		}
		out[providerID] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate shard holders: %w", err)
	}
	return out, nil
}

// splitByLargestRemainder divides totalPaise among the providers in counts
// (provider_id -> shard count held), proportional to each provider's share
// of the total shard count, guaranteeing the returned amounts sum to
// EXACTLY totalPaise (ADR-059 Decision §3) — never short, never over,
// never silently dropping a leftover paise. Returns nil if counts is
// empty (nothing to split among).
//
// Algorithm (largest-remainder method): each provider's base share is
// floor(totalPaise * theirShards / totalShards); the leftover
// (totalPaise - sum(baseShares)) paise are handed out one each, in
// provider_id ascending order for determinism across retries (ADR-059 Open
// constraints — this ordering must never change without a migration
// note), breaking ties among equal fractional remainders reproducibly.
func splitByLargestRemainder(totalPaise int64, counts map[uuid.UUID]int64) map[uuid.UUID]int64 {
	var totalShards int64
	providerIDs := make([]uuid.UUID, 0, len(counts))
	for id, c := range counts {
		totalShards += c
		providerIDs = append(providerIDs, id)
	}
	if totalShards == 0 {
		return nil
	}
	sort.Slice(providerIDs, func(i, j int) bool {
		return providerIDs[i].String() < providerIDs[j].String()
	})

	type remainder struct {
		providerID uuid.UUID
		frac       int64 // remainder numerator, out of totalShards
	}
	shares := make(map[uuid.UUID]int64, len(providerIDs))
	remainders := make([]remainder, 0, len(providerIDs))
	var distributed int64
	for _, id := range providerIDs {
		c := counts[id]
		base := (totalPaise * c) / totalShards
		shares[id] = base
		distributed += base
		remainders = append(remainders, remainder{providerID: id, frac: (totalPaise * c) % totalShards})
	}

	leftover := totalPaise - distributed
	// Stable sort descending by fractional remainder; ties keep provider_id
	// ascending order (the slice's incoming order) since sort.SliceStable
	// preserves relative order among equal elements.
	sort.SliceStable(remainders, func(i, j int) bool {
		return remainders[i].frac > remainders[j].frac
	})
	for i := int64(0); i < leftover; i++ {
		shares[remainders[i].providerID]++
	}
	return shares
}

// computeChargeForFile charges f's owner and distributes the exact same
// amount across f's current shard holders, for billingPeriod.
//
// Retry-safe by construction: if the owner-charge insert reports
// ErrDuplicateIdempotencyKey (this file+period was already charged on a
// prior run), execution still falls through to the distribution step
// rather than returning early — otherwise a run that charged the owner but
// failed partway through crediting providers could never be completed by a
// retry, defeating the exact retry-safety property the per-provider
// DEPOSIT idempotency key exists to provide.
func computeChargeForFile(ctx context.Context, db *sql.DB, profile config.NetworkProfile, f chargeableFile, billingPeriod string) error {
	counts, err := shardHolderCounts(ctx, db, f.fileID)
	if err != nil {
		return fmt.Errorf("shard holders: %w", err)
	}
	if len(counts) == 0 {
		// No currently-ACTIVE shard holder for this file (e.g. mid-repair,
		// or not yet assigned) — do not charge the owner for a period with
		// no one to credit. The next cycle picks this file back up once it
		// has active holders again.
		return nil
	}

	cost := fileMonthlyCostPaise(f.originalSizeBytes, profile)
	if cost <= 0 {
		return nil // a zero-byte or misconfigured-rate charge is a no-op, never an error
	}

	chargeKey := ChargeIdempotencyKey(f.ownerID, f.fileID, billingPeriod)
	if err := InsertOwnerEscrowEvent(ctx, db, f.ownerID, OwnerCharge, cost, chargeKey, &f.fileID); err != nil {
		if !errors.Is(err, ErrDuplicateIdempotencyKey) {
			return fmt.Errorf("charge owner: %w", err)
		}
		// Already charged for this file+period on a prior run — fall
		// through and still attempt distribution (see doc comment above).
	}

	shares := splitByLargestRemainder(cost, counts)
	var errs []error
	for providerID, amount := range shares {
		if amount <= 0 {
			continue
		}
		depositKey := chargeDepositIdempotencyKey(providerID, f.fileID, billingPeriod)
		if err := InsertEscrowEvent(ctx, db, providerID, EscrowDeposit, amount, depositKey, nil); err != nil {
			if errors.Is(err, ErrDuplicateIdempotencyKey) {
				continue // already credited — idempotent skip
			}
			errs = append(errs, fmt.Errorf("credit provider %s: %w", providerID, err))
		}
	}
	return errors.Join(errs...)
}

// ComputeMonthlyCharges runs the charge/distribution engine for every
// currently-ACTIVE file, for billingPeriod (a "YYYY-MM" string). Every
// file is processed independently: one file's failure does not abort the
// batch; all errors are joined and returned together — the same
// discipline ComputeMonthlyRelease already uses (release.go).
func ComputeMonthlyCharges(ctx context.Context, db *sql.DB, profile config.NetworkProfile, billingPeriod string) error {
	files, err := chargeableFiles(ctx, db)
	if err != nil {
		return fmt.Errorf("payment.ComputeMonthlyCharges: %w", err)
	}

	var errs []error
	for _, f := range files {
		if err := computeChargeForFile(ctx, db, profile, f, billingPeriod); err != nil {
			errs = append(errs, fmt.Errorf("file %s: %w", f.fileID, err))
		}
	}
	return errors.Join(errs...)
}

// ── Scheduling loop (ADR-059 Decision §4) ─────────────────────────────────

// chargeComputationDayOfMonth is the calendar day ADR-059 fixes charge
// computation to in production — the 1st of each month, charging in
// arrears for the month that just elapsed. Deliberately different from
// releaseComputationDayOfMonth (23rd, release.go) so the two
// calendar-driven loops never collide.
const chargeComputationDayOfMonth = 1

// chargeCalendarPollInterval mirrors calendarPollInterval (release.go) —
// an implementation detail, not a documented requirement.
const chargeCalendarPollInterval = 1 * time.Hour

// RunChargeComputationLoop drives ComputeMonthlyCharges on the cadence
// ADR-059 describes: a ticker firing every profile.ChargeComputationInterval
// in demo mode, or a once-a-month check for the 1st of the calendar month
// in production (profile.ChargeComputationInterval == 0 signals
// calendar-driven, mirroring RunReleaseComputationLoop exactly — MVP §5.4's
// same ticker-vs-calendar branch pattern, applied to a second scheduler).
// Blocks until ctx is cancelled.
//
// Unlike release, the charge job has no audit-period-closed precondition
// to wait for (ADR-059's whole point, Council Round 2 Q1) — it runs
// against "now" on a fixed calendar cadence.
func RunChargeComputationLoop(ctx context.Context, db *sql.DB, profile config.NetworkProfile) {
	if profile.ChargeComputationInterval == 0 {
		runChargeOnCalendarDate(ctx, db, profile)
		return
	}
	if profile.ChargeComputationInterval > 0 {
		runChargeOnTicker(ctx, db, profile)
	}
}

func runChargeOnTicker(ctx context.Context, db *sql.DB, profile config.NetworkProfile) {
	ticker := time.NewTicker(profile.ChargeComputationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Demo mode charges against the current month on every tick,
			// relying on this package's own idempotency keys — not a
			// lastRun tracker — to make repeated ticks safe, mirroring
			// runReleaseOnTicker's identical reliance (release.go).
			_ = ComputeMonthlyCharges(ctx, db, profile, time.Now().UTC().Format("2006-01"))
		}
	}
}

func runChargeOnCalendarDate(ctx context.Context, db *sql.DB, profile config.NetworkProfile) {
	ticker := time.NewTicker(chargeCalendarPollInterval)
	defer ticker.Stop()
	lastRun := "" // billing period ("YYYY-MM") last successfully charged; see shouldRunCharge
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if run, billingPeriod := shouldRunCharge(time.Now(), lastRun); run {
				_ = ComputeMonthlyCharges(ctx, db, profile, billingPeriod)
				lastRun = billingPeriod
			}
		}
	}
}

// shouldRunCharge reports whether now is a day runChargeOnCalendarDate
// should fire ComputeMonthlyCharges, and if so, which billing period (the
// month that just elapsed — charging is in arrears) to charge for, given
// lastRun (the billing period the previous firing charged, or "" if it has
// never fired).
//
// Identical in shape to shouldRunRelease (release.go, M10 corrections
// review Finding #6) for the exact same reason that fix exists: a bare
// int(now.Month()) comparison would silently skip a month once this
// process has run continuously past its first anniversary. This charge
// scheduler reuses that fix from day one — Aryan's explicit direction
// (ADR-059) — rather than reintroducing the bug class Finding #6 closed in
// a second scheduler.
func shouldRunCharge(now time.Time, lastRun string) (run bool, billingPeriod string) {
	if now.Day() != chargeComputationDayOfMonth {
		return false, lastRun
	}
	billingPeriod = now.AddDate(0, -1, 0).Format("2006-01") // arrears: the month that just elapsed
	if billingPeriod == lastRun {
		return false, lastRun
	}
	return true, billingPeriod
}
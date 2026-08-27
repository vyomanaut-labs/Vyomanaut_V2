// Package payment is declared in doc.go.
// This file implements the monthly release computation (FR-048, FR-049,
// FR-050) and its scheduling loop (MVP §5.4's ticker-vs-calendar branch).
//
// [Flagged, build.md Phase 10.4 Session 10.4.1] The originally-scoped
// signature — func ComputeMonthlyRelease(ctx, db, primaryDB, profile) error
// — has no way to actually call ReleaseEscrow, despite its own doc comment
// saying "4. Call ReleaseEscrow(...)": ReleaseEscrow is a PaymentProvider
// method, and no PaymentProvider value reaches this function anywhere in
// that signature. Fixed below by adding a provider PaymentProvider
// parameter — the same category of fix as internal/repair's
// IncrementConsecutivePasses needing a profile parameter (Milestone 9) or
// its DepartureDetector needing a PenaliseFunc injection point.
//
// [Decision] Every comparison against Score30d/Score7d in this file goes
// through scoring.ProviderScore's Score30dBasisPoints()/Score7dBasisPoints()
// accessors, never the underlying fields directly — see provider.go's
// header comment and internal/scoring/score.go's own documentation of why
// those accessors exist. This file's own multiplier arithmetic is,
// consequently, ordinary integer arithmetic throughout.
//
// [REF: FR-048, FR-049, FR-050, DM §7, MVP §5.4, build.md Phase 10.4
// Session 10.4.1]

package payment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/scoring"
)

// scoreStalenessLimit is DM §7's own CRITICAL threshold: "scores_as_of must
// be within 60 minutes before this view is used for release multiplier
// computation... Stale scores produce wrong payments."
const scoreStalenessLimit = 60 * time.Minute

// Release multiplier tiers, expressed in basis points (10000 = 1.00),
// FR-049. basisPointsDivisor converts a basis-points multiplier back to a
// plain integer paise amount: releasePaise = balancePaise * multiplierBP /
// basisPointsDivisor — ordinary integer division, never anything else.
const (
	basisPointsDivisor = 10000

	multiplierFullBP         = 10000 // score >= 0.95
	multiplierPartialHiBP    = 7500  // score >= 0.80
	multiplierPartialLoBP    = 5000  // score >= 0.65
	multiplierNoneBP         = 0     // score < 0.65
	tierFullThresholdBP      = 9500
	tierPartialHiThresholdBP = 8000
	tierPartialLoThresholdBP = 6500
)

// releaseMultiplierBasisPoints maps a basis-points score (from
// scoring.ProviderScore.Score30dBasisPoints() or .Score7dBasisPoints()) to
// the FR-049 release multiplier, also in basis points.
func releaseMultiplierBasisPoints(scoreBP int64) int64 {
	switch {
	case scoreBP >= tierFullThresholdBP:
		return multiplierFullBP
	case scoreBP >= tierPartialHiThresholdBP:
		return multiplierPartialHiBP
	case scoreBP >= tierPartialLoThresholdBP:
		return multiplierPartialLoBP
	default:
		return multiplierNoneBP
	}
}

// ComputeMonthlyRelease runs the release computation for every provider with
// release_computed = FALSE in the current audit period (FR-048).
//
//  1. Fetch the score via scoring.GetScoreFromPrimary — NOT scoring.GetScore.
//     Payment decisions require the freshest available data (DM §7 CRITICAL
//     note); a replica-routed read could be stale enough to misapply the
//     multiplier. If score.ScoresAsOf is more than 60 minutes old, skip this
//     provider for the current cycle and retry next tick rather than pay out
//     against stale data.
//  2. Compute the release multiplier from Score30dBasisPoints() (FR-049):
//     >= 9500bp -> 10000bp; 8000-9499bp -> 7500bp; 6500-7999bp -> 5000bp;
//     < 6500bp -> 0bp (hold in full; rolls to next month, FR-049).
//  3. If score.DualWindowFlag is true (FR-050: Score30d - Score7d > 0.20),
//     use the lower of the multiplier computed from Score30dBasisPoints()
//     and the multiplier Score7dBasisPoints() would produce under the same
//     table.
//  4. Call ReleaseEscrow(ctx, providerID, releaseAmountPaise, auditPeriodID,
//     idempotencyKey) where idempotencyKey = SHA-256(providerID ||
//     auditPeriodID).
//  5. Set audit_periods.release_computed = TRUE.
//
// Amounts held for more than 90 rolling days without release must be
// flagged for operations-team review, not auto-seized (FR-049) — that
// review workflow has no function signature anywhere in scope for this
// milestone and is not fabricated here; only release_computed is set.
//
// Every provider is processed independently: one provider's failure does
// not abort the batch; all errors are joined and returned together.
func ComputeMonthlyRelease(ctx context.Context, db *sql.DB, primaryDB *sql.DB, profile config.NetworkProfile, provider PaymentProvider) error {
	candidates, err := pendingReleaseCandidates(ctx, db)
	if err != nil {
		return fmt.Errorf("payment.ComputeMonthlyRelease: %w", err)
	}

	var errs []error
	for _, c := range candidates {
		if err := computeReleaseForProvider(ctx, db, primaryDB, provider, c.providerID, c.auditPeriodID); err != nil {
			errs = append(errs, fmt.Errorf("provider %s / audit period %s: %w", c.providerID, c.auditPeriodID, err))
		}
	}
	return errors.Join(errs...)
}

type pendingRelease struct {
	auditPeriodID uuid.UUID
	providerID    uuid.UUID
}

func pendingReleaseCandidates(ctx context.Context, db *sql.DB) ([]pendingRelease, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, provider_id FROM audit_periods WHERE release_computed = FALSE`)
	if err != nil {
		return nil, fmt.Errorf("query pending audit periods: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []pendingRelease
	for rows.Next() {
		var p pendingRelease
		if err := rows.Scan(&p.auditPeriodID, &p.providerID); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// isScoreStale reports whether scoresAsOf is more than scoreStalenessLimit
// old (DM §7's CRITICAL note). Factored out from computeReleaseForProvider
// as its own function specifically so the exact 60-minute boundary is
// directly unit-testable: mv_provider_scores.scores_as_of is tied to
// genuine wall-clock NOW() at the view's last refresh (Milestone 8, DM §7)
// and cannot be faked via seed data, so a true end-to-end integration test
// of "a 61-minute-old score gets skipped" would require actually waiting 61
// real minutes — this function is the practical, fast alternative.
func isScoreStale(scoresAsOf time.Time) bool {
	return time.Since(scoresAsOf) > scoreStalenessLimit
}

func computeReleaseForProvider(ctx context.Context, db, primaryDB *sql.DB, provider PaymentProvider, providerID, auditPeriodID uuid.UUID) error {
	score, err := scoring.GetScoreFromPrimary(ctx, primaryDB, providerID)
	if err != nil {
		return fmt.Errorf("get score: %w", err)
	}

	if isScoreStale(score.ScoresAsOf) {
		// Skip this cycle entirely; retry next tick rather than release
		// against data DM §7 no longer considers fresh enough for a payment
		// decision. release_computed is deliberately NOT set here, so the
		// next cycle reconsiders this same audit period.
		return nil
	}

	multiplierBP := releaseMultiplierBasisPoints(score.Score30dBasisPoints())
	if score.DualWindowFlag {
		if m7 := releaseMultiplierBasisPoints(score.Score7dBasisPoints()); m7 < multiplierBP {
			multiplierBP = m7
		}
	}

	balancePaise, err := providerBalance(ctx, db, providerID)
	if err != nil {
		return fmt.Errorf("get balance: %w", err)
	}
	releaseAmountPaise := balancePaise * multiplierBP / basisPointsDivisor

	if releaseAmountPaise > 0 {
		idempotencyKey := ReleaseIdempotencyKey(providerID, auditPeriodID)
		if err := provider.ReleaseEscrow(ctx, providerID, releaseAmountPaise, auditPeriodID, idempotencyKey); err != nil {
			return fmt.Errorf("release escrow: %w", err)
		}
	}

	if err := markReleaseComputed(ctx, db, auditPeriodID); err != nil {
		return fmt.Errorf("mark release_computed: %w", err)
	}
	return nil
}

// ProviderReleasePreview is one candidate provider's contribution to a
// PreviewMonthlyRelease result — computed by the identical
// score-multiplier/balance path computeReleaseForProvider itself uses, but
// never calling ReleaseEscrow or markReleaseComputed.
//
// RemainderBP is the sub-paise fraction (out of basisPointsDivisor) that
// integer division truncates from BalancePaise*MultiplierBP when computing
// ReleasePaise — genuinely worth less than one paise, and never itself
// separately tracked as money anywhere in the ledger, but shown explicitly
// per Session 17.6.3's own task text ("the remainder must be shown, not
// silently dropped"). The reconciling identity this value satisfies,
// always, by construction, is:
//
//	BalancePaise*MultiplierBP == ReleasePaise*basisPointsDivisor + RemainderBP
//
// ScoreStale mirrors isScoreStale's own 60-minute freshness check (DM §7).
// computeReleaseForProvider skips a stale-score provider entirely before
// any real money moves; this preview does the opposite — it still computes
// and shows the figure, flagged, because nothing here writes anything a
// stale score could corrupt. Silently omitting a provider from a preview
// table is the same "silently dropped" failure mode Session 17.6.3's task
// text warns against, just at the row level instead of the paise level.
type ProviderReleasePreview struct {
	ProviderID     uuid.UUID
	BalancePaise   int64
	MultiplierBP   int64
	ReleasePaise   int64
	RemainderBP    int64
	ScoreStale     bool
}

// PreviewMonthlyRelease is the read-only counterpart to ComputeMonthlyRelease,
// added for M17-E's `operator payout` admin endpoint (ADR-084 Design Council
// Addendum A — see internal/api/admin.go's AdminPayoutPreviewHandler for the
// full framing of why a read-only preview, not a mutating trigger, is the
// only safe way to show this on cmd/operator, which has no database
// connection of its own, I-DEMO-1).
//
// It walks the identical pendingReleaseCandidates -> score lookup ->
// releaseMultiplierBasisPoints -> providerBalance path
// computeReleaseForProvider itself uses, so the number displayed on the
// operator console can never drift from the real release algorithm — but it
// calls neither ReleaseEscrow nor markReleaseComputed, so it cannot race the
// real ticker-driven engine (RunReleaseComputationLoop): it writes nothing
// for that engine to race against.
//
// [Flagged, deliberate] uses scoring.GetScore (replica-tolerant), not
// scoring.GetScoreFromPrimary — DM §7's CRITICAL freshness note governs
// actual payment decisions, and internal/api's RouterConfig carries only one
// *sql.DB (cfg.DB), with no primary-only connection threaded through this
// package at all. A stale-score preview number is surfaced via ScoreStale
// below, never hidden; no money moves off this path regardless, so a
// replica-routed read cannot misapply a real payment the way DM §7 warns
// against for the mutating path.
//
// Every candidate is evaluated independently: one candidate's lookup
// failure does not abort the batch; all errors are joined and returned
// together, matching ComputeMonthlyRelease's own discipline.
func PreviewMonthlyRelease(ctx context.Context, db *sql.DB) ([]ProviderReleasePreview, error) {
	candidates, err := pendingReleaseCandidates(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("payment.PreviewMonthlyRelease: %w", err)
	}

	var out []ProviderReleasePreview
	var errs []error
	for _, c := range candidates {
		score, err := scoring.GetScore(ctx, db, c.providerID)
		if err != nil {
			errs = append(errs, fmt.Errorf("provider %s: get score: %w", c.providerID, err))
			continue
		}

		multiplierBP := releaseMultiplierBasisPoints(score.Score30dBasisPoints())
		if score.DualWindowFlag {
			if m7 := releaseMultiplierBasisPoints(score.Score7dBasisPoints()); m7 < multiplierBP {
				multiplierBP = m7
			}
		}

		balancePaise, err := providerBalance(ctx, db, c.providerID)
		if err != nil {
			errs = append(errs, fmt.Errorf("provider %s: get balance: %w", c.providerID, err))
			continue
		}

		numerator := balancePaise * multiplierBP
		releasePaise := numerator / basisPointsDivisor
		remainderBP := numerator - releasePaise*basisPointsDivisor

		out = append(out, ProviderReleasePreview{
			ProviderID:   c.providerID,
			BalancePaise: balancePaise,
			MultiplierBP: multiplierBP,
			ReleasePaise: releasePaise,
			RemainderBP:  remainderBP,
			ScoreStale:   isScoreStale(score.ScoresAsOf),
		})
	}
	return out, errors.Join(errs...)
}

func markReleaseComputed(ctx context.Context, db *sql.DB, auditPeriodID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `UPDATE audit_periods SET release_computed = TRUE WHERE id = $1`, auditPeriodID)
	if err != nil {
		return fmt.Errorf("update audit_periods: %w", err)
	}
	return nil
}

// MarkReleaseComputed sets audit_periods.release_computed = TRUE for
// auditPeriodID, so this exact period is never re-selected by
// pendingReleaseCandidates' WHERE release_computed = FALSE filter. Exported
// so internal/api's departure handler (HandleDepart) can call the same
// function ComputeMonthlyRelease itself uses, rather than growing a second,
// possibly-drifting implementation of the same one-line UPDATE.
//
// [Added, M10 corrections review Finding #8] HandleDepart previously never
// set this at all, so a departed provider's still-open audit period was
// queried, scored, and silently discarded by ComputeMonthlyRelease on every
// future cycle, forever.
func MarkReleaseComputed(ctx context.Context, db *sql.DB, auditPeriodID uuid.UUID) error {
	return markReleaseComputed(ctx, db, auditPeriodID)
}

// ReleaseIdempotencyKey computes SHA-256(providerID || auditPeriodID) as 64
// lowercase hex characters (ADR-012, FR-047). Exported so every code path
// that releases escrow against a given (providerID, auditPeriodID) pair —
// currently ComputeMonthlyRelease and internal/api's HandleDepart — derives
// the SAME idempotency key for the SAME logical event.
//
// [Fixed, M10 corrections review Finding #8] internal/api/provider.go's
// HandleDepart previously minted its own, differently-derived key
// (announcedDepartureIdempotencyKey) for a release against the same audit
// period ComputeMonthlyRelease could also select — defeating the
// escrow_events.idempotency_key UNIQUE constraint's "one release per
// provider per audit period" guarantee this key format exists to enforce.
// Both paths now call this one function.
func ReleaseIdempotencyKey(providerID, auditPeriodID uuid.UUID) string {
	h := sha256.New()
	h.Write(providerID[:])
	h.Write(auditPeriodID[:])
	return hex.EncodeToString(h.Sum(nil))
}

// ── Scheduling loop (MVP §5.4) ──────────────────────────────────────────────────

// releaseComputationDayOfMonth is the calendar day FR-048 fixes release
// computation to in production.
const releaseComputationDayOfMonth = 23

// calendarPollInterval is how often RunReleaseComputationLoop checks
// whether today is the 23rd, in production (calendar-driven) mode — an
// implementation detail, not a documented requirement.
const calendarPollInterval = 1 * time.Hour

// RunReleaseComputationLoop drives ComputeMonthlyRelease on the cadence
// MVP §5.4 describes: a ticker firing every
// profile.ReleaseComputationInterval in demo mode, or a once-a-month check
// for the 23rd of the calendar month in production
// (profile.ReleaseComputationInterval == 0 signals calendar-driven — MVP
// §5.4: "Branch on profile.ReleaseComputationInterval == 0"). Blocks until
// ctx is cancelled.
func RunReleaseComputationLoop(ctx context.Context, db, primaryDB *sql.DB, profile config.NetworkProfile, provider PaymentProvider) {
	if profile.ReleaseComputationInterval == 0 {
		runReleaseOnCalendarDate(ctx, db, primaryDB, profile, provider)
		return
	}
	if profile.ReleaseComputationInterval > 0 {
		runReleaseOnTicker(ctx, db, primaryDB, profile, provider)
	}
}

func runReleaseOnTicker(ctx context.Context, db, primaryDB *sql.DB, profile config.NetworkProfile, provider PaymentProvider) {
	ticker := time.NewTicker(profile.ReleaseComputationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = ComputeMonthlyRelease(ctx, db, primaryDB, profile, provider) // best-effort background loop
		}
	}
}

func runReleaseOnCalendarDate(ctx context.Context, db, primaryDB *sql.DB, profile config.NetworkProfile, provider PaymentProvider) {
	ticker := time.NewTicker(calendarPollInterval)
	defer ticker.Stop()
	lastRun := "" // year-month key of the last successful run; see shouldRunRelease
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if run, newLastRun := shouldRunRelease(time.Now(), lastRun); run {
				_ = ComputeMonthlyRelease(ctx, db, primaryDB, profile, provider)
				lastRun = newLastRun
			}
		}
	}
}

// shouldRunRelease reports whether now is a day runReleaseOnCalendarDate
// should fire ComputeMonthlyRelease, given lastRun (the year-month key
// returned by the previous call that fired, or "" if it has never fired).
// Extracted into its own pure function so the exact month-rollover
// comparison can be unit-tested without waiting a real year for the bug to
// reproduce.
//
// [Fixed, M10 corrections review Finding #6] runReleaseOnCalendarDate
// previously compared only int(now.Month()) (range 1-12) against the
// month of its last run. A process that runs continuously past its first
// anniversary — the expected steady state for this persistent,
// long-running loop, not an edge case — would compare e.g. January 2027
// against a lastRunMonth of 1 left over from January 2026, see 1 == 1, and
// silently skip that entire month's release computation. now.Format is
// monotonic across year boundaries (and, as a side benefit, lexicographically
// sortable) where a bare month number is not.
func shouldRunRelease(now time.Time, lastRun string) (run bool, newLastRun string) {
	if now.Day() != releaseComputationDayOfMonth {
		return false, lastRun
	}
	current := now.Format("2006-01")
	if current == lastRun {
		return false, lastRun
	}
	return true, current
}

// Package repair is declared in doc.go.
// This file implements SelectReplacementProvider — Power of Two Choices
// weighted by reliability score, with 20% ASN cap enforcement, for choosing
// a replacement provider during repair.
//
// [Decision, build.md Phase 9.4] Phase 9.4's own precondition text proposed
// importing internal/scoring for a read-only GetScore lookup, reasoning that
// "a read-only score lookup mirrors how internal/audit and internal/scoring
// already independently query shared tables" — and explicitly named a
// fallback if that reasoning didn't hold: query mv_provider_scores directly.
// It doesn't hold: the Milestone 9 header's own quotation of IC §9's closing
// paragraph is unconditional — "the microservice entrypoint wires
// internal/audit, internal/scoring, internal/repair, and internal/payment
// together; none of these four packages imports any of the others directly"
// — with no read-only carve-out. This file therefore takes the named
// fallback: it queries mv_provider_scores (score_composite) directly via SQL,
// never importing internal/scoring. Confirmed against the user (see chat):
// "use the fallback."
//
// [REF: IC §9, FR-045, ADR-005, ADR-014, ADR-008, build.md Phase 9.4 Session 9.4.1]

package repair

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// maxReplacementSelectionAttempts bounds SelectReplacementProvider's retry
// loop (see its own doc comment) so a network with almost no ASN diversity
// left cannot spin forever.
const maxReplacementSelectionAttempts = 5

// DBTX is satisfied by both *sql.DB and *sql.Tx. SelectReplacementProvider
// and its helpers below are read-only against `providers`,
// `mv_provider_scores`, and `chunk_assignments`, and are called both
// standalone (repair executor, a bare *sql.DB) and now from inside a
// caller's transaction (internal/api's upload/assign, Session 11.7.1 — see
// that package's upload.go header for why: the segment/chunk_assignments
// writes surrounding this candidate selection must all commit or roll back
// together, so the selection reads need to run against the same *sql.Tx).
//
// [M11 audit remediation, Finding 2] Added to accept *sql.Tx without
// widening these functions to accept a full transaction-management
// interface they have no business calling BeginTx/Commit/Rollback on.
type DBTX interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// SelectReplacementProvider chooses a new provider to receive the
// reconstructed shard for segmentID, excluding excludeProviderIDs (the
// departed/failed holder(s) and every other current holder of this
// segment's shards, so the same provider is never assigned two shards of one
// segment). Uses Power of Two Choices (ADR-005): draw two ACTIVE candidates
// at random from the vetted pool, pick the higher-scored one. Per DM
// §8.2/§8.3 (ADR-024, FR-025), "ACTIVE" here also requires a confirmed
// Razorpay Linked Account and an elapsed cooling period — see
// drawTwoActiveCandidates.
//
// The chosen candidate must not push any single ASN's share of this
// segment's TotalShards above floor(TotalShards * profile.ASNCapFraction)
// (FR-045, ADR-014) — the same 20% cap enforced at original assignment time.
// If the higher-scored candidate would violate the cap, fall back to the
// second candidate; if both would violate it, draw again (bounded retries,
// maxReplacementSelectionAttempts) before returning
// ErrNoEligibleReplacement.
//
// Score comparison queries mv_provider_scores.score_composite directly via
// SQL rather than calling internal/scoring.GetScore — see this file's own
// header comment for why. A candidate with no row yet in mv_provider_scores
// (no audit history) is treated as score 0, the lowest possible value, so it
// always loses Power of Two Choices against a scored peer rather than
// causing an error.
//
// Goroutine-safe: yes.
func SelectReplacementProvider(
	ctx context.Context,
	db DBTX,
	profile config.NetworkProfile,
	segmentID uuid.UUID,
	excludeProviderIDs []uuid.UUID,
) (uuid.UUID, error) {
	excluded := make(map[uuid.UUID]bool, len(excludeProviderIDs))
	for _, id := range excludeProviderIDs {
		excluded[id] = true
	}

	maxPerASN := int(math.Floor(float64(profile.TotalShards) * profile.ASNCapFraction))

	for attempt := 0; attempt < maxReplacementSelectionAttempts; attempt++ {
		candidates, err := drawTwoActiveCandidates(ctx, db, excluded)
		if err != nil {
			return uuid.UUID{}, fmt.Errorf("repair.SelectReplacementProvider: draw candidates: %w", err)
		}
		if len(candidates) == 0 {
			return uuid.UUID{}, ErrNoEligibleReplacement
		}

		ordered, err := orderCandidatesByScoreDesc(ctx, db, candidates)
		if err != nil {
			return uuid.UUID{}, fmt.Errorf("repair.SelectReplacementProvider: score candidates: %w", err)
		}

		for _, c := range ordered {
			ok, err := asnWithinCap(ctx, db, segmentID, c.asn, maxPerASN)
			if err != nil {
				return uuid.UUID{}, fmt.Errorf("repair.SelectReplacementProvider: ASN cap check: %w", err)
			}
			if ok {
				return c.providerID, nil
			}
			// This candidate loses on ASN cap; never draw it again this call.
			excluded[c.providerID] = true
		}
	}
	return uuid.UUID{}, ErrNoEligibleReplacement
}

// replacementCandidate is an ACTIVE provider drawn as a Power-of-Two-Choices candidate.
type replacementCandidate struct {
	providerID uuid.UUID
	asn        string
}

// drawTwoActiveCandidates draws up to two random ACTIVE providers not in
// excluded. May return fewer than two (or zero) if the eligible pool is
// smaller than that.
func drawTwoActiveCandidates(ctx context.Context, db DBTX, excluded map[uuid.UUID]bool) ([]replacementCandidate, error) {
	excludeStrs := make([]string, 0, len(excluded))
	for id := range excluded {
		excludeStrs = append(excludeStrs, id.String())
	}

	// [M11 audit remediation, Finding 5] razorpay_linked_account_id IS NOT
	// NULL AND razorpay_cooling_until < NOW() added per DM §8.2/§8.3
	// ("Chunk assignments are blocked until [razorpay_linked_account_id] is
	// non-null and the cooling period has elapsed", ADR-024, FR-025).
	// Previously this query filtered on status = 'ACTIVE' alone, so a
	// provider that reached ACTIVE via scoring.IncrementConsecutivePasses
	// (audit-pass and vetting-duration criteria only) became eligible for
	// real shard assignment even with no confirmed Razorpay Linked Account
	// or still inside its cooling window — exactly the condition this DM
	// invariant exists to prevent. Deliberately NOT duplicated into
	// scoring.IncrementConsecutivePasses's VETTING->ACTIVE transition: DM
	// scopes this invariant to "chunk assignments" specifically, not to the
	// ACTIVE status transition itself, and conflating the two would freeze
	// a well-vetted provider's consecutive_audit_passes tracking on an
	// unrelated payment-readiness concern. Gating here, the actual point of
	// consequence, closes the gap regardless of how a provider reached
	// ACTIVE.
	rows, err := db.QueryContext(ctx, `
		SELECT provider_id, asn
		FROM providers
		WHERE status = 'ACTIVE'
		  AND razorpay_linked_account_id IS NOT NULL
		  AND razorpay_cooling_until < NOW()
		  AND NOT (provider_id = ANY($1::uuid[]))
		ORDER BY random()
		LIMIT 2`,
		pq.Array(excludeStrs),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var candidates []replacementCandidate
	for rows.Next() {
		var c replacementCandidate
		if err := rows.Scan(&c.providerID, &c.asn); err != nil {
			return nil, err
		}
		candidates = append(candidates, c)
	}
	return candidates, rows.Err()
}

// orderCandidatesByScoreDesc returns candidates sorted by
// mv_provider_scores.score_composite, highest first. A candidate absent from
// the view (no audit history yet) is treated as score 0.
func orderCandidatesByScoreDesc(ctx context.Context, db DBTX, candidates []replacementCandidate) ([]replacementCandidate, error) {
	ids := make([]string, len(candidates))
	for i, c := range candidates {
		ids[i] = c.providerID.String()
	}

	rows, err := db.QueryContext(ctx,
		`SELECT provider_id, score_composite FROM mv_provider_scores WHERE provider_id = ANY($1::uuid[])`,
		pq.Array(ids),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	scores := make(map[uuid.UUID]float64, len(candidates))
	for rows.Next() {
		var id uuid.UUID
		var score float64
		if err := rows.Scan(&id, &score); err != nil {
			return nil, err
		}
		scores[id] = score
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	ordered := make([]replacementCandidate, len(candidates))
	copy(ordered, candidates)
	sort.SliceStable(ordered, func(i, j int) bool {
		return scores[ordered[i].providerID] > scores[ordered[j].providerID]
	})
	return ordered, nil
}

// asnWithinCap reports whether assigning one more shard of segmentID to a
// provider on the given asn would stay at or below maxPerASN, counting only
// currently live assignments (ACTIVE or REPAIRING — a shard mid-repair still
// occupies its ASN's share until the replacement is confirmed).
func asnWithinCap(ctx context.Context, db DBTX, segmentID uuid.UUID, asn string, maxPerASN int) (bool, error) {
	var currentCount int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM chunk_assignments ca
		JOIN providers p ON p.provider_id = ca.provider_id
		WHERE ca.segment_id = $1 AND ca.status IN ('ACTIVE', 'REPAIRING') AND p.asn = $2`,
		segmentID, asn,
	).Scan(&currentCount)
	if err != nil {
		return false, err
	}
	return currentCount+1 <= maxPerASN, nil
}

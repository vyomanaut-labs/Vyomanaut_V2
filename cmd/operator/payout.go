// Package main — `operator payout` (M17-E Session 17.6.3, requirement 10).
//
// [BUILD BLOCKER, resolved by design council] The task text as originally
// written asks this command to "trigger a charge/release cycle and print
// the per-provider split table." No admin endpoint exposed any
// per-provider escrow balance (adminProviderItem carries none — checked
// directly, internal/api/admin.go), cmd/operator has no database
// connection of its own to read one (I-DEMO-1), and the real charge/
// release engines only ever run from their own background tickers
// (internal/payment/charge.go, release.go) — an admin-triggerable re-run
// would race the ticker. This session's `/design-council` verdict (ADR-084
// addendum A) authorised one narrow, deliberately reviewed exception to
// NO_ADDITIONAL_ROUTES: a single READ-ONLY admin endpoint,
// GET /api/v1/admin/payout/preview, backed by
// payment.PreviewMonthlyRelease — the identical
// releasePaise = balancePaise * multiplierBP / 10000 path
// computeReleaseForProvider itself uses (ADR-061), but writing nothing and
// touching no idempotency key. This command reads that endpoint; it never
// causes a real release to run early.
//
// ADR-061's own words for the remainder this per-provider division
// truncates — "the remainder must be shown, not silently dropped" — are
// honoured literally: RemainderBP is a real, non-money, sub-paise quantity
// (out of 10,000ths of a paise), and this command's own reconciliation
// line proves BalancePaise*MultiplierBP == ReleasePaise*10000 + RemainderBP
// for every row, not just asserts it.
//
// [REF: ADR-061 Decision, ADR-084 requirement 10, ADR-084 addendum A;
// internal/payment/release.go PreviewMonthlyRelease (Session 17.6.3);
// build_M17E.md Phase 17.6 Session 17.6.3]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"text/tabwriter"
)

// basisPointsDivisor mirrors internal/payment/release.go's own constant of
// the same name and value (ADR-061) — not imported, since internal/payment
// exports no such constant and cmd/ cannot reach an unexported one; this
// package needs the identical divisor only to reconstruct the
// reconciliation identity for display, never to recompute the split
// itself (the server already did that).
const basisPointsDivisor = 10000

func dispatchPayout(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("operator payout", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	g.adminAPIKey = resolveAdminAPIKey(g.adminAPIKey)
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return exitUsage
	}
	if len(fs.Args()) != 0 {
		fprintln(errOut, "usage: operator payout [flags]")
		return exitUsage
	}

	client := newAdminClient(g.microserviceURL, g.adminAPIKey)
	resp, err := client.fetchPayoutPreview(context.Background())
	if err != nil {
		fprintf(errOut, "vyomanaut operator payout: %v\n", err)
		return 1
	}

	renderPayout(out, resp, g.json)
	return 0
}

// payoutTotals sums BalancePaise*MultiplierBP, ReleasePaise, and
// RemainderBP across every provider in resp. The reconciling identity this
// command exists to demonstrate is:
//
//	totalNumerator == totalRelease*basisPointsDivisor + totalRemainder
//
// which holds unconditionally because it holds per-row (ADR-061) and a sum
// of exact identities is itself exact — never assumed, always the actual
// arithmetic performed on the actual response.
func payoutTotals(resp payoutPreviewResponseBody) (totalRelease, totalRemainder, totalNumerator int64) {
	for _, p := range resp.Providers {
		totalRelease += p.ReleasePaise
		totalRemainder += p.RemainderBP
		totalNumerator += p.BalancePaise * p.MultiplierBP
	}
	return totalRelease, totalRemainder, totalNumerator
}

func renderPayout(out io.Writer, resp payoutPreviewResponseBody, jsonOutput bool) {
	totalRelease, totalRemainder, totalNumerator := payoutTotals(resp)

	if jsonOutput {
		type payoutJSONResult struct {
			payoutPreviewResponseBody
			TotalReleasePaise  int64 `json:"total_release_paise"`
			TotalRemainderBP   int64 `json:"total_remainder_bp"`
			TotalNumeratorBP   int64 `json:"total_numerator_bp"`
			ReconciledExactly  bool  `json:"reconciled_exactly"`
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(payoutJSONResult{
			payoutPreviewResponseBody: resp,
			TotalReleasePaise:         totalRelease,
			TotalRemainderBP:          totalRemainder,
			TotalNumeratorBP:          totalNumerator,
			ReconciledExactly:         totalRelease*basisPointsDivisor+totalRemainder == totalNumerator,
		})
		return
	}

	fprintf(out, "Payout preview — billing period %s (ADR-061 release multiplier: releasePaise = balancePaise x multiplierBP / %d)\n\n", resp.BillingPeriod, basisPointsDivisor)

	// Every candidate provider is rendered, even one whose multiplier is 0
	// (score below the lowest release tier, FR-049) — a zero-release row is
	// real information ("this provider is held in full this cycle"), not a
	// reason to omit the row. There is no minimum-row floor either: an
	// empty Providers slice prints a valid, honestly empty table.
	tw := tabwriter.NewWriter(out, 0, tableTabWidth, tablePadding, ' ', 0)
	fprintln(tw, "PROVIDER_ID\tBALANCE\tMULTIPLIER_BP\tRELEASE\tREMAINDER_BP\tSCORE")
	for _, p := range resp.Providers {
		scoreNote := "fresh"
		if p.ScoreStale {
			scoreNote = "STALE (>60min, DM S7)"
		}
		fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%s\n",
			p.ProviderID, formatPaise(p.BalancePaise), p.MultiplierBP, formatPaise(p.ReleasePaise), p.RemainderBP, scoreNote)
	}
	_ = tw.Flush()

	reconciled := totalRelease*basisPointsDivisor+totalRemainder == totalNumerator
	fprintf(out, "\n  reconciliation: sum(balance x multiplier) = %d;  sum(release)x%d + sum(remainder) = %d x %d + %d = %d\n",
		totalNumerator, basisPointsDivisor, totalRelease, basisPointsDivisor, totalRemainder, totalRelease*basisPointsDivisor+totalRemainder)
	if reconciled {
		fprintln(out, "  reconciled: EXACT (ADR-061 — nothing silently dropped)")
	} else {
		fprintln(out, "  reconciled: MISMATCH — this should never happen; file a build blocker")
	}
}

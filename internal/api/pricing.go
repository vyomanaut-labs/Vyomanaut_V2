// Package api is declared in doc.go.
// This file implements build.md Milestone 11 Phase 11.8: the two public,
// unauthenticated pricing-calculator endpoints — GET /api/v1/pricing/estimate
// (Session 11.8.1) and GET /api/v1/pricing/provider-estimate
// (Session 11.8.2). Both are pure calculators over config.NetworkProfile's
// single deterministic StorageRatePaisePerGBPerMonth (network_profile.go's
// own note: "[Added, build.md Milestone 11 Phase 11.5/11.8] FR-057 and
// FileListItem's monthly_cost_paise both need a concrete storage rate" —
// the same rate an owner pays is the same rate a provider earns, ADR-024's
// "deterministic pricing"). No DB access, no auth — safe to call before an
// account exists (FR-057: "accessible before registration ... available on
// the marketing site and within the installer welcome screen").
//
// [Flagged and corrected — OAS's estimated_escrow_hold_vetting_paise field
// description disagrees with two independent, agreeing sources on the
// vetting-period hold fraction, and with OAS's own neighbouring field.]
// That one field's description text states a hold fraction well below what
// ADR-024 §6 gives ("Release multiplier: capped at 0.50 until vetting is
// complete" / "at most 50% of any month's earnings until they pass the
// vetting threshold") and what FR-051 independently gives ("the release cap
// must be 50%") — two agreeing, detailed sources against one outlier
// description string. OAS's own estimated_net_paise_vetting field on this
// same response even agrees with the higher figure ("gross × 0.50 release
// cap during vetting"), meaning the outlier is internally inconsistent with
// its own sibling field, not just with FR-051/ADR-024: a hold of the lower
// figure alongside a release of 0.50 would not sum to gross. Since ADR-024
// §6 — the authoritative economic-mechanism decision this endpoint models —
// is unambiguous and self-consistent, vettingReleaseCapBP below implements
// the ADR-024/FR-051 figure for both the hold and the net-during-vetting
// fields (hold = 1 - release, so the two fields are numerically identical
// here); flagged for an OAS text correction rather than silently
// implementing the stale outlier.
//
// [REF: OAS paths./api/v1/pricing/*, components/schemas/
// PricingEstimateResponse, Paise, FR-013, FR-057, FR-051, ADR-024 §3 §6,
// build.md Phase 11.8]

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// ── Session 11.8.1 — Storage Pricing Estimate ───────────────────────────

// monthsPerYear converts a monthly paise figure to an annual one
// (OAS PricingEstimateResponse.annual_cost_paise: "monthly_cost_paise × 12").
const monthsPerYear = 12

// pricingEstimateResponseBody mirrors OAS components/schemas/
// PricingEstimateResponse. FileSizeBytes is a pointer so it is omitted
// (rather than emitted as an explicit JSON null) when the caller did not
// supply file_size_bytes — OAS's own description ties this field to being
// "echoed from query param if provided", not to the 1 GB default actually
// used internally for the rest of the calculation.
type pricingEstimateResponseBody struct {
	StorageRatePaisePerGBPerMonth int64  `json:"storage_rate_paise_per_gb_per_month"`
	FileSizeBytes                 *int64 `json:"file_size_bytes,omitempty"`
	MonthlyCostPaise              int64  `json:"monthly_cost_paise"`
	AnnualCostPaise               int64  `json:"annual_cost_paise"`
	MinEscrowBalancePaise         int64  `json:"min_escrow_balance_paise"`
}

// PricingEstimateHandler serves GET /api/v1/pricing/estimate (FR-013,
// FR-057; public, no auth — OAS security: []).
type PricingEstimateHandler struct {
	profile config.NetworkProfile
}

func NewPricingEstimateHandler(profile config.NetworkProfile) *PricingEstimateHandler {
	return &PricingEstimateHandler{profile: profile}
}

// HandleEstimate serves GET /api/v1/pricing/estimate. file_size_bytes is an
// optional query param (OAS: "If omitted, the response is for 1 GB.").
// monthly_cost_paise reuses fileMonthlyCostPaiseForBytes (Session 11.5.3),
// the same helper FileListItem's own monthly_cost_paise is computed from —
// one cost formula, not a second, drifting copy of it.
func (h *PricingEstimateHandler) HandleEstimate(w http.ResponseWriter, r *http.Request) {
	sizeBytes := int64(bytesPerGB) // default: 1 GB (OAS)
	var echoedSize *int64

	if raw := r.URL.Query().Get("file_size_bytes"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "file_size_bytes must be a positive integer", nil, "file_size_bytes", nil)
			return
		}
		sizeBytes = parsed
		echoedSize = &parsed
	}

	monthlyCost := fileMonthlyCostPaiseForBytes(sizeBytes, h.profile)

	resp := pricingEstimateResponseBody{
		StorageRatePaisePerGBPerMonth: h.profile.StorageRatePaisePerGBPerMonth,
		FileSizeBytes:                 echoedSize,
		MonthlyCostPaise:              monthlyCost,
		AnnualCostPaise:               monthlyCost * monthsPerYear,
		// 30 days' cost, same "one month ≈ 30 days" convention
		// ownerBalanceAndReserved already uses for its own "next 30 days"
		// reserved figure (Session 11.5.3) — not a second, independently
		// computed value.
		MinEscrowBalancePaise: monthlyCost,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ── Session 11.8.2 — Provider Earnings Estimate ─────────────────────────

const (
	// pricingBasisPointsDivisor converts a basis-points fraction back to a
	// plain multiplier, mirroring internal/payment/release.go's own
	// basisPointsDivisor idiom exactly (10000 = 1.00): releasePaise =
	// grossPaise * fractionBP / pricingBasisPointsDivisor, ordinary integer
	// division, never anything else.
	pricingBasisPointsDivisor = 10000

	// vettingReleaseCapBP is ADR-024 §6 / FR-051's release cap during the
	// 4-6 month vetting period — "at most 50% of any month's earnings" —
	// which is also, by construction, the vetting-period hold fraction
	// (hold = 1 - release; see this file's header note on why this is NOT
	// OAS's estimated_escrow_hold_vetting_paise description text).
	vettingReleaseCapBP = 5000

	// postVettingFullReleaseBP is ADR-024 §3's release_multiplier = 1.00 at
	// score >= 0.95 ("full release — provider is reliable"; OAS: "gross ×
	// release_multiplier (1.00 at >=0.95 score)") — the assumed best-case
	// tier for estimated_net_paise_post_vetting, since a not-yet-registered
	// provider calling this pre-registration calculator has no live
	// reliability score to look up. (internal/payment/release.go's own
	// multiplierFullBP implements the identical value but is unexported, so
	// it is restated here as this package's own named constant rather than
	// imported.)
	postVettingFullReleaseBP = 10000

	minUptimeTargetPct = 0.0
	maxUptimeTargetPct = 100.0
)

// providerEarningsEstimateResponseBody mirrors the inline 200 schema of OAS
// GET /api/v1/pricing/provider-estimate (no named component — see this
// endpoint's own path definition).
type providerEarningsEstimateResponseBody struct {
	StorageRatePaisePerGBPerMonth   int64 `json:"storage_rate_paise_per_gb_per_month"`
	GrossMonthlyPaise               int64 `json:"gross_monthly_paise"`
	EstimatedEscrowHoldVettingPaise int64 `json:"estimated_escrow_hold_vetting_paise"`
	EstimatedNetPaiseVetting        int64 `json:"estimated_net_paise_vetting"`
	EstimatedNetPaisePostVetting    int64 `json:"estimated_net_paise_post_vetting"`
}

// ProviderEarningsEstimateHandler serves GET /api/v1/pricing/provider-estimate
// (FR-057, ADR-024; public, no auth — OAS security: []).
type ProviderEarningsEstimateHandler struct {
	profile config.NetworkProfile
}

func NewProviderEarningsEstimateHandler(profile config.NetworkProfile) *ProviderEarningsEstimateHandler {
	return &ProviderEarningsEstimateHandler{profile: profile}
}

// validateProviderEarningsQuery parses and validates storage_gb and
// uptime_target_pct — both required (OAS: required: true) — returning the
// offending field name and message on the first violation found, the same
// (field, msg, ok) convention provider.go's validateRegisterRequest uses.
// storage_gb reuses provider.go's own minDeclaredStorageGB/
// maxDeclaredStorageGB (Session 11.6.1): the identical declared_storage_gb
// range a real provider registration enforces.
func validateProviderEarningsQuery(r *http.Request) (storageGB int, uptimeTargetPct float64, field, msg string, ok bool) {
	rawStorageGB := r.URL.Query().Get("storage_gb")
	if rawStorageGB == "" {
		return 0, 0, "storage_gb", "required", false
	}
	storageGB, err := strconv.Atoi(rawStorageGB)
	if err != nil || storageGB < minDeclaredStorageGB || storageGB > maxDeclaredStorageGB {
		return 0, 0, "storage_gb", fmt.Sprintf("must be an integer between %d and %d", minDeclaredStorageGB, maxDeclaredStorageGB), false
	}

	rawUptime := r.URL.Query().Get("uptime_target_pct")
	if rawUptime == "" {
		return 0, 0, "uptime_target_pct", "required", false
	}
	uptimeTargetPct, err = strconv.ParseFloat(rawUptime, 64)
	if err != nil || uptimeTargetPct < minUptimeTargetPct || uptimeTargetPct > maxUptimeTargetPct {
		return 0, 0, "uptime_target_pct", fmt.Sprintf("must be a number between %g and %g", minUptimeTargetPct, maxUptimeTargetPct), false
	}

	return storageGB, uptimeTargetPct, "", "", true
}

// HandleEstimate serves GET /api/v1/pricing/provider-estimate.
//
// gross_monthly_paise (OAS: "storage_gb × rate × (uptime_target_pct / 100)")
// is the one computation here that necessarily touches float64: an uptime
// percentage is inherently fractional, and it arrives from the query string
// as one, so there is no integer-only formulation of this particular step —
// rounded with the same "round half up" convention fileMonthlyCostPaiseForBytes
// already uses (roundingHalf, Session 11.5.3). Every computation downstream
// of that point (the vetting hold, the vetting-period net, and the
// post-vetting net) operates on the already-rounded integer gross figure
// using plain basis-point integer arithmetic, mirroring
// internal/payment/release.go's own multiplier convention exactly.
func (h *ProviderEarningsEstimateHandler) HandleEstimate(w http.ResponseWriter, r *http.Request) {
	storageGB, uptimeTargetPct, field, msg, ok := validateProviderEarningsQuery(r)
	if !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, msg, nil, field, nil)
		return
	}

	grossExact := float64(storageGB) * float64(h.profile.StorageRatePaisePerGBPerMonth) * (uptimeTargetPct / maxUptimeTargetPct)
	gross := int64(grossExact + roundingHalf)

	vettingPortion := gross * vettingReleaseCapBP / pricingBasisPointsDivisor
	postVetting := gross * postVettingFullReleaseBP / pricingBasisPointsDivisor

	resp := providerEarningsEstimateResponseBody{
		StorageRatePaisePerGBPerMonth:   h.profile.StorageRatePaisePerGBPerMonth,
		GrossMonthlyPaise:               gross,
		EstimatedEscrowHoldVettingPaise: vettingPortion,
		EstimatedNetPaiseVetting:        vettingPortion,
		EstimatedNetPaisePostVetting:    postVetting,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

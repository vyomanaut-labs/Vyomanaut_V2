// Package api is declared in doc.go.
// Unit tests for the two public pricing-calculator endpoints — both are
// pure functions of config.NetworkProfile, so unlike most of this package's
// tests, none of these need a live database.
//
// Tests:
//   - TestPricingEstimateDefaultsToOneGB
//   - TestPricingEstimateAnnualIsTwelveXMonthly
//   - TestPricingEstimateAllValuesAreIntegerPaise
//   - TestPricingEstimateEchoesExplicitFileSizeBytes
//   - TestPricingEstimateRejectsInvalidFileSizeBytes
//   - TestPricingEstimateMinEscrowBalanceEqualsMonthlyCost
//   - TestProviderEarningsGrossMonthlyFormula
//   - TestProviderEarningsVettingHoldIsFiftyPercent
//   - TestProviderEarningsPostVettingUsesFullMultiplierAtHighScore
//   - TestProviderEarningsHoldPlusNetVettingEqualsGross
//   - TestProviderEarningsRejectsMissingStorageGB
//   - TestProviderEarningsRejectsOutOfRangeStorageGB
//   - TestProviderEarningsRejectsMissingUptimeTargetPct
//   - TestProviderEarningsRejectsOutOfRangeUptimeTargetPct
//
// [REF: OAS paths./api/v1/pricing/*, FR-013, FR-057, FR-051, ADR-024,
// build.md Phase 11.8]

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// ── Session 11.8.1 — Storage Pricing Estimate ───────────────────────────

func TestPricingEstimateDefaultsToOneGB(t *testing.T) {
	h := NewPricingEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/estimate", nil)
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp pricingEstimateResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := fileMonthlyCostPaiseForBytes(bytesPerGB, config.DemoProfile)
	if resp.MonthlyCostPaise != want {
		t.Errorf("MonthlyCostPaise = %d, want %d (1 GB at the configured rate)", resp.MonthlyCostPaise, want)
	}
	if resp.FileSizeBytes != nil {
		t.Errorf("FileSizeBytes = %v, want nil (not echoed when file_size_bytes was never supplied)", *resp.FileSizeBytes)
	}
	if resp.StorageRatePaisePerGBPerMonth != config.DemoProfile.StorageRatePaisePerGBPerMonth {
		t.Errorf("StorageRatePaisePerGBPerMonth = %d, want %d", resp.StorageRatePaisePerGBPerMonth, config.DemoProfile.StorageRatePaisePerGBPerMonth)
	}
}

func TestPricingEstimateAnnualIsTwelveXMonthly(t *testing.T) {
	h := NewPricingEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/estimate?file_size_bytes=5000000000", nil) // ~4.66 GB
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp pricingEstimateResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.AnnualCostPaise != resp.MonthlyCostPaise*12 {
		t.Errorf("AnnualCostPaise = %d, want MonthlyCostPaise*12 = %d", resp.AnnualCostPaise, resp.MonthlyCostPaise*12)
	}
}

func TestPricingEstimateAllValuesAreIntegerPaise(t *testing.T) {
	h := NewPricingEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/estimate?file_size_bytes=3221225472", nil) // 3 GB
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.UseNumber()
	var raw map[string]json.Number
	if err := dec.Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, field := range []string{
		"storage_rate_paise_per_gb_per_month", "monthly_cost_paise",
		"annual_cost_paise", "min_escrow_balance_paise",
	} {
		num, ok := raw[field]
		if !ok {
			t.Fatalf("response missing field %q: %s", field, rec.Body.String())
		}
		if strings.Contains(num.String(), ".") {
			t.Errorf("%s = %s, want an integer paise value (no decimal point)", field, num.String())
		}
		if _, err := num.Int64(); err != nil {
			t.Errorf("%s = %s is not a valid int64: %v", field, num.String(), err)
		}
	}
}

func TestPricingEstimateEchoesExplicitFileSizeBytes(t *testing.T) {
	h := NewPricingEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/estimate?file_size_bytes=2147483648", nil) // 2 GB
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp pricingEstimateResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.FileSizeBytes == nil || *resp.FileSizeBytes != 2147483648 {
		t.Errorf("FileSizeBytes = %v, want 2147483648 echoed back", resp.FileSizeBytes)
	}
	want := fileMonthlyCostPaiseForBytes(2147483648, config.DemoProfile)
	if resp.MonthlyCostPaise != want {
		t.Errorf("MonthlyCostPaise = %d, want %d (2 GB at the configured rate)", resp.MonthlyCostPaise, want)
	}
}

func TestPricingEstimateRejectsInvalidFileSizeBytes(t *testing.T) {
	h := NewPricingEstimateHandler(config.DemoProfile)

	for _, raw := range []string{"0", "-5", "not-a-number"} {
		t.Run(raw, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/pricing/estimate?file_size_bytes="+raw, nil)
			rec := httptest.NewRecorder()
			h.HandleEstimate(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), string(ErrInvalidRequest)) {
				t.Errorf("body %q does not contain error_code %q", rec.Body.String(), ErrInvalidRequest)
			}
		})
	}
}

func TestPricingEstimateMinEscrowBalanceEqualsMonthlyCost(t *testing.T) {
	h := NewPricingEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/estimate", nil)
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	var resp pricingEstimateResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.MinEscrowBalancePaise != resp.MonthlyCostPaise {
		t.Errorf("MinEscrowBalancePaise = %d, want %d (30 days ≈ 1 month)", resp.MinEscrowBalancePaise, resp.MonthlyCostPaise)
	}
}

// ── Session 11.8.2 — Provider Earnings Estimate ─────────────────────────

func TestProviderEarningsGrossMonthlyFormula(t *testing.T) {
	h := NewProviderEarningsEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/provider-estimate?storage_gb=100&uptime_target_pct=100", nil)
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp providerEarningsEstimateResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := int64(100) * config.DemoProfile.StorageRatePaisePerGBPerMonth // 100 GB × rate × 100%
	if resp.GrossMonthlyPaise != want {
		t.Errorf("GrossMonthlyPaise = %d, want %d (storage_gb × rate × uptime_target_pct/100)", resp.GrossMonthlyPaise, want)
	}

	// A second point away from 100% uptime, still exact (no rounding
	// ambiguity): 10 GB at 50% uptime.
	req2 := httptest.NewRequest("GET", "/api/v1/pricing/provider-estimate?storage_gb=10&uptime_target_pct=50", nil)
	rec2 := httptest.NewRecorder()
	h.HandleEstimate(rec2, req2)
	var resp2 providerEarningsEstimateResponseBody
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want2 := int64(10) * config.DemoProfile.StorageRatePaisePerGBPerMonth / 2
	if resp2.GrossMonthlyPaise != want2 {
		t.Errorf("GrossMonthlyPaise (10GB, 50%%) = %d, want %d", resp2.GrossMonthlyPaise, want2)
	}
}

func TestProviderEarningsVettingHoldIsFiftyPercent(t *testing.T) {
	h := NewProviderEarningsEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/provider-estimate?storage_gb=100&uptime_target_pct=100", nil)
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	var resp providerEarningsEstimateResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	halfGross := resp.GrossMonthlyPaise / 2
	// FR-051 / ADR-024 §6: 50% release cap during vetting, i.e. also a 50%
	// hold — NOT OAS's stale outlier description (see pricing.go's header).
	if resp.EstimatedEscrowHoldVettingPaise != halfGross {
		t.Errorf("EstimatedEscrowHoldVettingPaise = %d, want %d (50%% of gross, FR-051)", resp.EstimatedEscrowHoldVettingPaise, halfGross)
	}
	if resp.EstimatedNetPaiseVetting != halfGross {
		t.Errorf("EstimatedNetPaiseVetting = %d, want %d (50%% release cap, FR-051)", resp.EstimatedNetPaiseVetting, halfGross)
	}
}

func TestProviderEarningsPostVettingUsesFullMultiplierAtHighScore(t *testing.T) {
	h := NewProviderEarningsEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/provider-estimate?storage_gb=100&uptime_target_pct=100", nil)
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	var resp providerEarningsEstimateResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// ADR-024 §3: release_multiplier = 1.00 at score >= 0.95 — the assumed
	// tier here, since a pre-registration calculator has no live score.
	if resp.EstimatedNetPaisePostVetting != resp.GrossMonthlyPaise {
		t.Errorf("EstimatedNetPaisePostVetting = %d, want %d (full gross at the >=0.95 tier)", resp.EstimatedNetPaisePostVetting, resp.GrossMonthlyPaise)
	}
}

func TestProviderEarningsHoldPlusNetVettingEqualsGross(t *testing.T) {
	h := NewProviderEarningsEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/provider-estimate?storage_gb=100&uptime_target_pct=100", nil)
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	var resp providerEarningsEstimateResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if sum := resp.EstimatedEscrowHoldVettingPaise + resp.EstimatedNetPaiseVetting; sum != resp.GrossMonthlyPaise {
		t.Errorf("hold + net_vetting = %d, want gross = %d", sum, resp.GrossMonthlyPaise)
	}
}

func TestProviderEarningsRejectsMissingStorageGB(t *testing.T) {
	h := NewProviderEarningsEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/provider-estimate?uptime_target_pct=95", nil)
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"field":"storage_gb"`) {
		t.Errorf("body %q does not name storage_gb as the offending field", rec.Body.String())
	}
}

func TestProviderEarningsRejectsOutOfRangeStorageGB(t *testing.T) {
	h := NewProviderEarningsEstimateHandler(config.DemoProfile)

	for _, gb := range []string{"9", "100001", "not-a-number"} {
		t.Run(gb, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/pricing/provider-estimate?storage_gb="+gb+"&uptime_target_pct=95", nil)
			rec := httptest.NewRecorder()
			h.HandleEstimate(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestProviderEarningsRejectsMissingUptimeTargetPct(t *testing.T) {
	h := NewProviderEarningsEstimateHandler(config.DemoProfile)
	req := httptest.NewRequest("GET", "/api/v1/pricing/provider-estimate?storage_gb=100", nil)
	rec := httptest.NewRecorder()
	h.HandleEstimate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"field":"uptime_target_pct"`) {
		t.Errorf("body %q does not name uptime_target_pct as the offending field", rec.Body.String())
	}
}

func TestProviderEarningsRejectsOutOfRangeUptimeTargetPct(t *testing.T) {
	h := NewProviderEarningsEstimateHandler(config.DemoProfile)

	for _, pct := range []string{"-1", "100.5", "101", "not-a-number"} {
		t.Run(pct, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/pricing/provider-estimate?storage_gb=100&uptime_target_pct="+pct, nil)
			rec := httptest.NewRecorder()
			h.HandleEstimate(rec, req)

			// 100.5 is a valid uptime percentage numerically but exceeds
			// the OAS maximum of 100; every case in this table must 400.
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

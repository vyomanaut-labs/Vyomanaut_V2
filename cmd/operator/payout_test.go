// Tests for payout.go (M17-E Session 17.6.3).
//
// Tests:
//   - TestPayoutSplitSumsToChargedTotalIncludingRemainder
//   - TestPayoutRendersEveryProviderEvenAtZeroRelease
//   - TestDispatchPayoutCallsTheAdminEndpoint
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPayoutSplitSumsToChargedTotalIncludingRemainder confirms the
// reconciliation identity this command exists to demonstrate —
// sum(balance*multiplier) == sum(release)*basisPointsDivisor +
// sum(remainder) — is computed for real from the response, not assumed,
// and that the rendered output states it as EXACT (ADR-061: nothing
// silently dropped). Uses deliberately un-clean numbers (multiplier tiers
// that do not divide balances evenly) specifically so a regression that
// dropped the remainder term would make this test fail.
func TestPayoutSplitSumsToChargedTotalIncludingRemainder(t *testing.T) {
	resp := payoutPreviewResponseBody{
		BillingPeriod: "2026-08",
		Providers: []payoutPreviewProviderItem{
			// 100003 paise * 7500bp = 750022500; /10000 = 75002, remainder 2500
			{ProviderID: "prov-a", BalancePaise: 100003, MultiplierBP: 7500, ReleasePaise: 75002, RemainderBP: 2500},
			// 33333 paise * 5000bp = 166665000; /10000 = 16666, remainder 5000
			{ProviderID: "prov-b", BalancePaise: 33333, MultiplierBP: 5000, ReleasePaise: 16666, RemainderBP: 5000},
		},
	}

	totalRelease, totalRemainder, totalNumerator := payoutTotals(resp)
	if got, want := totalRelease*basisPointsDivisor+totalRemainder, totalNumerator; got != want {
		t.Fatalf("release*%d + remainder = %d, want %d (sum of balance*multiplier)", basisPointsDivisor, got, want)
	}

	var buf bytes.Buffer
	renderPayout(&buf, resp, false)
	out := buf.String()
	if !strings.Contains(out, "reconciled: EXACT") {
		t.Errorf("output does not confirm exact reconciliation:\n%s", out)
	}
	if !strings.Contains(out, "remainder") {
		t.Errorf("output does not mention the remainder:\n%s", out)
	}

	// --json path carries the same figures, not just the human-readable text.
	buf.Reset()
	renderPayout(&buf, resp, true)
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal --json output: %v", err)
	}
	if reconciled, ok := decoded["reconciled_exactly"].(bool); !ok || !reconciled {
		t.Errorf("--json output reconciled_exactly = %v, want true", decoded["reconciled_exactly"])
	}
	if _, ok := decoded["total_remainder_bp"]; !ok {
		t.Errorf("--json output missing total_remainder_bp: %v", decoded)
	}
}

// TestPayoutRendersEveryProviderEvenAtZeroRelease guards against silently
// omitting a provider whose release this cycle is zero (score below the
// lowest FR-049 tier, multiplier_bp = 0) — a zero-release row is real,
// demo-relevant information ("held in full"), and dropping it would be
// the exact "silently dropped" failure mode this session's task text
// warns against, at the row level instead of the paise level.
func TestPayoutRendersEveryProviderEvenAtZeroRelease(t *testing.T) {
	resp := payoutPreviewResponseBody{
		BillingPeriod: "2026-08",
		Providers: []payoutPreviewProviderItem{
			{ProviderID: "prov-held", BalancePaise: 50000, MultiplierBP: 0, ReleasePaise: 0, RemainderBP: 0},
			{ProviderID: "prov-full", BalancePaise: 20000, MultiplierBP: 10000, ReleasePaise: 20000, RemainderBP: 0},
		},
	}

	var buf bytes.Buffer
	renderPayout(&buf, resp, false)
	out := buf.String()

	if !strings.Contains(out, "prov-held") {
		t.Errorf("output omits the zero-release provider prov-held:\n%s", out)
	}
	if !strings.Contains(out, "prov-full") {
		t.Errorf("output omits prov-full:\n%s", out)
	}

	// --json path: same row count, zero-release row still present.
	buf.Reset()
	renderPayout(&buf, resp, true)
	var decoded struct {
		Providers []payoutPreviewProviderItem `json:"providers"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal --json output: %v", err)
	}
	if len(decoded.Providers) != 2 {
		t.Fatalf("--json output has %d providers, want 2 (zero-release row must not be dropped)", len(decoded.Providers))
	}
}

// TestDispatchPayoutCallsTheAdminEndpoint is a thin end-to-end check that
// dispatchPayout actually reaches GET /api/v1/admin/payout/preview with
// the X-Admin-API-Key header set.
func TestDispatchPayoutCallsTheAdminEndpoint(t *testing.T) {
	const adminKey = "test-admin-key"
	var gotPath, gotKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("X-Admin-API-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payoutPreviewResponseBody{BillingPeriod: "2026-08"})
	}))
	defer server.Close()

	var out, errOut bytes.Buffer
	code := dispatchPayout([]string{
		"--microservice-url=" + server.URL,
		"--admin-api-key=" + adminKey,
	}, &out, &errOut)

	if code != 0 {
		t.Fatalf("dispatchPayout exit code = %d, want 0, stderr = %s", code, errOut.String())
	}
	if gotPath != "/api/v1/admin/payout/preview" {
		t.Errorf("request path = %q, want /api/v1/admin/payout/preview", gotPath)
	}
	if gotKey != adminKey {
		t.Errorf("X-Admin-API-Key = %q, want %q", gotKey, adminKey)
	}
}

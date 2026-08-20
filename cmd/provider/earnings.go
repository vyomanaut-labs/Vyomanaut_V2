// Package main — `provider earnings` (M17-E Session 17.5.2, requirement
// 10, provider side).
//
// CORRECTION to the build spec: build_M17E.md's Session 17.5.2 TASK item 4
// named GET /api/v1/provider/receipts as this session's source endpoint.
// Reading internal/api/provider.go directly shows that endpoint returns
// audit CHALLENGE/RESPONSE receipts (FR-058,
// ProviderReceiptsHandler/auditReceiptListItem) — pass/fail/timeout,
// response latency, signatures. No payment field appears anywhere in that
// response. The endpoint that actually carries
// pending_earnings_paise/held_earnings_paise is
// GET /api/v1/provider/{provider_id}/status (ProviderStatusHandler,
// providerStatusResponseBody) — used here instead. Recorded as a planning
// correction: the build document's own TASK text named the wrong
// endpoint, not something this session's implementation deviates from
// deliberately.
//
// Like onboard.go/depart.go, this file does not import internal/api;
// providerStatusResponseBody below is a local mirror of the server's own
// shape — see main.go's registrationSigningField header note for why.
//
// [REF: ADR-061; internal/api/provider.go Session 11.5.x (status),
// Session 11.6.4 (receipts, not used here — see correction above);
// build_M17E.md Phase 17.5 Session 17.5.2]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

// providerStatusResponseBody mirrors internal/api/provider.go's
// providerStatusResponseBody — only the fields this command actually
// displays are reproduced; the server may return more.
type providerStatusResponseBody struct {
	ProviderID           string `json:"provider_id"`
	Status               string `json:"status"`
	PendingEarningsPaise int64  `json:"pending_earnings_paise"`
	HeldEarningsPaise    int64  `json:"held_earnings_paise"`
	StoredChunks         int    `json:"stored_chunks"`
	StorageAdvisoryGB    int    `json:"storage_advisory_gb"`
}

type earningsFlags struct {
	microserviceURL string
	dataDir         string
	jsonOutput      bool
}

func parseEarningsFlags(args []string) earningsFlags {
	fs := flag.NewFlagSet("provider earnings", flag.ExitOnError)
	var f earningsFlags
	fs.StringVar(&f.microserviceURL, "microservice-url", "", "Required. HTTPS base URL of the coordination microservice.")
	fs.StringVar(&f.dataDir, "data-dir", defaultProviderDataDir(), "Persistent data directory — must match the --data-dir `provider onboard` used.")
	fs.BoolVar(&f.jsonOutput, "json", false, "Emit the report as a single JSON object instead of human-readable text.")
	_ = fs.Parse(args)
	return f
}

// fetchProviderStatus calls GET /api/v1/provider/{provider_id}/status.
// The server requires provider_id in the path to equal the bearer token's
// own JWT subject (HandleStatus's ownership check) — both come from the
// same persisted registration record here, so that always holds.
func fetchProviderStatus(ctx context.Context, microserviceURL, providerID, bearerToken string) (providerStatusResponseBody, error) {
	url := fmt.Sprintf("%s/api/v1/provider/%s/status", microserviceURL, providerID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return providerStatusResponseBody{}, fmt.Errorf("build status request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+bearerToken)

	client := &http.Client{Timeout: providerHTTPClientTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return providerStatusResponseBody{}, fmt.Errorf("status request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return providerStatusResponseBody{}, fmt.Errorf("status returned HTTP %d: %s", resp.StatusCode, errBody)
	}

	var body providerStatusResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return providerStatusResponseBody{}, fmt.Errorf("decode status response: %w", err)
	}
	return body, nil
}

// runEarnings executes the full flow, writing its report to out — factored
// out of earningsCmd exactly as onboard.go's runOnboard is, so tests can
// drive it against a fake server and a buffer instead of the real network
// and os.Stdout.
func runEarnings(ctx context.Context, flags earningsFlags, out io.Writer) error {
	rec, found, err := loadRegistrationRecord(flags.dataDir)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no registration found under %s — run `provider onboard` first", flags.dataDir)
	}

	status, err := fetchProviderStatus(ctx, flags.microserviceURL, rec.ProviderID, rec.Token)
	if err != nil {
		return err
	}

	if flags.jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(status)
	}

	fmt.Fprintf(out, "Provider %s (%s)\n", status.ProviderID, status.Status)
	fmt.Fprintf(out, "  pending earnings: %s\n", formatPaise(status.PendingEarningsPaise))
	fmt.Fprintf(out, "  held earnings:    %s\n", formatPaise(status.HeldEarningsPaise))
	fmt.Fprintf(out, "  stored chunks:    %d (declared %d GB, NFR-044 ceiling %d GB)\n",
		status.StoredChunks, rec.DeclaredStorageGB, status.StorageAdvisoryGB)
	return nil
}

// earningsCmd is the "earnings" subcommand's handler (dispatch.go).
func earningsCmd(args []string) int {
	flags := parseEarningsFlags(args)
	if flags.microserviceURL == "" {
		fmt.Fprintln(os.Stderr, "vyomanaut provider earnings: --microservice-url is required")
		return 1
	}

	if err := runEarnings(context.Background(), flags, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "vyomanaut provider earnings: %v\n", err)
		return 1
	}
	return 0
}

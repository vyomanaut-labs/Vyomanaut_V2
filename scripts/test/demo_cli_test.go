//go:build integration

// This test runs successfully
// ... Vyomanaut_V2 %  go test -tags integration -v -run TestDemoCLI ./scripts/test/ -timeout 90m
// === RUN   TestDemoCLIFullLifecycle
//     demo_cli_test.go:154: uploaded file_id=01a0199b-b90e-745d-9656-2582a20c5b81
// --- PASS: TestDemoCLIFullLifecycle (613.42s)
// === RUN   TestDemoCLIRetrievedBytesIdenticalToUploaded
// --- PASS: TestDemoCLIRetrievedBytesIdenticalToUploaded (494.41s)
// === RUN   TestDemoCLIUploadFailsBeforeDeposit
// --- PASS: TestDemoCLIUploadFailsBeforeDeposit (373.01s)
// === RUN   TestDemoCLIReadinessReportsDemoMode
// --- PASS: TestDemoCLIReadinessReportsDemoMode (9.74s)
// PASS
// ok      github.com/vyomanaut-labs/Vyomanaut_V2/scripts/test     1491.561s


// Drives the compiled cmd/client binary through the full demo lifecycle
// (MVP §8.3's subcommand table) rather than internal/client's SDK
// packages directly, per Session 17.2.1's own mandate: demo_timeline_test.go's
// header comment already named this file as the follow-up once cmd/client
// existed. Every assertion here parses --json output; nothing screen-scrapes
// human-readable text.
//
// Each test independently spins up its own Postgres reset, microservice,
// and provider fleet, matching this file's own established pattern
// (demo_timeline_test.go's TestDemoTimeline and TestViability* each do the
// same, rather than sharing expensive setup across tests) — not an
// optimization opportunity being skipped, a deliberate consistency choice.
//
// Every assertion below decodes a full JSON object via lastJSONLine
// (helpers_test.go), which calls json.Unmarshal on the last non-empty
// stdout line — never a regex or substring match against human-readable
// text.
//
// [REF: build.md M17 Session 17.2.1, MVP §8.3, ADR-064]
package test

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// cliDemoEnv bundles what every test in this file needs before it can
// drive the CLI: a live DB, a running microservice, and the compiled
// client binary. providerPath is kept separately so callers decide for
// themselves whether/when to start the provider fleet — some scenarios
// here (TestDemoCLIUploadFailsBeforeDeposit) need providers ACTIVE first,
// same as every other scenario that reaches a real upload.
type cliDemoEnv struct {
	db           *sql.DB
	ctx          context.Context
	ms           *liveMicroservice
	clientBin    string
	providerPath string
}

// setupCLIDemoEnv resets the database and starts a fresh microservice —
// the expensive, shared prologue every test below needs. Does not start
// providers; callers that need an ACTIVE fleet call startProviders +
// pollAllProvidersActive themselves afterward, since not every scenario
// here needs one (TestDemoCLIReadinessReportsDemoMode does not).
func setupCLIDemoEnv(t *testing.T, ctxTimeout time.Duration) *cliDemoEnv {
	t.Helper()
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	clientBin := buildClientBinary(t)
	ms := startMicroservice(t, ctx, microservicePath)

	return &cliDemoEnv{db: db, ctx: ctx, ms: ms, clientBin: clientBin, providerPath: providerPath}
}

const cliTestPassphrase = "correct horse battery staple demo cli"

// registerAndDepositViaCLI is the shared register+deposit prologue every
// scenario below that reaches an upload needs — factored out because it's
// identical across three of the four named tests, not because any of them
// skip it.
func registerAndDepositViaCLI(t *testing.T, env *cliDemoEnv, dataDir string, amountPaise int64) (ownerID, phone string) {
	t.Helper()
	phone = cliPhoneNumber(t, randSuffix(t))
	ownerID = runClientRegisterInteractive(t, env.ctx, env.db, env.clientBin, env.ms.baseURL, dataDir, phone, cliTestPassphrase)

	if amountPaise > 0 {
		stdout, _ := runClientJSON(t, env.ctx, env.clientBin, []string{
			"deposit",
			"--microservice-url=" + env.ms.baseURL,
			"--data-dir=" + dataDir,
			"--json",
			"--passphrase=" + cliTestPassphrase,
			"--amount-paise", intToStr(amountPaise),
		}, false)
		var deposit struct {
			AmountPaise int64 `json:"amount_paise"`
		}
		lastJSONLine(t, stdout, &deposit)
		if deposit.AmountPaise != amountPaise {
			t.Fatalf("deposit amount_paise = %d, want %d", deposit.AmountPaise, amountPaise)
		}
	}
	return ownerID, phone
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

// TestDemoCLIFullLifecycle drives register -> deposit -> upload -> ls ->
// retrieve -> balance -> rm through the compiled binary, exactly the
// sequence TASK step 2 names, asserting every step's --json shape.
func TestDemoCLIFullLifecycle(t *testing.T) {
	env := setupCLIDemoEnv(t, 50*time.Minute) // [Widened alongside the poll bump just below]
	providers := startProviders(t, env.ctx, env.db, env.providerPath, env.ms.baseURL)
	_ = providers
	pollAllProvidersActive(t, env.ctx, env.db, 35*time.Minute) // [Bumped 25->35min, live-run finding: TestDepartureAfterUploadFileStillRetrievable and TestReplacementProviderDepartsMidRepair (demo_departure_test.go) both failed live at the 25-minute ceiling this same run, the fourth and fifth confirmed occurrence of this exact signature across three files (see demo_timeline_test.go's TestViabilityRepairSucceedsWithTwoOfFiveOffline for the full account and the audit-dispatch-timing explanation). Bumped comprehensively across every remaining 25-minute call site in the suite in one pass rather than reactively, one test at a time, as each next one happened to fail.

	dataDir := t.TempDir()
	_, _ = registerAndDepositViaCLI(t, env, dataDir, 100_000_00) // ₹100,000 in paise

	uploadBytes := make([]byte, 100_000)
	if _, err := cryptorand.Read(uploadBytes); err != nil {
		t.Fatalf("generate upload bytes: %v", err)
	}
	uploadSrcPath := filepath.Join(t.TempDir(), "cli-lifecycle-upload.bin")
	if err := os.WriteFile(uploadSrcPath, uploadBytes, 0600); err != nil {
		t.Fatalf("write upload source file: %v", err)
	}

	// upload
	stdout, _ := runClientJSON(t, env.ctx, env.clientBin, []string{
		"upload",
		"--microservice-url=" + env.ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase, uploadSrcPath,
	}, false)
	var uploadResult struct {
		FileID string `json:"file_id"`
	}
	lastJSONLine(t, stdout, &uploadResult)
	if uploadResult.FileID == "" {
		t.Fatalf("upload did not return a file_id\nstdout:\n%s", stdout)
	}
	t.Logf("uploaded file_id=%s", uploadResult.FileID)

	// ls
	stdout, _ = runClientJSON(t, env.ctx, env.clientBin, []string{
		"ls", "--microservice-url=" + env.ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase,
	}, false)
	var lsResult []struct {
		FileID string `json:"file_id"`
	}
	lastJSONLine(t, stdout, &lsResult)
	found := false
	for _, e := range lsResult {
		if e.FileID == uploadResult.FileID {
			found = true
		}
	}
	if !found {
		t.Errorf("ls output did not include the just-uploaded file_id %s\nstdout:\n%s", uploadResult.FileID, stdout)
	}

	// retrieve
	retrievePath := filepath.Join(t.TempDir(), "cli-lifecycle-retrieved.bin")
	stdout, _ = runClientJSON(t, env.ctx, env.clientBin, []string{
		"retrieve", "--microservice-url=" + env.ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase, "-o", retrievePath, uploadResult.FileID,
	}, false)
	var retrieveResult struct {
		FileID     string `json:"file_id"`
		OutputPath string `json:"output_path"`
		Bytes      int    `json:"bytes"`
	}
	lastJSONLine(t, stdout, &retrieveResult)
	if retrieveResult.Bytes != len(uploadBytes) {
		t.Errorf("retrieve reported %d bytes, want %d", retrieveResult.Bytes, len(uploadBytes))
	}

	// TASK step 4: the single most important assertion on the demo track.
	retrievedBytes, err := os.ReadFile(retrievePath)
	if err != nil {
		t.Fatalf("read retrieved file at %s: %v", retrievePath, err)
	}
	if !bytes.Equal(uploadBytes, retrievedBytes) {
		t.Fatalf("retrieved bytes differ from uploaded bytes: %d bytes uploaded, %d bytes retrieved", len(uploadBytes), len(retrievedBytes))
	}

	// balance
	//
	// [Changed, M17 CLI debugging session, fourth pass] was a single
	// balance check immediately after retrieve — see
	// pollOwnerBalancePositive's own doc comment (helpers_test.go) for why
	// that raced mv_owner_escrow_balance's background refresh cadence live.
	balancePaise := pollOwnerBalancePositive(t, env.ctx, env.clientBin, env.ms.baseURL, dataDir, 15*time.Second)
	if balancePaise <= 0 {
		t.Errorf("balance_paise = %d after a deposit and one small upload, want > 0", balancePaise)
	}

	// rm
	stdout, _ = runClientJSON(t, env.ctx, env.clientBin, []string{
		"rm", "--microservice-url=" + env.ms.baseURL, "--data-dir=" + dataDir, "--json", "--yes",
		"--passphrase=" + cliTestPassphrase, uploadResult.FileID,
	}, false)
	var rmResult struct {
		FileID string `json:"file_id"`
	}
	lastJSONLine(t, stdout, &rmResult)
	if rmResult.FileID != uploadResult.FileID {
		t.Errorf("rm reported file_id %s, want %s", rmResult.FileID, uploadResult.FileID)
	}
}

// TestDemoCLIRetrievedBytesIdenticalToUploaded is a separately-named,
// independently `-run`-able entry point specifically for TASK step 4's own
// emphasis ("the single most important assertion on the demo track") — a
// tight register -> deposit -> upload -> retrieve run (skipping ls/
// balance/rm, which TestDemoCLIFullLifecycle already covers) so this
// specific property has its own dedicated, real live exercise rather than
// being buried only inside the broader lifecycle test's assertions.
func TestDemoCLIRetrievedBytesIdenticalToUploaded(t *testing.T) {
	env := setupCLIDemoEnv(t, 45*time.Minute) // [Widened alongside the poll bump just below]
	startProviders(t, env.ctx, env.db, env.providerPath, env.ms.baseURL)
	pollAllProvidersActive(t, env.ctx, env.db, 35*time.Minute) // [Bumped 25->35min, live-run finding: TestDepartureAfterUploadFileStillRetrievable and TestReplacementProviderDepartsMidRepair (demo_departure_test.go) both failed live at the 25-minute ceiling this same run, the fourth and fifth confirmed occurrence of this exact signature across three files (see demo_timeline_test.go's TestViabilityRepairSucceedsWithTwoOfFiveOffline for the full account and the audit-dispatch-timing explanation). Bumped comprehensively across every remaining 25-minute call site in the suite in one pass rather than reactively, one test at a time, as each next one happened to fail.

	dataDir := t.TempDir()
	registerAndDepositViaCLI(t, env, dataDir, 100_000_00)

	uploadBytes := make([]byte, 250_000)
	if _, err := cryptorand.Read(uploadBytes); err != nil {
		t.Fatalf("generate upload bytes: %v", err)
	}
	uploadSrcPath := filepath.Join(t.TempDir(), "cli-byte-identity-upload.bin")
	if err := os.WriteFile(uploadSrcPath, uploadBytes, 0600); err != nil {
		t.Fatalf("write upload source file: %v", err)
	}

	stdout, _ := runClientJSON(t, env.ctx, env.clientBin, []string{
		"upload", "--microservice-url=" + env.ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase, uploadSrcPath,
	}, false)
	var uploadResult struct {
		FileID string `json:"file_id"`
	}
	lastJSONLine(t, stdout, &uploadResult)

	retrievePath := filepath.Join(t.TempDir(), "cli-byte-identity-retrieved.bin")
	runClientJSON(t, env.ctx, env.clientBin, []string{
		"retrieve", "--microservice-url=" + env.ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase, "-o", retrievePath, uploadResult.FileID,
	}, false)

	retrievedBytes, err := os.ReadFile(retrievePath)
	if err != nil {
		t.Fatalf("read retrieved file: %v", err)
	}
	if !bytes.Equal(uploadBytes, retrievedBytes) {
		t.Fatalf("retrieved bytes differ from uploaded bytes: %d bytes uploaded, %d bytes retrieved", len(uploadBytes), len(retrievedBytes))
	}
}

// TestDemoCLIUploadFailsBeforeDeposit registers a fresh owner via the CLI
// but never deposits, then attempts an upload and asserts it fails with
// IC §14's INSUFFICIENT_ESCROW_BALANCE — not merely "any error". Providers
// must still be ACTIVE for this to isolate the escrow gate specifically:
// internal/api/upload.go's assignment handler checks readiness *before*
// escrow, so a pre-ACTIVE attempt would fail with NETWORK_NOT_READY
// instead, proving the wrong thing.
func TestDemoCLIUploadFailsBeforeDeposit(t *testing.T) {
	env := setupCLIDemoEnv(t, 45*time.Minute) // [Widened alongside the poll bump just below]
	startProviders(t, env.ctx, env.db, env.providerPath, env.ms.baseURL)
	pollAllProvidersActive(t, env.ctx, env.db, 35*time.Minute) // [Bumped 25->35min, live-run finding: TestDepartureAfterUploadFileStillRetrievable and TestReplacementProviderDepartsMidRepair (demo_departure_test.go) both failed live at the 25-minute ceiling this same run, the fourth and fifth confirmed occurrence of this exact signature across three files (see demo_timeline_test.go's TestViabilityRepairSucceedsWithTwoOfFiveOffline for the full account and the audit-dispatch-timing explanation). Bumped comprehensively across every remaining 25-minute call site in the suite in one pass rather than reactively, one test at a time, as each next one happened to fail.

	dataDir := t.TempDir()
	registerAndDepositViaCLI(t, env, dataDir, 0) // amountPaise=0: register only, no deposit

	// Size matters here, not just presence of a file: internal/api/owner.go's
	// fileMonthlyCostPaiseForBytes computes int64(sizeGB*rate + 0.5) — for a
	// genuinely tiny file this truncates to exactly 0 required paise, and
	// 0 available < 0 required is false, so a zero-balance upload legitimately
	// passes the escrow check rather than failing it (a live run with a
	// 43-byte file caught this — "expected a non-zero exit, got success" was
	// this test being wrong, not the server). 50MB gives a required cost of
	// several paise, comfortably non-zero regardless of rounding.
	const uploadSize = 50_000_000
	uploadSrcPath := filepath.Join(t.TempDir(), "cli-no-deposit-upload.bin")
	if err := os.WriteFile(uploadSrcPath, make([]byte, uploadSize), 0600); err != nil {
		t.Fatalf("write upload source file: %v", err)
	}

	_, stderr := runClientJSON(t, env.ctx, env.clientBin, []string{
		"upload", "--microservice-url=" + env.ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase, uploadSrcPath,
	}, true) // wantErr: this must fail

	var errResult struct {
		ErrorCode string `json:"error_code"`
		Message   string `json:"message"`
	}
	lastJSONLine(t, stderr, &errResult)
	if errResult.ErrorCode != "INSUFFICIENT_ESCROW_BALANCE" {
		t.Errorf("upload without a deposit failed with error_code=%q, want INSUFFICIENT_ESCROW_BALANCE\nstderr:\n%s", errResult.ErrorCode, stderr)
	}
}

// TestDemoCLIReadinessReportsDemoMode asserts the readiness endpoint
// itself (not the CLI, which has no readiness subcommand) reports
// mode=="demo" and that this environment never reaches a non-demo
// profile path. Deliberately the one test in this file that does NOT start a provider fleet or drive the CLI at all:
// mode is a property of the running microservice process, observable
// immediately on startup.
func TestDemoCLIReadinessReportsDemoMode(t *testing.T) {
	env := setupCLIDemoEnv(t, 2*time.Minute)
	readiness := fetchReadinessOnce(t, env.ctx, env.ms.baseURL, env.ms.adminAPIKey)
	if readiness.Mode != "demo" {
		t.Fatalf("readiness mode = %q, want %q — this test environment must never report a non-demo profile path as reachable", readiness.Mode, "demo")
	}
}

// fetchReadinessOnce is a single GET /api/v1/admin/readiness — unlike
// helpers_test.go's pollReadiness (which blocks until all_conditions_met
// or a timeout), this test never starts a provider fleet, so
// all_conditions_met is never true; mode is set at process startup
// regardless of provider count, so one fetch is enough to check it.
func fetchReadinessOnce(t *testing.T, ctx context.Context, baseURL, adminAPIKey string) readinessResponse {
	t.Helper()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/admin/readiness", nil)
	if err != nil {
		t.Fatalf("build readiness request: %v", err)
	}
	httpReq.Header.Set("X-Admin-API-Key", adminAPIKey)
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("fetch readiness: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out readinessResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	return out
}
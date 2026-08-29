//go:build integration

// scripts/test/demo_requirements_test.go — M17-E Session 17.8.2.
//
// One named integration test per founding functional requirement
// (ADR-084-demo-presentation-surface.md, Appendix A — the eleven founding
// requirements, verbatim), so a deleted requirement test breaks CI rather
// than passing quietly (build_part3.md, Session 17.8.2 TASK item 7):
//
//	TestReqD01OwnerUploadsLocalFile
//	TestReqD02SevenProvidersVolunteerAndReachActive
//	TestReqD03FileIsEncryptedAndDistributedAcrossDistinctASNs
//	TestReqD04OperatorSeesNetworkStateAndCannotDecode
//	TestReqD05ProviderLocalStorageIsCiphertext
//	TestReqD06HeartbeatMarksProviderOnline
//	TestReqD07FileRetrievableAfterProviderLossAndRepair   — defined in
//	  demo_departure_test.go (Session 17.7.2), referenced by name in this
//	  file's own header, never duplicated (task item 1's own instruction).
//	TestReqD08RetrievedBytesIdenticalToUploaded
//	TestReqD09AuditChallengeVerifiesProviderStorage
//	TestReqD10PaymentSplitsEquallyAcrossProviders
//	TestReqD11ProviderAllocationIsHonoured
//
// TestReqD02 and TestReqD11 start providers in NORMAL mode, on distinct
// --listen-port values, via the real `provider onboard` interactive OTP
// flow against cmd/microservice's FileOtpSender delivery log — never
// --sim-count anywhere on this path (F-D-3's own standing rule) — closing
// F-D-2 and F-D-3 in CI rather than only at the physical rig. Every other
// test in this file uses the existing sim-mode fleet
// (demo_timeline_test.go's startProviders), which is the right tool for
// requirements this file's own task text does not tie to the onboarding
// flow specifically.
//
// Every assertion in this file parses --json (lastJSONLine, or a direct
// json.Unmarshal against a file this project's own code already writes as
// JSON, e.g. onboard.go's registration.json) — never screen-scrapes a
// human-readable rendering.
//
// [Flagged, not fabricated — carried into TestReqD10's own doc comment
// too] No production code path in this codebase inserts into
// audit_periods at all; TestReqD10 seeds it directly
// (seedAuditPeriodsForActiveProviders, helpers_test.go) rather than
// silently pretending a real trigger exists. See that helper's own doc
// comment for the full account.
//
// [REF: ADR-084-demo-presentation-surface.md Appendix A; build_part3.md
// Phase 17.8 Session 17.8.2; HANDOFF_M17E_phase_17.8.2]
package test

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// ═══════════════════════════════════════════════════════════════════════
// Requirement 1 — "The interface allows a data owner to upload a file
// present on his desktop."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD01OwnerUploadsLocalFile(t *testing.T) {
	// [Widened — live-run finding, shared class with
	// TestDepartureMidRetrievalStillGathersK] pollAllProvidersActive's own
	// 25-minute deadline is occasionally too tight for a 7th provider's
	// ACTIVE transition on real hardware — confirmed live twice in the
	// same run (this suite's own TestDepartureMidRetrievalStillGathersK
	// and TestReqD08, both failing with the identical "last count: 6"
	// message). Bumped here, and the outer context timeout correspondingly,
	// rather than only bumping the outer `go test -timeout` flag, since
	// THIS internal deadline — not the process-level one — is what was
	// actually being hit.
	env := setupCLIDemoEnv(t, 40*time.Minute)
	startProviders(t, env.ctx, env.db, env.providerPath, env.ms.baseURL)
	pollAllProvidersActive(t, env.ctx, env.db, 35*time.Minute)

	dataDir := t.TempDir()
	registerAndDepositViaCLI(t, env, dataDir, 100_000_00) // ₹100,000 in paise

	uploadBytes := make([]byte, 64_000)
	if _, err := cryptorand.Read(uploadBytes); err != nil {
		t.Fatalf("generate upload bytes: %v", err)
	}
	// Requirement 1's own wording: "a file present on his desktop" — a
	// real path on this machine's filesystem, uploaded by that path
	// through the real CLI, not bytes handed directly to an SDK call.
	uploadSrcPath := filepath.Join(t.TempDir(), "reqd01-local-upload.bin")
	if err := os.WriteFile(uploadSrcPath, uploadBytes, 0600); err != nil {
		t.Fatalf("write local upload source file: %v", err)
	}

	stdout, _ := runClientJSON(t, env.ctx, env.clientBin, []string{
		"upload", "--microservice-url=" + env.ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase, uploadSrcPath,
	}, false)
	var uploadResult struct {
		FileID string `json:"file_id"`
	}
	lastJSONLine(t, stdout, &uploadResult)
	if uploadResult.FileID == "" {
		t.Fatalf("upload of a real local file did not return a file_id\nstdout:\n%s", stdout)
	}
	t.Logf("uploaded local file %s as file_id=%s", uploadSrcPath, uploadResult.FileID)
}

// ═══════════════════════════════════════════════════════════════════════
// Requirement 2 — "On the same desktop (or later on a separate machine),
// another user can volunteer as a provider (up to 7 providers in total)."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD02SevenProvidersVolunteerAndReachActive(t *testing.T) {
	db := liveDB(t)
	// [Widened — same live-run finding as TestReqD01] 45m outer / 35m
	// poll, not 40m/25m — see TestReqD01's own comment for the full
	// account.
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	operatorPath := buildOperatorBinary(t)
	deliveryLogPath := filepath.Join(t.TempDir(), "otp-delivery.log")
	ms := startMicroserviceWithFlags(t, ctx, microservicePath, "--otp-delivery-log="+deliveryLogPath)

	// F-D-3: normal mode, distinct --listen-port per instance, never
	// --sim-count — the real `provider onboard` flow, exactly as a
	// volunteer would run it (scripts/demo/join.sh), driven here through
	// its interactive OTP prompt rather than at the physical rig.
	fleet := startNormalModeProviderFleet(t, ctx, providerPath, operatorPath, ms.baseURL, deliveryLogPath, testSimCount)
	if len(fleet.instances) != testSimCount {
		t.Fatalf("onboarded %d provider(s), want %d (requirement 2: \"up to 7 providers\")", len(fleet.instances), testSimCount)
	}
	for i, rec := range fleet.records {
		if rec.ProviderID == "" {
			t.Errorf("provider index %d: onboard registration record has an empty provider_id", i)
		}
	}

	pollAllProvidersActive(t, ctx, db, 35*time.Minute)
}

// ═══════════════════════════════════════════════════════════════════════
// Requirement 3 — "The uploaded file gets encrypted and distributed among
// the providers present on the network."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD03FileIsEncryptedAndDistributedAcrossDistinctASNs(t *testing.T) {
	db := liveDB(t)
	// [Widened — same live-run finding as TestReqD01/D02.]
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	operatorPath := buildOperatorBinary(t)
	ms := startMicroservice(t, ctx, microservicePath)
	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00)
	startProviders(t, ctx, db, providerPath, ms.baseURL)
	pollReadiness(t, ctx, ms.baseURL, ms.adminAPIKey, 12*time.Minute)
	pollAllProvidersActive(t, ctx, db, 35*time.Minute)

	fileID, _, plaintext := uploadTestFileTracked(t, ctx, ms, owner, testUploadBytes)

	profile := config.SelectProfile("demo")

	// ADR-084's own phase table scopes requirement 3 to the operator
	// console (Phase 17.6) — this is deliberately the SAME artifact
	// TestReqD04 drives, since the operator's admin-key view is exactly
	// where "distributed among the providers" and "encrypted" (i.e.
	// content the console structurally cannot show) are both checkable at
	// once.
	//
	// [Fixed — live-run finding] file_id (a positional argument) must come
	// LAST: cmd/operator's stdlib flag.Parse stops at the first non-flag
	// token, so putting it before the flags silently drops every flag that
	// follows — see runOperatorJSON's own doc comment (helpers_test.go)
	// for the full account.
	stdout, _ := runOperatorJSON(t, ctx, operatorPath, []string{
		"shards",
		"--microservice-url=" + ms.baseURL,
		"--admin-api-key=" + ms.adminAPIKey,
		"--mode=demo",
		fileID.String(),
	})

	var shardsResult struct {
		FileID string `json:"file_id"`
		Shards []struct {
			ChunkID    string `json:"chunk_id"`
			SegmentID  string `json:"segment_id"`
			ShardIndex int    `json:"shard_index"`
			ProviderID string `json:"provider_id"`
			ASN        string `json:"asn"`
			SizeBytes  int    `json:"size_bytes"`
		} `json:"shards"`
	}
	lastJSONLine(t, stdout, &shardsResult)

	if len(shardsResult.Shards) != profile.TotalShards {
		t.Errorf("operator shards reported %d shard(s), want %d (profile.TotalShards) — requirement 3's \"distributed among the providers\"",
			len(shardsResult.Shards), profile.TotalShards)
	}
	distinctASNs := map[string]bool{}
	distinctProviders := map[string]bool{}
	for _, s := range shardsResult.Shards {
		distinctASNs[s.ASN] = true
		distinctProviders[s.ProviderID] = true
	}
	if len(distinctASNs) < profile.MinDistinctASNs {
		t.Errorf("shards span %d distinct ASN(s), want >= %d (profile.MinDistinctASNs)", len(distinctASNs), profile.MinDistinctASNs)
	}
	if len(distinctProviders) < profile.MinDistinctASNs {
		t.Errorf("shards are held by %d distinct provider(s), want >= %d", len(distinctProviders), profile.MinDistinctASNs)
	}

	// Requirement 3's "encrypted" half: the operator's own admin-key view
	// of this file exposes only chunk_id (a content hash), provider_id,
	// asn, and size_bytes — never a byte of the file itself. This is
	// expected to hold structurally (the wire shape has no field capable
	// of carrying it), but the raw plaintext's presence is checked
	// directly rather than only inferred from the response shape.
	if bytes.Contains([]byte(stdout), plaintext[:min(64, len(plaintext))]) {
		t.Errorf("operator shards --json output contains a window of the uploaded plaintext — requirement 3's confidentiality claim violated")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Requirement 4 — "A terminal can monitor a new node entry and also the
// log of the entire network health, performance, and transfers taking
// place (but never see the originally uploaded data)."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD04OperatorSeesNetworkStateAndCannotDecode(t *testing.T) {
	db := liveDB(t)
	// [Widened — same live-run finding as TestReqD01/D02/D03.]
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	operatorPath := buildOperatorBinary(t)
	clientBin := buildClientBinary(t)
	ms := startMicroservice(t, ctx, microservicePath)
	startProviders(t, ctx, db, providerPath, ms.baseURL)
	pollAllProvidersActive(t, ctx, db, 35*time.Minute)

	dataDir := t.TempDir()
	phone := cliPhoneNumber(t, randSuffix(t))
	runClientRegisterInteractive(t, ctx, db, clientBin, ms.baseURL, dataDir, phone, cliTestPassphrase)
	depositStdout, _ := runClientJSON(t, ctx, clientBin, []string{
		"deposit", "--microservice-url=" + ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase, "--amount-paise", "10000000",
	}, false)
	var depositResult struct {
		AmountPaise int64 `json:"amount_paise"`
	}
	lastJSONLine(t, depositStdout, &depositResult)
	if depositResult.AmountPaise != 10_000_000 {
		t.Fatalf("deposit reported amount_paise=%d, want 10000000", depositResult.AmountPaise)
	}

	// Requirement 4's own wording: "never see the originally uploaded
	// data." A distinctive local filename, uploaded through the real CLI
	// path (requirement 1's own artifact), must never surface anywhere the
	// operator can see — whether by cryptographic protection or (today's
	// disclosed state; internal/client/upload/orchestrator.go's own header
	// note that no upload path currently sets a display name at all) by
	// simply never having been transmitted. Both count as "cannot see";
	// this test proves the outcome, not the specific mechanism.
	marker := fmt.Sprintf("reqd04-secret-marker-%s.bin", randomHex(t, 8))
	uploadSrcPath := filepath.Join(t.TempDir(), marker)
	uploadBytes := make([]byte, 32_000)
	if _, err := cryptorand.Read(uploadBytes); err != nil {
		t.Fatalf("generate upload bytes: %v", err)
	}
	if err := os.WriteFile(uploadSrcPath, uploadBytes, 0600); err != nil {
		t.Fatalf("write local upload source file: %v", err)
	}

	uploadStdout, _ := runClientJSON(t, ctx, clientBin, []string{
		"upload", "--microservice-url=" + ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase, uploadSrcPath,
	}, false)
	var uploadResult struct {
		FileID string `json:"file_id"`
	}
	lastJSONLine(t, uploadStdout, &uploadResult)
	if uploadResult.FileID == "" {
		t.Fatalf("upload did not return a file_id\nstdout:\n%s", uploadStdout)
	}

	watchStdout, _ := runOperatorJSON(t, ctx, operatorPath, []string{
		"watch",
		"--microservice-url=" + ms.baseURL,
		"--admin-api-key=" + ms.adminAPIKey,
		"--mode=demo",
	})
	var watchResult struct {
		Providers *struct {
			Total int `json:"total"`
		} `json:"providers"`
	}
	lastJSONLine(t, watchStdout, &watchResult)
	if watchResult.Providers == nil || watchResult.Providers.Total == 0 {
		t.Errorf("operator watch --json reported no providers — requirement 4's \"monitor a new node entry\" half")
	}

	// [Fixed — live-run finding, same class as TestReqD03] file_id last,
	// after every flag — see runOperatorJSON's own doc comment.
	shardsStdout, _ := runOperatorJSON(t, ctx, operatorPath, []string{
		"shards",
		"--microservice-url=" + ms.baseURL,
		"--admin-api-key=" + ms.adminAPIKey,
		"--mode=demo",
		uploadResult.FileID,
	})
	var shardsResult struct {
		FileID string `json:"file_id"`
	}
	lastJSONLine(t, shardsStdout, &shardsResult)
	if shardsResult.FileID != uploadResult.FileID {
		t.Errorf("operator shards --json reported file_id=%s, want %s", shardsResult.FileID, uploadResult.FileID)
	}

	for name, raw := range map[string]string{"watch": watchStdout, "shards": shardsStdout} {
		if strings.Contains(raw, marker) {
			t.Errorf("operator %s --json output contains the uploaded file's real local filename %q — requirement 4's confidentiality claim violated", name, marker)
		}
	}

	// I-DEMO-1, asserted structurally by the suite itself (task item 3),
	// not only by scripts/ci/grep_checks.sh's own static source-text
	// check: this confirms it against cmd/operator's ACTUAL built
	// dependency graph, matching main.go's own header comment verbatim —
	// "no import path, direct or transitive, to any decoding primitive...
	// and no database access of any kind."
	repoRoot := findRepoRoot(t)
	listCmd := exec.CommandContext(ctx, "go", "list", "-deps", "./cmd/operator")
	listCmd.Dir = repoRoot
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/operator: %v\n%s", err, listOut)
	}
	forbiddenDeps := []string{
		"internal/crypto/aont",
		"internal/erasure",
		"internal/client/retrieve",
		"internal/client/upload",
		"database/sql",
		"github.com/lib/pq",
	}
	for _, dep := range forbiddenDeps {
		if strings.Contains(string(listOut), dep) {
			t.Errorf("cmd/operator's dependency graph includes %q — I-DEMO-1 violated", dep)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Requirement 5 — "The providers can store the file on their local
// machine and see encrypted data upon opening the file."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD05ProviderLocalStorageIsCiphertext(t *testing.T) {
	db := liveDB(t)
	// [Widened — same live-run finding as TestReqD01-04; larger margin
	// here since this test also onboards a fleet AND does the
	// upload/kill/inspect/full-store-scan work afterward.]
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	operatorPath := buildOperatorBinary(t)
	deliveryLogPath := filepath.Join(t.TempDir(), "otp-delivery.log")
	ms := startMicroserviceWithFlags(t, ctx, microservicePath, "--otp-delivery-log="+deliveryLogPath)

	// `provider inspect` (inspect.go) opens storage.NewChunkStore(--data-dir)
	// directly, with no "/db" suffix — the exact layout normal-mode's own
	// chunkStoreDir uses (main.go's runCmd: chunkStoreDir == dataDir), but
	// NOT the layout --sim-count's runSimulation uses (chunkStoreDir ==
	// dataDir/db). This test therefore inspects a normal-mode (onboarded)
	// fleet member, matching inspect.go's own designed usage, rather than
	// the sim-mode fleet most other tests in this file use.
	fleet := startNormalModeProviderFleet(t, ctx, providerPath, operatorPath, ms.baseURL, deliveryLogPath, testSimCount)
	pollAllProvidersActive(t, ctx, db, 35*time.Minute)

	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00)
	// A deliberately small plaintext: the absence check below searches
	// every 32-byte window of the PLAINTEXT against each holder's full
	// on-disk chunk content (not merely the first 128 bytes `provider
	// inspect --hex` would show) — bounding the plaintext keeps that
	// search fast without weakening what it proves, since AONT+RS pads
	// every segment to the SAME fixed shard size regardless of input
	// length (plaintextSegmentSize, internal/client/upload/orchestrator.go).
	const reqD05PlaintextBytes = 8192
	fileID, _, plaintext := uploadTestFileTracked(t, ctx, ms, owner, reqD05PlaintextBytes)

	var holderProviderID string
	err := db.QueryRowContext(ctx, `
		SELECT ca.provider_id::text
		FROM chunk_assignments ca
		JOIN segments s ON s.segment_id = ca.segment_id
		WHERE s.file_id = $1 AND ca.is_vetting_chunk = FALSE AND ca.status = 'ACTIVE'
		LIMIT 1`, fileID).Scan(&holderProviderID)
	if err != nil {
		t.Fatalf("query a real chunk holder for file %s: %v", fileID, err)
	}

	holderIdx := -1
	for i, rec := range fleet.records {
		if rec.ProviderID == holderProviderID {
			holderIdx = i
			break
		}
	}
	if holderIdx == -1 {
		t.Fatalf("uploaded file's holder provider_id %s does not match any onboarded fleet member", holderProviderID)
	}
	holderInst := fleet.instances[holderIdx]

	// `provider inspect` requires the daemon to be stopped first — both
	// storage engines hold an exclusive lock on --data-dir
	// (inspect.go's own documented constraint).
	killDaemonProcessGroup(holderInst.cmd)

	inspectCmd := exec.Command(providerPath, "inspect", "--data-dir="+holderInst.dataDir, "--json")
	inspectOut, err := inspectCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("provider inspect --data-dir=%s: %v\n%s", holderInst.dataDir, err, inspectOut)
	}
	var inspectResult struct {
		Chunks []struct {
			ChunkID   string  `json:"chunk_id"`
			SizeBytes int     `json:"size_bytes"`
			Entropy   float64 `json:"entropy_bits_per_byte"`
		} `json:"chunks"`
	}
	lastJSONLine(t, string(inspectOut), &inspectResult)
	if len(inspectResult.Chunks) == 0 {
		t.Fatalf("provider inspect --json reported zero chunks for a holder of the uploaded file (data-dir=%s)", holderInst.dataDir)
	}

	const minEntropyBitsPerByte = 7.9
	for _, c := range inspectResult.Chunks {
		if c.Entropy <= minEntropyBitsPerByte {
			t.Errorf("chunk %s entropy = %.4f bits/byte, want > %.1f", c.ChunkID, c.Entropy, minEntropyBitsPerByte)
		}
	}

	// The stronger assertion (task item 4's own wording): no 32-byte
	// window of the ORIGINAL plaintext appears anywhere in the provider's
	// store — high entropy alone is consistent with a bad cipher; absence
	// of plaintext is not. `provider inspect --json`'s own hex dump is
	// truncated to the first 128 bytes per chunk, not enough to search a
	// whole (up to 256 KB) shard, so this opens the SAME storage.ChunkStore
	// the daemon itself used directly, now that its exclusive lock is
	// free, for full-content coverage.
	store, err := storage.NewChunkStore(holderInst.dataDir)
	if err != nil {
		t.Fatalf("open chunk store at %s: %v", holderInst.dataDir, err)
	}
	defer func() { _ = store.Close() }()

	chunkIDs, err := store.ListChunks()
	if err != nil {
		t.Fatalf("list chunks at %s: %v", holderInst.dataDir, err)
	}
	if len(chunkIDs) == 0 {
		t.Fatalf("holder's chunk store at %s is empty", holderInst.dataDir)
	}

	const plaintextWindow = 32
	for _, id := range chunkIDs {
		data, lookupErr := store.LookupChunk(id)
		if lookupErr != nil {
			t.Fatalf("lookup chunk %x: %v", id, lookupErr)
		}
		for i := 0; i+plaintextWindow <= len(plaintext); i++ {
			if bytes.Contains(data, plaintext[i:i+plaintextWindow]) {
				t.Fatalf("chunk %x contains a 32-byte window of the original plaintext (offset %d) — provider local storage is NOT ciphertext", id, i)
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Requirement 6 — "A mechanism to mark the provider online, as a
// heartbeat."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD06HeartbeatMarksProviderOnline(t *testing.T) {
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	ms := startMicroservice(t, ctx, microservicePath)
	startProviders(t, ctx, db, providerPath, ms.baseURL)

	// [Fixed — live-run finding] last_heartbeat_ts is NOT a reliable signal
	// that the periodic heartbeat mechanism has fired: F-17E-02
	// (internal/api/provider.go's own registration handler) deliberately
	// seeds last_heartbeat_ts = NOW() at REGISTRATION time too — a real
	// proof-of-life event in its own right, and the fix for a genuine
	// departure-detection bug (a provider killed before its first
	// heartbeat could never be detected as departed). So
	// last_heartbeat_ts IS NOT NULL is true from the moment of
	// registration onward, before the heartbeat mechanism this
	// requirement is actually about has run even once — confirmed live: a
	// fresh 7-provider fleet failed this test's old assertion within 8
	// seconds, far less than one HeartbeatInterval (30s). The unambiguous
	// signal that HandleHeartbeat specifically (not HandleRegister) has
	// processed a real heartbeat is providers.status advancing past
	// PENDING_ONBOARDING — HandleHeartbeat's own atomic UPDATE is the
	// ONLY place in the codebase that CASEs status from PENDING_ONBOARDING
	// to VETTING (confirmed by search), and it sets last_heartbeat_ts in
	// that same statement, so a provider whose status has advanced is
	// live proof both columns reflect a genuine heartbeat, not just
	// registration.
	const heartbeatWait = 3 * time.Minute
	deadline := time.Now().Add(heartbeatWait)
	for {
		pollContextAlive(t, ctx, "TestReqD06HeartbeatMarksProviderOnline")
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM providers WHERE status <> 'PENDING_ONBOARDING'`).Scan(&count); err == nil && count > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no provider's status advanced past PENDING_ONBOARDING within %s — no real heartbeat (HandleHeartbeat, not registration) appears to have been processed", heartbeatWait)
		}
		time.Sleep(2 * time.Second)
	}

	var lastHeartbeatIsSet bool
	if err := db.QueryRowContext(ctx, `SELECT last_heartbeat_ts IS NOT NULL FROM providers WHERE status <> 'PENDING_ONBOARDING' LIMIT 1`).Scan(&lastHeartbeatIsSet); err != nil {
		t.Fatalf("query heartbeating provider's last_heartbeat_ts: %v", err)
	}
	if !lastHeartbeatIsSet {
		t.Errorf("a provider whose status advanced past PENDING_ONBOARDING (i.e. received a real heartbeat) has no last_heartbeat_ts recorded")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Requirement 7 — "When the provider goes offline, repair takes place,
// ensuring that the file can be retrieved at any time by the data owner."
//
// Defined in demo_departure_test.go (Session 17.7.2), delegating to
// runDepartureAfterUpload — the SAME scenario
// TestDepartureAfterUploadFileStillRetrievable already proves. Referenced
// here by name only, per this session's own task item 1 instruction not
// to duplicate it — see this file's own package-level header comment
// above for the full eleven-name list, requirement 7's entry included.
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
// Requirement 8 — "The data owner can fetch the file back, and the file
// has no changes."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD08RetrievedBytesIdenticalToUploaded(t *testing.T) {
	// [Widened — this is the exact test that failed live: "not all 7
	// providers reached ACTIVE within 25m0s (last count: 6)" — see
	// TestReqD01's own comment for the full account.]
	env := setupCLIDemoEnv(t, 40*time.Minute)
	startProviders(t, env.ctx, env.db, env.providerPath, env.ms.baseURL)
	pollAllProvidersActive(t, env.ctx, env.db, 35*time.Minute)

	dataDir := t.TempDir()
	registerAndDepositViaCLI(t, env, dataDir, 100_000_00)

	uploadBytes := make([]byte, 300_000)
	if _, err := cryptorand.Read(uploadBytes); err != nil {
		t.Fatalf("generate upload bytes: %v", err)
	}
	uploadSrcPath := filepath.Join(t.TempDir(), "reqd08-upload.bin")
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
	if uploadResult.FileID == "" {
		t.Fatalf("upload did not return a file_id\nstdout:\n%s", stdout)
	}

	retrievePath := filepath.Join(t.TempDir(), "reqd08-retrieved.bin")
	runClientJSON(t, env.ctx, env.clientBin, []string{
		"retrieve", "--microservice-url=" + env.ms.baseURL, "--data-dir=" + dataDir, "--json",
		"--passphrase=" + cliTestPassphrase, "-o", retrievePath, uploadResult.FileID,
	}, false)

	retrievedBytes, err := os.ReadFile(retrievePath)
	if err != nil {
		t.Fatalf("read retrieved file at %s: %v", retrievePath, err)
	}
	if !bytes.Equal(uploadBytes, retrievedBytes) {
		t.Fatalf("retrieved bytes differ from uploaded bytes: %d bytes uploaded, %d bytes retrieved", len(uploadBytes), len(retrievedBytes))
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Requirement 9 (optional, treated as mandatory) — "A test to the
// provider verifies their storage and proves it can be retrieved easily."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD09AuditChallengeVerifiesProviderStorage(t *testing.T) {
	db := liveDB(t)
	// [Widened — same live-run finding as TestReqD01 etc.; extra margin
	// for the up-to-6-minute real-audit-pass poll that follows.]
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	operatorPath := buildOperatorBinary(t)
	ms := startMicroservice(t, ctx, microservicePath)
	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00)
	startProviders(t, ctx, db, providerPath, ms.baseURL)
	pollReadiness(t, ctx, ms.baseURL, ms.adminAPIKey, 12*time.Minute)
	pollAllProvidersActive(t, ctx, db, 35*time.Minute)

	fileID, _, _ := uploadTestFileTracked(t, ctx, ms, owner, 8192)

	// The real, continuous audit path: the background scheduler issues
	// challenges on its own cadence and the provider answers over the
	// wire. This polls audit_receipts directly for the first PASS against
	// a REAL (non-vetting, file_id NOT NULL) chunk of THIS upload —
	// deliberately not demo_timeline_test.go's own pollFirstAuditPass,
	// which only confirms providers.consecutive_audit_passes >= 1 and so
	// could already be satisfied by a provider's earlier, pre-ACTIVE
	// vetting-chunk passes rather than by a genuine audit of this file's
	// own real shard.
	var passProviderID, passChunkIDHex string
	deadline := time.Now().Add(6 * time.Minute)
	for {
		pollContextAlive(t, ctx, "TestReqD09AuditChallengeVerifiesProviderStorage")
		err := db.QueryRowContext(ctx, `
			SELECT provider_id::text, encode(chunk_id, 'hex')
			FROM audit_receipts
			WHERE audit_result = 'PASS' AND file_id = $1
			ORDER BY server_challenge_ts DESC LIMIT 1`, fileID).Scan(&passProviderID, &passChunkIDHex)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no real (file_id=%s) audit_receipts PASS row appeared within %s: %v", fileID, 6*time.Minute, err)
		}
		time.Sleep(5 * time.Second)
	}

	// Requirement 9's own "on demand, in front of an audience" half:
	// operator audit dispatches a fresh challenge against the SAME
	// provider/chunk pair the real background path already proved PASSes.
	//
	// [Fixed — live-run finding, same class as TestReqD03/D04] both
	// positional arguments (provider_id, chunk_id) must come after every
	// flag, in that order — see runOperatorJSON's own doc comment.
	stdout, _ := runOperatorJSON(t, ctx, operatorPath, []string{
		"audit",
		"--microservice-url=" + ms.baseURL,
		"--admin-api-key=" + ms.adminAPIKey,
		"--mode=demo",
		passProviderID, passChunkIDHex,
	})
	var auditResult struct {
		ProviderID     string `json:"provider_id"`
		ChunkID        string `json:"chunk_id"`
		ChallengeNonce string `json:"challenge_nonce"`
		ResponseStatus string `json:"response_status"`
	}
	lastJSONLine(t, stdout, &auditResult)
	if auditResult.ChallengeNonce == "" {
		t.Fatalf("operator audit did not return a challenge_nonce\nstdout:\n%s", stdout)
	}
	if auditResult.ProviderID != passProviderID || auditResult.ChunkID != passChunkIDHex {
		t.Errorf("operator audit echoed provider_id=%s chunk_id=%s, want %s / %s",
			auditResult.ProviderID, auditResult.ChunkID, passProviderID, passChunkIDHex)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Requirement 10 (optional, treated as mandatory) — "A demo number acts
// as the payment sent by the data owner and gets equally split amongst
// the providers for the set duration of time."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD10PaymentSplitsEquallyAcrossProviders(t *testing.T) {
	db := liveDB(t)
	// [Widened — same live-run finding as TestReqD01 etc.; extra margin
	// for the audit-pass poll and payout-preview poll that follow.]
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	operatorPath := buildOperatorBinary(t)
	ms := startMicroservice(t, ctx, microservicePath)
	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00)
	startProviders(t, ctx, db, providerPath, ms.baseURL)
	pollReadiness(t, ctx, ms.baseURL, ms.adminAPIKey, 12*time.Minute)
	pollAllProvidersActive(t, ctx, db, 35*time.Minute)

	uploadTestFileTracked(t, ctx, ms, owner, 8192)
	pollFirstAuditPass(t, ctx, db, 5*time.Minute)

	// See seedAuditPeriodsForActiveProviders' own doc comment
	// (helpers_test.go) for why this seed is necessary: no production
	// code path in this codebase creates an audit_periods row today.
	seedAuditPeriodsForActiveProviders(t, ctx, db)

	type payoutProviderResult struct {
		ProviderID   string `json:"provider_id"`
		BalancePaise int64  `json:"balance_paise"`
		MultiplierBP int64  `json:"multiplier_bp"`
		ReleasePaise int64  `json:"release_paise"`
		RemainderBP  int64  `json:"remainder_bp"`
	}
	var payoutResult struct {
		Providers         []payoutProviderResult `json:"providers"`
		TotalReleasePaise int64                  `json:"total_release_paise"`
		TotalRemainderBP  int64                  `json:"total_remainder_bp"`
		TotalNumeratorBP  int64                  `json:"total_numerator_bp"`
		ReconciledExactly bool                   `json:"reconciled_exactly"`
	}

	const payoutPreviewWait = 5 * time.Minute
	deadline := time.Now().Add(payoutPreviewWait)
	var lastStdout string
	for {
		pollContextAlive(t, ctx, "TestReqD10PaymentSplitsEquallyAcrossProviders")
		stdout, _ := runOperatorJSON(t, ctx, operatorPath, []string{
			"payout",
			"--microservice-url=" + ms.baseURL,
			"--admin-api-key=" + ms.adminAPIKey,
			"--mode=demo",
		})
		lastStdout = stdout
		lastJSONLine(t, stdout, &payoutResult)
		if len(payoutResult.Providers) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("operator payout --json reported zero providers after %s (audit_periods seeded; provider scores may not have materialized yet)\nlast stdout:\n%s", payoutPreviewWait, stdout)
		}
		time.Sleep(5 * time.Second)
	}

	// ADR-061's own reconciling identity, checked independently of the
	// server's own reconciled_exactly field rather than trusted blindly —
	// task item 5's own wording: "asserts the split sums to the charge
	// including the integer remainder."
	const basisPointsDivisor = 10000
	var totalRelease, totalRemainder, totalNumerator int64
	for _, p := range payoutResult.Providers {
		numerator := p.BalancePaise * p.MultiplierBP
		if p.ReleasePaise*basisPointsDivisor+p.RemainderBP != numerator {
			t.Errorf("provider %s: releasePaise*%d + remainderBP = %d, want balancePaise*multiplierBP = %d",
				p.ProviderID, basisPointsDivisor, p.ReleasePaise*basisPointsDivisor+p.RemainderBP, numerator)
		}
		totalRelease += p.ReleasePaise
		totalRemainder += p.RemainderBP
		totalNumerator += numerator
	}
	if totalRelease*basisPointsDivisor+totalRemainder != totalNumerator {
		t.Errorf("sum(release)*%d + sum(remainder) = %d, want sum(balance*multiplier) = %d",
			basisPointsDivisor, totalRelease*basisPointsDivisor+totalRemainder, totalNumerator)
	}
	if !payoutResult.ReconciledExactly {
		t.Errorf("operator payout --json reported reconciled_exactly=false\nstdout:\n%s", lastStdout)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Requirement 11 (optional, treated as mandatory) — "The provider can
// choose how much storage he wishes to allocate."
// ═══════════════════════════════════════════════════════════════════════

func TestReqD11ProviderAllocationIsHonoured(t *testing.T) {
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	operatorPath := buildOperatorBinary(t)
	deliveryLogPath := filepath.Join(t.TempDir(), "otp-delivery.log")
	ms := startMicroserviceWithFlags(t, ctx, microservicePath, "--otp-delivery-log="+deliveryLogPath)

	// A deliberately distinctive value — nothing else in this suite
	// defaults to it (normalModeStorageGB=25, testDeclaredGB=100) — so a
	// later match is unambiguous evidence of THIS onboarding choice
	// specifically, not a coincidence.
	const chosenStorageGB = 37

	dataDir := t.TempDir()
	listenPort := freePort(t)
	phone := onboardPhoneNumber(0)
	rec := onboardProviderInteractive(t, ctx, providerPath, operatorPath, ms.baseURL, deliveryLogPath, dataDir, phone, listenPort, chosenStorageGB)
	if rec.DeclaredStorageGB != chosenStorageGB {
		t.Fatalf("registration.json declared_storage_gb = %d, want %d (the operator's own onboarding choice)", rec.DeclaredStorageGB, chosenStorageGB)
	}

	inst := startProviderNormalMode(t, ctx, providerPath, ms.baseURL, dataDir, listenPort, chosenStorageGB)

	providerID := pollProviderRegisteredByPhone(t, ctx, db, phone, 3*time.Minute)
	var dbDeclaredGB int
	if err := db.QueryRowContext(ctx, `SELECT declared_storage_gb FROM providers WHERE provider_id = $1`, providerID).Scan(&dbDeclaredGB); err != nil {
		t.Fatalf("query declared_storage_gb for provider %s: %v", providerID, err)
	}
	if dbDeclaredGB != chosenStorageGB {
		t.Fatalf("server-side providers.declared_storage_gb = %d, want %d", dbDeclaredGB, chosenStorageGB)
	}

	// Stop the daemon so `provider inspect` can open the exclusive-locked
	// chunk store and confirm the SAME chosen allocation is what the
	// provider's own local view reports — requirement 11's actual UX: the
	// number governs a real limit (NFR-044/ChunkCeiling), not merely a
	// database column (inspect.go's own header comment).
	killDaemonProcessGroup(inst.cmd)

	inspectCmd := exec.Command(providerPath, "inspect", "--data-dir="+dataDir, "--json")
	inspectOut, err := inspectCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("provider inspect --data-dir=%s: %v\n%s", dataDir, err, inspectOut)
	}
	var inspectResult struct {
		DeclaredStorageGB int   `json:"declared_storage_gb"`
		ChunkCeiling      int64 `json:"chunk_ceiling"`
	}
	lastJSONLine(t, string(inspectOut), &inspectResult)
	if inspectResult.DeclaredStorageGB != chosenStorageGB {
		t.Fatalf("provider inspect --json declared_storage_gb = %d, want %d", inspectResult.DeclaredStorageGB, chosenStorageGB)
	}
	if inspectResult.ChunkCeiling <= 0 {
		t.Errorf("provider inspect --json chunk_ceiling = %d, want > 0 (NFR-044's own ceiling, governed regardless of the chosen allocation)", inspectResult.ChunkCeiling)
	}
}

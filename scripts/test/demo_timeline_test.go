//go:build integration

// Package test drives the full demo lifecycle from mvp.md §3.6 against a
// real, live stack: a real Postgres instance, a real cmd/microservice
// binary, and real cmd/provider processes — no step mocked, stubbed, or
// driven through a parallel code path.
//
// [Live-verification context] Every stage this test drives (registration,
// heartbeat, vetting-chunk assignment, capability-token verification,
// VETTING→ACTIVE, vetting GC delivery, cluster-secret refresh) was, before
// this session, either completely unwired or subtly broken in ways
// invisible to any existing unit test — see the ADR recording the full
// eleven-finding chain (Track: DEMO, so citable here under the demo track's
// frozen ADR ceiling). This test is written against a system now confirmed
// live end-to-end, not against assumptions about how it should behave.
//
// [Scope note — cmd/client] The demo CLI's own ADR specifies that this file
// should eventually drive the real cmd/client binary via --json, so the
// integration test is evidence of the artifact being demonstrated rather
// than of a parallel code path. cmd/client is still an unbuilt stub as of
// this session — the milestone that builds it sits immediately after this
// one in the demo dependency graph. This test therefore drives
// internal/client's SDK packages directly (the same packages cmd/client
// will wrap), matching this milestone's actual position in that sequence.
// Revisiting this file to drive the CLI once it exists is a follow-up, not
// a gap silently left here.
//
// [REF: mvp.md §3.6 (demo timeline), §7 (viability fact-checks); build.md
// Session 16.1.1, 16.1.2]
package test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/masamasaowl/Vyomanaut_V2/internal/client/upload"
	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	"github.com/masamasaowl/Vyomanaut_V2/internal/erasure"
	"github.com/masamasaowl/Vyomanaut_V2/internal/p2p"
)

// ── fixed test parameters (mvp.md §3.6 / §7) ────────────────────────────────

const (
	testSimCount    = 5
	testSimASNCount = 5
	testDeclaredGB  = 100
	testUploadBytes = 1_000_000 // < 1.25 MB, per mvp.md §3.6's own upload-size assertion
)

// ── skip-if-unavailable, matching internal/api/readiness_test.go's own
// established convention for this codebase's live-DB integration tests ────

func liveDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := testDSN("PGMIGRATORUSER", "vyomanaut_migrator", "PGMIGRATORPASSWORD")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("sql.Open failed, skipping live-infra test: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("live Postgres not reachable, skipping live-infra test: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testDSN(userEnvKey, userFallback, passEnvKey string) string {
	host := envOr("PGHOST", "localhost")
	port := envOr("PGPORT", "5432")
	user := envOr(userEnvKey, userFallback)
	password := os.Getenv(passEnvKey)
	dbname := envOr("PGDATABASE", "vyomanaut_test")
	sslmode := envOr("PGSSLMODE", "disable")
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── binary builds ───────────────────────────────────────────────────────────

// buildBinaries compiles cmd/microservice and cmd/provider fresh into a temp
// directory, so this test always exercises the current source tree, not a
// stale pre-built binary. Both take real wall-clock time (a minute or more
// on first run, before the Go build cache is warm) — accepted, since a
// stale binary silently testing yesterday's code is worse than a slow test.
func buildBinaries(t *testing.T) (microservicePath, providerPath string) {
	t.Helper()
	binDir := t.TempDir()
	repoRoot := findRepoRoot(t)

	microservicePath = filepath.Join(binDir, "microservice")
	providerPath = filepath.Join(binDir, "provider")

	build := func(out, pkg string) {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Dir = repoRoot
		cmd.Env = os.Environ()
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", pkg, err, output)
		}
	}
	build(microservicePath, "./cmd/microservice/")
	build(providerPath, "./cmd/provider/")
	return microservicePath, providerPath
}

// findRepoRoot walks up from the working directory to the module root
// (identified by go.mod) — scripts/test/ itself is two directories deep.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root (go.mod) above %s", dir)
		}
		dir = parent
	}
}

// freePort asks the OS for an ephemeral port, then immediately releases it —
// the same brief bind/close race every other test in this codebase's
// cmd/provider package already accepts for the same reason (no OS API
// reserves a port without holding it open).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// ── microservice lifecycle ──────────────────────────────────────────────────

type liveMicroservice struct {
	baseURL     string
	adminAPIKey string
	signingSeed string // hex, VYOMANAUT_MICROSERVICE_SIGNING_SEED (32-byte Ed25519 seed, 64 hex chars)
	clusterSeed string // base64, VYOMANAUT_CLUSTER_MASTER_SEED
}

func startMicroservice(t *testing.T, ctx context.Context, binPath string) *liveMicroservice {
	t.Helper()

	adminKey := randomHex(t, 32)
	signingSeed := randomHex(t, ed25519.SeedSize) // VYOMANAUT_MICROSERVICE_SIGNING_SEED: hex, not base64 — confirmed against cmd/microservice/config_env.go's own field comment ("64 hex chars (32-byte Ed25519 seed)"); caught live, since the two seed env vars use different encodings and an earlier version of this function used base64 for both.
	clusterSeed := randomBase64Seed(t)
	port := freePort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	cmd := exec.CommandContext(ctx, binPath)
	cmd.Env = append(os.Environ(),
		"VYOMANAUT_MODE=demo",
		"PGHOST="+envOr("PGHOST", "localhost"),
		"PGPORT="+envOr("PGPORT", "5432"),
		"PGUSER="+envOr("PGUSER", "vyomanaut_app"),
		"PGPASSWORD="+os.Getenv("PGPASSWORD"),
		"PGDATABASE="+envOr("PGDATABASE", "vyomanaut_test"),
		"PGSSLMODE="+envOr("PGSSLMODE", "disable"),
		"PGMIGRATORUSER="+envOr("PGMIGRATORUSER", "vyomanaut_migrator"),
		"PGMIGRATORPASSWORD="+os.Getenv("PGMIGRATORPASSWORD"),
		"VYOMANAUT_ADMIN_API_KEY="+adminKey,
		"VYOMANAUT_MICROSERVICE_SIGNING_SEED="+signingSeed,
		"VYOMANAUT_CLUSTER_MASTER_SEED="+clusterSeed,
		fmt.Sprintf("VYOMANAUT_HTTP_LISTEN_ADDR=:%d", port),
	)
	logFile, err := os.Create(filepath.Join(t.TempDir(), "microservice.log"))
	if err != nil {
		t.Fatalf("create microservice log file: %v", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		t.Fatalf("start microservice: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	ms := &liveMicroservice{baseURL: baseURL, adminAPIKey: adminKey, signingSeed: signingSeed, clusterSeed: clusterSeed}
	waitForHTTP(t, baseURL+"/api/v1/admin/readiness", 30*time.Second)
	return ms
}

// waitForHTTP polls url until it returns any HTTP response (not connection
// refused) or timeout elapses — the microservice is "up" once its listener
// accepts connections, regardless of what status code an unauthenticated
// request to an admin endpoint returns.
func waitForHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s to accept connections: %v", url, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return hex.EncodeToString(b)
}

func randomBase64Seed(t *testing.T) string {
	t.Helper()
	b := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64Encode(b)
}

func base64Encode(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		chunk := b[i:min(i+3, len(b))]
		var n uint32
		for _, c := range chunk {
			n = n<<8 | uint32(c)
		}
		n <<= uint(8 * (3 - len(chunk)))
		for j := 0; j < 4; j++ {
			if j <= len(chunk) {
				out = append(out, alphabet[(n>>uint(18-6*j))&0x3F])
			} else {
				out = append(out, '=')
			}
		}
	}
	return string(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── OTP flow: send, brute-force-recover the code from its stored hash
// (otp_codes.code_hash is a SHA-256 hash — the plaintext is never persisted
// or logged, even by the demo-mode no-op sender; brute-forcing the 6-digit
// space is fast and is how a test harness with legitimate DB access
// completes this flow, matching what live verification of this exact flow
// established), verify, and return the resulting bearer token ─────────────

func otpVerifyToken(t *testing.T, ctx context.Context, db *sql.DB, baseURL, phoneNumber, purpose string) string {
	t.Helper()

	sendBody, _ := json.Marshal(map[string]string{"phone_number": phoneNumber, "purpose": purpose})
	resp, err := http.Post(baseURL+"/api/v1/auth/otp/send", "application/json", bytes.NewReader(sendBody))
	if err != nil {
		t.Fatalf("otp send: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("otp send: HTTP %d", resp.StatusCode)
	}

	code := recoverOTPCode(t, ctx, db, phoneNumber)

	verifyBody, _ := json.Marshal(map[string]string{"phone_number": phoneNumber, "otp_code": code})
	resp, err = http.Post(baseURL+"/api/v1/auth/otp/verify", "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatalf("otp verify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("otp verify: HTTP %d", resp.StatusCode)
	}
	var respBody struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("decode otp verify response: %v", err)
	}
	return respBody.Token
}

// recoverOTPCode brute-forces the 6-digit code space (1,000,000
// possibilities) against otp_codes.code_hash — fast (well under a second)
// and, for a test harness with legitimate direct DB access, the only way to
// recover the plaintext: it is never persisted anywhere, by design.
func recoverOTPCode(t *testing.T, ctx context.Context, db *sql.DB, phoneNumber string) string {
	t.Helper()
	var hashHex string
	err := db.QueryRowContext(ctx,
		`SELECT encode(code_hash, 'hex') FROM otp_codes WHERE phone_number = $1 ORDER BY created_at DESC LIMIT 1`,
		phoneNumber).Scan(&hashHex)
	if err != nil {
		t.Fatalf("query otp_codes for %s: %v", phoneNumber, err)
	}
	for i := 0; i < 1_000_000; i++ {
		code := fmt.Sprintf("%06d", i)
		if hex.EncodeToString(sha256Sum(code)) == hashHex {
			return code
		}
	}
	t.Fatalf("could not recover OTP code for %s from hash %s", phoneNumber, hashHex)
	return ""
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// ── owner registration + deposit (ADR-064: deposit is a hard prerequisite
// of the demo's first upload, not a production-only nicety — upload is
// gated on escrow balance, and MockProvider.InitiateEscrow credits it
// synchronously in demo mode) ───────────────────────────────────────────

type liveOwner struct {
	ownerID    uuid.UUID
	token      string
	signingKey ed25519.PrivateKey
}

func registerOwner(t *testing.T, ctx context.Context, db *sql.DB, baseURL string) *liveOwner {
	t.Helper()

	regToken := otpVerifyToken(t, ctx, db, baseURL, "+919876520000", "OWNER_REGISTER")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate owner identity: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	signingInput := fmt.Sprintf(`{"ed25519_public_key":"%s"}`, pubHex)
	sig := ed25519.Sign(priv, []byte(signingInput))

	reqBody, _ := json.Marshal(map[string]string{
		"ed25519_public_key": pubHex,
		"owner_sig":          hex.EncodeToString(sig),
	})
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/owner/register", bytes.NewReader(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+regToken)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("owner register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("owner register: HTTP %d", resp.StatusCode)
	}
	var respBody struct {
		OwnerID uuid.UUID `json:"owner_id"`
		Token   string    `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("decode owner register response: %v", err)
	}
	return &liveOwner{ownerID: respBody.OwnerID, token: respBody.Token, signingKey: priv}
}

// depositForOwner credits the owner's escrow balance via the mock payment
// provider (synchronous in demo mode) — required before upload, per ADR-064.
func depositForOwner(t *testing.T, ctx context.Context, baseURL string, owner *liveOwner, amountPaise int64) {
	t.Helper()
	reqBody, _ := json.Marshal(map[string]interface{}{
		"amount_paise":    amountPaise,
		"idempotency_key": randomHex(t, 32),
	})
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/owner/deposit", bytes.NewReader(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+owner.token)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("owner deposit: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner deposit: HTTP %d", resp.StatusCode)
	}
}

// ── provider fleet: testSimCount separate OS processes, each
// --sim-only-index=N with its own OTP-derived registration token —
// required for correct multi-provider registration (single-use tokens),
// not merely for independent kill/departure testing, per live verification
// ───────────────────────────────────────────────────────────────────────

type liveProviders struct {
	cmds       [testSimCount]*exec.Cmd
	simDataDir string
}

func startProviders(t *testing.T, ctx context.Context, db *sql.DB, providerBinPath, microserviceURL string) *liveProviders {
	t.Helper()

	simDataDir := t.TempDir()
	simBasePort := freePort(t)

	lp := &liveProviders{simDataDir: simDataDir}
	for i := 0; i < testSimCount; i++ {
		phone := fmt.Sprintf("+91987653%04d", i)
		token := otpVerifyToken(t, ctx, db, microserviceURL, phone, "PROVIDER_REGISTER")

		cmd := exec.CommandContext(ctx, providerBinPath,
			"--mode=demo",
			"--microservice-url="+microserviceURL,
			fmt.Sprintf("--declared-storage-gb=%d", testDeclaredGB),
			fmt.Sprintf("--sim-count=%d", testSimCount),
			fmt.Sprintf("--sim-asn-count=%d", testSimASNCount),
			fmt.Sprintf("--sim-only-index=%d", i),
			"--sim-data-dir="+simDataDir,
			fmt.Sprintf("--sim-base-port=%d", simBasePort),
			"--registration-bearer-token="+token,
		)
		logFile, err := os.Create(filepath.Join(t.TempDir(), fmt.Sprintf("provider-%d.log", i)))
		if err != nil {
			t.Fatalf("create provider %d log file: %v", i, err)
		}
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		if err := cmd.Start(); err != nil {
			t.Fatalf("start provider %d: %v", i, err)
		}
		lp.cmds[i] = cmd
	}

	t.Cleanup(func() {
		for _, cmd := range lp.cmds {
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		}
	})
	return lp
}

// killProvider terminates exactly one provider process (by --sim-only-index)
// while leaving the other testSimCount-1 running — the mechanism
// --sim-only-index exists for.
func (lp *liveProviders) killProvider(t *testing.T, index int) {
	t.Helper()
	cmd := lp.cmds[index]
	if cmd == nil || cmd.Process == nil {
		t.Fatalf("provider %d is not running", index)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill provider %d: %v", index, err)
	}
	_ = cmd.Wait()
	lp.cmds[index] = nil
}

// ── readiness polling ────────────────────────────────────────────────────

type readinessCondition struct {
	Name          string `json:"name"`
	Satisfied     bool   `json:"satisfied"`
	CurrentValue  int    `json:"current_value"`
	RequiredValue int    `json:"required_value"`
	DemoValue     *int   `json:"demo_value,omitempty"`
}

type readinessConditions struct {
	ActiveVettedProviders    readinessCondition `json:"active_vetted_providers"`
	DistinctASNs             readinessCondition `json:"distinct_asns"`
	DistinctMetroRegions     readinessCondition `json:"distinct_metro_regions"`
	MicroserviceQuorum       readinessCondition `json:"microservice_quorum"`
	RazorpayAccountsReady    readinessCondition `json:"razorpay_accounts_ready"`
	RelayNodesDeployed       readinessCondition `json:"relay_nodes_deployed"`
	ClusterAuditSecretLoaded readinessCondition `json:"cluster_audit_secret_loaded"`
}

type readinessResponse struct {
	AllConditionsMet          bool                `json:"all_conditions_met"`
	Mode                      string              `json:"mode"`
	Conditions                readinessConditions `json:"conditions"`
	ProvidersNearCeilingCount int                 `json:"providers_near_ceiling_count"`
}

// pollReadiness polls GET /api/v1/admin/readiness until all_conditions_met
// or timeout, returning the last response either way so the caller can
// assert on it precisely.
func pollReadiness(t *testing.T, ctx context.Context, baseURL, adminAPIKey string, timeout time.Duration) readinessResponse {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last readinessResponse
	for {
		httpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/admin/readiness", nil)
		httpReq.Header.Set("X-Admin-API-Key", adminAPIKey)
		resp, err := http.DefaultClient.Do(httpReq)
		if err == nil {
			if decErr := json.NewDecoder(resp.Body).Decode(&last); decErr == nil && last.AllConditionsMet {
				_ = resp.Body.Close()
				return last
			}
			_ = resp.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("readiness gate did not pass within %s; last response: %+v", timeout, last)
		}
		time.Sleep(2 * time.Second)
	}
}

// ── upload (internal/client/upload's SDK, directly — see this file's own
// header comment for why, given cmd/client's position in the milestone
// sequence) ─────────────────────────────────────────────────────────────

// uploadTestFile performs a real upload via internal/client/upload's SDK
// (see this file's own header comment for why this drives the SDK directly
// rather than cmd/client) and fails the test if it does not succeed. Used
// after providers are confirmed ACTIVE (ADR-071).
func uploadTestFile(t *testing.T, ctx context.Context, ms *liveMicroservice, owner *liveOwner) uuid.UUID {
	t.Helper()
	fileID, err := uploadTestFileAllowingError(t, ctx, ms, owner)
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}
	return fileID
}

// uploadTestFileAllowingError is uploadTestFile's core: same real upload
// attempt, but returns the error instead of failing the test, so a caller
// expecting rejection (attemptUploadExpectRejected, ADR-071) can inspect it.
func uploadTestFileAllowingError(t *testing.T, ctx context.Context, ms *liveMicroservice, owner *liveOwner) (uuid.UUID, error) {
	t.Helper()

	profile := config.SelectProfile("demo")
	engine, err := erasure.NewEngine(profile)
	if err != nil {
		t.Fatalf("erasure.NewEngine: %v", err)
	}

	clientPort := freePort(t)
	host, err := p2p.NewHost(p2p.HostConfig{
		PrivateKey: owner.signingKey,
		ListenAddr: fmt.Sprintf("0.0.0.0:%d", clientPort),
	})
	if err != nil {
		t.Fatalf("p2p.NewHost (client): %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })

	orch := upload.NewOrchestrator(ms.baseURL, owner.token, http.DefaultClient, host, engine, profile, owner.signingKey, t.TempDir())

	var masterSecret [32]byte
	if _, err := rand.Read(masterSecret[:]); err != nil {
		t.Fatalf("rand.Read masterSecret: %v", err)
	}

	plaintext := make([]byte, testUploadBytes)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read plaintext: %v", err)
	}

	return orch.UploadFile(ctx, masterSecret, owner.ownerID, plaintext)
}

// ── DB-observed progress: audit passes, VETTING→ACTIVE, GC delivery,
// departure, repair — polling the same tables live verification of this
// exact chain already confirmed are the correct signals ────────────────

func pollFirstAuditPass(t *testing.T, ctx context.Context, db *sql.DB, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var count int
		err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM providers WHERE consecutive_audit_passes >= 1`).Scan(&count)
		if err == nil && count > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no provider recorded a first audit PASS within %s", timeout)
		}
		time.Sleep(5 * time.Second)
	}
}

func pollAllProvidersActive(t *testing.T, ctx context.Context, db *sql.DB, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var activeCount int
		err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM providers WHERE status = 'ACTIVE'`).Scan(&activeCount)
		if err == nil && activeCount == testSimCount {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not all %d providers reached ACTIVE within %s (last count: %d)", testSimCount, timeout, activeCount)
		}
		time.Sleep(5 * time.Second)
	}
}

// pollGCDelivered asserts every ACTIVE provider's synthetic vetting chunk
// assignments have moved out of 'ACTIVE' status (DeliverGCInstruction's
// documented post-condition) — the observable signal that vetting GC was
// actually delivered, not merely that the provider transitioned.
func pollGCDelivered(t *testing.T, ctx context.Context, db *sql.DB, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var lingering int
		err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM chunk_assignments ca
JOIN providers p ON p.provider_id = ca.provider_id
WHERE p.status = 'ACTIVE' AND ca.is_vetting_chunk = TRUE AND ca.status = 'ACTIVE'`).Scan(&lingering)
		if err == nil && lingering == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("synthetic vetting chunks still ACTIVE after GC-delivery timeout (%s); lingering=%d", timeout, lingering)
		}
		time.Sleep(5 * time.Second)
	}
}

func pollDeparted(t *testing.T, ctx context.Context, db *sql.DB, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var count int
		err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM providers WHERE status = 'DEPARTED'`).Scan(&count)
		if err == nil && count >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no provider reached DEPARTED within %s", timeout)
		}
		time.Sleep(10 * time.Second)
	}
}

func pollRepairCompleted(t *testing.T, ctx context.Context, db *sql.DB, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var created, completed int
		_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repair_jobs`).Scan(&created)
		_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repair_jobs WHERE status = 'COMPLETED'`).Scan(&completed)
		if created > 0 && completed > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("repair job not created-and-completed within %s (created=%d completed=%d)", timeout, created, completed)
		}
		time.Sleep(10 * time.Second)
	}
}

// ── TestDemoTimeline — Session 16.1.1 ───────────────────────────────────────

func TestDemoTimeline(t *testing.T) {
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()

	microservicePath, providerPath := buildBinaries(t)
	ms := startMicroservice(t, ctx, microservicePath)

	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00) // ₹100,000 in paise — comfortably above any demo storage rate

	providers := startProviders(t, ctx, db, providerPath, ms.baseURL)

	// Assert readiness gate passes within 60s of startup.
	readiness := pollReadiness(t, ctx, ms.baseURL, ms.adminAPIKey, 60*time.Second)

	// Assert ReadinessResponse.mode == "demo" and demo thresholds match the
	// OAS DemoReady example.
	if readiness.Mode != "demo" {
		t.Errorf("readiness mode = %q, want %q", readiness.Mode, "demo")
	}
	// active_vetted_providers.required_value=5 per the OAS DemoReady example.
	assertDemoThreshold(t, "active_vetted_providers", readiness.Conditions.ActiveVettedProviders, 5)
	// distinct_asns.required_value=5 per the OAS DemoReady example.
	assertDemoThreshold(t, "distinct_asns", readiness.Conditions.DistinctASNs, 5)
	// distinct_metro_regions.required_value=1 per the OAS DemoReady example.
	assertDemoThreshold(t, "distinct_metro_regions", readiness.Conditions.DistinctMetroRegions, 1)
	// microservice_quorum.required_value=1 per the OAS DemoReady example.
	assertDemoThreshold(t, "microservice_quorum", readiness.Conditions.MicroserviceQuorum, 1)
	// relay_nodes_deployed.required_value=0 per the OAS DemoReady example.
	assertDemoThreshold(t, "relay_nodes_deployed", readiness.Conditions.RelayNodesDeployed, 0)

	// Assert file upload succeeds for a file ≤ 1.25 MB.
	//
	// [ADR-071 — Design Council verdict] mvp.md §3.6's demo timeline
	// originally placed this upload immediately after the readiness gate
	// (T+01:00), before any provider reaches ACTIVE. That contradicted
	// ADR-030 (Accepted): real shard data is only ever assigned to ACTIVE
	// providers — VETTING providers receive only synthetic chunks, by
	// design, so a departure during vetting (statistically expected; that
	// is the point of vetting) never triggers a real repair cycle. Live
	// verification confirmed the contradiction directly: the general
	// readiness gate reported all_conditions_met=true while the
	// upload-specific capacity check (internal/api/upload.go's
	// eligibleActiveProviderCountAtOrUnder, WHERE status = 'ACTIVE')
	// rejected the same request 19ms later — not a race, two checks
	// consistently asking different questions. The Council's resolution
	// (ADR-071) corrected mvp.md's timeline, not the code: ADR-030's trust
	// boundary is unchanged. This test now asserts BOTH halves of the
	// corrected timeline explicitly: the early attempt fails exactly as
	// designed, and the real attempt succeeds only once providers have
	// earned ACTIVE status.
	attemptUploadExpectRejected(t, ctx, ms, owner)

	// Assert first audit PASS is recorded within 3 minutes.
	pollFirstAuditPass(t, ctx, db, 3*time.Minute)

	// Assert VETTING→ACTIVE transition completes within 12 minutes.
	pollAllProvidersActive(t, ctx, db, 12*time.Minute)

	// Now the real upload — ADR-071's corrected T+10:30: "Real data owner
	// shard assignments begin." Providers are ACTIVE; ADR-030's trust
	// boundary is satisfied; this must succeed.
	fileID := uploadTestFile(t, ctx, ms, owner)
	t.Logf("uploaded file_id=%s", fileID)

	// Assert synthetic chunk GC is delivered after ACTIVE transition.
	pollGCDelivered(t, ctx, db, 2*time.Minute)

	// Kill one simulated daemon; assert departure detection within
	// profile.DepartureThreshold (10 min in demo).
	providers.killProvider(t, 0)
	pollDeparted(t, ctx, db, 11*time.Minute)

	// Assert repair job created and completed.
	pollRepairCompleted(t, ctx, db, 5*time.Minute)
}

// attemptUploadExpectRejected asserts ADR-071's corrected T+01:00 behavior:
// an upload attempted before any provider is ACTIVE is rejected with
// ErrNetworkNotReady (HTTP 503), per ADR-030's trust boundary — not a bug,
// the designed behavior this test now exercises directly instead of
// contradicting.
func attemptUploadExpectRejected(t *testing.T, ctx context.Context, ms *liveMicroservice, owner *liveOwner) {
	t.Helper()
	_, err := uploadTestFileAllowingError(t, ctx, ms, owner)
	if err == nil {
		t.Fatalf("early upload attempt succeeded; expected ErrNetworkNotReady (providers should still be VETTING, ADR-030)")
	}
	if !errors.Is(err, upload.ErrNetworkNotReady) {
		t.Fatalf("early upload attempt failed with unexpected error: %v (want ErrNetworkNotReady)", err)
	}
}

func assertDemoThreshold(t *testing.T, name string, cond readinessCondition, want int) {
	t.Helper()
	if !cond.Satisfied {
		t.Errorf("%s: not satisfied (current=%d required=%d)", name, cond.CurrentValue, cond.RequiredValue)
	}
	if cond.RequiredValue != want {
		t.Errorf("%s: required_value = %d, want %d (OAS DemoReady example)", name, cond.RequiredValue, want)
	}
}

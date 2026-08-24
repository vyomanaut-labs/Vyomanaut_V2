//go:build integration

// Package test — the departure matrix (M17-E Session 17.7.2, ADR-084 §D-4,
// mvp.md §7). Closes F-D-1, the most serious finding on the demo track:
// TestViabilityRepairSucceedsWithTwoOfFiveOffline (demo_timeline_test.go,
// §7.2) ends at pollRepairCompleted — a repair job reaching COMPLETED
// proves the SYSTEM believes it repaired something, not that the file is
// still byte-for-byte retrievable. Every test in this file ends in an
// actual sha256/bytes.Equal comparison against a real retrieve, or (E-1)
// an explicit assertion that no retrieve was ever needed in the first
// place.
//
// Runs at --departure-threshold=90s (Session 17.7.1's own override),
// deliberately NOT config.DemoProfile's real 10-minute constant — ADR-084
// §D-4's own reasoning: 90s gives margin above the derived 70s safety
// floor while keeping this phase's departure-detection waits inside a
// reasonable test budget. DemoProfile itself is never edited (this file
// never touches internal/config/profiles.go); the override is applied
// per-process, at startup, exactly as Session 17.7.1 built it to be.
//
// [REF: ADR-084 §D-4, mvp.md §7.3-§7.6, FR-065; build_M17E.md Phase 17.7
// Session 17.7.2]
package test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/repair"
)

// departureThresholdOverrideFlag is the exact flag this whole file's
// scenarios run under (OVERRIDE_USED_NOT_PROFILE_EDIT's own check) — named
// once, here, rather than repeating the literal string at every
// startMicroserviceWithFlags call site.
const departureThresholdOverrideFlag = "--departure-threshold=90s"

// ═══════════════════════════════════════════════════════════════════════
// The one shared harness helper (task item 2). Every case in this phase
// and Session 17.7.3 goes through departAt — six bespoke setups would
// drift, per this session's own build contract.
// ═══════════════════════════════════════════════════════════════════════

type departPhase string

const (
	phaseVetting     departPhase = "VETTING"
	phaseMidUpload   departPhase = "MID_UPLOAD"
	phasePostUpload  departPhase = "POST_UPLOAD"
	phaseMidRepair   departPhase = "MID_REPAIR"
	phaseMidRetrieve departPhase = "MID_RETRIEVE"
	phaseBurst       departPhase = "BURST"
)

type departMode string

const (
	modeKill   departMode = "KILL"
	modeDepart departMode = "DEPART"
)

// departEnv bundles a running scenario's live infrastructure and the
// scratch fields departAt fills in for its phase — reading env's own
// fields back afterward (rather than a large, phase-varying return tuple)
// is what lets departAt hold a single, fixed 5-parameter signature across
// all six phases.
type departEnv struct {
	db              *sql.DB
	ms              *liveMicroservice
	providers       *liveProviders
	providerBinPath string
	owner           *liveOwner

	// Populated by departAt; read back by the caller after it returns.
	departedIndex       int
	secondDepartedIndex int // BURST and MID_REPAIR only: the second departure (respectively, the burst's own second provider, and MID_REPAIR's own killed replacement)
	fileID              uuid.UUID
	masterSecret        [32]byte
	plaintext           []byte
	uploadErr           error // MID_UPLOAD only: the racing UploadFile call's own outcome
	retrieveErr         error // MID_RETRIEVE only: the racing RetrieveFile call's own outcome
}

// departAt is the one reusable harness helper (task item 2). phase names
// the moment; mode is KILL (ungraceful, SIGKILL) or DEPART (graceful,
// `provider depart`). Every departure case in this phase and 17.7.3 goes
// through this function.
func departAt(t *testing.T, ctx context.Context, env *departEnv, phase departPhase, mode departMode) {
	t.Helper()
	switch phase {
	case phaseVetting:
		departAtVetting(t, ctx, env, mode)
	case phaseMidUpload:
		departAtMidUpload(t, ctx, env, mode)
	case phasePostUpload:
		departAtPostUpload(t, ctx, env, mode)
	case phaseMidRepair:
		departAtMidRepair(t, ctx, env, mode)
	case phaseMidRetrieve:
		departAtMidRetrieve(t, ctx, env, mode)
	case phaseBurst:
		departAtBurst(t, ctx, env, mode)
	default:
		t.Fatalf("departAt: unknown phase %q", phase)
	}
}

// killOrDepart is departAt's shared KILL/DEPART dispatch — every phase
// implementation below calls this exactly once for its chosen provider
// index, rather than each re-deriving its own kill-vs-depart branch.
func killOrDepart(t *testing.T, ctx context.Context, env *departEnv, index int, mode departMode) {
	t.Helper()
	switch mode {
	case modeKill:
		env.providers.killProvider(t, index)
	case modeDepart:
		// Graceful notice first (server records it, releases escrow
		// proactively, queues repair — internal/api/provider.go's
		// HandleDepart) — then the volunteer's own software exits, same
		// as a real departure: `provider depart` is a separate,
		// short-lived CLI invocation (cmd/provider/depart.go), not a
		// signal to the long-running daemon, so the daemon process
		// itself is killed here as a second, explicit step.
		gracefulDepartProvider(t, ctx, env.providerBinPath, env.ms.baseURL, env.providers.simDataDir, index)
		env.providers.killProvider(t, index)
	default:
		t.Fatalf("killOrDepart: unknown mode %q", mode)
	}
}

// departAtVetting (E-1): departs a provider that has never left VETTING —
// no upload has ever happened, so every provider is equally VETTING at
// this point; index 0 is picked only for determinism, not significance.
func departAtVetting(t *testing.T, ctx context.Context, env *departEnv, mode departMode) {
	t.Helper()
	const index = 0
	killOrDepart(t, ctx, env, index, mode)
	env.departedIndex = index
}

// departAtMidUpload (E-2): races a real upload against the departure of
// one of ITS OWN just-assigned holders — "after /upload/assign, before
// all shards transferred" (task item 4's own wording) is a window with no
// existing hook to pause inside, so this drives the real upload in a
// goroutine and polls chunk_assignments for the first row belonging to
// this owner's newest file, then kills/departs that specific holder as
// fast as possible. Genuinely racy by construction — see this file's
// header note and the package-level "expect findings" comment on
// TestDepartureMidUploadLeavesNoHalfRegisteredFile below.
func departAtMidUpload(t *testing.T, ctx context.Context, env *departEnv, mode departMode) {
	t.Helper()

	host, engine := newClientHostAndEngine(t, env.owner)

	type uploadOutcome struct {
		fileID       uuid.UUID
		masterSecret [32]byte
		plaintext    []byte
		err          error
	}
	resultCh := make(chan uploadOutcome, 1)
	go func() {
		fileID, masterSecret, plaintext, err := uploadTestFileTrackedAllowingError(ctx, env.ms, env.owner, host, engine, testUploadBytes)
		resultCh <- uploadOutcome{fileID, masterSecret, plaintext, err}
	}()

	holderProviderID, fileIDSeen, pollErr := pollFirstChunkAssignmentHolder(ctx, env.db, env.owner.ownerID, 90*time.Second)
	if pollErr != nil {
		// The race-detection poll itself timed out — before failing the
		// test, check whether the racing upload goroutine has ALREADY
		// finished (successfully or not): if so, its own error is the
		// actual root cause (e.g. a readiness/escrow rejection that meant
		// /upload/assign was never reached at all, which is a real upload
		// failure, not a race-timing problem), and reporting it is far
		// more useful than a bare "no row appeared." diagnoseUploadFailure
		// additionally captures the live readiness/ASN-distribution state
		// at this moment, since the SDK itself discards the server's
		// specific error_code for any HTTP 503 (internal/client/upload/
		// assign.go's requestAssignment maps ALL of NETWORK_NOT_READY,
		// INSUFFICIENT_ASN_DIVERSITY, and INSUFFICIENT_PROVIDER_CAPACITY
		// to the one ErrNetworkNotReady sentinel) — this is the only way
		// to see which of the three actually fired without touching that
		// production file, which is outside this session's own FILES list.
		select {
		case result := <-resultCh:
			t.Fatalf("pollFirstChunkAssignmentHolder: %v — and the racing upload had already finished with fileID=%s err=%v (this looks like an upload failure, not a race-timing issue)\n%s",
				pollErr, result.fileID, result.err, diagnoseUploadFailure(ctx, env.db, env.ms))
		default:
			t.Fatalf("pollFirstChunkAssignmentHolder: %v — the racing upload has not finished either\n%s", pollErr, diagnoseUploadFailure(ctx, env.db, env.ms))
		}
	}
	index := providerIndexForID(t, ctx, env.db, holderProviderID)
	killOrDepart(t, ctx, env, index, mode)
	env.departedIndex = index

	result := <-resultCh
	env.fileID = result.fileID
	if env.fileID == uuid.Nil {
		// UploadFile itself never returned a fileID (e.g. it failed before
		// reaching that point) — fall back to the file_id the race-poll
		// above already observed via createPlaceholderFile's own row, so
		// the DB-invariant assertion still has a file to check against.
		env.fileID = fileIDSeen
	}
	env.masterSecret = result.masterSecret
	env.plaintext = result.plaintext
	env.uploadErr = result.err
}

// departAtPostUpload (E-3): the file already exists and is fully assigned
// — env.fileID/masterSecret/plaintext must already be set by the caller
// (via uploadTestFileTracked) before calling departAt with this phase.
// Departs a provider that actually holds a real shard of THIS file — an
// uninvolved provider's departure would prove nothing about this file's
// own survivability.
func departAtPostUpload(t *testing.T, ctx context.Context, env *departEnv, mode departMode) {
	t.Helper()
	if env.fileID == uuid.Nil {
		t.Fatalf("departAtPostUpload: env.fileID is not set — call uploadTestFileTracked and populate env before departAt(phasePostUpload)")
	}
	index := firstRealChunkHolderIndex(t, ctx, env.db, env.fileID)
	killOrDepart(t, ctx, env, index, mode)
	env.departedIndex = index
}

// departAtMidRepair (E-4, Session 17.7.3): departs a real holder to
// trigger repair, then races to depart the SELECTED REPLACEMENT while
// ExecuteRepairJob (internal/repair/executor.go) is still blocked inside
// its own uploadShard call — a single, synchronous, blocking network
// operation, not a long-lived async state. preRegisterChunkAssignment
// writes the replacement's chunk_assignments row (status='REPAIRING')
// BEFORE uploadShard is attempted, which is this race's own detection
// signal: as soon as that row appears for a DIFFERENT provider than the
// one that just departed, its holder is killed immediately. High-risk by
// construction — the window is however long a single ~256KB localhost
// shard transfer takes.
func departAtMidRepair(t *testing.T, ctx context.Context, env *departEnv, mode departMode) {
	t.Helper()
	if env.fileID == uuid.Nil {
		t.Fatalf("departAtMidRepair: env.fileID is not set")
	}
	holderIndex := firstRealChunkHolderIndex(t, ctx, env.db, env.fileID)
	holderProviderID := providerIDForIndex(t, ctx, env.db, holderIndex)
	chunkID := chunkHeldByProviderForFile(t, ctx, env.db, env.fileID, holderProviderID)

	killOrDepart(t, ctx, env, holderIndex, mode)
	env.departedIndex = holderIndex

	// [Fixed — test-harness bug, live verification] Was 90s. The
	// dominant latency here is NOT repair execution — the repair
	// executor loop polls every repairExecutorIdleBackoff (2s,
	// cmd/microservice/repair_loop.go) — it is the ORIGINAL holder's
	// OWN departure being DETECTED in the first place: up to
	// --departure-threshold (90s override, ADR-084 D-4) plus one more
	// DeparturePollingInterval (30s) before repair is even enqueued.
	// 90s gave zero margin for that detection latency alone, let alone
	// the repair execution afterward — confirmed live: this poll timed
	// out with no row ever appearing, not because the mechanism failed,
	// but because the window couldn't possibly contain the detection
	// step it was implicitly assuming had already happened. 4 minutes
	// matches this file's own established margin for the same
	// detection latency elsewhere (pollDeparted's 3-minute budget)
	// plus headroom for the repair itself.
	replacementProviderID := pollReplacementAssignment(t, ctx, env.db, chunkID, holderProviderID, 4*time.Minute)
	replacementIndex := providerIndexForID(t, ctx, env.db, replacementProviderID)
	// Always a hard KILL for the replacement: it never had the chance to
	// depart gracefully — it is being interrupted mid-transfer, by this
	// phase's own construction, regardless of what mode the ORIGINAL
	// holder departed under.
	env.providers.killProvider(t, replacementIndex)
	env.secondDepartedIndex = replacementIndex
}

// departAtMidRetrieve (E-5, Session 17.7.3): departs a real holder while a
// real RetrieveFile call is in flight. Unlike MID_UPLOAD, there is no
// database write to poll for — retrieval is a pure P2P read
// (internal/client/retrieve's own orchestrator never writes to
// chunk_assignments or any other table) — so this uses a small, fixed
// delay instead of a poll, an honest engineering judgment call rather
// than a precisely-timed hook (this function's own header note). At
// DataShards=3 of TotalShards=5, retrieval is designed to gather k=3 from
// whichever holders respond, so the exact millisecond timing of the kill
// relative to any one holder's own shard fetch matters less than for
// MID_UPLOAD/MID_REPAIR: what this phase actually proves is that losing a
// holder DURING an in-flight retrieve doesn't corrupt or abort it.
func departAtMidRetrieve(t *testing.T, ctx context.Context, env *departEnv, mode departMode) {
	t.Helper()
	if env.fileID == uuid.Nil {
		t.Fatalf("departAtMidRetrieve: env.fileID is not set")
	}
	index := firstRealChunkHolderIndex(t, ctx, env.db, env.fileID)
	host, engine := newClientHostAndEngine(t, env.owner)

	type retrieveOutcome struct {
		plaintext []byte
		err       error
	}
	resultCh := make(chan retrieveOutcome, 1)
	go func() {
		plaintext, err := retrieveTestFileTrackedAllowingError(ctx, env.ms, env.owner, host, engine, env.masterSecret, env.fileID)
		resultCh <- retrieveOutcome{plaintext, err}
	}()

	const midRetrieveKillDelay = 20 * time.Millisecond
	time.Sleep(midRetrieveKillDelay)
	killOrDepart(t, ctx, env, index, mode)
	env.departedIndex = index

	result := <-resultCh
	env.plaintext = result.plaintext
	env.retrieveErr = result.err
}

// departAtBurst (E-6, Session 17.7.3): departs two real holders of the
// same file back-to-back, with no delay between the two killOrDepart
// calls — both SIGKILLs execute within milliseconds of each other, both
// are silent until DepartureThreshold elapses for each independently, so
// sequential calls with no artificial gap are indistinguishable in
// practice from a genuinely simultaneous burst for this test's own
// purposes. realChunkHolderIndices (not firstRealChunkHolderIndex, called
// twice) is used deliberately: a provider's own chunk_assignments row
// does not change status the instant it is SIGKILLed — a second
// first-holder query issued right after the first kill could return the
// SAME provider again, since nothing in the database has changed yet.
func departAtBurst(t *testing.T, ctx context.Context, env *departEnv, mode departMode) {
	t.Helper()
	if env.fileID == uuid.Nil {
		t.Fatalf("departAtBurst: env.fileID is not set")
	}
	const burstDepartureCount = 2
	indices := realChunkHolderIndices(t, ctx, env.db, env.fileID, burstDepartureCount)
	killOrDepart(t, ctx, env, indices[0], mode)
	killOrDepart(t, ctx, env, indices[1], mode)
	env.departedIndex = indices[0]
	env.secondDepartedIndex = indices[1]
}

// pollFirstChunkAssignmentHolder polls for the first chunk_assignments row
// (real, non-vetting) belonging to any file owned by ownerID, returning
// its provider_id and file_id as soon as one appears, or a non-nil error
// on timeout (returned rather than calling t.Fatalf directly, so
// departAtMidUpload can inspect the racing upload goroutine's own outcome
// first — see that function's own comment on why). This is the
// MID_UPLOAD race's own detection signal: assignSegment
// (internal/api/upload.go) inserts these rows with status='ACTIVE' at
// /upload/assign time, before any shard data has actually been
// transferred to the provider — confirmed by reading that INSERT
// directly, not inferred.
func pollFirstChunkAssignmentHolder(ctx context.Context, db *sql.DB, ownerID uuid.UUID, timeout time.Duration) (providerID, fileID uuid.UUID, err error) {
	deadline := time.Now().Add(timeout)
	for {
		queryErr := db.QueryRowContext(ctx, `
			SELECT ca.provider_id, s.file_id
			FROM chunk_assignments ca
			JOIN segments s ON s.segment_id = ca.segment_id
			JOIN files f ON f.file_id = s.file_id
			WHERE f.owner_id = $1 AND ca.is_vetting_chunk = FALSE
			ORDER BY ca.created_at ASC
			LIMIT 1`, ownerID).Scan(&providerID, &fileID)
		if queryErr == nil {
			return providerID, fileID, nil
		}
		if time.Now().After(deadline) {
			return uuid.UUID{}, uuid.UUID{}, fmt.Errorf("no chunk_assignments row appeared for owner %s within %s: %w", ownerID, timeout, queryErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// diagnoseUploadFailure captures the live system state a failed upload
// attempt cannot itself report — the SDK discards the server's specific
// error_code for any HTTP 503 (see this file's own call-site comment on
// why) — so this queries GET /api/v1/admin/readiness for the full
// condition-by-condition breakdown, and providers/chunk_assignments
// directly for the live ASN distribution, giving a direct answer to
// "which of NETWORK_NOT_READY / INSUFFICIENT_ASN_DIVERSITY /
// INSUFFICIENT_PROVIDER_CAPACITY actually fired" without needing to
// instrument or guess at the production SDK/handler code.
func diagnoseUploadFailure(ctx context.Context, db *sql.DB, ms *liveMicroservice) string {
	var b strings.Builder
	fmt.Fprintf(&b, "── diagnostic snapshot at failure time ──\n")

	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, ms.baseURL+"/api/v1/admin/readiness", nil)
	httpReq.Header.Set("X-Admin-API-Key", ms.adminAPIKey)
	if resp, err := http.DefaultClient.Do(httpReq); err != nil {
		fmt.Fprintf(&b, "GET /api/v1/admin/readiness: %v\n", err)
	} else {
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(&b, "GET /api/v1/admin/readiness (HTTP %d):\n%s\n", resp.StatusCode, raw)
	}

	rows, err := db.QueryContext(ctx, `
		SELECT asn, COUNT(*) FILTER (WHERE status = 'ACTIVE') AS active_count
		FROM providers GROUP BY asn ORDER BY asn`)
	if err != nil {
		fmt.Fprintf(&b, "query providers by ASN: %v\n", err)
	} else {
		defer func() { _ = rows.Close() }()
		fmt.Fprintf(&b, "live ASN distribution (ACTIVE providers):\n")
		for rows.Next() {
			var asn string
			var count int
			if err := rows.Scan(&asn, &count); err == nil {
				fmt.Fprintf(&b, "  %s: %d active\n", asn, count)
			}
		}
	}

	var overCeilingCount int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT provider_id FROM chunk_assignments
			WHERE is_vetting_chunk = FALSE AND status IN ('ACTIVE', 'REPAIRING')
			GROUP BY provider_id HAVING COUNT(*) >= 1
		) x`).Scan(&overCeilingCount); err == nil {
		fmt.Fprintf(&b, "providers already holding >=1 real chunk: %d\n", overCeilingCount)
	}

	return b.String()
}

// ═══════════════════════════════════════════════════════════════════════
// E-1 — TestDepartureDuringVettingProducesNoRepairJobs
// ═══════════════════════════════════════════════════════════════════════

// TestDepartureDuringVettingProducesNoRepairJobs (E-1, FR-065): a provider
// that departs while still VETTING has only synthetic chunks — no real
// file has ever been assigned to it (ADR-030's trust boundary). Departure
// must soft-delete those synthetic chunks and create ZERO repair jobs, and
// must not seize escrow beyond whatever penalty is actually specified (a
// VETTING provider has no real earnings yet, so processDeparture's own
// sealedBalance>0 guard should mean no seizure at all here).
func TestDepartureDuringVettingProducesNoRepairJobs(t *testing.T) {
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	ms := startMicroserviceWithFlags(t, ctx, microservicePath, departureThresholdOverrideFlag)
	providers := startProviders(t, ctx, db, providerPath, ms.baseURL)

	// [Fixed — test-harness bug] wait for provider index 0's own row to
	// actually exist before departing it — see pollProviderRegistered's
	// own doc comment (helpers_test.go) for why this is necessary and why
	// it replaces the pollReadiness call this line used to have, rather
	// than nothing at all.
	pollProviderRegistered(t, ctx, db, 0, 60*time.Second)

	env := &departEnv{db: db, ms: ms, providers: providers, providerBinPath: providerPath}
	departAt(t, ctx, env, phaseVetting, modeKill)

	pollDeparted(t, ctx, db, 1, 3*time.Minute)

	// FR-065: zero repair jobs, ever — not merely zero completed ones.
	var repairJobCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repair_jobs`).Scan(&repairJobCount); err != nil {
		t.Fatalf("count repair_jobs: %v", err)
	}
	if repairJobCount != 0 {
		t.Errorf("repair_jobs count = %d, want 0 (FR-065: a VETTING departure must never enqueue real-shard repair)", repairJobCount)
	}

	// Synthetic vetting chunks soft-deleted: no lingering ACTIVE vetting
	// assignment for the departed provider (DeleteVettingChunksOnDeparture's
	// own documented post-condition, internal/repair/departure.go).
	var departedProviderID uuid.UUID
	if err := db.QueryRowContext(ctx, `SELECT provider_id FROM providers WHERE status = 'DEPARTED' LIMIT 1`).Scan(&departedProviderID); err != nil {
		t.Fatalf("find departed provider: %v", err)
	}
	var lingeringVettingChunks int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM chunk_assignments
		WHERE provider_id = $1 AND is_vetting_chunk = TRUE AND status = 'ACTIVE'`,
		departedProviderID).Scan(&lingeringVettingChunks); err != nil {
		t.Fatalf("count lingering vetting chunks: %v", err)
	}
	if lingeringVettingChunks != 0 {
		t.Errorf("departed provider still has %d ACTIVE synthetic vetting chunk(s), want 0 (soft-delete did not happen)", lingeringVettingChunks)
	}

	// No escrow seizure beyond the specified penalty: a VETTING provider
	// has accrued no real earnings, so processDeparture's own
	// sealedBalance>0 guard means escrow_events should hold nothing for
	// this provider at all.
	var escrowEventCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM escrow_events WHERE provider_id = $1`, departedProviderID).Scan(&escrowEventCount); err != nil {
		t.Fatalf("count escrow_events: %v", err)
	}
	if escrowEventCount != 0 {
		t.Errorf("escrow_events count for departed VETTING provider = %d, want 0 (no seizure beyond the specified penalty — a VETTING provider has no sealed balance to seize)", escrowEventCount)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// E-2 — TestDepartureMidUploadLeavesNoHalfRegisteredFile
// ═══════════════════════════════════════════════════════════════════════

// TestDepartureMidUploadLeavesNoHalfRegisteredFile (E-2, high-risk): kills
// a provider after /upload/assign returns but before all shards have
// necessarily finished transferring. The upload itself may fail (an IC
// §14 error code) or may complete across the surviving set — either is
// acceptable. What is NOT acceptable, and what this test actually asserts
// against the database directly rather than the CLI/SDK's own exit code:
// a files row whose registration state (pointer_ciphertext non-empty,
// meaning the owner was told the upload succeeded) disagrees with what
// chunk_assignments actually shows being held for it.
//
// Expect findings. This window — assign returned, shards mid-flight — has
// never been exercised by any test before this session. If this fails,
// the failure is this session's product: file it as F-17E-nn, draft the
// corrective ADR, and do not weaken this assertion to make the session
// close (this file's own package header, and task item 4's own note).
func TestDepartureMidUploadLeavesNoHalfRegisteredFile(t *testing.T) {
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	ms := startMicroserviceWithFlags(t, ctx, microservicePath, departureThresholdOverrideFlag)
	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00)
	providers := startProviders(t, ctx, db, providerPath, ms.baseURL)
	pollReadiness(t, ctx, ms.baseURL, ms.adminAPIKey, 12*time.Minute) // [Fixed — F-17E-01] was 60s; see TestDemoTimeline's identical fix note (demo_timeline_test.go)
	pollFirstAuditPass(t, ctx, db, 3*time.Minute)
	pollAllProvidersActive(t, ctx, db, 15*time.Minute) // [Bumped 12->15min, F-17E-08] see demo_timeline_test.go:TestViabilityActiveTransitionAtTenMinutes for the arithmetic

	env := &departEnv{db: db, ms: ms, providers: providers, providerBinPath: providerPath, owner: owner}
	departAt(t, ctx, env, phaseMidUpload, modeKill)

	t.Logf("mid-upload departure: killed provider index=%d, file_id=%s, upload error=%v", env.departedIndex, env.fileID, env.uploadErr)

	if env.fileID == uuid.Nil {
		// /upload/assign itself never even got far enough to create a
		// files row (createPlaceholderFile, internal/api/upload.go) —
		// nothing to check the invariant against, and no half-registered
		// state is possible if no row exists at all.
		t.Logf("no files row was ever created for this attempt — nothing to check the registration invariant against")
		return
	}

	// The invariant itself — files.pointer_ciphertext registered implies
	// every segment's chunk_assignments actually holds >= DataShards live
	// shards — is asserted directly against chunk_assignments below, not
	// merely against the upload call's own exit status.
	assertNoHalfRegisteredFile(t, ctx, db, env.fileID)
}

// assertNoHalfRegisteredFile is E-2's own core invariant, queried directly
// against the database rather than through the CLI/SDK's exit code (task
// item 4's own explicit requirement): if files.pointer_ciphertext is
// non-empty (register/commit completed — file.go's own documented
// "pointer_ciphertext's emptiness is the not-yet-registered signal"), then
// every segment of that file must have at least profile.DataShards ACTIVE
// or REPAIRING real chunk_assignments — otherwise the owner has been told
// the upload succeeded while the underlying data is not actually durable.
func assertNoHalfRegisteredFile(t *testing.T, ctx context.Context, db *sql.DB, fileID uuid.UUID) {
	t.Helper()

	var pointerCiphertext []byte
	if err := db.QueryRowContext(ctx, `SELECT pointer_ciphertext FROM files WHERE file_id = $1`, fileID).Scan(&pointerCiphertext); err != nil {
		t.Fatalf("assertNoHalfRegisteredFile: query files row for %s: %v", fileID, err)
	}
	registered := len(pointerCiphertext) > 0
	t.Logf("file %s: registered=%v (pointer_ciphertext length=%d)", fileID, registered, len(pointerCiphertext))
	if !registered {
		// Never reached register/commit — an incomplete-but-honestly-incomplete
		// upload, not a half-registered one. Nothing further to assert.
		return
	}

	rows, err := db.QueryContext(ctx, `
		SELECT s.segment_id,
		       COUNT(*) FILTER (WHERE ca.status IN ('ACTIVE', 'REPAIRING')) AS available_shard_count
		FROM segments s
		LEFT JOIN chunk_assignments ca ON ca.segment_id = s.segment_id AND ca.is_vetting_chunk = FALSE
		WHERE s.file_id = $1
		GROUP BY s.segment_id`, fileID)
	if err != nil {
		t.Fatalf("assertNoHalfRegisteredFile: query segment shard counts: %v", err)
	}
	defer func() { _ = rows.Close() }()

	segmentCount := 0
	for rows.Next() {
		var segmentID uuid.UUID
		var availableShardCount int
		if err := rows.Scan(&segmentID, &availableShardCount); err != nil {
			t.Fatalf("assertNoHalfRegisteredFile: scan segment shard count: %v", err)
		}
		segmentCount++
		t.Logf("file %s segment %s: available_shard_count(chunk_assignments) = %d", fileID, segmentID, availableShardCount)
		if availableShardCount < demoDataShards {
			t.Errorf("file %s is registered (pointer_ciphertext non-empty) but segment %s has only %d available shard(s) in chunk_assignments, want >= %d (DataShards) — a HALF-REGISTERED FILE: the owner was told this upload succeeded, but the underlying data cannot actually be reconstructed",
				fileID, segmentID, availableShardCount, demoDataShards)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("assertNoHalfRegisteredFile: iterate segments: %v", err)
	}
	if segmentCount == 0 {
		t.Errorf("file %s is registered (pointer_ciphertext non-empty) but has ZERO segments — a HALF-REGISTERED FILE if there ever was one", fileID)
	}
}

// demoDataShards mirrors config.DemoProfile.DataShards's own value (3) —
// duplicated as a plain int here rather than importing internal/config
// solely for this one field, matching this package's own existing
// duplication discipline (see providerSimDataDir's neighbours in
// helpers_test.go). Confirmed against config.DemoProfile directly, not
// assumed: internal/config/profiles.go's DemoProfile literal.
const demoDataShards = 3

// ═══════════════════════════════════════════════════════════════════════
// E-3 — TestDepartureAfterUploadFileStillRetrievable (F-D-1's own case)
// ═══════════════════════════════════════════════════════════════════════

// runDepartureAfterUpload is E-3's own scenario, factored out so both the
// KILL and DEPART runs (task item 5: "run E-3 twice") share one
// implementation rather than two near-identical test bodies drifting
// apart from each other.
func runDepartureAfterUpload(t *testing.T, mode departMode) {
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	ms := startMicroserviceWithFlags(t, ctx, microservicePath, departureThresholdOverrideFlag)
	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00)
	providers := startProviders(t, ctx, db, providerPath, ms.baseURL)
	pollReadiness(t, ctx, ms.baseURL, ms.adminAPIKey, 12*time.Minute) // [Fixed — F-17E-01] was 60s; see TestDemoTimeline's identical fix note (demo_timeline_test.go)
	pollFirstAuditPass(t, ctx, db, 3*time.Minute)
	pollAllProvidersActive(t, ctx, db, 15*time.Minute) // [Bumped 12->15min, F-17E-08] see demo_timeline_test.go:TestViabilityActiveTransitionAtTenMinutes for the arithmetic

	fileID, masterSecret, plaintext := uploadTestFileTracked(t, ctx, ms, owner, testUploadBytes)
	wantHash := sha256.Sum256(plaintext)
	t.Logf("uploaded file_id=%s (%d bytes)", fileID, len(plaintext))

	env := &departEnv{
		db: db, ms: ms, providers: providers, providerBinPath: providerPath, owner: owner,
		fileID: fileID, masterSecret: masterSecret, plaintext: plaintext,
	}
	departAt(t, ctx, env, phasePostUpload, mode)
	t.Logf("departed provider index=%d (mode=%s)", env.departedIndex, mode)

	pollDeparted(t, ctx, db, 1, 3*time.Minute)
	pollRepairCompleted(t, ctx, db, 1, 5*time.Minute)

	got := retrieveTestFileTracked(t, ctx, ms, owner, masterSecret, fileID)
	gotHash := sha256.Sum256(got)

	if !bytes.Equal(gotHash[:], wantHash[:]) {
		t.Fatalf("retrieved content does not match: sha256(retrieved)=%x, sha256(original)=%x", gotHash, wantHash)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("retrieved content differs from original byte-for-byte, despite matching sha256 (should be unreachable)")
	}
}

// TestDepartureAfterUploadFileStillRetrievable (E-3, the F-D-1 case):
// upload -> sha256 -> kill -> pollDeparted -> pollRepairCompleted ->
// retrieve -> sha256 -> bytes.Equal.
func TestDepartureAfterUploadFileStillRetrievable(t *testing.T) {
	runDepartureAfterUpload(t, modeKill)
}

// TestDepartureAfterUploadFileStillRetrievableGraceful is E-3's own second
// run (task item 5: "Run E-3 twice: once KILL, once DEPART. Both
// departure paths must end in a retrievable file, or requirement 7 is
// only half true.").
func TestDepartureAfterUploadFileStillRetrievableGraceful(t *testing.T) {
	runDepartureAfterUpload(t, modeDepart)
}

// ═══════════════════════════════════════════════════════════════════════
// TestReqD07 — task item 6: delegates to the E-3 helper; referenced (not
// re-implemented) by Session 17.8.2.
// ═══════════════════════════════════════════════════════════════════════

// TestReqD07FileRetrievableAfterProviderLossAndRepair is requirement 7's
// own named integration test (build.md's "eleven founding requirements
// each acquire a named integration test" — ADR-084's Consequences
// section). Delegates entirely to runDepartureAfterUpload — the SAME
// scenario TestDepartureAfterUploadFileStillRetrievable already proves —
// rather than re-implementing it a third time; Session 17.8.2 references
// this test by name, not by copying its body.
func TestReqD07FileRetrievableAfterProviderLossAndRepair(t *testing.T) {
	// Delegates to runDepartureAfterUpload, which calls departAt
	// (phasePostUpload) and then performs a real "retrieve" compared
	// byte-for-byte against what was uploaded — see that function's own
	// body for the full sequence this test is named for.
	runDepartureAfterUpload(t, modeKill)
}

// ═══════════════════════════════════════════════════════════════════════
// E-4 — TestReplacementProviderDepartsMidRepair (Session 17.7.3)
// ═══════════════════════════════════════════════════════════════════════

// TestReplacementProviderDepartsMidRepair (E-4, high-risk): a real holder
// departs, triggering repair; the SELECTED REPLACEMENT is then killed
// while its own upload is still in flight (departAtMidRepair). The job
// must be re-queued to a NEW replacement, not left stuck — asserted
// against repair.RepairPromotionTimeout(profile) (3 minutes in demo)
// rather than an arbitrary wait, per task item 1's own requirement.
//
// [Flag, read directly from internal/repair/executor.go, not inferred]
// ExecuteRepairJob's own replacement-retry loop only retries on
// ErrReplacementStorageFull (the M9 review's "Optional Fix A"); any OTHER
// uploadShard failure — including a plain network failure from a
// SIGKILLed replacement, which is exactly what this test causes — calls
// MarkJobComplete(ctx, db, job.JobID, false) and returns immediately, with
// no further retry attempted on that code path. Whether "the job must be
// re-queued to a new replacement" (task item 1) is actually true today, or
// is this session's own second finding (after Session 17.7.2's E-2), is
// exactly what this test determines — the assertion below is not weakened
// either way.
func TestReplacementProviderDepartsMidRepair(t *testing.T) {
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	ms := startMicroserviceWithFlags(t, ctx, microservicePath, departureThresholdOverrideFlag)
	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00)
	providers := startProviders(t, ctx, db, providerPath, ms.baseURL)
	pollReadiness(t, ctx, ms.baseURL, ms.adminAPIKey, 12*time.Minute) // [Fixed — F-17E-01] was 60s; see TestDemoTimeline's identical fix note (demo_timeline_test.go)
	pollFirstAuditPass(t, ctx, db, 3*time.Minute)
	pollAllProvidersActive(t, ctx, db, 15*time.Minute) // [Bumped 12->15min, F-17E-08] see demo_timeline_test.go:TestViabilityActiveTransitionAtTenMinutes for the arithmetic

	profile := config.SelectProfile("demo")
	fileID, masterSecret, plaintext := uploadTestFileTracked(t, ctx, ms, owner, testUploadBytes)
	wantHash := sha256.Sum256(plaintext)
	t.Logf("uploaded file_id=%s", fileID)

	env := &departEnv{
		db: db, ms: ms, providers: providers, providerBinPath: providerPath, owner: owner,
		fileID: fileID, masterSecret: masterSecret, plaintext: plaintext,
	}
	departAt(t, ctx, env, phaseMidRepair, modeKill)
	t.Logf("departed original holder index=%d; replacement killed mid-transfer index=%d", env.departedIndex, env.secondDepartedIndex)

	pollDeparted(t, ctx, db, 1, 3*time.Minute)

	// repair.RepairPromotionTimeout(profile) itself governs a DIFFERENT
	// thing server-side (PRE_WARNING -> PERMANENT_DEPARTURE priority
	// promotion, queue.go's own doc comment) — it is used HERE only as
	// this test's own real, profile-derived poll budget (task item 1's
	// own wording: "assert against RepairPromotionTimeout... rather than
	// an arbitrary wait"), doubled for slack beyond the bare timeout
	// value itself.
	const repairPromotionBudgetMultiplier = 2
	pollRepairCompleted(t, ctx, db, 1, repair.RepairPromotionTimeout(profile)*repairPromotionBudgetMultiplier)

	got := retrieveTestFileTracked(t, ctx, ms, owner, masterSecret, fileID)
	gotHash := sha256.Sum256(got)
	if !bytes.Equal(gotHash[:], wantHash[:]) {
		t.Fatalf("retrieved content does not match: sha256(retrieved)=%x, sha256(original)=%x", gotHash, wantHash)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("retrieved content differs from original byte-for-byte, despite matching sha256 (should be unreachable)")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// E-5 — TestDepartureMidRetrievalStillGathersK (Session 17.7.3)
// ═══════════════════════════════════════════════════════════════════════

// TestDepartureMidRetrievalStillGathersK (E-5, high-risk): departs one of
// a file's five real holders while a real retrieve is in flight
// (departAtMidRetrieve). With DataShards=3 of TotalShards=5, retrieval
// must still gather k=3 from the surviving four holders and reconstruct
// byte-identical content.
func TestDepartureMidRetrievalStillGathersK(t *testing.T) {
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	ms := startMicroserviceWithFlags(t, ctx, microservicePath, departureThresholdOverrideFlag)
	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00)
	providers := startProviders(t, ctx, db, providerPath, ms.baseURL)
	pollReadiness(t, ctx, ms.baseURL, ms.adminAPIKey, 12*time.Minute) // [Fixed — F-17E-01] was 60s; see TestDemoTimeline's identical fix note (demo_timeline_test.go)
	pollFirstAuditPass(t, ctx, db, 3*time.Minute)
	pollAllProvidersActive(t, ctx, db, 15*time.Minute) // [Bumped 12->15min, F-17E-08] see demo_timeline_test.go:TestViabilityActiveTransitionAtTenMinutes for the arithmetic

	fileID, masterSecret, plaintext := uploadTestFileTracked(t, ctx, ms, owner, testUploadBytes)
	wantHash := sha256.Sum256(plaintext)
	t.Logf("uploaded file_id=%s", fileID)

	env := &departEnv{
		db: db, ms: ms, providers: providers, providerBinPath: providerPath, owner: owner,
		fileID: fileID, masterSecret: masterSecret, plaintext: plaintext,
	}
	departAt(t, ctx, env, phaseMidRetrieve, modeKill)
	t.Logf("departed holder index=%d mid-retrieve; retrieve error=%v", env.departedIndex, env.retrieveErr)

	if env.retrieveErr != nil {
		t.Fatalf("retrieve failed despite DataShards=%d of TotalShards=5 remaining after losing 1 holder: %v", demoDataShards, env.retrieveErr)
	}
	gotHash := sha256.Sum256(env.plaintext)
	if !bytes.Equal(gotHash[:], wantHash[:]) {
		t.Fatalf("retrieved content does not match: sha256(retrieved)=%x, sha256(original)=%x", gotHash, wantHash)
	}
	if !bytes.Equal(env.plaintext, plaintext) {
		t.Fatalf("retrieved content differs from original byte-for-byte, despite matching sha256 (should be unreachable)")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// E-6 — TestTwoConcurrentDeparturesAtEmergencyFloor (Session 17.7.3)
// ═══════════════════════════════════════════════════════════════════════

// TestTwoConcurrentDeparturesAtEmergencyFloor (E-6): two real holders
// depart together (departAtBurst), leaving s=DataShards=3 exactly — the
// SAME scenario TestViabilityRepairSucceedsWithTwoOfFiveOffline
// (demo_timeline_test.go, untouched — never modified or deleted, task
// item 3's own instruction) already exercises, supplemented here with the
// retrieval step F-D-1 showed that test was missing.
//
// [Flag, on "ADR-055's emergency-eject path must hold" (task item 3's own
// wording)] ADR-055 (Burst-Failure Emergency Eject to Data Owner) has its
// OWN document status field set to "Proposed", and a direct search of
// internal/ for EmergencyEject/BurstFailure finds no implementation of
// that ADR's own direct-to-owner-delivery mechanism anywhere in this
// codebase — only EMERGENCY_FLOOR, which is a repair_jobs.priority value
// belonging to the EXISTING, already-built ADR-007 floor trigger (ordinary
// P2P repair, the same mechanism TestViabilityRepairSucceedsWithTwoOfFiveOffline
// already proves). In demo profile, ADR-055's own would-be threshold
// (⌈0.75×ParityShards⌉ = ⌈0.75×2⌉ = 2) and ADR-007's floor
// (TotalShards-DataShards+1 = 3, i.e. losing 2 reaches it) happen to
// coincide at "lose 2 of 5" — so this test necessarily exercises ADR-007's
// real, built mechanism, not ADR-055's proposed, unbuilt one. Naming that
// distinction here rather than silently implying ADR-055 is what's under
// test.
func TestTwoConcurrentDeparturesAtEmergencyFloor(t *testing.T) {
	db := liveDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	resetDemoDatabase(t, ctx, db)

	microservicePath, providerPath := buildBinaries(t)
	ms := startMicroserviceWithFlags(t, ctx, microservicePath, departureThresholdOverrideFlag)
	owner := registerOwner(t, ctx, db, ms.baseURL)
	depositForOwner(t, ctx, ms.baseURL, owner, 100_000_00)
	providers := startProviders(t, ctx, db, providerPath, ms.baseURL)
	pollReadiness(t, ctx, ms.baseURL, ms.adminAPIKey, 12*time.Minute) // [Fixed — F-17E-01] was 60s; see TestDemoTimeline's identical fix note (demo_timeline_test.go)
	pollFirstAuditPass(t, ctx, db, 3*time.Minute)
	pollAllProvidersActive(t, ctx, db, 15*time.Minute) // [Bumped 12->15min, F-17E-08] see demo_timeline_test.go:TestViabilityActiveTransitionAtTenMinutes for the arithmetic

	fileID, masterSecret, plaintext := uploadTestFileTracked(t, ctx, ms, owner, testUploadBytes)
	wantHash := sha256.Sum256(plaintext)
	t.Logf("uploaded file_id=%s", fileID)

	env := &departEnv{
		db: db, ms: ms, providers: providers, providerBinPath: providerPath, owner: owner,
		fileID: fileID, masterSecret: masterSecret, plaintext: plaintext,
	}
	departAt(t, ctx, env, phaseBurst, modeKill)
	t.Logf("departed indices=%d,%d — leaving s=DataShards=%d exactly", env.departedIndex, env.secondDepartedIndex, demoDataShards)

	// DepartureThreshold applies per provider, independently — both
	// departures must be detected, not just the first (same reasoning
	// TestViabilityRepairSucceedsWithTwoOfFiveOffline's own comment gives).
	pollDeparted(t, ctx, db, 2, 11*time.Minute)
	pollRepairCompleted(t, ctx, db, 2, 5*time.Minute)

	got := retrieveTestFileTracked(t, ctx, ms, owner, masterSecret, fileID)
	gotHash := sha256.Sum256(got)
	if !bytes.Equal(gotHash[:], wantHash[:]) {
		t.Fatalf("retrieved content does not match: sha256(retrieved)=%x, sha256(original)=%x", gotHash, wantHash)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("retrieved content differs from original byte-for-byte, despite matching sha256 (should be unreachable)")
	}
}

// ── small local helpers ─────────────────────────────────────────────────

// newClientHostAndEngine builds the p2p.Host + erasure.Engine pair every
// upload/retrieve call in this file needs — factored out since
// departAtMidUpload needs to build them itself (ahead of, and independent
// from, uploadTestFileTracked's own internal construction) to hand the
// SAME host to uploadTestFileTrackedAllowingError.
func newClientHostAndEngine(t *testing.T, owner *liveOwner) (host p2p.Host, engine *erasure.Engine) {
	t.Helper()
	profile := config.SelectProfile("demo")
	engine, err := erasure.NewEngine(profile)
	if err != nil {
		t.Fatalf("newClientHostAndEngine: erasure.NewEngine: %v", err)
	}
	clientPort := freePort(t)
	host, err = p2p.NewHost(p2p.HostConfig{PrivateKey: owner.signingKey, ListenAddr: fmt.Sprintf("0.0.0.0:%d", clientPort)})
	if err != nil {
		t.Fatalf("newClientHostAndEngine: p2p.NewHost: %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return host, engine
}

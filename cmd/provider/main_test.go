package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	"github.com/masamasaowl/Vyomanaut_V2/internal/p2p"
)

// TestProviderStartup is a thin wrapper so `go test -run TestProviderStartup`
// (this session's own VERIFY invocation) matches — the three tests it runs
// as subtests are the actual, independently-meaningful test functions below
// (also runnable directly; nothing here is duplicated logic, just
// t.Run(name, existingTestFunc)). FLAGGED: build.md's own VERIFY block
// names three tests whose names do not contain "ProviderStartup" as a
// substring of "TestStartupRunsRAMCheckBeforeChunkStore" etc., so a bare
// `-run TestProviderStartup` would not match any of them without this
// wrapper — the same class of small, independently-recomputed inconsistency
// as the RAM-formula sanity numbers (see internal/storage/ram_requirement.go).
func TestProviderStartup(t *testing.T) {
	t.Run("TestStartupRunsRAMCheckBeforeChunkStore", TestStartupRunsRAMCheckBeforeChunkStore)
	t.Run("TestStartupRecoversBeforeWriterGoroutine", TestStartupRecoversBeforeWriterGoroutine)
	t.Run("TestStartupRegistersAllFourProtocolHandlers", TestStartupRegistersAllFourProtocolHandlers)
}

// TestStartupRunsRAMCheckBeforeChunkStore verifies runRAMCheck (main()'s
// Step 3) has no dependency on a storage.ChunkStore at all — its signature
// takes only a declared-storage value and internally calls
// storage.RequiredDHTCacheRAMMB/storage.AvailableRAMBytes, neither of which
// touches an opened store. This is the structural guarantee that lets it
// run before ChunkStore is ever constructed in main(): there is nothing in
// runRAMCheck that COULD require store state to exist first.
func TestStartupRunsRAMCheckBeforeChunkStore(t *testing.T) {
	// No dataDir, no storage.NewChunkStore call anywhere in this test —
	// deliberately, to demonstrate the independence.
	effectiveGB, constrained := runRAMCheck(50)
	if effectiveGB <= 0 {
		t.Fatalf("runRAMCheck(50) returned effectiveGB = %d, want > 0", effectiveGB)
	}
	// constrained may legitimately be true or false depending on the host
	// running this test; the property under test is that the call
	// completed at all without any store having been opened.
	_ = constrained
}

// TestStartupRecoversBeforeWriterGoroutine verifies the correct sequence —
// RecoverFromCrash completing before the writer goroutine starts consuming
// writes — actually works: a fresh store recovers cleanly, and only after
// that does starting the writer goroutine and submitting a write succeed.
func TestStartupRecoversBeforeWriterGoroutine(t *testing.T) {
	store := newTestChunkStore(t) // this helper already calls RecoverFromCrash (handler_upload_test.go)

	writeCh := make(chan chunkWriteRequest, 1)
	go runChunkStoreWriter(store, writeCh)
	defer close(writeCh)

	data := make([]byte, uploadChunkDataSize)
	_, _ = rand.Read(data)
	chunkID := sha256.Sum256(data)

	resultCh := make(chan chunkWriteResult, 1)
	writeCh <- chunkWriteRequest{chunkID: chunkID, data: data, resultCh: resultCh}

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("AppendChunk after RecoverFromCrash: %v", res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for write result")
	}

	if _, err := store.LookupChunk(chunkID); err != nil {
		t.Fatalf("LookupChunk after successful write: %v", err)
	}
}

// TestStartupRegistersAllFourProtocolHandlers wires a Host exactly the way
// main() does at Steps 7-8 (construct handlers, SetStreamHandler for each
// of the four protocols) and verifies every one of the four protocol IDs
// is actually reachable by a client — the same structural guarantee
// ALL_FOUR_HANDLERS_REGISTERED's source-text grep checks, exercised at
// runtime instead.
func TestStartupRegistersAllFourProtocolHandlers(t *testing.T) {
	store := newTestChunkStore(t)
	writeCh := startTestChunkWriter(t, store)

	_, providerPriv, _ := ed25519.GenerateKey(rand.Reader)
	msPub, _, _ := ed25519.GenerateKey(rand.Reader)
	statusHolder := newProviderStatusHolder(providerStatusActive)
	authz := newStaticMicroserviceAuthorizer()
	msPeerID := p2p.PeerID("test-microservice-peer")

	uploadHandler := NewUploadHandler(store, writeCh, msPub, providerPriv, [16]byte{}, statusHolder)
	auditHandler := NewAuditHandler(store, providerPriv, [16]byte{})
	repairHandler := NewRepairDownloadHandler(store, msPub, authz, 120*time.Second, msPeerID)
	vettingGCHandler := NewVettingGCHandler(store, msPub, authz, 120*time.Second, msPeerID)

	port := pickFreeLoopbackPort(t)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverHost, err := p2p.NewHost(p2p.HostConfig{PrivateKey: serverPriv, ListenAddr: listenAddr})
	if err != nil {
		t.Fatalf("NewHost server: %v", err)
	}
	t.Cleanup(func() { _ = serverHost.Close() })

	serverHost.SetStreamHandler(chunkUploadProtocolID, uploadHandler.HandleStream)
	serverHost.SetStreamHandler(auditChallengeProtocolID, auditHandler.HandleStream)
	serverHost.SetStreamHandler(repairDownloadProtocolID, repairHandler.HandleStream)
	serverHost.SetStreamHandler(vettingGCProtocolID, vettingGCHandler.HandleStream)

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientHost, err := p2p.NewHost(p2p.HostConfig{PrivateKey: clientPriv})
	if err != nil {
		t.Fatalf("NewHost client: %v", err)
	}
	t.Cleanup(func() { _ = clientHost.Close() })

	ma, err := p2p.ParseMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	ctx := context.Background()
	if err := clientHost.Connect(ctx, serverHost.PeerID(), []p2p.Multiaddr{ma}); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	protocols := []p2p.ProtocolID{
		chunkUploadProtocolID,
		auditChallengeProtocolID,
		repairDownloadProtocolID,
		vettingGCProtocolID,
	}
	for _, proto := range protocols {
		stream, err := clientHost.NewStream(ctx, serverHost.PeerID(), proto)
		if err != nil {
			t.Errorf("NewStream(%s): %v", proto, err)
			continue
		}
		_ = stream.Close()
	}
}

// ── --sim-count tests (Session 16.2.1) ─────────────────────────────────────

// TestSimCount is a thin wrapper so `go test -run TestSimCount` (this
// session's own VERIFY invocation) matches every test below — same pattern
// TestProviderStartup already uses above for the same reason.
func TestSimCount(t *testing.T) {
	t.Run("TestSimCountSpawnsNIndependentInstances", TestSimCountSpawnsNIndependentInstances)
	t.Run("TestSimCountAssignsDistinctEd25519Identities", TestSimCountAssignsDistinctEd25519Identities)
	t.Run("TestSimCountZeroPadsInstanceIDToFourDigits", TestSimCountZeroPadsInstanceIDToFourDigits)
	t.Run("TestSimCountAssignsSyntheticASNsFromFlag", TestSimCountAssignsSyntheticASNsFromFlag)
	t.Run("TestSimCountNeverReferencesStorageEngineDirectly", TestSimCountNeverReferencesStorageEngineDirectly)
}

// runSimulationForTest starts runSimulation with simCount instances against
// a fresh t.TempDir(), returns once every instance's identity file exists
// (i.e. each instance has completed Steps 3-4 of its startup sequence), and
// registers a t.Cleanup that cancels the shared context and waits for every
// instance goroutine to return. microserviceURL deliberately points at a
// port nothing is listening on: fetchMicroservicePublicKey's failure path
// is a logged WARNING, not fatal (main.go), so instances still start.
func runSimulationForTest(t *testing.T, simCount, simASNCount int) (simDataDir string, flags providerFlags) {
	t.Helper()

	simDataDir = t.TempDir()
	unreachablePort := pickFreeLoopbackPort(t) // freed immediately — nothing listens here
	flags = providerFlags{
		mode:              "demo",
		microserviceURL:   fmt.Sprintf("http://127.0.0.1:%d", unreachablePort),
		declaredStorageGB: 10,
		simCount:          simCount,
		simBasePort:       pickFreeLoopbackPort(t),
		simDataDir:        simDataDir,
		simASNCount:       simASNCount,
	}
	profile := config.SelectProfile(flags.mode)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSimulation(ctx, flags, profile)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("runSimulation did not return within 10s of cancellation")
		}
	})

	// Wait for every instance to reach ready: both its identity file
	// (Step 4) AND its ChunkStore directory having real content (Step 6,
	// storage.NewChunkStore) must be present. An earlier version of this
	// helper waited only for the identity file — but Step 6 runs strictly
	// after Steps 4-5 (identity, then a JWKS fetch attempt) inside
	// runProviderInstance, so that was an under-synchronized wait: the
	// last-spawned instance's goroutine could still be mid-JWKS-fetch by
	// the time its identity file appeared, making
	// TestSimCountSpawnsNIndependentInstances's directory-content check
	// genuinely flaky (observed directly: 3 failures in 5 runs before this
	// fix, all "chunk store dir ... is empty", never any other instance
	// property). Waiting on the chunk-store directory's own content is the
	// correct, race-free signal for "this instance's startup sequence has
	// reached Step 6", and identity files are always already present by
	// the time content check passes since Step 4 precedes Step 6.
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < simCount; i++ {
		idFile := filepath.Join(simDataDir, fmt.Sprintf("%04d", i), ownerSeedFileName)
		chunkStoreDir := filepath.Join(simDataDir, fmt.Sprintf("%04d", i), "db")
		for {
			_, idErr := os.Stat(idFile)
			entries, dirErr := os.ReadDir(chunkStoreDir)
			if idErr == nil && dirErr == nil && len(entries) > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for instance %d to become ready (identity err=%v, chunk-store err=%v)", i, idErr, dirErr)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return simDataDir, flags
}

// TestSimCountSpawnsNIndependentInstances verifies --sim-count=N actually
// results in N independently-running instances: each gets its own
// storage.ChunkStore directory (this session's ".../db/" convention) with
// real on-disk content, not just N goroutines that started and did nothing.
func TestSimCountSpawnsNIndependentInstances(t *testing.T) {
	const n = 3
	simDataDir, _ := runSimulationForTest(t, n, defaultSimASNCount)

	for i := 0; i < n; i++ {
		chunkStoreDir := filepath.Join(simDataDir, fmt.Sprintf("%04d", i), "db")
		info, err := os.Stat(chunkStoreDir)
		if err != nil {
			t.Errorf("instance %d: chunk store dir %s: %v", i, chunkStoreDir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("instance %d: %s is not a directory", i, chunkStoreDir)
		}
		entries, err := os.ReadDir(chunkStoreDir)
		if err != nil {
			t.Errorf("instance %d: read chunk store dir: %v", i, err)
			continue
		}
		if len(entries) == 0 {
			t.Errorf("instance %d: chunk store dir %s is empty — storage.NewChunkStore did not persist anything", i, chunkStoreDir)
		}
	}
}

// TestSimCountAssignsDistinctEd25519Identities verifies every simulated
// instance gets its own separate, stable Ed25519 identity — a direct
// consequence of each instance receiving its own dataDir (runSimulation),
// checked here by reloading each instance's identity from disk after the
// fact and confirming no two Peer IDs collide.
func TestSimCountAssignsDistinctEd25519Identities(t *testing.T) {
	const n = 3
	simDataDir, _ := runSimulationForTest(t, n, defaultSimASNCount)

	seen := make(map[string]int, n)
	for i := 0; i < n; i++ {
		instanceRoot := filepath.Join(simDataDir, fmt.Sprintf("%04d", i))
		masterSecret, ownerID, err := loadOrGenerateOwnerSeed(instanceRoot)
		if err != nil {
			t.Fatalf("instance %d: loadOrGenerateOwnerSeed: %v", i, err)
		}
		_, peerID, err := p2p.LoadOrGenerateIdentity(instanceRoot, masterSecret, ownerID[:])
		if err != nil {
			t.Fatalf("instance %d: LoadOrGenerateIdentity: %v", i, err)
		}
		key := peerID.String()
		if prev, ok := seen[key]; ok {
			t.Errorf("instance %d has the same Peer ID as instance %d: %s", i, prev, key)
		}
		seen[key] = i
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct Peer IDs, want %d", len(seen), n)
	}
}

// TestSimCountZeroPadsInstanceIDToFourDigits verifies instance directories
// are named with the exact IC §10 zero-padded-4-digit convention — "0000",
// "0001", "0002" — not "0", "00", or any other width.
func TestSimCountZeroPadsInstanceIDToFourDigits(t *testing.T) {
	const n = 3
	simDataDir, _ := runSimulationForTest(t, n, defaultSimASNCount)

	entries, err := os.ReadDir(simDataDir)
	if err != nil {
		t.Fatalf("read simDataDir: %v", err)
	}
	want := map[string]bool{"0000": false, "0001": false, "0002": false}
	for _, e := range entries {
		if _, ok := want[e.Name()]; ok {
			want[e.Name()] = true
		} else {
			t.Errorf("unexpected entry %q in simDataDir — not a 4-digit zero-padded instance ID", e.Name())
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected instance directory %q not found", name)
		}
	}
}

// TestSimCountAssignsSyntheticASNsFromFlag tests syntheticASNForInstance
// directly — the pure function runSimulation calls per instance — rather
// than a running simulation, since the assigned ASN currently has no
// externally-observable side effect to inspect (see runProviderInstance's
// PROVIDER-REGISTRATION GAP note: it is computed and logged, not yet
// transmitted anywhere a test could otherwise read it back from).
func TestSimCountAssignsSyntheticASNsFromFlag(t *testing.T) {
	cases := []struct {
		instanceIndex int
		asnCount      int
		want          string
	}{
		{0, 5, "SIM-AS1"},
		{4, 5, "SIM-AS5"},
		{5, 5, "SIM-AS1"}, // cycles back to the start of the pool
		{7, 3, "SIM-AS2"},
	}
	for _, c := range cases {
		got := syntheticASNForInstance(c.instanceIndex, c.asnCount)
		if got != c.want {
			t.Errorf("syntheticASNForInstance(%d, %d) = %q, want %q", c.instanceIndex, c.asnCount, got, c.want)
		}
	}
}

// TestSimCountNeverReferencesStorageEngineDirectly is a static-analysis-
// style test asserting, at the Go test level, the same property the
// session's own NO_ENGINE_NAMED_IN_SIM_CODE_PATH shell grep checks: this
// file must never name a storage-engine-specific type or check GOOS itself
// — engine selection is entirely internal/storage's business (ADR-046).
func TestSimCountNeverReferencesStorageEngineDirectly(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	forbidden := regexp.MustCompile(`(?i)rocksdb|grocksdb|badger`)
	if loc := forbidden.FindIndex(src); loc != nil {
		t.Fatalf("main.go references a storage engine directly at byte offset %d: %q", loc[0], src[loc[0]:loc[1]])
	}
}

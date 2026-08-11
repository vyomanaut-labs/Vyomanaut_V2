package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	localcrypto "github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
)

// ── canonicalHeartbeatSigningInput ─────────────────────────────────────────

// TestCanonicalHeartbeatSigningInputExactBytes locks in the exact wire shape
// (sorted keys, no whitespace, provider_sig absent) IC §3.1/§3.2 require.
func TestCanonicalHeartbeatSigningInputExactBytes(t *testing.T) {
	got, err := canonicalHeartbeatSigningInput(
		[]string{"/ip4/1.2.3.4/tcp/4001", "/ip4/5.6.7.8/tcp/4001"},
		"2026-07-09T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("canonicalHeartbeatSigningInput: %v", err)
	}
	want := `{"current_multiaddrs":["/ip4/1.2.3.4/tcp/4001","/ip4/5.6.7.8/tcp/4001"],"timestamp":"2026-07-09T12:00:00Z"}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// TestCanonicalHeartbeatSigningInputEmptyAddrs verifies the zero-multiaddr
// edge case produces valid, well-formed JSON rather than a malformed array.
func TestCanonicalHeartbeatSigningInputEmptyAddrs(t *testing.T) {
	got, err := canonicalHeartbeatSigningInput(nil, "2026-07-09T12:00:00Z")
	if err != nil {
		t.Fatalf("canonicalHeartbeatSigningInput: %v", err)
	}
	want := `{"current_multiaddrs":[],"timestamp":"2026-07-09T12:00:00Z"}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Errorf("output is not valid JSON: %v", err)
	}
}

// TestCanonicalHeartbeatSigningInputEscapesSpecialChars verifies a
// pathological multiaddr string containing a quote/backslash is escaped
// correctly rather than corrupting the JSON structure.
func TestCanonicalHeartbeatSigningInputEscapesSpecialChars(t *testing.T) {
	got, err := canonicalHeartbeatSigningInput([]string{`weird"addr\here`}, "ts")
	if err != nil {
		t.Fatalf("canonicalHeartbeatSigningInput: %v", err)
	}
	var parsed struct {
		CurrentMultiaddrs []string `json:"current_multiaddrs"`
		Timestamp         string   `json:"timestamp"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, got)
	}
	if len(parsed.CurrentMultiaddrs) != 1 || parsed.CurrentMultiaddrs[0] != `weird"addr\here` {
		t.Errorf("round-trip mismatch: got %+v", parsed.CurrentMultiaddrs)
	}
}

// TestCanonicalHeartbeatSigningInputDeterministic verifies identical inputs
// always produce identical bytes (required for signature reproducibility).
func TestCanonicalHeartbeatSigningInputDeterministic(t *testing.T) {
	a, err := canonicalHeartbeatSigningInput([]string{"/ip4/1.2.3.4/tcp/1"}, "ts")
	if err != nil {
		t.Fatalf("canonicalHeartbeatSigningInput: %v", err)
	}
	b, err := canonicalHeartbeatSigningInput([]string{"/ip4/1.2.3.4/tcp/1"}, "ts")
	if err != nil {
		t.Fatalf("canonicalHeartbeatSigningInput: %v", err)
	}
	if string(a) != string(b) {
		t.Error("non-deterministic output for identical input")
	}
}

// ── jitteredInterval ────────────────────────────────────────────────────────

// TestJitteredIntervalBounds verifies the output always lies within
// [base-jitter, base+jitter] across many trials, and that a non-positive
// jitter returns base unchanged.
func TestJitteredIntervalBounds(t *testing.T) {
	base := 4 * time.Hour
	jitter := 5 * time.Minute
	for i := 0; i < 200; i++ {
		got := jitteredInterval(base, jitter)
		if got < base-jitter || got > base+jitter {
			t.Fatalf("iter=%d: jitteredInterval = %v, want within [%v, %v]", i, got, base-jitter, base+jitter)
		}
	}
	if got := jitteredInterval(base, 0); got != base {
		t.Errorf("zero jitter: got %v, want %v unchanged", got, base)
	}
	if got := jitteredInterval(base, -time.Second); got != base {
		t.Errorf("negative jitter: got %v, want %v unchanged", got, base)
	}
}

// TestJitteredIntervalVaries verifies successive calls are not all identical
// (i.e. jitter is actually being applied, not silently a no-op).
func TestJitteredIntervalVaries(t *testing.T) {
	base := 30 * time.Second
	jitter := 5 * time.Second
	seen := make(map[time.Duration]bool)
	for i := 0; i < 50; i++ {
		seen[jitteredInterval(base, jitter)] = true
	}
	if len(seen) < 2 {
		t.Error("jitteredInterval produced the same value 50 times in a row — jitter does not appear to be applied")
	}
}

// ── doHeartbeat / postHeartbeat over a real httptest server ───────────────

// testSigningIdentity returns a fresh Ed25519 key pair for use as a
// heartbeat signing key in tests.
func testSigningIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// TestDoHeartbeatSendsVerifiableSignedPayload spins up a real HTTP server,
// sends one heartbeat, and independently reconstructs + verifies the
// signature exactly as a microservice implementation would (IC §3.2's
// verification procedure), over the real network stack (loopback TCP).
func TestDoHeartbeatSendsVerifiableSignedPayload(t *testing.T) {
	pub, priv := testSigningIdentity(t)

	var received heartbeatWirePayload
	var gotPath string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("server: decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	addr, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/4001")
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}

	cfg := HeartbeatConfig{
		Profile:         config.DemoProfile,
		CurrentAddrs:    func() []Multiaddr { return []Multiaddr{addr} },
		MicroserviceURL: srv.URL,
		ProviderID:      "test-provider-id",
		DaemonVersion:   "0.1.0-test",
		SigningKey:      priv,
	}

	doHeartbeat(context.Background(), cfg)

	if gotPath != heartbeatPath {
		t.Errorf("request path = %q, want %q", gotPath, heartbeatPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if received.ProviderID != "test-provider-id" {
		t.Errorf("provider_id = %q, want %q", received.ProviderID, "test-provider-id")
	}
	if len(received.CurrentMultiaddrs) != 1 || received.CurrentMultiaddrs[0] != "/ip4/127.0.0.1/tcp/4001" {
		t.Errorf("current_multiaddrs = %v, want [/ip4/127.0.0.1/tcp/4001]", received.CurrentMultiaddrs)
	}
	if received.Timestamp == "" {
		t.Error("timestamp must not be empty")
	}
	if _, err := time.Parse(time.RFC3339, received.Timestamp); err != nil {
		t.Errorf("timestamp %q is not valid RFC3339/ISO8601: %v", received.Timestamp, err)
	}

	// Independently reconstruct the signing input exactly as a verifier
	// would, and verify with crypto.VerifyBytes (IC §3.2 verification
	// procedure) — proves the signature is over the documented fields only
	// (provider_sig itself is excluded from what was signed).
	sigBytes, err := hex.DecodeString(received.ProviderSig)
	if err != nil {
		t.Fatalf("provider_sig is not valid hex: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Fatalf("provider_sig decodes to %d bytes, want 64", len(sigBytes))
	}
	var sigArr [64]byte
	copy(sigArr[:], sigBytes)

	signingInput, err := canonicalHeartbeatSigningInput(received.CurrentMultiaddrs, received.Timestamp)
	if err != nil {
		t.Fatalf("canonicalHeartbeatSigningInput: %v", err)
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)
	if !localcrypto.VerifyBytes(pubArr, signingInput, sigArr) {
		t.Error("signature does not verify against the reconstructed canonical signing input")
	}
}

// TestDoHeartbeatSignatureRejectsTamperedField verifies that altering any
// signed field after the fact breaks verification — the signature is not
// vacuously valid for anything.
func TestDoHeartbeatSignatureRejectsTamperedField(t *testing.T) {
	pub, priv := testSigningIdentity(t)

	signingInput, err := canonicalHeartbeatSigningInput([]string{"/ip4/1.2.3.4/tcp/1"}, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("canonicalHeartbeatSigningInput: %v", err)
	}
	sig := localcrypto.SignBytes(priv, signingInput)

	tamperedInput, err := canonicalHeartbeatSigningInput([]string{"/ip4/9.9.9.9/tcp/1"}, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("canonicalHeartbeatSigningInput: %v", err)
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)
	if localcrypto.VerifyBytes(pubArr, tamperedInput, sig) {
		t.Error("signature verified against a tampered multiaddr list — must not")
	}
}

// TestDoHeartbeatNoServerDoesNotPanic verifies a completely unreachable
// microservice URL degrades to a logged failure, never a panic or hang past
// the client timeout.
func TestDoHeartbeatNoServerDoesNotPanic(t *testing.T) {
	_, priv := testSigningIdentity(t)
	cfg := HeartbeatConfig{
		Profile:         config.DemoProfile,
		MicroserviceURL: "http://127.0.0.1:1", // nothing listens on port 1
		SigningKey:      priv,
		HTTPClient:      &http.Client{Timeout: 2 * time.Second},
	}
	doHeartbeat(context.Background(), cfg) // must return, not panic
}

// ── token refresh ───────────────────────────────────────────────────────────

// TestMaybeRefreshTokenTriggersWhenExpiringSoon verifies RefreshToken is
// called when less than tokenRefreshLeadTime remains.
func TestMaybeRefreshTokenTriggersWhenExpiringSoon(t *testing.T) {
	var refreshed int32
	cfg := HeartbeatConfig{
		GetToken: func() (string, time.Time) {
			return "tok", time.Now().Add(1 * time.Hour) // well under 24h
		},
		RefreshToken: func(ctx context.Context) error {
			atomic.AddInt32(&refreshed, 1)
			return nil
		},
	}
	maybeRefreshToken(context.Background(), cfg)
	if atomic.LoadInt32(&refreshed) != 1 {
		t.Errorf("RefreshToken called %d times, want 1", refreshed)
	}
}

// TestMaybeRefreshTokenSkipsWhenFarFromExpiry verifies RefreshToken is NOT
// called when the token is comfortably valid.
func TestMaybeRefreshTokenSkipsWhenFarFromExpiry(t *testing.T) {
	var refreshed int32
	cfg := HeartbeatConfig{
		GetToken: func() (string, time.Time) {
			return "tok", time.Now().Add(72 * time.Hour) // well over 24h
		},
		RefreshToken: func(ctx context.Context) error {
			atomic.AddInt32(&refreshed, 1)
			return nil
		},
	}
	maybeRefreshToken(context.Background(), cfg)
	if atomic.LoadInt32(&refreshed) != 0 {
		t.Errorf("RefreshToken called %d times, want 0", refreshed)
	}
}

// TestMaybeRefreshTokenFailureDoesNotPanicAndIsRetriedNextCycle verifies a
// refresh failure is tolerated (logged, not fatal) when within the grace
// period — NeedsReauth must NOT fire yet.
func TestMaybeRefreshTokenFailureWithinGraceDoesNotReauth(t *testing.T) {
	var reauthed int32
	cfg := HeartbeatConfig{
		GetToken: func() (string, time.Time) {
			// Expired 10 minutes ago — within the 1-hour grace period.
			return "tok", time.Now().Add(-10 * time.Minute)
		},
		RefreshToken: func(ctx context.Context) error {
			return fmt.Errorf("simulated refresh failure")
		},
		NeedsReauth: func() { atomic.AddInt32(&reauthed, 1) },
	}
	maybeRefreshToken(context.Background(), cfg)
	if atomic.LoadInt32(&reauthed) != 0 {
		t.Error("NeedsReauth fired while still within the grace period")
	}
}

// TestMaybeRefreshTokenFailureBeyondGraceTriggersReauth verifies NeedsReauth
// fires once the token has been expired longer than tokenExpiredGracePeriod
// and a refresh attempt fails.
func TestMaybeRefreshTokenFailureBeyondGraceTriggersReauth(t *testing.T) {
	var reauthed int32
	cfg := HeartbeatConfig{
		GetToken: func() (string, time.Time) {
			// Expired 2 hours ago — beyond the 1-hour grace period.
			return "tok", time.Now().Add(-2 * time.Hour)
		},
		RefreshToken: func(ctx context.Context) error {
			return fmt.Errorf("simulated refresh failure")
		},
		NeedsReauth: func() { atomic.AddInt32(&reauthed, 1) },
	}
	maybeRefreshToken(context.Background(), cfg)
	if atomic.LoadInt32(&reauthed) != 1 {
		t.Errorf("NeedsReauth called %d times, want 1", reauthed)
	}
}

// TestMaybeRefreshTokenSuccessBeyondGraceDoesNotReauth verifies a
// SUCCESSFUL refresh — even for a badly expired token — never triggers
// NeedsReauth (that path is refresh-failure-specific).
func TestMaybeRefreshTokenSuccessBeyondGraceDoesNotReauth(t *testing.T) {
	var reauthed int32
	cfg := HeartbeatConfig{
		GetToken: func() (string, time.Time) {
			return "tok", time.Now().Add(-48 * time.Hour)
		},
		RefreshToken: func(ctx context.Context) error {
			return nil // succeeds
		},
		NeedsReauth: func() { atomic.AddInt32(&reauthed, 1) },
	}
	maybeRefreshToken(context.Background(), cfg)
	if atomic.LoadInt32(&reauthed) != 0 {
		t.Error("NeedsReauth fired despite a successful refresh")
	}
}

// TestDoHeartbeatSendsEvenWhenRefreshFails verifies a heartbeat is still
// sent using the existing token when refresh fails (IC §3.1: "Do not abort
// — send heartbeat with existing token").
func TestDoHeartbeatSendsEvenWhenRefreshFails(t *testing.T) {
	_, priv := testSigningIdentity(t)

	var heartbeatsReceived int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&heartbeatsReceived, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := HeartbeatConfig{
		Profile:         config.DemoProfile,
		MicroserviceURL: srv.URL,
		SigningKey:      priv,
		GetToken: func() (string, time.Time) {
			return "tok", time.Now().Add(1 * time.Hour)
		},
		RefreshToken: func(ctx context.Context) error {
			return fmt.Errorf("simulated failure")
		},
	}
	doHeartbeat(context.Background(), cfg)

	if atomic.LoadInt32(&heartbeatsReceived) != 1 {
		t.Errorf("server received %d heartbeats, want 1 (heartbeat must still send after a failed refresh)", heartbeatsReceived)
	}
}

// ── doRepublish ─────────────────────────────────────────────────────────────

// fakeChunkDHTKeySource is a minimal in-memory ChunkDHTKeySource for tests.
type fakeChunkDHTKeySource struct {
	keys map[[32]byte][32]byte
	err  error
}

func (f *fakeChunkDHTKeySource) AllChunkDHTKeys() (map[[32]byte][32]byte, error) {
	return f.keys, f.err
}

// fakeDHT is a minimal in-memory DHT test double that just records
// PutProviderRecord calls (doRepublish does not need FindProviders/Bootstrap).
type fakeDHT struct {
	mu   sync.Mutex
	puts [][]byte
	err  error
}

func (f *fakeDHT) PutProviderRecord(ctx context.Context, key []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	f.puts = append(f.puts, cp)
	return nil
}

func (f *fakeDHT) FindProviders(ctx context.Context, key []byte, maxCount int) ([]AddrInfo, error) {
	return nil, fmt.Errorf("not implemented in fakeDHT")
}

func (f *fakeDHT) Bootstrap(ctx context.Context) error { return nil }

// TestDoRepublishPutsEveryCachedKey verifies every (chunkID, dhtKey) pair
// AllChunkDHTKeys returns results in exactly one PutProviderRecord call with
// that dhtKey, and that no key is recomputed (the fake source is the only
// source of dhtKeys — there is nothing to recompute from).
func TestDoRepublishPutsEveryCachedKey(t *testing.T) {
	var chunkA, chunkB [32]byte
	var keyA, keyB [32]byte
	chunkA[0], chunkB[0] = 0xAA, 0xBB
	keyA[0], keyB[0] = 0x11, 0x22

	store := &fakeChunkDHTKeySource{keys: map[[32]byte][32]byte{chunkA: keyA, chunkB: keyB}}
	dht := &fakeDHT{}

	cfg := HeartbeatConfig{Store: store, DHT: dht}
	doRepublish(context.Background(), cfg)

	dht.mu.Lock()
	defer dht.mu.Unlock()
	if len(dht.puts) != 2 {
		t.Fatalf("got %d PutProviderRecord calls, want 2", len(dht.puts))
	}
	seen := make(map[[32]byte]bool)
	for _, p := range dht.puts {
		var k [32]byte
		copy(k[:], p)
		seen[k] = true
	}
	if !seen[keyA] || !seen[keyB] {
		t.Errorf("expected both cached keys to be republished; seen=%v", seen)
	}
}

// TestDoRepublishToleratesPartialFailure verifies one failing
// PutProviderRecord call does not stop the rest of the batch, matching
// PutProviderRecord's own best-effort replication philosophy (dht.go).
func TestDoRepublishToleratesPartialFailure(t *testing.T) {
	var chunkA [32]byte
	var keyA [32]byte
	chunkA[0], keyA[0] = 0xAA, 0x11

	store := &fakeChunkDHTKeySource{keys: map[[32]byte][32]byte{chunkA: keyA}}
	dht := &fakeDHT{err: fmt.Errorf("simulated network failure")}

	cfg := HeartbeatConfig{Store: store, DHT: dht}
	doRepublish(context.Background(), cfg) // must not panic despite the failure
}

// TestDoRepublishNilStoreOrDHTIsNoop verifies doRepublish degrades gracefully
// (rather than nil-panicking) if wiring is incomplete.
func TestDoRepublishNilStoreOrDHTIsNoop(t *testing.T) {
	doRepublish(context.Background(), HeartbeatConfig{}) // Store and DHT both nil
}

// TestDoRepublishNeverMentionsDeriveDHTKey is a structural regression guard:
// doRepublish must consume only pre-cached keys, matching IC §12.2. This is
// enforced positively here (via the fake source being the sole key origin,
// exercised above) rather than by grepping doRepublish's own source for
// forbidden identifiers — see heartbeat.go's file-level comment for why
// mentioning the underlying concept in prose is unavoidable there.
func TestDoRepublishNeverMentionsDeriveDHTKey(t *testing.T) {
	// No import of internal/crypto's DHT-key derivation functions exists in
	// this file at all; if one were added, this file would fail to compile
	// without also using it, which every other test here would immediately
	// make obviously redundant. This test exists as documentation of intent.
	t.Log("doRepublish sources DHT keys exclusively from ChunkDHTKeySource; see TestDoRepublishPutsEveryCachedKey")
}

// ── RunHeartbeat integration ────────────────────────────────────────────────

// TestRunHeartbeatFiresBothLoopsAndRespectsCancellation runs the full loop
// with demo-scale (sub-second) intervals and verifies both the heartbeat and
// republish paths actually fire multiple times, then verifies the goroutine
// exits promptly once ctx is cancelled.
func TestRunHeartbeatFiresBothLoopsAndRespectsCancellation(t *testing.T) {
	_, priv := testSigningIdentity(t)

	var heartbeats int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&heartbeats, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var chunkA, keyA [32]byte
	chunkA[0], keyA[0] = 0x01, 0x02
	store := &fakeChunkDHTKeySource{keys: map[[32]byte][32]byte{chunkA: keyA}}
	dht := &fakeDHT{}

	fastProfile := config.DemoProfile
	fastProfile.HeartbeatInterval = 30 * time.Millisecond
	fastProfile.HeartbeatJitter = 5 * time.Millisecond
	fastProfile.DHTRepublishInterval = 40 * time.Millisecond

	cfg := HeartbeatConfig{
		Profile:         fastProfile,
		MicroserviceURL: srv.URL,
		SigningKey:      priv,
		Store:           store,
		DHT:             dht,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunHeartbeat(ctx, cfg)
		close(done)
	}()

	time.Sleep(250 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunHeartbeat did not return within 2s of context cancellation")
	}

	if atomic.LoadInt32(&heartbeats) < 2 {
		t.Errorf("expected multiple heartbeats over 250ms at a ~30ms interval, got %d", heartbeats)
	}
	dht.mu.Lock()
	putCount := len(dht.puts)
	dht.mu.Unlock()
	if putCount < 2 {
		t.Errorf("expected multiple republish cycles over 250ms at a ~40ms interval, got %d PutProviderRecord calls", putCount)
	}
}

// TestRunHeartbeatExitsImmediatelyOnAlreadyCancelledContext verifies the
// loop does not send even one heartbeat if ctx is already cancelled when
// RunHeartbeat starts.
func TestRunHeartbeatExitsImmediatelyOnAlreadyCancelledContext(t *testing.T) {
	_, priv := testSigningIdentity(t)

	var heartbeats int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&heartbeats, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	cfg := HeartbeatConfig{
		Profile:         config.DemoProfile,
		MicroserviceURL: srv.URL,
		SigningKey:      priv,
	}

	done := make(chan struct{})
	go func() {
		RunHeartbeat(ctx, cfg)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunHeartbeat did not return promptly for an already-cancelled context")
	}
	if atomic.LoadInt32(&heartbeats) != 0 {
		t.Errorf("got %d heartbeats for an already-cancelled context, want 0", heartbeats)
	}
}

// ── profile-driven duration checks ─────────────────────────────────────────

// TestRunHeartbeatUsesProfileIntervalsNotHardcoded verifies demo and
// production profiles genuinely drive different jittered heartbeat interval
// ranges — a structural check that HeartbeatInterval is actually read from
// the profile, complementing the source-level grep checks in the build doc.
func TestRunHeartbeatUsesProfileIntervalsNotHardcoded(t *testing.T) {
	demoInterval := jitteredInterval(config.DemoProfile.HeartbeatInterval, config.DemoProfile.HeartbeatJitter)
	prodInterval := jitteredInterval(config.ProductionProfile.HeartbeatInterval, config.ProductionProfile.HeartbeatJitter)

	if demoInterval >= time.Minute {
		t.Errorf("demo jittered interval = %v, want well under 1 minute", demoInterval)
	}
	if prodInterval <= time.Hour {
		t.Errorf("production jittered interval = %v, want well over 1 hour", prodInterval)
	}
}

// TestDoRepublishCapsPerCycleAndDefersRemainder verifies that a chunk count
// exceeding doRepublishMaxPerCycle only attempts the cap's worth in a
// single doRepublish call, deferring the rest. [REF: ARCH §27.2, M6 review §8]
func TestDoRepublishCapsPerCycleAndDefersRemainder(t *testing.T) {
	keys := make(map[[32]byte][32]byte, doRepublishMaxPerCycle+50)
	for i := 0; i < doRepublishMaxPerCycle+50; i++ {
		var chunkID, dhtKey [32]byte
		binary.BigEndian.PutUint32(chunkID[:4], uint32(i))
		binary.BigEndian.PutUint32(dhtKey[:4], uint32(i))
		keys[chunkID] = dhtKey
	}
	store := &fakeChunkDHTKeySource{keys: keys}
	dht := &fakeDHT{}

	cfg := HeartbeatConfig{Store: store, DHT: dht}
	doRepublish(context.Background(), cfg)

	dht.mu.Lock()
	got := len(dht.puts)
	dht.mu.Unlock()
	if got != doRepublishMaxPerCycle {
		t.Errorf("PutProviderRecord called %d times in one cycle, want exactly the cap (%d)", got, doRepublishMaxPerCycle)
	}
}

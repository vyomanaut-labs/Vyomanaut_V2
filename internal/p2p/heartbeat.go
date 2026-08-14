// Package p2p is declared in doc.go.
// This file implements the heartbeat and DHT republication loops (IC §3.1,
// IC §12.2, ARCH §13, ADR-028).
//
// DEPENDENCY NOTE (see doc.go for the full substitution rationale): the
// build.md session plan for this file types HeartbeatConfig.Store as
// storage.ChunkStore, importing internal/storage directly. That import is
// not taken here. internal/storage depends on github.com/linxGnu/grocksdb,
// a cgo binding that requires a from-source RocksDB build (see
// deployments/docker/Dockerfile.ci) — the same class of "cannot be
// vendored/built cheaply in this sandbox" problem go-libp2p hit, just via
// native-library compilation rather than blocked network egress. Pulling in
// RocksDB purely to reference a struct field's type, in a file that is
// otherwise pure networking/signing logic, was not a proportionate cost.
//
// It is also not a real integration gap: internal/storage.ChunkStore (as it
// stands) does not yet expose per-chunk DHT-key iteration either —
// allChunkIDs is unexported and the DHT-key cache accessor is commented out
// pending its own future session. The build.md template's own doRepublish
// TODO already anticipates this: "once the storage package exposes ... an
// equivalent iterator." ChunkDHTKeySource below IS that iterator's contract,
// scoped to exactly what this file needs — internal/storage (or a thin
// adapter over it) can satisfy it once that future session lands, without
// this package ever needing to import internal/storage or grocksdb.
//
// [REF: IC §3.1, IC §3.2, IC §12.2, ARCH §13, ADR-028, MVP §5.4]

package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	localcrypto "github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
)

// ── constants ──────────────────────────────────────────────────────────────

// tokenRefreshLeadTime is the "less than this much time left" threshold that
// triggers a proactive token refresh on every heartbeat cycle (IC §3.1).
const tokenRefreshLeadTime = 24 * time.Hour

// tokenExpiredGracePeriod is how long past actual expiry a token may still be
// used while refresh attempts continue silently. Once the token has been
// expired longer than this AND a refresh attempt fails, NeedsReauth fires
// (IC §3.1: "If the token is beyond the 1-hour grace period and refresh
// fails, the daemon must prompt re-registration").
const tokenExpiredGracePeriod = 1 * time.Hour

// heartbeatHTTPTimeout bounds a single heartbeat POST so one slow/hung
// microservice call cannot stall the goroutine past the next scheduled tick.
const heartbeatHTTPTimeout = 15 * time.Second

// heartbeatPath and this package's own presumed base path composition are
// intentionally simple string concatenation (cfg.MicroserviceURL + heartbeatPath)
// rather than net/url.JoinPath: MicroserviceURL is operator-supplied
// configuration, not attacker-controlled input.
const heartbeatPath = "/api/v1/provider/heartbeat"

// The jitter range goes from -jitter through +jitter, so its total inclusive width is 2*jitter + 1
const jitterRangeMultiplier = 2

// ── ChunkDHTKeySource ──────────────────────────────────────────────────────

// ChunkDHTKeySource is the minimal capability the DHT-republication half of
// the heartbeat loop needs from local chunk storage: the set of DHT keys
// already cached at upload time for chunks this daemon currently holds.
//
// See the file-level comment above for why this is a narrow local interface
// rather than a dependency on internal/storage.ChunkStore.
type ChunkDHTKeySource interface {
	// AllChunkDHTKeys returns every locally stored chunk's content address
	// mapped to its pre-cached DHT key. Only the values are used to call
	// DHT.PutProviderRecord; chunk IDs are retained in the return type purely
	// so callers can produce useful per-chunk error/log messages.
	AllChunkDHTKeys() (map[[32]byte][32]byte, error)
}

// ── HeartbeatConfig ────────────────────────────────────────────────────────

// HeartbeatConfig holds all runtime dependencies for the heartbeat goroutine.
// All duration values come from the active NetworkProfile — never hardcoded.
type HeartbeatConfig struct {
	Profile config.NetworkProfile

	// CurrentAddrs returns this node's current advertised multiaddrs
	// (ordered by preference), including any active relay address, at the
	// moment each heartbeat is sent — a func rather than a static slice
	// because NAT/relay state can change between cycles (ARCH §13).
	CurrentAddrs func() []Multiaddr

	DHT   DHT
	Store ChunkDHTKeySource // see file-level comment; internal/storage-independent

	MicroserviceURL string
	ProviderID      string
	DaemonVersion   string

	// SigningKey is the daemon's Ed25519 identity private key (64 bytes,
	// crypto/ed25519.PrivateKeySize) — the same key LoadOrGenerateIdentity
	// returns. The build.md reference text for this session describes this
	// field as "44 bytes"; that does not match ed25519.PrivateKeySize (64)
	// or crypto.SignBytes' actual signature and is treated as an error in
	// that text, not reproduced here.
	SigningKey ed25519.PrivateKey

	GetToken     func() (token string, expiry time.Time)
	RefreshToken func(ctx context.Context) error

	// NeedsReauth is invoked when the daemon's token has been expired for
	// longer than tokenExpiredGracePeriod and a refresh attempt has just
	// failed again (IC §3.1). Wiring this to an actual "local status
	// interface" prompting full OTP re-registration is a different
	// subsystem's concern; this is the extension point for it. May be nil.
	NeedsReauth func()

	// HTTPClient sends the heartbeat POST. Defaults to a client with
	// heartbeatHTTPTimeout if nil — overridable so tests (and callers who
	// want custom transport/proxy behaviour) do not have to touch the
	// package default.
	HTTPClient *http.Client
}

// ── RunHeartbeat ───────────────────────────────────────────────────────────

// RunHeartbeat runs the heartbeat and DHT republication loops until ctx is
// cancelled. Must be called once from cmd/provider/main.go after the daemon
// is fully initialised.
//
// The heartbeat timer is jittered by ±cfg.Profile.HeartbeatJitter and
// rescheduled after every attempt (IC §3.1: "random jitter... to prevent
// thundering herd after microservice restart. Timer is reset after each
// successful acknowledgement" — this implementation reschedules on both
// success and failure, since IC §3.1 specifies no distinct failure-retry
// interval; a failed attempt simply waits for the next regular, jittered
// cycle). DHT republication uses a plain ticker: NetworkProfile carries no
// republication jitter field, and IC §12.2 does not call for one.
func RunHeartbeat(ctx context.Context, cfg HeartbeatConfig) {
	heartbeatTimer := time.NewTimer(jitteredInterval(cfg.Profile.HeartbeatInterval, cfg.Profile.HeartbeatJitter))
	defer heartbeatTimer.Stop()

	republishTimer := time.NewTimer(jitteredRepublishInterval(cfg.Profile.DHTRepublishInterval))
	defer republishTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatTimer.C:
			doHeartbeat(ctx, cfg)
			heartbeatTimer.Reset(jitteredInterval(cfg.Profile.HeartbeatInterval, cfg.Profile.HeartbeatJitter))
		case <-republishTimer.C:
			doRepublish(ctx, cfg)
			republishTimer.Reset(jitteredRepublishInterval(cfg.Profile.DHTRepublishInterval))
		}
	}
}

// dhtRepublishJitterFraction bounds the random jitter applied to each DHT
// republication cycle, as a fraction of cfg.Profile.DHTRepublishInterval
// itself — unlike the heartbeat timer, NetworkProfile has no dedicated
// republication-jitter field (IC §12.2 does not call for one), so jitter is
// derived from the existing interval rather than adding a new profile
// field. Still closes the real operational gap M6 review §8 flagged:
// without this, a fleet of daemons started around the same time
// republishes in lockstep on every cycle.
const dhtRepublishJitterFraction = 10 // interval/10 = ±10% jitter

// jitteredRepublishInterval applies ±(base/dhtRepublishJitterFraction)
// jitter to base, reusing the existing, already-tested jitteredInterval
// helper. Falls back to base unchanged if the derived jitter window is too
// small to be meaningful (e.g. an aggressively fast test profile).
// [REF: IC §12.2, M6 review §8]
func jitteredRepublishInterval(base time.Duration) time.Duration {
	jitter := base / dhtRepublishJitterFraction
	if jitter <= 0 {
		return base
	}
	return jitteredInterval(base, jitter)
}

// jitteredInterval returns base plus a uniformly random offset in
// [-jitter, +jitter]. jitter <= 0 returns base unchanged.
func jitteredInterval(base, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return base
	}
	span := int64(jitterRangeMultiplier*jitter) + 1
	offset := time.Duration(mathrand.Int64N(span)) - jitter
	return base + offset
}

// ── doHeartbeat ────────────────────────────────────────────────────────────

// doHeartbeat sends one signed heartbeat to the microservice control plane
// (IC §3.1).
//
// Steps:
//  1. Token refresh check: if expiry is under tokenRefreshLeadTime away (or
//     already past), call cfg.RefreshToken (IC §3.1). A failure here does not
//     abort the heartbeat — the existing token is still sent, and refresh is
//     retried next cycle — unless the token is also past
//     tokenExpiredGracePeriod, in which case cfg.NeedsReauth fires.
//  2. Collect current multiaddrs from cfg.CurrentAddrs (includes any active
//     relay address).
//  3. Build the canonical signing input (current_multiaddrs, timestamp;
//     provider_sig excluded) and sign it (IC §3.1, IC §3.2).
//  4. POST the full wire payload to cfg.MicroserviceURL + heartbeatPath.
func doHeartbeat(ctx context.Context, cfg HeartbeatConfig) {
	maybeRefreshToken(ctx, cfg)

	var addrs []string
	if cfg.CurrentAddrs != nil {
		for _, a := range cfg.CurrentAddrs() {
			addrs = append(addrs, a.String())
		}
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)

	signingInput, err := canonicalHeartbeatSigningInput(addrs, timestamp)
	if err != nil {
		log.Printf("[heartbeat] build signing input: %v", err)
		return
	}
	sig := localcrypto.SignBytes(cfg.SigningKey, signingInput)

	payload := heartbeatWirePayload{
		ProviderID:        cfg.ProviderID,
		CurrentMultiaddrs: addrs,
		Timestamp:         timestamp,
		DaemonVersion:     cfg.DaemonVersion,
		// hex, not base64 — matches decodeProviderSig / every other
		// provider_sig in the system (internal/api/provider.go's own
		// header comment already flagged this exact mismatch as a real,
		// unfixed cross-package bug; fixed here as part of closing the
		// PENDING_ONBOARDING->VETTING heartbeat gap, discovered via live
		// verification, build.md Session 16.1.1).
		ProviderSig: hex.EncodeToString(sig[:]),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[heartbeat] marshal wire payload: %v", err)
		return
	}

	// Authorization: Bearer <provider JWT> — POST /api/v1/provider/heartbeat
	// is bearerAuthRole("provider")-gated server-side (router.go); this was
	// missing entirely before (postHeartbeat took no token parameter at
	// all), which is why every heartbeat attempt was rejected with 401
	// "missing Bearer token" regardless of GetToken/RefreshToken existing
	// on HeartbeatConfig — discovered via live verification, not visible
	// from code review alone (build.md Session 16.1.1).
	var token string
	if cfg.GetToken != nil {
		token, _ = cfg.GetToken()
	}
	status, respBody, err := postHeartbeat(ctx, cfg.effectiveHTTPClient(), cfg.MicroserviceURL+heartbeatPath, token, body)
	if err != nil {
		log.Printf("[heartbeat] send failed; will retry next cycle: %v", err)
		return
	}
	if status != http.StatusOK {
		log.Printf("[heartbeat] microservice returned %d: %s", status, respBody)
	}
}

// maybeRefreshToken implements the token-refresh half of IC §3.1's heartbeat
// pseudocode, plus the "beyond the 1-hour grace period" re-registration
// escalation.
func maybeRefreshToken(ctx context.Context, cfg HeartbeatConfig) {
	if cfg.GetToken == nil || cfg.RefreshToken == nil {
		return
	}
	_, expiry := cfg.GetToken()
	untilExpiry := time.Until(expiry)
	if untilExpiry >= tokenRefreshLeadTime {
		return
	}

	if err := cfg.RefreshToken(ctx); err != nil {
		log.Printf("[heartbeat] token refresh failed; will retry next cycle: %v", err)
		if untilExpiry < -tokenExpiredGracePeriod && cfg.NeedsReauth != nil {
			cfg.NeedsReauth()
		}
	}
}

func (cfg HeartbeatConfig) effectiveHTTPClient() *http.Client {
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient
	}
	return &http.Client{Timeout: heartbeatHTTPTimeout}
}

// heartbeatWirePayload is the full JSON envelope actually transmitted.
// Using encoding/json here (unlike the signing input) is safe: this is the
// transmitted representation, not the signed byte sequence — its exact
// layout has no cryptographic significance, only the signing input's does
// (IC §3.2).
type heartbeatWirePayload struct {
	ProviderID        string   `json:"provider_id,omitempty"`
	CurrentMultiaddrs []string `json:"current_multiaddrs"`
	Timestamp         string   `json:"timestamp"`
	DaemonVersion     string   `json:"daemon_version,omitempty"`
	ProviderSig       string   `json:"provider_sig"`
}

// canonicalHeartbeatSigningInput builds the exact byte sequence that is
// hashed and signed for a heartbeat payload (IC §3.1, IC §3.2).
//
// This is hand-constructed rather than produced by encoding/json.Marshal on
// a struct or map: IC §3.2 requires signing inputs to be "a fixed-layout
// byte sequence" whose encoding is not left to a library's internal,
// version-dependent behaviour. The two required signing fields are written
// in a fixed, explicitly sorted order (current_multiaddrs, then timestamp —
// already alphabetical; provider_sig is excluded from the signing input per
// IC §3.1), removing any dependency on encoding/json's field-ordering
// behaviour for this security-relevant computation. Individual string
// values are still escaped via encoding/json.Marshal on the bare string
// (safe: escaping one string has no field-ordering ambiguity), so this does
// not reimplement JSON string escaping by hand.
func canonicalHeartbeatSigningInput(multiaddrs []string, timestamp string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(`{"current_multiaddrs":[`)
	for i, addr := range multiaddrs {
		if i > 0 {
			buf.WriteByte(',')
		}
		escaped, err := json.Marshal(addr)
		if err != nil {
			return nil, fmt.Errorf("p2p: canonicalHeartbeatSigningInput: escape multiaddr: %w", err)
		}
		buf.Write(escaped)
	}
	buf.WriteString(`],"timestamp":`)
	escapedTS, err := json.Marshal(timestamp)
	if err != nil {
		return nil, fmt.Errorf("p2p: canonicalHeartbeatSigningInput: escape timestamp: %w", err)
	}
	buf.Write(escapedTS)
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// postHeartbeat sends body to url via client, with an Authorization: Bearer
// header when token is non-empty, returning the HTTP status code and
// response body.
func postHeartbeat(ctx context.Context, client *http.Client, url, token string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("p2p: postHeartbeat: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("p2p: postHeartbeat: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("p2p: postHeartbeat: read response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

// ── doRepublish ────────────────────────────────────────────────────────────

// doRepublish re-announces all locally stored chunks in the DHT (IC §12.2,
// ARCH §13).
//
// Steps (IC §12.2 §DHT Republication Contract):
//  1. Retrieve every (chunk ID, cached DHT key) pair this daemon holds via
//     cfg.Store.AllChunkDHTKeys() — never recomputed, since the per-file
//     secret needed to derive a DHT key belongs to the data owner and is not
//     available to the daemon after upload completes (IC §12.2).
//  2. Call cfg.DHT.PutProviderRecord(ctx, dhtKey) for each, best-effort: one
//     failed key does not abort the batch.
const (
	// doRepublishMaxConcurrency bounds how many PutProviderRecord calls run
	// in parallel during one republish cycle — without this, republication
	// is fully serial, and each PutProviderRecord internally opens up to
	// kBucketSize (dht.go) fresh streams of its own.
	doRepublishMaxConcurrency = 8

	// doRepublishMaxPerCycle caps how many chunks a single republish cycle
	// attempts. A provider can hold up to ~200,000+ chunks at 50GB declared
	// storage (ARCH §27.2) — without a cap, one cycle could still be
	// running when the next DHTRepublishInterval fires. Any keys beyond the
	// cap are simply picked up on a later cycle (AllChunkDHTKeys is
	// re-queried fresh every cycle, so there is no missed-forever key, only
	// a bounded delay before retry — IC §12.2's staleness window is hours,
	// not seconds, so this delay is immaterial in practice).
	//
	// [REF: ARCH §27.2, IC §12.2, M6 review §8]
	doRepublishMaxPerCycle = 5000
)

func doRepublish(ctx context.Context, cfg HeartbeatConfig) {
	if cfg.Store == nil || cfg.DHT == nil {
		return
	}

	keys, err := cfg.Store.AllChunkDHTKeys()
	if err != nil {
		log.Printf("[republish] read local DHT key cache: %v", err)
		return
	}

	type republishJob struct {
		chunkID [32]byte
		dhtKey  [32]byte
	}
	jobs := make(chan republishJob, doRepublishMaxConcurrency)

	var wg sync.WaitGroup
	var failed int32 // written concurrently by worker goroutines below; read after wg.Wait()
	for i := 0; i < doRepublishMaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if err := cfg.DHT.PutProviderRecord(ctx, j.dhtKey[:]); err != nil {
					atomic.AddInt32(&failed, 1)
					log.Printf("[republish] chunk %x: PutProviderRecord failed: %v", j.chunkID, err)
				}
			}
		}()
	}

	// Only this goroutine ever touches attempted/skipped — no atomics needed.
	attempted, skipped := 0, 0
	for chunkID, dhtKey := range keys {
		if attempted >= doRepublishMaxPerCycle {
			skipped++
			continue
		}
		attempted++
		jobs <- republishJob{chunkID: chunkID, dhtKey: dhtKey}
	}
	close(jobs)
	wg.Wait()

	if failed > 0 {
		log.Printf("[republish] %d/%d chunk records failed to republish this cycle", failed, attempted)
	}
	if skipped > 0 {
		log.Printf("[republish] %d chunk records deferred to a later cycle (per-cycle cap %d reached)", skipped, doRepublishMaxPerCycle)
	}
}

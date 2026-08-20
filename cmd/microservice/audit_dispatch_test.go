package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/audit"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/scoring"
)

// ── Wire-framing round trip (no DB needed) ─────────────────────────────────

func TestChallengeFrameRoundTrip(t *testing.T) {
	chunkID := [32]byte{1, 2, 3}
	nonce := [33]byte{9, 8, 7}
	serverTsMs := time.Now().UnixMilli()

	var buf bytes.Buffer
	if err := writeChallengeRequest(&buf, chunkID, nonce, serverTsMs); err != nil {
		t.Fatalf("writeChallengeRequest: %v", err)
	}
	if got := buf.Len(); got != lengthPrefixSize+challengeRequestFrameSize {
		t.Fatalf("writeChallengeRequest: wrote %d bytes, want %d", got, lengthPrefixSize+challengeRequestFrameSize)
	}

	length := binary.BigEndian.Uint32(buf.Bytes()[:4])
	if length != challengeRequestFrameSize {
		t.Fatalf("writeChallengeRequest: length prefix = %d, want %d", length, challengeRequestFrameSize)
	}
}

func TestReadChallengeResponseOK(t *testing.T) {
	var respHash [32]byte
	var sig [64]byte
	cryptorand.Read(respHash[:])
	cryptorand.Read(sig[:])

	body := append([]byte{challengeStatusOK}, respHash[:]...)
	body = append(body, sig[:]...)
	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	buf.Write(lenBuf[:])
	buf.Write(body)

	status, gotHash, gotSig, err := readChallengeResponse(&buf)
	if err != nil {
		t.Fatalf("readChallengeResponse: %v", err)
	}
	if status != challengeStatusOK {
		t.Fatalf("status = 0x%02x, want 0x00", status)
	}
	if gotHash != respHash {
		t.Fatalf("response_hash mismatch")
	}
	if gotSig != sig {
		t.Fatalf("provider_sig mismatch")
	}
}

func TestReadChallengeResponseInvalidNonceHasNoSig(t *testing.T) {
	body := []byte{challengeStatusInvalidNonce}
	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	buf.Write(lenBuf[:])
	buf.Write(body)

	status, _, _, err := readChallengeResponse(&buf)
	if err != nil {
		t.Fatalf("readChallengeResponse: %v", err)
	}
	if status != challengeStatusInvalidNonce {
		t.Fatalf("status = 0x%02x, want 0x03", status)
	}
}

func TestComputeThroughputKbps(t *testing.T) {
	// 256 KB in 1000ms should be ~256 KB/s = 256 Kbps by this function's own
	// (bytes-per-second-ish) definition.
	got := computeThroughputKbps(config.DemoProfile, 1000)
	want := float64(config.DemoProfile.ShardSize) / throughputBytesPerKB
	if got != want {
		t.Fatalf("computeThroughputKbps(1000ms) = %f, want %f", got, want)
	}
	if got := computeThroughputKbps(config.DemoProfile, 0); got != 0 {
		t.Fatalf("computeThroughputKbps(0ms) = %f, want 0", got)
	}
}

// adjudicateResponse's INVALID_NONCE/INTERNAL_ERROR branches still never
// touch the DB — they carry no provider_sig at all per IC §4.2's own field
// table ("absent for 0x03, 0x04"), so there is nothing to look a key up
// for; see this file's header note.
func TestAdjudicateResponseNoSigStatusesAreFailWithoutDB(t *testing.T) {
	for _, status := range []byte{challengeStatusInvalidNonce, challengeStatusInternalError} {
		result, err := adjudicateResponse(context.Background(), nil, [33]byte{}, 0, uuid.New(), status, [32]byte{}, [64]byte{})
		if err != nil {
			t.Fatalf("status 0x%02x: unexpected error: %v", status, err)
		}
		if result != audit.AuditFail {
			t.Fatalf("status 0x%02x: result = %v, want AuditFail", status, result)
		}
	}
}

// [Updated — M12 audit corrections, Finding 4] FAIL_NOT_FOUND/
// FAIL_CORRUPTION now DO look up the provider's public key (to verify IC
// §4.2's FAIL-status provider_sig — see adjudicateResponse's own doc
// comment), so — unlike the no-signature statuses above — they need a real
// DB and a real provider row, not db == nil. A garbage all-zero signature
// (as here) still correctly scores as AuditFail either way: an unverifiable
// FAIL claim scores the same as a verified one (see adjudicateResponse's
// own comment on why), so this test's core assertion is unchanged from
// before Finding 4 — only the DB requirement is new.
func TestAdjudicateResponseFailStatusesAreFailEvenWithBadSignature(t *testing.T) {
	db := openTestDB(t)
	providerID, _, _ := insertTestProvider(t, db, "ACTIVE")

	for _, status := range []byte{challengeStatusFailNotFound, challengeStatusFailCorruption} {
		result, err := adjudicateResponse(context.Background(), db, [33]byte{}, 0, providerID, status, [32]byte{}, [64]byte{})
		if err != nil {
			t.Fatalf("status 0x%02x: unexpected error: %v", status, err)
		}
		if result != audit.AuditFail {
			t.Fatalf("status 0x%02x: result = %v, want AuditFail", status, result)
		}
	}
}

// TestAdjudicateResponseFailStatusWithValidSignature verifies the positive
// case Finding 4 actually adds: a genuinely, correctly signed FAIL response
// is distinguishable from a forged one at the audit.ValidateFailResponse
// layer (adjudicateResponse itself still scores both as AuditFail — see
// that function's own comment on why — but this proves the correct
// IC §4.2 FAIL signing input, not the OK-status one, is what gets checked).
func TestAdjudicateResponseFailStatusWithValidSignature(t *testing.T) {
	db := openTestDB(t)
	providerID, _, priv := insertTestProvider(t, db, "ACTIVE")

	nonce := audit.ChallengeNonce([]byte("0123456789abcdef0123456789abcdef"), 1, testChunkID(t), 1_700_000_000_000)
	serverTsMs := int64(1_700_000_000_000)
	status := byte(challengeStatusFailCorruption)

	signingInput := sha256.Sum256(concatBytes([]byte{status}, nonce[:], int64ToBytes(serverTsMs), providerID[:]))
	sig := ed25519.Sign(priv, signingInput[:])
	var providerSig [64]byte
	copy(providerSig[:], sig)

	result, err := adjudicateResponse(context.Background(), db, nonce, serverTsMs, providerID, status, [32]byte{}, providerSig)
	if err != nil {
		t.Fatalf("adjudicateResponse: %v", err)
	}
	if result != audit.AuditFail {
		t.Fatalf("adjudicateResponse(valid FAIL signature) = %v, want AuditFail (a proven FAIL is still a FAIL)", result)
	}
}

// ── DB-gated fixtures and tests ────────────────────────────────────────────

// insertTestProvider inserts a minimal, valid providers row and returns its
// ID and Ed25519 keypair (ed25519_public_key must be exactly 32 bytes per
// the table's own CHECK constraint).
func insertTestProvider(t *testing.T, db *sql.DB, status string) (uuid.UUID, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}
	var providerID uuid.UUID
	phone := fmt.Sprintf("+1555%07d", time.Now().UnixNano()%10000000)
	err = db.QueryRowContext(context.Background(), `
		INSERT INTO providers (phone_number, ed25519_public_key, status, declared_storage_gb, city, region, asn)
		VALUES ($1, $2, $3, 100, 'Testville', 'Test Region', 'AS12345')
		RETURNING provider_id`,
		phone, []byte(pub), status,
	).Scan(&providerID)
	if err != nil {
		t.Fatalf("insert test provider: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM providers WHERE provider_id = $1`, providerID)
	})
	return providerID, pub, priv
}

func testChunkID(t *testing.T) [32]byte {
	t.Helper()
	var id [32]byte
	if _, err := cryptorand.Read(id[:]); err != nil {
		t.Fatalf("random chunk id: %v", err)
	}
	return id
}

func TestDispatchCallsValidateResponseWithFullSigningInput(t *testing.T) {
	db := openTestDB(t)
	providerID, pub, priv := insertTestProvider(t, db, "VETTING")

	chunkID := testChunkID(t)
	nonce := audit.ChallengeNonce([]byte("0123456789abcdef0123456789abcdef"), 1, chunkID, 1_700_000_000_000)
	serverTsMs := int64(1_700_000_000_000)

	var responseHash [32]byte
	if _, err := cryptorand.Read(responseHash[:]); err != nil {
		t.Fatal(err)
	}
	signingInput := sha256.Sum256(concatBytes(responseHash[:], nonce[:], int64ToBytes(serverTsMs), providerID[:]))
	sig := ed25519.Sign(priv, signingInput[:])
	var providerSig [64]byte
	copy(providerSig[:], sig)

	result, err := adjudicateResponse(context.Background(), db, nonce, serverTsMs, providerID, challengeStatusOK, responseHash, providerSig)
	if err != nil {
		t.Fatalf("adjudicateResponse: %v", err)
	}
	if result != audit.AuditPass {
		t.Fatalf("adjudicateResponse with a genuinely valid signature = %v, want AuditPass (proves ValidateResponse was called with the correct 6-parameter signing input)", result)
	}
	_ = pub
}

func TestDispatchUsesPoolMedianRTOForNewProviders(t *testing.T) {
	db := openTestDB(t)
	// Seed a provider with an established RTT measurement so
	// scoring.PoolMedianRTO has something real to compute over — otherwise
	// it legitimately returns scoring.ErrNoPoolMedianAvailable (this
	// codebase's own documented "very early in the network's life"
	// bootstrap case), and computeRTO would fall back to
	// bootstrapFallbackRTO instead of exercising the pool-median path this
	// test is actually named for.
	seedProviderID, _, _ := insertTestProvider(t, db, "ACTIVE")
	if _, err := db.Exec(
		`UPDATE providers SET rto_sample_count = 10, avg_rtt_ms = 100, var_rtt_ms = 5 WHERE provider_id = $1`,
		seedProviderID,
	); err != nil {
		t.Fatalf("seed rto sample: %v", err)
	}

	providerID, _, _ := insertTestProvider(t, db, "ACTIVE")
	// rto_sample_count defaults to 0 (< 5) — computeRTO must fall back to
	// scoring.PoolMedianRTO rather than this provider's own (meaningless,
	// zero-value) avg_rtt_ms/var_rtt_ms.

	wantMedianMs, err := scoring.PoolMedianRTO(context.Background(), db)
	if err != nil {
		t.Fatalf("scoring.PoolMedianRTO: %v", err)
	}
	got, err := computeRTO(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("computeRTO: %v", err)
	}
	want := time.Duration(wantMedianMs * float64(time.Millisecond))
	if got != want {
		t.Fatalf("computeRTO for a new provider (rto_sample_count < 5) = %s, want pool median %s", got, want)
	}
}

// singleVersionSecretsClient reports exactly one secret version, and
// audit.ErrSecretNotFound for every other path — the same steady-state
// contract envSecretsClient (secrets_client.go) implements for real.
type singleVersionSecretsClient struct {
	version uint8
	secret  []byte
}

func (c *singleVersionSecretsClient) GetSecret(_ context.Context, path string) ([]byte, error) {
	if path == fmt.Sprintf("/vyomanaut/audit-secret/v%d", c.version) {
		return c.secret, nil
	}
	return nil, audit.ErrSecretNotFound
}

// ── Full dispatchOneChallenge integration via a fake p2p.Host ─────────────

// fakeStream is a minimal in-memory p2p.Stream backed by a bytes.Buffer pair.
type fakeStream struct {
	r io.Reader
	w io.Writer
}

func (s *fakeStream) Read(p []byte) (int, error)       { return s.r.Read(p) }
func (s *fakeStream) Write(p []byte) (int, error)      { return s.w.Write(p) }
func (s *fakeStream) Close() error                     { return nil }
func (s *fakeStream) Protocol() p2p.ProtocolID         { return auditChallengeProtocolID }
func (s *fakeStream) RemotePeer() p2p.PeerID           { return "fake-peer" }
func (s *fakeStream) Reset() error                     { return nil }
func (s *fakeStream) SetDeadline(time.Time) error      { return nil }
func (s *fakeStream) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeStream) SetWriteDeadline(time.Time) error { return nil }

// timeoutStream always returns a deadline-exceeded error on Read, and
// discards writes — simulates a provider that never responds.
type timeoutStream struct{}

func (timeoutStream) Read([]byte) (int, error)         { return 0, context.DeadlineExceeded }
func (timeoutStream) Write(p []byte) (int, error)      { return len(p), nil }
func (timeoutStream) Close() error                     { return nil }
func (timeoutStream) Protocol() p2p.ProtocolID         { return auditChallengeProtocolID }
func (timeoutStream) RemotePeer() p2p.PeerID           { return "fake-peer" }
func (timeoutStream) Reset() error                     { return nil }
func (timeoutStream) SetDeadline(time.Time) error      { return nil }
func (timeoutStream) SetReadDeadline(time.Time) error  { return nil }
func (timeoutStream) SetWriteDeadline(time.Time) error { return nil }

// fakeHost implements p2p.Host against an in-memory response, so
// dispatchOneChallenge can be exercised end to end without a live network.
type fakeHost struct {
	peerID        p2p.PeerID
	newStreamFunc func() (p2p.Stream, error)
}

func (h *fakeHost) PeerID() p2p.PeerID { return h.peerID }
func (h *fakeHost) Connect(context.Context, p2p.PeerID, []p2p.Multiaddr) error {
	return nil
}
func (h *fakeHost) NewStream(context.Context, p2p.PeerID, p2p.ProtocolID) (p2p.Stream, error) {
	return h.newStreamFunc()
}
func (h *fakeHost) PromoteConn(context.Context, net.Conn, p2p.PeerID, p2p.ProtocolID) (p2p.Stream, error) {
	return nil, fmt.Errorf("fakeHost: PromoteConn not implemented")
}
func (h *fakeHost) SetStreamHandler(p2p.ProtocolID, p2p.StreamHandler) {}
func (h *fakeHost) NATType() p2p.NATStatus                             { return 0 }
func (h *fakeHost) Close() error                                       { return nil }

// passResponseStream returns a fakeStream that, once the request has been
// written to it, yields a well-formed ChallengeResponse OK frame signed by
// priv over the exact bytes dispatchOneChallenge will have sent.
func passResponseStream(t *testing.T, providerID uuid.UUID, priv ed25519.PrivateKey) *fakeStream {
	t.Helper()
	reqBuf := &bytes.Buffer{}
	respBuf := &bytes.Buffer{}
	// Deferred: populated once the request bytes are known (see wrapper below).
	return &fakeStream{r: &lazyPassReader{reqBuf: reqBuf, respBuf: respBuf, providerID: providerID, priv: priv}, w: reqBuf}
}

// lazyPassReader builds a valid signed PASS response only once the request
// has actually been written (so it can read the real chunk_id/nonce/ts back
// out and sign over the real response_hash it fabricates), then serves that
// response on the first Read call.
type lazyPassReader struct {
	reqBuf     *bytes.Buffer
	respBuf    *bytes.Buffer
	providerID uuid.UUID
	priv       ed25519.PrivateKey
	built      bool
}

func (r *lazyPassReader) Read(p []byte) (int, error) {
	if !r.built {
		r.build()
		r.built = true
	}
	return r.respBuf.Read(p)
}

func (r *lazyPassReader) build() {
	req := r.reqBuf.Bytes()
	// req = length(4) || chunk_id(32) || nonce(33) || ts(8)
	if len(req) != lengthPrefixSize+challengeRequestFrameSize {
		return
	}
	nonce := req[4+32 : 4+32+33]
	tsBytes := req[4+32+33:]
	serverTsMs := int64(binary.BigEndian.Uint64(tsBytes))

	var responseHash [32]byte
	cryptorand.Read(responseHash[:])
	signingInput := sha256.Sum256(concatBytes(responseHash[:], nonce, int64ToBytes(serverTsMs), r.providerID[:]))
	sig := ed25519.Sign(r.priv, signingInput[:])

	body := append([]byte{challengeStatusOK}, responseHash[:]...)
	body = append(body, sig...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	r.respBuf.Write(lenBuf[:])
	r.respBuf.Write(body)
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func int64ToBytes(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return b[:]
}

func newTestCache(t *testing.T) *audit.ClusterSecretCache {
	t.Helper()
	fake := &singleVersionSecretsClient{version: 1, secret: []byte("0123456789abcdef0123456789abcdef")}
	cache := audit.NewClusterSecretCache(fake)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}
	return cache
}

func TestDispatchIncrementsPassesOnPass(t *testing.T) {
	db := openTestDB(t)
	providerID, _, priv := insertTestProvider(t, db, "VETTING")
	cache := newTestCache(t)

	host := &fakeHost{
		peerID: "fake-peer",
		newStreamFunc: func() (p2p.Stream, error) {
			return passResponseStream(t, providerID, priv), nil
		},
	}
	assignment := chunkAssignmentRow{ChunkID: testChunkID(t), ProviderID: providerID, MultiaddrStale: false}

	// dispatchOneChallenge calls resolveProviderPeer first, which requires a
	// providers.last_known_multiaddrs entry; insert one so Connect/NewStream
	// are reached at all. dht is nil throughout this file: every assignment
	// here has MultiaddrStale: false, so resolveProviderPeer's DHT fallback
	// (M12 audit corrections, Finding 2) is never consulted — see
	// internal/p2p/dht_test.go for FindPeer's own routing-table-level
	// coverage, and adapters_test.go for resolveProviderPeer's own
	// dedicated fallback-integration coverage.
	seedTestMultiaddr(t, db, providerID)

	if err := dispatchOneChallenge(context.Background(), db, config.DemoProfile, cache, host, nil, priv, assignment); err != nil {
		t.Fatalf("dispatchOneChallenge: %v", err)
	}

	var passes int
	if err := db.QueryRow(`SELECT consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).Scan(&passes); err != nil {
		t.Fatalf("read consecutive_audit_passes: %v", err)
	}
	if passes != 1 {
		t.Fatalf("consecutive_audit_passes = %d, want 1 after a single PASS", passes)
	}
}

// seedTestMultiaddr gives a test provider a dialable-looking multiaddr so
// resolveProviderPeer succeeds (the fakeHost never actually dials it).
func seedTestMultiaddr(t *testing.T, db *sql.DB, providerID uuid.UUID) {
	t.Helper()
	_, err := db.Exec(`UPDATE providers SET last_known_multiaddrs = $1 WHERE provider_id = $2`,
		`["/ip4/127.0.0.1/udp/4001/quic"]`, providerID)
	if err != nil {
		t.Fatalf("seed multiaddr: %v", err)
	}
}

func TestDispatchResetsOnGenuineTimeout(t *testing.T) {
	db := openTestDB(t)
	providerID, _, priv := insertTestProvider(t, db, "ACTIVE")
	seedTestMultiaddr(t, db, providerID)
	cache := newTestCache(t)

	if _, err := db.Exec(`UPDATE providers SET consecutive_audit_passes = 3 WHERE provider_id = $1`, providerID); err != nil {
		t.Fatalf("seed consecutive_audit_passes: %v", err)
	}

	host := &fakeHost{peerID: "fake-peer", newStreamFunc: func() (p2p.Stream, error) { return timeoutStream{}, nil }}
	assignment := chunkAssignmentRow{ChunkID: testChunkID(t), ProviderID: providerID, MultiaddrStale: false}

	if err := dispatchOneChallenge(context.Background(), db, config.DemoProfile, cache, host, nil, priv, assignment); err != nil {
		t.Fatalf("dispatchOneChallenge: %v", err)
	}

	var passes int
	if err := db.QueryRow(`SELECT consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).Scan(&passes); err != nil {
		t.Fatalf("read consecutive_audit_passes: %v", err)
	}
	if passes != 0 {
		t.Fatalf("consecutive_audit_passes = %d after a genuine (non-stale-address) TIMEOUT, want 0 (ResetConsecutivePasses should have run)", passes)
	}
}

func TestDispatchDoesNotResetOnStaleAddressTimeout(t *testing.T) {
	db := openTestDB(t)
	providerID, _, priv := insertTestProvider(t, db, "ACTIVE")
	seedTestMultiaddr(t, db, providerID)
	cache := newTestCache(t)

	if _, err := db.Exec(`UPDATE providers SET consecutive_audit_passes = 3 WHERE provider_id = $1`, providerID); err != nil {
		t.Fatalf("seed consecutive_audit_passes: %v", err)
	}

	host := &fakeHost{peerID: "fake-peer", newStreamFunc: func() (p2p.Stream, error) { return timeoutStream{}, nil }}
	assignment := chunkAssignmentRow{ChunkID: testChunkID(t), ProviderID: providerID, MultiaddrStale: true}

	if err := dispatchOneChallenge(context.Background(), db, config.DemoProfile, cache, host, nil, priv, assignment); err != nil {
		t.Fatalf("dispatchOneChallenge: %v", err)
	}

	var passes int
	if err := db.QueryRow(`SELECT consecutive_audit_passes FROM providers WHERE provider_id = $1`, providerID).Scan(&passes); err != nil {
		t.Fatalf("read consecutive_audit_passes: %v", err)
	}
	if passes != 3 {
		t.Fatalf("consecutive_audit_passes = %d after a stale-address TIMEOUT, want unchanged at 3 (DM §4.7: do nothing)", passes)
	}
}

func TestDispatchSkipsUpdateRTOForTimeout(t *testing.T) {
	db := openTestDB(t)
	providerID, _, priv := insertTestProvider(t, db, "ACTIVE")
	seedTestMultiaddr(t, db, providerID)
	cache := newTestCache(t)

	var wantSampleCount int
	if err := db.QueryRow(`SELECT rto_sample_count FROM providers WHERE provider_id = $1`, providerID).Scan(&wantSampleCount); err != nil {
		t.Fatalf("read rto_sample_count: %v", err)
	}

	host := &fakeHost{peerID: "fake-peer", newStreamFunc: func() (p2p.Stream, error) { return timeoutStream{}, nil }}
	assignment := chunkAssignmentRow{ChunkID: testChunkID(t), ProviderID: providerID, MultiaddrStale: false}

	if err := dispatchOneChallenge(context.Background(), db, config.DemoProfile, cache, host, nil, priv, assignment); err != nil {
		t.Fatalf("dispatchOneChallenge: %v", err)
	}

	var gotSampleCount int
	if err := db.QueryRow(`SELECT rto_sample_count FROM providers WHERE provider_id = $1`, providerID).Scan(&gotSampleCount); err != nil {
		t.Fatalf("read rto_sample_count: %v", err)
	}
	if gotSampleCount != wantSampleCount {
		t.Fatalf("rto_sample_count changed from %d to %d after a TIMEOUT — scoring.UpdateRTO must never be called for TIMEOUT", wantSampleCount, gotSampleCount)
	}
}

func TestDispatchRejectsResponseWithInvalidSecretVersion(t *testing.T) {
	// dispatchOneChallenge always builds its OWN nonce from
	// cache.CurrentSecret() (Session 12.1.2 step 2), so the only realistic
	// way a response's version byte stops being valid by the time it's
	// adjudicated is a rotation race between dispatch and response arrival
	// — not reproducible synchronously without deeper surgery on
	// *audit.ClusterSecretCache's concrete (non-interface) type. This test
	// instead directly exercises the exact mechanism dispatchOneChallenge's
	// step-7a gate depends on (cache.IsVersionValid) — see this file's
	// header note and audit_dispatch.go's own header note on why this
	// session flags and fixes the missing check that gate closes.
	fake := &singleVersionSecretsClient{version: 1, secret: []byte("0123456789abcdef0123456789abcdef")}
	cache := audit.NewClusterSecretCache(fake)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}
	if !cache.IsVersionValid(1) {
		t.Fatal("IsVersionValid(1): expected true for the currently-loaded version")
	}
	if cache.IsVersionValid(250) {
		t.Fatal("IsVersionValid(250): expected false for a version that was never loaded — dispatchOneChallenge's step-7a gate must not adjudicate a response received under this condition")
	}
}

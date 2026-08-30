package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"
)

// ── test helpers ───────────────────────────────────────────────────────────
//
// Unlike the original build.md template (which left buildTestHost/buildTestDHT
// as t.Skip stubs pending Host construction), Session 6.1.1 already delivered
// a working NewHost, so these are real, running constructors.

// buildTestHost creates a Host with a fresh Ed25519 identity, listening on an
// OS-assigned loopback port.
func buildTestHost(t *testing.T) Host {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	h, err := NewHost(HostConfig{PrivateKey: priv, ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// buildTestDHT creates a kademliaDHT instance wired to host, with
// dhtKeyNamespace registered as its stream protocol.
func buildTestDHT(t *testing.T, host Host) DHT {
	t.Helper()
	addr, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, host))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	d, err := NewDHT(host, DHTConfig{SelfAddrs: []Multiaddr{addr}})
	if err != nil {
		t.Fatalf("NewDHT: %v", err)
	}
	return d
}

func testHostPort(t *testing.T, h Host) string {
	t.Helper()
	concrete, ok := h.(*host)
	if !ok || concrete.listener == nil {
		t.Fatalf("buildTestDHT: host has no listener")
	}
	return portOf(t, concrete.listener.Addr().String())
}

// sha256Multihash builds a bare SHA2-256 multihash exactly as
// github.com/multiformats/go-multihash's mh.Sum(data, mh.SHA2_256, -1) would:
// varint(0x12) || varint(32) || 32-byte digest = 34 bytes. Both varints are
// single bytes here, so this is a plain byte concatenation. Used in place of
// that package (unavailable in this build environment — see doc.go) to
// exercise the same "plain CID/multihash must be rejected" regression case
// IC §12 describes.
func sha256Multihash(data []byte) []byte {
	sum := sha256.Sum256(data)
	out := []byte{0x12, 32}
	return append(out, sum[:]...)
}

// ── Session 6.2.3 mandatory CI gate ───────────────────────────────────────────

// TestDHTKeyValidatorPersists is a mandatory CI gate (CI check 5, MVP §8.4).
//
// PURPOSE: Detect a silent namespace/validator regression. If a future change
// resets the custom HMAC validator to accept arbitrary byte strings (or the
// default CID/multihash shape), this test catches it immediately.
//
// Run with: go test -run TestDHTKeyValidatorPersists ./internal/p2p/
// This test MUST be re-run after every change to dht.go's validator logic.
//
// TRACK: DEMO+LTS — rationale restated, assertions unchanged (Session 18.1.1,
// ADR-062 §1, ADR-063 §3).
//
// This check's originally documented trigger was "re-run after every
// go-libp2p upgrade." That trigger does not exist on the demo track, because
// its subject does not: this repository never imported go-libp2p, and the
// DHT below it is a from-scratch
// Kademlia implementation over stdlib TLS 1.3/TCP, not
// go-libp2p-kad-dht — the substitution is recorded in full in doc.go and
// ratified by ADR-063. There is no upgrade that could ever fire the original
// trigger here, so a reader who took the comment at face value would conclude
// this gate guards something it does not.
//
// The property this test actually guards, on both tracks, is IC §12's key
// accept/reject rules — 32-byte HMAC-derived keys accepted, plain
// multihash-shaped keys and any other length rejected — implemented
// byte-for-byte against that contract. ADR-063's substitution table lists
// exactly this row as "preserved exactly," with the routing machinery
// (k-buckets, iterative lookup) as the approximated part. That is why the
// gate is DEMO+LTS and not LTS: the assertions below hold identically once
// go-libp2p-kad-dht is restored behind the same validator in the LTS
// Foundation milestone, and any change that weakens them breaks this test on
// either track.
func TestDHTKeyValidatorPersists(t *testing.T) {
	ctx := context.Background()
	testHost := buildTestHost(t)
	dht := buildTestDHT(t, testHost)

	// CASE 1: A valid 32-byte HMAC-derived key MUST be accepted by the validator.
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i + 1) // deterministic, non-zero test key
	}
	err := dht.PutProviderRecord(ctx, validKey)
	if err != nil {
		t.Errorf("valid 32-byte key must be accepted; a failure here means the HMAC validator is broken: %v", err)
	}

	// CASE 2: A plain multihash (the shape a libp2p default CID takes) MUST be
	// rejected. This is the critical regression check: a validator reset to
	// libp2p defaults would accept this key (IC §12).
	cidBytes := sha256Multihash([]byte("test-chunk-content"))
	err = dht.PutProviderRecord(ctx, cidBytes)
	if !isDHTKeyInvalid(err) {
		t.Errorf("plain multihash-shaped key must be rejected with ErrDHTKeyInvalid, got %v — "+
			"a validator regression may have reset the namespace/length check", err)
	}

	// CASE 3: A 31-byte key (one byte short of 32) MUST be rejected.
	shortKey := validKey[:31]
	err = dht.PutProviderRecord(ctx, shortKey)
	if !isDHTKeyInvalid(err) {
		t.Errorf("31-byte key must be rejected with ErrDHTKeyInvalid, got %v", err)
	}
}

// TestDHTKeyValidatorRejectsAll is a table-driven exhaustive rejection test (IC §12).
func TestDHTKeyValidatorRejectsAll(t *testing.T) {
	ctx := context.Background()
	testHost := buildTestHost(t)
	dht := buildTestDHT(t, testHost)

	cases := []struct {
		name string
		key  []byte
	}{
		{"empty key", []byte{}},
		{"31 bytes (one short)", make([]byte, 31)},
		{"33 bytes (one over)", make([]byte, 33)},
		{"64 bytes (Ed25519 sig length)", make([]byte, 64)},
		{"vyom-chunk prefix", append([]byte("vyom-chunk:"), make([]byte, 21)...)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := dht.PutProviderRecord(ctx, tc.key)
			if !isDHTKeyInvalid(err) {
				t.Errorf("key %q (%d bytes) must be rejected by the HMAC validator, got %v",
					tc.name, len(tc.key), err)
			}
		})
	}
}

// TestDHTKeyValidatorAcceptsHMAC tests positive acceptance with boundary key values.
func TestDHTKeyValidatorAcceptsHMAC(t *testing.T) {
	ctx := context.Background()
	testHost := buildTestHost(t)
	dht := buildTestDHT(t, testHost)

	allFF := make([]byte, 32)
	for i := range allFF {
		allFF[i] = 0xFF
	}
	validKeys := [][]byte{
		make([]byte, 32), // all-zero 32-byte key
		allFF,            // all-FF 32-byte key
	}

	for _, key := range validKeys {
		if err := dht.PutProviderRecord(ctx, key); err != nil {
			t.Errorf("32-byte key must be accepted regardless of content: %v", err)
		}
	}
}

// isDHTKeyInvalid reports whether err wraps ErrDHTKeyInvalid.
func isDHTKeyInvalid(err error) bool {
	for err != nil {
		if err == ErrDHTKeyInvalid { //nolint:errorlint // also checked via errors.Is below for wrapped cases
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return false
}

// ── namespace / minimality checks (Session 6.2.1) ─────────────────────────────

func TestDHTNamespaceConstantValue(t *testing.T) {
	if dhtKeyNamespace != "/vyomanaut/dht-key/1.0.0" {
		t.Errorf("dhtKeyNamespace = %q, want %q", dhtKeyNamespace, "/vyomanaut/dht-key/1.0.0")
	}
}

// ── DHT parameter checks (ARCH §13) ───────────────────────────────────────────

func TestDHTParameters(t *testing.T) {
	if kBucketSize != 16 {
		t.Errorf("kBucketSize = %d, want 16 (ARCH §13: k = 2×d, d=8)", kBucketSize)
	}
	if dhtAlpha != 3 {
		t.Errorf("dhtAlpha = %d, want 3 (ARCH §13: parallel lookups)", dhtAlpha)
	}
	if dhtMode != "Server" {
		t.Errorf("dhtMode = %q, want %q (ARCH §13: every provider daemon is a full participant)", dhtMode, "Server")
	}
}

// ── PutProviderRecord / FindProviders semantics ───────────────────────────────

// TestFindProvidersReturnsSelfAfterPut verifies the basic single-node loop:
// after PutProviderRecord, FindProviders on the same node returns our own
// AddrInfo from the local record store.
func TestFindProvidersReturnsSelfAfterPut(t *testing.T) {
	ctx := context.Background()
	testHost := buildTestHost(t)
	dht := buildTestDHT(t, testHost)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	if err := dht.PutProviderRecord(ctx, key); err != nil {
		t.Fatalf("PutProviderRecord: %v", err)
	}

	found, err := dht.FindProviders(ctx, key, 10)
	if err != nil {
		t.Fatalf("FindProviders: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("FindProviders returned %d results, want 1", len(found))
	}
	if found[0].ID != testHost.PeerID() {
		t.Errorf("FindProviders returned ID %q, want self %q", found[0].ID, testHost.PeerID())
	}
}

// TestFindProvidersUnknownKeyReturnsEmpty verifies a key nobody has announced
// returns an empty (not error) result.
func TestFindProvidersUnknownKeyReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	testHost := buildTestHost(t)
	dht := buildTestDHT(t, testHost)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xAA)
	}
	found, err := dht.FindProviders(ctx, key, 10)
	if err != nil {
		t.Fatalf("FindProviders: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("expected 0 results for an unannounced key, got %d", len(found))
	}
}

// TestTwoNodeBootstrapPutFind is the genuine two-node round trip: node B
// bootstraps against node A, then B announces a provider record. Because B's
// routing table now contains A, PutProviderRecord's best-effort replication
// pushes the record to A too — so a lookup on A's own DHT (with no further
// network round trip) finds it.
func TestTwoNodeBootstrapPutFind(t *testing.T) {
	hostA := buildTestHost(t)
	dhtA := buildTestDHT(t, hostA)

	hostB := buildTestHost(t)
	addrA, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, hostA))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	addrB, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, hostB))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	dhtB, err := NewDHT(hostB, DHTConfig{
		// B must advertise a real, dialable address of its own in its
		// PUT_PROVIDER message — handlePut's fix calls
		// Connect(sender.ID, sender.Addrs) before adding the sender to the
		// routing table, and Connect requires at least one address.
		// Without this, B always sends an empty Addrs list, Connect always
		// fails with "at least one address is required", and the fix
		// (correctly) never adds an unverifiable peer.
		SelfAddrs: []Multiaddr{addrB},
		Seeds:     []AddrInfo{{ID: hostA.PeerID(), Addrs: []Multiaddr{addrA}}},
	})
	if err != nil {
		t.Fatalf("NewDHT (B): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := dhtB.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	if err := dhtB.PutProviderRecord(ctx, key); err != nil {
		t.Fatalf("PutProviderRecord (B): %v", err)
	}

	// Give the best-effort replication goroutine-free synchronous push a
	// moment to land (PutProviderRecord itself blocks on the push, so this is
	// just headroom for the TLS handshake round trip, not a race).
	deadline := time.Now().Add(3 * time.Second)
	var foundOnA []AddrInfo
	for time.Now().Before(deadline) {
		foundOnA, err = dhtA.FindProviders(ctx, key, 10)
		if err != nil {
			t.Fatalf("FindProviders (A): %v", err)
		}
		if len(foundOnA) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(foundOnA) != 1 {
		t.Fatalf("node A found %d providers for B's replicated record, want 1", len(foundOnA))
	}
	if foundOnA[0].ID != hostB.PeerID() {
		t.Errorf("node A's record is for %q, want %q", foundOnA[0].ID, hostB.PeerID())
	}
}

// ── FindPeer semantics (M12 audit corrections, Finding 2) ─────────────────

// TestFindPeerUnknownReturnsErrPeerNotInRoutingTable verifies a peer this
// node has never observed any DHT traffic from returns the documented
// sentinel, not a zero-value success.
func TestFindPeerUnknownReturnsErrPeerNotInRoutingTable(t *testing.T) {
	ctx := context.Background()
	testHost := buildTestHost(t)
	dht := buildTestDHT(t, testHost)

	unknownPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	unknownPeerID, err := PeerIDFromEd25519PublicKey(unknownPub)
	if err != nil {
		t.Fatalf("PeerIDFromEd25519PublicKey: %v", err)
	}

	_, err = dht.FindPeer(ctx, unknownPeerID)
	if !errors.Is(err, ErrPeerNotInRoutingTable) {
		t.Fatalf("FindPeer(unknown) error = %v, want ErrPeerNotInRoutingTable", err)
	}
}

// TestFindPeerAfterBootstrapReturnsSeedAddr verifies FindPeer can serve a
// peer added to the routing table via Bootstrap's own addToRoutingTable
// call — the simplest case, with no PUT_PROVIDER traffic involved.
func TestFindPeerAfterBootstrapReturnsSeedAddr(t *testing.T) {
	hostA := buildTestHost(t)
	_ = buildTestDHT(t, hostA)

	hostB := buildTestHost(t)
	addrA, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, hostA))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	addrB, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, hostB))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	dhtB, err := NewDHT(hostB, DHTConfig{
		SelfAddrs: []Multiaddr{addrB},
		Seeds:     []AddrInfo{{ID: hostA.PeerID(), Addrs: []Multiaddr{addrA}}},
	})
	if err != nil {
		t.Fatalf("NewDHT (B): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dhtB.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	got, err := dhtB.FindPeer(ctx, hostA.PeerID())
	if err != nil {
		t.Fatalf("FindPeer(seed A) after Bootstrap: %v", err)
	}
	if got.ID != hostA.PeerID() {
		t.Errorf("FindPeer returned ID %q, want %q", got.ID, hostA.PeerID())
	}
	if len(got.Addrs) != 1 || got.Addrs[0].String() != addrA.String() {
		t.Errorf("FindPeer returned addrs %v, want [%s]", got.Addrs, addrA)
	}
}

// TestFindPeerAfterInboundPutProviderRecord is the scenario
// cmd/microservice/adapters.go's resolveProviderPeer fallback actually
// depends on in production: node A learns node B's CURRENT, connect-
// verified address purely as a side effect of B announcing an unrelated
// content record — no seed relationship between A and B is configured
// ahead of time, mirroring how the microservice (never a bootstrap seed for
// any provider) would passively learn a provider's refreshed address from
// ordinary heartbeat-driven DHT republication traffic.
func TestFindPeerAfterInboundPutProviderRecord(t *testing.T) {
	hostA := buildTestHost(t)
	dhtA := buildTestDHT(t, hostA)

	hostB := buildTestHost(t)
	addrA, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, hostA))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	addrB, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, hostB))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	dhtB, err := NewDHT(hostB, DHTConfig{
		SelfAddrs: []Multiaddr{addrB},
		Seeds:     []AddrInfo{{ID: hostA.PeerID(), Addrs: []Multiaddr{addrA}}},
	})
	if err != nil {
		t.Fatalf("NewDHT (B): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dhtB.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// A does not know B yet at this point — Bootstrap only populated B's
	// own routing table with A, not the reverse. B announcing any record
	// is what should teach A about B's address (handlePut's fix, M6 review
	// §5.4), exactly like FindProviders' own TestTwoNodeBootstrapPutFind
	// above verifies for the content-record side of the same mechanism.
	if _, err := dhtA.FindPeer(ctx, hostB.PeerID()); !errors.Is(err, ErrPeerNotInRoutingTable) {
		t.Fatalf("FindPeer(B) on A before any B traffic: err = %v, want ErrPeerNotInRoutingTable", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	if err := dhtB.PutProviderRecord(ctx, key); err != nil {
		t.Fatalf("PutProviderRecord (B): %v", err)
	}

	// handlePut's routing-table-growth fix runs Connect + addToRoutingTable
	// in its own goroutine after the ack (see dht.go's handlePut) — poll
	// rather than assume synchronous completion, same pattern as
	// TestTwoNodeBootstrapPutFind above.
	deadline := time.Now().Add(3 * time.Second)
	var (
		got     AddrInfo
		findErr error
	)
	for time.Now().Before(deadline) {
		got, findErr = dhtA.FindPeer(ctx, hostB.PeerID())
		if findErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if findErr != nil {
		t.Fatalf("FindPeer(B) on A after B's PUT_PROVIDER: %v", findErr)
	}
	if got.ID != hostB.PeerID() {
		t.Errorf("FindPeer returned ID %q, want %q", got.ID, hostB.PeerID())
	}
	if len(got.Addrs) != 1 || got.Addrs[0].String() != addrB.String() {
		t.Errorf("FindPeer returned addrs %v, want [%s] (B's real, connect-verified address)", got.Addrs, addrB)
	}
}

// TestBootstrapNoSeedsIsNoop verifies Bootstrap with no configured seeds
// succeeds trivially rather than blocking or erroring.
func TestBootstrapNoSeedsIsNoop(t *testing.T) {
	testHost := buildTestHost(t)
	dht := buildTestDHT(t, testHost)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dht.Bootstrap(ctx); err != nil {
		t.Errorf("Bootstrap with no seeds should be a no-op, got error: %v", err)
	}
}

// TestBootstrapAllSeedsFail verifies Bootstrap surfaces an error when every
// seed is unreachable.
func TestBootstrapAllSeedsFail(t *testing.T) {
	testHost := buildTestHost(t)

	// A loopback address nothing is listening on.
	deadAddr, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/1")
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	dht, err := NewDHT(testHost, DHTConfig{
		Seeds: []AddrInfo{{ID: PeerID("12D3KooWDeadSeedPeerId00000000000000000000000000"), Addrs: []Multiaddr{deadAddr}}},
	})
	if err != nil {
		t.Fatalf("NewDHT: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := dht.Bootstrap(ctx); err == nil {
		t.Error("expected Bootstrap to fail when all seeds are unreachable, got nil")
	}
}

// ── routing table unit tests ───────────────────────────────────────────────

// TestCommonPrefixLen exercises the XOR-metric bucket-index function directly.
func TestCommonPrefixLen(t *testing.T) {
	var a, b [32]byte
	if got := commonPrefixLen(a, b); got != 256 {
		t.Errorf("identical IDs: commonPrefixLen = %d, want 256", got)
	}

	b[0] = 0x80 // flip the top bit of the first byte
	if got := commonPrefixLen(a, b); got != 0 {
		t.Errorf("top-bit differs: commonPrefixLen = %d, want 0", got)
	}

	var c [32]byte
	c[0] = 0x01 // differ only in the last bit of the first byte
	if got := commonPrefixLen(a, c); got != 7 {
		t.Errorf("last-bit-of-first-byte differs: commonPrefixLen = %d, want 7", got)
	}
}

// TestClosestPeersOrdering verifies closestPeers sorts by ascending XOR
// distance to the target key, not insertion order.
func TestClosestPeersOrdering(t *testing.T) {
	testHost := buildTestHost(t)
	dhtIface := buildTestDHT(t, testHost)
	d, ok := dhtIface.(*kademliaDHT)
	if !ok {
		t.Fatalf("buildTestDHT returned %T, want *kademliaDHT", dhtIface)
	}

	var key [32]byte // all-zero target

	// Insert peers with kadIDs at known distances by directly seeding the
	// routing table (bypassing PeerID->kadID hashing so the test can control
	// exact distances).
	far := &peerEntry{info: AddrInfo{ID: "far"}, kadID: [32]byte{0xFF}}
	near := &peerEntry{info: AddrInfo{ID: "near"}, kadID: [32]byte{0x01}}
	mid := &peerEntry{info: AddrInfo{ID: "mid"}, kadID: [32]byte{0x0F}}

	d.mu.Lock()
	d.buckets[0] = []*peerEntry{far, near, mid}
	d.mu.Unlock()

	ordered := d.closestPeers(key, 3)
	if len(ordered) != 3 {
		t.Fatalf("got %d peers, want 3", len(ordered))
	}
	wantOrder := []PeerID{"near", "mid", "far"}
	for i, p := range ordered {
		if p.info.ID != wantOrder[i] {
			t.Errorf("position %d: got %q, want %q", i, p.info.ID, wantOrder[i])
		}
	}
}

// TestAddToRoutingTableRespectsCapacity verifies that after inserting many
// more peers than could possibly fit if every bucket were unbounded, no
// single k-bucket ever exceeds kBucketSize — the eviction path in
// addToRoutingTable is exercised for real (via its own kadID/bucket-index
// computation), not synthetically forced into a specific bucket.
func TestAddToRoutingTableRespectsCapacity(t *testing.T) {
	testHost := buildTestHost(t)
	dhtIface := buildTestDHT(t, testHost)
	d, ok := dhtIface.(*kademliaDHT)
	if !ok {
		t.Fatalf("buildTestDHT returned %T, want *kademliaDHT", dhtIface)
	}

	for i := 0; i < 500; i++ {
		d.addToRoutingTable(AddrInfo{ID: PeerID(fmt.Sprintf("synthetic-peer-%d", i))})
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	for i, bucket := range d.buckets {
		if len(bucket) > kBucketSize {
			t.Errorf("bucket %d has %d entries after 500 inserts, want <= %d", i, len(bucket), kBucketSize)
		}
	}
}

// TestAddToRoutingTableRefreshesExisting verifies that re-adding a known peer
// updates its entry in place rather than creating a duplicate.
func TestAddToRoutingTableRefreshesExisting(t *testing.T) {
	testHost := buildTestHost(t)
	dhtIface := buildTestDHT(t, testHost)
	d, ok := dhtIface.(*kademliaDHT)
	if !ok {
		t.Fatalf("buildTestDHT returned %T, want *kademliaDHT", dhtIface)
	}

	const id PeerID = "12D3KooWRepeatedPeerId0000000000000000000000000000"
	d.addToRoutingTable(AddrInfo{ID: id})
	d.addToRoutingTable(AddrInfo{ID: id})
	d.addToRoutingTable(AddrInfo{ID: id})

	d.mu.RLock()
	defer d.mu.RUnlock()
	count := 0
	for _, bucket := range d.buckets {
		for _, entry := range bucket {
			if entry.info.ID == id {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("re-adding the same peer %d times produced %d routing-table entries, want 1", 3, count)
	}
}

// TestAddToRoutingTableIgnoresSelf verifies self is never inserted into the
// routing table (a node is not its own neighbour).
func TestAddToRoutingTableIgnoresSelf(t *testing.T) {
	testHost := buildTestHost(t)
	dhtIface := buildTestDHT(t, testHost)
	d, ok := dhtIface.(*kademliaDHT)
	if !ok {
		t.Fatalf("buildTestDHT returned %T, want *kademliaDHT", dhtIface)
	}

	d.addToRoutingTable(AddrInfo{ID: testHost.PeerID()})

	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, bucket := range d.buckets {
		for _, entry := range bucket {
			if entry.info.ID == testHost.PeerID() {
				t.Fatal("self was inserted into the routing table")
			}
		}
	}
}

// TestHandlePutGrowsRoutingTable verifies that receiving a PUT_PROVIDER
// request adds the SENDER to the RECEIVER's routing table, not just
// Bootstrap's own seed list — before this fix, addToRoutingTable was only
// ever called from Bootstrap, so a node's k-buckets never grew from
// ordinary inbound DHT traffic. [REF: M6 review §5.4]
func TestHandlePutGrowsRoutingTable(t *testing.T) {
	hostA := buildTestHost(t)
	dhtAIface := buildTestDHT(t, hostA)
	dhtA, ok := dhtAIface.(*kademliaDHT)
	if !ok {
		t.Fatalf("buildTestDHT returned %T, want *kademliaDHT", dhtAIface)
	}

	hostB := buildTestHost(t)
	addrA, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, hostA))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	addrB, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, hostB))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	dhtB, err := NewDHT(hostB, DHTConfig{
		// B must advertise a real, dialable address of its own in its
		// PUT_PROVIDER message — handlePut's fix calls
		// Connect(sender.ID, sender.Addrs) before adding the sender to the
		// routing table, and Connect requires at least one address.
		// Without this, B always sends an empty Addrs list, Connect always
		// fails with "at least one address is required", and the fix
		// (correctly) never adds an unverifiable peer.
		SelfAddrs: []Multiaddr{addrB},
		Seeds:     []AddrInfo{{ID: hostA.PeerID(), Addrs: []Multiaddr{addrA}}},
	})
	if err != nil {
		t.Fatalf("NewDHT (B): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dhtB.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	if err := dhtB.PutProviderRecord(ctx, key); err != nil {
		t.Fatalf("PutProviderRecord (B): %v", err)
	}

	// A never called Bootstrap and has no seeds of its own — its ONLY route
	// to learning about B is via handlePut's fix. Runs in a background
	// goroutine after the ack (see handlePut), so poll briefly.
	deadline := time.Now().Add(3 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		dhtA.mu.RLock()
		for _, bucket := range dhtA.buckets {
			for _, entry := range bucket {
				if entry.info.ID == hostB.PeerID() {
					found = true
				}
			}
		}
		dhtA.mu.RUnlock()
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Error("host B was never added to host A's routing table after A received B's PUT_PROVIDER — " +
			"addToRoutingTable is still only reachable from Bootstrap's own seed list")
	}
}

// TestHandleGetRespectsZeroMaxCount verifies that a GET_PROVIDERS request
// with maxCount=0 returns zero results even when a matching record exists
// locally. Unreachable through the exported FindProviders API (which
// rejects maxCount <= 0 before ever sending a frame), so this hand-crafts
// the wire request the way an adversarial or buggy peer could.
// [REF: M6 review §5.6]
func TestHandleGetRespectsZeroMaxCount(t *testing.T) {
	serverHost := buildTestHost(t)
	dht := buildTestDHT(t, serverHost)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	if err := dht.PutProviderRecord(context.Background(), key); err != nil {
		t.Fatalf("PutProviderRecord: %v", err)
	}

	clientHost := buildTestHost(t)
	addr, err := ParseMultiaddr("/ip4/127.0.0.1/tcp/" + testHostPort(t, serverHost))
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := clientHost.Connect(ctx, serverHost.PeerID(), []Multiaddr{addr}); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	stream, err := clientHost.NewStream(ctx, serverHost.PeerID(), ProtocolID(dhtKeyNamespace))
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = stream.Close() }()

	var k [32]byte
	copy(k[:], key)
	if _, err := stream.Write(encodeGetRequest(k, 0)); err != nil { // hand-crafted maxCount=0
		t.Fatalf("write GET_PROVIDERS(maxCount=0): %v", err)
	}

	infos, err := decodeGetResponse(stream)
	if err != nil {
		t.Fatalf("decodeGetResponse: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("GET_PROVIDERS with maxCount=0 returned %d results, want 0 (a record for this key does exist "+
			"locally, so a non-empty result here means the zero-maxCount guard is still backwards)", len(infos))
	}
}

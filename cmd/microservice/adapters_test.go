package main

// Tests for adapters.go's resolveProviderPeer DHT fallback (M12 audit
// corrections, Finding 2). See internal/p2p/dht_test.go for FindPeer's own
// dedicated routing-table-level coverage; the tests here exercise
// resolveProviderPeer's INTEGRATION with a p2p.DHT — the actual
// multiaddr_stale-gated fallback decision — using a fake DHT rather than a
// live two-node one, since the routing-table mechanics themselves are
// already covered there.

import (
	"context"
	"fmt"
	"testing"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// fakeDHT is a minimal p2p.DHT test double for resolveProviderPeer's
// fallback logic — only FindPeer is ever exercised by this file's tests
// (resolveProviderPeer never calls PutProviderRecord/FindProviders/
// Bootstrap), so those simply fail loudly if ever reached.
type fakeDHT struct {
	findPeerResult p2p.AddrInfo
	findPeerErr    error
	findPeerCalled bool
}

func (f *fakeDHT) PutProviderRecord(context.Context, []byte) error {
	return fmt.Errorf("fakeDHT: PutProviderRecord not expected in this test")
}

func (f *fakeDHT) FindProviders(context.Context, []byte, int) ([]p2p.AddrInfo, error) {
	return nil, fmt.Errorf("fakeDHT: FindProviders not expected in this test")
}

func (f *fakeDHT) FindPeer(_ context.Context, _ p2p.PeerID) (p2p.AddrInfo, error) {
	f.findPeerCalled = true
	return f.findPeerResult, f.findPeerErr
}

func (f *fakeDHT) Bootstrap(context.Context) error {
	return fmt.Errorf("fakeDHT: Bootstrap not expected in this test")
}

// TestResolveProviderPeerUsesDHTFallbackWhenStale verifies the core fix: a
// provider marked multiaddr_stale prefers a FindPeer hit over the stored
// (possibly-outdated) Postgres address.
func TestResolveProviderPeerUsesDHTFallbackWhenStale(t *testing.T) {
	db := openTestDB(t)
	providerID, pub, _ := insertTestProvider(t, db, "ACTIVE")
	seedTestMultiaddr(t, db, providerID) // stale, stored address
	if _, err := db.Exec(`UPDATE providers SET multiaddr_stale = TRUE WHERE provider_id = $1`, providerID); err != nil {
		t.Fatalf("seed multiaddr_stale: %v", err)
	}

	expectedPeerID, err := p2p.PeerIDFromEd25519PublicKey(pub)
	if err != nil {
		t.Fatalf("PeerIDFromEd25519PublicKey: %v", err)
	}
	freshAddr, err := p2p.ParseMultiaddr("/ip4/10.0.0.99/udp/4001/quic")
	if err != nil {
		t.Fatalf("ParseMultiaddr: %v", err)
	}
	dht := &fakeDHT{findPeerResult: p2p.AddrInfo{ID: expectedPeerID, Addrs: []p2p.Multiaddr{freshAddr}}}

	gotPeerID, gotAddrs, err := resolveProviderPeer(context.Background(), db, dht, providerID)
	if err != nil {
		t.Fatalf("resolveProviderPeer: %v", err)
	}
	if !dht.findPeerCalled {
		t.Fatalf("resolveProviderPeer did not consult the DHT for a multiaddr_stale provider")
	}
	if gotPeerID != expectedPeerID {
		t.Errorf("resolveProviderPeer peerID = %q, want %q", gotPeerID, expectedPeerID)
	}
	if len(gotAddrs) != 1 || gotAddrs[0].String() != freshAddr.String() {
		t.Errorf("resolveProviderPeer addrs = %v, want the DHT's fresh address [%s], not the stale stored one", gotAddrs, freshAddr)
	}
}

// TestResolveProviderPeerFallsBackToStoredAddressWhenDHTHasNothing verifies
// that a DHT miss (ErrPeerNotInRoutingTable) falls through to the stored,
// possibly-stale address rather than failing the whole lookup outright —
// better a possibly-stale dial attempt than none at all.
func TestResolveProviderPeerFallsBackToStoredAddressWhenDHTHasNothing(t *testing.T) {
	db := openTestDB(t)
	providerID, _, _ := insertTestProvider(t, db, "ACTIVE")
	seedTestMultiaddr(t, db, providerID)
	if _, err := db.Exec(`UPDATE providers SET multiaddr_stale = TRUE WHERE provider_id = $1`, providerID); err != nil {
		t.Fatalf("seed multiaddr_stale: %v", err)
	}

	dht := &fakeDHT{findPeerErr: fmt.Errorf("p2p.FindPeer: %w", p2p.ErrPeerNotInRoutingTable)}

	_, gotAddrs, err := resolveProviderPeer(context.Background(), db, dht, providerID)
	if err != nil {
		t.Fatalf("resolveProviderPeer: %v", err)
	}
	if !dht.findPeerCalled {
		t.Fatalf("resolveProviderPeer did not consult the DHT for a multiaddr_stale provider")
	}
	if len(gotAddrs) != 1 || gotAddrs[0].String() != "/ip4/127.0.0.1/udp/4001/quic" {
		t.Errorf("resolveProviderPeer addrs = %v, want the stored fallback address when the DHT has nothing", gotAddrs)
	}
}

// TestResolveProviderPeerIgnoresDHTWhenNotStale verifies the DHT is never
// even consulted when multiaddr_stale is false — the stored address is
// trusted as-is, matching Session 12.1.2 step 1's "primary; DHT fallback IF
// stale" ordering.
func TestResolveProviderPeerIgnoresDHTWhenNotStale(t *testing.T) {
	db := openTestDB(t)
	providerID, _, _ := insertTestProvider(t, db, "ACTIVE")
	seedTestMultiaddr(t, db, providerID)
	// multiaddr_stale defaults to FALSE — not set here deliberately.

	dht := &fakeDHT{findPeerErr: fmt.Errorf("fakeDHT: FindPeer should not have been called")}

	_, _, err := resolveProviderPeer(context.Background(), db, dht, providerID)
	if err != nil {
		t.Fatalf("resolveProviderPeer: %v", err)
	}
	if dht.findPeerCalled {
		t.Errorf("resolveProviderPeer consulted the DHT for a non-stale provider; it must trust the stored address as-is")
	}
}

// TestResolveProviderPeerNilDHTFallsBackSafely verifies a nil DHT (e.g. DHT
// participation disabled) behaves exactly like "the DHT found nothing" —
// no panic, falls through to the stored address.
func TestResolveProviderPeerNilDHTFallsBackSafely(t *testing.T) {
	db := openTestDB(t)
	providerID, _, _ := insertTestProvider(t, db, "ACTIVE")
	seedTestMultiaddr(t, db, providerID)
	if _, err := db.Exec(`UPDATE providers SET multiaddr_stale = TRUE WHERE provider_id = $1`, providerID); err != nil {
		t.Fatalf("seed multiaddr_stale: %v", err)
	}

	_, gotAddrs, err := resolveProviderPeer(context.Background(), db, nil, providerID)
	if err != nil {
		t.Fatalf("resolveProviderPeer with nil dht: %v", err)
	}
	if len(gotAddrs) != 1 || gotAddrs[0].String() != "/ip4/127.0.0.1/udp/4001/quic" {
		t.Errorf("resolveProviderPeer with nil dht addrs = %v, want the stored fallback address", gotAddrs)
	}
}

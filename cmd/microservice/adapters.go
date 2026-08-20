// cmd/microservice — see main.go's package doc comment.
//
// This file implements resolveProviderPeer (shared by the audit dispatch
// loop and the repair transport adapter below) and repairTransportAdapter
// itself.
//
// [Decision — repairTransportAdapter is genuinely required, not a trivial
// structural pass-through] internal/repair/executor.go's own header comment
// says the microservice entrypoint is "expected to supply a small adapter
// converting string<->p2p.PeerID / string<->p2p.ProtocolID... rather than
// passing *p2p.Host directly." This session's own step 11 pseudocode
// ("repairTransport := p2pHost — satisfies repair.RepairTransport
// structurally") undersells that: repair.RepairTransport.NewStream takes a
// plain peerID string, but p2p.Host.NewStream takes a typed p2p.PeerID and
// additionally REQUIRES Connect to have already succeeded for that peer
// (host.go's own doc comment). A bare *p2p.Host cannot satisfy
// repair.RepairTransport at all (different parameter types — Go requires an
// exact method-set match) and could not be used directly even if the types
// lined up, since nothing would ever call Connect first. The adapter below
// is the "small adapter" executor.go's own comment anticipates: it
// interprets the peerID string ExecuteRepairJob passes in (a provider UUID
// string — see executor.go's own `replacementProviderID.String()` call and
// SurvivingHolder.PeerID, populated the same way by audit_dispatch.go's
// findSurvivingHolders below) as a provider_id, resolves it to a real
// p2p.PeerID + dialable Multiaddrs via the providers table, Connects, and
// only then opens the stream.
//
// [Corrected — M12 audit corrections, Finding 2 — DHT fallback for stale
// provider addresses] Session 12.1.2 step 1 ("Determine provider
// multiaddrs: providers.last_known_multiaddrs (primary); DHT fallback if
// multiaddr_stale = true") was previously unimplemented: resolveProviderPeer
// unconditionally read only the (possibly stale) Postgres row. It now
// consults a DHT's FindPeer for a fresher, connect-verified address when
// multiaddr_stale is true — see internal/p2p/dht.go's FindPeer doc comment
// for why FindPeer (not FindProviders) is the correct primitive here: this
// service already independently derives the target's stable PeerID from
// providers.ed25519_public_key, so what's actually needed is "what is this
// KNOWN peer's current address", not a content-key lookup keyed by
// material (an owner's dht_key) this service structurally never has.
//
// dht may be nil (e.g. in tests, or if a future session needs to disable
// DHT participation entirely) — resolveProviderPeer treats that exactly
// like "the DHT fallback found nothing," falling through to the stored
// Postgres address.
//
// [REF: IC §4.4.1, IC §4.1, IC §5.4, ARCH §13, build.md Milestone 9 Session
// 9.2.1, Milestone 12 Phase 12.1 Session 12.1.1, Session 12.1.2 step 1,
// Milestone 12 audit corrections Finding 2]
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/repair"
)

// resolveProviderPeer looks up providerID's Ed25519 public key, last known
// multiaddrs, and staleness flag (providers.ed25519_public_key, providers.
// last_known_multiaddrs, providers.multiaddr_stale) and derives the real
// p2p.PeerID plus dial addresses. Shared by repairTransportAdapter and the
// audit dispatch loop (Session 12.1.2), which both need to turn a
// provider_id into a real, dialable p2p identity.
//
// When multiaddr_stale is true, dht.FindPeer(peerID) — a routing-table
// lookup keyed by the peer's own (never-stale) identity, not the stale
// Postgres row — is tried FIRST, on the theory that a known-unreliable
// stored address is worth less than a connect-verified one the DHT has
// observed more recently, if it has one; the stored address remains the
// fallback when the DHT has nothing yet (better a possibly-stale dial
// attempt than none at all). See this file's header note and
// internal/p2p/dht.go's FindPeer doc comment for why FindPeer, not
// FindProviders, is correct here. dht == nil is treated exactly like "DHT
// found nothing" (no fallback attempted).
func resolveProviderPeer(ctx context.Context, db *sql.DB, dht p2p.DHT, providerID uuid.UUID) (p2p.PeerID, []p2p.Multiaddr, error) {
	var (
		pubKey         []byte
		multiaddrsRaw  []byte
		multiaddrStale bool
	)
	err := db.QueryRowContext(ctx,
		`SELECT ed25519_public_key, last_known_multiaddrs, multiaddr_stale FROM providers WHERE provider_id = $1`,
		providerID,
	).Scan(&pubKey, &multiaddrsRaw, &multiaddrStale)
	if err != nil {
		return "", nil, fmt.Errorf("resolveProviderPeer: look up provider %s: %w", providerID, err)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("resolveProviderPeer: provider %s: ed25519_public_key is %d bytes, want %d", providerID, len(pubKey), ed25519.PublicKeySize)
	}
	peerID, err := p2p.PeerIDFromEd25519PublicKey(pubKey)
	if err != nil {
		return "", nil, fmt.Errorf("resolveProviderPeer: provider %s: derive Peer ID: %w", providerID, err)
	}

	if multiaddrStale && dht != nil {
		if info, dhtErr := dht.FindPeer(ctx, peerID); dhtErr == nil && len(info.Addrs) > 0 {
			return peerID, info.Addrs, nil
		}
		// DHT has nothing newer (ErrPeerNotInRoutingTable, or some other
		// lookup failure) — fall through to the stored, possibly-stale
		// address below rather than failing outright.
	}

	var addrStrings []string
	if err := json.Unmarshal(multiaddrsRaw, &addrStrings); err != nil {
		return "", nil, fmt.Errorf("resolveProviderPeer: provider %s: parse last_known_multiaddrs: %w", providerID, err)
	}
	if len(addrStrings) == 0 {
		return "", nil, fmt.Errorf("resolveProviderPeer: provider %s: no known multiaddrs", providerID)
	}

	addrs := make([]p2p.Multiaddr, 0, len(addrStrings))
	for _, s := range addrStrings {
		addr, err := p2p.ParseMultiaddr(s)
		if err != nil {
			continue // skip unparseable entries; try the rest before failing outright
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return "", nil, fmt.Errorf("resolveProviderPeer: provider %s: no parseable multiaddrs among %d stored", providerID, len(addrStrings))
	}
	return peerID, addrs, nil
}

// repairTransportAdapter wraps p2p.Host to satisfy repair.RepairTransport —
// see this file's header note for why this adapter is genuinely necessary,
// not a trivial pass-through. dht may be nil (see resolveProviderPeer's own
// doc comment) — repair jobs against a provider with a stale address get
// the same DHT-fallback benefit audit dispatch does (Finding 2), since both
// call sites go through the same resolveProviderPeer.
type repairTransportAdapter struct {
	db   *sql.DB
	host p2p.Host
	dht  p2p.DHT
}

// NewStream implements repair.RepairTransport. peerID is interpreted as a
// provider_id string (see this file's header note); protocolID is passed
// through unchanged to p2p.Host.NewStream.
func (a *repairTransportAdapter) NewStream(ctx context.Context, peerID string, protocolID string) (repair.RepairStream, error) {
	providerID, err := uuid.Parse(peerID)
	if err != nil {
		return nil, fmt.Errorf("repairTransportAdapter.NewStream: peerID %q is not a provider UUID: %w", peerID, err)
	}
	realPeerID, addrs, err := resolveProviderPeer(ctx, a.db, a.dht, providerID)
	if err != nil {
		return nil, fmt.Errorf("repairTransportAdapter.NewStream: %w", err)
	}
	if err := a.host.Connect(ctx, realPeerID, addrs); err != nil {
		return nil, fmt.Errorf("repairTransportAdapter.NewStream: connect to provider %s: %w", providerID, err)
	}
	// p2p.Stream (the concrete return type of host.NewStream) is a superset
	// of repair.RepairStream's method set (io.Reader, io.Writer, io.Closer,
	// SetDeadline) — see executor.go's own header note — so it is returned
	// here with no further wrapping needed.
	return a.host.NewStream(ctx, realPeerID, p2p.ProtocolID(protocolID))
}

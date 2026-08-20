// Package p2p is declared in doc.go.
// This file implements the Kademlia DHT interface (IC §5.4) and the custom
// HMAC key validator (IC §12, ADR-001).
//
// Per the substitution decision recorded in doc.go, the concrete DHT here does
// not use github.com/libp2p/go-libp2p-kad-dht, github.com/libp2p/go-libp2p-record,
// or github.com/multiformats/go-multihash (all unreachable in this build
// environment for the same reason go-libp2p itself was). What is NOT
// substituted is the actual security-relevant contract: the HMAC key
// validator's accept/reject rules (validateDHTKey) are implemented exactly as
// IC §12 specifies, byte for byte, and are the piece CI check 5
// (TestDHTKeyValidatorPersists) exists to guard — see dht_test.go.
//
// The routing/storage machinery around that validator (k-buckets, provider
// record replication, iterative lookup) is a from-scratch, same-shape
// Kademlia implementation over this package's own Host transport (host.go):
//
//	k-bucket size = 16   (ARCH §13: k = 2×d where d = 8)
//	alpha         = 3    (ARCH §13: parallel lookups)
//	mode          = Server (ARCH §13: every provider daemon is a full participant)
//
// dhtKeyNamespace (dht_namespace.go) doubles as both the record-validator
// namespace IC §12 describes AND this package's own wire-protocol ID for DHT
// operations — a deliberate simplification given there is no separate
// go-libp2p-kad-dht protocol registration mechanism to hang a namespace off
// of here; see doc.go.
//
// [REF: IC §5.4, IC §12, IC §12.1, IC §12.2, ARCH §13, ADR-001, ADR-021]

package p2p

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// ── ARCH §13 §DHT configuration parameters ────────────────────────────────────

// kBucketSize is the Kademlia k-bucket capacity (ARCH §13: k = 2×d where d = 8).
const kBucketSize = 16

// dhtAlpha is the parallel-lookup fan-out (ARCH §13: produces O(log N / α) round trips).
const dhtAlpha = 3

// dhtPeerVerifyTimeout bounds how long handlePut waits for Connect to verify
// a PUT_PROVIDER sender's self-reported addresses before giving up on
// adding them to the routing table (M6 review §5.4). Does not block the
// PUT itself — storeRecord and the ack both already completed before this
// runs.
const dhtPeerVerifyTimeout = 5 * time.Second

// dhtMode documents that every Vyomanaut provider daemon runs the DHT in
// Server mode — a full participant, reachable for challenge dispatch — never
// Client (relay-only, unreachable) mode (ARCH §13 §DHT configuration).
const dhtMode = "Server"

// dhtKeyLen is the fixed byte length of every valid DHT key: HMAC-SHA256
// output is always exactly 32 bytes (IC §12).
const dhtKeyLen = 32

// defaultRecordTTL is used when DHTConfig.RecordTTL is zero. Real deployments
// should pass profile.DHTExpiryDuration (12h prod / 4min demo per
// NetworkProfile) — this package intentionally does not import internal/config
// (consistent with keeping internal/p2p dependency-free), so the caller is
// responsible for threading the profile-appropriate value through DHTConfig.
const defaultRecordTTL = 24 * time.Hour

// maxGetCount is the maximum count encoded in a single GET_PROVIDERS request.
const maxGetCount = 255

// ── AddrInfo ─────────────────────────────────────────────────────────────────

// AddrInfo pairs a Peer ID with the multiaddrs at which it is currently
// believed to be reachable.
//
// Mirrors github.com/libp2p/go-libp2p/core/peer.AddrInfo.
type AddrInfo struct {
	ID    PeerID
	Addrs []Multiaddr
}

// ── DHT interface (IC §5.4) ───────────────────────────────────────────────────

// DHT is the Kademlia DHT interface for chunk content-address lookup
// (IC §5.4, ADR-001).
//
// PURPOSE: chunk address lookup and stale-address fallback only. Provider
// discovery goes through the microservice control plane, NOT the DHT (ARCH §5).
type DHT interface {
	// PutProviderRecord announces that the local peer holds the value for
	// key: the local Peer ID and advertised addresses are stored as the
	// provider record for key, both locally and (best effort) replicated to
	// the closest known peers (IC §12.1).
	//
	// Pre-conditions:
	//   - len(key) == 32  (HMAC-SHA256 output is always 32 bytes)
	//   - key was retrieved from the daemon's local cache of the dht_key
	//     computed at upload time — NEVER recomputed (IC §12.2, ARCH §13):
	//     file_owner_key = HKDF(master_secret, ...) is only known to the data
	//     owner and is not available to the daemon after upload completes.
	//
	// Error semantics:
	//   - ErrDHTKeyInvalid: key fails the HMAC-shape validator (IC §12).
	PutProviderRecord(ctx context.Context, key []byte) error

	// FindProviders returns up to maxCount peers that have announced holding
	// the value for key (checking the local record store first, then
	// querying known peers), for use as the stale-address fallback path
	// (IC §12.3).
	//
	// SCOPE (decided, M6 review §5.5): this is a single-hop lookup, not an
	// iterative Kademlia lookup — it queries only the up-to-dhtAlpha
	// closest peers already in the LOCAL routing table and returns
	// whatever they report, without recursing into peers those peers might
	// in turn know about. A record held only outside the querier's
	// immediate k-buckets returns an empty result (not an error). This is
	// a deliberate scope match to IC §12.3's own framing — the DHT is a
	// fallback path, not primary retrieval (which uses microservice-
	// heartbeat-tracked addresses) — not an oversight. Revisit as a
	// dedicated iterative-lookup session if a concrete scenario ever
	// requires the fallback path to survive microservice unavailability at
	// real network scale.
	//
	// Error semantics:
	//   - ErrDHTKeyInvalid: key fails the HMAC-shape validator (IC §12).
	FindProviders(ctx context.Context, key []byte, maxCount int) ([]AddrInfo, error)

	// FindPeer returns the current, connect-verified address(es) this node
	// has locally observed for id — a direct k-bucket routing-table lookup
	// by the peer's OWN identity, not a network round trip and not keyed by
	// any content-address key.
	//
	// [Added — M12 audit corrections, Finding 2] This is deliberately a
	// DIFFERENT primitive from FindProviders. FindProviders answers "who
	// holds this content", keyed by a dht_key that is only ever computable
	// from an owner's file_owner_key (HKDF(master_secret, ...), IC §12.2) —
	// material the coordination microservice never has access to by design
	// (see internal/crypto/hkdf.go's DeriveDHTKey, internal/storage/
	// index.go's dht-keys cache comment). FindPeer instead answers "what is
	// THIS peer's current address", keyed by nothing but the peer's own,
	// never-stale PeerID — exactly what cmd/microservice/adapters.go's
	// resolveProviderPeer already independently derives from
	// providers.ed25519_public_key via PeerIDFromEd25519PublicKey. A stale
	// providers.last_known_multiaddrs row is a stale ADDRESS for an
	// already-known peer identity, not an unknown content lookup — FindPeer
	// is the primitive that actually matches that need; FindProviders
	// cannot serve it without material the microservice structurally does
	// not have.
	//
	// The routing table FindPeer reads is populated purely as a side effect
	// of ordinary inbound DHT traffic: handlePut Connect-verifies and adds
	// every PUT_PROVIDER sender to the local k-buckets (see addToRoutingTable
	// and its call site in handlePut, M6 review §5.4) — no additional wire
	// protocol is required for this method to have real data to return,
	// once this node is bootstrapped and receiving that traffic from
	// providers' periodic heartbeat republication (internal/p2p/heartbeat.go).
	//
	// SCOPE: a local-only lookup (this node's own k-buckets), matching the
	// same single-hop scope decision FindProviders' own doc comment
	// documents for M6 review §5.5 — not an iterative FIND_NODE query that
	// recurses into peers this node doesn't already know. Revisit as a
	// dedicated iterative-lookup session if a concrete scenario requires
	// this fallback to succeed for a peer this node has never heard from at
	// all.
	//
	// Error semantics:
	//   - ErrPeerNotInRoutingTable: id is not currently present in the
	//     local routing table (an ordinary, expected outcome — see that
	//     sentinel's own doc comment).
	FindPeer(ctx context.Context, id PeerID) (AddrInfo, error)

	// Bootstrap connects to the configured seed nodes and fills the k-buckets.
	// Must be called once at daemon startup, after the Host is created
	// (ARCH §13). A DHT with no configured seeds bootstraps as a no-op.
	Bootstrap(ctx context.Context) error
}

// ── HMAC key validator (IC §12) ───────────────────────────────────────────────

// validateDHTKey enforces the IC §12 key acceptance rules.
//
// Accept: len(key) == 32 and no forbidden prefix.
// Reject (ErrDHTKeyInvalid): wrong length, or "vyom-chunk:" prefix.
//
// The third IC §12 rejection rule — "the libp2p default CID namespace keys...
// not produced by HMAC-SHA256" — requires no separate check: every multihash
// encoding (identity, SHA2-256, or otherwise) prepends at least a 2-byte
// function-code/length header before its digest, so a CID or bare multihash
// is never exactly 32 bytes. The length check alone rejects it. See
// dht_test.go's CASE 2 for the regression test that pins this down.
func validateDHTKey(key []byte) error {
	if len(key) != dhtKeyLen {
		return fmt.Errorf("%w: key length %d != %d", ErrDHTKeyInvalid, len(key), dhtKeyLen)
	}
	// Plaintext SHA-256 chunk hashes are prefixed "vyom-chunk:" in other
	// Vyomanaut contexts. They must never be stored directly in the DHT —
	// that would leak file identity (IC §12).
	if bytes.HasPrefix(key, []byte("vyom-chunk:")) {
		return fmt.Errorf("%w: key has forbidden plaintext chunk-hash prefix", ErrDHTKeyInvalid)
	}
	return nil
}

// ── kademliaDHT concrete implementation ───────────────────────────────────────

// providerRecord is one entry in the local record store: key -> a provider's
// AddrInfo, with the time it was last (re)announced for TTL expiry.
type providerRecord struct {
	info      AddrInfo
	updatedAt time.Time
}

// peerEntry is one k-bucket routing-table entry.
type peerEntry struct {
	info  AddrInfo
	kadID [32]byte // SHA-256(PeerID) — see kadID(), used for XOR-metric bucketing
}

// DHTConfig supplies the addresses this node advertises for itself and the
// bootstrap seed set for NewDHT.
type DHTConfig struct {
	// SelfAddrs are the multiaddrs other peers should use to reach this node —
	// advertised whenever PutProviderRecord announces this node as a provider.
	SelfAddrs []Multiaddr

	// Seeds are the well-known bootstrap peers Bootstrap connects to.
	Seeds []AddrInfo

	// RecordTTL is the local record staleness window (IC §12.2). Zero uses
	// defaultRecordTTL; production wiring should pass profile.DHTExpiryDuration.
	RecordTTL time.Duration
}

// kademliaDHT is the concrete, unexported DHT implementation.
type kademliaDHT struct {
	host      Host
	selfID    PeerID
	selfAddrs []Multiaddr
	seeds     []AddrInfo
	recordTTL time.Duration

	mu      sync.RWMutex
	buckets [256][]*peerEntry // indexed by XOR common-prefix-length vs selfKadID
	records map[[32]byte]*providerRecord
	selfKad [32]byte
}

// NewDHT constructs a DHT bound to host, registering this package's DHT wire
// protocol handler so remote peers can PUT/GET provider records against us.
//
// [REF: IC §5.4, ARCH §13]
func NewDHT(host Host, cfg DHTConfig) (DHT, error) {
	if host == nil {
		return nil, fmt.Errorf("p2p.NewDHT: host must not be nil")
	}
	d := &kademliaDHT{
		host:      host,
		selfID:    host.PeerID(),
		selfAddrs: cfg.SelfAddrs,
		seeds:     cfg.Seeds,
		recordTTL: cfg.RecordTTL,
		records:   make(map[[32]byte]*providerRecord),
	}
	if d.recordTTL <= 0 {
		d.recordTTL = defaultRecordTTL
	}
	d.selfKad = kadID(d.selfID)

	host.SetStreamHandler(ProtocolID(dhtKeyNamespace), d.handleStream)

	return d, nil
}

// ── PutProviderRecord ─────────────────────────────────────────────────────────

func (d *kademliaDHT) PutProviderRecord(ctx context.Context, key []byte) error {
	if err := validateDHTKey(key); err != nil {
		return err
	}
	var k [32]byte
	copy(k[:], key)

	self := AddrInfo{ID: d.selfID, Addrs: d.selfAddrs}
	d.storeRecord(k, self)

	// Best-effort replication to the kBucketSize closest known peers (the
	// Kademlia "store at the k closest nodes" step). Individual failures do
	// not fail the call — the local announcement above already succeeded,
	// and replication is a durability optimisation, not a correctness
	// requirement for a node that is itself reachable.
	for _, peer := range d.closestPeers(k, kBucketSize) {
		d.pushProviderRecord(ctx, peer, k, self)
	}
	return nil
}

func (d *kademliaDHT) storeRecord(key [32]byte, info AddrInfo) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[key] = &providerRecord{info: info, updatedAt: time.Now()}
}

// pushProviderRecord sends a PUT_PROVIDER message to peer for key/info,
// tolerating any failure (best-effort replication).
func (d *kademliaDHT) pushProviderRecord(ctx context.Context, peer *peerEntry, key [32]byte, info AddrInfo) {
	stream, err := d.host.NewStream(ctx, peer.info.ID, ProtocolID(dhtKeyNamespace))
	if err != nil {
		log.Printf("[dht] push key %x to peer %s: open stream: %v", key, peer.info.ID, err)
		return
	}
	defer func() { _ = stream.Close() }()

	req := encodePutRequest(key, info)
	if _, err := stream.Write(req); err != nil {
		log.Printf("[dht] push key %x to peer %s: write request: %v", key, peer.info.ID, err)
		return
	}
	ack := make([]byte, 1)
	if _, err := streamReadFull(stream, ack); err != nil {
		log.Printf("[dht] push key %x to peer %s: read ack: %v", key, peer.info.ID, err)
		return
	}
	if ack[0] != negotiationAckOK {
		log.Printf("[dht] push key %x to peer %s: rejected", key, peer.info.ID)
	}
}

// ── FindProviders ──────────────────────────────────────────────────────────

func (d *kademliaDHT) FindProviders(ctx context.Context, key []byte, maxCount int) ([]AddrInfo, error) {
	if err := validateDHTKey(key); err != nil {
		return nil, err
	}
	if maxCount <= 0 {
		return nil, fmt.Errorf("p2p.FindProviders: maxCount must be > 0, got %d", maxCount)
	}
	var k [32]byte
	copy(k[:], key)

	results := make(map[PeerID]AddrInfo)

	if rec := d.lookupLocal(k); rec != nil {
		results[rec.info.ID] = rec.info
	}

	// Query up to dhtAlpha of the closest known peers for the remainder.
	for _, peer := range d.closestPeers(k, dhtAlpha) {
		if len(results) >= maxCount {
			break
		}
		for _, found := range d.queryPeer(ctx, peer, k, maxCount) {
			results[found.ID] = found
		}
	}

	out := make([]AddrInfo, 0, len(results))
	for _, info := range results {
		out = append(out, info)
		if len(out) >= maxCount {
			break
		}
	}
	return out, nil
}

// ── FindPeer ──────────────────────────────────────────────────────────────

// FindPeer implements the DHT interface — see that method's own doc comment
// for why this is a routing-table lookup keyed by peer identity, not a
// FindProviders-style content-key lookup.
//
// ctx is accepted for interface-signature consistency with FindProviders
// and to leave room for a future iterative version to make real network
// calls; the current single-hop, local-routing-table-only implementation
// never blocks on it.
func (d *kademliaDHT) FindPeer(_ context.Context, id PeerID) (AddrInfo, error) {
	// addToRoutingTable always places a peer at exactly this bucket index —
	// commonPrefixLen(selfKad, kadID(peer)) — so a target lookup only ever
	// needs to scan that one bucket, never all 256.
	target := kadID(id)
	idx := commonPrefixLen(d.selfKad, target)
	if idx >= len(d.buckets) {
		idx = len(d.buckets) - 1
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, entry := range d.buckets[idx] {
		if entry.info.ID == id {
			return entry.info, nil
		}
	}
	return AddrInfo{}, fmt.Errorf("p2p.FindPeer: %w", ErrPeerNotInRoutingTable)
}

// lookupLocal returns the local provider record for key, or nil if absent or
// expired (IC §12.2 staleness window).
func (d *kademliaDHT) lookupLocal(key [32]byte) *providerRecord {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rec, ok := d.records[key]
	if !ok || time.Since(rec.updatedAt) > d.recordTTL {
		return nil
	}
	return rec
}

// queryPeer sends a GET_PROVIDERS message to peer and returns whatever
// providers it reports, tolerating any failure by returning nil.
func (d *kademliaDHT) queryPeer(ctx context.Context, peer *peerEntry, key [32]byte, maxCount int) []AddrInfo {
	stream, err := d.host.NewStream(ctx, peer.info.ID, ProtocolID(dhtKeyNamespace))
	if err != nil {
		log.Printf("[dht] query peer %s for key %x: open stream: %v", peer.info.ID, key, err)
		return nil
	}
	defer func() { _ = stream.Close() }()

	req := encodeGetRequest(key, maxCount)
	if _, err := stream.Write(req); err != nil {
		log.Printf("[dht] query peer %s for key %x: write request: %v", peer.info.ID, key, err)
		return nil
	}
	infos, err := decodeGetResponse(stream)
	if err != nil {
		log.Printf("[dht] query peer %s for key %x: read response: %v", peer.info.ID, key, err)
		return nil
	}
	return infos
}

// ── Bootstrap ──────────────────────────────────────────────────────────────

func (d *kademliaDHT) Bootstrap(ctx context.Context) error {
	if len(d.seeds) == 0 {
		return nil
	}
	var succeeded int
	var lastErr error
	for _, seed := range d.seeds {
		if err := d.host.Connect(ctx, seed.ID, seed.Addrs); err != nil {
			lastErr = err
			continue
		}
		d.addToRoutingTable(seed)
		succeeded++
	}
	if succeeded == 0 {
		return fmt.Errorf("p2p.Bootstrap: all %d seed(s) failed, last error: %w", len(d.seeds), lastErr)
	}
	return nil
}

// ── routing table (k-buckets, XOR metric) ─────────────────────────────────────

// kadID maps a PeerID into a uniform 256-bit ID space via SHA-256, so XOR
// distance is well-distributed regardless of how peer IDs are encoded
// upstream (the same technique real libp2p k-bucket implementations use).
func kadID(id PeerID) [32]byte {
	return sha256.Sum256([]byte(id))
}

// commonPrefixLen returns the number of leading bits a and b share — the
// bucket index a peer at XOR-distance from self falls into.
func commonPrefixLen(a, b [32]byte) int {
	count := 0
	for i := 0; i < 32; i++ {
		x := a[i] ^ b[i]
		if x == 0 {
			count += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if x&(1<<uint(bit)) != 0 {
				return count
			}
			count++
		}
	}
	return count
}

// addToRoutingTable inserts peer into the appropriate k-bucket relative to
// self, evicting the oldest entry if the bucket is already at kBucketSize
// (a simplification of Kademlia's usual "ping the least-recently-seen node
// first" eviction policy — acceptable here since eviction only matters at a
// peer-table scale this implementation is not expected to reach; see doc.go).
func (d *kademliaDHT) addToRoutingTable(info AddrInfo) {
	if info.ID == d.selfID {
		return
	}
	entry := &peerEntry{info: info, kadID: kadID(info.ID)}
	idx := commonPrefixLen(d.selfKad, entry.kadID)
	if idx >= len(d.buckets) {
		idx = len(d.buckets) - 1
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	bucket := d.buckets[idx]
	for i, existing := range bucket {
		if existing.info.ID == info.ID {
			bucket[i] = entry // refresh
			return
		}
	}
	if len(bucket) >= kBucketSize {
		bucket = bucket[1:] // evict oldest
	}
	d.buckets[idx] = append(bucket, entry)
}

// closestPeers returns up to n known peers ordered by ascending XOR distance
// from key (used both for provider-record replication targets and for
// choosing which peers to query in FindProviders).
func (d *kademliaDHT) closestPeers(key [32]byte, n int) []*peerEntry {
	d.mu.RLock()
	all := make([]*peerEntry, 0)
	for _, bucket := range d.buckets {
		all = append(all, bucket...)
	}
	d.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool {
		return xorLess(all[i].kadID, key, all[j].kadID)
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// xorLess reports whether a is closer to key than b is (smaller XOR distance).
func xorLess(a, key, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		da := a[i] ^ key[i]
		db := b[i] ^ key[i]
		if da != db {
			return da < db
		}
	}
	return false
}

// ── wire protocol ────────────────────────────────────────────────────────────
//
// Two message kinds are multiplexed on the dhtKeyNamespace stream protocol,
// distinguished by a one-byte kind tag:
//
//	0x01 PUT_PROVIDER request:  kind(1) key(32) addrCount(1) [addrLen(1) addr...]
//	                  response: ack(1)              (negotiationAckOK / Reject)
//	0x02 GET_PROVIDERS request: kind(1) key(32) maxCount(1)
//	                  response: count(1) [peerIDLen(1) peerID addrCount(1) [addrLen(1) addr...]]

const (
	dhtMsgPutProvider  byte = 0x01
	dhtMsgGetProviders byte = 0x02
)

func encodePutRequest(key [32]byte, info AddrInfo) []byte {
	buf := []byte{dhtMsgPutProvider}
	buf = append(buf, key[:]...)
	buf = append(buf, byte(len(info.Addrs)))
	for _, a := range info.Addrs {
		s := a.String()
		buf = append(buf, byte(len(s)))
		buf = append(buf, s...)
	}
	return buf
}

func encodeGetRequest(key [32]byte, maxCount int) []byte {
	buf := []byte{dhtMsgGetProviders}
	buf = append(buf, key[:]...)
	if maxCount > maxGetCount {
		maxCount = maxGetCount
	}
	buf = append(buf, byte(maxCount))
	return buf
}

func encodeGetResponse(infos []AddrInfo) []byte {
	buf := []byte{byte(len(infos))}
	for _, info := range infos {
		idBytes := []byte(info.ID)
		buf = append(buf, byte(len(idBytes)))
		buf = append(buf, idBytes...)
		buf = append(buf, byte(len(info.Addrs)))
		for _, a := range info.Addrs {
			s := a.String()
			buf = append(buf, byte(len(s)))
			buf = append(buf, s...)
		}
	}
	return buf
}

func decodeGetResponse(r streamReader) ([]AddrInfo, error) {
	countBuf := make([]byte, 1)
	if _, err := streamReadFull(r, countBuf); err != nil {
		return nil, err
	}
	out := make([]AddrInfo, 0, countBuf[0])
	for i := 0; i < int(countBuf[0]); i++ {
		idLenBuf := make([]byte, 1)
		if _, err := streamReadFull(r, idLenBuf); err != nil {
			return nil, err
		}
		idBuf := make([]byte, idLenBuf[0])
		if _, err := streamReadFull(r, idBuf); err != nil {
			return nil, err
		}
		addrCountBuf := make([]byte, 1)
		if _, err := streamReadFull(r, addrCountBuf); err != nil {
			return nil, err
		}
		var addrs []Multiaddr
		for j := 0; j < int(addrCountBuf[0]); j++ {
			addrLenBuf := make([]byte, 1)
			if _, err := streamReadFull(r, addrLenBuf); err != nil {
				return nil, err
			}
			addrBuf := make([]byte, addrLenBuf[0])
			if _, err := streamReadFull(r, addrBuf); err != nil {
				return nil, err
			}
			if ma, err := ParseMultiaddr(string(addrBuf)); err == nil {
				addrs = append(addrs, ma)
			}
		}
		out = append(out, AddrInfo{ID: PeerID(idBuf), Addrs: addrs})
	}
	return out, nil
}

// handleStream is the dhtKeyNamespace stream handler registered with the
// Host in NewDHT; it dispatches inbound PUT_PROVIDER / GET_PROVIDERS
// requests from peers.
func (d *kademliaDHT) handleStream(s Stream) {
	defer func() { _ = s.Close() }()

	kindBuf := make([]byte, 1)
	if _, err := streamReadFull(s, kindBuf); err != nil {
		return
	}

	switch kindBuf[0] {
	case dhtMsgPutProvider:
		d.handlePut(s)
	case dhtMsgGetProviders:
		d.handleGet(s)
	}
}

func (d *kademliaDHT) handlePut(s Stream) {
	keyBuf := make([]byte, dhtKeyLen)
	if _, err := streamReadFull(s, keyBuf); err != nil {
		return
	}
	addrCountBuf := make([]byte, 1)
	if _, err := streamReadFull(s, addrCountBuf); err != nil {
		return
	}
	var addrs []Multiaddr
	for i := 0; i < int(addrCountBuf[0]); i++ {
		lenBuf := make([]byte, 1)
		if _, err := streamReadFull(s, lenBuf); err != nil {
			_, _ = s.Write([]byte{negotiationAckReject})
			return
		}
		addrBuf := make([]byte, lenBuf[0])
		if _, err := streamReadFull(s, addrBuf); err != nil {
			_, _ = s.Write([]byte{negotiationAckReject})
			return
		}
		if ma, err := ParseMultiaddr(string(addrBuf)); err == nil {
			addrs = append(addrs, ma)
		}
	}

	if err := validateDHTKey(keyBuf); err != nil {
		_, _ = s.Write([]byte{negotiationAckReject})
		return
	}

	var key [32]byte
	copy(key[:], keyBuf)
	// The remote peer's identity is taken from the already-authenticated TLS
	// handshake (RemotePeer), never from a self-reported field in the wire
	// message — the wire message intentionally carries no separate,
	// spoofable peer-ID field.
	sender := AddrInfo{ID: s.RemotePeer(), Addrs: addrs}
	d.storeRecord(key, sender)
	_, _ = s.Write([]byte{negotiationAckOK})

	// Grow the routing table from real DHT traffic, not just the initial
	// seed list (M6 review §5.4) — without this, k-buckets never expand
	// past whatever was hardcoded at startup, degrading the network to a
	// star topology centred on the seeds. Runs after the ack, in its own
	// goroutine, so a slow/unresponsive sender never delays the PUT
	// response the caller is waiting on. Connect (not just
	// addToRoutingTable) verifies the sender's self-reported addrs
	// actually belong to them — the same authentication Bootstrap already
	// performs for seeds — and populates h.knownAddrs, which NewStream
	// requires before this peer can ever be dialled again by
	// pushProviderRecord/queryPeer; skipping Connect would add a routing-
	// table entry that silently can never be used. Best-effort: the PUT
	// already succeeded via storeRecord above regardless of this outcome.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dhtPeerVerifyTimeout)
		defer cancel()
		if connErr := d.host.Connect(ctx, sender.ID, sender.Addrs); connErr == nil {
			d.addToRoutingTable(sender)
		}
	}()
}

func (d *kademliaDHT) handleGet(s Stream) {
	keyBuf := make([]byte, dhtKeyLen)
	if _, err := streamReadFull(s, keyBuf); err != nil {
		return
	}
	maxCountBuf := make([]byte, 1)
	if _, err := streamReadFull(s, maxCountBuf); err != nil {
		return
	}

	if err := validateDHTKey(keyBuf); err != nil {
		_, _ = s.Write(encodeGetResponse(nil))
		return
	}

	var key [32]byte
	copy(key[:], keyBuf)
	rec := d.lookupLocal(key)

	var infos []AddrInfo
	if rec != nil {
		infos = append(infos, rec.info)
	}
	// M6 review §5.6: maxCount=0 must mean "return nothing", not "no
	// limit". The old `maxCountBuf[0] > 0 &&` guard skipped truncation
	// entirely for that case.
	if len(infos) > int(maxCountBuf[0]) {
		infos = infos[:maxCountBuf[0]]
	}
	_, _ = s.Write(encodeGetResponse(infos))
}

// streamReader is the minimal read surface decodeGetResponse needs; Stream
// satisfies it directly (kept separate purely so streamReadFull can also be
// exercised against a bare net.Conn in tests without importing net here).
type streamReader interface {
	Read(p []byte) (int, error)
}

func streamReadFull(r streamReader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Package p2p is declared in doc.go.
// This file defines the sentinel errors exported by the p2p package.
// Callers must compare using errors.Is; never construct these values inline.
//
// [REF: IC §5.4]

package p2p

import "errors"

var (
	// ErrPeerIDMismatch is returned by Connect when the remote peer's authenticated ID
	// does not match the expected peerID supplied by the caller (IC §5.4, NFR-016).
	ErrPeerIDMismatch = errors.New("p2p: remote Peer ID does not match expected")

	// ErrAllAddrsFailed is returned by Connect when every provided multiaddr
	// fails to establish a connection (IC §5.4).
	ErrAllAddrsFailed = errors.New("p2p: all provided multiaddrs failed to connect")

	// ErrDHTKeyInvalid is returned by PutProviderRecord or FindProviders when
	// the key does not satisfy the custom HMAC validator (IC §5.4, IC §12).
	ErrDHTKeyInvalid = errors.New("p2p: DHT key does not pass HMAC validator")

	// ErrPeerNotInRoutingTable is returned by FindPeer when id is not
	// currently present in the local k-bucket routing table (M12 audit
	// corrections, Finding 2). This is an ordinary, expected outcome — not
	// a failure — whenever this node has not yet observed any DHT traffic
	// from that peer; callers should treat it as "the DHT fallback has
	// nothing newer to offer right now," not as an error condition to
	// surface to an operator.
	ErrPeerNotInRoutingTable = errors.New("p2p: peer not present in local routing table")
)

// Package cluster is declared in doc.go.
// This file implements Membership and GossipCluster: a stand-in for the real
// gossip-based cluster membership protocol ARCH §18 describes (each replica
// contacts one randomly chosen peer per second to reconcile membership
// histories; two seed node addresses prevent the cluster from partitioning
// on restart).
//
// [Decision, build.md Milestone 12 Phase 12.1 Session 12.1.1] Session
// 12.1.1's own PRECONDITIONS treat "internal/cluster/mock_cluster.go's
// MockClusterMembership" as something already on disk, usable as a
// startup-time stub. It was not: internal/cluster was an empty package
// (doc.go only) before this session, and no file anywhere constructs a
// cluster.NewGossipCluster or references cluster.ResponsibleReplica. The
// only pre-existing stub is api.MockClusterMembership
// (internal/api/readiness.go), built for Milestone 11's readiness gate
// specifically and already wired into api.NewReadinessEvaluator. That stub
// is left untouched — this file adds the SEPARATE stub ARCH §18 and this
// session's own step 6 describe (a general gossip-cluster membership
// object, constructed from seed addresses, with a quorum-wait method),
// following the exact "stub until the LTS Production Hardening milestone's
// gossip-cluster session" pattern the
// session text uses elsewhere (e.g. the client-driven router in router.go).
//
// Membership's single HealthyCount() int method is intentionally identical
// in shape to api.ClusterMembership (internal/api/readiness.go) so that
// *GossipCluster and SoloMembership below can also be passed directly to
// api.NewReadinessEvaluator without either package importing the other —
// Go interface satisfaction is structural, so no import is needed for that
// to work.
//
// [REF: ARCH §18, ADR-025, IC §9, build.md Milestone 12 Phase 12.1 Session 12.1.1]

package cluster

import (
	"context"
	"fmt"
)

// productionQuorumSize mirrors ADR-025's (3, 2, 2) quorum — three replicas,
// matching api.MockClusterMembership's own existing stub value
// (internal/api/readiness.go) so the two independently-built stubs agree on
// what "a healthy production cluster" reports until the LTS Production
// Hardening milestone (relocated from the old Milestone 17 by M17 Session
// 17.3.1; see build_part4.md) replaces
// both with the real gossip protocol.
const productionQuorumSize = 3

// soloInstanceSize is the demo-mode healthy count: one instance, quorum
// disabled (ADR-031).
const soloInstanceSize = 1

// Membership reports the current gossip cluster's healthy replica count.
// Structurally identical to api.ClusterMembership (internal/api/readiness.go)
// — see this file's header note for why that similarity is deliberate.
type Membership interface {
	HealthyCount() int
}

// SoloMembership always reports 1 healthy replica — the demo-mode stub
// (profile.RequireQuorum == false), where quorum is disabled entirely and
// no gossip cluster is ever constructed.
type SoloMembership struct{}

// HealthyCount implements Membership.
func (SoloMembership) HealthyCount() int { return soloInstanceSize }

// GossipCluster is a stub for the real gossip-based membership protocol
// (ARCH §18: 1-second reconciliation ticker, two pre-configured seed node
// addresses). Its permanent home is the LTS track's Production Hardening
// milestone (relocated from the old Milestone 17 by M17 Session 17.3.1 —
// see build_part4.md's "LTS — Production Hardening" section); until then
// it always reports 3 healthy replicas and WaitForQuorum returns
// immediately once that threshold is met — no actual gossip reconciliation
// happens yet.
type GossipCluster struct {
	seeds []string
}

// NewGossipCluster constructs the stub gossip cluster from the two
// pre-configured seed node addresses (ARCH §18). seeds is retained only for
// future use by the real LTS Production Hardening implementation; the stub
// does not
// dial them.
func NewGossipCluster(seeds []string) *GossipCluster {
	return &GossipCluster{seeds: seeds}
}

// HealthyCount implements Membership. Stub: always reports the production
// quorum size, matching api.MockClusterMembership's existing behaviour.
func (g *GossipCluster) HealthyCount() int { return productionQuorumSize }

// WaitForQuorum blocks until at least minPeers replicas (this one included)
// have acknowledged membership, or ctx is cancelled — the cold-start
// split-brain guard ARCH §18 and this session's step 6 both require
// ("BLOCK until >= 2 peers ack membership"). Stub: since HealthyCount always
// reports 3, this returns immediately for any minPeers <= 3; there is no
// actual peer-ack wait to perform yet (the LTS Production Hardening
// milestone's gossip-cluster session).
func (g *GossipCluster) WaitForQuorum(ctx context.Context, minPeers int) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if g.HealthyCount() < minPeers {
		return fmt.Errorf("cluster.GossipCluster.WaitForQuorum: have %d healthy peers, want >= %d",
			g.HealthyCount(), minPeers)
	}
	return nil
}

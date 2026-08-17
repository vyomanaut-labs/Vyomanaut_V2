// Package cluster is declared in doc.go.
// This file implements Router and ResponsibleReplica — the client-driven
// routing ARCH §18 describes for latency-sensitive paths (audit challenge
// dispatch, chunk assignment decisions): "the service client caches cluster
// membership and routes directly to the responsible replica, bypassing the
// load balancer... reduces 99.9th-percentile latency by 30+ ms."
//
// [Decision, build.md Milestone 12 Phase 12.1 Session 12.1.1] See
// membership.go's header note: this file, like that one, did not exist
// before this session despite being treated as a precondition. Built here
// as a stub — a no-op until the LTS track's Production Hardening milestone
// (relocated from the old Milestone 17 by M17 Session 17.3.1 — see
// build_part4.md's "LTS — Production Hardening" section): ResponsibleReplica
// always returns the load balancer's own address, i.e. every audit-dispatch/
// chunk-assignment call routes exactly the way it would without this
// optimisation at all. The real membership-aware routing logic (caching
// which replica owns which key range, dialing it directly) is that
// milestone's gossip-cluster session's job — do not attempt it here.
//
// [REF: ARCH §18, IC §2, IC §9, build.md Milestone 12 Phase 12.1 Session 12.1.1]

package cluster

// OpType identifies a latency-sensitive operation category for
// client-driven routing (ARCH §18).
type OpType int

const (
	// OpAuditDispatch is the audit-challenge-dispatch hot path.
	OpAuditDispatch OpType = iota
	// OpChunkAssignment is the chunk-assignment-decision hot path.
	OpChunkAssignment
)

// Router routes latency-sensitive requests directly to the responsible
// replica, bypassing the load balancer (ARCH §18).
type Router struct {
	// loadBalancerAddr is the address every OpType currently routes to —
	// see ResponsibleReplica's own doc comment for why that is the STUB
	// behaviour, not merely a fallback.
	loadBalancerAddr string
	membership       Membership
}

// NewRouter constructs a Router. membership is retained for the LTS
// Production Hardening milestone's real implementation to consult; the
// stub in this file never reads it.
func NewRouter(membership Membership, loadBalancerAddr string) *Router {
	return &Router{membership: membership, loadBalancerAddr: loadBalancerAddr}
}

// ResponsibleReplica returns the address audit-dispatch/chunk-assignment
// hot paths (ARCH §18) should send opType traffic to.
//
// STUB behaviour (no-op until the LTS track's Production Hardening
// milestone): this always returns the load balancer's own address — i.e.
// the 30+ ms latency optimisation ARCH §18 describes is a no-op until that
// milestone provides the real gossip-aware implementation. Do not attempt the real membership-aware
// routing logic here; every caller of this method already tolerates
// load-balancer-indirection latency today, so this stub changes nothing
// about correctness — only the future optimisation is deferred.
func (r *Router) ResponsibleReplica(opType OpType) string {
	return r.loadBalancerAddr
}

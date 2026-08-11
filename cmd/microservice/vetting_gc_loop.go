// cmd/microservice — see main.go's package doc comment.
//
// [Flagged and fixed — closes a gap found via live verification, the same
// shape as vetting_chunk_loop.go and cluster_secret_refresh_loop.go: a
// correctly-implemented component (internal/vettingchunk.GCDelivery,
// Milestone 14) that nothing ever called]
//
// internal/scoring.IncrementConsecutivePasses (passes.go) performs the
// VETTING→ACTIVE database transition but returns only error — it has no way
// to signal "a transition just happened" to its caller
// (runAuditDispatchLoop, audit_dispatch.go), so nothing was ever positioned
// to call vettingchunk.GCDelivery.DeliverGCInstruction at the one moment
// IC §5.10 specifies: immediately after ACTIVE transition. Rather than
// changing IncrementConsecutivePasses's signature (internal/scoring is an
// already-tested package; this fix stays entirely inside cmd/microservice,
// same discipline as the other two loops), this file polls for the
// resulting state instead of the event: any ACTIVE provider that still has
// live (status = 'ACTIVE') synthetic chunk_assignments has not yet had GC
// delivered, regardless of how long ago the transition happened.
//
// [REF: IC §5.10, IC §4.5, ADR-030, ADR-036, DM §4.5,
// build.md Milestone 14 Phase 14.2 Session 14.2.1, build.md Session 16.1.1]
package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/vettingchunk"
)

// vettingGCPollInterval is how often this loop checks for ACTIVE providers
// with undelivered vetting GC. Independent of the other two loops'
// intervals for the same reason theirs are independent of each other:
// distinct concerns that happen to share similar cadences today.
const vettingGCPollInterval = 30 * time.Second

// runVettingGCLoop blocks until ctx is cancelled, delivering the vetting GC
// instruction (IC §5.10) to every ACTIVE provider that still has live
// synthetic chunk_assignments, on vettingGCPollInterval.
func runVettingGCLoop(ctx context.Context, db *sql.DB, gc vettingchunk.GCDelivery) {
	ticker := time.NewTicker(vettingGCPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deliverGCForActiveProviders(ctx, db, gc)
		}
	}
}

// deliverGCForActiveProviders finds every ACTIVE provider with at least one
// live (status = 'ACTIVE') synthetic chunk_assignments row — i.e., every
// provider GC has not yet successfully delivered to — and calls
// DeliverGCInstruction for each. A single provider's failure (e.g.
// ErrProviderOffline, per GCDelivery's own documented retry contract) is
// logged and skipped, not fatal to the cycle; the next tick retries.
func deliverGCForActiveProviders(ctx context.Context, db *sql.DB, gc vettingchunk.GCDelivery) {
	const query = `
SELECT DISTINCT p.provider_id
FROM providers p
JOIN chunk_assignments ca ON ca.provider_id = p.provider_id
WHERE p.status = 'ACTIVE'
  AND ca.is_vetting_chunk = TRUE
  AND ca.status = 'ACTIVE'`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		log.Printf("[vetting-gc] load ACTIVE providers with undelivered GC: %v", err)
		return
	}

	var providerIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if scanErr := rows.Scan(&id); scanErr != nil {
			log.Printf("[vetting-gc] scan provider_id: %v", scanErr)
			continue
		}
		providerIDs = append(providerIDs, id)
	}
	closeErr := rows.Close()
	if err := rows.Err(); err != nil {
		log.Printf("[vetting-gc] iterate ACTIVE providers: %v", err)
		return
	}
	if closeErr != nil {
		log.Printf("[vetting-gc] close ACTIVE providers query: %v", closeErr)
	}

	for _, providerID := range providerIDs {
		if err := gc.DeliverGCInstruction(ctx, providerID); err != nil {
			log.Printf("[vetting-gc][%s] DeliverGCInstruction: %v", providerID, err)
		}
	}
}
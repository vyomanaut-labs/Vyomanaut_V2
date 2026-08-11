// cmd/microservice — see main.go's package doc comment.
//
// [Flagged and fixed — closes a gap that blocked VETTING→ACTIVE for every
// provider in any deployment of this codebase, discovered via live
// verification (build.md Session 16.1.1), not visible from a code-only
// review] internal/vettingchunk/generator.go's Generator (Milestone 14) was
// never imported anywhere in cmd/microservice — nothing ever called
// GenerateChunk for a newly-VETTING provider. Without a chunk_assignments
// row, loadActiveChunkAssignments (audit_dispatch.go) always returns empty
// for that provider, runAuditDispatchLoop has nothing to challenge,
// consecutive_audit_passes never advances past 0, and internal/scoring's
// own VETTING→ACTIVE transition (passes.go) — gated on
// consecutive_audit_passes >= profile.VettingMinPasses — can never fire.
// This is the second of two gaps in the same registration→heartbeat→
// vetting→active chain found this session; see the heartbeat-auth gap
// (internal/p2p/heartbeat.go) for the first. Both are documented together
// in an ADR addendum once confirmed working end-to-end.
//
// [REF: IC §5.10, ADR-030, DM §4.5, build.md Milestone 14, build.md Session
// 16.1.1]
package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/vettingchunk"
)

// vettingChunkGenerationInterval is how often this loop checks for VETTING
// providers needing more synthetic chunks. Deliberately independent of
// profile.PollingInterval (runAuditDispatchLoop's cadence) rather than
// reusing that field — generation and audit dispatch are different
// concerns that happen to share a value (2m) in the demo profile today;
// tying them together would be an accidental coupling, not a real one.
const vettingChunkGenerationInterval = 30 * time.Second

// vettingChunkPerCycleTarget is how many synthetic chunks this loop ensures
// a VETTING provider has assigned — NOT vettingchunk.Generator's Cap()
// ceiling (declared_storage_gb × 400, e.g. 40,000 for a 100 GB demo
// provider). Cap() bounds how MANY a provider could ever be assigned
// (production-scale headroom); it is not a target this loop tries to reach.
// runAuditDispatchLoop only needs at least one real assignment per provider
// to have something to challenge each cycle — a small fixed target proves
// and exercises the full VETTING→ACTIVE path without generating and
// uploading tens of thousands of 256 KB chunks per provider for no
// additional verification value.
const vettingChunkPerCycleTarget = 3

// runVettingChunkGenerationLoop blocks until ctx is cancelled, topping up
// synthetic vetting-chunk assignments for every VETTING provider on
// vettingChunkGenerationInterval.
func runVettingChunkGenerationLoop(ctx context.Context, db *sql.DB, generator vettingchunk.Generator) {
	ticker := time.NewTicker(vettingChunkGenerationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			generateForVettingProviders(ctx, db, generator)
		}
	}
}

// vettingProviderTarget is one VETTING provider's declared storage size —
// the only input Cap() needs alongside CurrentCount's live DB read.
type vettingProviderTarget struct {
	providerID        uuid.UUID
	declaredStorageGB int
}

// generateForVettingProviders runs one generation cycle: load every VETTING
// provider, and for each, generate synthetic chunks up to
// min(vettingChunkPerCycleTarget, generator.Cap(declaredStorageGB)) if it
// isn't already there. A single provider's GenerateChunk failure (e.g. a
// transiently unreachable multiaddr) is logged and skipped, not fatal to
// the cycle — the next tick retries automatically, matching every other
// background loop's retry-by-polling convention in this file set.
func generateForVettingProviders(ctx context.Context, db *sql.DB, generator vettingchunk.Generator) {
	rows, err := db.QueryContext(ctx, `SELECT provider_id, declared_storage_gb FROM providers WHERE status = 'VETTING'`)
	if err != nil {
		log.Printf("[vetting-chunk] load VETTING providers: %v", err)
		return
	}

	var targets []vettingProviderTarget
	for rows.Next() {
		var t vettingProviderTarget
		if scanErr := rows.Scan(&t.providerID, &t.declaredStorageGB); scanErr != nil {
			log.Printf("[vetting-chunk] scan VETTING provider: %v", scanErr)
			continue
		}
		targets = append(targets, t)
	}
	closeErr := rows.Close()
	if err := rows.Err(); err != nil {
		log.Printf("[vetting-chunk] iterate VETTING providers: %v", err)
		return
	}
	if closeErr != nil {
		log.Printf("[vetting-chunk] close VETTING providers query: %v", closeErr)
	}

	for _, t := range targets {
		generateForOneProvider(ctx, db, generator, t)
	}
}

func generateForOneProvider(ctx context.Context, db *sql.DB, generator vettingchunk.Generator, t vettingProviderTarget) {
	current, err := generator.CurrentCount(ctx, db, t.providerID)
	if err != nil {
		log.Printf("[vetting-chunk][%s] CurrentCount: %v", t.providerID, err)
		return
	}

	target := vettingChunkPerCycleTarget
	if cap := generator.Cap(t.declaredStorageGB); cap < target {
		target = cap
	}

	for ; current < target; current++ {
		if _, genErr := generator.GenerateChunk(ctx, t.providerID); genErr != nil {
			log.Printf("[vetting-chunk][%s] GenerateChunk: %v", t.providerID, genErr)
			return
		}

		// providers.first_chunk_assignment_at: closes a third gap in the
		// same VETTING→ACTIVE chain (heartbeat auth, this file's own
		// existence, and now this) — internal/scoring/passes.go's own
		// comment already documents this column as set by "the assignment
		// service" on a provider's first chunk assignment, but nothing
		// anywhere in this codebase ever wrote it before this loop existed.
		// Without it, IncrementConsecutivePasses's duration condition
		// (first_chunk_assignment_at + VettingMinDuration <= NOW()) could
		// never be satisfied no matter how many consecutive audit passes
		// accumulated — VETTING→ACTIVE would stay permanently blocked.
		// WHERE ... IS NULL makes this idempotent across every call after
		// the first for a given provider.
		if _, updErr := db.ExecContext(ctx,
			`UPDATE providers SET first_chunk_assignment_at = NOW() WHERE provider_id = $1 AND first_chunk_assignment_at IS NULL`,
			t.providerID); updErr != nil {
			log.Printf("[vetting-chunk][%s] set first_chunk_assignment_at: %v", t.providerID, updErr)
		}
	}
}

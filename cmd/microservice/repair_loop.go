// cmd/microservice — see main.go's package doc comment.
//
// This file implements the two background loops this session's steps 14 and
// 15 describe: the stale PRE_WARNING promotion ticker, and the repair
// executor loop. Neither has anywhere else in the build plan to live —
// repair/queue.go's own doc comment on PromoteStalePreWarningJobs says it is
// "intended to run on a periodic ticker from the microservice entrypoint
// (Milestone 12)," and nothing anywhere else in the codebase ever calls
// repair.DequeueNextJob at all.
//
// [REF: FR-042-FR-045, ADR-004, build.md Milestone 9 Phase 9.2 Session 9.2.1,
// Session 9.2.2, Milestone 12 Phase 12.1 Session 12.1.1]
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/repair"
)

// repairExecutorIdleBackoff is how long the executor loop sleeps after
// finding the queue empty (repair.DequeueNextJob's documented "nil, nil"
// empty-queue return), so it polls rather than busy-loops.
const repairExecutorIdleBackoff = 2 * time.Second

const sha256Size = 32

// runPromotionTicker implements this session's step 14: on
// profile.PollingInterval, promote stale QUEUED PRE_WARNING jobs to
// PERMANENT_DEPARTURE priority (FR-043). Blocks until ctx is cancelled.
//
// [Corrected — M12 audit corrections, Finding 5] Each tick now acquires a
// backgroundSemaphore slot before calling PromoteStalePreWarningJobs — see
// acquireBackgroundSlot's own doc comment (background_loops.go) for why
// this closes a real, previously-unwired gap in NFR-028's throttle.
func runPromotionTicker(ctx context.Context, db *sql.DB, profile config.NetworkProfile) {
	ticker := time.NewTicker(profile.PollingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			release, err := acquireBackgroundSlot(ctx)
			if err != nil {
				return // ctx cancelled while waiting for a throttle slot
			}
			promoted, err := repair.PromoteStalePreWarningJobs(ctx, db, profile)
			release()
			if err != nil {
				log.Printf("[REPAIR] PromoteStalePreWarningJobs: %v", err)
				continue
			}
			if promoted > 0 {
				log.Printf("[REPAIR] promoted %d stale PRE_WARNING job(s) to PERMANENT_DEPARTURE", promoted)
			}
		}
	}
}

// findSurvivingHolders queries chunk_assignments for every other ACTIVE,
// non-vetting shard holder of segmentID, excluding excludeProviderID (the
// departed/failed holder repair.ExecuteRepairJob is replacing). Returns the
// holder list (SurvivingHolder.PeerID set to the provider's UUID string —
// the same convention repair/executor.go's own upload-path code already
// uses for replacementPeerID, resolved to a real p2p identity by
// repairTransportAdapter) plus the provider IDs found, so the caller can
// fold them into ExecuteRepairJob's excludeProviderIDs (a replacement must
// not be a provider that already holds another shard of this segment).
func findSurvivingHolders(ctx context.Context, db *sql.DB, segmentID uuid.UUID, excludeProviderID *uuid.UUID) ([]repair.SurvivingHolder, []uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT provider_id, shard_index, chunk_id
		FROM chunk_assignments
		WHERE segment_id = $1 AND is_vetting_chunk = FALSE AND status = 'ACTIVE'`,
		segmentID,
	)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()

	var (
		holders []repair.SurvivingHolder
		ids     []uuid.UUID
	)
	for rows.Next() {
		var (
			providerID   uuid.UUID
			shardIndex   int
			chunkIDBytes []byte
		)
		if err := rows.Scan(&providerID, &shardIndex, &chunkIDBytes); err != nil {
			return nil, nil, err
		}
		if excludeProviderID != nil && providerID == *excludeProviderID {
			continue
		}
		// [Fixed — F-16-4] chunk_id must be fetched per-holder: each shard
		// within a segment is different bytes (RS systematic/parity
		// encoding), hence a different SHA-256 content address. The
		// original query never selected this column at all, so every
		// download request downstream used the lost shard's own chunk_id
		// (job.ChunkID) against every surviving holder — none of whom
		// ever stored that exact chunk_id — producing a deterministic
		// repairStatusNotFound (0x01) from every holder, every time. See
		// SurvivingHolder.ChunkID's doc comment (internal/repair/executor.go).
		if len(chunkIDBytes) != sha256Size {
			return nil, nil, fmt.Errorf("findSurvivingHolders: chunk_assignments.chunk_id has length %d, want %d (provider_id=%s, shard_index=%d)",
				len(chunkIDBytes), sha256Size, providerID, shardIndex)
		}
		var chunkID [32]byte
		copy(chunkID[:], chunkIDBytes)
		holders = append(holders, repair.SurvivingHolder{
			ProviderID: providerID,
			PeerID:     providerID.String(),
			ShardIndex: shardIndex,
			ChunkID:    chunkID,
		})
		ids = append(ids, providerID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return holders, ids, nil
}

// runRepairExecutorLoop implements this session's step 15: dequeue and run
// the repair pipeline for one job at a time. Blocks until ctx is cancelled.
// Nothing else in the build plan drives repair.DequeueNextJob.
//
// [Corrected — M12 audit corrections, Finding 5] Once a real job is
// dequeued, a backgroundSemaphore slot is acquired before the actual
// DB-heavy repair work (findSurvivingHolders, ExecuteRepairJob) — see
// acquireBackgroundSlot's own doc comment (background_loops.go). Acquired
// only after confirming a job exists, not around DequeueNextJob's own idle
// polling — holding a throttle slot while merely blocked in an empty-queue
// backoff would waste that slot on no real background work, defeating the
// throttle's own purpose.
func runRepairExecutorLoop(
	ctx context.Context,
	db *sql.DB,
	profile config.NetworkProfile,
	transport repair.RepairTransport,
	engine *erasure.Engine,
	signingKey ed25519.PrivateKey,
	microserviceHost p2p.Host,
) {
	microservicePeerID := microserviceHost.PeerID().String()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		job, err := repair.DequeueNextJob(ctx, db)
		if err != nil {
			log.Printf("[REPAIR] DequeueNextJob: %v", err)
			sleepOrDone(ctx, repairExecutorIdleBackoff)
			continue
		}
		if job == nil {
			// Empty queue (repair.DequeueNextJob's documented, non-error
			// "nil, nil" result) — poll rather than busy-loop.
			sleepOrDone(ctx, repairExecutorIdleBackoff)
			continue
		}

		release, err := acquireBackgroundSlot(ctx)
		if err != nil {
			return // ctx cancelled while waiting for a throttle slot
		}

		holders, holderIDs, err := findSurvivingHolders(ctx, db, job.SegmentID, job.ProviderID)
		if err != nil {
			log.Printf("[REPAIR] job %s: find surviving holders: %v", job.JobID, err)
			_ = repair.MarkJobComplete(ctx, db, job.JobID, false)
			release()
			continue
		}
		excludeProviderIDs := holderIDs
		if job.ProviderID != nil {
			excludeProviderIDs = append(excludeProviderIDs, *job.ProviderID)
		}

		err = repair.ExecuteRepairJob(ctx, db, profile, transport, engine, signingKey, microservicePeerID, job, holders, excludeProviderIDs)
		release()
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[REPAIR] job %s: %v", job.JobID, err)
		}
	}
}

// sleepOrDone waits for d or returns early if ctx is cancelled.
func sleepOrDone(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

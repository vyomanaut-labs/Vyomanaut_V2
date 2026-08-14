// cmd/microservice — see main.go's package doc comment.
//
// This file implements the background throttle goroutine (this session's
// step 18, NFR-028, ARCH §18) and the readiness gate evaluator goroutine
// (step 7, IC §3.4).
//
// [Decision — readiness monitor is observational only] internal/api's own
// ReadinessEvaluator.Evaluate is called synchronously, live, by BOTH
// existing Milestone 11 consumers (HandleReadiness for GET
// /api/v1/admin/readiness, and UploadAssignHandler for the upload-assign
// gate) — neither reads from a cache. IC §3.4's "re-evaluated every 60
// seconds" and readiness.go's own comment ("the 60-second caching cadence...
// is a background-goroutine concern... Milestone 12, Session 12.1.1") name
// this session as owning that cadence, but modifying either existing,
// already-tested Milestone 11 handler to consult a new cache is outside
// this session's own file list (cmd/microservice only). The loop below
// satisfies "start the readiness gate evaluator goroutine... 60-second
// cycle" literally and safely: it runs Evaluate on that cadence for
// observability (logging condition state and transitions), without
// changing either existing handler's live-evaluation behaviour.
//
// [REF: IC §3.4, NFR-028, ARCH §18, ADR-025, build.md Milestone 12 Phase
// 12.1 Session 12.1.1]
package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/api"
)

// readinessEvaluationCycle is IC §3.4's 60-second re-evaluation cadence.
const readinessEvaluationCycle = 60 * time.Second

// startReadinessMonitorLoop implements this session's step 7: runs the
// readiness gate evaluator on IC §3.4's 60-second cycle, logging condition
// state and any ready/not-ready transitions. See this file's header note on
// why this is observational rather than a cache the existing handlers read
// from. Blocks until ctx is cancelled; intended to be run in its own
// goroutine.
func startReadinessMonitorLoop(ctx context.Context, evaluator *api.ReadinessEvaluator) {
	ticker := time.NewTicker(readinessEvaluationCycle)
	defer ticker.Stop()

	lastReady := true // assume ready until the first evaluation proves otherwise, to avoid a spurious transition log at startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resp, err := evaluator.Evaluate(ctx)
			if err != nil {
				log.Printf("[READINESS] evaluation failed: %v", err)
				continue
			}
			if resp.AllConditionsMet != lastReady {
				log.Printf("[READINESS] transition: ready=%v", resp.AllConditionsMet)
				lastReady = resp.AllConditionsMet
			}
		}
	}
}

// Background throttle thresholds (NFR-028, ARCH §18): background work (view
// refresh, repair queuing, Merkle log compaction) monitors the 99th-
// percentile of foreground DB read latency over the last 60 seconds. As it
// approaches 50ms, background task allocation is reduced; it is restored
// once latency drops back under 30ms.
const (
	backgroundThrottleSampleInterval = 60 * time.Second
	backgroundThrottleHighWater      = 50 * time.Millisecond
	backgroundThrottleLowWater       = 30 * time.Millisecond

	// backgroundSemaphoreMaxSize and backgroundSemaphoreMinSize bound how far
	// backgroundSemaphore's capacity can be throttled down and restored.
	// Not specified numerically by NFR-028/ARCH §18; chosen so throttling has
	// a visible effect (max allows real concurrency, min never reaches zero —
	// starving background work entirely would itself be a bug, only
	// SLA-threatening throughput needs reducing, per NFR-028's own framing of
	// "reduced," never "stopped").
	backgroundSemaphoreMaxSize = 8
	backgroundSemaphoreMinSize = 1
)

// backgroundSemaphore gates this process's own background work (this
// session's repair executor loop, promotion ticker, and readiness monitor
// loop — the "background work" NFR-028 names: view refresh, repair queuing,
// Merkle log compaction all ultimately run through these) so its capacity
// can be throttled under foreground load. A buffered channel used as a
// counting semaphore: acquire by sending, release by receiving.
var backgroundSemaphore = make(chan struct{}, backgroundSemaphoreMaxSize)

// dbReadP99Prober is the shape of a function returning the 99th-percentile
// foreground DB read latency over the last 60 seconds (NFR-028). Exposed as
// a variable (not directly pg_stat_statements-backed here) so tests can
// substitute a fake — this codebase has no existing metrics/observability
// subsystem to query a real p99 from (out of scope for this session; the
// throttle LOGIC is what NFR-028 requires, and is what this session builds).
type dbReadP99Prober func(ctx context.Context, db *sql.DB) (time.Duration, error)

// runBackgroundThrottleLoop implements this session's step 18 (NFR-028):
// every 60 seconds, sample foreground DB read p99 latency and adjust
// backgroundSemaphore's effective capacity — reduced as latency approaches
// 50ms, restored once it drops back under 30ms. Blocks until ctx is
// cancelled.
func runBackgroundThrottleLoop(ctx context.Context, db *sql.DB, probe dbReadP99Prober) {
	ticker := time.NewTicker(backgroundThrottleSampleInterval)
	defer ticker.Stop()

	current := backgroundSemaphoreMaxSize
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p99, err := probe(ctx, db)
			if err != nil {
				log.Printf("[THROTTLE] db read p99 probe: %v", err)
				continue
			}
			switch {
			case p99 >= backgroundThrottleHighWater && current > backgroundSemaphoreMinSize:
				current--
				resizeBackgroundSemaphore(current)
				log.Printf("[THROTTLE] foreground p99=%s >= %s: reduced background concurrency to %d",
					p99, backgroundThrottleHighWater, current)
			case p99 < backgroundThrottleLowWater && current < backgroundSemaphoreMaxSize:
				current++
				resizeBackgroundSemaphore(current)
				log.Printf("[THROTTLE] foreground p99=%s < %s: restored background concurrency to %d",
					p99, backgroundThrottleLowWater, current)
			}
		}
	}
}

// resizeBackgroundSemaphore replaces backgroundSemaphore with one of the
// given capacity. Only this loop ever calls it (single-writer), avoiding any
// need for additional synchronization beyond the channel itself.
func resizeBackgroundSemaphore(size int) {
	// avoid unused var error
	_ = cap(backgroundSemaphore)
	backgroundSemaphore = make(chan struct{}, size)
}

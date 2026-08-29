// cmd/microservice — see main.go's package doc comment.
//
// This file implements the background throttle goroutine (this session's
// step 18, NFR-028, ARCH §18) and the readiness gate evaluator goroutine
// (step 7, IC §3.4).
//
// [Corrected — M12 audit corrections, Finding 3] This file's readiness
// monitor loop was ORIGINALLY observational only — internal/api's own
// ReadinessEvaluator.Evaluate was called synchronously, live, by BOTH
// existing Milestone 11 consumers (HandleReadiness for GET
// /api/v1/admin/readiness, and UploadAssignHandler for the upload-assign
// gate), neither reading from any cache; this loop just ran Evaluate for
// logging, on the same 60-second cadence, without those two handlers ever
// consuming its result. That split was a deliberate scope decision at the
// time (modifying either existing, already-tested Milestone 11 handler was
// outside this session's own file list, cmd/microservice only) — but the
// audit's own Recheck pass treated it as a real finding rather than an
// accepted scope boundary, since it leaves the busiest write path in the
// system doing 5+ extra DB queries, a gossip-membership call, and a
// secrets-cache check on every single request. Given IC §3.4's explicit
// "MUST NOT cache... re-query each 60-second cycle" language for the
// razorpay sub-condition ONLY makes sense if a 60-second-cadence cached
// evaluation is the intended architecture for everything else, this
// session's corrections now close that gap directly: startReadinessMonitorLoop
// calls ReadinessEvaluator.RefreshCache (internal/api/readiness.go), and
// both existing handlers now read ReadinessEvaluator.Cached() instead of
// calling Evaluate live — see those two files' own updated header notes.
//
// [REF: IC §3.4, NFR-028, ARCH §18, ADR-025, ADR-029, build.md Milestone 12
// Phase 12.1 Session 12.1.1, Milestone 12 audit corrections Finding 3,
// Finding 5]
package main

import (
	"context"
	"database/sql"
	"log"
	"sync/atomic"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/api"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// readinessEvaluationCycle is IC §3.4's 60-second re-evaluation cadence.
const readinessEvaluationCycle = 60 * time.Second

// startReadinessMonitorLoop implements this session's step 15/Session
// 12.1.1 background half of IC §3.4's 60-second readiness cache.
//
// [Corrected — M12 audit corrections, Finding 3] Previously called
// evaluator.Evaluate(ctx) purely for transition logging — nothing ever
// consumed its result, so the actual gate (internal/api/upload.go's
// UploadAssignHandler and the admin GET /readiness handler) evaluated live
// on every request instead of reading a cache this loop was supposed to be
// maintaining. Now calls evaluator.RefreshCache(ctx), which does everything
// Evaluate did AND atomically publishes the result for those two consumers
// to read via ReadinessEvaluator.Cached() — see that method's own doc
// comment.
//
// Runs one refresh immediately, before entering the ticker loop, rather
// than waiting up to readinessEvaluationCycle for the first tick — this
// shrinks Cached()'s cold-start "not yet populated" window (during which
// callers fall back to a live per-request Evaluate) down to roughly "however
// long one Evaluate call takes," not up to a full cycle.
//
// [Corrected — M12 audit corrections, Finding 5] Each refresh now acquires
// a backgroundSemaphore slot first (NFR-028) — this loop's own DB work is
// exactly the kind of background load NFR-028 says should be throttled
// under foreground pressure, and previously wasn't (see
// acquireBackgroundSlot's own doc comment for why a plain channel-capacity
// check isn't sufficient once multiple goroutines share it).
func startReadinessMonitorLoop(ctx context.Context, evaluator *api.ReadinessEvaluator) {
	ticker := time.NewTicker(readinessEvaluationCycle)
	defer ticker.Stop()

	lastReady := true // assume ready until the first evaluation proves otherwise, to avoid a spurious transition log at startup

	refresh := func() {
		release, err := acquireBackgroundSlot(ctx)
		if err != nil {
			return // ctx cancelled while waiting for a throttle slot
		}
		defer release()

		resp, err := evaluator.RefreshCache(ctx)
		if err != nil {
			log.Printf("[READINESS] evaluation failed: %v", err)
			return
		}
		if resp.AllConditionsMet != lastReady {
			log.Printf("[READINESS] transition: ready=%v", resp.AllConditionsMet)
			lastReady = resp.AllConditionsMet
		}
	}

	refresh() // prime the cache immediately — see this function's own doc comment
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
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
//
// [Corrected — M12 audit corrections, Finding 5] Previously a plain
// package-level `chan struct{}` that resizeBackgroundSemaphore reassigned
// directly (`backgroundSemaphore = make(...)`) with a comment claiming this
// needed "no additional synchronization beyond the channel itself" — true
// only as long as nothing ever concurrently READ that variable while the
// throttle loop's single goroutine WROTE it, which was the actual situation
// before this fix: the audit's own finding was that nothing anywhere ever
// acquired a token from backgroundSemaphore at all. The moment real
// acquisition is wired in below (three consumer loops, each its own
// goroutine, reading this package var concurrently with the throttle loop's
// resizes), a plain unsynchronized variable read/write race becomes real —
// exactly the kind `go test -race` is a hard CI gate to catch. Stored
// behind atomic.Pointer instead: Store (throttle loop, single writer) and
// Load (every acquirer, many readers) are both atomic pointer operations,
// so a resize is always fully visible-or-not to any concurrent acquirer,
// never a torn read.
var backgroundSemaphore atomic.Pointer[chan struct{}]

func init() {
	ch := make(chan struct{}, backgroundSemaphoreMaxSize)
	backgroundSemaphore.Store(&ch)
}

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

// resizeBackgroundSemaphore replaces backgroundSemaphore's underlying
// channel with one of the given capacity. Only this loop ever calls it
// (single-writer) — but see backgroundSemaphore's own doc comment for why
// that alone no longer means "no synchronization needed" now that
// acquireBackgroundSlot gives it concurrent readers too.
func resizeBackgroundSemaphore(size int) {
	ch := make(chan struct{}, size)
	backgroundSemaphore.Store(&ch)
}

// acquireBackgroundSlot blocks until a background-work slot is available
// under runBackgroundThrottleLoop's current NFR-028 concurrency limit, or
// ctx is cancelled first. Every caller MUST defer the returned release
// func on success.
//
// [Added — M12 audit corrections, Finding 5] Reads backgroundSemaphore
// fresh via Load() on every call, rather than a caller capturing the
// channel once at its own loop's start — a resize takes effect on this
// caller's very NEXT acquisition either way, not just for callers/
// goroutines started after the resize. Wired into all three of this
// package's background-work loops: startReadinessMonitorLoop above, and
// runPromotionTicker / runRepairExecutorLoop in repair_loop.go — closing
// the gap the audit found (backgroundSemaphore correctly computed and
// resized, but nothing anywhere ever acquired from it).
func acquireBackgroundSlot(ctx context.Context) (release func(), err error) {
	sem := *backgroundSemaphore.Load()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// backgroundRefreshedViews are the materialized views this loop keeps
// current. Order is deliberate but not load-bearing: none of the views
// reads from another, so a partial failure partway through (logged, not
// fatal — see runBackgroundViewRefreshLoop) only leaves whichever views
// weren't reached yet stale until the next tick, same as if the whole tick
// were skipped.
//
// [Fixed — live-run finding, M17-E Session 17.8.2's own TestReqD10] added
// "mv_provider_scores": that view is DROPPED and CREATEd exactly once, at
// microservice startup (scores_view.go's regenerateProviderScoresView),
// before any provider has registered or been audited — it was never
// wired into this loop or any other periodic refresh, so it was
// permanently frozen at zero rows for the entire life of every
// microservice process. Every caller of scoring.GetScore/
// GetScoreFromPrimary (internal/payment.PreviewMonthlyRelease/
// ComputeMonthlyRelease, internal/repair.SelectReplacementProvider) was
// silently reading a snapshot from before any audit history existed.
// PreviewMonthlyRelease surfaced this loudly (a hard 500 the first time
// `operator payout` was ever actually exercised against a live run — see
// that endpoint's own errors.Join behavior, which turns any one
// candidate's missing-score error into a total failure for the whole
// batch); SelectReplacementProvider evidently tolerates a missing score
// more gracefully, which is presumably why this went unnoticed through
// every prior repair-pipeline test. mv_provider_scores already carries
// the unique index REFRESH MATERIALIZED VIEW CONCURRENTLY needs
// (providerScoresViewTemplate's own final CREATE UNIQUE INDEX statement,
// scores_view.go), so it drops into this exact mechanism with no further
// schema change. Flagged for its own review rather than folded silently
// into a test-only fix: this is a genuine, previously-undiscovered
// production gap in scoring/payment/repair, not a Session 17.8.2 test bug,
// and may warrant its own ADR and a design decision on whether it belongs
// in this shared, 5-second-interval loop at all versus a
// scoring-specific refresh cadence tied to ScoreWindowShort.
var backgroundRefreshedViews = [...]string{
	"mv_owner_escrow_balance",
	"mv_provider_escrow_balance",
	"mv_segment_shard_counts",
	"mv_provider_scores",
}

// runBackgroundViewRefreshLoop implements the "view refresh" background
// task NFR-028 and this file's own header comment name but which no session
// ever assigned a file to build (see NetworkProfile.BackgroundViewRefreshInterval's
// doc comment for the full trail). Every
// profile.BackgroundViewRefreshInterval, REFRESH MATERIALIZED VIEW
// CONCURRENTLY runs against each view in backgroundRefreshedViews in turn —
// CONCURRENTLY so foreground readers (owner balance checks, provider balance
// checks, the owner file-list endpoint) are never blocked behind it, which
// every view's own unique index (DM §7) exists to support. A failed refresh
// is logged and this tick moves on to the next view rather than aborting —
// matching runBackgroundThrottleLoop's own probe-failure handling
// immediately above — since a transient failure on one view has no bearing
// on whether the others can still be refreshed, and the next tick will
// retry the one that failed anyway. Blocks until ctx is cancelled.
//
// db MUST be a vyomanaut_migrator connection, never the request-path
// vyomanaut_app pool — REFRESH MATERIALIZED VIEW requires owning the view
// object; vyomanaut_app's GRANT SELECT does not confer this (ADR-032), the
// same reason regenerateProviderScoresView (scores_view.go) already uses a
// migrator connection instead of the app pool for its own DROP/CREATE.
// main.go passes a.viewRefreshDB, never a.db.
//
// [Added, M17 CLI debugging session, second pass] Every other line in this
// file logs only on state transitions or failures (readiness, throttle) —
// correct for those, but it means a live run's log can't distinguish
// "this loop never started" from "this loop is ticking and succeeding"
// from "this loop is ticking and failing every time": all three look like
// silence. A first live run after this loop's own introduction still
// failed TestDemoCLIFullLifecycle's balance assertion with unchanged
// symptoms, and a faithful local repro of the exact schema/role/statement
// (same CREATE MATERIALIZED VIEW, same GRANT structure, same
// vyomanaut_migrator-vs-vyomanaut_app split) proved the underlying
// REFRESH MATERIALIZED VIEW CONCURRENTLY mechanism itself works correctly
// end-to-end — so the remaining unknown is specifically whether THIS
// goroutine, in the real process, ever runs or ever succeeds. Logging
// unconditionally (start + every tick's outcome) trades a few hundred
// extra log lines over a 490s demo run for a log that can actually answer
// that question on the next run, rather than adding another layer of
// silent-either-way code on top of the existing silent-either-way pattern.
func runBackgroundViewRefreshLoop(ctx context.Context, db *sql.DB, profile config.NetworkProfile) {
	log.Printf("[VIEW-REFRESH] loop started: interval=%s views=%v",
		profile.BackgroundViewRefreshInterval, backgroundRefreshedViews)

	ticker := time.NewTicker(profile.BackgroundViewRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[VIEW-REFRESH] loop stopping: %v", ctx.Err())
			return
		case <-ticker.C:
			start := time.Now()
			succeeded, failed := 0, 0
			for _, view := range backgroundRefreshedViews {
				stmt := "REFRESH MATERIALIZED VIEW CONCURRENTLY " + view
				if _, err := db.ExecContext(ctx, stmt); err != nil {
					failed++
					log.Printf("[VIEW-REFRESH] refresh %s failed: %v", view, err)
				} else {
					succeeded++
				}
			}
			log.Printf("[VIEW-REFRESH] tick: %d/%d views refreshed (%d failed) in %s",
				succeeded, len(backgroundRefreshedViews), failed, time.Since(start))
		}
	}
}

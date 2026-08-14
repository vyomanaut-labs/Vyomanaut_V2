// Package repair is declared in doc.go.
// This file implements the repair job queue lifecycle: Priority/TriggerType
// enums, EnqueueJob, DequeueNextJob, IsVettingChunk,
// DeleteVettingChunksOnDeparture, MarkJobComplete, RepairPromotionTimeout,
// and PromoteStalePreWarningJobs.
//
// [REF: IC §5.7, DM §4.10, DM §3 Invariant 6, ADR-004, ADR-030, FR-042–FR-045,
// FR-065–FR-067, build.md Phase 9.1 Session 9.1.1]

package repair

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/metrics"
)

// Priority mirrors the repair_priority DB enum (DM §4.10) — all three values,
// ordered to match the ENUM's declaration order in PostgreSQL (see
// DequeueNextJob for why declaration order, not alphabetical order, is what
// matters).
//
// [Flagged and fixed, build.md Phase 9.1] IC §5.7 as originally written
// declared only two values (PriorityPermanentDeparture, PriorityPreWarning),
// which left no way to represent the EMERGENCY tier DM §4.10's own enum and
// ADR-004's emergency-floor rule both require. PriorityEmergency is added
// below as the first (lowest-ordinal, drains-first) value.
type Priority int

const (
	PriorityEmergency          Priority = iota // EMERGENCY — s at reconstruction floor; front of queue
	PriorityPermanentDeparture                 // SILENT_DEPARTURE / ANNOUNCED_DEPARTURE — drains next
	PriorityPreWarning                         // THRESHOLD_WARNING — waits behind the above
)

// TriggerType mirrors the repair_trigger_type DB enum (DM §4.10).
type TriggerType int

const (
	TriggerSilentDeparture TriggerType = iota
	TriggerAnnouncedDeparture
	TriggerThresholdWarning
	TriggerEmergencyFloor
)

// RepairJob is the in-memory representation of a dequeued job (IC §5.7).
type RepairJob struct {
	JobID               uuid.UUID
	ChunkID             [32]byte
	SegmentID           uuid.UUID
	ProviderID          *uuid.UUID // nil for THRESHOLD_WARNING and EMERGENCY_FLOOR
	TriggerType         TriggerType
	Priority            Priority
	AvailableShardCount int
}

// priorityForTrigger derives the DM §4.10 repair_jobs_priority_matches_trigger
// mapping in Go, so EnqueueJob and the database CHECK constraint can never
// drift apart:
//
//	TriggerEmergencyFloor                             -> PriorityEmergency
//	TriggerSilentDeparture, TriggerAnnouncedDeparture -> PriorityPermanentDeparture
//	TriggerThresholdWarning                           -> PriorityPreWarning
func priorityForTrigger(t TriggerType) Priority {
	switch t {
	case TriggerEmergencyFloor:
		return PriorityEmergency
	case TriggerSilentDeparture, TriggerAnnouncedDeparture:
		return PriorityPermanentDeparture
	case TriggerThresholdWarning:
		return PriorityPreWarning
	default:
		panic(fmt.Sprintf("repair: priorityForTrigger: invalid TriggerType %d", int(t)))
	}
}

// dbValue returns the repair_priority ENUM label for p.
func (p Priority) dbValue() string {
	switch p {
	case PriorityEmergency:
		return "EMERGENCY"
	case PriorityPermanentDeparture:
		return "PERMANENT_DEPARTURE"
	case PriorityPreWarning:
		return "PRE_WARNING"
	default:
		panic(fmt.Sprintf("repair: Priority.dbValue: invalid Priority %d", int(p)))
	}
}

// priorityFromDB parses a repair_priority ENUM label read back from the
// database. Panics on an unrecognised label — that would mean the schema and
// this package's enum have already drifted apart, a programming error, not a
// recoverable runtime condition.
func priorityFromDB(s string) Priority {
	switch s {
	case "EMERGENCY":
		return PriorityEmergency
	case "PERMANENT_DEPARTURE":
		return PriorityPermanentDeparture
	case "PRE_WARNING":
		return PriorityPreWarning
	default:
		panic(fmt.Sprintf("repair: priorityFromDB: unrecognised repair_priority value %q", s))
	}
}

// dbValue returns the repair_trigger_type ENUM label for t.
func (t TriggerType) dbValue() string {
	switch t {
	case TriggerSilentDeparture:
		return "SILENT_DEPARTURE"
	case TriggerAnnouncedDeparture:
		return "ANNOUNCED_DEPARTURE"
	case TriggerThresholdWarning:
		return "THRESHOLD_WARNING"
	case TriggerEmergencyFloor:
		return "EMERGENCY_FLOOR"
	default:
		panic(fmt.Sprintf("repair: TriggerType.dbValue: invalid TriggerType %d", int(t)))
	}
}

// triggerTypeFromDB parses a repair_trigger_type ENUM label read back from
// the database. Panics on an unrecognised label (see priorityFromDB).
func triggerTypeFromDB(s string) TriggerType {
	switch s {
	case "SILENT_DEPARTURE":
		return TriggerSilentDeparture
	case "ANNOUNCED_DEPARTURE":
		return TriggerAnnouncedDeparture
	case "THRESHOLD_WARNING":
		return TriggerThresholdWarning
	case "EMERGENCY_FLOOR":
		return TriggerEmergencyFloor
	default:
		panic(fmt.Sprintf("repair: triggerTypeFromDB: unrecognised repair_trigger_type value %q", s))
	}
}

// refreshRepairQueueDepthGauge re-derives the current count of QUEUED
// repair_jobs and publishes it to metrics.RepairQueueDepth (NFR-025,
// ARCH §23 — the NFR-027 alert fires when this exceeds 1,000). Called after
// every successful EnqueueJob and DequeueNextJob so the exported gauge
// never needs a separate polling loop to stay current.
//
// [Decision — OBS.1.2] A failed depth query is deliberately swallowed
// rather than surfaced: this is a best-effort observability refresh, not
// part of either caller's correctness contract. EnqueueJob and
// DequeueNextJob have already committed their own transaction by the time
// this runs, so failing the caller over a COUNT(*) that couldn't complete
// would turn a successful repair-queue operation into a reported failure.
// The gauge simply keeps its last published value until the next
// successful call — the same "no signal is not an error" posture
// Phase 12.1's computeRTO fallback and background_loops.go's
// dbReadP99Prober both already take.
func refreshRepairQueueDepthGauge(ctx context.Context, db *sql.DB) {
	const countQueued = `SELECT COUNT(*) FROM repair_jobs WHERE status = 'QUEUED'`
	var depth int
	if err := db.QueryRowContext(ctx, countQueued).Scan(&depth); err != nil {
		return
	}
	metrics.RepairQueueDepth.Set(float64(depth))
}

// EnqueueJob inserts a repair job into repair_jobs. Priority is derived
// automatically and completely from triggerType (DM §4.10
// repair_jobs_priority_matches_trigger CHECK) via priorityForTrigger.
//
// Pre-conditions:
//   - len(chunkID) == 32; segmentID is a valid UUID
//   - availableShardCount is in [profile.DataShards, profile.TotalShards]
//     (16-56 in production, 3-5 in demo — DM §4.10; NEVER hardcode [16,56])
//   - the chunk_assignments row for (chunkID, any active provider) has
//     is_vetting_chunk = FALSE. Calling EnqueueJob for a synthetic vetting
//     chunk is a calling-contract violation: PANICS in debug builds
//     (`go build -tags debug`) as a second line of defence (the departure
//     handler, Session 9.3.1, must call IsVettingChunk() first — this panic
//     only catches a caller that skipped that check; it does not run in
//     ordinary release builds — see debug_on.go / debug_off.go).
//     (ADR-030, DM §3 Invariant 6)
//
// Post-conditions (on nil error):
//   - a row with status='QUEUED' is inserted into repair_jobs with the
//     derived priority
//
// Error semantics: ErrShardCountOutOfRange if the pre-condition on
// availableShardCount fails; other database errors returned as-is.
// Goroutine-safe: yes.
//
// [Flagged and fixed, build.md Phase 9.1] IC §5.7's declared signature has no
// profile parameter, yet its own pre-condition ("availableShardCount is in
// [16, 56]") is a fixed range that is actually profile-variable (3-5 in
// demo). Adding profile config.NetworkProfile matches the calling convention
// already used by RepairPromotionTimeout(profile) later in this file.
func EnqueueJob(
	ctx context.Context,
	db *sql.DB,
	profile config.NetworkProfile,
	chunkID [32]byte,
	segmentID uuid.UUID,
	providerID *uuid.UUID,
	triggerType TriggerType,
	availableShardCount int,
) error {
	if availableShardCount < profile.DataShards || availableShardCount > profile.TotalShards {
		return ErrShardCountOutOfRange
	}

	// Second line of defence (debug builds only): a caller that skipped its
	// own IsVettingChunk() pre-check would otherwise silently enqueue a
	// repair job for a chunk that requires none (ADR-030, DM §3 Invariant 6,
	// FR-067). This is defensive, not authoritative — the departure handler's
	// own IsVettingChunk() call (Session 9.1.3) is the real gate.
	if buildDebug {
		var isVetting bool
		err := db.QueryRowContext(ctx,
			`SELECT is_vetting_chunk FROM chunk_assignments WHERE chunk_id = $1 LIMIT 1`,
			chunkID[:],
		).Scan(&isVetting)
		if err == nil && isVetting {
			panic("repair.EnqueueJob: called for a chunk with is_vetting_chunk = TRUE — " +
				"caller must call IsVettingChunk() first and skip EnqueueJob entirely (ADR-030, DM §3 Invariant 6)")
		}
		// sql.ErrNoRows or any other error: no evidence available either way;
		// this is only a second line of defence, so proceed rather than fail
		// a legitimate repair job on an unrelated query problem.
	}

	priority := priorityForTrigger(triggerType)

	const insert = `
INSERT INTO repair_jobs (chunk_id, segment_id, provider_id, trigger_type, priority, available_shard_count)
VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := db.ExecContext(ctx, insert,
		chunkID[:], segmentID, providerID, triggerType.dbValue(), priority.dbValue(), availableShardCount,
	)
	if err != nil {
		return fmt.Errorf("repair.EnqueueJob: insert: %w", err)
	}
	refreshRepairQueueDepthGauge(ctx, db)
	return nil
}

// DequeueNextJob atomically retrieves and marks IN_PROGRESS the highest-priority
// QUEUED repair job, using SELECT ... FOR UPDATE SKIP LOCKED so concurrent
// workers never contend for the same row (IC §5.7).
//
// Ordering: ORDER BY priority ASC, created_at ASC — EMERGENCY drains first,
// then PERMANENT_DEPARTURE, then PRE_WARNING; FIFO within each tier (ADR-004,
// DM §4.10).
//
// This ordering works because PostgreSQL ENUM comparison operators sort by
// the enum's DECLARATION order (the order values were listed in `CREATE TYPE
// ... AS ENUM (...)`), not lexicographically. DM §4.10's own comment
// describes this as "EMERGENCY < PERMANENT_DEPARTURE < PRE_WARNING
// alphabetically" — that phrasing is misleading: it is only a coincidence
// that the declaration order chosen here also happens to be alphabetical. If
// a fourth priority value were ever added via `ALTER TYPE ... ADD VALUE`
// without care for its position, alphabetical order and declaration order
// would diverge, and this comment would break silently. What actually
// guarantees `ORDER BY priority ASC` drains EMERGENCY first is that
// 'EMERGENCY' was declared before 'PERMANENT_DEPARTURE' before 'PRE_WARNING'
// in the CREATE TYPE statement (Session 4.2.1) — not the spelling.
//
// Returns nil, nil if the queue is empty (not an error condition).
// Goroutine-safe: yes.
func DequeueNextJob(ctx context.Context, db *sql.DB) (*RepairJob, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repair.DequeueNextJob: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	const selectNext = `
SELECT job_id, chunk_id, segment_id, provider_id, trigger_type, priority, available_shard_count
FROM repair_jobs
WHERE status = 'QUEUED'
ORDER BY priority ASC, created_at ASC
LIMIT 1
FOR UPDATE SKIP LOCKED`

	var (
		jobID               uuid.UUID
		chunkIDBytes        []byte
		segmentID           uuid.UUID
		providerID          *uuid.UUID
		triggerTypeStr      string
		priorityStr         string
		availableShardCount int
	)
	err = tx.QueryRowContext(ctx, selectNext).Scan(
		&jobID, &chunkIDBytes, &segmentID, &providerID, &triggerTypeStr, &priorityStr, &availableShardCount,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repair.DequeueNextJob: select: %w", err)
	}

	const markInProgress = `
UPDATE repair_jobs
SET status = 'IN_PROGRESS', started_at = NOW()
WHERE job_id = $1`
	if _, err := tx.ExecContext(ctx, markInProgress, jobID); err != nil {
		return nil, fmt.Errorf("repair.DequeueNextJob: mark in-progress: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("repair.DequeueNextJob: commit: %w", err)
	}
	refreshRepairQueueDepthGauge(ctx, db)

	var chunkID [32]byte
	copy(chunkID[:], chunkIDBytes)

	return &RepairJob{
		JobID:               jobID,
		ChunkID:             chunkID,
		SegmentID:           segmentID,
		ProviderID:          providerID,
		TriggerType:         triggerTypeFromDB(triggerTypeStr),
		Priority:            priorityFromDB(priorityStr),
		AvailableShardCount: availableShardCount,
	}, nil
}

// IsVettingChunk returns true iff the chunk_assignments row for
// (chunkID, providerID) has is_vetting_chunk = TRUE. Must be called by the
// departure handler (Session 9.3.1) and by any threshold monitor BEFORE
// calling EnqueueJob for that chunk (ADR-030, FR-066).
//
// If no chunk_assignments row exists for (chunkID, providerID) at all,
// returns (false, nil) rather than an error — there is no evidence the chunk
// is a vetting chunk, which is the correct default for a pre-condition check
// that gates a repair-job enqueue (absence of proof is not proof of
// vetting-ness, but the caller's own EnqueueJob debug-build panic is a
// second, independent line of defence if this reasoning is ever wrong).
//
// Goroutine-safe: yes.
func IsVettingChunk(ctx context.Context, db *sql.DB, chunkID [32]byte, providerID uuid.UUID) (bool, error) {
	var isVetting bool
	err := db.QueryRowContext(ctx,
		`SELECT is_vetting_chunk FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], providerID,
	).Scan(&isVetting)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("repair.IsVettingChunk: %w", err)
	}
	return isVetting, nil
}

// DeleteVettingChunksOnDeparture soft-deletes all synthetic chunk_assignments
// for a departing vetting provider (status='DELETED', deleted_at=NOW()).
// Enqueues zero repair_jobs (FR-065, DM §3 Invariant 6).
//
// Pre-conditions:
//   - providerID identifies a provider transitioning to status='DEPARTED'
//   - all of that provider's chunk_assignments have is_vetting_chunk = TRUE
//     (the departure handler must have already verified this — a VETTING
//     provider that somehow holds a real shard is itself a bug elsewhere)
//
// Goroutine-safe: yes.
func DeleteVettingChunksOnDeparture(ctx context.Context, db *sql.DB, providerID uuid.UUID) error {
	const query = `
UPDATE chunk_assignments
SET status = 'DELETED', deleted_at = NOW()
WHERE provider_id = $1 AND is_vetting_chunk = TRUE`
	if _, err := db.ExecContext(ctx, query, providerID); err != nil {
		return fmt.Errorf("repair.DeleteVettingChunksOnDeparture: %w", err)
	}
	return nil
}

// MarkJobComplete sets a repair job's status to COMPLETED or FAILED, and
// stamps completed_at = NOW() (DM §4.10 repair_jobs_completed_after_started
// CHECK: completed_at requires started_at to already be set). Called by the
// repair executor (Session 9.2.1) after the replacement upload succeeds
// (success=true) or exhausts retries (success=false).
//
// Error semantics: if jobID's started_at is still NULL (the job was never
// dequeued via DequeueNextJob), the repair_jobs_completed_after_started CHECK
// constraint itself rejects the UPDATE; that database error is wrapped and
// returned as-is rather than pre-checked and translated to a sentinel — the
// constraint is the single source of truth for this rule, and duplicating it
// in application code would risk the two drifting apart (the same reasoning
// DM §4.10 gives for deriving priority from trigger_type in Go rather than
// hand-maintaining both independently).
//
// Goroutine-safe: yes.
func MarkJobComplete(ctx context.Context, db *sql.DB, jobID uuid.UUID, success bool) error {
	status := "COMPLETED"
	if !success {
		status = "FAILED"
	}
	const query = `
UPDATE repair_jobs
SET status = $1, completed_at = NOW()
WHERE job_id = $2`
	if _, err := db.ExecContext(ctx, query, status, jobID); err != nil {
		return fmt.Errorf("repair.MarkJobComplete: %w", err)
	}
	return nil
}

// RepairPromotionTimeout returns the duration after which a QUEUED PRE_WARNING
// job is promoted to PERMANENT_DEPARTURE priority (ADR-031, FR-043).
// 6 hours in production, 3 minutes in demo — the scheduler must call this
// rather than reading a constant.
func RepairPromotionTimeout(profile config.NetworkProfile) time.Duration {
	return profile.RepairPromotionTimeout
}

// PromoteStalePreWarningJobs finds every QUEUED PRE_WARNING job whose
// created_at is older than RepairPromotionTimeout(profile) and updates its
// priority to PERMANENT_DEPARTURE (FR-043). Intended to run on a periodic
// ticker from the microservice entrypoint (Milestone 12), independent of
// DequeueNextJob's own invocation cadence.
//
// [Fixed, build.md Phase 9.2 Session 9.2.2 — documented per the user's
// instruction to build past the milestone text and note the decision in
// code.] The repair_jobs_priority_matches_trigger CHECK constraint
// (migrations/generator.go) originally paired trigger_type='THRESHOLD_WARNING'
// with priority='PRE_WARNING' as the ONLY legal combination — which made this
// exact promotion (an UPDATE that sets priority='PERMANENT_DEPARTURE' while
// trigger_type stays 'THRESHOLD_WARNING') impossible to perform without
// violating the constraint FR-043 itself requires satisfying. Fixed the
// constraint to allow trigger_type='THRESHOLD_WARNING' with EITHER
// priority — 'PRE_WARNING' at creation or 'PERMANENT_DEPARTURE' once
// promoted — leaving EMERGENCY_FLOOR and SILENT/ANNOUNCED_DEPARTURE's
// single-value pairings untouched, since only threshold-triggered jobs are
// ever promoted.
//
//	UPDATE repair_jobs
//	SET priority = 'PERMANENT_DEPARTURE'
//	WHERE priority = 'PRE_WARNING'
//	  AND status = 'QUEUED'
//	  AND created_at < NOW() - $1  -- RepairPromotionTimeout(profile)
//
// Returns the number of rows promoted, for observability.
func PromoteStalePreWarningJobs(ctx context.Context, db *sql.DB, profile config.NetworkProfile) (int, error) {
	const query = `
UPDATE repair_jobs
SET priority = 'PERMANENT_DEPARTURE'
WHERE priority = 'PRE_WARNING'
  AND status = 'QUEUED'
  AND created_at < NOW() - $1::interval`

	// Postgres interval literals don't accept a Go time.Duration directly;
	// pq encodes it as a string like "3m0s", which is not valid interval
	// syntax. Format explicitly as seconds, which Postgres's interval input
	// parser always accepts regardless of profile-variable magnitude (a few
	// minutes in demo, several hours in production).
	intervalArg := fmt.Sprintf("%f seconds", RepairPromotionTimeout(profile).Seconds())

	result, err := db.ExecContext(ctx, query, intervalArg)
	if err != nil {
		return 0, fmt.Errorf("repair.PromoteStalePreWarningJobs: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("repair.PromoteStalePreWarningJobs: rows affected: %w", err)
	}
	return int(affected), nil
}

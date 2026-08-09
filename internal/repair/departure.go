// Package repair is declared in doc.go.
// This file implements the departure detector: a periodic scan for silently-
// departed providers, seizing escrow and enqueueing repair (or, for a
// departing VETTING provider, soft-deleting its synthetic chunks and
// enqueueing nothing).
//
// [Flagged and fixed, build.md Phase 9.3] The detection query originally read
// WHERE status = 'ACTIVE' only. ARCH §12's own "Exiting" table lists TWO
// silent-departure rows keyed on the same last_heartbeat_ts/threshold
// mechanism — one for status = VETTING, one for status = ACTIVE — and
// FR-065 explicitly presupposes a VETTING provider crosses this same
// threshold. IC §6 also confirms providers.status may transition to
// DEPARTED from "any" prior state. As originally written, a silently
// departing vetting provider would never be selected, never marked
// DEPARTED, never have its escrow seized, and never free its synthetic
// assignment slot. Fixed below to WHERE status IN ('ACTIVE', 'VETTING');
// only the downstream handling (real-shard repair vs. synthetic soft-delete)
// differs by status, not detection itself.
//
// [REF: IC §3.1, IC §6, DM §4.2, DM §3 Invariant 3, FR-035, FR-065, ARCH §12,
// build.md Phase 9.3 Session 9.3.1]

package repair

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
)

// PenaliseFunc is the shape of internal/payment.Penalise, injected by the
// caller so internal/repair never imports internal/payment (IC §9). Set to a
// real implementation only in Milestone 12, Session 12.1.1.
//
// Note on atomicity: MVP §8.2 describes this file as doing "seizure + repair
// enqueue in one transaction." This signature — matching IC §5.7 as
// declared, with no *sql.Tx parameter — cannot participate in the same
// Go-level transaction as the status UPDATE and the repair-enqueue/
// vetting-soft-delete step below, since it is an opaque callback with no way
// to thread a shared transaction through to the real internal/payment
// implementation. processDeparture therefore performs the status UPDATE,
// then the branch-specific step, then calls penalise, as three sequential
// (not jointly atomic) operations. This is a deliberate, documented
// trade-off: each step is independently safe (its own statement or its own
// internal transaction), the detection query's own WHERE clause naturally
// excludes an already-DEPARTED provider from being re-selected on the next
// cycle, and idempotencyKey below protects the seizure step specifically
// against being applied twice even if a later retry re-processes the same
// provider. True cross-step atomicity would require widening this
// signature to accept a shared executor; left for Milestone 12 to decide
// once the real internal/payment.Penalise implementation exists.
type PenaliseFunc func(ctx context.Context, providerID uuid.UUID, amountPaise int64, idempotencyKey string) error

// DepartureDetector periodically scans for silently-departed providers.
type DepartureDetector struct {
	db       *sql.DB
	profile  config.NetworkProfile
	penalise PenaliseFunc
}

// NewDepartureDetector constructs a DepartureDetector. penalise is required
// (see PenaliseFunc's doc comment); a nil value will panic the first time a
// departure is actually processed, which is preferable to silently skipping
// escrow seizure.
func NewDepartureDetector(db *sql.DB, profile config.NetworkProfile, penalise PenaliseFunc) *DepartureDetector {
	return &DepartureDetector{db: db, profile: profile, penalise: penalise}
}

// Run polls at profile.DeparturePollingInterval. Blocks until ctx is
// cancelled.
//
// [Fixed, M9 review Optional Fix B] Previously reused profile.PollingInterval
// (the audit-scheduling cadence) here — that field's own doc comment already
// flagged this as "an inference, not a documented requirement" with a
// self-acknowledged inexact detection-latency-to-threshold ratio (24h:72h in
// production vs. 2min:10min in demo — not the same multiple, and a
// semantically-overloaded field name besides). DeparturePollingInterval is
// now its own NetworkProfile field, set independently in both profiles.
func (d *DepartureDetector) Run(ctx context.Context) {
	ticker := time.NewTicker(d.profile.DeparturePollingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = d.DetectOnce(ctx) // best-effort background loop; errors are not fatal to the next cycle
		}
	}
}

// DetectOnce scans providers once for any ACTIVE or VETTING provider whose
// last_heartbeat_ts is older than profile.DepartureThreshold, and processes
// every one found. Exposed (not just used internally by Run) so callers —
// including tests — can drive one detection cycle synchronously. Every
// candidate is processed independently: one candidate's failure does not
// abort the rest of the batch; all errors are joined and returned together.
func (d *DepartureDetector) DetectOnce(ctx context.Context) error {
	candidates, err := d.findDepartureCandidates(ctx)
	if err != nil {
		return fmt.Errorf("repair.DepartureDetector.DetectOnce: find candidates: %w", err)
	}

	var errs []error
	for _, c := range candidates {
		if err := d.processDeparture(ctx, c); err != nil {
			errs = append(errs, fmt.Errorf("provider %s: %w", c.providerID, err))
		}
	}
	return errors.Join(errs...)
}

// departureCandidate is one provider crossing the departure threshold,
// along with the status it held AT DETECTION TIME — captured before the
// status UPDATE, so downstream branching (real-shard repair vs. synthetic
// soft-delete) uses the ORIGINAL status, never a re-queried post-UPDATE one.
type departureCandidate struct {
	providerID     uuid.UUID
	originalStatus string
}

// findDepartureCandidates is the corrected detection query — see this
// file's header comment for why VETTING must be included alongside ACTIVE.
func (d *DepartureDetector) findDepartureCandidates(ctx context.Context) ([]departureCandidate, error) {
	// Postgres interval literals don't accept a Go time.Duration directly
	// (pq would encode e.g. "10m0s", not valid interval syntax); format as
	// seconds explicitly, which Postgres's interval parser always accepts.
	thresholdArg := fmt.Sprintf("%f seconds", d.profile.DepartureThreshold.Seconds())

	rows, err := d.db.QueryContext(ctx, `
		SELECT provider_id, status
		FROM providers
		WHERE status IN ('ACTIVE', 'VETTING')
		  AND last_heartbeat_ts < NOW() - $1::interval`,
		thresholdArg,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []departureCandidate
	for rows.Next() {
		var c departureCandidate
		if err := rows.Scan(&c.providerID, &c.originalStatus); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// processDeparture handles one departing provider end to end: mark
// DEPARTED (any prior status -> DEPARTED is valid per IC §6), branch on the
// ORIGINAL status to either soft-delete synthetic vetting chunks (zero
// repair jobs, FR-065) or enqueue real-shard repair, then seize escrow via
// the injected penalise callback. providers is never physically deleted
// (DM §3 Invariant 3) — only status/frozen/departed_at are updated.
func (d *DepartureDetector) processDeparture(ctx context.Context, c departureCandidate) error {
	const updateStatus = `
UPDATE providers
SET status = 'DEPARTED', frozen = TRUE, departed_at = NOW()
WHERE provider_id = $1
RETURNING departed_at`
	var departedAt time.Time
	if err := d.db.QueryRowContext(ctx, updateStatus, c.providerID).Scan(&departedAt); err != nil {
		return fmt.Errorf("mark departed: %w", err)
	}

	if c.originalStatus == "VETTING" {
		if err := DeleteVettingChunksOnDeparture(ctx, d.db, c.providerID); err != nil {
			return fmt.Errorf("delete vetting chunks: %w", err)
		}
	} else {
		if err := EnqueueRepairForRealChunks(ctx, d.db, d.profile, c.providerID, TriggerSilentDeparture); err != nil {
			return fmt.Errorf("enqueue repair jobs: %w", err)
		}
	}

	sealedBalance, err := computeSealedBalance(ctx, d.db, c.providerID)
	if err != nil {
		return fmt.Errorf("compute sealed balance: %w", err)
	}

	idempotencyKey := seizureIdempotencyKey(c.providerID, departedAt)
	if err := d.penalise(ctx, c.providerID, sealedBalance, idempotencyKey); err != nil {
		return fmt.Errorf("penalise: %w", err)
	}
	return nil
}

// EnqueueRepairForRealChunks enqueues one PERMANENT_DEPARTURE-priority
// repair job for every real (non-vetting) chunk assignment currently ACTIVE
// for providerID, calling EnqueueJob (Session 9.1.1) for each. triggerType
// should be TriggerSilentDeparture (the departure detector's own call,
// below) or TriggerAnnouncedDeparture (build.md Milestone 11 Phase 11.6's
// POST /api/v1/provider/depart handler) — both map to the same
// PriorityPermanentDeparture queue priority, but the trigger_type column
// itself still records which actually happened, which matters for
// auditing/reporting even though the queue behaviour is identical.
//
// [Exported, build.md Milestone 11 Phase 11.6] Originally a private method
// on *DepartureDetector, hardcoded to TriggerSilentDeparture, with its own
// doc comment already anticipating this exact gap: "an announced departure
// is a separate, not-yet-built code path, e.g. a REST endpoint handler."
// Exported and parameterized here rather than duplicating this logic a
// second time in internal/api.
func EnqueueRepairForRealChunks(ctx context.Context, db *sql.DB, profile config.NetworkProfile, providerID uuid.UUID, triggerType TriggerType) error {
	rows, err := db.QueryContext(ctx, `
		SELECT chunk_id, segment_id
		FROM chunk_assignments
		WHERE provider_id = $1 AND is_vetting_chunk = FALSE AND status = 'ACTIVE'`,
		providerID,
	)
	if err != nil {
		return fmt.Errorf("query real chunk assignments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type realAssignment struct {
		chunkID   []byte
		segmentID uuid.UUID
	}
	var assignments []realAssignment
	for rows.Next() {
		var a realAssignment
		if err := rows.Scan(&a.chunkID, &a.segmentID); err != nil {
			return fmt.Errorf("scan real chunk assignment: %w", err)
		}
		assignments = append(assignments, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, a := range assignments {
		var chunkID [32]byte
		copy(chunkID[:], a.chunkID)

		// Defensive re-check (Invariant 6's hard gate, FR-066, FR-067) even
		// though the query above already filtered is_vetting_chunk = FALSE —
		// belt-and-suspenders against a chunk_assignments row somehow
		// drifting out of sync between the query and this loop iteration.
		isVetting, err := IsVettingChunk(ctx, db, chunkID, providerID)
		if err != nil {
			return fmt.Errorf("defensive IsVettingChunk check: %w", err)
		}
		if isVetting {
			continue
		}

		// available_shard_count: neither caller tracks live fragment
		// counts per segment (that bookkeeping belongs to the
		// audit/threshold-monitoring subsystem, out of scope here).
		// profile.TotalShards-1 is used as a documented placeholder — one
		// shard (this departing provider's) just went dark; if other
		// shards for the same segment are ALSO already missing, a
		// subsequent threshold/emergency scan is expected to catch that
		// independently via its own, more accurate count.
		if err := EnqueueJob(ctx, db, profile, chunkID, a.segmentID, &providerID,
			triggerType, profile.TotalShards-1); err != nil {
			return fmt.Errorf("EnqueueJob for chunk: %w", err)
		}

		// [Fixed, M9 review Finding #1 — CRITICAL] This soft-delete was
		// missing entirely: the departed provider's chunk_assignments row
		// stayed status='ACTIVE' forever, so idx_chunk_assignments_one_
		// active_per_shard (the partial unique index on (segment_id,
		// shard_index) WHERE status IN ('ACTIVE','REPAIRING')) rejected
		// preRegisterChunkAssignment's INSERT for the replacement provider
		// the moment ExecuteRepairJob actually tried to claim that slot —
		// every real-shard repair failed with a Postgres unique-constraint
		// violation. ARCH §12 ("removes all their chunk assignments from
		// the assignment table, stopping further challenge issuance"),
		// DM §4.5's table comment, and IC §6's DML grant table all agree:
		// SILENT/ANNOUNCED departure must soft-delete the old row here.
		//
		// Ordering is load-bearing: EnqueueJob above must land BEFORE this
		// soft-delete, never after. A soft-deleted row with no matching
		// repair job would make the shard permanently unrepairable — no
		// detector will ever notice it's gone, since findMissingShardIndex
		// (executor.go) derives "missing" from the surviving-holders list a
		// caller supplies, not from a fresh scan of chunk_assignments. This
		// UPDATE also runs per-row, immediately after each EnqueueJob call,
		// rather than batched after the loop: a batched version would leave
		// shards from a mid-loop failure with a fresh repair job but a
		// stale ACTIVE old row, reproducing this exact bug for just those
		// shards.
		//
		// [REF: ARCH §12, DM §4.5, IC §6, M9 review Finding #1]
		const markOldAssignmentDeleted = `
UPDATE chunk_assignments
SET status = 'DELETED', deleted_at = NOW()
WHERE chunk_id = $1 AND provider_id = $2 AND status = 'ACTIVE'`
		if _, err := db.ExecContext(ctx, markOldAssignmentDeleted, chunkID[:], providerID); err != nil {
			return fmt.Errorf("mark old chunk_assignments row deleted: %w", err)
		}
	}
	return nil
}

// computeSealedBalance queries escrow_events directly via SQL for
// providerID's current total ledger balance — Balance = SUM(DEPOSIT +
// REVERSAL) - SUM(RELEASE + SEIZURE) (DM §4.8 / §7's amended
// mv_provider_escrow_balance formula) — rather than importing
// internal/scoring... internal/payment (IC §9 forbids it; same reasoning as
// assignment.go's mv_provider_scores query for SelectReplacementProvider,
// Phase 9.4). On silent departure ALL currently held escrow is seized
// (ADR-024 §5), not just a 30-day window — the 30-day window governs
// ordinary monthly releases, not the seizure event.
//
// [Fixed, M9 review Finding #2 — HIGH] REVERSAL was being debited here
// (SUM(DEPOSIT) - SUM(RELEASE + SEIZURE + REVERSAL)), the opposite of DM
// §7's amended formula. A REVERSAL corrects a previously recorded
// RELEASE/SEIZURE/DEPOSIT entry back toward the provider — it must credit
// the balance, not debit it twice. internal/payment/ledger.go and
// provider.go already implement the correct formula (verified against them
// directly); this was an isolated regression local to this function, not a
// genuine spec ambiguity. Any provider with a reversed payout had their
// sealed escrow under-computed by 2x the reversed amount.
//
// [REF: DM §4.8, DM §7, ADR-024 §5, M9 review Finding #2]
func computeSealedBalance(ctx context.Context, db *sql.DB, providerID uuid.UUID) (int64, error) {
	var balance int64
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(
			CASE
				WHEN event_type IN ('DEPOSIT', 'REVERSAL') THEN amount_paise
				WHEN event_type IN ('RELEASE', 'SEIZURE') THEN -amount_paise
				ELSE 0
			END
		), 0)
		FROM escrow_events
		WHERE provider_id = $1`,
		providerID,
	).Scan(&balance)
	if err != nil {
		return 0, fmt.Errorf("compute sealed balance: %w", err)
	}
	if balance < 0 {
		balance = 0 // a negative ledger balance would indicate a bug elsewhere; never seize a negative amount
	}
	return balance, nil
}

// seizureIdempotencyKey computes SHA-256(providerID || "seizure" ||
// departedAt) as 64 lowercase hex characters, matching
// escrow_events.idempotency_key's VARCHAR(64) column (IC §5.8).
func seizureIdempotencyKey(providerID uuid.UUID, departedAt time.Time) string {
	h := sha256.New()
	h.Write(providerID[:])
	h.Write([]byte("seizure"))
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(departedAt.UnixNano()))
	h.Write(tsBuf[:])
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Downstream note (not implemented here): peer-blocking after departure
// (FR-036 — a departed provider that reconnects gets HTTP 403) is enforced
// by every authenticated REST endpoint checking providers.status !=
// 'DEPARTED' (IC §3.3 error code PROVIDER_DEPARTED), not by this detector.

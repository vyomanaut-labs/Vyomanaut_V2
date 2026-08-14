// Package audit is declared in doc.go.
// This file implements the three-phase crash-safe audit_receipts write
// (ADR-015, DM §4.7, DM §6, DM §3 Invariant 1): AuditResult, ReceiptFields,
// WriteReceiptPhase1, WriteReceiptRecordResponse, and WriteReceiptPhase2.
//
// MILESTONE 7 CORRECTIONS SESSION — Option B: this file originally
// implemented a TWO-phase write (Phase1 INSERT at dispatch, Phase2 UPDATE at
// adjudication) with no place for response_hash, provider_sig,
// response_latency_ms, or jit_flag to ever be written — see the removed
// "KNOWN GAP" note this comment block replaces. WriteReceiptRecordResponse
// is the new middle phase: it persists everything a provider's signed
// response makes knowable, the instant ValidateResponse confirms it, while
// the row is still PENDING. Phase 2 is otherwise unchanged — it still only
// ever sets audit_result, service_sig, and service_countersign_ts — but for
// PASS/FAIL it now depends on WriteReceiptRecordResponse having already run
// (see WriteReceiptPhase2's doc comment for the exact contract).
//
// PHASE TIMING NOTE: ADR-015's original prose describes Phase 1 as happening
// "on receipt of a provider's challenge response." ReceiptFields as declared
// for this session — ChunkID, FileID, ProviderID, ChallengeNonce,
// ServerChallengeTs, AddressWasStale — contains nothing that could only be
// known AFTER a response (no ResponseHash, no ProviderSig, no
// ResponseLatencyMs). Phase 1 as implemented here is written at CHALLENGE
// DISPATCH time, before the provider has replied at all: every dispatched
// challenge gets a PENDING row immediately, so the microservice's own RTO
// timer can promote a genuinely silent provider straight to
// audit_result = TIMEOUT in Phase 2 without needing a separate "did anything
// ever come back" bookkeeping path. This is a clarification of ADR-015's
// prose, not a contradiction of its guarantees — the crash-safety and
// idempotent-retry properties ADR-015 describes hold identically either way.
// WriteReceiptRecordResponse is what actually happens "on receipt of a
// provider's challenge response" — ADR-015's prose maps onto the middle
// phase, not Phase 1.
//
// [REF: IC §5.5, IC §6, DM §4.7, DM §6, DM §3 Invariant 1, FR-039, ADR-015,
//  ADR-033]

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/metrics"
)

// AuditResult is the terminal state of an audit receipt (IC §5.5).
type AuditResult int

const (
	AuditPass AuditResult = iota
	AuditFail
	AuditTimeout
)

// auditResultToSQL converts an AuditResult to its audit_result_type ENUM
// string (DM §4.7: 'PASS' | 'FAIL' | 'TIMEOUT'). Every declared AuditResult
// constant is listed explicitly (not routed through the default case) so
// this switch stays exhaustive-linted per .golangci.yml's
// default-signifies-exhaustive: false setting.
func auditResultToSQL(result AuditResult) (string, error) {
	switch result {
	case AuditPass:
		return "PASS", nil
	case AuditFail:
		return "FAIL", nil
	case AuditTimeout:
		return "TIMEOUT", nil
	default:
		return "", fmt.Errorf("audit: AuditResult(%d) is not a valid terminal result", int(result))
	}
}

// ReceiptFields carries every audit_receipts column that Phase 1 (the initial
// INSERT) populates. Derived from DM §4.7 — excludes receipt_id and
// schema_version (DB-generated) and audit_result/response_hash/
// response_latency_ms/provider_sig/service_sig/service_countersign_ts
// (all Phase-2-only, or only ever knowable once the provider has responded).
// PROPOSED definition — IC §5.5 uses this type name without defining its
// fields; reconcile with interface-contracts.md in a follow-up PR.
type ReceiptFields struct {
	ChunkID [32]byte
	// FileID is nil for a synthetic vetting-chunk audit (DM §8.20); non-nil
	// for every real shard audit.
	FileID            *uuid.UUID
	ProviderID        uuid.UUID
	ChallengeNonce    [33]byte
	ServerChallengeTs time.Time
	// AddressWasStale is true if this challenge was dispatched via DHT
	// fallback (DM §4.7 — providers.multiaddr_stale was TRUE at dispatch).
	AddressWasStale bool
}

// validate checks the four required ReceiptFields per WriteReceiptPhase1's
// pre-conditions. FileID is intentionally excluded (nil is a legitimate,
// meaningful value — DM §8.20) and so is AddressWasStale (false is a
// legitimate value, not a "missing" sentinel).
func (f ReceiptFields) validate() error {
	if f.ChunkID == ([32]byte{}) {
		return fmt.Errorf("ChunkID must not be the zero value")
	}
	if f.ProviderID == uuid.Nil {
		return fmt.Errorf("ProviderID must not be the zero UUID")
	}
	if f.ChallengeNonce == ([33]byte{}) {
		return fmt.Errorf("ChallengeNonce must not be the zero value")
	}
	if f.ServerChallengeTs.IsZero() {
		return fmt.Errorf("ServerChallengeTs must not be the zero value")
	}
	return nil
}

// nonceUniqueViolationCode is the Postgres error code for a unique_violation
// (SQLSTATE 23505) — the code audit_receipt_nonces' PRIMARY KEY raises on a
// replayed challenge_nonce. Mirrors internal/payment/ledger.go's
// insertEventErrCode; duplicated rather than imported because internal/audit
// may not import internal/payment (.golangci.yml depguard, IC §9).
const nonceUniqueViolationCode = "23505"

// isNonceUniqueViolation reports whether err is a Postgres unique_violation
// on audit_receipt_nonces' PRIMARY KEY, via lib/pq's own *pq.Error type — the
// same pattern internal/payment/ledger.go's isUniqueViolation uses for its
// own unique_violation check.
func isNonceUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && string(pqErr.Code) == nonceUniqueViolationCode
}

// WriteReceiptPhase1 performs the crash-safe Phase 1 INSERT to audit_receipts.
// Inserts a PENDING row (audit_result = NULL) at challenge-dispatch time —
// see the PHASE TIMING NOTE above. The provider's signature is not yet known
// at this point (dispatch precedes any response), so provider_sig is left
// NULL along with every other later-phase column; see DM §8.9 for the
// PENDING-state field semantics. (ADR-015)
//
// REPLAY-PROTECTION FIX (Milestone 7 corrections session): this function now
// also INSERTs into audit_receipt_nonces, in the SAME database transaction
// as the audit_receipts INSERT — exactly what that table's own migration
// comment (migrations/generator.go, ADR-033) always said the microservice
// would do, but which this function never actually did until now.
// audit_receipts_nonce_unique alone (UNIQUE(challenge_nonce,
// server_challenge_ts), necessarily scoped to the partition key — ADR-033)
// cannot catch a replayed nonce submitted with a different
// server_challenge_ts; audit_receipt_nonces' PRIMARY KEY on challenge_nonce
// ALONE is what actually enforces global replay protection (DM §4.7). Both
// INSERTs commit together or neither does: a rejected replay leaves no
// partial audit_receipts row behind.
//
// The nonce-guard INSERT runs FIRST, before the (larger) audit_receipts
// INSERT: a replay is rejected by a single-column PRIMARY KEY lookup without
// the database needing to attempt the bigger insert first. This is a
// performance detail, not a correctness one — either statement failing rolls
// back the whole transaction regardless of order.
//
// Pre-conditions:
//   - fields.ChunkID, fields.ProviderID, fields.ChallengeNonce, fields.ServerChallengeTs
//     are all populated (checked; returns an error before touching the
//     database if not — no partial row is ever created for invalid fields)
//   - the database connection is open
//
// Post-conditions (on nil error):
//   - a row with audit_result = NULL exists in audit_receipts
//   - a matching row exists in audit_receipt_nonces
//   - both rows are durable before this function returns: COMMIT under
//     PostgreSQL's default synchronous_commit = on already guarantees the
//     WAL is flushed before COMMIT returns — no special flush call is
//     needed. (There is no pg_wal_flush() function in PostgreSQL; do not
//     reference one.)
//
// Error semantics:
//   - ErrReplayDetected: challenge_nonce was already used in a prior
//     receipt (audit_receipt_nonces PRIMARY KEY violation) — the whole
//     transaction is rolled back, nothing is written.
//   - field-validation errors: returned before any database call.
//   - other database errors: returned to caller; caller must not proceed to
//     WriteReceiptRecordResponse/WriteReceiptPhase2 if Phase 1 fails.
//
// Goroutine-safe: yes (uses connection pool).
//
// [REF: IC §5.5, IC §6, DM §4.7, DM §8.9, DM §3 Invariant 5, ADR-015,
//
//	ADR-033, FR-039]
func WriteReceiptPhase1(ctx context.Context, db *sql.DB, fields ReceiptFields) (receiptID uuid.UUID, err error) {
	if err := fields.validate(); err != nil {
		return uuid.Nil, fmt.Errorf("audit.WriteReceiptPhase1: %w", err)
	}

	receiptID, err = uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("audit.WriteReceiptPhase1: generate UUIDv7 receipt_id: %w", err)
	}

	// FileID is *uuid.UUID; a nil pointer must become a genuine nil
	// interface{} before it reaches database/sql. Passing the (possibly nil)
	// *uuid.UUID directly would risk a nil-pointer panic: uuid.UUID.Value()
	// has a VALUE receiver, so Go's method-set promotion gives *uuid.UUID
	// that same method — including on a nil pointer, where calling it
	// dereferences nil. database/sql's nil-interface fast path only catches
	// an untyped nil, not a typed-nil pointer wrapped in interface{}, so this
	// conversion has to happen explicitly here.
	var fileIDParam interface{}
	if fields.FileID != nil {
		fileIDParam = *fields.FileID
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, fmt.Errorf("audit.WriteReceiptPhase1: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	const insertNonceGuard = `
INSERT INTO audit_receipt_nonces (challenge_nonce, server_challenge_ts)
VALUES ($1, $2)`
	_, err = tx.ExecContext(ctx, insertNonceGuard, fields.ChallengeNonce[:], fields.ServerChallengeTs)
	if err != nil {
		if isNonceUniqueViolation(err) {
			return uuid.Nil, fmt.Errorf("audit.WriteReceiptPhase1: %w", ErrReplayDetected)
		}
		return uuid.Nil, fmt.Errorf("audit.WriteReceiptPhase1: nonce guard insert: %w", err)
	}

	const insertPhase1 = `
INSERT INTO audit_receipts (
    receipt_id, chunk_id, file_id, provider_id,
    challenge_nonce, server_challenge_ts, address_was_stale
) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	// audit_result is left NULL (omitted above — Postgres has no DEFAULT for
	// it), alongside response_hash, response_latency_ms, provider_sig,
	// service_sig, and service_countersign_ts: this is the PENDING state
	// DM §8.9 describes. Nothing about the provider's eventual response is
	// knowable yet at Phase 1 dispatch time.
	_, err = tx.ExecContext(ctx, insertPhase1,
		receiptID, fields.ChunkID[:], fileIDParam, fields.ProviderID,
		fields.ChallengeNonce[:], fields.ServerChallengeTs, fields.AddressWasStale,
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("audit.WriteReceiptPhase1: insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, fmt.Errorf("audit.WriteReceiptPhase1: commit: %w", err)
	}

	return receiptID, nil
}

// WriteReceiptRecordResponse performs the middle phase of the three-phase
// write (Option B, Milestone 7 corrections session): it UPDATEs the
// response-derived columns — response_hash, provider_sig,
// response_latency_ms, and jit_flag — onto a still-PENDING row the instant a
// provider's signed response has been validated (ValidateResponse), before
// WriteReceiptPhase2 adjudicates PASS/FAIL/TIMEOUT.
//
// This is what closes the data-flow gap the original two-phase write had:
// Phase 1 runs at dispatch time, before any response exists (see the PHASE
// TIMING NOTE atop this file), and Phase 2's signature never carried these
// columns. jit_flag in particular is computed HERE, via
// EvaluateJIT(responseLatencyMs, p95ThroughputKbps) — giving EvaluateJIT's
// result an actual place to be persisted, which no code anywhere previously
// did (EvaluateJIT itself is a pure function with no caller in this
// package). p95ThroughputKbps is the caller's responsibility to supply, from
// the same providers row read the IC §6 EWMA update already requires after
// every response — this function does not query providers itself;
// internal/audit has no dependency on that table.
//
// Callers MUST call this before WriteReceiptPhase2 for any PASS or FAIL
// result. WriteReceiptPhase2 does not accept response_hash/provider_sig
// itself and relies on this function to have already populated them, so DM
// §4.7's audit_receipts_response_consistency CHECK constraint is satisfied
// by the time Phase 2 sets audit_result. A genuine TIMEOUT never calls this
// function at all — WriteReceiptPhase2 promotes straight from Phase 1's
// PENDING row, leaving response_hash and provider_sig NULL, exactly as the
// CHECK constraint's TIMEOUT branch requires.
//
// Pre-conditions:
//   - receiptID identifies an existing PENDING row from WriteReceiptPhase1
//   - responseLatencyMs >= 0 (DM §4.7 CHECK; not re-validated here — an
//     out-of-range value surfaces as the same CHECK-constraint database
//     error WriteReceiptPhase2's own out-of-contract calls surface as)
//
// Post-conditions (on nil error):
//   - response_hash, provider_sig, response_latency_ms, and jit_flag are
//     set; audit_result is still NULL (WriteReceiptPhase2 has not run yet)
//
// Error semantics:
//   - ErrResponseAlreadyRecorded: the UPDATE affected zero rows because
//     response_hash was already non-NULL (a duplicate signed response for
//     the same challenge arrived twice — idempotent retry), or because the
//     row is already abandoned or already final. The WHERE clause below
//     cannot distinguish those three cases from each other, the same way
//     WriteReceiptPhase2's own WHERE clause cannot (see its doc comment).
//   - other database errors: returned to caller.
//
// Goroutine-safe: yes.
//
// [REF: IC §5.5, IC §6, DM §4.7, DM §8.9–§8.12, ADR-014 Defence 3, ADR-015]
func WriteReceiptRecordResponse(
	ctx context.Context,
	db *sql.DB,
	receiptID uuid.UUID,
	responseHash [32]byte,
	providerSig [64]byte,
	responseLatencyMs int,
	p95ThroughputKbps *float64,
) error {
	jitFlag := EvaluateJIT(responseLatencyMs, p95ThroughputKbps)

	const updateResponse = `
UPDATE audit_receipts
SET response_hash = $1, provider_sig = $2, response_latency_ms = $3, jit_flag = $4
WHERE receipt_id = $5 AND audit_result IS NULL AND abandoned_at IS NULL AND response_hash IS NULL`
	// The WHERE clause above must match the USING clause of the
	// audit_receipts_record_response row security policy (DM §6) exactly —
	// same reasoning as WriteReceiptPhase2's own WHERE/USING-clause comment.
	res, err := db.ExecContext(ctx, updateResponse,
		responseHash[:], providerSig[:], responseLatencyMs, jitFlag, receiptID,
	)
	if err != nil {
		return fmt.Errorf("audit.WriteReceiptRecordResponse: update: %w", err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit.WriteReceiptRecordResponse: rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrResponseAlreadyRecorded
	}
	return nil
}

// WriteReceiptPhase2 performs the crash-safe Phase 2 UPDATE on audit_receipts.
// Sets audit_result, service_sig, and service_countersign_ts atomically,
// promoting a PENDING row to its terminal state. Unchanged in shape by the
// Milestone 7 corrections session's move to a three-phase write (Option B) —
// still only ever touches these three columns.
// (ADR-015, DM §3 Invariant 1, DM §6 row security policy)
//
// PRECONDITION FOR PASS/FAIL (was a "KNOWN GAP" in this function before the
// Milestone 7 corrections session; resolved by WriteReceiptRecordResponse,
// not by a signature change here): DM §4.7's audit_receipts_response_consistency
// CHECK constraint requires response_hash IS NOT NULL AND provider_sig IS NOT
// NULL whenever audit_result IN ('PASS', 'FAIL'). This function has no
// parameter for either column and never will — WriteReceiptRecordResponse
// must be called first to populate them while the row is still PENDING (see
// its doc comment). Calling this function with result = AuditPass or
// AuditFail WITHOUT a prior WriteReceiptRecordResponse call will fail the
// CHECK constraint, exactly as it always did — that failure now signals a
// caller-ordering bug, not a data-flow gap in this file. AuditTimeout is
// unaffected either way: its branch of the same CHECK requires response_hash
// and provider_sig to BOTH be NULL, which is what Phase 1 alone already
// leaves them as, and no genuine timeout ever calls WriteReceiptRecordResponse.
//
// Pre-conditions:
//   - receiptID identifies an existing row
//   - result is AuditPass, AuditFail, or AuditTimeout
//   - for AuditPass/AuditFail: WriteReceiptRecordResponse has already
//     succeeded for this receiptID (see PRECONDITION note above)
//   - len(serviceSig) == 64 — enforced by the compiler via the fixed
//     [64]byte parameter type, so no runtime check is needed for this one.
//
// Post-conditions (on nil error):
//   - the row is updated; audit_result is no longer NULL
//
// Error semantics:
//   - ErrReceiptAlreadyFinal: the UPDATE affected zero rows. The WHERE
//     clause below cannot distinguish "already promoted to a terminal
//     state" from "abandoned by GC" from "receiptID does not exist" — all
//     three read back as zero rows affected. IC §5.5's idempotent-retry
//     protocol treats this as the expected outcome for a legitimate retry:
//     the caller should treat it as success and return the row's existing
//     service_sig rather than surfacing this as a fresh error to whatever
//     triggered the retry. Reading that existing service_sig back is safe to
//     implement now: audit_receipts_app_select grants vyomanaut_app
//     unconditional SELECT on this table (DM §6, ADR-032) — confirmed
//     against a live database. (An earlier version of this comment claimed
//     no SELECT policy existed; that was true of an older schema revision,
//     not of DM §6 as currently generated.)
//   - other database errors: returned to caller. This includes the
//     audit_receipts_response_consistency CHECK-constraint violation
//     described in the PRECONDITION note above, for a caller that skips
//     WriteReceiptRecordResponse before a PASS/FAIL call.
//
// Goroutine-safe: yes.
//
// [REF: IC §5.5, DM §3 Invariant 1, DM §4.7, DM §6, ADR-015, ADR-032]
func WriteReceiptPhase2(ctx context.Context, db *sql.DB, receiptID uuid.UUID, result AuditResult, serviceSig [64]byte, serviceTS time.Time) error {
	resultStr, err := auditResultToSQL(result)
	if err != nil {
		return fmt.Errorf("audit.WriteReceiptPhase2: %w", err)
	}

	const updatePhase2 = `
UPDATE audit_receipts
SET audit_result = $1, service_sig = $2, service_countersign_ts = $3
WHERE receipt_id = $4 AND audit_result IS NULL AND abandoned_at IS NULL`
	// The WHERE clause above must match the USING clause of the
	// audit_receipts_phase2_update row security policy (DM §6) exactly: a
	// mismatch would make legitimate Phase 2 updates silently affect 0 rows
	// under row-level security instead of surfacing a clear application
	// error — RLS enforces the same boundary independently at the database
	// engine level, so this is defense in depth, not the only guard.
	//
	// [Decision — OBS.1.2, ADR-033] internal/audit issues no SELECT queries
	// today — every DB round trip in this file is a transactional write
	// (see WriteReceiptPhase1's two INSERTs and WriteReceiptRecordResponse's
	// UPDATE above). This UPDATE is nonetheless the ADR-033 "foreground DB
	// read" instrumentation point: it is the one call guaranteed to execute
	// exactly once for every terminal audit result (PASS, FAIL, or TIMEOUT),
	// and its round-trip latency reflects the same connection-pool/DB
	// contention NFR-028's throttle is watching for — the metric name
	// (vyomanaut_db_read_latency_seconds) describes the throttle signal's
	// origin in ARCH §23, not a restriction to SELECT statements.
	start := time.Now()
	res, err := db.ExecContext(ctx, updatePhase2, resultStr, serviceSig[:], serviceTS, receiptID)
	metrics.ForegroundReadLatency.Observe(time.Since(start))
	if err != nil {
		return fmt.Errorf("audit.WriteReceiptPhase2: update: %w", err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit.WriteReceiptPhase2: rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrReceiptAlreadyFinal
	}
	// Only a genuinely new terminal result is counted — ErrReceiptAlreadyFinal
	// above (an idempotent retry hitting an already-final row) must not
	// double-count the same audit result a second time.
	metrics.AuditResultsTotal.With(prometheus.Labels{"result": resultStr}).Inc()
	return nil
}

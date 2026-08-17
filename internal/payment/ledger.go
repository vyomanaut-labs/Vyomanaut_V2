// Package payment is declared in doc.go.
// This file implements the append-only escrow ledger: InsertEscrowEvent for
// the provider-side ledger (Session 10.2.1) and InsertOwnerEscrowEvent for
// the owner-side ledger (Session 10.5.1) — both are ledger-write functions
// and belong in the same file per this package's one-ledger-file convention.
// All amounts here are int64 paise, per NFR-038 (the CI-enforced no-float
// rule for internal/payment/), a metric-naming requirement (numbered one
// higher) — D-07, M17 Session 17.1.2 corrected the same mix-up in this
// package's doc.go.
//
// [REF: IC §5.8, DM §4.8, DM §4.9, DM §3 Invariant 2, IC §6, NFR-038,
// build.md Phase 10.2 Session 10.2.1, Phase 10.5 Session 10.5.1]

package payment

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/metrics"
)

// EscrowEventType mirrors the escrow_event_type DB enum (DM §4.8).
type EscrowEventType string

const (
	EscrowDeposit  EscrowEventType = "DEPOSIT"
	EscrowRelease  EscrowEventType = "RELEASE"
	EscrowSeizure  EscrowEventType = "SEIZURE"
	EscrowReversal EscrowEventType = "REVERSAL"
)

// ErrDuplicateIdempotencyKey is returned by InsertEscrowEvent and
// InsertOwnerEscrowEvent when idempotencyKey already exists. Callers should
// treat this as an idempotent success — the event was already recorded on a
// prior call or webhook delivery, not as a failure to surface.
var ErrDuplicateIdempotencyKey = errors.New("payment: idempotency key already exists")

// insertEventErrCode is the Postgres error code for a unique_violation
// (23505) — the code the escrow_events.idempotency_key and
// owner_escrow_events.idempotency_key UNIQUE constraints raise on a
// duplicate insert.
const insertEventErrCode = "23505"

// InsertEscrowEvent appends one row to escrow_events — the ONLY permitted
// write to this table (DM §3 Invariant 2). amountPaise is int64 by
// construction (see provider.go's header comment on why that alone is
// sufficient enforcement) — never accepted or derived from any non-integer
// numeric type anywhere in this call chain.
//
// Pre-conditions:
//   - amountPaise > 0 (sign is implied by eventType, per DM §4.8)
//   - idempotencyKey is globally unique (enforced by the DB UNIQUE
//     constraint, not by this function)
//
// Error semantics:
//   - ErrDuplicateIdempotencyKey on UNIQUE violation — idempotent retry,
//     caller should treat as success.
//
// Goroutine-safe: yes.
func InsertEscrowEvent(
	ctx context.Context,
	db *sql.DB,
	providerID uuid.UUID,
	eventType EscrowEventType,
	amountPaise int64,
	idempotencyKey string,
	auditPeriodID *uuid.UUID,
) error {
	const insert = `
INSERT INTO escrow_events (provider_id, event_type, amount_paise, audit_period_id, idempotency_key)
VALUES ($1, $2, $3, $4, $5)`
	_, err := db.ExecContext(ctx, insert, providerID, string(eventType), amountPaise, auditPeriodID, idempotencyKey)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateIdempotencyKey
		}
		return fmt.Errorf("payment.InsertEscrowEvent: insert: %w", err)
	}
	// Only a genuinely new event is counted — ErrDuplicateIdempotencyKey
	// above (an idempotent retry / duplicate webhook delivery) must not
	// double-count the same escrow event a second time (NFR-025, ARCH §23:
	// "Payment volume").
	metrics.PaymentEscrowEventsTotal.With(prometheus.Labels{"type": string(eventType)}).Inc()
	return nil
}

// isUniqueViolation reports whether err is a Postgres unique_violation
// (SQLSTATE 23505), via lib/pq's own *pq.Error type — the standard,
// driver-provided way to distinguish a duplicate-key insert from any other
// database error.
func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && string(pqErr.Code) == insertEventErrCode
}

// OwnerEscrowEventType mirrors the owner_escrow_event_type DB enum (DM §4.9).
type OwnerEscrowEventType string

const (
	OwnerDeposit    OwnerEscrowEventType = "DEPOSIT"
	OwnerCharge     OwnerEscrowEventType = "CHARGE"
	OwnerWithdrawal OwnerEscrowEventType = "WITHDRAWAL"
	OwnerRefund     OwnerEscrowEventType = "REFUND"
)

// InsertOwnerEscrowEvent appends one row to owner_escrow_events — the ONLY
// permitted write to this table, mirroring InsertEscrowEvent's role for the
// provider-side ledger (DM §4.9). amountPaise is int64 by construction, for
// the same reason given on InsertEscrowEvent and this file's own header.
//
// Pre-conditions:
//   - amountPaise > 0
//   - idempotencyKey is globally unique (enforced by the DB UNIQUE
//     constraint, not by this function)
//
// Error semantics:
//   - ErrDuplicateIdempotencyKey on UNIQUE violation — idempotent retry,
//     caller should treat as success.
//
// Goroutine-safe: yes.
func InsertOwnerEscrowEvent(
	ctx context.Context,
	db *sql.DB,
	ownerID uuid.UUID,
	eventType OwnerEscrowEventType,
	amountPaise int64,
	idempotencyKey string,
	fileID *uuid.UUID,
) error {
	const insert = `
INSERT INTO owner_escrow_events (owner_id, event_type, amount_paise, file_id, idempotency_key)
VALUES ($1, $2, $3, $4, $5)`
	_, err := db.ExecContext(ctx, insert, ownerID, string(eventType), amountPaise, fileID, idempotencyKey)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateIdempotencyKey
		}
		return fmt.Errorf("payment.InsertOwnerEscrowEvent: insert: %w", err)
	}
	return nil
}

// providerBalance queries mv_provider_escrow_balance directly — the same
// view both RazorpayProvider.GetBalance and MockProvider.GetBalance use, so
// neither implementation maintains any separate balance state (IC §5.8:
// "always SUM(DEPOSIT + REVERSAL) - SUM(RELEASE + SEIZURE); never
// negative").
func providerBalance(ctx context.Context, db *sql.DB, providerID uuid.UUID) (int64, error) {
	var balance int64
	err := db.QueryRowContext(ctx, `SELECT balance_paise FROM mv_provider_escrow_balance WHERE provider_id = $1`, providerID).Scan(&balance)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil // no events yet -> zero balance, not an error
	}
	if err != nil {
		return 0, fmt.Errorf("query mv_provider_escrow_balance: %w", err)
	}
	if balance < 0 {
		balance = 0
	}
	return balance, nil
}

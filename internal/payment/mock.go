// Package payment is declared in doc.go.
// This file implements MockProvider, used for demo mode (profile.PaymentMode
// == "mock") and for tests.
//
// [Flagged and corrected, build.md Phase 10.1 Session 10.1.2] The original
// task described an in-memory mock — exactly the anti-pattern MVP §6.1
// CR-10 warns against ("direct DB writes from a mock break the interface
// abstraction... the mock must implement the interface fully, not bypass
// it"), and it would have made MVP §7.7's idempotency claim ("the DB
// constraint is the enforcement — the mock does not need additional logic")
// false, since that is only true if the mock's writes actually reach the
// real escrow_events/owner_escrow_events tables and their
// UNIQUE(idempotency_key) constraints. Fixed below: every ledger-writing
// method calls the same InsertEscrowEvent/InsertOwnerEscrowEvent
// (Session 10.2.1/10.5.1) the real RazorpayProvider uses. Only the external
// Razorpay HTTP calls — which have no database representation of their own
// — are mocked out; there is no separate in-memory ledger anywhere in this
// file.
//
// [REF: MVP §6.1 CR-10, MVP §7.7, build.md Phase 10.1 Session 10.1.2]

package payment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// MockProvider implements PaymentProvider for demo mode and for tests. It
// mocks only the external Razorpay HTTP calls; every ledger write goes
// through the same InsertEscrowEvent/InsertOwnerEscrowEvent path the real
// RazorpayProvider uses, so the DB-level UNIQUE(idempotency_key) constraint
// enforces idempotency identically for both (MVP §7.7) — this is also why
// the mock "implements the interface fully" rather than bypassing it
// (MVP §6.1 CR-10).
type MockProvider struct {
	db *sql.DB
}

func NewMockProvider(db *sql.DB) *MockProvider {
	return &MockProvider{db: db}
}

var _ PaymentProvider = (*MockProvider)(nil)

// InitiateEscrow returns a synthetic vpa/qrURL (no real Razorpay call) and,
// because there is no real Razorpay webhook to wait for in demo mode,
// immediately calls InsertOwnerEscrowEvent — matching MVP's own Feature Gap
// Table row F-09 ("CLI command deposits into mock ledger" — no async
// webhook in demo mode).
func (m *MockProvider) InitiateEscrow(ctx context.Context, ownerID uuid.UUID, amountPaise int64, contractID uuid.UUID) (string, string, error) {
	vpa := fmt.Sprintf("mock.%s@mockbank", ownerID.String()[:8])
	qrURL := fmt.Sprintf("https://mock.vyomanaut.local/qr/%s", contractID)

	idempotencyKey := mockDepositIdempotencyKey(ownerID, contractID)
	if err := InsertOwnerEscrowEvent(ctx, m.db, ownerID, OwnerDeposit, amountPaise, idempotencyKey, nil); err != nil {
		if !errors.Is(err, ErrDuplicateIdempotencyKey) {
			return "", "", fmt.Errorf("payment.MockProvider.InitiateEscrow: %w", err)
		}
	}
	return vpa, qrURL, nil
}

func mockDepositIdempotencyKey(ownerID, contractID uuid.UUID) string {
	h := sha256.New()
	h.Write([]byte("mock-deposit"))
	h.Write(ownerID[:])
	h.Write(contractID[:])
	return hex.EncodeToString(h.Sum(nil))
}

// ReleaseEscrow calls InsertEscrowEvent(..., EscrowRelease, ...) directly —
// no real Razorpay payout call, but a real row with a real idempotency
// constraint.
func (m *MockProvider) ReleaseEscrow(ctx context.Context, providerID uuid.UUID, amountPaise int64, auditPeriodID uuid.UUID, idempotencyKey string) error {
	if err := InsertEscrowEvent(ctx, m.db, providerID, EscrowRelease, amountPaise, idempotencyKey, &auditPeriodID); err != nil {
		if errors.Is(err, ErrDuplicateIdempotencyKey) {
			return nil
		}
		return fmt.Errorf("payment.MockProvider.ReleaseEscrow: %w", err)
	}
	return nil
}

// Penalise calls InsertEscrowEvent(..., EscrowSeizure, ...) directly.
// Penalise seizes amountPaise from providerID's escrow (silent departure).
//
// [Fixed, M10 corrections review Finding #3, defense-in-depth] a zero or
// negative amountPaise would violate escrow_events' CHECK (amount_paise >
// 0) constraint and surface as a raw Postgres error. The primary fix lives
// at the caller (internal/repair/departure.go's processDeparture now only
// calls this when sealedBalance > 0) — this guard exists so this
// implementation is safe on its own merits too, per the audit's explicit
// "don't rely solely on the caller remembering the guard."
func (m *MockProvider) Penalise(ctx context.Context, providerID uuid.UUID, amountPaise int64, idempotencyKey string) error {
	if amountPaise <= 0 {
		return nil
	}
	if err := InsertEscrowEvent(ctx, m.db, providerID, EscrowSeizure, amountPaise, idempotencyKey, nil); err != nil {
		if errors.Is(err, ErrDuplicateIdempotencyKey) {
			return nil
		}
		return fmt.Errorf("payment.MockProvider.Penalise: %w", err)
	}
	return nil
}

// GetBalance queries mv_provider_escrow_balance — the SAME view the real
// provider's balance queries use. There is no separate in-memory balance
// state to keep in sync.
func (m *MockProvider) GetBalance(ctx context.Context, providerID uuid.UUID) (int64, error) {
	return providerBalance(ctx, m.db, providerID)
}

// WithdrawOwnerEscrow calls InsertOwnerEscrowEvent(..., OwnerWithdrawal, ...)
// directly and returns a synthetic payoutID.
// payoutIDKeyPrefixLen is how many hex characters of the idempotency key
// are folded into MockProvider's synthetic payoutID for display/log
// correlation purposes only — has no bearing on the actual idempotency
// guarantee, which comes entirely from owner_escrow_events'
// UNIQUE(idempotency_key) constraint below.
const payoutIDKeyPrefixLen = 16

func (m *MockProvider) WithdrawOwnerEscrow(ctx context.Context, ownerID uuid.UUID, amountPaise int64, idempotencyKey string) (string, error) {
	// [Fixed, M10 corrections review, minor item] idempotencyKey[:16] had no
	// length guard — currently safe only because the HTTP layer
	// (idempotencyKeyPattern in internal/api/owner.go) enforces exactly 64
	// hex chars before this is ever reached, but this package has no
	// defense of its own if called with a shorter key by some future
	// internal caller that bypasses that HTTP-layer validation.
	prefixLen := min(payoutIDKeyPrefixLen, len(idempotencyKey))
	payoutID := "mock-payout-" + idempotencyKey[:prefixLen]
	if err := InsertOwnerEscrowEvent(ctx, m.db, ownerID, OwnerWithdrawal, amountPaise, idempotencyKey, nil); err != nil {
		if errors.Is(err, ErrDuplicateIdempotencyKey) {
			return payoutID, nil
		}
		return "", fmt.Errorf("payment.MockProvider.WithdrawOwnerEscrow: %w", err)
	}
	return payoutID, nil
}
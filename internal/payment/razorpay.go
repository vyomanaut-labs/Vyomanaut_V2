// Package payment is declared in doc.go.
// This file implements RazorpayProvider (the live PaymentProvider backed by
// Razorpay Route + Smart Collect 2.0 + RazorpayX, ARCH §17) and the three
// webhook handlers.
//
// [Flagged and corrected, build.md Phase 10.3 — the single most important
// fix in this milestone] IC §7.1's given SQL for virtual_account.payment.
// captured inserted into escrow_events using an owner-side value in the
// provider_id column. escrow_events.provider_id is NOT NULL REFERENCES
// providers(provider_id) (DM §4.8). Smart Collect 2.0 deposits are
// unambiguously owner-side (ARCH §17, DM §8.1 owners.smart_collect_vpa).
// owner_escrow_events exists specifically because "the owners table has no
// balance information" (DM §4.9) — inserting an owner's deposit into the
// provider ledger either violates the foreign key outright or silently
// defeats the entire reason that table was created. Corrected below:
// HandleDepositCaptured targets owner_escrow_events, column owner_id,
// event_type = OwnerDeposit (owner_escrow_event_type), not escrow_event_type.
//
// [Fixed, build.md Milestone 11 Session 11.5.6's own flagged note — that
// session explicitly says this is "a follow-up to Milestone 10 Session
// 10.3.1, not a new session", so it is addressed here rather than deferred.]
// owner_escrow_event_type (DEPOSIT, CHARGE, WITHDRAWAL, REFUND) has no value
// representing "a withdrawal came back" — a reversed payout may be either a
// provider RELEASE or an owner WITHDRAWAL, and the original payout.reversed
// design only handled the provider case. HandlePayoutReversed below checks
// both ledgers by idempotency_key and branches; the owner case records the
// reversal using the existing OwnerDeposit type (money is being credited
// back, which is exactly what DEPOSIT means) with idempotency key
// SHA-256("withdrawal-reversal" || original_idempotency_key) — distinct from
// both a genuine deposit's key and a provider reversal's key.
//
// [REF: IC §7, IC §11, ARCH §17, ADR-011, ADR-012, FR-047, FR-048, NFR-029,
// build.md Phase 10.3 Session 10.3.1, Phase 10.5 Session 10.5.1]

package payment

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
)

// ErrInvalidWebhookSignature is returned by every webhook handler below when
// X-Razorpay-Signature does not verify against the payload and shared
// secret. Callers (internal/api, Milestone 11/12) must translate this into
// HTTP 400 and must not perform any database write beforehand (IC §7).
var ErrInvalidWebhookSignature = errors.New("payment: invalid Razorpay webhook signature")

// verifyRazorpaySignature checks X-Razorpay-Signature: HMAC-SHA256(secret,
// rawBody), hex-encoded, using a constant-time comparison. Every webhook
// handler in this file calls this BEFORE any database write (IC §7: "All
// incoming webhooks must be verified... before any database write is
// triggered").
func verifyRazorpaySignature(rawBody []byte, signature string, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(rawBody)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// ── Webhook payloads ───────────────────────────────────────────────────────────
// Each struct carries only the already-parsed fields IC §7's own tables
// name; extracting them from Razorpay's raw nested JSON is the caller's
// responsibility (internal/api, Milestone 11/12) — this package receives
// values, not envelopes.

// DepositWebhookPayload carries the fields IC §7.1 names for
// virtual_account.payment.captured.
type DepositWebhookPayload struct {
	PaymentID   string // payload.payment.entity.id
	VPA         string // the owner's Smart Collect virtual UPI address (extracted from payload.virtual_account.entity by the caller)
	AmountPaise int64  // payload.payment.entity.amount — already in paise; never rescaled here
}

// PayoutReversedWebhookPayload carries the fields IC §7.2 names for
// payout.reversed.
type PayoutReversedWebhookPayload struct {
	AmountPaise int64  // payload.payout.entity.amount
	ReferenceID string // payload.payout.entity.reference_id — the original X-Payout-Idempotency value
}

// AccountCreatedWebhookPayload carries the fields IC §7.3 names for
// account.created.
type AccountCreatedWebhookPayload struct {
	AccountID  string    // payload.account.entity.id
	ProviderID uuid.UUID // payload.account.entity.notes.provider_id
}

// ── Handlers ───────────────────────────────────────────────────────────────────

// HandleDepositCaptured processes virtual_account.payment.captured (IC §7.1,
// corrected — see this file's header comment). The idempotency key combines
// IC §7.1's original "deposit" domain-separation prefix with DM §4.9's
// owner_id convention and the Razorpay payment ID, harmonising the two
// documents' slightly different formats into one unambiguous key.
func HandleDepositCaptured(ctx context.Context, db *sql.DB, webhookSecret []byte, rawBody []byte, signature string, payload DepositWebhookPayload) error {
	if !verifyRazorpaySignature(rawBody, signature, webhookSecret) {
		return ErrInvalidWebhookSignature
	}

	var ownerID uuid.UUID
	err := db.QueryRowContext(ctx, `SELECT owner_id FROM owners WHERE smart_collect_vpa = $1`, payload.VPA).Scan(&ownerID)
	if err != nil {
		return fmt.Errorf("payment.HandleDepositCaptured: look up owner by VPA: %w", err)
	}

	idempotencyKey := depositIdempotencyKey(ownerID, payload.PaymentID)
	if err := InsertOwnerEscrowEvent(ctx, db, ownerID, OwnerDeposit, payload.AmountPaise, idempotencyKey, nil); err != nil {
		if errors.Is(err, ErrDuplicateIdempotencyKey) {
			return nil // idempotent redelivery (IC §7): same webhook twice -> one row
		}
		return fmt.Errorf("payment.HandleDepositCaptured: %w", err)
	}
	return nil
}

func depositIdempotencyKey(ownerID uuid.UUID, paymentID string) string {
	h := sha256.New()
	h.Write([]byte("deposit"))
	h.Write(ownerID[:])
	h.Write([]byte(paymentID))
	return hex.EncodeToString(h.Sum(nil))
}

// HandlePayoutReversed processes payout.reversed (IC §7.2), branching on
// whether reference_id names an original provider RELEASE or an original
// owner WITHDRAWAL — see this file's header comment for why both cases are
// handled here.
func HandlePayoutReversed(ctx context.Context, db *sql.DB, webhookSecret []byte, rawBody []byte, signature string, payload PayoutReversedWebhookPayload) error {
	if !verifyRazorpaySignature(rawBody, signature, webhookSecret) {
		return ErrInvalidWebhookSignature
	}

	providerID, auditPeriodID, isProviderRelease, err := lookupOriginalRelease(ctx, db, payload.ReferenceID)
	if err != nil {
		return fmt.Errorf("payment.HandlePayoutReversed: %w", err)
	}
	if isProviderRelease {
		idempotencyKey := reversalIdempotencyKey(payload.ReferenceID)
		if err := InsertEscrowEvent(ctx, db, providerID, EscrowReversal, payload.AmountPaise, idempotencyKey, &auditPeriodID); err != nil {
			if errors.Is(err, ErrDuplicateIdempotencyKey) {
				return nil
			}
			return fmt.Errorf("payment.HandlePayoutReversed: %w", err)
		}
		return nil
	}

	ownerID, isOwnerWithdrawal, err := lookupOriginalWithdrawal(ctx, db, payload.ReferenceID)
	if err != nil {
		return fmt.Errorf("payment.HandlePayoutReversed: %w", err)
	}
	if isOwnerWithdrawal {
		idempotencyKey := withdrawalReversalIdempotencyKey(payload.ReferenceID)
		if err := InsertOwnerEscrowEvent(ctx, db, ownerID, OwnerDeposit, payload.AmountPaise, idempotencyKey, nil); err != nil {
			if errors.Is(err, ErrDuplicateIdempotencyKey) {
				return nil
			}
			return fmt.Errorf("payment.HandlePayoutReversed: %w", err)
		}
		return nil
	}

	// IC §7.2 failure mode: reference_id unknown in EITHER ledger -> the
	// caller should log at WARNING (this package has no logger injected) and
	// this handler returns nil (HTTP 200) rather than trigger indefinite
	// Razorpay retries.
	return nil
}

func lookupOriginalRelease(ctx context.Context, db *sql.DB, referenceID string) (providerID uuid.UUID, auditPeriodID uuid.UUID, ok bool, err error) {
	err = db.QueryRowContext(ctx, `
		SELECT provider_id, audit_period_id FROM escrow_events
		WHERE idempotency_key = $1 AND event_type = 'RELEASE'`,
		referenceID,
	).Scan(&providerID, &auditPeriodID)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.UUID{}, uuid.UUID{}, false, nil
	}
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, fmt.Errorf("look up original RELEASE: %w", err)
	}
	return providerID, auditPeriodID, true, nil
}

func lookupOriginalWithdrawal(ctx context.Context, db *sql.DB, referenceID string) (ownerID uuid.UUID, ok bool, err error) {
	err = db.QueryRowContext(ctx, `
		SELECT owner_id FROM owner_escrow_events
		WHERE idempotency_key = $1 AND event_type = 'WITHDRAWAL'`,
		referenceID,
	).Scan(&ownerID)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.UUID{}, false, nil
	}
	if err != nil {
		return uuid.UUID{}, false, fmt.Errorf("look up original WITHDRAWAL: %w", err)
	}
	return ownerID, true, nil
}

func reversalIdempotencyKey(originalIdempotencyKey string) string {
	h := sha256.New()
	h.Write([]byte("reversal"))
	h.Write([]byte(originalIdempotencyKey))
	return hex.EncodeToString(h.Sum(nil))
}

func withdrawalReversalIdempotencyKey(originalIdempotencyKey string) string {
	h := sha256.New()
	h.Write([]byte("withdrawal-reversal"))
	h.Write([]byte(originalIdempotencyKey))
	return hex.EncodeToString(h.Sum(nil))
}

// HandleAccountCreated processes account.created (IC §7.3). The cooling
// period is profile.RazorpayCoolingPeriod (24h in production, instant in
// demo — MVP §5.4), never a hardcoded duration. The
// razorpay_linked_account_id IS NULL guard makes this idempotent on
// redelivery.
func HandleAccountCreated(ctx context.Context, db *sql.DB, profile config.NetworkProfile, webhookSecret []byte, rawBody []byte, signature string, payload AccountCreatedWebhookPayload) error {
	if !verifyRazorpaySignature(rawBody, signature, webhookSecret) {
		return ErrInvalidWebhookSignature
	}

	// Postgres interval literals don't accept a Go time.Duration directly;
	// format as seconds explicitly (same convention used in
	// internal/repair/departure.go and queue.go for the same reason).
	intervalArg := fmt.Sprintf("%f seconds", profile.RazorpayCoolingPeriod.Seconds())

	const update = `
UPDATE providers
SET razorpay_linked_account_id = $1,
    razorpay_cooling_until = NOW() + $2::interval
WHERE provider_id = $3
  AND razorpay_linked_account_id IS NULL`
	if _, err := db.ExecContext(ctx, update, payload.AccountID, intervalArg, payload.ProviderID); err != nil {
		return fmt.Errorf("payment.HandleAccountCreated: %w", err)
	}
	return nil
}

// ── RazorpayProvider ───────────────────────────────────────────────────────────

// razorpayClient is the narrow subset of Razorpay's live HTTP API this
// provider needs. A real implementation — issuing genuine HTTPS calls to
// api.razorpay.com with live credentials — is out of scope for this
// environment (no live Razorpay account or network reachability to it from
// here); this interface exists so every OTHER concern (ledger writes,
// idempotency, balance queries, the deposit/reversal/cooling-period fixes
// above) is fully implemented and independently testable against a mock,
// the same pattern already used for internal/repair's RepairTransport
// (Milestone 9) and internal/audit's SecretsManagerClient (Milestone 7).
// Wiring in a genuine implementation is Milestone 12's concern.
type razorpayClient interface {
	// CreateVirtualAccount corresponds to Smart Collect 2.0 VPA assignment (ARCH §17).
	CreateVirtualAccount(ctx context.Context, ownerID uuid.UUID, amountPaise int64, contractID uuid.UUID) (vpa string, qrURL string, err error)
	// CreateTransfer corresponds to a Route transfer with on_hold_until set (ARCH §17).
	CreateTransfer(ctx context.Context, linkedAccountID string, amountPaise int64, idempotencyKey string, onHoldUntil time.Time) error
	// CreatePayout corresponds to a RazorpayX payout with no hold — used for
	// owner withdrawals (Session 10.5.1).
	CreatePayout(ctx context.Context, destinationUPI string, amountPaise int64, idempotencyKey string) (payoutID string, err error)
}

// RazorpayProvider is the live PaymentProvider implementation.
type RazorpayProvider struct {
	db     *sql.DB
	client razorpayClient
}

func NewRazorpayProvider(db *sql.DB, client razorpayClient) *RazorpayProvider {
	return &RazorpayProvider{db: db, client: client}
}

var _ PaymentProvider = (*RazorpayProvider)(nil)

// InitiateEscrow creates the Smart Collect virtual account. It does not
// itself credit any ledger — the actual DEPOSIT event is recorded
// asynchronously by HandleDepositCaptured once the owner's UPI payment is
// captured by Razorpay; creating a virtual account moves no money.
func (r *RazorpayProvider) InitiateEscrow(ctx context.Context, ownerID uuid.UUID, amountPaise int64, contractID uuid.UUID) (string, string, error) {
	vpa, qrURL, err := r.client.CreateVirtualAccount(ctx, ownerID, amountPaise, contractID)
	if err != nil {
		return "", "", fmt.Errorf("payment.RazorpayProvider.InitiateEscrow: %w", err)
	}
	return vpa, qrURL, nil
}

// ReleaseEscrow creates the Route transfer, on_hold_until the last business
// day of the current month (FR-048 — see lastBusinessDayOfMonth's own
// comment for a documented scope limitation), then records the RELEASE
// event.
func (r *RazorpayProvider) ReleaseEscrow(ctx context.Context, providerID uuid.UUID, amountPaise int64, auditPeriodID uuid.UUID, idempotencyKey string) error {
	linkedAccountID, err := r.providerLinkedAccountID(ctx, providerID)
	if err != nil {
		return fmt.Errorf("payment.RazorpayProvider.ReleaseEscrow: %w", err)
	}

	onHoldUntil := lastBusinessDayOfMonth(time.Now())
	if err := r.client.CreateTransfer(ctx, linkedAccountID, amountPaise, idempotencyKey, onHoldUntil); err != nil {
		return fmt.Errorf("payment.RazorpayProvider.ReleaseEscrow: create transfer: %w", err)
	}

	if err := InsertEscrowEvent(ctx, r.db, providerID, EscrowRelease, amountPaise, idempotencyKey, &auditPeriodID); err != nil {
		if errors.Is(err, ErrDuplicateIdempotencyKey) {
			return nil
		}
		return fmt.Errorf("payment.RazorpayProvider.ReleaseEscrow: %w", err)
	}
	return nil
}

// Penalise records the SEIZURE event. The actual escrow account freeze
// (providers.frozen = TRUE) is internal/repair's departure detector's
// responsibility (Milestone 9), not this method's — Penalise only seizes
// the ledger balance; it is called BY that detector via the
// PenaliseFunc-shaped injection point (internal/repair/departure.go).
// Penalise seizes amountPaise from providerID's escrow (silent departure).
//
// [Fixed, M10 corrections review Finding #3, defense-in-depth] see
// MockProvider.Penalise's identical guard for the full rationale — both
// PaymentProvider implementations must be safe against a zero/negative
// amount independent of the caller.
func (r *RazorpayProvider) Penalise(ctx context.Context, providerID uuid.UUID, amountPaise int64, idempotencyKey string) error {
	if amountPaise <= 0 {
		return nil
	}
	if err := InsertEscrowEvent(ctx, r.db, providerID, EscrowSeizure, amountPaise, idempotencyKey, nil); err != nil {
		if errors.Is(err, ErrDuplicateIdempotencyKey) {
			return nil
		}
		return fmt.Errorf("payment.RazorpayProvider.Penalise: %w", err)
	}
	return nil
}

// GetBalance queries mv_provider_escrow_balance — the SAME view
// MockProvider.GetBalance uses (Session 10.1.2), so both implementations
// report identically with no separate balance state.
func (r *RazorpayProvider) GetBalance(ctx context.Context, providerID uuid.UUID) (int64, error) {
	return providerBalance(ctx, r.db, providerID)
}

// WithdrawOwnerEscrow (Session 10.5.1) initiates a real Razorpay payout to
// the owner's UPI-linked bank account, then records a WITHDRAWAL event via
// InsertOwnerEscrowEvent. Balance check (available = balance - reserved
// next 30 days) and the in-flight-upload block are enforced by the caller
// (Milestone 11, Session 11.5.6) before this is invoked — this method
// trusts amountPaise as already validated.
func (r *RazorpayProvider) WithdrawOwnerEscrow(ctx context.Context, ownerID uuid.UUID, amountPaise int64, idempotencyKey string) (string, error) {
	upiHandle, err := r.ownerUPIHandle(ctx, ownerID)
	if err != nil {
		return "", fmt.Errorf("payment.RazorpayProvider.WithdrawOwnerEscrow: %w", err)
	}

	payoutID, err := r.client.CreatePayout(ctx, upiHandle, amountPaise, idempotencyKey)
	if err != nil {
		return "", fmt.Errorf("payment.RazorpayProvider.WithdrawOwnerEscrow: create payout: %w", err)
	}

	if err := InsertOwnerEscrowEvent(ctx, r.db, ownerID, OwnerWithdrawal, amountPaise, idempotencyKey, nil); err != nil {
		if errors.Is(err, ErrDuplicateIdempotencyKey) {
			return payoutID, nil
		}
		return "", fmt.Errorf("payment.RazorpayProvider.WithdrawOwnerEscrow: %w", err)
	}
	return payoutID, nil
}

func (r *RazorpayProvider) providerLinkedAccountID(ctx context.Context, providerID uuid.UUID) (string, error) {
	var linkedAccountID sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT razorpay_linked_account_id FROM providers WHERE provider_id = $1`, providerID).Scan(&linkedAccountID)
	if err != nil {
		return "", fmt.Errorf("look up linked account: %w", err)
	}
	if !linkedAccountID.Valid {
		return "", fmt.Errorf("provider %s has no razorpay_linked_account_id yet", providerID)
	}
	return linkedAccountID.String, nil
}

// ownerUPIHandle reuses smart_collect_vpa as the withdrawal destination —
// the schema has no separate payout-destination column for owners, and the
// same UPI address that legitimately receives a deposit can equally
// legitimately receive a payout.
func (r *RazorpayProvider) ownerUPIHandle(ctx context.Context, ownerID uuid.UUID) (string, error) {
	var vpa sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT smart_collect_vpa FROM owners WHERE owner_id = $1`, ownerID).Scan(&vpa)
	if err != nil {
		return "", fmt.Errorf("look up owner VPA: %w", err)
	}
	if !vpa.Valid {
		return "", fmt.Errorf("owner %s has no smart_collect_vpa provisioned yet", ownerID)
	}
	return vpa.String, nil
}

// lastBusinessDayOfMonth returns midnight on the last Monday-Friday day of
// the calendar month containing t (FR-048).
//
// Scope limitation, documented rather than fabricated: FR-048 additionally
// requires accounting for RBI bank holidays via "a static
// rbi_bank_holidays_YYYY table updated each December" — externally-sourced
// calendar data this package has no access to. This function is a
// weekend-only approximation; wiring in the real RBI table is a follow-up
// once that data is available (same category of honest scope note as
// internal/repair's departure detector reusing PollingInterval, Milestone 9).
func lastBusinessDayOfMonth(t time.Time) time.Time {
	firstOfNextMonth := time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
	lastDay := firstOfNextMonth.AddDate(0, 0, -1)
	for lastDay.Weekday() == time.Saturday || lastDay.Weekday() == time.Sunday {
		lastDay = lastDay.AddDate(0, 0, -1)
	}
	return lastDay
}

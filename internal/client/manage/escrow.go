// Package manage is declared in doc.go.
// This file implements escrow balance, deposit, and withdrawal (Session
// 15.4.2, FR-021, FR-059).
//
// PRECONDITION (per this session's own TASK text): the live
// DepositInitiateResponse (docs/api/openapi.yaml) currently returns only
// vpa/qr_code_url/expires_at — ADR-035 (intent_url) is Proposed, not
// merged. Deposit renders against BOTH possible response shapes: if
// intent_url is present, it's the primary, copyable output (ADR-035 §3's
// specified client behavior); if absent, this falls back to vpa +
// qr_code_url, so this session does not block on ADR-035 landing first and
// needs no rework once it does.
//
// [REF: FR-021, FR-059, ADR-035, OAS OwnerBalance/DepositInitiateResponse/
// WithdrawRequest/WithdrawResponse, IC §11 (no floating point on any
// payment-adjacent path), MVP §8.2 Phase 15.4 Session 15.4.2]

package manage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ── GET /api/v1/owner/{owner_id}/balance ───────────────────────────────────

type ownerBalanceResponse struct {
	BalancePaise         int64 `json:"balance_paise"`
	ReservedNext30dPaise int64 `json:"reserved_next_30d_paise"`
	AvailablePaise       int64 `json:"available_paise"`
}

// Balance calls GET /api/v1/owner/{owner_id}/balance and returns all three
// figures as integer paise (IC §11's payment-path rule applied here even
// though this is a read-only client display, not internal/payment itself —
// no floating point on any payment-adjacent path).
func (m *Manager) Balance(ctx context.Context, ownerID uuid.UUID) (balancePaise, reservedNext30dPaise, availablePaise int64, err error) {
	var resp ownerBalanceResponse
	httpResp, rawBody, err := m.api.doJSON(ctx, http.MethodGet, "/api/v1/owner/"+ownerID.String()+"/balance", nil, &resp)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("manage: Balance: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return 0, 0, 0, fmt.Errorf("manage: Balance: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return 0, 0, 0, fmt.Errorf("manage: Balance: unexpected status %d", httpResp.StatusCode)
	}
	return resp.BalancePaise, resp.ReservedNext30dPaise, resp.AvailablePaise, nil
}

// ── POST /api/v1/owner/deposit ─────────────────────────────────────────────

type depositInitiateRequest struct {
	AmountPaise    int64  `json:"amount_paise"`
	IdempotencyKey string `json:"idempotency_key"`
}

type depositInitiateResponse struct {
	VPA       string    `json:"vpa"`
	QRCodeURL string    `json:"qr_code_url"`
	IntentURL *string   `json:"intent_url,omitempty"` // ADR-035 — pending merge; see PRECONDITIONS
	ExpiresAt time.Time `json:"expires_at"`
}

// DepositInfo is what the caller (CLI/GUI) should render.
type DepositInfo struct {
	// PrimaryOutput is intent_url when present (ADR-035 §3: "the client
	// renders this directly"), otherwise vpa (PRECONDITIONS fallback).
	PrimaryOutput string
	QRCodeURL     string
	UsesIntentURL bool
	ExpiresAt     time.Time
}

// DepositRequestID is the client-generated, per-deposit-attempt identifier
// Deposit's idempotency key is derived from — the same shape and purpose
// as WithdrawalRequestID above (generate once per attempt, reuse across
// retries of that same attempt).
//
// [Bug found and fixed, M17 Session 17.2.1 live verification] Deposit
// previously sent no idempotency_key at all — internal/api/owner.go's
// OwnerDepositHandler has required a 64-hex-char one since at least this
// package's own withdrawIdempotencyKey precedent was written (this file
// already had the pattern for Withdraw; Deposit was simply never brought
// in line with it). Every prior unit test in this package used a mock
// server that didn't enforce the real validation, so this went uncaught
// until a live TestDemoCLIFullLifecycle run hit the real microservice and
// got a 400 INVALID_REQUEST back. Fixed here rather than papered over in
// cmd/client, since the missing field was in the SDK's own request
// construction, not anything the CLI does.
type DepositRequestID = uuid.UUID

// depositIdempotencyKey computes the same shape of key
// withdrawIdempotencyKey does, for the same reason: deterministic from
// (ownerID, depositRequestID), so retry-safety is a property of Deposit's
// signature rather than something a caller could get wrong by
// regenerating a key inline.
func depositIdempotencyKey(ownerID uuid.UUID, depositRequestID DepositRequestID) string {
	input := make([]byte, 0, len(ownerID)+len(depositRequestID))
	input = append(input, ownerID[:]...)
	input = append(input, depositRequestID[:]...)
	sum := sha256.Sum256(input)
	return fmt.Sprintf("%x", sum)
}

// Deposit calls POST /api/v1/owner/deposit. depositRequestID must be the
// same value across every retry of a single deposit attempt (see
// DepositRequestID's own doc comment).
func (m *Manager) Deposit(ctx context.Context, ownerID uuid.UUID, depositRequestID DepositRequestID, amountPaise int64) (DepositInfo, error) {
	key := depositIdempotencyKey(ownerID, depositRequestID)
	var resp depositInitiateResponse
	httpResp, rawBody, err := m.api.doJSON(ctx, http.MethodPost, "/api/v1/owner/deposit",
		depositInitiateRequest{AmountPaise: amountPaise, IdempotencyKey: key}, &resp)
	if err != nil {
		return DepositInfo{}, fmt.Errorf("manage: Deposit: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK && httpResp.StatusCode != http.StatusCreated {
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return DepositInfo{}, fmt.Errorf("manage: Deposit: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return DepositInfo{}, fmt.Errorf("manage: Deposit: unexpected status %d", httpResp.StatusCode)
	}

	if resp.IntentURL != nil && *resp.IntentURL != "" {
		return DepositInfo{PrimaryOutput: *resp.IntentURL, QRCodeURL: resp.QRCodeURL, UsesIntentURL: true, ExpiresAt: resp.ExpiresAt}, nil
	}
	// Fallback (PRECONDITIONS): intent_url absent — render vpa + qr_code_url.
	return DepositInfo{PrimaryOutput: resp.VPA, QRCodeURL: resp.QRCodeURL, UsesIntentURL: false, ExpiresAt: resp.ExpiresAt}, nil
}

// ── POST /api/v1/owner/withdraw ────────────────────────────────────────────

type withdrawRequest struct {
	AmountPaise    int64  `json:"amount_paise"`
	IdempotencyKey string `json:"idempotency_key"` // hex SHA-256(owner_id || withdrawal_request_id)
}

type withdrawResponse struct {
	PayoutID    string `json:"payout_id"`
	AmountPaise int64  `json:"amount_paise"`
	Status      string `json:"status"`
}

// WithdrawalRequestID is the client-generated, per-withdrawal-attempt
// identifier FR-059's idempotency key is derived from. Callers must
// generate this ONCE (e.g. via uuid.NewV7()) when a withdrawal attempt
// first begins, hold onto it for the lifetime of that attempt, and pass the
// SAME value into every Withdraw call for that attempt — including
// retries. A fresh value on retry would defeat the idempotency guarantee
// FR-059 exists for.
type WithdrawalRequestID = uuid.UUID

// ErrWithdrawBlockedUploadInFlight surfaces HTTP 409 as an explicit,
// actionable message (TASK step 3) rather than a generic error — the
// withdrawal is blocked because an upload is currently in flight, not
// rejected for any other reason.
var ErrWithdrawBlockedUploadInFlight = errors.New("manage: withdrawal blocked: an upload is currently in flight for this account — try again once it completes")

// withdrawIdempotencyKey computes FR-059's idempotency key:
// SHA-256(owner_id || withdrawal_request_id), hex-encoded. Deterministic —
// calling this again with the same (ownerID, withdrawalRequestID) always
// produces the same key, which is what makes retry-safety a property of
// Withdraw's own signature (callers only need to keep withdrawalRequestID
// stable, not cache the derived key itself) rather than something a caller
// could get wrong by regenerating a key inline.
func withdrawIdempotencyKey(ownerID uuid.UUID, withdrawalRequestID WithdrawalRequestID) string {
	input := make([]byte, 0, len(ownerID)+len(withdrawalRequestID))
	input = append(input, ownerID[:]...)
	input = append(input, withdrawalRequestID[:]...)
	sum := sha256.Sum256(input)
	return fmt.Sprintf("%x", sum)
}

// Withdraw calls POST /api/v1/owner/withdraw. withdrawalRequestID must be
// the same value across every retry of a single withdrawal attempt (see
// WithdrawalRequestID's own doc comment) — this function never generates
// one internally, so retry-safety depends entirely on the caller reusing
// the value it was given, not on anything this function does per call.
func (m *Manager) Withdraw(ctx context.Context, ownerID uuid.UUID, withdrawalRequestID WithdrawalRequestID, amountPaise int64) (payoutID string, err error) {
	key := withdrawIdempotencyKey(ownerID, withdrawalRequestID)
	var resp withdrawResponse
	httpResp, rawBody, err := m.api.doJSON(ctx, http.MethodPost, "/api/v1/owner/withdraw",
		withdrawRequest{AmountPaise: amountPaise, IdempotencyKey: key}, &resp)
	if err != nil {
		return "", fmt.Errorf("manage: Withdraw: %w", err)
	}

	switch httpResp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return resp.PayoutID, nil
	case http.StatusConflict:
		return "", ErrWithdrawBlockedUploadInFlight
	default:
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return "", fmt.Errorf("manage: Withdraw: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return "", fmt.Errorf("manage: Withdraw: unexpected status %d", httpResp.StatusCode)
	}
}

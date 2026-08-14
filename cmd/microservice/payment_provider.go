// cmd/microservice — see main.go's package doc comment.
//
// This file selects the payment.PaymentProvider per profile.PaymentMode
// (this session's step 12).
//
// [Decision — real Razorpay client deferred] internal/payment/razorpay.go's
// own header comment scopes a genuine Razorpay HTTP client
// ("issuing genuine HTTPS calls to api.razorpay.com with live credentials")
// as out of scope for "this environment" and says wiring one in "is
// Milestone 12's concern" — naming this session. Building it properly means
// committing to exact request/response JSON shapes for Smart Collect 2.0
// (virtual accounts), Route (transfers), and RazorpayX (payouts) against
// Razorpay's live API surface, none of which any document in scope (MVP,
// ARCH, IC, DM) specifies, and which this sandbox cannot validate against a
// live or sandbox endpoint (network egress here does not reach
// api.razorpay.com). Unlike the p2p.Host/RepairTransport wiring below (a
// subsystem that already fully exists and only needed a small adapter),
// there is no existing Razorpay HTTP client anywhere in this codebase to
// wire in — building one now would mean inventing a financial integration's
// wire format from memory, with no way to verify it here, which is a
// materially different (and materially riskier) kind of gap than the
// stub-until-Milestone-17 pattern used elsewhere in this session
// (cluster membership, client-driven routing, the real secrets-manager
// adapter). notImplementedRazorpayClient below fails closed on every call,
// exactly as notImplementedSecretsClient does for the same reason — a
// real implementation is flagged here as follow-up work, not silently
// guessed at.
//
// [REF: IC §5.8, ADR-011, ADR-012, build.md Milestone 12 Phase 12.1
// Session 12.1.1]
package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/payment"
)

// notImplementedRazorpayClient satisfies internal/payment's unexported
// razorpayClient interface structurally (CreateVirtualAccount,
// CreateTransfer, CreatePayout — see razorpay.go) via Go's structural
// interface satisfaction, without either package needing to export or
// import a shared interface type. See this file's header note for why a
// real implementation is not built here. Method signatures below are copied
// exactly from internal/payment/razorpay.go's unexported razorpayClient
// interface — Go requires an exact method-set match for structural
// satisfaction.
type notImplementedRazorpayClient struct{}

var errRazorpayClientNotImplemented = fmt.Errorf(
	"cmd/microservice: no real Razorpay HTTP client is wired yet (flagged in payment_provider.go); " +
		"profile.PaymentMode must be \"mock\" until one is built")

func (notImplementedRazorpayClient) CreateVirtualAccount(context.Context, uuid.UUID, int64, uuid.UUID) (vpa string, qrURL string, err error) {
	return "", "", errRazorpayClientNotImplemented
}

func (notImplementedRazorpayClient) CreateTransfer(context.Context, string, int64, string, time.Time) error {
	return errRazorpayClientNotImplemented
}

func (notImplementedRazorpayClient) CreatePayout(context.Context, string, int64, string) (payoutID string, err error) {
	return "", errRazorpayClientNotImplemented
}

// buildPaymentProvider selects the payment.PaymentProvider per
// profile.PaymentMode (this session's step 12): payment.NewMockProvider for
// "mock" (demo), payment.NewRazorpayProvider wrapping
// notImplementedRazorpayClient for "razorpay_test"/"razorpay_live" (prod) —
// see this file's header note on why the latter fails closed rather than
// making real HTTPS calls.
func buildPaymentProvider(db *sql.DB, profile config.NetworkProfile) payment.PaymentProvider {
	if profile.PaymentMode == "mock" {
		return payment.NewMockProvider(db)
	}
	return payment.NewRazorpayProvider(db, notImplementedRazorpayClient{})
}

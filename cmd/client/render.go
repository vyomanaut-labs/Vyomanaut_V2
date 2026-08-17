// interface-contracts.md §14.1 is the single canonical mapping from
// error_code to end-user copy — cmd/client renders from this table, never
// from a server error's raw `message` field (§3.3: "may change between
// releases") and never from a bare err.Error(). This file transcribes
// §14.1 verbatim (28 rows; 6 are marked n/a in this codebase's live
// error.go and are deliberately omitted here — an n/a code should never
// reach cmd/client, and if one somehow does, renderError's fallback rule
// below still produces honest, IC §14.1-specified copy instead of a
// missing-map-entry crash) and also §14.2's file-availability labels for
// later sessions (17.1.3) to use unchanged.
//
// [REF: interface-contracts.md §14.1, §14.2, ADR-034]
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/account"
)

// copyEntry is one row of IC §14.1.
type copyEntry struct {
	headline string
	body     string
	action   string
	severity string // info | action-required | transient-retry | escalate
}

// copyTable is IC §14.1's table, transcribed verbatim (headline/body/
// action text unchanged). Keyed by the wire error_code string exactly as
// internal/api/errors.go declares it.
var copyTable = map[string]copyEntry{
	"INVALID_REQUEST": {
		headline: "That didn't go through",
		body:     "Something in the request wasn't formatted correctly.",
		action:   "Update to the latest client version and try again; if it keeps happening, contact support with the request ID. Usually a client-side defect, not a user mistake.",
		severity: "escalate",
	},
	"PROVIDER_DEPARTED": {
		headline: "This provider has left the network",
		body:     "Your provider record is marked departed and can no longer serve requests.",
		action:   "If this is unexpected, re-register via cmd/provider register to rejoin.",
		severity: "action-required",
	},
	"ESCROW_FROZEN": {
		headline: "Your account is frozen",
		body:     "Your escrow balance is frozen pending a dispute or seizure review.",
		action:   "Contact support — this isn't something to retry.",
		severity: "escalate",
	},
	"NETWORK_NOT_READY": {
		headline: "Uploads are paused network-wide",
		body:     "The network hasn't met its minimum readiness conditions yet.",
		action:   "Retrying automatically — no action needed.",
		severity: "transient-retry",
	},
	"INSUFFICIENT_ASN_DIVERSITY": {
		headline: "Upload paused",
		body:     "Not enough provider diversity right now.",
		action:   "Retry will happen automatically when the network recovers.",
		severity: "transient-retry",
	},
	"RAZORPAY_UNAVAILABLE": {
		headline: "Payment service is temporarily down",
		body:     "We couldn't reach the payment provider just now.",
		action:   "Try again in a few minutes.",
		severity: "transient-retry",
	},
	"INTERNAL_ERROR": {
		headline: "Something went wrong on our end",
		body:     "An unexpected error occurred.",
		action:   "Try again; if it persists, contact support with the request ID shown.",
		severity: "escalate",
	},
	"UNAUTHORIZED": {
		headline: "You've been signed out",
		body:     "Your session token is missing, expired, or invalid.",
		action:   "Log in again.",
		severity: "action-required",
	},
	"INSUFFICIENT_ESCROW_BALANCE": {
		headline: "Add funds to continue",
		body:     "Your balance won't cover 30 days of storage for this file.",
		action:   "Top up your balance, then retry the upload.",
		severity: "action-required",
	},
	"INVALID_PHONE_NUMBER": {
		headline: "Check that phone number",
		body:     "The number entered isn't in a recognized format.",
		action:   "Re-enter your number including the country code.",
		severity: "action-required",
	},
	"INVALID_AMOUNT": {
		headline: "Enter a valid amount",
		body:     "The amount needs to be a positive number.",
		action:   "Re-enter the amount and try again.",
		severity: "action-required",
	},
	"WRONG_ROLE": {
		headline: "Wrong kind of account for this",
		body:     "This action needs a different account type than the one signed in.",
		action:   "Switch accounts, or check you're running the right command (cmd/client vs. cmd/provider).",
		severity: "action-required",
	},
	"INVALID_BODY_SIGNATURE": {
		headline: "Couldn't verify that request",
		body:     "The cryptographic signature on this request didn't check out.",
		action:   "Usually a client bug or a corrupted local key. Try again; if it persists, check your keystore or contact support.",
		severity: "escalate",
	},
	"NOT_FOUND": {
		headline: "Couldn't find that",
		body:     "The file or provider referenced doesn't exist, or you don't have access to it.",
		action:   "Double-check the ID and try again.",
		severity: "action-required",
	},
	"PHONE_ALREADY_REGISTERED": {
		headline: "That number is already registered",
		body:     "An account already exists for this phone number.",
		action:   "Log in instead, or use account recovery if you've lost access.",
		severity: "action-required",
	},
	"OTP_RATE_LIMITED": {
		headline: "Too many attempts",
		body:     "You've requested a verification code too many times.",
		action:   "Wait for the cooldown shown, then try again.",
		severity: "transient-retry",
	},
	"INVALID_OTP": {
		headline: "That code didn't match",
		body:     "The verification code entered is wrong or has expired.",
		action:   "Request a new code and try again.",
		severity: "action-required",
	},
	"TOKEN_REFRESH_RATE_LIMITED": {
		headline: "Session refresh on cooldown",
		body:     "Your daemon tried to refresh its session token too soon.",
		action:   "Automatic — the daemon retries after the cooldown. No action needed.",
		severity: "transient-retry",
	},
	"DOWNTIME_ALREADY_ACTIVE": {
		headline: "Downtime window already open",
		body:     "You've already reported planned downtime that hasn't ended yet.",
		action:   "No action needed. If this is unexpected, check your daemon's status.",
		severity: "info",
	},
	"FILE_ALREADY_DELETED": {
		headline: "Already deleted",
		body:     "This file was already removed.",
		action:   "No action needed.",
		severity: "info",
	},
	"FILE_ALREADY_REGISTERED": {
		headline: "Already uploaded",
		body:     "A file with this ID has already been registered.",
		action:   "If this wasn't intentional, check your upload history before retrying.",
		severity: "info",
	},
	"INSUFFICIENT_PROVIDER_CAPACITY": {
		headline: "Not enough storage available right now",
		body:     "The network doesn't have enough free provider capacity for this upload size.",
		action:   "Try again later, or try a smaller file.",
		severity: "transient-retry",
	},
}

// codedError is the minimal, cross-package shape every internal/client/*
// package's own API error type must satisfy for renderError to map it
// through IC §14.1 — a structural interface, not a shared type, so each
// package's existing package-local error type (manage/upload/retrieve's
// own unexported apiError; this session's account.RegistrationError) can
// implement it with one added method rather than needing a shared
// exported type across packages. Only account.RegistrationError
// implements this today (Session 17.1.1) — manage/upload/retrieve's own
// apiError types need the same one-line method when Sessions 17.1.2/
// 17.1.3 wire them in. Flagged here, not silently assumed.
type codedError interface {
	ErrorCode() string
}

// renderError maps any error from an internal/client/* call to IC §14.1's
// end-user copy. Two local (non-server) sentinels get mapped to the
// closest existing row rather than invented copy, per §14.1's own
// "authoritative for tone and wording" rule:
//   - account.ErrWrongRoleForOwnerCLI -> WRONG_ROLE (same underlying
//     situation the row's own wording already covers: "check you're
//     running the right command").
//   - account.ErrInvalidRecoveryPhrase -> rendered as-is; its own message
//     is already the deliberately generic, end-user-appropriate text IC
//     §5.1's timing-oracle warning requires (see recover.go's own doc
//     comment), and §14.1 has no dedicated row for a client-side-only
//     mnemonic checksum failure that never reaches the server.
func renderError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, account.ErrWrongRoleForOwnerCLI) {
		return formatCopy(copyTable["WRONG_ROLE"])
	}
	if errors.Is(err, account.ErrInvalidRecoveryPhrase) {
		return account.ErrInvalidRecoveryPhrase.Error()
	}

	var ce codedError
	if errors.As(err, &ce) {
		entry, ok := copyTable[ce.ErrorCode()]
		if !ok {
			// IC §14.1's fallback rule, verbatim: any error_code without a
			// row (including one added to §3.3 after this table was last
			// updated) renders this exact copy, logged client-side as a
			// warning so the gap is caught in testing rather than shipped
			// silently.
			log.Printf("[WARN] no IC §14.1 copy row for error_code=%q", ce.ErrorCode())
			return fmt.Sprintf("Something went wrong (code: %s). Try again, or contact support with this code.", ce.ErrorCode())
		}
		return formatCopy(entry)
	}

	// No server error_code at all: a local/network-level failure (dial
	// error, timeout, local file I/O). Outside §14.1's literal scope (it
	// maps error_code, and there isn't one here) but the same spirit
	// applies — never a bare Go error string with no context.
	return fmt.Sprintf("Something went wrong: %v", err)
}

func formatCopy(e copyEntry) string {
	return fmt.Sprintf("%s\n%s\n%s", e.headline, e.body, e.action)
}

// printCLIError writes err to errOut in whichever mode jsonMode calls for:
// renderError's human-readable IC §14 copy normally, or a
// {"error_code":...,"message":...} JSON object when --json is set — so a
// failed invocation is exactly as parseable as a successful one. humanRender
// lets each dispatch file supply its own human-copy function (renderError
// generically; transfer_cmds.go's renderTransferError, which additionally
// handles four local, non-server sentinels) while every call site shares
// one JSON path. Every dispatchX function in this package should route
// through this rather than calling fmt.Fprintln(errOut, renderError(err))
// directly, which silently stays human-readable even under --json.
func printCLIError(errOut io.Writer, jsonMode bool, err error, humanRender func(error) string) {
	if jsonMode {
		fmt.Fprintln(errOut, renderErrorJSON(err))
		return
	}
	fmt.Fprintln(errOut, humanRender(err))
}

// errorCodeOf extracts the raw error_code from err for --json error
// output, distinct from renderError's human-readable multi-line copy.
// Returns "" when err carries no server error_code.
func errorCodeOf(err error) string {
	var ce codedError
	if errors.As(err, &ce) {
		return ce.ErrorCode()
	}
	return ""
}

// marshalJSONNoEscape is cmd/client's only JSON encoder for --json output.
// encoding/json.Marshal HTML-escapes <, >, and & by default (a
// browser-embedding safeguard irrelevant to a CLI's stdout) — which would
// silently corrupt ADR-035's server-supplied intent_url (a UPI deep link,
// always containing literal & between query parameters) if any call site
// used json.Marshal directly. Every --json output in this package goes
// through this function instead, so "render exactly as returned" holds
// for every field this package ever emits, not only intent_url.
func marshalJSONNoEscape(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return `{"message":"an error occurred and could not be formatted as JSON"}`
	}
	return strings.TrimRight(buf.String(), "\n")
}

// jsonErrorOutput is --json mode's error shape — the error_code plus a
// short message, never the full multi-line human copy and never a raw Go
// error string.
type jsonErrorOutput struct {
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message"`
}

func renderErrorJSON(err error) string {
	out := jsonErrorOutput{ErrorCode: errorCodeOf(err), Message: err.Error()}
	return marshalJSONNoEscape(out)
}

// ── register/recover JSON output shapes ─────────────────────────────────
//
// Neither struct below has any field capable of carrying a mnemonic —
// structurally, not just by omission — satisfying MNEMONIC_NEVER_LOGGED_
// OR_SERIALISED's json-tag check across every file in this package, not
// merely account_cmds.go.

type registerOutput struct {
	OwnerID    string `json:"owner_id"`
	Registered bool   `json:"registered"`
}

func renderRegisterJSON(ownerID uuid.UUID) string {
	return marshalJSONNoEscape(registerOutput{OwnerID: ownerID.String(), Registered: true})
}

type recoverOutput struct {
	OwnerID            string `json:"owner_id"`
	Recovered          bool   `json:"recovered"`
	SigningKeyRestored bool   `json:"signing_key_restored"`
}

func renderRecoverJSON(ownerID uuid.UUID, signingKeyRestored bool) string {
	return marshalJSONNoEscape(recoverOutput{OwnerID: ownerID.String(), Recovered: true, SigningKeyRestored: signingKeyRestored})
}

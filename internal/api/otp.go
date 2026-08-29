// Package api is declared in doc.go.
// This file implements POST /api/v1/auth/otp/send and
// POST /api/v1/auth/otp/verify.
//
// [Decision, registration-token subject] OAS BearerAuth describes "sub
// (entity UUID)", but a registration token (is_new_entity == true) has no
// entity yet — no owners/providers row exists until the subsequent register
// call succeeds. The registration token's sub is
// UUIDv5(phoneNumberNamespace, phone_number) — deterministic, but this
// derivation is NOT invertible: given only the UUID, the register endpoint
// cannot recover the original phone_number, and OAS's
// OwnerRegisterRequest/ProviderRegisterRequest schemas have no phone_number
// field to be told it directly. pending_registrations (added to the schema
// for this reason) bridges the gap: this file writes a row at issuance
// time; RecoverPendingRegistration/DeletePendingRegistration (exported
// below) let the register endpoints redeem it exactly once.
//
// This file also declares the OtpSender interface HandleSend delivers a
// code through, and its two implementations: NoopOtpSender (does nothing;
// production, until a real SMS gateway is wired in) and FileOtpSender
// (M17-E Session 17.4.2, ADR-084 §D-3 — appends each OTP to a demo-mode
// delivery log on disk, cmd/microservice's own --otp-delivery-log /
// VYOMANAUT_OTP_DELIVERY_LOG, fatal to enable outside demo mode). Neither
// implementation nor the interface changes anything about otp_codes
// itself: the database only ever stores code_hash, regardless of which
// sender delivered the plaintext.
//
// [REF: FR-001, OAS OtpSendRequest/Response, OtpVerifyRequest/Response,
// build.md Phase 11.4; ADR-084 §D-3, build_part3.md Phase 17.4 Session
// 17.4.2 (FileOtpSender)]

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	otpCodeLength = 6
	otpTTL        = 10 * time.Minute

	// [M11 audit remediation, Finding 3] Was 1*time.Hour / 5 — build.md
	// Session 11.4.1 (and OAS otp/send's 429 response, which documents
	// Retry-After: 600 with "3 attempts per phone per 10 minutes" in its
	// description) both require 3 attempts per 10 minutes. The previous
	// values sent Retry-After: 3600 to a client the spec told to wait 600
	// seconds, and let a 4th send through in the same 10-minute window that
	// should have been rejected. See otp_test.go's TestOtpSendRateLimited
	// for why the old test didn't catch this: it looped
	// otpRateLimitMax times, so it passed unchanged regardless of what
	// that constant was set to.
	otpRateLimitWindow = 10 * time.Minute
	otpRateLimitMax    = 3 // max OTP sends per phone_number+purpose per window
)

// otpMaxCodeValue is the exclusive upper bound for a 6-digit code (000000-999999).
const otpMaxCodeValue = 1000000

// phoneNumberNamespace is a fixed, arbitrary namespace UUID for deriving a
// registration token's deterministic subject (see this file's header note).
// Any fixed UUID works here — RFC 4122's own DNS namespace UUID is reused
// rather than minting a new arbitrary constant, since it is already a
// well-known, unambiguous fixed value.
var phoneNumberNamespace = uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

// RegistrationSubjectForPhone derives the deterministic pre-registration
// JWT subject for phoneNumber (see this file's header note). Exported so
// Phase 11.5's register handlers can independently re-derive and compare
// against the registration token's own sub claim.
func RegistrationSubjectForPhone(phoneNumber string) uuid.UUID {
	return uuid.NewSHA1(phoneNumberNamespace, []byte(phoneNumber))
}

var phoneNumberPattern = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

var validOtpPurposes = map[string]bool{
	"OWNER_REGISTER":    true,
	"PROVIDER_REGISTER": true,
	"LOGIN":             true,
}

var otpCodePattern = regexp.MustCompile(`^\d{6}$`)

// OtpSender abstracts over actual SMS delivery — no real integration
// (Twilio, MSG91, etc.) exists anywhere in scope for this milestone.
// Injected so this handler is fully implemented and testable now, with a
// real implementation wired in whenever SMS delivery is actually built
// (same pattern as internal/payment's razorpayClient, Milestone 10).
type OtpSender interface {
	SendOTP(ctx context.Context, phoneNumber, code string) error
}

// NoopOtpSender does nothing but succeed — suitable for demo mode, where
// there is no real SMS integration and the operator retrieves the code some
// other way (e.g. reading otp_codes directly in a demo/dev environment).
type NoopOtpSender struct{}

func (NoopOtpSender) SendOTP(context.Context, string, string) error { return nil }

// FileOtpSender is a real OtpSender implementation (ADR-084 D-3, M17-E
// Session 17.4.2): it appends each OTP to a delivery log on disk — mode
// 0600, append-only — instead of doing nothing (NoopOtpSender) or requiring
// a database read (the rejected alternative; see ADR-084 §D-3, which
// weighed this against a demo-mode endpoint returning the plaintext code
// and against an `operator otp` command brute-forcing otp_codes.code_hash).
// This is what a real SMS gateway's own delivery log looks like: the
// gateway holds the plaintext code transiently, the database never does —
// otp_codes.code_hash stays hash-only regardless of which OtpSender is
// wired in at cmd/microservice/main.go.
//
// Never served over HTTP and read by no handler in this package. The only
// intended reader is cmd/operator's `otp` subcommand (a later M17-E
// session), tailing the file directly — the same authority a human
// onboarding as a provider (cmd/provider's `onboard` subcommand,
// M17-E Session 17.4.2) does not have and is not given.
type FileOtpSender struct {
	mu   sync.Mutex
	file *os.File
}

const otpLogFileMode fs.FileMode = 0600

// NewFileOtpSender opens (creating if absent) the delivery log at path,
// mode 0600, for append-only writes. The file is opened ONCE, here, for
// this sender's lifetime — not reopened per SendOTP call — matching how a
// long-lived gateway client would actually behave.
func NewFileOtpSender(path string) (*FileOtpSender, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, otpLogFileMode)
	if err != nil {
		return nil, fmt.Errorf("api: NewFileOtpSender: open %s: %w", path, err)
	}
	return &FileOtpSender{file: f}, nil
}

// Close releases the underlying file handle. Safe to call once, typically
// at daemon shutdown (cmd/microservice/main.go's app.shutdown).
func (s *FileOtpSender) Close() error {
	return s.file.Close()
}

var _ OtpSender = (*FileOtpSender)(nil)

// SendOTP appends one line to the delivery log:
//
//	<RFC3339 UTC timestamp>  <phone_number>  <code>
//
// Writes are serialized under s.mu — concurrent HandleSend calls
// (multiple in-flight OTP requests) must never interleave partial writes
// into the log.
func (s *FileOtpSender) SendOTP(_ context.Context, phoneNumber, code string) error {
	line := fmt.Sprintf("%s  %s  %s\n", time.Now().UTC().Format(time.RFC3339), phoneNumber, code)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.file.WriteString(line); err != nil {
		return fmt.Errorf("api: FileOtpSender.SendOTP: write: %w", err)
	}
	return nil
}

// OtpHandler holds the dependencies for both OTP endpoints.
type OtpHandler struct {
	db     *sql.DB
	sender OtpSender
}

func NewOtpHandler(db *sql.DB, sender OtpSender) *OtpHandler {
	return &OtpHandler{db: db, sender: sender}
}

type otpSendRequestBody struct {
	PhoneNumber string `json:"phone_number"`
	Purpose     string `json:"purpose"`
}

type otpSendResponseBody struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// HandleSend serves POST /api/v1/auth/otp/send.
func (h *OtpHandler) HandleSend(w http.ResponseWriter, r *http.Request) {
	var req otpSendRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	if !phoneNumberPattern.MatchString(req.PhoneNumber) {
		WriteError(w, http.StatusBadRequest, ErrInvalidPhoneNumber, "phone_number must be E.164 format", nil, "phone_number", nil)
		return
	}
	if !validOtpPurposes[req.Purpose] {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "purpose must be OWNER_REGISTER, PROVIDER_REGISTER, or LOGIN", nil, "purpose", nil)
		return
	}

	ctx := r.Context()
	limited, err := h.isRateLimited(ctx, req.PhoneNumber, req.Purpose)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "rate limit check failed", nil, "", nil)
		return
	}
	if limited {
		retryAfter := int(otpRateLimitWindow.Seconds())
		WriteError(w, http.StatusTooManyRequests, ErrOTPRateLimited, "too many OTP requests for this phone number", &retryAfter, "", nil)
		return
	}

	code, err := generateOtpCode()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to generate OTP", nil, "", nil)
		return
	}
	expiresAt := time.Now().UTC().Add(otpTTL)
	codeHash := sha256.Sum256([]byte(code))

	if _, err := h.db.ExecContext(ctx, `
		INSERT INTO otp_codes (phone_number, purpose, code_hash, expires_at)
		VALUES ($1, $2, $3, $4)`,
		req.PhoneNumber, req.Purpose, codeHash[:], expiresAt,
	); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to store OTP", nil, "", nil)
		return
	}

	if err := h.sender.SendOTP(ctx, req.PhoneNumber, code); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to send OTP", nil, "", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(otpSendResponseBody{ExpiresAt: expiresAt})
}

func (h *OtpHandler) isRateLimited(ctx context.Context, phoneNumber, purpose string) (bool, error) {
	var count int
	windowArg := fmt.Sprintf("%f seconds", otpRateLimitWindow.Seconds())
	err := h.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM otp_codes
		WHERE phone_number = $1 AND purpose = $2 AND created_at > NOW() - $3::interval`,
		phoneNumber, purpose, windowArg,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("isRateLimited: %w", err)
	}
	return count >= otpRateLimitMax, nil
}

func generateOtpCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(otpMaxCodeValue))
	if err != nil {
		return "", fmt.Errorf("generateOtpCode: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// ── Verify ─────────────────────────────────────────────────────────────────────

type otpVerifyRequestBody struct {
	PhoneNumber string `json:"phone_number"`
	OtpCode     string `json:"otp_code"`
}

type otpVerifyResponseBody struct {
	Token       string  `json:"token"`
	Role        *string `json:"role"`
	EntityID    *string `json:"entity_id,omitempty"`
	IsNewEntity bool    `json:"is_new_entity"`
}

// OtpVerifyHandler holds the additional signing-key dependency
// HandleVerify needs beyond OtpHandler's own (db, sender).
type OtpVerifyHandler struct {
	*OtpHandler
	signingKey ed25519.PrivateKey
}

func NewOtpVerifyHandler(otp *OtpHandler, signingKey ed25519.PrivateKey) *OtpVerifyHandler {
	return &OtpVerifyHandler{OtpHandler: otp, signingKey: signingKey}
}

// HandleVerify serves POST /api/v1/auth/otp/verify.
func (h *OtpVerifyHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	var req otpVerifyRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	if !phoneNumberPattern.MatchString(req.PhoneNumber) {
		WriteError(w, http.StatusBadRequest, ErrInvalidPhoneNumber, "phone_number must be E.164 format", nil, "phone_number", nil)
		return
	}
	if !otpCodePattern.MatchString(req.OtpCode) {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "otp_code must be exactly 6 digits", nil, "otp_code", nil)
		return
	}

	ctx := r.Context()
	codeHash := sha256.Sum256([]byte(req.OtpCode))

	var otpID uuid.UUID
	var otpPurpose string
	err := h.db.QueryRowContext(ctx, `
		SELECT id, purpose FROM otp_codes
		WHERE phone_number = $1 AND code_hash = $2 AND consumed_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1`,
		req.PhoneNumber, codeHash[:],
	).Scan(&otpID, &otpPurpose)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusUnauthorized, ErrInvalidOTP, "invalid or expired OTP", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "OTP lookup failed", nil, "", nil)
		return
	}

	if _, err := h.db.ExecContext(ctx, `UPDATE otp_codes SET consumed_at = NOW() WHERE id = $1`, otpID); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to consume OTP", nil, "", nil)
		return
	}

	entityID, role, isNew, err := h.lookupEntityByPhone(ctx, req.PhoneNumber)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "entity lookup failed", nil, "", nil)
		return
	}

	var token string
	var roleField *string
	var entityIDField *string

	if isNew {
		subject := RegistrationSubjectForPhone(req.PhoneNumber)
		// [M11 audit remediation, Finding 4] otpPurpose threaded through from
		// the otp_codes row consumed above into pending_registrations, so the
		// register endpoint that redeems this row can enforce OAS's
		// OtpSendRequest.purpose contract ("The microservice validates that
		// the subsequent register call matches this declared purpose") —
		// previously dropped on the floor here, so nothing downstream could
		// enforce it at all. A LOGIN-purpose OTP reaching this branch is
		// itself odd (LOGIN implies an existing entity, i.e. isNew == false)
		// but not impossible if the entity was deleted between send and
		// verify; recorded as-is rather than special-cased, since owner.go's
		// and provider.go's purpose checks reject anything that isn't their
		// own OWNER_REGISTER/PROVIDER_REGISTER regardless of which
		// unexpected value it is.
		if err := h.recordPendingRegistration(ctx, subject, req.PhoneNumber, otpPurpose); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to record pending registration", nil, "", nil)
			return
		}
		newToken, err := IssueJWT(h.signingKey, subject, "", RegistrationTokenTTL)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "token issuance failed", nil, "", nil)
			return
		}
		token = newToken
	} else {
		ttl := OwnerTokenTTL
		if role == "provider" {
			ttl = ProviderTokenTTL
		}
		newToken, err := IssueJWT(h.signingKey, entityID, role, ttl)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "token issuance failed", nil, "", nil)
			return
		}
		token = newToken
		roleCopy := role
		roleField = &roleCopy
		idCopy := entityID.String()
		entityIDField = &idCopy
	}

	resp := otpVerifyResponseBody{
		Token:       token,
		Role:        roleField,
		EntityID:    entityIDField,
		IsNewEntity: isNew,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *OtpVerifyHandler) recordPendingRegistration(ctx context.Context, subject uuid.UUID, phoneNumber, purpose string) error {
	expiresAt := time.Now().UTC().Add(RegistrationTokenTTL)
	_, err := h.db.ExecContext(ctx, `
		INSERT INTO pending_registrations (subject, phone_number, purpose, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (subject) DO UPDATE SET phone_number = EXCLUDED.phone_number, purpose = EXCLUDED.purpose, expires_at = EXCLUDED.expires_at, created_at = NOW()`,
		subject, phoneNumber, purpose, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("recordPendingRegistration: %w", err)
	}
	return nil
}

// RecoverPendingRegistration looks up the phone number and OTP purpose a
// registration token's subject was issued for (see this file's header note
// on why this bridge table exists). Returns sql.ErrNoRows if no unexpired
// pending registration exists for subject — the caller (Phase 11.5/11.6's
// register handlers) should treat that as an invalid/expired registration
// token.
//
// [M11 audit remediation, Finding 4] Now also returns purpose so the caller
// can reject a token issued under the wrong OTP purpose (e.g. a LOGIN or
// PROVIDER_REGISTER token redeemed against POST /api/v1/owner/register) —
// previously the phone_number was recovered but purpose was neither stored
// nor checked anywhere, so this gate didn't exist.
func RecoverPendingRegistration(ctx context.Context, db *sql.DB, subject uuid.UUID) (phoneNumber, purpose string, err error) {
	err = db.QueryRowContext(ctx, `
		SELECT phone_number, purpose FROM pending_registrations
		WHERE subject = $1 AND expires_at > NOW()`,
		subject,
	).Scan(&phoneNumber, &purpose)
	if err != nil {
		return "", "", err
	}
	return phoneNumber, purpose, nil
}

// DeletePendingRegistration removes a pending registration row once its
// register call has succeeded — the mapping is single-use.
func DeletePendingRegistration(ctx context.Context, db *sql.DB, subject uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM pending_registrations WHERE subject = $1`, subject)
	if err != nil {
		return fmt.Errorf("DeletePendingRegistration: %w", err)
	}
	return nil
}

// lookupEntityByPhone checks owners then providers for phoneNumber. A phone
// number is unique across BOTH tables in practice (each table has its own
// UNIQUE constraint per DM §4.1/§4.2, and registration purpose keeps the
// two flows separate), so checking owners first and falling back to
// providers is unambiguous — a phone number is never legitimately
// registered in both.
func (h *OtpVerifyHandler) lookupEntityByPhone(ctx context.Context, phoneNumber string) (entityID uuid.UUID, role string, isNew bool, err error) {
	var ownerID uuid.UUID
	err = h.db.QueryRowContext(ctx, `SELECT owner_id FROM owners WHERE phone_number = $1`, phoneNumber).Scan(&ownerID)
	if err == nil {
		return ownerID, "owner", false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.UUID{}, "", false, fmt.Errorf("lookupEntityByPhone: query owners: %w", err)
	}

	var providerID uuid.UUID
	err = h.db.QueryRowContext(ctx, `SELECT provider_id FROM providers WHERE phone_number = $1`, phoneNumber).Scan(&providerID)
	if err == nil {
		return providerID, "provider", false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.UUID{}, "", false, fmt.Errorf("lookupEntityByPhone: query providers: %w", err)
	}

	return uuid.UUID{}, "", true, nil
}

// Package account is declared in doc.go.
// This file implements the live network registration/login ceremony that
// this package's other files (register.go, recover.go) deliberately leave
// to the caller — see register.go's own header note. Added in Milestone 17
// Session 17.1.1 (outside that session's original FILES list; extended
// here per the Design Council verdict "Owner Registration: Keypair/OwnerID
// Ordering") after discovering register.go's Register cannot itself
// perform live registration against the real server:
//
//   - internal/api/owner.go's HandleRegister requires the CLIENT to
//     already hold an Ed25519 keypair (it signs owner_sig over the
//     public key) and only THEN assigns ownerID, in its response.
//   - Register(ownerID, passphrase, profile) requires ownerID as an INPUT
//     and generates its own, unrelated keypair — the opposite order, and
//     a DIFFERENT keypair than whatever signed the registration request.
//   - internal/client/upload.NewOrchestrator's signingKey parameter is
//     documented as "internal/client/account.Identity.PrivateKey" — so
//     whichever keypair registers with the server MUST be the one
//     Identity ends up holding, or every future owner_sig fails
//     server-side verification (the exact class of bug ADR-074/F-16-1
//     already spent time catching).
//
// This file is therefore the actual entry point for live registration.
// Register (register.go) remains correct and tested for what it always
// was — deriving a master secret from an already-known ownerID — and is
// simply not called by the live CLI path anymore. Not deleted: its own
// tests still pass and nothing here changes its contract.
//
// OTP verification doubles as login for an already-registered phone
// number: per internal/api/otp.go's HandleVerify, is_new_entity == false
// means the response already carries a fresh, ready-to-use JWT (token,
// role, entity_id) with NO further /owner/register call needed —
// cmd/client's live "recover" path relies on exactly this to restore
// account access without re-registering. The genuine, remaining gap this
// does NOT solve: if the local encrypted keystore (holding the Ed25519
// PRIVATE key) is truly lost — not just the JWT — there is no endpoint in
// this codebase to re-key an existing owner_id. Recovery in that case is
// limited to the master secret (decrypting/decoding already-known file
// data); new uploads need a keystore that still has the original private
// key. Stated here plainly rather than worked around.
//
// [REF: internal/api/owner.go HandleRegister, internal/api/otp.go
// HandleSend/HandleVerify, internal/client/upload/orchestrator.go
// NewOrchestrator, Design Council verdict "Owner Registration:
// Keypair/OwnerID Ordering" (M17 Session 17.1.1)]

package account

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
)

// ── Package-local authenticated-JSON HTTP client ───────────────────────────
//
// A twin of internal/client/{manage,upload,retrieve}'s own package-local
// apiClient (see manage/files.go's header note on why no shared HTTP
// client convention exists anywhere in this codebase to import instead).
// This one takes its bearer token per-call rather than at construction,
// since registration legitimately makes some calls with no token at all
// (otp/send, otp/verify) and others with a short-lived registration token
// that is never the long-lived session token every other package uses.

type apiClient struct {
	baseURL string
	http    *http.Client
}

func newAPIClient(baseURL string, httpClient *http.Client) *apiClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &apiClient{baseURL: baseURL, http: httpClient}
}

// RegistrationError is this package's exported API-error shape for the
// registration/login flow — exported (unlike manage/upload/retrieve's own
// package-local apiError) specifically so cmd/client's renderError can map
// it to an IC §14 copy code via the ErrorCode() method below, without
// needing a shared exported error type across every internal/client/*
// package.
type RegistrationError struct {
	Code       string
	Message    string
	RequestID  string
	RetryAfter *int
}

func (e *RegistrationError) Error() string {
	return fmt.Sprintf("%s: %s (request_id=%s)", e.Code, e.Message, e.RequestID)
}

// ErrorCode satisfies the structural interface cmd/client/render.go's
// renderError uses to map any internal/client/* package's own error type
// to an IC §14 copy code.
func (e *RegistrationError) ErrorCode() string { return e.Code }

func decodeRegistrationError(body []byte) *RegistrationError {
	var wire struct {
		ErrorCode  string `json:"error_code"`
		Message    string `json:"message"`
		RequestID  string `json:"request_id"`
		RetryAfter *int   `json:"retry_after"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || wire.ErrorCode == "" {
		return nil
	}
	return &RegistrationError{Code: wire.ErrorCode, Message: wire.Message, RequestID: wire.RequestID, RetryAfter: wire.RetryAfter}
}

func (c *apiClient) doJSON(ctx context.Context, method, path, bearerToken string, reqBody, out any) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, nil, fmt.Errorf("account: doJSON: encode request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("account: doJSON: build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("account: doJSON: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("account: doJSON: read response body: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp, respBody, fmt.Errorf("account: doJSON: decode response: %w", err)
		}
	}
	return resp, respBody, nil
}

// ── OTP send / verify (shared by register's and recover's live paths) ─────

// OTP purpose constants mirror internal/api/otp.go's validOtpPurposes
// exactly; that table is not itself exported across the API boundary, so
// this is a deliberate, documented duplication of two fixed strings, not
// independent guesswork. ("PROVIDER_REGISTER" is the third value in that
// table — irrelevant here, this is the data-owner CLI.)
const (
	OTPPurposeOwnerRegister = "OWNER_REGISTER"
	OTPPurposeLogin         = "LOGIN"
)

// SendOTP calls POST /api/v1/auth/otp/send. In demo mode there is no real
// SMS integration (internal/api/otp.go's NoopOtpSender) — the operator
// retrieves the 6-digit code directly from the otp_codes table, exactly as
// scripts/test/demo_timeline_test.go's recoverOTPCode already does for
// test purposes. This is a manual demo-mode step, not a code branch: the
// same call, unmodified, sends a real SMS in prod once a real OtpSender is
// wired server-side (Scale Advocate's point in the Design Council verdict
// — this is why cmd/client does its own phone/OTP round-trip instead of
// mirroring cmd/provider's externally-supplied-token shortcut, which is
// only justified for a daemon with no human in the loop).
func SendOTP(ctx context.Context, baseURL string, httpClient *http.Client, phoneNumber, purpose string) error {
	api := newAPIClient(baseURL, httpClient)
	reqBody := struct {
		PhoneNumber string `json:"phone_number"`
		Purpose     string `json:"purpose"`
	}{PhoneNumber: phoneNumber, Purpose: purpose}

	resp, rawBody, err := api.doJSON(ctx, http.MethodPost, "/api/v1/auth/otp/send", "", reqBody, nil)
	if err != nil {
		return fmt.Errorf("account: SendOTP: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if apiErr := decodeRegistrationError(rawBody); apiErr != nil {
			return fmt.Errorf("account: SendOTP: unexpected status %d: %w", resp.StatusCode, apiErr)
		}
		return fmt.Errorf("account: SendOTP: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// VerifyResult is POST /api/v1/auth/otp/verify's decoded response.
// IsNewEntity distinguishes the two cases callers must branch on:
//
//   - true:  no owner/provider exists for this phone number yet. Token is
//     a short-lived registration token (Role == ""); the caller must
//     proceed to RegisterOwner to actually create the account.
//   - false: an owner (or provider) already exists. Token is a full,
//     ready-to-use JWT for that role/entity — this is the login case
//     cmd/client's live "recover" path relies on; no further network
//     call is needed to regain a valid session.
type VerifyResult struct {
	Token       string
	Role        string // "" when IsNewEntity; "owner" or "provider" otherwise
	EntityID    uuid.UUID
	IsNewEntity bool
}

// ErrWrongRoleForOwnerCLI is returned when a phone number already belongs
// to a PROVIDER, not an owner — cmd/client is the data-owner CLI and has
// no business minting a session for a provider account. There is no
// server-side error_code for this (verify succeeds fine from the server's
// perspective); it is this package refusing to proceed. render.go maps
// this to IC §14.1's existing WRONG_ROLE copy ("check you're running the
// right command (cmd/client vs. cmd/provider)") rather than inventing new
// wording.
var ErrWrongRoleForOwnerCLI = errors.New("account: this phone number is registered as a provider, not a data owner — use cmd/provider instead")

// VerifyOTP calls POST /api/v1/auth/otp/verify.
//
// Goroutine-safe: yes.
func VerifyOTP(ctx context.Context, baseURL string, httpClient *http.Client, phoneNumber, otpCode string) (VerifyResult, error) {
	api := newAPIClient(baseURL, httpClient)
	reqBody := struct {
		PhoneNumber string `json:"phone_number"`
		OtpCode     string `json:"otp_code"`
	}{PhoneNumber: phoneNumber, OtpCode: otpCode}

	var resp struct {
		Token       string  `json:"token"`
		Role        *string `json:"role"`
		EntityID    *string `json:"entity_id"`
		IsNewEntity bool    `json:"is_new_entity"`
	}
	httpResp, rawBody, err := api.doJSON(ctx, http.MethodPost, "/api/v1/auth/otp/verify", "", reqBody, &resp)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("account: VerifyOTP: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		if apiErr := decodeRegistrationError(rawBody); apiErr != nil {
			return VerifyResult{}, fmt.Errorf("account: VerifyOTP: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return VerifyResult{}, fmt.Errorf("account: VerifyOTP: unexpected status %d", httpResp.StatusCode)
	}

	result := VerifyResult{Token: resp.Token, IsNewEntity: resp.IsNewEntity}
	if resp.Role != nil {
		result.Role = *resp.Role
	}
	if resp.EntityID != nil {
		parsed, parseErr := uuid.Parse(*resp.EntityID)
		if parseErr != nil {
			return VerifyResult{}, fmt.Errorf("account: VerifyOTP: parse entity_id: %w", parseErr)
		}
		result.EntityID = parsed
	}
	if !result.IsNewEntity && result.Role == "provider" {
		return VerifyResult{}, ErrWrongRoleForOwnerCLI
	}
	return result, nil
}

// ── Owner registration (POST /api/v1/owner/register) ───────────────────────

// canonicalOwnerSigningInput mirrors internal/api/owner.go's verifyOwnerSig
// exactly: plain (not hash-prefixed) Ed25519 over the canonical JSON
// `{"ed25519_public_key":"<value>"}` — a deliberate exception to this
// project's usual fixed-layout-binary signing rule (owner.go's own header
// note calls this out as "a THIRD distinct signing convention in this
// package"). Do NOT "fix" this to fixed-layout binary — that would break
// server-side verification, not correct it.
func canonicalOwnerSigningInput(pubKeyHex string) []byte {
	return []byte(fmt.Sprintf(`{"ed25519_public_key":"%s"}`, pubKeyHex))
}

// RegisteredOwner is RegisterOwner's result: the server-assigned identity
// plus the freshly generated Ed25519 keypair that authenticated the
// registration call. Callers MUST carry PublicKey/PrivateKey forward
// unchanged into FinalizeIdentity (and ultimately into the local
// keystore) — generating or substituting a different keypair after this
// call succeeds silently breaks every future owner_sig the server will
// reject.
type RegisteredOwner struct {
	OwnerID    uuid.UUID
	Token      string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// RegisterOwner performs the second half of live registration: generate a
// fresh Ed25519 keypair, sign it per canonicalOwnerSigningInput, and call
// POST /api/v1/owner/register with registrationToken (obtained from
// VerifyOTP when IsNewEntity was true) as the bearer token.
//
// Pre-conditions:
//   - registrationToken is a still-valid registration token from VerifyOTP
//     (IsNewEntity == true)
//
// Goroutine-safe: yes.
func RegisterOwner(ctx context.Context, baseURL string, httpClient *http.Client, registrationToken string) (RegisteredOwner, error) {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return RegisteredOwner{}, fmt.Errorf("account: RegisterOwner: generate Ed25519 key: %w", err)
	}
	pubHex := hex.EncodeToString(pub)
	sig := ed25519.Sign(priv, canonicalOwnerSigningInput(pubHex))

	api := newAPIClient(baseURL, httpClient)
	reqBody := struct {
		Ed25519PublicKey string `json:"ed25519_public_key"`
		OwnerSig         string `json:"owner_sig"`
	}{Ed25519PublicKey: pubHex, OwnerSig: hex.EncodeToString(sig)}

	var resp struct {
		OwnerID uuid.UUID `json:"owner_id"`
		Token   string    `json:"token"`
	}
	httpResp, rawBody, err := api.doJSON(ctx, http.MethodPost, "/api/v1/owner/register", registrationToken, reqBody, &resp)
	if err != nil {
		return RegisteredOwner{}, fmt.Errorf("account: RegisterOwner: %w", err)
	}
	if httpResp.StatusCode != http.StatusCreated && httpResp.StatusCode != http.StatusOK {
		if apiErr := decodeRegistrationError(rawBody); apiErr != nil {
			return RegisteredOwner{}, fmt.Errorf("account: RegisterOwner: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return RegisteredOwner{}, fmt.Errorf("account: RegisterOwner: unexpected status %d", httpResp.StatusCode)
	}

	return RegisteredOwner{OwnerID: resp.OwnerID, Token: resp.Token, PublicKey: pub, PrivateKey: priv}, nil
}

// FinalizeIdentity derives the master secret and mnemonic for an
// already-registered owner. register.go's Register performs the same
// Argon2id derivation but ALSO generates a new keypair — wrong here, since
// the keypair must be the exact one RegisterOwner already registered with
// the server (this function's pub/priv parameters), never a fresh one.
// profile.Argon2Time/Argon2Memory/Argon2Threads are always read from the
// active NetworkProfile, never hardcoded (ADR-031, mirrored from
// register.go's own Register).
//
// Goroutine-safe: yes.
func FinalizeIdentity(pub ed25519.PublicKey, priv ed25519.PrivateKey, ownerID uuid.UUID, passphrase []byte, profile config.NetworkProfile) (Identity, error) {
	masterSecret := crypto.DeriveMasterSecret(passphrase, ownerID[:],
		profile.Argon2Time, profile.Argon2Memory, profile.Argon2Threads)

	mnemonic, err := crypto.MasterSecretToMnemonic(masterSecret)
	if err != nil {
		return Identity{}, fmt.Errorf("account: FinalizeIdentity: encode mnemonic: %w", err)
	}

	return Identity{
		PublicKey:    pub,
		PrivateKey:   priv,
		MasterSecret: masterSecret,
		Mnemonic:     mnemonic,
	}, nil
}

package account

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

func TestSendOTPPostsCorrectPurpose(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody struct {
		PhoneNumber string `json:"phone_number"`
		Purpose     string `json:"purpose"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"expires_at": "2026-01-01T00:00:00Z"})
	}))
	defer srv.Close()

	err := SendOTP(context.Background(), srv.URL, srv.Client(), "+919876543210", OTPPurposeOwnerRegister)
	if err != nil {
		t.Fatalf("SendOTP: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/auth/otp/send" {
		t.Fatalf("got %s %s, want POST /api/v1/auth/otp/send", gotMethod, gotPath)
	}
	if gotBody.PhoneNumber != "+919876543210" || gotBody.Purpose != OTPPurposeOwnerRegister {
		t.Fatalf("unexpected request body: %+v", gotBody)
	}
}

func TestSendOTPSurfacesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error_code": "OTP_RATE_LIMITED",
			"message":    "too many OTP requests for this phone number",
			"request_id": "req-1",
		})
	}))
	defer srv.Close()

	err := SendOTP(context.Background(), srv.URL, srv.Client(), "+919876543210", OTPPurposeOwnerRegister)
	var regErr *RegistrationError
	if !errors.As(err, &regErr) {
		t.Fatalf("expected *RegistrationError, got %v", err)
	}
	if regErr.ErrorCode() != "OTP_RATE_LIMITED" {
		t.Fatalf("got error code %q, want OTP_RATE_LIMITED", regErr.ErrorCode())
	}
}

func TestVerifyOTPParsesNewEntity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":         "reg-token-abc",
			"role":          nil,
			"entity_id":     nil,
			"is_new_entity": true,
		})
	}))
	defer srv.Close()

	result, err := VerifyOTP(context.Background(), srv.URL, srv.Client(), "+919876543210", "123456")
	if err != nil {
		t.Fatalf("VerifyOTP: %v", err)
	}
	if !result.IsNewEntity || result.Token != "reg-token-abc" || result.Role != "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyOTPParsesExistingOwnerAsLogin(t *testing.T) {
	ownerID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":         "session-jwt-xyz",
			"role":          "owner",
			"entity_id":     ownerID.String(),
			"is_new_entity": false,
		})
	}))
	defer srv.Close()

	result, err := VerifyOTP(context.Background(), srv.URL, srv.Client(), "+919876543210", "123456")
	if err != nil {
		t.Fatalf("VerifyOTP: %v", err)
	}
	if result.IsNewEntity {
		t.Fatalf("expected IsNewEntity=false (login case)")
	}
	if result.Role != "owner" || result.Token != "session-jwt-xyz" || result.EntityID != ownerID {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyOTPRejectsProviderRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":         "session-jwt-xyz",
			"role":          "provider",
			"entity_id":     uuid.New().String(),
			"is_new_entity": false,
		})
	}))
	defer srv.Close()

	_, err := VerifyOTP(context.Background(), srv.URL, srv.Client(), "+919876543210", "123456")
	if !errors.Is(err, ErrWrongRoleForOwnerCLI) {
		t.Fatalf("expected ErrWrongRoleForOwnerCLI, got %v", err)
	}
}

func TestRegisterOwnerSignsCanonicalPayloadAndPreservesKeypair(t *testing.T) {
	ownerID := uuid.New()
	var gotAuth string
	var gotReq struct {
		Ed25519PublicKey string `json:"ed25519_public_key"`
		OwnerSig         string `json:"owner_sig"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotReq)

		// Verify the signature server-side exactly the way owner.go's
		// verifyOwnerSig does, to prove RegisterOwner's wire format is
		// actually correct, not just internally self-consistent.
		pubBytes, err := hex.DecodeString(gotReq.Ed25519PublicKey)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			t.Errorf("bad public key in request: %v", err)
		}
		sigBytes, err := hex.DecodeString(gotReq.OwnerSig)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			t.Errorf("bad signature in request: %v", err)
		}
		signingInput := canonicalOwnerSigningInput(gotReq.Ed25519PublicKey)
		if !ed25519.Verify(pubBytes, signingInput, sigBytes) {
			t.Errorf("owner_sig does not verify against canonical signing input")
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"owner_id": ownerID.String(),
			"token":    "owner-jwt-123",
		})
	}))
	defer srv.Close()

	result, err := RegisterOwner(context.Background(), srv.URL, srv.Client(), "registration-token-xyz")
	if err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
	if gotAuth != "Bearer registration-token-xyz" {
		t.Fatalf("got Authorization %q, want Bearer registration-token-xyz", gotAuth)
	}
	if result.OwnerID != ownerID || result.Token != "owner-jwt-123" {
		t.Fatalf("unexpected result: %+v", result)
	}
	// The keypair returned MUST be the exact one that signed the request —
	// this is the whole point of the Design Council's resolution.
	wantPubHex := hex.EncodeToString(result.PublicKey)
	if wantPubHex != gotReq.Ed25519PublicKey {
		t.Fatalf("returned PublicKey %q does not match the key that signed the request %q", wantPubHex, gotReq.Ed25519PublicKey)
	}
	if !ed25519.PublicKey(result.PublicKey).Equal(result.PrivateKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("returned PublicKey/PrivateKey are not a matching pair")
	}
}

func TestFinalizeIdentityPreservesCallerSuppliedKeypair(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ownerID := uuid.New()
	profile := config.DemoProfile

	identity, err := FinalizeIdentity(pub, priv, ownerID, []byte("correct horse battery staple"), profile)
	if err != nil {
		t.Fatalf("FinalizeIdentity: %v", err)
	}
	if !identity.PublicKey.Equal(pub) {
		t.Fatalf("FinalizeIdentity generated a different public key than it was given")
	}
	if hex.EncodeToString(identity.PrivateKey) != hex.EncodeToString(priv) {
		t.Fatalf("FinalizeIdentity generated a different private key than it was given")
	}
	if len(identity.Mnemonic) != 24 {
		t.Fatalf("got %d mnemonic words, want 24", len(identity.Mnemonic))
	}
}

func TestFinalizeIdentityUsesProfileArgon2Params(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ownerID := uuid.New()
	passphrase := []byte("same passphrase for both profiles")

	demoIdentity, err := FinalizeIdentity(pub, priv, ownerID, passphrase, config.DemoProfile)
	if err != nil {
		t.Fatalf("FinalizeIdentity (demo): %v", err)
	}
	prodIdentity, err := FinalizeIdentity(pub, priv, ownerID, passphrase, config.ProductionProfile)
	if err != nil {
		t.Fatalf("FinalizeIdentity (prod): %v", err)
	}
	// Demo and prod use different Argon2id cost parameters (profiles.go) —
	// the same passphrase/ownerID must NOT derive the same master secret
	// across profiles, proving profile.Argon2* is actually read, not a
	// hardcoded constant that happens to satisfy the grep.
	if demoIdentity.MasterSecret == prodIdentity.MasterSecret {
		t.Fatalf("master secret identical across demo/prod profiles — Argon2 params are not actually being read from profile")
	}

	// Same profile, same inputs: deterministic.
	demoIdentityAgain, err := FinalizeIdentity(pub, priv, ownerID, passphrase, config.DemoProfile)
	if err != nil {
		t.Fatalf("FinalizeIdentity (demo, again): %v", err)
	}
	if demoIdentity.MasterSecret != demoIdentityAgain.MasterSecret {
		t.Fatalf("master secret not deterministic for identical (passphrase, ownerID, profile)")
	}
}

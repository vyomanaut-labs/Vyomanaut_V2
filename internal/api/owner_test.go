// Package api is declared in doc.go.
// Unit and live-database integration tests for the six owner endpoints.
//
// [REF: OAS paths./api/v1/owner/*, build.md Phase 11.5]

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/payment"
)

func withClaims(req *http.Request, claims VerifiedClaims) *http.Request {
	ctx := context.WithValue(req.Context(), claimsContextKey, claims)
	return req.WithContext(ctx)
}

func randPhoneForOwner() string {
	var suffix [4]byte
	_, _ = rand.Read(suffix[:])
	n := uint64(suffix[0])<<24 | uint64(suffix[1])<<16 | uint64(suffix[2])<<8 | uint64(suffix[3])
	return fmt.Sprintf("+91%010d", n%10000000000)
}

// testSeedIdempotencyKey generates a fresh, valid-length (64 hex chars)
// idempotency key for seeding owner_escrow_events rows with no relationship
// to the actual function under test's own key derivation.
func testSeedIdempotencyKey() string {
	h := sha256.Sum256([]byte(uuid.New().String()))
	return hex.EncodeToString(h[:])
}

// ── Session 11.5.1 — Owner Register ─────────────────────────────────────────────

func signOwnerSig(priv ed25519.PrivateKey, pubKeyHex string) string {
	signingInput := fmt.Sprintf(`{"ed25519_public_key":"%s"}`, pubKeyHex)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return hex.EncodeToString(sig)
}

func TestOwnerRegisterSucceedsWithValidSig(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	msPub, msPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	handler := NewOwnerRegisterHandler(db, msPriv)

	ownerPub, ownerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey (owner): %v", err)
	}
	phone := randPhoneForOwner()
	subject := RegistrationSubjectForPhone(phone)
	if _, err := db.Exec(`INSERT INTO pending_registrations (subject, phone_number, expires_at) VALUES ($1,$2,NOW()+interval '1 hour')`,
		subject, phone); err != nil {
		t.Fatalf("seed pending_registrations: %v", err)
	}

	pubKeyHex := hex.EncodeToString(ownerPub)
	sigHex := signOwnerSig(ownerPriv, pubKeyHex)
	reqBody, _ := json.Marshal(ownerRegisterRequestBody{Ed25519PublicKey: pubKeyHex, OwnerSig: sigHex})
	req := httptest.NewRequest("POST", "/api/v1/owner/register", bytes.NewReader(reqBody))
	req = withClaims(req, VerifiedClaims{Subject: subject, Role: ""})
	rec := httptest.NewRecorder()
	handler.HandleRegister(rec, req)

	if rec.Code != 201 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp ownerRegisterResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var storedPhone string
	if err := verify.QueryRow(`SELECT phone_number FROM owners WHERE owner_id = $1`, resp.OwnerID).Scan(&storedPhone); err != nil {
		t.Fatalf("query owner: %v", err)
	}
	if storedPhone != phone {
		t.Errorf("stored phone = %q, want %q", storedPhone, phone)
	}

	claims, err := VerifyJWT(msPub, resp.Token)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if claims.Role != "owner" || claims.Subject != resp.OwnerID {
		t.Errorf("token claims = %+v, want role=owner subject=%v", claims, resp.OwnerID)
	}
	if claims.Expiry.Sub(time.Now().UTC()) > OwnerTokenTTL || claims.Expiry.Before(time.Now().UTC()) {
		t.Errorf("token expiry %v not within OwnerTokenTTL of now", claims.Expiry)
	}

	// pending_registrations must be consumed (single-use).
	var count int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM pending_registrations WHERE subject = $1`, subject).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Error("pending_registrations row still exists after successful register — should be deleted")
	}
}

func TestOwnerRegisterRejectsBadSig(t *testing.T) {
	db := openTestDB(t)
	_, msPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	handler := NewOwnerRegisterHandler(db, msPriv)

	ownerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey (owner): %v", err)
	}
	phone := randPhoneForOwner()
	subject := RegistrationSubjectForPhone(phone)
	if _, err := db.Exec(`INSERT INTO pending_registrations (subject, phone_number, expires_at) VALUES ($1,$2,NOW()+interval '1 hour')`,
		subject, phone); err != nil {
		t.Fatalf("seed: %v", err)
	}

	pubKeyHex := hex.EncodeToString(ownerPub)
	badSig := hex.EncodeToString(make([]byte, 64)) // all-zero, wrong
	reqBody, _ := json.Marshal(ownerRegisterRequestBody{Ed25519PublicKey: pubKeyHex, OwnerSig: badSig})
	req := httptest.NewRequest("POST", "/api/v1/owner/register", bytes.NewReader(reqBody))
	req = withClaims(req, VerifiedClaims{Subject: subject, Role: ""})
	rec := httptest.NewRecorder()
	handler.HandleRegister(rec, req)

	if rec.Code != 401 {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestOwnerRegisterRejectsDuplicatePhone(t *testing.T) {
	db := openTestDB(t)
	_, msPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	handler := NewOwnerRegisterHandler(db, msPriv)

	phone := randPhoneForOwner()
	var existingPubKey [32]byte
	_, _ = rand.Read(existingPubKey[:])
	if _, err := db.Exec(`INSERT INTO owners (owner_id, phone_number, ed25519_public_key) VALUES ($1,$2,$3)`,
		uuid.New(), phone, existingPubKey[:]); err != nil {
		t.Fatalf("seed existing owner: %v", err)
	}

	ownerPub, ownerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey (owner): %v", err)
	}
	subject := RegistrationSubjectForPhone(phone)
	if _, err := db.Exec(`INSERT INTO pending_registrations (subject, phone_number, expires_at) VALUES ($1,$2,NOW()+interval '1 hour')`,
		subject, phone); err != nil {
		t.Fatalf("seed pending: %v", err)
	}

	pubKeyHex := hex.EncodeToString(ownerPub)
	sigHex := signOwnerSig(ownerPriv, pubKeyHex)
	reqBody, _ := json.Marshal(ownerRegisterRequestBody{Ed25519PublicKey: pubKeyHex, OwnerSig: sigHex})
	req := httptest.NewRequest("POST", "/api/v1/owner/register", bytes.NewReader(reqBody))
	req = withClaims(req, VerifiedClaims{Subject: subject, Role: ""})
	rec := httptest.NewRecorder()
	handler.HandleRegister(rec, req)

	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["error_code"] != string(ErrPhoneAlreadyRegistered) {
		t.Errorf("error_code = %v, want %q", body["error_code"], ErrPhoneAlreadyRegistered)
	}
}

func TestOwnerRegisterRejectsNonRegistrationToken(t *testing.T) {
	db := openTestDB(t)
	_, msPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	handler := NewOwnerRegisterHandler(db, msPriv)

	ownerPub, ownerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey (owner): %v", err)
	}
	pubKeyHex := hex.EncodeToString(ownerPub)
	sigHex := signOwnerSig(ownerPriv, pubKeyHex)
	reqBody, _ := json.Marshal(ownerRegisterRequestBody{Ed25519PublicKey: pubKeyHex, OwnerSig: sigHex})
	req := httptest.NewRequest("POST", "/api/v1/owner/register", bytes.NewReader(reqBody))
	// An already-established owner token (Role != "") must not re-register.
	req = withClaims(req, VerifiedClaims{Subject: uuid.New(), Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleRegister(rec, req)

	if rec.Code != 403 {
		t.Errorf("status = %d, want 403 (not a registration token)", rec.Code)
	}
}

// ── Session 11.5.2 — Deposit Initiate ────────────────────────────────────────────

func TestDepositInitiateReturnsVPAAndQR(t *testing.T) {
	db := openTestDB(t)
	provider := payment.NewMockProvider(db)
	handler := NewOwnerDepositHandler(provider)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	reqBody, _ := json.Marshal(depositInitiateRequestBody{AmountPaise: 50000, IdempotencyKey: testSeedIdempotencyKey()})
	req := httptest.NewRequest("POST", "/api/v1/owner/deposit", bytes.NewReader(reqBody))
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleDeposit(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp depositInitiateResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.VPA == "" || resp.QRCodeURL == "" {
		t.Errorf("empty vpa/qr_code_url: %+v", resp)
	}
}

func TestDepositInitiateRejectsMissingOrMalformedIdempotencyKey(t *testing.T) {
	db := openTestDB(t)
	provider := payment.NewMockProvider(db)
	handler := NewOwnerDepositHandler(provider)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	for _, tc := range []struct {
		name string
		key  string
	}{
		{"missing", ""},
		{"too short", "abc123"},
		{"uppercase", strings.ToUpper(testSeedIdempotencyKey())},
		{"not hex", strings.Repeat("z", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(depositInitiateRequestBody{AmountPaise: 50000, IdempotencyKey: tc.key})
			req := httptest.NewRequest("POST", "/api/v1/owner/deposit", bytes.NewReader(reqBody))
			req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
			rec := httptest.NewRecorder()
			handler.HandleDeposit(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (idempotency_key = %q)", rec.Code, tc.key)
			}
		})
	}
}

// TestDepositInitiateIdempotentOnRetry is the regression test for Finding
// #4 (M10 corrections review): MockProvider.InitiateEscrow credits
// owner_escrow_events SYNCHRONOUSLY (demo mode has no real webhook to wait
// for), so before this fix, every retry of a deposit HTTP request with a
// fresh contractID credited the owner's balance again — a demo user could
// inflate their own balance by double-clicking deposit. Calling the
// handler twice with the SAME client-supplied idempotency_key must credit
// the owner's balance exactly once.
func TestDepositInitiateIdempotentOnRetry(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	provider := payment.NewMockProvider(db)
	handler := NewOwnerDepositHandler(provider)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")
	key := testSeedIdempotencyKey()

	for i := 0; i < 2; i++ {
		reqBody, _ := json.Marshal(depositInitiateRequestBody{AmountPaise: 40000, IdempotencyKey: key})
		req := httptest.NewRequest("POST", "/api/v1/owner/deposit", bytes.NewReader(reqBody))
		req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
		rec := httptest.NewRecorder()
		handler.HandleDeposit(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("call #%d: status = %d, body = %s", i+1, rec.Code, rec.Body.String())
		}
	}

	var rows int
	var total int64
	if err := verify.QueryRow(`SELECT COUNT(*), COALESCE(SUM(amount_paise), 0) FROM owner_escrow_events WHERE owner_id = $1 AND event_type = 'DEPOSIT'`,
		ownerID).Scan(&rows, &total); err != nil {
		t.Fatalf("query owner_escrow_events: %v", err)
	}
	if rows != 1 {
		t.Errorf("owner_escrow_events DEPOSIT rows after 2 identical retries = %d, want 1 (same idempotency_key "+
			"must not credit the balance twice — Finding #4)", rows)
	}
	if total != 40000 {
		t.Errorf("total credited = %d, want 40000 (must reflect exactly one deposit, not two)", total)
	}
}

func TestDepositInitiateDistinctKeysCreditIndependently(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	provider := payment.NewMockProvider(db)
	handler := NewOwnerDepositHandler(provider)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	for i := 0; i < 2; i++ {
		reqBody, _ := json.Marshal(depositInitiateRequestBody{AmountPaise: 15000, IdempotencyKey: testSeedIdempotencyKey()})
		req := httptest.NewRequest("POST", "/api/v1/owner/deposit", bytes.NewReader(reqBody))
		req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
		rec := httptest.NewRecorder()
		handler.HandleDeposit(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("call #%d: status = %d, body = %s", i+1, rec.Code, rec.Body.String())
		}
	}

	var rows int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM owner_escrow_events WHERE owner_id = $1 AND event_type = 'DEPOSIT'`,
		ownerID).Scan(&rows); err != nil {
		t.Fatalf("query owner_escrow_events: %v", err)
	}
	if rows != 2 {
		t.Errorf("owner_escrow_events DEPOSIT rows after 2 DIFFERENT idempotency keys = %d, want 2 (a fix for "+
			"Finding #4 must not accidentally collapse genuinely distinct deposits together)", rows)
	}
}

func TestDepositInitiateWritesNoLedgerRow(t *testing.T) {
	// MockProvider.InitiateEscrow DOES credit the ledger synchronously (by
	// design — MVP §7.7/CR-10, Milestone 10) since demo mode has no real
	// webhook to wait for. This test instead confirms the deposit handler
	// itself never writes to escrow_events (the wrong, provider-scoped
	// table) — the actual correctness property this session's flagged note
	// is about.
	db := openTestDB(t)
	verify := openVerifyDB(t)
	provider := payment.NewMockProvider(db)
	handler := NewOwnerDepositHandler(provider)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	var providerLedgerRowsBefore int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM escrow_events`).Scan(&providerLedgerRowsBefore); err != nil {
		t.Fatalf("count before: %v", err)
	}

	reqBody, _ := json.Marshal(depositInitiateRequestBody{AmountPaise: 25000, IdempotencyKey: testSeedIdempotencyKey()})
	req := httptest.NewRequest("POST", "/api/v1/owner/deposit", bytes.NewReader(reqBody))
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleDeposit(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var providerLedgerRowsAfter int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM escrow_events`).Scan(&providerLedgerRowsAfter); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if providerLedgerRowsAfter != providerLedgerRowsBefore {
		t.Errorf("escrow_events (provider ledger) row count changed from %d to %d — a deposit must never land there",
			providerLedgerRowsBefore, providerLedgerRowsAfter)
	}
}

// ── Session 11.5.3 — Owner Balance ───────────────────────────────────────────────

func insertTestOwnerForOwnerTests(t *testing.T, db *sql.DB, vpa string) uuid.UUID {
	t.Helper()
	if vpa == "" {
		var suffix [6]byte
		_, _ = rand.Read(suffix[:])
		vpa = fmt.Sprintf("vyomanaut.%x@icici", suffix[:])
	}
	id := uuid.New()
	var pubKey [32]byte
	_, _ = rand.Read(pubKey[:])
	if _, err := db.Exec(`INSERT INTO owners (owner_id, phone_number, ed25519_public_key, smart_collect_vpa) VALUES ($1,$2,$3,$4)`,
		id, randPhoneForOwner(), pubKey[:], vpa); err != nil {
		t.Fatalf("insertTestOwnerForOwnerTests: %v", err)
	}
	return id
}

func insertTestFile(t *testing.T, db *sql.DB, ownerID uuid.UUID, sizeBytes int64, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	nonce := make([]byte, 12)
	tag := make([]byte, 16)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(tag)
	_, err := db.Exec(`
		INSERT INTO files (file_id, owner_id, pointer_ciphertext, pointer_nonce, pointer_tag, original_size_bytes, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, ownerID, []byte("ciphertext"), nonce, tag, sizeBytes, status,
	)
	if err != nil {
		t.Fatalf("insertTestFile: %v", err)
	}
	return id
}

func TestOwnerBalanceComputesAvailableCorrectly(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile
	handler := NewOwnerBalanceHandler(db, profile)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	idempotencyKey := testSeedIdempotencyKey()
	if err := payment.InsertOwnerEscrowEvent(context.Background(), db, ownerID, payment.OwnerDeposit, 500000, idempotencyKey, nil); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}
	if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW mv_owner_escrow_balance`); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	insertTestFile(t, db, ownerID, bytesPerGB, "ACTIVE")

	req := httptest.NewRequest("GET", "/api/v1/owner/"+ownerID.String()+"/balance", nil)
	req.SetPathValue("owner_id", ownerID.String())
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleBalance(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp ownerBalanceResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.BalancePaise != 500000 {
		t.Errorf("BalancePaise = %d, want 500000", resp.BalancePaise)
	}
	wantReserved := profile.StorageRatePaisePerGBPerMonth
	if resp.ReservedNext30dPaise != wantReserved {
		t.Errorf("ReservedNext30dPaise = %d, want %d", resp.ReservedNext30dPaise, wantReserved)
	}
	if resp.AvailablePaise != resp.BalancePaise-resp.ReservedNext30dPaise {
		t.Errorf("AvailablePaise = %d, want balance - reserved = %d", resp.AvailablePaise, resp.BalancePaise-resp.ReservedNext30dPaise)
	}
}

func TestOwnerBalanceNeverNegative(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile
	handler := NewOwnerBalanceHandler(db, profile)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")
	insertTestFile(t, db, ownerID, 1000*bytesPerGB, "ACTIVE")

	req := httptest.NewRequest("GET", "/api/v1/owner/"+ownerID.String()+"/balance", nil)
	req.SetPathValue("owner_id", ownerID.String())
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleBalance(rec, req)

	var resp ownerBalanceResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.AvailablePaise < 0 {
		t.Errorf("AvailablePaise = %d, want never negative", resp.AvailablePaise)
	}
}

// ── Session 11.5.4 — Owner File List ────────────────────────────────────────────

func TestOwnerFileListAvailabilityDemoThresholds(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile
	handler := NewOwnerFileListHandler(db, profile)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")
	insertTestFile(t, db, ownerID, bytesPerGB, "ACTIVE")

	req := httptest.NewRequest("GET", "/api/v1/owner/"+ownerID.String()+"/files", nil)
	req.SetPathValue("owner_id", ownerID.String())
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleFiles(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp ownerFileListResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Files) != 1 {
		t.Fatalf("Files count = %d, want 1", len(resp.Files))
	}
	if resp.Files[0].Availability != "CRITICAL" {
		t.Errorf("Availability = %q, want CRITICAL for a file with zero assignments", resp.Files[0].Availability)
	}
}

func TestOwnerFileListReturnsDisplayNameWhenPresent(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile
	handler := NewOwnerFileListHandler(db, profile)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	fileID := uuid.New()
	nonce := make([]byte, 12)
	tag := make([]byte, 16)
	displayCiphertext := []byte("encrypted-name")
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(tag)
	_, err := db.Exec(`
		INSERT INTO files (file_id, owner_id, pointer_ciphertext, pointer_nonce, pointer_tag, original_size_bytes, status,
			display_name_ciphertext, display_name_nonce, display_name_tag)
		VALUES ($1,$2,$3,$4,$5,$6,'ACTIVE',$7,$8,$9)`,
		fileID, ownerID, []byte("ciphertext"), nonce, tag, bytesPerGB, displayCiphertext, nonce, tag,
	)
	if err != nil {
		t.Fatalf("insert file with display name: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/owner/"+ownerID.String()+"/files", nil)
	req.SetPathValue("owner_id", ownerID.String())
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleFiles(rec, req)

	var resp ownerFileListResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Files) != 1 || resp.Files[0].DisplayNameCiphertext == nil {
		t.Fatalf("expected exactly 1 file with a non-nil display_name_ciphertext, got %+v", resp.Files)
	}
}

// ── Session 11.5.5 — Owner Escrow History ───────────────────────────────────────

func TestOwnerEscrowHistoryIncludesBalanceSummary(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile
	handler := NewOwnerEscrowHistoryHandler(db, profile)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	idempotencyKey := testSeedIdempotencyKey()
	if err := payment.InsertOwnerEscrowEvent(context.Background(), db, ownerID, payment.OwnerDeposit, 100000, idempotencyKey, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW mv_owner_escrow_balance`); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/owner/"+ownerID.String()+"/escrow", nil)
	req.SetPathValue("owner_id", ownerID.String())
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleEscrowHistory(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp ownerEscrowHistoryResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.BalancePaise != 100000 {
		t.Errorf("BalancePaise = %d, want 100000", resp.BalancePaise)
	}
	if len(resp.Events) != 1 || resp.Events[0].AmountPaise != 100000 {
		t.Errorf("Events = %+v, want exactly 1 event of 100000 paise", resp.Events)
	}
}

func TestOwnerEscrowHistoryPaginates(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile
	handler := NewOwnerEscrowHistoryHandler(db, profile)
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	for i := 0; i < 3; i++ {
		idempotencyKey := testSeedIdempotencyKey()
		if err := payment.InsertOwnerEscrowEvent(context.Background(), db, ownerID, payment.OwnerDeposit, 1000, idempotencyKey, nil); err != nil {
			t.Fatalf("seed event %d: %v", i, err)
		}
	}

	req := httptest.NewRequest("GET", "/api/v1/owner/"+ownerID.String()+"/escrow?limit=2", nil)
	req.SetPathValue("owner_id", ownerID.String())
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleEscrowHistory(rec, req)

	var resp ownerEscrowHistoryResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Errorf("Events count = %d, want 2 (limit=2 respected)", len(resp.Events))
	}
}

// ── Session 11.5.6 — Owner Withdraw ─────────────────────────────────────────────

type stubInFlightChecker struct{ inFlight bool }

func (s stubInFlightChecker) HasInFlightUpload(context.Context, uuid.UUID) (bool, error) {
	return s.inFlight, nil
}

func withdrawIdempotencyKey(ownerID uuid.UUID) string {
	h := sha256.Sum256([]byte(ownerID.String() + uuid.New().String()))
	return hex.EncodeToString(h[:])
}

func TestOwnerWithdrawSucceedsWhenNoUploadInFlight(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile
	provider := payment.NewMockProvider(db)
	handler := NewOwnerWithdrawHandler(db, profile, provider, stubInFlightChecker{inFlight: false})
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	idempotencyKey := testSeedIdempotencyKey()
	if err := payment.InsertOwnerEscrowEvent(context.Background(), db, ownerID, payment.OwnerDeposit, 100000, idempotencyKey, nil); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}
	if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW mv_owner_escrow_balance`); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	reqBody, _ := json.Marshal(withdrawRequestBody{AmountPaise: 50000, IdempotencyKey: withdrawIdempotencyKey(ownerID)})
	req := httptest.NewRequest("POST", "/api/v1/owner/withdraw", bytes.NewReader(reqBody))
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleWithdraw(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp withdrawResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "QUEUED" || resp.PayoutID == "" {
		t.Errorf("resp = %+v, want Status=QUEUED and non-empty PayoutID", resp)
	}
}

func TestOwnerWithdrawBlockedDuringUpload(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile
	provider := payment.NewMockProvider(db)
	handler := NewOwnerWithdrawHandler(db, profile, provider, stubInFlightChecker{inFlight: true})
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	reqBody, _ := json.Marshal(withdrawRequestBody{AmountPaise: 100, IdempotencyKey: withdrawIdempotencyKey(ownerID)})
	req := httptest.NewRequest("POST", "/api/v1/owner/withdraw", bytes.NewReader(reqBody))
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleWithdraw(rec, req)

	if rec.Code != 409 {
		t.Errorf("status = %d, want 409 (upload in-flight)", rec.Code)
	}
}

func TestOwnerWithdrawRejectsAmountAboveAvailable(t *testing.T) {
	db := openTestDB(t)
	profile := config.DemoProfile
	provider := payment.NewMockProvider(db)
	handler := NewOwnerWithdrawHandler(db, profile, provider, stubInFlightChecker{inFlight: false})
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	reqBody, _ := json.Marshal(withdrawRequestBody{AmountPaise: 999999, IdempotencyKey: withdrawIdempotencyKey(ownerID)})
	req := httptest.NewRequest("POST", "/api/v1/owner/withdraw", bytes.NewReader(reqBody))
	req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
	rec := httptest.NewRecorder()
	handler.HandleWithdraw(rec, req)

	if rec.Code != 409 {
		t.Errorf("status = %d, want 409 (amount exceeds available)", rec.Code)
	}
}

func TestOwnerWithdrawIdempotentOnRetry(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	profile := config.DemoProfile
	provider := payment.NewMockProvider(db)
	handler := NewOwnerWithdrawHandler(db, profile, provider, stubInFlightChecker{inFlight: false})
	ownerID := insertTestOwnerForOwnerTests(t, db, "")

	idempotencyKey := testSeedIdempotencyKey()
	if err := payment.InsertOwnerEscrowEvent(context.Background(), db, ownerID, payment.OwnerDeposit, 100000, idempotencyKey, nil); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}
	if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW mv_owner_escrow_balance`); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	withdrawKey := withdrawIdempotencyKey(ownerID)
	for i := 0; i < 2; i++ {
		reqBody, _ := json.Marshal(withdrawRequestBody{AmountPaise: 50000, IdempotencyKey: withdrawKey})
		req := httptest.NewRequest("POST", "/api/v1/owner/withdraw", bytes.NewReader(reqBody))
		req = withClaims(req, VerifiedClaims{Subject: ownerID, Role: "owner"})
		rec := httptest.NewRecorder()
		handler.HandleWithdraw(rec, req)
		if rec.Code != 200 {
			t.Fatalf("call %d: status = %d, body = %s", i, rec.Code, rec.Body.String())
		}
	}

	var rows int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM owner_escrow_events WHERE idempotency_key = $1`, withdrawKey).Scan(&rows); err != nil {
		t.Fatalf("query: %v", err)
	}
	if rows != 1 {
		t.Errorf("owner_escrow_events rows for this idempotency key = %d, want exactly 1", rows)
	}
}

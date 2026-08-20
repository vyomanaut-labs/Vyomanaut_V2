// Package api is declared in doc.go.
// Unit and live-database integration tests for OTP send/verify.
//
// Tests:
//   - TestOtpSendStoresHashedCode
//   - TestOtpSendRejectsInvalidPhoneNumber
//   - TestOtpSendRateLimited
//   - TestOtpVerifySucceedsAndConsumesCode
//   - TestOtpVerifyRejectsWrongCode
//   - TestOtpVerifyRejectsReplayedCode
//   - TestOtpVerifyNewEntityGetsRegistrationToken
//   - TestOtpVerifyExistingOwnerGetsOwnerToken
//
// [REF: FR-001, OAS OtpSendRequest/Response, OtpVerifyRequest/Response,
// build.md Phase 11.4]

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// capturingOtpSender records the last code sent, for tests that need to
// verify with the real generated code.
type capturingOtpSender struct {
	lastCode string
}

func (c *capturingOtpSender) SendOTP(_ context.Context, _ string, code string) error {
	c.lastCode = code
	return nil
}

func randPhoneForOtp() string {
	var suffix [4]byte
	_, _ = rand.Read(suffix[:])
	// Decimal digits only — E.164's pattern (^\+[1-9]\d{1,14}$) rejects hex
	// letters, which a naive hex-encoded random suffix could produce.
	n := uint64(suffix[0])<<24 | uint64(suffix[1])<<16 | uint64(suffix[2])<<8 | uint64(suffix[3])
	return fmt.Sprintf("+91%010d", n%10000000000)
}

func TestOtpSendStoresHashedCode(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	sender := &capturingOtpSender{}
	handler := NewOtpHandler(db, sender)
	phone := randPhoneForOtp()

	reqBody, _ := json.Marshal(otpSendRequestBody{PhoneNumber: phone, Purpose: "LOGIN"})
	req := httptest.NewRequest("POST", "/api/v1/auth/otp/send", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.HandleSend(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if sender.lastCode == "" {
		t.Fatal("sender never received a code")
	}
	if !otpCodePattern.MatchString(sender.lastCode) {
		t.Errorf("code %q does not match 6-digit pattern", sender.lastCode)
	}

	wantHash := sha256.Sum256([]byte(sender.lastCode))
	var storedHash []byte
	if err := verify.QueryRow(`SELECT code_hash FROM otp_codes WHERE phone_number = $1 ORDER BY created_at DESC LIMIT 1`, phone).
		Scan(&storedHash); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !bytes.Equal(storedHash, wantHash[:]) {
		t.Error("stored code_hash does not match SHA-256 of the code actually sent")
	}

	var rawCount int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM otp_codes WHERE phone_number = $1 AND octet_length(code_hash) != 32`, phone).
		Scan(&rawCount); err != nil {
		t.Fatalf("query: %v", err)
	}
	if rawCount != 0 {
		t.Error("found a code_hash that is not 32 bytes — plaintext code may have leaked into a wrong column")
	}
}

func TestOtpSendRejectsInvalidPhoneNumber(t *testing.T) {
	db := openTestDB(t)
	handler := NewOtpHandler(db, &capturingOtpSender{})

	reqBody, _ := json.Marshal(otpSendRequestBody{PhoneNumber: "not-a-phone-number", Purpose: "LOGIN"})
	req := httptest.NewRequest("POST", "/api/v1/auth/otp/send", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.HandleSend(rec, req)

	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// [M11 audit remediation, Finding 3] Loop bound changed from
// otpRateLimitMax (tautological — passes regardless of what that constant
// is set to, since the loop and the limit are the same variable) to the
// literal 3, per build.md Session 11.4.1 and OAS otp/send's 429
// description ("3 attempts per phone per 10 minutes"). Also now asserts
// the actual Retry-After header value and the body's retry_after field,
// neither of which was checked before — both would have silently stayed
// wrong (3600 instead of 600) even after fixing just the loop bound.
func TestOtpSendRateLimited(t *testing.T) {
	db := openTestDB(t)
	handler := NewOtpHandler(db, &capturingOtpSender{})
	phone := randPhoneForOtp()

	const wantMax = 3
	var lastCode int
	for i := 0; i < wantMax; i++ {
		reqBody, _ := json.Marshal(otpSendRequestBody{PhoneNumber: phone, Purpose: "LOGIN"})
		req := httptest.NewRequest("POST", "/api/v1/auth/otp/send", bytes.NewReader(reqBody))
		rec := httptest.NewRecorder()
		handler.HandleSend(rec, req)
		lastCode = rec.Code
	}
	if lastCode != 200 {
		t.Fatalf("expected the first %d requests to succeed, last status = %d", wantMax, lastCode)
	}

	// One more, over the limit.
	reqBody, _ := json.Marshal(otpSendRequestBody{PhoneNumber: phone, Purpose: "LOGIN"})
	req := httptest.NewRequest("POST", "/api/v1/auth/otp/send", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.HandleSend(rec, req)
	if rec.Code != 429 {
		t.Fatalf("status after exceeding rate limit = %d, want 429", rec.Code)
	}

	const wantRetryAfter = "600" // OAS otp/send 429: "Retry-After: Seconds until the rate limit resets", example 600
	if got := rec.Header().Get("Retry-After"); got != wantRetryAfter {
		t.Errorf("Retry-After header = %q, want %q", got, wantRetryAfter)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body: %v", err)
	}
	if got := body["retry_after"]; got != float64(600) {
		t.Errorf("body retry_after = %v, want 600", got)
	}
}

func TestOtpVerifySucceedsAndConsumesCode(t *testing.T) {
	db := openTestDB(t)
	verify := openVerifyDB(t)
	sender := &capturingOtpSender{}
	otpHandler := NewOtpHandler(db, sender)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	verifyHandler := NewOtpVerifyHandler(otpHandler, priv)
	phone := randPhoneForOtp()

	sendBody, _ := json.Marshal(otpSendRequestBody{PhoneNumber: phone, Purpose: "LOGIN"})
	sendReq := httptest.NewRequest("POST", "/api/v1/auth/otp/send", bytes.NewReader(sendBody))
	otpHandler.HandleSend(httptest.NewRecorder(), sendReq)

	verifyBody, _ := json.Marshal(otpVerifyRequestBody{PhoneNumber: phone, OtpCode: sender.lastCode})
	verifyReq := httptest.NewRequest("POST", "/api/v1/auth/otp/verify", bytes.NewReader(verifyBody))
	rec := httptest.NewRecorder()
	verifyHandler.HandleVerify(rec, verifyReq)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp otpVerifyResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Token == "" {
		t.Error("token is empty")
	}

	var consumedAt sql.NullTime
	if err := verify.QueryRow(`SELECT consumed_at FROM otp_codes WHERE phone_number = $1 ORDER BY created_at DESC LIMIT 1`, phone).
		Scan(&consumedAt); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !consumedAt.Valid {
		t.Error("consumed_at is still NULL after a successful verify")
	}
}

func TestOtpVerifyRejectsWrongCode(t *testing.T) {
	db := openTestDB(t)
	otpHandler := NewOtpHandler(db, &capturingOtpSender{})
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	verifyHandler := NewOtpVerifyHandler(otpHandler, priv)
	phone := randPhoneForOtp()

	sendBody, _ := json.Marshal(otpSendRequestBody{PhoneNumber: phone, Purpose: "LOGIN"})
	sendReq := httptest.NewRequest("POST", "/api/v1/auth/otp/send", bytes.NewReader(sendBody))
	otpHandler.HandleSend(httptest.NewRecorder(), sendReq)

	verifyBody, _ := json.Marshal(otpVerifyRequestBody{PhoneNumber: phone, OtpCode: "000000"})
	verifyReq := httptest.NewRequest("POST", "/api/v1/auth/otp/verify", bytes.NewReader(verifyBody))
	rec := httptest.NewRecorder()
	verifyHandler.HandleVerify(rec, verifyReq)

	if rec.Code != 401 {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestOtpVerifyRejectsReplayedCode(t *testing.T) {
	db := openTestDB(t)
	sender := &capturingOtpSender{}
	otpHandler := NewOtpHandler(db, sender)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	verifyHandler := NewOtpVerifyHandler(otpHandler, priv)
	phone := randPhoneForOtp()

	sendBody, _ := json.Marshal(otpSendRequestBody{PhoneNumber: phone, Purpose: "LOGIN"})
	sendReq := httptest.NewRequest("POST", "/api/v1/auth/otp/send", bytes.NewReader(sendBody))
	otpHandler.HandleSend(httptest.NewRecorder(), sendReq)

	verifyBody, _ := json.Marshal(otpVerifyRequestBody{PhoneNumber: phone, OtpCode: sender.lastCode})

	req1 := httptest.NewRequest("POST", "/api/v1/auth/otp/verify", bytes.NewReader(verifyBody))
	rec1 := httptest.NewRecorder()
	verifyHandler.HandleVerify(rec1, req1)
	if rec1.Code != 200 {
		t.Fatalf("first verify: status = %d, want 200", rec1.Code)
	}

	req2 := httptest.NewRequest("POST", "/api/v1/auth/otp/verify", bytes.NewReader(verifyBody))
	rec2 := httptest.NewRecorder()
	verifyHandler.HandleVerify(rec2, req2)
	if rec2.Code != 401 {
		t.Errorf("replayed verify: status = %d, want 401", rec2.Code)
	}
}

func TestOtpVerifyNewEntityGetsRegistrationToken(t *testing.T) {
	db := openTestDB(t)
	sender := &capturingOtpSender{}
	otpHandler := NewOtpHandler(db, sender)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	verifyHandler := NewOtpVerifyHandler(otpHandler, priv)
	phone := randPhoneForOtp() // guaranteed not to exist in owners or providers

	sendBody, _ := json.Marshal(otpSendRequestBody{PhoneNumber: phone, Purpose: "OWNER_REGISTER"})
	sendReq := httptest.NewRequest("POST", "/api/v1/auth/otp/send", bytes.NewReader(sendBody))
	otpHandler.HandleSend(httptest.NewRecorder(), sendReq)

	verifyBody, _ := json.Marshal(otpVerifyRequestBody{PhoneNumber: phone, OtpCode: sender.lastCode})
	verifyReq := httptest.NewRequest("POST", "/api/v1/auth/otp/verify", bytes.NewReader(verifyBody))
	rec := httptest.NewRecorder()
	verifyHandler.HandleVerify(rec, verifyReq)

	var resp otpVerifyResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.IsNewEntity {
		t.Error("IsNewEntity = false, want true for a never-before-seen phone number")
	}
	if resp.Role != nil {
		t.Errorf("Role = %v, want nil for a registration token", resp.Role)
	}
	if resp.EntityID != nil {
		t.Errorf("EntityID = %v, want nil for a registration token", resp.EntityID)
	}

	claims, err := VerifyJWT(pub, resp.Token)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if claims.Role != "" {
		t.Errorf("token Role = %q, want empty for a registration token", claims.Role)
	}
	wantSubject := RegistrationSubjectForPhone(phone)
	if claims.Subject != wantSubject {
		t.Errorf("token Subject = %v, want deterministic %v", claims.Subject, wantSubject)
	}

	// The pending_registrations bridge row must exist so a subsequent
	// register call can recover this phone number from claims.Subject alone.
	recoveredPhone, recoveredPurpose, err := RecoverPendingRegistration(context.Background(), db, claims.Subject)
	if err != nil {
		t.Fatalf("RecoverPendingRegistration: %v", err)
	}
	if recoveredPhone != phone {
		t.Errorf("RecoverPendingRegistration phone = %q, want %q", recoveredPhone, phone)
	}
	// [M11 audit remediation, Finding 4] purpose must round-trip through
	// pending_registrations too — this is what owner.go's/provider.go's
	// register handlers gate on.
	if recoveredPurpose != "OWNER_REGISTER" {
		t.Errorf("RecoverPendingRegistration purpose = %q, want %q", recoveredPurpose, "OWNER_REGISTER")
	}
}

func TestOtpVerifyExistingOwnerGetsOwnerToken(t *testing.T) {
	db := openTestDB(t)
	sender := &capturingOtpSender{}
	otpHandler := NewOtpHandler(db, sender)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	verifyHandler := NewOtpVerifyHandler(otpHandler, priv)

	phone := randPhoneForOtp()
	ownerID := uuid.New()
	var pubkey [32]byte
	_, _ = rand.Read(pubkey[:])
	if _, err := db.Exec(`INSERT INTO owners (owner_id, phone_number, ed25519_public_key) VALUES ($1,$2,$3)`,
		ownerID, phone, pubkey[:]); err != nil {
		t.Fatalf("insert test owner: %v", err)
	}

	sendBody, _ := json.Marshal(otpSendRequestBody{PhoneNumber: phone, Purpose: "LOGIN"})
	sendReq := httptest.NewRequest("POST", "/api/v1/auth/otp/send", bytes.NewReader(sendBody))
	otpHandler.HandleSend(httptest.NewRecorder(), sendReq)

	verifyBody, _ := json.Marshal(otpVerifyRequestBody{PhoneNumber: phone, OtpCode: sender.lastCode})
	verifyReq := httptest.NewRequest("POST", "/api/v1/auth/otp/verify", bytes.NewReader(verifyBody))
	rec := httptest.NewRecorder()
	verifyHandler.HandleVerify(rec, verifyReq)

	var resp otpVerifyResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.IsNewEntity {
		t.Error("IsNewEntity = true, want false for an already-registered owner")
	}
	if resp.Role == nil || *resp.Role != "owner" {
		t.Errorf("Role = %v, want \"owner\"", resp.Role)
	}
	if resp.EntityID == nil || *resp.EntityID != ownerID.String() {
		t.Errorf("EntityID = %v, want %q", resp.EntityID, ownerID.String())
	}

	claims, err := VerifyJWT(pub, resp.Token)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if claims.Subject != ownerID {
		t.Errorf("token Subject = %v, want %v", claims.Subject, ownerID)
	}
	if claims.Expiry.Sub(time.Now().UTC()) > OwnerTokenTTL || claims.Expiry.Before(time.Now().UTC()) {
		t.Errorf("token expiry %v is not within OwnerTokenTTL of now", claims.Expiry)
	}
}

// ── FileOtpSender (ADR-084 D-3, M17-E Session 17.4.2) ──────────────────────
//
// Tests:
//   - TestFileOtpSenderAppendsOneLinePerSend
//   - TestFileOtpSenderCreatesLogMode0600
//   - TestFileOtpSenderIsConcurrencySafe

func TestFileOtpSenderAppendsOneLinePerSend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "otp-delivery.log")
	sender, err := NewFileOtpSender(path)
	if err != nil {
		t.Fatalf("NewFileOtpSender: %v", err)
	}
	t.Cleanup(func() { _ = sender.Close() })

	if err := sender.SendOTP(context.Background(), "+919876500001", "111111"); err != nil {
		t.Fatalf("SendOTP (1): %v", err)
	}
	if err := sender.SendOTP(context.Background(), "+919876500002", "222222"); err != nil {
		t.Fatalf("SendOTP (2): %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read delivery log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (one send == one line): %q", len(lines), data)
	}
	if !strings.Contains(lines[0], "+919876500001") || !strings.Contains(lines[0], "111111") {
		t.Errorf("line 1 = %q, want it to contain the phone number and code", lines[0])
	}
	if !strings.Contains(lines[1], "+919876500002") || !strings.Contains(lines[1], "222222") {
		t.Errorf("line 2 = %q, want it to contain the phone number and code", lines[1])
	}
}

func TestFileOtpSenderCreatesLogMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "otp-delivery.log")
	sender, err := NewFileOtpSender(path)
	if err != nil {
		t.Fatalf("NewFileOtpSender: %v", err)
	}
	t.Cleanup(func() { _ = sender.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("delivery log mode = %o, want 0600 — this file holds plaintext OTP codes", perm)
	}
}

// TestFileOtpSenderIsConcurrencySafe fires many SendOTP calls concurrently
// (the shape multiple in-flight HandleSend requests produce) and verifies
// every line survives intact — a missing mutex would interleave partial
// writes and corrupt, merge, or drop lines under `go test -race`.
func TestFileOtpSenderIsConcurrencySafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "otp-delivery.log")
	sender, err := NewFileOtpSender(path)
	if err != nil {
		t.Fatalf("NewFileOtpSender: %v", err)
	}
	t.Cleanup(func() { _ = sender.Close() })

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = sender.SendOTP(context.Background(), fmt.Sprintf("+9198765%05d", i), fmt.Sprintf("%06d", i))
		}(i)
	}
	wg.Wait()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read delivery log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d — a data race would corrupt/merge/drop concurrent writes", len(lines), n)
	}
}

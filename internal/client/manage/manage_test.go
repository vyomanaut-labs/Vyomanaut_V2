// Package manage is declared in doc.go.
// Unit tests for file list/delete (Session 15.4.1) and escrow balance/
// deposit/withdraw (Session 15.4.2). No live database is needed — this
// package never touches Postgres directly. An httptest.Server stands in
// for the microservice REST API.
//
// Tests:
//   - TestFileListDecryptsDisplayNameWhenPresent
//   - TestFileListFallsBackToFileIDWhenNamePlaintextAbsent
//   - TestFileListRendersAvailabilityThroughLabelMapping
//   - TestFileDeleteSurfacesProviderNotificationCounts
//   - TestFileDeleteTreats409AsIdempotentSuccess
//   - TestBalanceRendersAllThreeFiguresAsIntegerPaise
//   - TestDepositRendersIntentURLWhenPresent
//   - TestDepositFallsBackToVPAAndQRWhenIntentURLAbsent
//   - TestWithdrawReusesSameIdempotencyKeyOnRetry
//   - TestWithdrawSurfaces409AsActionableMessage
//
// [REF: MVP §8.2 Phase 15.4 Session 15.4.1, Session 15.4.2]

package manage

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
)

// ── Test helpers ────────────────────────────────────────────────────────

// manageTestServer wires the endpoints this package calls against
// configurable, per-test handlers.
type manageTestServer struct {
	*httptest.Server
	filesResp    fileListResponse
	deleteStatus int
	deleteResp   deleteFileResponse
	deleteErr    apiError
	balanceResp  ownerBalanceResponse
	depositResp  depositInitiateResponse
	withdrawFunc func(req withdrawRequest) (int, withdrawResponse, apiError)
}

func newManageTestServer(t *testing.T) *manageTestServer {
	t.Helper()
	ts := &manageTestServer{deleteStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/owner/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && hasSuffix(r.URL.Path, "/files"):
			writeJSON(w, http.StatusOK, ts.filesResp)
		case r.Method == http.MethodGet && hasSuffix(r.URL.Path, "/balance"):
			writeJSON(w, http.StatusOK, ts.balanceResp)
		case r.Method == http.MethodPost && hasSuffix(r.URL.Path, "/deposit"):
			writeJSON(w, http.StatusOK, ts.depositResp)
		case r.Method == http.MethodPost && hasSuffix(r.URL.Path, "/withdraw"):
			var req withdrawRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			status, resp, apiErr := ts.withdrawFunc(req)
			if status == http.StatusOK || status == http.StatusCreated || status == http.StatusAccepted {
				writeJSON(w, status, resp)
			} else {
				writeJSON(w, status, apiErr)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	mux.HandleFunc("/api/v1/file/", func(w http.ResponseWriter, r *http.Request) {
		if ts.deleteStatus == http.StatusOK {
			writeJSON(w, http.StatusOK, ts.deleteResp)
			return
		}
		writeJSON(w, ts.deleteStatus, ts.deleteErr)
	})
	ts.Server = httptest.NewServer(mux)
	return ts
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newTestManager(baseURL string) *Manager {
	return NewManager(baseURL, "test-token", nil)
}

// encryptTestDisplayName encrypts name the same way upload/pointer.go's
// registerPointerFile does, so files.go's decryptDisplayName is exercised
// against a real ciphertext, not a synthetic stand-in.
func encryptTestDisplayName(t *testing.T, masterSecret [32]byte, ownerID, fileID uuid.UUID, name string) (ciphertextB64, nonceB64, tagB64 string) {
	t.Helper()
	key := deriveFilenameKey(masterSecret[:], ownerID[:], fileID[:])
	var nonce [12]byte
	nonce[len(nonce)-1] = 1
	full, err := crypto.EncryptAEAD(key, nonce, filenameAAD(ownerID, fileID), []byte(name))
	if err != nil {
		t.Fatalf("EncryptAEAD: %v", err)
	}
	ciphertext := full[:len(full)-16]
	tag := full[len(full)-16:]
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce[:]), base64.StdEncoding.EncodeToString(tag)
}

// ── Session 15.4.1 tests ────────────────────────────────────────────────

func TestFileListDecryptsDisplayNameWhenPresent(t *testing.T) {
	var masterSecret [32]byte
	_, _ = cryptorand.Read(masterSecret[:])
	ownerID, fileID := uuid.New(), uuid.New()
	const wantName = "vacation-photos.zip"

	ctB64, nonceB64, tagB64 := encryptTestDisplayName(t, masterSecret, ownerID, fileID, wantName)

	ts := newManageTestServer(t)
	defer ts.Close()
	ts.filesResp = fileListResponse{Files: []fileListItem{
		{
			FileID: fileID, OriginalSizeBytes: 1024, UploadedAt: time.Now(),
			MonthlyCostPaise: 100, Status: "ACTIVE", Availability: "OK",
			AvailableShardCount: 5, TotalShardCount: 5,
			DisplayNameCiphertext: &ctB64, DisplayNameNonce: &nonceB64, DisplayNameTag: &tagB64,
		},
	}}

	m := newTestManager(ts.URL)
	entries, err := m.ListFiles(context.Background(), masterSecret, ownerID)
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].DisplayName != wantName {
		t.Errorf("DisplayName = %q, want %q", entries[0].DisplayName, wantName)
	}
}

func TestFileListFallsBackToFileIDWhenNamePlaintextAbsent(t *testing.T) {
	ownerID, fileID := uuid.New(), uuid.New()
	ts := newManageTestServer(t)
	defer ts.Close()
	ts.filesResp = fileListResponse{Files: []fileListItem{
		{
			FileID: fileID, OriginalSizeBytes: 1024, UploadedAt: time.Now(),
			MonthlyCostPaise: 100, Status: "ACTIVE", Availability: "OK",
			AvailableShardCount: 5, TotalShardCount: 5,
			// No display_name_* fields set.
		},
	}}

	m := newTestManager(ts.URL)
	var masterSecret [32]byte
	entries, err := m.ListFiles(context.Background(), masterSecret, ownerID)
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].DisplayName != fileID.String() {
		t.Errorf("DisplayName = %q, want file_id string %q", entries[0].DisplayName, fileID.String())
	}
}

func TestFileListRendersAvailabilityThroughLabelMapping(t *testing.T) {
	ownerID := uuid.New()
	ts := newManageTestServer(t)
	defer ts.Close()
	ts.filesResp = fileListResponse{Files: []fileListItem{
		{FileID: uuid.New(), OriginalSizeBytes: 1, UploadedAt: time.Now(), Status: "ACTIVE", Availability: "DEGRADED", TotalShardCount: 5},
	}}

	m := newTestManager(ts.URL)
	var masterSecret [32]byte
	entries, err := m.ListFiles(context.Background(), masterSecret, ownerID)
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	want := AvailabilityLabel("DEGRADED")
	if entries[0].AvailabilityLabel != want {
		t.Errorf("AvailabilityLabel = %q, want %q (the mapped label, not necessarily the raw enum)", entries[0].AvailabilityLabel, want)
	}
}

func TestFileDeleteSurfacesProviderNotificationCounts(t *testing.T) {
	ts := newManageTestServer(t)
	defer ts.Close()
	ts.deleteStatus = http.StatusOK
	ts.deleteResp = deleteFileResponse{
		FileID: uuid.New(), AssignmentsMarked: 56, ProvidersNotified: 50, ProvidersPending: 6, Status: "DELETED",
	}

	m := newTestManager(ts.URL)
	result, err := m.DeleteFile(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if result.AssignmentsMarked != 56 || result.ProvidersNotified != 50 || result.ProvidersPending != 6 {
		t.Errorf("DeleteResult = %+v, want AssignmentsMarked=56 ProvidersNotified=50 ProvidersPending=6", result)
	}
	if result.AlreadyDeleted {
		t.Errorf("AlreadyDeleted = true for a fresh 200 deletion")
	}
}

func TestFileDeleteTreats409AsIdempotentSuccess(t *testing.T) {
	ts := newManageTestServer(t)
	defer ts.Close()
	ts.deleteStatus = http.StatusConflict
	ts.deleteErr = apiError{ErrorCode: "FILE_ALREADY_DELETED", Message: "already deleted", RequestID: uuid.NewString()}

	m := newTestManager(ts.URL)
	result, err := m.DeleteFile(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("DeleteFile with FILE_ALREADY_DELETED: got error %v, want nil (idempotent success)", err)
	}
	if !result.AlreadyDeleted {
		t.Errorf("AlreadyDeleted = false, want true")
	}
}

// ── Session 15.4.2 tests ────────────────────────────────────────────────

func TestBalanceRendersAllThreeFiguresAsIntegerPaise(t *testing.T) {
	ts := newManageTestServer(t)
	defer ts.Close()
	ts.balanceResp = ownerBalanceResponse{BalancePaise: 500000, ReservedNext30dPaise: 120000, AvailablePaise: 380000}

	m := newTestManager(ts.URL)
	balance, reserved, available, err := m.Balance(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if balance != 500000 || reserved != 120000 || available != 380000 {
		t.Errorf("Balance() = (%d, %d, %d), want (500000, 120000, 380000)", balance, reserved, available)
	}
}

func TestDepositRendersIntentURLWhenPresent(t *testing.T) {
	ts := newManageTestServer(t)
	defer ts.Close()
	intentURL := "upi://pay?pa=vyomanaut@upi&pn=Vyomanaut&am=100.00&cu=INR&tr=abc123"
	ts.depositResp = depositInitiateResponse{
		VPA: "vyomanaut@upi", QRCodeURL: "https://example.com/qr.png",
		IntentURL: &intentURL, ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	m := newTestManager(ts.URL)
	info, err := m.Deposit(context.Background(), 10000)
	if err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if !info.UsesIntentURL {
		t.Fatal("UsesIntentURL = false, want true when intent_url is present in the response")
	}
	if info.PrimaryOutput != intentURL {
		t.Errorf("PrimaryOutput = %q, want the intent_url %q", info.PrimaryOutput, intentURL)
	}
}

func TestDepositFallsBackToVPAAndQRWhenIntentURLAbsent(t *testing.T) {
	ts := newManageTestServer(t)
	defer ts.Close()
	ts.depositResp = depositInitiateResponse{
		VPA: "vyomanaut@upi", QRCodeURL: "https://example.com/qr.png",
		IntentURL: nil, ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	m := newTestManager(ts.URL)
	info, err := m.Deposit(context.Background(), 10000)
	if err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if info.UsesIntentURL {
		t.Fatal("UsesIntentURL = true, want false when intent_url is absent from the response")
	}
	if info.PrimaryOutput != "vyomanaut@upi" {
		t.Errorf("PrimaryOutput = %q, want the vpa fallback %q", info.PrimaryOutput, "vyomanaut@upi")
	}
	if info.QRCodeURL != "https://example.com/qr.png" {
		t.Errorf("QRCodeURL = %q, want %q", info.QRCodeURL, "https://example.com/qr.png")
	}
}

func TestWithdrawReusesSameIdempotencyKeyOnRetry(t *testing.T) {
	ownerID := uuid.New()
	withdrawalRequestID := uuid.New()

	var capturedKeys []string
	ts := newManageTestServer(t)
	defer ts.Close()
	attempt := 0
	ts.withdrawFunc = func(req withdrawRequest) (int, withdrawResponse, apiError) {
		capturedKeys = append(capturedKeys, req.IdempotencyKey)
		attempt++
		if attempt == 1 {
			// Simulate a transient failure on the first attempt.
			return http.StatusInternalServerError, withdrawResponse{}, apiError{ErrorCode: "INTERNAL_ERROR", Message: "transient", RequestID: uuid.NewString()}
		}
		return http.StatusOK, withdrawResponse{PayoutID: "pout_TEST123", AmountPaise: 5000, Status: "QUEUED"}, apiError{}
	}

	m := newTestManager(ts.URL)
	// First attempt fails.
	if _, err := m.Withdraw(context.Background(), ownerID, withdrawalRequestID, 5000); err == nil {
		t.Fatal("expected the first (simulated transient failure) attempt to return an error")
	}
	// Retry with the SAME withdrawalRequestID.
	payoutID, err := m.Withdraw(context.Background(), ownerID, withdrawalRequestID, 5000)
	if err != nil {
		t.Fatalf("Withdraw retry: %v", err)
	}
	if payoutID != "pout_TEST123" {
		t.Errorf("payoutID = %q, want %q", payoutID, "pout_TEST123")
	}

	if len(capturedKeys) != 2 {
		t.Fatalf("captured %d idempotency keys, want 2 (one per attempt)", len(capturedKeys))
	}
	if capturedKeys[0] != capturedKeys[1] {
		t.Errorf("idempotency key changed across retry: %q != %q — a fresh key on retry defeats FR-059's guarantee", capturedKeys[0], capturedKeys[1])
	}
	wantKey := withdrawIdempotencyKey(ownerID, withdrawalRequestID)
	if capturedKeys[0] != wantKey {
		t.Errorf("idempotency key = %q, want SHA-256(owner_id||withdrawal_request_id) = %q", capturedKeys[0], wantKey)
	}
}

func TestWithdrawSurfaces409AsActionableMessage(t *testing.T) {
	ts := newManageTestServer(t)
	defer ts.Close()
	ts.withdrawFunc = func(req withdrawRequest) (int, withdrawResponse, apiError) {
		return http.StatusConflict, withdrawResponse{}, apiError{ErrorCode: "UPLOAD_IN_FLIGHT", Message: "blocked", RequestID: uuid.NewString()}
	}

	m := newTestManager(ts.URL)
	_, err := m.Withdraw(context.Background(), uuid.New(), uuid.New(), 5000)
	if !errors.Is(err, ErrWithdrawBlockedUploadInFlight) {
		t.Fatalf("Withdraw error = %v, want ErrWithdrawBlockedUploadInFlight (an explicit, actionable message, not a generic error)", err)
	}
}

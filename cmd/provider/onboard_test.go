package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnboardFlow is a thin wrapper so `go test -run TestOnboardFlow`
// matches every test below — same pattern dispatch_test.go's
// TestDispatchRouting already uses.
func TestOnboardFlow(t *testing.T) {
	t.Run("TestOnboardRejectsMissingStorageGB", TestOnboardRejectsMissingStorageGB)
	t.Run("TestOnboardNeverWritesTheCodeToDisk", TestOnboardNeverWritesTheCodeToDisk)
}

// TestOnboardRejectsMissingStorageGB verifies resolveStorageGB errors out
// rather than defaulting silently when neither --storage-gb nor an
// interactive answer is available (requirement 11: the allocation is a
// question the human answers, never an invented default).
func TestOnboardRejectsMissingStorageGB(t *testing.T) {
	_, err := resolveStorageGB(0, io.Discard, strings.NewReader(""))
	if err == nil {
		t.Fatal("resolveStorageGB(0, ..., empty stdin): expected an error, got nil")
	}
}

// newFakeOnboardServer stands in for cmd/microservice, implementing only
// the three endpoints runOnboard calls, and asserting the delivered OTP
// code matches expectedCode before issuing a registration token — the
// same check the real server performs against otp_codes.code_hash.
func newFakeOnboardServer(t *testing.T, expectedCode string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/auth/otp/send", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("POST /api/v1/auth/otp/verify", func(w http.ResponseWriter, r *http.Request) {
		var req onboardOtpVerifyRequestBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("fake server: decode otp verify request: %v", err)
		}
		if req.OtpCode != expectedCode {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(onboardOtpVerifyResponseBody{Token: "fake-registration-token", IsNewEntity: true})
	})

	mux.HandleFunc("POST /api/v1/provider/register", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer fake-registration-token" {
			t.Errorf("fake server: register Authorization = %q, want Bearer fake-registration-token", got)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(providerRegisterResponseBody{
			ProviderID: "11111111-1111-1111-1111-111111111111",
			Status:     "VETTING",
			Token:      "fake-provider-jwt",
		})
	})

	return httptest.NewServer(mux)
}

// TestOnboardNeverWritesTheCodeToDisk runs the full onboarding flow against
// a fake microservice, feeding a known OTP code on stdin, then walks every
// file runOnboard created under --data-dir and asserts the raw code
// appears in none of them — the behavioral proof of TASK item 6 ("never
// written to a file"), stronger than a source-text grep because it
// exercises the actual code path rather than trusting that no call site
// was missed.
func TestOnboardNeverWritesTheCodeToDisk(t *testing.T) {
	const otpCode = "482913"
	server := newFakeOnboardServer(t, otpCode)
	defer server.Close()

	dataDir := t.TempDir()
	flags := onboardFlags{
		microserviceURL: server.URL,
		phone:           "+919876500001",
		storageGB:       30, // set directly — this test is about the OTP code, not the storage prompt (see TestOnboardRejectsMissingStorageGB)
		dataDir:         dataDir,
		listenPort:      4001,
		city:            demoProviderCity,
		region:          demoProviderRegion,
	}

	stdin := strings.NewReader(otpCode + "\n")
	rec, err := runOnboard(context.Background(), flags, io.Discard, stdin)
	if err != nil {
		t.Fatalf("runOnboard: %v", err)
	}
	if rec.ProviderID == "" {
		t.Fatal("runOnboard: returned an empty ProviderID")
	}

	walkErr := filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Contains(data, []byte(otpCode)) {
			t.Errorf("%s contains the raw OTP code %q — it must never be persisted (ADR-084 D-3, TASK item 6)", path, otpCode)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk data dir: %v", walkErr)
	}
}

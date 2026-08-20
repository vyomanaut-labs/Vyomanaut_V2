package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEarningsFlow is a thin wrapper so `go test -run TestEarningsFlow`
// matches every test below — same pattern this package's other test files
// already use.
func TestEarningsFlow(t *testing.T) {
	t.Run("TestEarningsFormatsPaiseAsIntegerRupees", TestEarningsFormatsPaiseAsIntegerRupees)
	t.Run("TestEarningsFailsCleanlyWithNoRegistration", TestEarningsFailsCleanlyWithNoRegistration)
	t.Run("TestEarningsJSONOutputIsValidJSON", TestEarningsJSONOutputIsValidJSON)
}

func newFakeStatusServer(t *testing.T, wantProviderID, wantToken string, body providerStatusResponseBody) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/provider/{provider_id}/status", func(w http.ResponseWriter, r *http.Request) {
		if got := r.PathValue("provider_id"); got != wantProviderID {
			t.Errorf("provider_id path value = %q, want %q", got, wantProviderID)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+wantToken {
			t.Errorf("Authorization = %q, want %q", got, "Bearer "+wantToken)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	})
	return httptest.NewServer(mux)
}

// TestEarningsFormatsPaiseAsIntegerRupees runs the full flow — fake
// server, real runEarnings, real formatPaise — and verifies the rendered
// output contains the correctly-formatted rupee figures for both pending
// and held earnings, proving the paise→rupee conversion end to end rather
// than only unit-testing the formatter in isolation (money_test.go does
// that separately).
func TestEarningsFormatsPaiseAsIntegerRupees(t *testing.T) {
	const providerID = "11111111-1111-1111-1111-111111111111"
	const token = "test-jwt"

	server := newFakeStatusServer(t, providerID, token, providerStatusResponseBody{
		ProviderID:           providerID,
		Status:               "ACTIVE",
		PendingEarningsPaise: 123456,
		HeldEarningsPaise:    7890,
		StoredChunks:         42,
		StorageAdvisoryGB:    70,
	})
	defer server.Close()

	dataDir := t.TempDir()
	if err := saveRegistrationRecord(dataDir, registrationRecord{
		ProviderID: providerID, Token: token, DeclaredStorageGB: 50,
	}); err != nil {
		t.Fatalf("saveRegistrationRecord: %v", err)
	}

	var out bytes.Buffer
	flags := earningsFlags{microserviceURL: server.URL, dataDir: dataDir}
	if err := runEarnings(context.Background(), flags, &out); err != nil {
		t.Fatalf("runEarnings: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "\u20b91234.56") {
		t.Errorf("output missing formatted pending earnings (\u20b91234.56): %s", got)
	}
	if !strings.Contains(got, "\u20b978.90") {
		t.Errorf("output missing formatted held earnings (\u20b978.90): %s", got)
	}
	if !strings.Contains(got, "50 GB") {
		t.Errorf("output missing declared allocation (50 GB): %s", got)
	}
	if !strings.Contains(got, "70 GB") {
		t.Errorf("output missing NFR-044 ceiling (70 GB): %s", got)
	}
}

// TestEarningsFailsCleanlyWithNoRegistration verifies runEarnings refuses
// with a clear error rather than attempting a request with an empty
// bearer token — the same discipline depart.go's equivalent check uses.
func TestEarningsFailsCleanlyWithNoRegistration(t *testing.T) {
	dataDir := t.TempDir()
	var out bytes.Buffer
	flags := earningsFlags{microserviceURL: "http://127.0.0.1:1", dataDir: dataDir}
	err := runEarnings(context.Background(), flags, &out)
	if err == nil {
		t.Fatal("runEarnings with no prior onboard: expected an error, got nil")
	}
}

// TestEarningsJSONOutputIsValidJSON verifies --json produces output that
// actually parses back — the contract cmd/operator (a later M17-E
// session) will depend on when it shells out to this subcommand.
func TestEarningsJSONOutputIsValidJSON(t *testing.T) {
	const providerID = "22222222-2222-2222-2222-222222222222"
	const token = "test-jwt-2"

	server := newFakeStatusServer(t, providerID, token, providerStatusResponseBody{
		ProviderID: providerID, Status: "ACTIVE", PendingEarningsPaise: 100, HeldEarningsPaise: 0,
	})
	defer server.Close()

	dataDir := t.TempDir()
	if err := saveRegistrationRecord(dataDir, registrationRecord{ProviderID: providerID, Token: token, DeclaredStorageGB: 20}); err != nil {
		t.Fatalf("saveRegistrationRecord: %v", err)
	}

	var out bytes.Buffer
	flags := earningsFlags{microserviceURL: server.URL, dataDir: dataDir, jsonOutput: true}
	if err := runEarnings(context.Background(), flags, &out); err != nil {
		t.Fatalf("runEarnings: %v", err)
	}

	var parsed providerStatusResponseBody
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("--json output did not parse: %v\noutput: %s", err, out.String())
	}
	if parsed.ProviderID != providerID {
		t.Errorf("parsed ProviderID = %q, want %q", parsed.ProviderID, providerID)
	}
}

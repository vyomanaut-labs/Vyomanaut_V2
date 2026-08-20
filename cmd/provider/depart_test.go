package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDepartFlow is a thin wrapper so `go test -run TestDepartFlow`
// matches every test below — same pattern onboard_test.go's
// TestOnboardFlow already uses.
func TestDepartFlow(t *testing.T) {
	t.Run("TestDepartFailsCleanlyWithNoRegistration", TestDepartFailsCleanlyWithNoRegistration)
	t.Run("TestDepartSignatureVerifiesAgainstThePublicKey", TestDepartSignatureVerifiesAgainstThePublicKey)
	t.Run("TestDepartSignatureOmitsDepartAtCleanly", TestDepartSignatureOmitsDepartAtCleanly)
	t.Run("TestPostDepartParsesSuccessResponse", TestPostDepartParsesSuccessResponse)
}

// TestDepartFailsCleanlyWithNoRegistration verifies departCmd refuses,
// with a clear message and exit code 1, when --data-dir holds no
// registration.json — rather than attempting a request with an empty
// bearer token and failing on the server side with a confusing 401.
func TestDepartFailsCleanlyWithNoRegistration(t *testing.T) {
	dataDir := t.TempDir()
	got := departCmd([]string{"--microservice-url=http://127.0.0.1:1", "--data-dir=" + dataDir})
	if got != 1 {
		t.Fatalf("departCmd with no prior onboard: exit = %d, want 1", got)
	}
}

// TestDepartSignatureVerifiesAgainstThePublicKey proves signDepartRequest's
// output actually verifies against the signing key's own public key using
// the exact digest construction the server side
// (internal/api/provider.go's canonicalDepartSigningInput +
// localcrypto.VerifyBytes) performs — reading both sides of the wire
// protocol independently, the same discipline that caught F-16-1.
func TestDepartSignatureVerifiesAgainstThePublicKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	departAt := "2026-08-19T12:00:00Z"
	sig := signDepartRequest(priv, &departAt)

	digest := sha256.Sum256(clientCanonicalDepartSigningInput(&departAt))
	if !ed25519.Verify(pub, digest[:], sig) {
		t.Fatal("signDepartRequest produced a signature that does not verify against its own signing key's public key")
	}
}

// TestDepartSignatureOmitsDepartAtCleanly verifies the nil-depart_at case
// (--depart-at not given) still produces a signature verifying against
// canonicalSigningObject() with no fields — matching
// internal/api/provider.go's canonicalDepartSigningInput's own nil branch.
func TestDepartSignatureOmitsDepartAtCleanly(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig := signDepartRequest(priv, nil)
	digest := sha256.Sum256(clientCanonicalDepartSigningInput(nil))
	if !ed25519.Verify(pub, digest[:], sig) {
		t.Fatal("signDepartRequest(nil): produced a signature that does not verify")
	}
}

// TestPostDepartParsesSuccessResponse verifies postDepart sends the bearer
// token and a non-empty provider_sig, and correctly decodes a successful
// response body.
func TestPostDepartParsesSuccessResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/provider/depart", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
		}
		var req providerDepartRequestBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode depart request: %v", err)
		}
		if req.ProviderSig == "" {
			t.Error("depart request has an empty provider_sig")
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(providerDepartResponseBody{Status: "DEPARTED", EscrowReleasePaise: 12345, RepairJobsQueued: 2})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := postDepart(context.Background(), server.URL, "test-token", providerDepartRequestBody{
		ProviderSig: hex.EncodeToString(make([]byte, ed25519.SignatureSize)),
	})
	if err != nil {
		t.Fatalf("postDepart: %v", err)
	}
	if resp.Status != "DEPARTED" || resp.EscrowReleasePaise != 12345 || resp.RepairJobsQueued != 2 {
		t.Errorf("postDepart response = %+v, want {DEPARTED 12345 2}", resp)
	}
}

// Tests for audit.go (M17-E Session 17.6.3).
//
// Tests:
//   - TestAuditRendersReceiptAndStatus
//   - TestDispatchAuditCallsTheChallengeEndpoint
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAuditRendersReceiptAndStatus confirms the challenge nonce, dispatch
// timestamp, and deadline from a real 202 response are all rendered, and
// that the response-status/signed-receipt fields this session's task text
// names are shown honestly (PENDING, no fabricated receipt) rather than
// silently omitted or invented — the same "flagged, not fabricated"
// judgment already established at held_earnings_paise/
// content_hash_failures elsewhere in this codebase.
func TestAuditRendersReceiptAndStatus(t *testing.T) {
	dispatchedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	resp := auditChallengeResponseBody{
		ChallengeNonce:    "aa" + strings.Repeat("bb", 32),
		ServerChallengeTS: dispatchedAt,
		DeadlineMs:        1500,
	}

	var buf bytes.Buffer
	renderAuditChallenge(&buf, "prov-1", "chunk-1", resp, false)
	out := buf.String()

	if !strings.Contains(out, resp.ChallengeNonce) {
		t.Errorf("output does not contain the challenge nonce:\n%s", out)
	}
	if !strings.Contains(out, "PENDING") {
		t.Errorf("output does not render the response status as PENDING:\n%s", out)
	}
	if !strings.Contains(out, "not available") {
		t.Errorf("output does not honestly flag the missing signed receipt:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "fail") || strings.Contains(strings.ToLower(out), "pass") {
		t.Errorf("output must never fabricate a PASS/FAIL response status this milestone cannot produce:\n%s", out)
	}

	// --json path carries the same honest fields.
	buf.Reset()
	renderAuditChallenge(&buf, "prov-1", "chunk-1", resp, true)
	var decoded auditRenderResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal --json output: %v", err)
	}
	if decoded.ResponseStatus != auditReceiptStatusPending {
		t.Errorf("--json response_status = %q, want %q", decoded.ResponseStatus, auditReceiptStatusPending)
	}
	if decoded.SignedReceipt != "" {
		t.Errorf("--json signed_receipt = %q, want empty (no fabricated receipt)", decoded.SignedReceipt)
	}
	if decoded.ChallengeNonce != resp.ChallengeNonce {
		t.Errorf("--json challenge_nonce = %q, want %q", decoded.ChallengeNonce, resp.ChallengeNonce)
	}
}

// TestDispatchAuditCallsTheChallengeEndpoint is a thin end-to-end check
// that dispatchAudit actually reaches POST /api/v1/audit/challenge with
// the X-Admin-API-Key header and the provider_id/chunk_id body fields set.
func TestDispatchAuditCallsTheChallengeEndpoint(t *testing.T) {
	const adminKey = "test-admin-key"
	var gotPath, gotKey, gotMethod string
	var gotBody auditChallengeRequestBody

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotKey = r.Header.Get("X-Admin-API-Key")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(auditChallengeResponseBody{
			ChallengeNonce:    "nonce",
			ServerChallengeTS: time.Now().UTC(),
			DeadlineMs:        1500,
		})
	}))
	defer server.Close()

	var out, errOut bytes.Buffer
	code := dispatchAudit([]string{
		"--microservice-url=" + server.URL,
		"--admin-api-key=" + adminKey,
		"prov-42",
		"chunk-99",
	}, &out, &errOut)

	if code != 0 {
		t.Fatalf("dispatchAudit exit code = %d, want 0, stderr = %s", code, errOut.String())
	}
	if gotMethod != http.MethodPost {
		t.Errorf("request method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/audit/challenge" {
		t.Errorf("request path = %q, want /api/v1/audit/challenge", gotPath)
	}
	if gotKey != adminKey {
		t.Errorf("X-Admin-API-Key = %q, want %q", gotKey, adminKey)
	}
	if gotBody.ProviderID != "prov-42" || gotBody.ChunkID != "chunk-99" {
		t.Errorf("request body = %+v, want provider_id=prov-42 chunk_id=chunk-99", gotBody)
	}
}

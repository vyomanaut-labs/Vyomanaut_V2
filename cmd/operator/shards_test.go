// Tests for shards.go (M17-E Session 17.6.1).
//
// Tests:
//   - TestShardsRendersCiphertextFilenameAsHexOnly
//   - TestShardsNeverRendersPlaintextFilename
//   - TestDispatchShardsCallsTheAdminEndpoint
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestShardsRendersCiphertextFilenameAsHexOnly confirms the display-name
// line is present, carries the hex string verbatim, and is explicitly
// labelled as ciphertext the operator cannot read (ADR-020) — requirement
// 4's parenthetical made visible.
func TestShardsRendersCiphertextFilenameAsHexOnly(t *testing.T) {
	hexName := hex.EncodeToString([]byte("some ciphertext bytes"))
	resp := shardsAdminResponseBody{
		FileID:                "11111111-1111-1111-1111-111111111111",
		OriginalSizeBytes:     4096,
		DisplayNameCiphertext: &hexName,
		Shards: []shardsAdminChunkItem{
			{ChunkID: "aa", SegmentID: "seg-0", ShardIndex: 0, ProviderID: "prov-0", ASN: "AS12345", SizeBytes: 262144},
		},
	}

	var buf bytes.Buffer
	renderShards(&buf, resp, false)
	out := buf.String()

	if !strings.Contains(out, hexName) {
		t.Errorf("output does not contain the hex-encoded display name %q:\n%s", hexName, out)
	}
	if !strings.Contains(out, "display_name_ciphertext") {
		t.Errorf("output does not label the field as display_name_ciphertext:\n%s", out)
	}
	if !strings.Contains(out, "ADR-020") {
		t.Errorf("output does not cite ADR-020 (the operator cannot read this):\n%s", out)
	}
}

// TestShardsNeverRendersPlaintextFilename guards against exactly the
// regression I-DEMO-1 exists to prevent: display_name_ciphertext arrives
// from the server as an opaque hex string (shardsAdminResponseBody's own
// field type), and this test confirms renderShards echoes it verbatim,
// never additionally hex-decoding it before printing. The ciphertext here
// is chosen to hex-decode to readable ASCII specifically so that a
// regression (someone "helpfully" hex-decoding before display) would be
// caught by this test failing, not merely by nothing catching it.
func TestShardsNeverRendersPlaintextFilename(t *testing.T) {
	plaintextLookingBytes := []byte("my-secret-file.pdf")
	hexName := hex.EncodeToString(plaintextLookingBytes)
	resp := shardsAdminResponseBody{
		FileID:                "11111111-1111-1111-1111-111111111111",
		OriginalSizeBytes:     4096,
		DisplayNameCiphertext: &hexName,
	}

	var buf bytes.Buffer
	renderShards(&buf, resp, false)
	out := buf.String()

	if strings.Contains(out, string(plaintextLookingBytes)) {
		t.Errorf("output contains the decoded plaintext %q — display_name_ciphertext must only ever be shown as hex:\n%s", plaintextLookingBytes, out)
	}
	if !strings.Contains(out, hexName) {
		t.Errorf("output does not contain the hex-encoded form %q:\n%s", hexName, out)
	}

	// --json path: confirm the same holds for the machine-readable
	// output — the field name in the JSON envelope must be the
	// ciphertext field, never a plaintext-named sibling.
	buf.Reset()
	renderShards(&buf, resp, true)
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal --json output: %v", err)
	}
	if _, ok := decoded["display_name_ciphertext"]; !ok {
		t.Errorf("--json output missing display_name_ciphertext key: %v", decoded)
	}
	if _, ok := decoded["display_name_plaintext"]; ok {
		t.Errorf("--json output must never contain a display_name_plaintext key: %v", decoded)
	}
}

// TestDispatchShardsCallsTheAdminEndpoint is a thin end-to-end check that
// dispatchShards actually reaches GET /api/v1/admin/file/{file_id}/shards
// with the X-Admin-API-Key header set — the wiring shards.go/client.go/
// dispatch.go establish together, not just renderShards in isolation.
func TestDispatchShardsCallsTheAdminEndpoint(t *testing.T) {
	const fileID = "22222222-2222-2222-2222-222222222222"
	const adminKey = "test-admin-key"
	var gotPath, gotKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("X-Admin-API-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(shardsAdminResponseBody{FileID: fileID, OriginalSizeBytes: 1, Shards: nil})
	}))
	defer server.Close()

	var out, errOut bytes.Buffer
	code := dispatchShards([]string{
		"--microservice-url=" + server.URL,
		"--admin-api-key=" + adminKey,
		fileID,
	}, &out, &errOut)

	if code != 0 {
		t.Fatalf("dispatchShards exit code = %d, want 0, stderr = %s", code, errOut.String())
	}
	wantPath := "/api/v1/admin/file/" + fileID + "/shards"
	if gotPath != wantPath {
		t.Errorf("request path = %q, want %q", gotPath, wantPath)
	}
	if gotKey != adminKey {
		t.Errorf("X-Admin-API-Key = %q, want %q", gotKey, adminKey)
	}
}

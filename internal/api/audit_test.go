// Package api is declared in doc.go.
// Tests for audit.go: Session 11.9.1 — POST /api/v1/audit/challenge.
//
// Tests:
//   - TestManualChallengeRejectsDepartedProvider
//   - TestManualChallengeReturnsCorrectDeadlineMs
//   - TestManualChallengeDoesNotBypassDedup
//   - TestManualChallengeRejectsInvalidProviderID
//   - TestManualChallengeRejectsInvalidChunkID
//   - TestManualChallengeRejectsUnknownProvider
//   - TestManualChallengeRejectsUnassignedChunk
//   - TestManualChallengeWritesPendingReceiptOnFreshDispatch
//   - TestManualChallengeSubstitutesPoolMedianForNullThroughput
//
// [REF: OAS paths./api/v1/audit/challenge, FR-037, ADR-002, ADR-006,
// ADR-014, build.md Phase 11.9 Session 11.9.1]

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// setProviderThroughput UPDATEs an already-inserted provider's
// p95_throughput_kbps directly — insertTestProviderDirect never sets this
// column (NULL by default, DM §4.2), so tests that need an established
// value set it explicitly here.
func setProviderThroughput(t *testing.T, db *sql.DB, providerID uuid.UUID, kbps float64) {
	t.Helper()
	if _, err := db.Exec(`UPDATE providers SET p95_throughput_kbps = $1 WHERE provider_id = $2`, kbps, providerID); err != nil {
		t.Fatalf("set p95_throughput_kbps: %v", err)
	}
}

// doAuditChallengeRequest builds and fires a POST /api/v1/audit/challenge
// request directly at the handler — this package's tests exercise handlers
// directly rather than through NewRouter/adminAuthMiddleware (see
// TestProviderDepartRejectsAlreadyDeparted and this package's other handler
// tests for the identical convention); AdminApiKey auth is router.go's
// concern, covered separately by router_test.go.
func doAuditChallengeRequest(t *testing.T, h *AuditChallengeHandler, providerID, chunkIDHex string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(auditChallengeDispatchRequestBody{
		ProviderID: providerID,
		ChunkID:    chunkIDHex,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/audit/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleDispatch(w, r)
	return w
}

func TestManualChallengeRejectsDepartedProvider(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "DEPARTED")
	chunkID := randChunkID(t)

	h := NewAuditChallengeHandler(db, config.DemoProfile, loadedClusterSecretCache(t))
	w := doAuditChallengeRequest(t, h, providerID.String(), hex.EncodeToString(chunkID[:]))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), string(ErrProviderDeparted)) {
		t.Errorf("body %q does not contain error_code %q", w.Body.String(), ErrProviderDeparted)
	}
}

func TestManualChallengeReturnsCorrectDeadlineMs(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	setProviderThroughput(t, db, providerID, 500.0)

	ownerID := insertTestOwnerDirect(t, db)
	fileID := insertTestFileDirect(t, db, ownerID)
	segmentID := insertTestSegmentDirect(t, db, fileID, 0)
	shardIdx := 0
	chunkID := insertChunkAssignmentDirect(t, db, providerID, &segmentID, &shardIdx, "ACTIVE")

	h := NewAuditChallengeHandler(db, config.DemoProfile, loadedClusterSecretCache(t))
	w := doAuditChallengeRequest(t, h, providerID.String(), hex.EncodeToString(chunkID[:]))

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[auditChallengeDispatchResponseBody](t, w.Body.Bytes())

	want := int64(math.Ceil((float64(auditChallengeChunkSizeKB) / 500.0) * auditDeadlineMsFactor)) // ceil((256/500)*1500) = 768
	if resp.DeadlineMs != want {
		t.Errorf("DeadlineMs = %d, want %d (ceil((256/500)*1500))", resp.DeadlineMs, want)
	}
	if len(resp.ChallengeNonce) != 66 {
		t.Errorf("ChallengeNonce length = %d, want 66 hex chars (33 bytes)", len(resp.ChallengeNonce))
	}
}

// TestManualChallengeDoesNotBypassDedup: a chunk already challenged within
// the window (DemoProfile.PollingInterval = 2 minutes) must be answered
// with the SAME existing challenge, not a freshly-dispatched second one —
// see audit.go's header note on why this is 202-with-existing-data rather
// than a 409 (OAS defines no 409 for this endpoint).
func TestManualChallengeDoesNotBypassDedup(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	setProviderThroughput(t, db, providerID, 500.0)

	// Synthetic vetting chunk (segmentID/shardIdx nil) — simplest valid
	// assignment shape; the dedup rule applies identically to real shards.
	chunkID := insertChunkAssignmentDirect(t, db, providerID, nil, nil, "ACTIVE")
	insertAuditReceipt(t, db, providerID, nil, chunkID, "", time.Now().UTC()) // "" = PENDING, just dispatched

	var existingNonce []byte
	var existingTS time.Time
	if err := db.QueryRow(
		`SELECT challenge_nonce, server_challenge_ts FROM audit_receipts WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], providerID,
	).Scan(&existingNonce, &existingTS); err != nil {
		t.Fatalf("read back seeded receipt: %v", err)
	}

	h := NewAuditChallengeHandler(db, config.DemoProfile, loadedClusterSecretCache(t))
	w := doAuditChallengeRequest(t, h, providerID.String(), hex.EncodeToString(chunkID[:]))

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[auditChallengeDispatchResponseBody](t, w.Body.Bytes())

	if resp.ChallengeNonce != hex.EncodeToString(existingNonce) {
		t.Errorf("ChallengeNonce = %s, want the existing in-window nonce %s (must not bypass dedup)",
			resp.ChallengeNonce, hex.EncodeToString(existingNonce))
	}
	if !resp.ServerChallengeTS.Equal(existingTS) {
		t.Errorf("ServerChallengeTS = %v, want the existing challenge's timestamp %v", resp.ServerChallengeTS, existingTS)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_receipts WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], providerID).Scan(&count); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if count != 1 {
		t.Errorf("audit_receipts rows for this chunk = %d, want 1 (a second dispatch within the window must not create a duplicate)", count)
	}
}

func TestManualChallengeRejectsInvalidProviderID(t *testing.T) {
	db := openTestDB(t)
	chunkID := randChunkID(t)
	h := NewAuditChallengeHandler(db, config.DemoProfile, loadedClusterSecretCache(t))

	w := doAuditChallengeRequest(t, h, "not-a-uuid", hex.EncodeToString(chunkID[:]))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"field":"provider_id"`) {
		t.Errorf("body %q does not name provider_id as the offending field", w.Body.String())
	}
}

func TestManualChallengeRejectsInvalidChunkID(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	h := NewAuditChallengeHandler(db, config.DemoProfile, loadedClusterSecretCache(t))

	for _, chunkID := range []string{"too-short", "zz" + strings.Repeat("0", 62)} {
		t.Run(chunkID, func(t *testing.T) {
			w := doAuditChallengeRequest(t, h, providerID.String(), chunkID)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), `"field":"chunk_id"`) {
				t.Errorf("body %q does not name chunk_id as the offending field", w.Body.String())
			}
		})
	}
}

func TestManualChallengeRejectsUnknownProvider(t *testing.T) {
	db := openTestDB(t)
	chunkID := randChunkID(t)
	h := NewAuditChallengeHandler(db, config.DemoProfile, loadedClusterSecretCache(t))

	unknownID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generate uuid: %v", err)
	}
	w := doAuditChallengeRequest(t, h, unknownID.String(), hex.EncodeToString(chunkID[:]))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", w.Code, w.Body.String())
	}
}

func TestManualChallengeRejectsUnassignedChunk(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	chunkID := randChunkID(t) // never assigned to this (or any) provider

	h := NewAuditChallengeHandler(db, config.DemoProfile, loadedClusterSecretCache(t))
	w := doAuditChallengeRequest(t, h, providerID.String(), hex.EncodeToString(chunkID[:]))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", w.Code, w.Body.String())
	}
}

func TestManualChallengeWritesPendingReceiptOnFreshDispatch(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "VETTING")
	setProviderThroughput(t, db, providerID, 500.0)
	chunkID := insertChunkAssignmentDirect(t, db, providerID, nil, nil, "ACTIVE") // synthetic vetting chunk

	h := NewAuditChallengeHandler(db, config.DemoProfile, loadedClusterSecretCache(t))
	w := doAuditChallengeRequest(t, h, providerID.String(), hex.EncodeToString(chunkID[:]))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", w.Code, w.Body.String())
	}

	var (
		count       int
		auditResult sql.NullString
		fileID      uuid.NullUUID
	)
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_receipts WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], providerID).Scan(&count); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_receipts rows = %d, want exactly 1", count)
	}
	if err := db.QueryRow(`SELECT audit_result, file_id FROM audit_receipts WHERE chunk_id = $1 AND provider_id = $2`,
		chunkID[:], providerID).Scan(&auditResult, &fileID); err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	if auditResult.Valid {
		t.Errorf("audit_result = %q, want NULL (PENDING — Phase 1 only, ADR-015)", auditResult.String)
	}
	if fileID.Valid {
		t.Errorf("file_id = %v, want NULL (synthetic vetting chunk, DM §8.20)", fileID.UUID)
	}
}

// TestManualChallengeSubstitutesPoolMedianForNullThroughput: this
// provider's own p95_throughput_kbps is NULL (never set), so the deadline
// must come from the pool median instead of dividing by zero (DM §4.2). The
// expected median is computed via the package's own poolMedianThroughputKbps
// immediately before the request — robust to whatever other providers this
// shared test database already has (see main_test.go's own note on
// cross-test accumulation), rather than assuming a clean slate.
func TestManualChallengeSubstitutesPoolMedianForNullThroughput(t *testing.T) {
	db := openTestDB(t)

	seedPub, _, _ := ed25519.GenerateKey(nil)
	seedProviderID := insertTestProviderDirect(t, db, seedPub, "ACTIVE")
	setProviderThroughput(t, db, seedProviderID, 1000.0) // guarantees a non-empty pool regardless of run order

	medianBefore, ok, err := poolMedianThroughputKbps(context.Background(), db)
	if err != nil {
		t.Fatalf("poolMedianThroughputKbps: %v", err)
	}
	if !ok {
		t.Fatal("poolMedianThroughputKbps: ok = false, want true (just seeded a provider)")
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE") // p95_throughput_kbps left NULL
	chunkID := insertChunkAssignmentDirect(t, db, providerID, nil, nil, "ACTIVE")

	h := NewAuditChallengeHandler(db, config.DemoProfile, loadedClusterSecretCache(t))
	w := doAuditChallengeRequest(t, h, providerID.String(), hex.EncodeToString(chunkID[:]))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[auditChallengeDispatchResponseBody](t, w.Body.Bytes())

	want := int64(math.Ceil((float64(auditChallengeChunkSizeKB) / medianBefore) * auditDeadlineMsFactor))
	if resp.DeadlineMs != want {
		t.Errorf("DeadlineMs = %d, want %d (ceil((256/pool_median=%v)*1500))", resp.DeadlineMs, want, medianBefore)
	}
}

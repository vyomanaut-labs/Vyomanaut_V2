// Package api is declared in doc.go.
// Tests for admin.go: build.md Milestone 11 Phase 11.10, Sessions
// 11.10.1-11.10.6.
//
// Tests:
//   - TestAdminProvidersFiltersByStatus
//   - TestAdminProvidersFiltersByVettingGCPending
//   - TestAdminProvidersRequiresAdminAPIKey
//   - TestRepairQueueCountsByPriority
//   - TestRepairQueueFiltersByStatus
//   - TestManualRepairTriggerCreatesJob
//   - TestManualRepairTriggerAllowsNullProviderID
//   - TestAuditStatsDefaultsToLastHour
//   - TestAuditStatsExcludesAbandonedRows
//   - TestAuditStatsPassRateFormula
//   - TestVettingStatusAggregatesAcrossProviders
//   - TestVettingStatusIncludeGCPendingOnlyFilter
//   - TestVettingGCRetryRejectsNonActiveProvider
//   - TestVettingGCRetryReturns200WhenUnreachable
//   - TestAdminShardsEndpointRequiresAdminKey
//   - TestAdminFileShardsReturnsPlacementAndCiphertextAsHex
//   - TestAdminFileShardsReturnsNotFoundForUnknownFile
//
// This package's tests exercise handlers directly rather than through
// NewRouter/adminAuthMiddleware (see audit_test.go's identical convention);
// AdminApiKey auth itself is router.go's concern, covered by
// router_test.go's TestAdminRoutesRejectMissingAPIKey /
// TestAdminRoutesRejectShortAPIKey (which already exercise all six routes
// added in this phase via allRegisteredRoutes()).
// TestAdminProvidersRequiresAdminAPIKey below is the one exception: build.md
// Session 11.10.1 names it explicitly, so it is written against the real
// router (testRouterConfig, from router_test.go) rather than the handler
// directly, since AdminProvidersHandler itself has no auth logic of its own
// to exercise.
//
// [REF: OAS paths./api/v1/admin/*, build.md Phase 11.10]

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/repair"
)

// insertRepairJobDirect inserts a repair_jobs row with full control over
// every column — used where the filter/count behaviour under test needs a
// status or priority repair.EnqueueJob itself would never produce (e.g. a
// FAILED job), unlike TestRepairQueueCountsByPriority below, which goes
// through the real repair.EnqueueJob to also confirm trigger_type ->
// priority derivation end-to-end.
func insertRepairJobDirect(t *testing.T, db *sql.DB, chunkID [32]byte, segmentID uuid.UUID, providerID *uuid.UUID, triggerType, priority, status string, availableShardCount int) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`
		INSERT INTO repair_jobs (chunk_id, segment_id, provider_id, trigger_type, priority, status, available_shard_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING job_id`,
		chunkID[:], segmentID, providerID, triggerType, priority, status, availableShardCount,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert repair job: %v", err)
	}
	return id
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.1 — listAdminProviders
// ═══════════════════════════════════════════════════════════════════════

func TestAdminProvidersFiltersByStatus(t *testing.T) {
	db := openTestDB(t)
	pubActive, _, _ := ed25519.GenerateKey(nil)
	pubVetting, _, _ := ed25519.GenerateKey(nil)
	activeID := insertTestProviderDirect(t, db, pubActive, "ACTIVE")
	_ = insertTestProviderDirect(t, db, pubVetting, "VETTING")

	h := NewAdminProvidersHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers?status=ACTIVE", nil)
	w := httptest.NewRecorder()
	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp adminProvidersResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range resp.Providers {
		if p.Status != "ACTIVE" {
			t.Errorf("got provider with status %q, want only ACTIVE", p.Status)
		}
	}
	found := false
	for _, p := range resp.Providers {
		if p.ProviderID == activeID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected seeded ACTIVE provider %s in results", activeID)
	}
}

func TestAdminProvidersFiltersByVettingGCPending(t *testing.T) {
	db := openTestDB(t)
	pubGCPending, _, _ := ed25519.GenerateKey(nil)
	pubNormal, _, _ := ed25519.GenerateKey(nil)

	gcPendingID := insertTestProviderDirect(t, db, pubGCPending, "ACTIVE")
	insertChunkAssignmentDirect(t, db, gcPendingID, nil, nil, "PENDING_DELETION") // vetting=true (nil segmentID)

	normalID := insertTestProviderDirect(t, db, pubNormal, "ACTIVE")
	insertChunkAssignmentDirect(t, db, normalID, nil, nil, "ACTIVE")

	h := NewAdminProvidersHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers?vetting_gc_pending=true", nil)
	w := httptest.NewRecorder()
	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp adminProvidersResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sawGCPending, sawNormal := false, false
	for _, p := range resp.Providers {
		if p.ProviderID == gcPendingID {
			sawGCPending = true
			if p.VettingGCPending == nil || !*p.VettingGCPending {
				t.Errorf("gc-pending provider: vetting_gc_pending = %v, want true", p.VettingGCPending)
			}
		}
		if p.ProviderID == normalID {
			sawNormal = true
		}
	}
	if !sawGCPending {
		t.Errorf("expected gc-pending provider %s in filtered results", gcPendingID)
	}
	if sawNormal {
		t.Errorf("did not expect non-gc-pending provider %s in filtered results", normalID)
	}
}

func TestAdminProvidersRequiresAdminAPIKey(t *testing.T) {
	cfg, _, _ := testRouterConfig(t)
	mux := NewRouter(cfg)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers", nil) // no X-Admin-API-Key header
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 401 or 403 (missing admin key)", w.Code)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.2 — getRepairQueue
// ═══════════════════════════════════════════════════════════════════════

func TestRepairQueueCountsByPriority(t *testing.T) {
	db := openTestDB(t)
	ownerID := insertTestOwnerDirect(t, db)
	fileID := insertTestFileDirect(t, db, ownerID)
	segmentID := insertTestSegmentDirect(t, db, fileID, 0)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	// One of each trigger type -> one of each priority tier (repair's own
	// TriggerType -> Priority derivation, exercised end-to-end here via the
	// real repair.EnqueueJob rather than a direct INSERT).
	for _, tt := range []repair.TriggerType{repair.TriggerEmergencyFloor, repair.TriggerSilentDeparture, repair.TriggerThresholdWarning} {
		chunkID := randChunkID(t)
		if err := repair.EnqueueJob(context.Background(), db, config.DemoProfile, chunkID, segmentID, &providerID, tt, config.DemoProfile.DataShards); err != nil {
			t.Fatalf("EnqueueJob(%v): %v", tt, err)
		}
	}

	h := NewRepairQueueHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/repair/queue", nil)
	w := httptest.NewRecorder()
	h.HandleQueue(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp repairQueueResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.EmergencyQueued != 1 {
		t.Errorf("emergency_queued = %d, want 1", resp.EmergencyQueued)
	}
	if resp.PermanentDepartureQueued != 1 {
		t.Errorf("permanent_departure_queued = %d, want 1", resp.PermanentDepartureQueued)
	}
	if resp.PreWarningQueued != 1 {
		t.Errorf("pre_warning_queued = %d, want 1", resp.PreWarningQueued)
	}
	if resp.TotalQueued != 3 {
		t.Errorf("total_queued = %d, want 3", resp.TotalQueued)
	}
	// Drain order: EMERGENCY first (ADR-004).
	if len(resp.Jobs) != 3 || resp.Jobs[0].Priority != "EMERGENCY" {
		t.Errorf("jobs[0].priority = %q, want EMERGENCY (drain order)", resp.Jobs[0].Priority)
	}
}

func TestRepairQueueFiltersByStatus(t *testing.T) {
	db := openTestDB(t)
	ownerID := insertTestOwnerDirect(t, db)
	fileID := insertTestFileDirect(t, db, ownerID)
	segmentID := insertTestSegmentDirect(t, db, fileID, 0)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	// This table accumulates rows across this whole shared test database
	// from every test that has run before this one in the same process
	// (readiness_test.go's header comment documents this convention) — a
	// baseline-delta comparison, not an absolute count, is what's actually
	// robust here.
	h := NewRepairQueueHandler(db)
	baselineTotal := repairQueueTotalQueued(t, h)

	queuedChunk := randChunkID(t)
	insertRepairJobDirect(t, db, queuedChunk, segmentID, &providerID, "ANNOUNCED_DEPARTURE", "PERMANENT_DEPARTURE", "QUEUED", config.DemoProfile.DataShards)
	failedChunk := randChunkID(t)
	failedID := insertRepairJobDirect(t, db, failedChunk, segmentID, &providerID, "ANNOUNCED_DEPARTURE", "PERMANENT_DEPARTURE", "FAILED", config.DemoProfile.DataShards)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/repair/queue?status=FAILED", nil)
	w := httptest.NewRecorder()
	h.HandleQueue(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp repairQueueResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sawFailed := false
	for _, j := range resp.Jobs {
		if j.JobID == failedID {
			sawFailed = true
			if j.Status != "FAILED" {
				t.Errorf("job.status = %q, want FAILED", j.Status)
			}
		}
		if j.Status != "FAILED" {
			t.Errorf("status=FAILED filter returned a job with status %q", j.Status)
		}
	}
	if !sawFailed {
		t.Errorf("expected FAILED job %s in status=FAILED results", failedID)
	}
	// total_queued/emergency_queued/etc. always reflect the real QUEUED
	// depth regardless of the status filter applied to the jobs list: it
	// should rise by exactly 1 (the QUEUED job), not by 2 (the FAILED job
	// must not be counted).
	if resp.TotalQueued != baselineTotal+1 {
		t.Errorf("total_queued = %d, want %d (baseline + the 1 QUEUED job; unaffected by status=FAILED filter and by the FAILED job)", resp.TotalQueued, baselineTotal+1)
	}
}

// repairQueueTotalQueued reads the current total_queued via the handler
// itself — the same "top up whatever already exists" baseline pattern
// readiness_test.go documents for this shared test database.
func repairQueueTotalQueued(t *testing.T, h *RepairQueueHandler) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/repair/queue", nil)
	w := httptest.NewRecorder()
	h.HandleQueue(w, r)
	var resp repairQueueResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal baseline: %v", err)
	}
	return resp.TotalQueued
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.3 — triggerRepair
// ═══════════════════════════════════════════════════════════════════════

// seedRepairableSegment creates a file/segment with count ACTIVE, non-vetting
// shard assignments across count distinct ACTIVE providers, returning the
// segment id, the first assignment's chunk id/provider id, and all provider
// ids. count must fall within [DataShards, TotalShards] for
// config.DemoProfile so repair.EnqueueJob accepts the resulting live shard
// count.
func seedRepairableSegment(t *testing.T, db *sql.DB, count int) (segmentID uuid.UUID, chunkID [32]byte, providerID uuid.UUID) {
	t.Helper()
	ownerID := insertTestOwnerDirect(t, db)
	fileID := insertTestFileDirect(t, db, ownerID)
	segmentID = insertTestSegmentDirect(t, db, fileID, 0)
	for i := 0; i < count; i++ {
		pub, _, _ := ed25519.GenerateKey(nil)
		pid := insertTestProviderDirect(t, db, pub, "ACTIVE")
		idx := i
		cid := insertChunkAssignmentDirect(t, db, pid, &segmentID, &idx, "ACTIVE")
		if i == 0 {
			chunkID = cid
			providerID = pid
		}
	}
	return segmentID, chunkID, providerID
}

func TestManualRepairTriggerCreatesJob(t *testing.T) {
	db := openTestDB(t)
	segmentID, chunkID, providerID := seedRepairableSegment(t, db, config.DemoProfile.DataShards)

	h := NewManualRepairTriggerHandler(db, config.DemoProfile)
	reqBody, err := json.Marshal(manualRepairTriggerRequestBody{
		ChunkID:     hex.EncodeToString(chunkID[:]),
		SegmentID:   segmentID,
		TriggerType: "ANNOUNCED_DEPARTURE",
		ProviderID:  &providerID,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/repair/trigger", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	h.HandleTrigger(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", w.Code, w.Body.String())
	}
	var resp repairJobItemBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.JobID == uuid.Nil {
		t.Error("job_id is nil, want a created job id")
	}
	if resp.Priority != "PERMANENT_DEPARTURE" {
		t.Errorf("priority = %q, want PERMANENT_DEPARTURE (ANNOUNCED_DEPARTURE trigger)", resp.Priority)
	}
	if resp.Status != "QUEUED" {
		t.Errorf("status = %q, want QUEUED", resp.Status)
	}
	if resp.AvailableShardCount != config.DemoProfile.DataShards {
		t.Errorf("available_shard_count = %d, want %d (live count)", resp.AvailableShardCount, config.DemoProfile.DataShards)
	}
	if resp.ProviderID == nil || *resp.ProviderID != providerID {
		t.Errorf("provider_id = %v, want %s", resp.ProviderID, providerID)
	}
}

func TestManualRepairTriggerAllowsNullProviderID(t *testing.T) {
	db := openTestDB(t)
	segmentID, chunkID, _ := seedRepairableSegment(t, db, config.DemoProfile.DataShards)

	h := NewManualRepairTriggerHandler(db, config.DemoProfile)
	reqBody, err := json.Marshal(manualRepairTriggerRequestBody{
		ChunkID:     hex.EncodeToString(chunkID[:]),
		SegmentID:   segmentID,
		TriggerType: "THRESHOLD_WARNING",
		ProviderID:  nil,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/repair/trigger", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	h.HandleTrigger(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", w.Code, w.Body.String())
	}
	var resp repairJobItemBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ProviderID != nil {
		t.Errorf("provider_id = %v, want nil (threshold-triggered repair)", resp.ProviderID)
	}
	if resp.Priority != "PRE_WARNING" {
		t.Errorf("priority = %q, want PRE_WARNING (THRESHOLD_WARNING trigger)", resp.Priority)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.4 — getAuditStats
// ═══════════════════════════════════════════════════════════════════════

func TestAuditStatsDefaultsToLastHour(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	chunkID := randChunkID(t)

	now := time.Now().UTC()
	insertAuditReceipt(t, db, providerID, nil, chunkID, "PASS", now.Add(-10*time.Minute)) // inside default window
	insertAuditReceipt(t, db, providerID, nil, chunkID, "PASS", now.Add(-2*time.Hour))    // outside default window

	h := NewAuditStatsHandler(db)
	// provider_id scopes to this test's own freshly-generated provider, so
	// results are independent of whatever this shared test database
	// accumulates from other tests (readiness_test.go's header comment
	// documents this convention for the same underlying tables).
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/stats?provider_id="+providerID.String(), nil) // no from/to
	w := httptest.NewRecorder()
	h.HandleStats(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp auditStatsResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Challenges != 1 {
		t.Errorf("challenges_issued = %d, want 1 (only the receipt inside the default 1h window)", resp.Challenges)
	}
	gotWindow := resp.WindowEnd.Sub(resp.WindowStart)
	if gotWindow < 59*time.Minute || gotWindow > 61*time.Minute {
		t.Errorf("window_end - window_start = %v, want ~1h", gotWindow)
	}
}

func TestAuditStatsExcludesAbandonedRows(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	chunkID := randChunkID(t)
	now := time.Now().UTC()

	insertAuditReceipt(t, db, providerID, nil, chunkID, "PASS", now.Add(-5*time.Minute)) // kept
	abandonedID := insertAuditReceipt(t, db, providerID, nil, chunkID, "", now.Add(-5*time.Minute))
	// abandoned_at is settable only under vyomanaut_gc's
	// audit_receipts_gc_abandon RLS policy (migrations/
	// 001_initial_schema.sql) — vyomanaut_app (openTestDB) cannot set it
	// directly. openVerifyDB's superuser connection bypasses RLS
	// entirely, the same simulate-GC-abandonment pattern
	// internal/audit/receipt_test.go's TestWriteReceiptPhase2RejectsAbandonedRow
	// already establishes.
	verify := openVerifyDB(t)
	if _, err := verify.Exec(`UPDATE audit_receipts SET abandoned_at = NOW() WHERE receipt_id = $1`, abandonedID); err != nil {
		t.Fatalf("mark abandoned: %v", err)
	}

	h := NewAuditStatsHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/stats?provider_id="+providerID.String(), nil)
	w := httptest.NewRecorder()
	h.HandleStats(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp auditStatsResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Challenges != 1 {
		t.Errorf("challenges_issued = %d, want 1 (abandoned row excluded)", resp.Challenges)
	}
}

func TestAuditStatsPassRateFormula(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	chunkID := randChunkID(t)
	now := time.Now().UTC()

	insertAuditReceipt(t, db, providerID, nil, chunkID, "PASS", now.Add(-1*time.Minute))
	insertAuditReceipt(t, db, providerID, nil, chunkID, "PASS", now.Add(-2*time.Minute))
	insertAuditReceipt(t, db, providerID, nil, chunkID, "FAIL", now.Add(-3*time.Minute))
	insertAuditReceipt(t, db, providerID, nil, chunkID, "TIMEOUT", now.Add(-4*time.Minute))
	insertAuditReceipt(t, db, providerID, nil, chunkID, "", now.Add(-5*time.Minute)) // pending, excluded from pass_rate denominator

	h := NewAuditStatsHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/stats?provider_id="+providerID.String(), nil)
	w := httptest.NewRecorder()
	h.HandleStats(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp auditStatsResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Results.Pass != 2 || resp.Results.Fail != 1 || resp.Results.Timeout != 1 || resp.Results.Pending != 1 {
		t.Fatalf("results = %+v, want pass=2 fail=1 timeout=1 pending=1", resp.Results)
	}
	// pass_rate = pass / (pass + fail + timeout) = 2 / 4 = 0.5
	if resp.PassRate != 0.5 {
		t.Errorf("pass_rate = %v, want 0.5", resp.PassRate)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.5 — getVettingStatus
// ═══════════════════════════════════════════════════════════════════════

func TestVettingStatusAggregatesAcrossProviders(t *testing.T) {
	db := openTestDB(t)
	h := NewVettingStatusHandler(db)

	// This table accumulates VETTING providers across this whole shared
	// test database from other tests run earlier in the same process
	// (readiness_test.go's header comment documents this convention) — a
	// baseline-delta comparison plus presence checks for this test's own
	// two providers, not an absolute count/length, is what's robust here.
	baseline := vettingStatusSnapshot(t, h)

	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)
	providerA := insertTestProviderDirect(t, db, pubA, "VETTING")
	providerB := insertTestProviderDirect(t, db, pubB, "VETTING")
	insertChunkAssignmentDirect(t, db, providerA, nil, nil, "ACTIVE")
	insertChunkAssignmentDirect(t, db, providerB, nil, nil, "ACTIVE")

	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/vetting/status", nil)
	w := httptest.NewRecorder()
	h.HandleStatus(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp vettingStatusResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TotalVettingProviders != baseline.totalVettingProviders+2 {
		t.Errorf("total_vetting_providers = %d, want %d (baseline + 2)", resp.TotalVettingProviders, baseline.totalVettingProviders+2)
	}
	if resp.TotalSyntheticChunksActive != baseline.totalSyntheticChunksActive+2 {
		t.Errorf("total_synthetic_chunks_active = %d, want %d (baseline + 2)", resp.TotalSyntheticChunksActive, baseline.totalSyntheticChunksActive+2)
	}
	sawA, sawB := false, false
	for _, p := range resp.Providers {
		if p.ProviderID == providerA {
			sawA = true
		}
		if p.ProviderID == providerB {
			sawB = true
		}
		if p.ProviderID != providerA && p.ProviderID != providerB {
			continue
		}
		if p.VettingSummary.ChunksAssigned != 1 {
			t.Errorf("provider %s: chunks_assigned = %d, want 1", p.ProviderID, p.VettingSummary.ChunksAssigned)
		}
		if p.VettingSummary.ChunkCap != 100*vettingChunksPerGB {
			t.Errorf("provider %s: chunk_cap = %d, want %d", p.ProviderID, p.VettingSummary.ChunkCap, 100*vettingChunksPerGB)
		}
	}
	if !sawA || !sawB {
		t.Errorf("expected both seeded providers (%s, %s) in results, sawA=%v sawB=%v", providerA, providerB, sawA, sawB)
	}
}

type vettingStatusBaseline struct {
	totalVettingProviders      int
	totalSyntheticChunksActive int64
}

func vettingStatusSnapshot(t *testing.T, h *VettingStatusHandler) vettingStatusBaseline {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/vetting/status", nil)
	w := httptest.NewRecorder()
	h.HandleStatus(w, r)
	var resp vettingStatusResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal baseline: %v", err)
	}
	return vettingStatusBaseline{
		totalVettingProviders:      resp.TotalVettingProviders,
		totalSyntheticChunksActive: resp.TotalSyntheticChunksActive,
	}
}

func TestVettingStatusIncludeGCPendingOnlyFilter(t *testing.T) {
	db := openTestDB(t)
	pubVetting, _, _ := ed25519.GenerateKey(nil)
	pubStraggler, _, _ := ed25519.GenerateKey(nil)

	vettingID := insertTestProviderDirect(t, db, pubVetting, "VETTING")
	insertChunkAssignmentDirect(t, db, vettingID, nil, nil, "ACTIVE") // no pending GC

	stragglerID := insertTestProviderDirect(t, db, pubStraggler, "ACTIVE")
	insertChunkAssignmentDirect(t, db, stragglerID, nil, nil, "PENDING_DELETION") // ACTIVE provider, GC straggler

	h := NewVettingStatusHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/vetting/status?include_gc_pending_only=true", nil)
	w := httptest.NewRecorder()
	h.HandleStatus(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp vettingStatusResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sawStraggler, sawVetting := false, false
	for _, p := range resp.Providers {
		if p.ProviderID == stragglerID {
			sawStraggler = true
			if p.VettingSummary.ChunksPendingGC != 1 {
				t.Errorf("straggler chunks_pending_gc = %d, want 1", p.VettingSummary.ChunksPendingGC)
			}
		}
		if p.ProviderID == vettingID {
			sawVetting = true
		}
	}
	if !sawStraggler {
		t.Errorf("expected gc-pending straggler %s in include_gc_pending_only=true results", stragglerID)
	}
	if sawVetting {
		t.Errorf("did not expect non-gc-pending VETTING provider %s in include_gc_pending_only=true results", vettingID)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.6 — retryVettingGC
// ═══════════════════════════════════════════════════════════════════════

func TestVettingGCRetryRejectsNonActiveProvider(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "VETTING") // not ACTIVE

	h := NewVettingGCRetryHandler(db)
	reqBody, err := json.Marshal(vettingGCRetryRequestBody{ProviderID: providerID})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/vetting/gc/retry", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	h.HandleRetry(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

func TestVettingGCRetryReturns200WhenUnreachable(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	insertChunkAssignmentDirect(t, db, providerID, nil, nil, "PENDING_DELETION")

	h := NewVettingGCRetryHandler(db)
	reqBody, err := json.Marshal(vettingGCRetryRequestBody{ProviderID: providerID})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/vetting/gc/retry", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	h.HandleRetry(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp vettingGCRetryResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.DeliveryAttempted {
		t.Error("delivery_attempted = true, want false (Milestone 14 not built; see admin.go header note)")
	}
	if resp.ChunksPendingGCBefore != 1 {
		t.Errorf("chunks_pending_gc_before = %d, want 1", resp.ChunksPendingGCBefore)
	}
	if resp.ChunksPendingGCAfter != 1 {
		t.Errorf("chunks_pending_gc_after = %d, want 1 (no real delivery happened)", resp.ChunksPendingGCAfter)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// M17-E Session 17.6.1 — getFileShards (ADR-084 §D-2a)
// ═══════════════════════════════════════════════════════════════════════

// insertTestFileWithDisplayNameDirect is insertTestFileDirect
// (provider_test.go) plus a non-NULL display_name_ciphertext — needed here
// specifically to prove that ciphertext survives the round trip as opaque
// bytes rather than silently coming back empty/omitted.
func insertTestFileWithDisplayNameDirect(t *testing.T, db *sql.DB, ownerID uuid.UUID, displayNameCiphertext []byte) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`
		INSERT INTO files (owner_id, pointer_ciphertext, pointer_nonce, pointer_tag, original_size_bytes,
		                    display_name_ciphertext, display_name_nonce, display_name_tag)
		VALUES ($1, $2, $3, $4, 1048576, $5, $6, $7)
		RETURNING file_id`,
		ownerID, []byte("ciphertext"), make([]byte, 12), make([]byte, 16),
		displayNameCiphertext, make([]byte, 12), make([]byte, 16),
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert test file with display name: %v", err)
	}
	return id
}

func TestAdminShardsEndpointRequiresAdminKey(t *testing.T) {
	cfg, _, _ := testRouterConfig(t)
	mux := NewRouter(cfg)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/file/11111111-1111-1111-1111-111111111111/shards", nil) // no X-Admin-API-Key header
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 401 or 403 (missing admin key)", w.Code)
	}
}

func TestAdminFileShardsReturnsPlacementAndCiphertextAsHex(t *testing.T) {
	db := openTestDB(t)
	ownerID := insertTestOwnerDirect(t, db)
	displayName := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
	fileID := insertTestFileWithDisplayNameDirect(t, db, ownerID, displayName)
	segmentID := insertTestSegmentDirect(t, db, fileID, 0)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	shardIdx := 0
	realChunkID := insertChunkAssignmentDirect(t, db, providerID, &segmentID, &shardIdx, "ACTIVE")
	// A synthetic vetting chunk on the same provider — segment_id/shard_index
	// NULL, so it cannot join to this file's segments at all; included here
	// to confirm the query's WHERE clause (not merely the join) is what
	// keeps it out, matching DM §4.5's own is_vetting_chunk semantics.
	insertChunkAssignmentDirect(t, db, providerID, nil, nil, "ACTIVE")

	h := NewAdminFileShardsHandler(db, config.DemoProfile)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/file/"+fileID.String()+"/shards", nil)
	r.SetPathValue("file_id", fileID.String())
	w := httptest.NewRecorder()
	h.HandleShards(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp adminFileShardsResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.OriginalSizeBytes != 1048576 {
		t.Errorf("original_size_bytes = %d, want 1048576", resp.OriginalSizeBytes)
	}
	if resp.DisplayNameCiphertext == nil {
		t.Fatal("display_name_ciphertext = nil, want the hex-encoded ciphertext")
	}
	if *resp.DisplayNameCiphertext != hex.EncodeToString(displayName) {
		t.Errorf("display_name_ciphertext = %q, want %q", *resp.DisplayNameCiphertext, hex.EncodeToString(displayName))
	}
	if len(resp.Shards) != 1 {
		t.Fatalf("len(shards) = %d, want 1 (the synthetic vetting chunk must not appear)", len(resp.Shards))
	}
	got := resp.Shards[0]
	if got.ChunkID != hex.EncodeToString(realChunkID[:]) {
		t.Errorf("chunk_id = %q, want %q", got.ChunkID, hex.EncodeToString(realChunkID[:]))
	}
	if got.SegmentID != segmentID {
		t.Errorf("segment_id = %s, want %s", got.SegmentID, segmentID)
	}
	if got.ShardIndex != shardIdx {
		t.Errorf("shard_index = %d, want %d", got.ShardIndex, shardIdx)
	}
	if got.ProviderID != providerID {
		t.Errorf("provider_id = %s, want %s", got.ProviderID, providerID)
	}
	if got.ASN != "AS12345" {
		t.Errorf("asn = %q, want %q (insertTestProviderDirect's fixed ASN)", got.ASN, "AS12345")
	}
	if got.SizeBytes != config.DemoProfile.ShardSize {
		t.Errorf("size_bytes = %d, want profile.ShardSize = %d", got.SizeBytes, config.DemoProfile.ShardSize)
	}
}

func TestAdminFileShardsReturnsNotFoundForUnknownFile(t *testing.T) {
	db := openTestDB(t)
	h := NewAdminFileShardsHandler(db, config.DemoProfile)
	unknown := uuid.New()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/file/"+unknown.String()+"/shards", nil)
	r.SetPathValue("file_id", unknown.String())
	w := httptest.NewRecorder()
	h.HandleShards(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", w.Code, w.Body.String())
	}
}

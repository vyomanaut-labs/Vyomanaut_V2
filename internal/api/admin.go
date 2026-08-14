// Package api is declared in doc.go.
// This file implements build.md Milestone 11 Phase 11.10's six AdminApiKey
// endpoints: listAdminProviders, getRepairQueue, triggerRepair,
// getAuditStats, getVettingStatus, retryVettingGC. Every handler here is
// wrapped by router.go's adminAuthMiddleware — none of them read
// ClaimsFromContext (the AdminApiKey scheme has no bearer claims to read).
//
// [Flagged and corrected — wrong NFR citation, build.md Phase 11.10] The
// getRepairQueue task text as originally written attributes
// "emergency_queued > 0 fires immediately" to NFR-027. NFR-027 lists four
// alert thresholds and none of them is per-priority-tier queue depth — it
// covers total_queued > 1,000 only. OAS's own emergency_queued field
// description cites FR-044/ADR-004 instead. Both citations appear in this
// file's comments accordingly: NFR-027 for total_queued and
// timeout_rate (getAuditStats); FR-044/ADR-004 for emergency_queued.
//
// [Flagged, placeholder shipped — build.md Phase 11.10 Session 11.10.4,
// confirmed with the user] AuditStatsResponse.content_hash_failures is
// documented as "receipts with corruption error code" (OAS), and FR-041 /
// IC §5.5 describe a wire-protocol status byte (FAIL_CORRUPTION among
// others) the provider daemon returns on a failed challenge response. That
// status byte is never persisted anywhere: audit_receipts (data-model.md,
// migrations/001_initial_schema.sql) has only the coarse three-value
// audit_result column (PASS/FAIL/TIMEOUT), no finer-grained error/status
// code, and internal/audit/validate.go's own doc comment states outright
// that the microservice cannot verify content_hash itself (it never holds
// chunk_data). There is no query against the current schema that can
// distinguish a corruption FAIL from any other FAIL. This mirrors the
// held_earnings_paise precedent already established in provider.go
// (HandleStatus): content_hash_failures is reported as 0 here — a flagged
// placeholder, not a silent fabrication — pending a schema addition (e.g. a
// fail_reason/status_code column on audit_receipts, threaded through
// WriteReceiptPhase2) that is outside this session's file list. This gap
// does not block VERIFY: Session 11.10.4's own test list does not assert
// any particular content_hash_failures value.
//
// [Flagged — Milestone 14 not yet built, build.md Phase 11.10 Session
// 11.10.6] retryVettingGC's task text names
// vettingchunk.DeliverGCInstruction() as the real delivery path, explicitly
// noting it "may not exist yet" and to "stub the call here and revisit once
// Milestone 14 lands." internal/vettingchunk (checked directly) currently
// contains only doc.go — no DeliverGCInstruction function exists to import.
// This handler does not import internal/vettingchunk at all: it always
// reports delivery_attempted: false, which is a real, valid, non-error
// outcome under OAS's own contract ("If the provider is still offline, the
// endpoint returns 200 with delivery_attempted: false and the background
// retry continues") — the observable behaviour is correct even though the
// underlying reason (no delivery mechanism yet, rather than an offline
// provider) differs. chunks_pending_gc_before/after both reflect the real,
// live count either way, so this endpoint is truthful about the one thing
// it can actually report.
//
// [REF: OAS paths./api/v1/admin/*, components/schemas/AdminProvidersResponse,
// AdminProviderItem, RepairQueueResponse, RepairJobItem, AuditStatsResponse,
// VettingStatusSummary, NFR-027, FR-041, FR-044, FR-062-FR-064, ADR-004,
// ADR-030, IC §5.5, build.md Phase 11.10]

package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/repair"
)

// ═══════════════════════════════════════════════════════════════════════
// Shared enum validators — the ProviderStatus / RepairJobStatus /
// RepairPriority / RepairTriggerType string sets, kept local to this file
// since repair.Priority/TriggerType's own dbValue()/FromDB() mappers are
// package-private to internal/repair (queue.go) and internal/api cannot
// reach them.
// ═══════════════════════════════════════════════════════════════════════

func isValidProviderStatus(s string) bool {
	switch s {
	case "PENDING_ONBOARDING", "VETTING", "ACTIVE", "DEPARTED":
		return true
	}
	return false
}

func isValidRepairJobStatus(s string) bool {
	switch s {
	case "QUEUED", "IN_PROGRESS", "COMPLETED", "FAILED":
		return true
	}
	return false
}

func isValidRepairPriority(s string) bool {
	switch s {
	case "EMERGENCY", "PERMANENT_DEPARTURE", "PRE_WARNING":
		return true
	}
	return false
}

// parseRepairTriggerType maps OAS's RepairTriggerType string values onto
// repair's exported TriggerType constants (the reverse mapping,
// TriggerType.dbValue(), is package-private to internal/repair).
func parseRepairTriggerType(s string) (repair.TriggerType, bool) {
	switch s {
	case "SILENT_DEPARTURE":
		return repair.TriggerSilentDeparture, true
	case "ANNOUNCED_DEPARTURE":
		return repair.TriggerAnnouncedDeparture, true
	case "THRESHOLD_WARNING":
		return repair.TriggerThresholdWarning, true
	case "EMERGENCY_FLOOR":
		return repair.TriggerEmergencyFloor, true
	default:
		return 0, false
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.1 — GET /api/v1/admin/providers (listAdminProviders)
// ═══════════════════════════════════════════════════════════════════════

const (
	defaultAdminProvidersLimit = 100
	maxAdminProvidersLimit     = 200
)

type adminProviderItem struct {
	ProviderID             uuid.UUID  `json:"provider_id"`
	PhoneNumber            string     `json:"phone_number"`
	Status                 string     `json:"status"`
	ASN                    string     `json:"asn"`
	Region                 string     `json:"region"`
	LastHeartbeatTS        *time.Time `json:"last_heartbeat_ts"`
	MultiaddrStale         bool       `json:"multiaddr_stale"`
	ScoreComposite         *float64   `json:"score_composite"`
	StoredChunks           int        `json:"stored_chunks"`
	ConsecutiveAuditPasses int        `json:"consecutive_audit_passes"`
	AcceleratedReaudit     bool       `json:"accelerated_reaudit"`
	Frozen                 bool       `json:"frozen"`
	VettingChunksAssigned  *int       `json:"vetting_chunks_assigned"`
	VettingChunkCap        *int       `json:"vetting_chunk_cap"`
	VettingGCPending       *bool      `json:"vetting_gc_pending"`
	DepartedAt             *time.Time `json:"departed_at"`
}

type adminProvidersResponseBody struct {
	Total      int                 `json:"total"`
	Providers  []adminProviderItem `json:"providers"`
	NextCursor *string             `json:"next_cursor"`
}

// AdminProvidersHandler serves GET /api/v1/admin/providers.
type AdminProvidersHandler struct {
	db *sql.DB
}

func NewAdminProvidersHandler(db *sql.DB) *AdminProvidersHandler {
	return &AdminProvidersHandler{db: db}
}

func (h *AdminProvidersHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	limit := defaultAdminProvidersLimit
	if l := q.Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed <= 0 || parsed > maxAdminProvidersLimit {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, fmt.Sprintf("limit must be between 1 and %d", maxAdminProvidersLimit), nil, "limit", nil)
			return
		}
		limit = parsed
	}

	where := []string{"1=1"}
	args := []any{}

	if status := q.Get("status"); status != "" {
		if !isValidProviderStatus(status) {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "status must be a valid ProviderStatus", nil, "status", nil)
			return
		}
		args = append(args, status)
		where = append(where, fmt.Sprintf("p.status = $%d", len(args)))
	}
	if asn := q.Get("asn"); asn != "" {
		args = append(args, asn)
		where = append(where, fmt.Sprintf("p.asn = $%d", len(args)))
	}
	if region := q.Get("region"); region != "" {
		args = append(args, region)
		where = append(where, fmt.Sprintf("p.region = $%d", len(args)))
	}
	if v := q.Get("multiaddr_stale"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "multiaddr_stale must be a boolean", nil, "multiaddr_stale", nil)
			return
		}
		args = append(args, b)
		where = append(where, fmt.Sprintf("p.multiaddr_stale = $%d", len(args)))
	}
	if v := q.Get("accelerated_reaudit"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "accelerated_reaudit must be a boolean", nil, "accelerated_reaudit", nil)
			return
		}
		args = append(args, b)
		where = append(where, fmt.Sprintf("p.accelerated_reaudit = $%d", len(args)))
	}
	// vetting_gc_pending: OAS's own field description only gives meaning to
	// the true case ("filter to providers with chunks_pending_gc > 0") — a
	// bare EXISTS filter is only ever added, never negated, matching that
	// one-directional contract exactly.
	if v := q.Get("vetting_gc_pending"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "vetting_gc_pending must be a boolean", nil, "vetting_gc_pending", nil)
			return
		}
		if b {
			where = append(where, "EXISTS (SELECT 1 FROM chunk_assignments gc WHERE gc.provider_id = p.provider_id AND gc.is_vetting_chunk = TRUE AND gc.status = 'PENDING_DELETION')")
		}
	}

	var cursorTS time.Time
	var cursorID uuid.UUID
	if cursor := q.Get("cursor"); cursor != "" {
		var decErr error
		cursorTS, cursorID, decErr = decodeReceiptsCursor(cursor)
		if decErr != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid cursor", nil, "cursor", nil)
			return
		}
		args = append(args, cursorTS, cursorID)
		where = append(where, fmt.Sprintf("(p.created_at, p.provider_id) < ($%d, $%d)", len(args)-1, len(args)))
	}

	whereClause := strings.Join(where, " AND ")

	var total int
	if err := h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM providers p WHERE `+whereClause, args...).Scan(&total); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "count failed", nil, "", nil)
		return
	}

	fetchArgs := append(append([]any{}, args...), limit+1)
	rows, err := h.db.QueryContext(ctx, `
		SELECT p.provider_id, p.phone_number, p.status, p.asn, p.region, p.last_heartbeat_ts,
		       p.multiaddr_stale, s.score_composite, p.consecutive_audit_passes,
		       p.accelerated_reaudit, p.frozen, p.departed_at, p.declared_storage_gb, p.created_at,
		       (SELECT COUNT(*) FROM chunk_assignments ca WHERE ca.provider_id = p.provider_id AND ca.status = 'ACTIVE') AS stored_chunks,
		       (SELECT COUNT(*) FROM chunk_assignments ca WHERE ca.provider_id = p.provider_id AND ca.is_vetting_chunk = TRUE AND ca.status = 'ACTIVE') AS vetting_assigned,
		       EXISTS (SELECT 1 FROM chunk_assignments ca WHERE ca.provider_id = p.provider_id AND ca.is_vetting_chunk = TRUE AND ca.status = 'PENDING_DELETION') AS gc_pending
		FROM providers p
		LEFT JOIN mv_provider_scores s ON s.provider_id = p.provider_id
		WHERE `+whereClause+`
		ORDER BY p.created_at DESC, p.provider_id DESC
		LIMIT $`+strconv.Itoa(len(fetchArgs)), fetchArgs...)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "query failed", nil, "", nil)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("AdminProvidersHandler.HandleList: close rows", "error", err)
		}
	}()

	type rowExtras struct {
		createdAt         time.Time
		declaredStorageGB int
		vettingAssigned   int
		gcPending         bool
	}
	items := make([]adminProviderItem, 0, limit)
	extras := make([]rowExtras, 0, limit)
	for rows.Next() {
		var item adminProviderItem
		var scoreComposite sql.NullFloat64
		var lastHeartbeat sql.NullTime
		var departedAt sql.NullTime
		var ex rowExtras
		if err := rows.Scan(&item.ProviderID, &item.PhoneNumber, &item.Status, &item.ASN, &item.Region,
			&lastHeartbeat, &item.MultiaddrStale, &scoreComposite, &item.ConsecutiveAuditPasses,
			&item.AcceleratedReaudit, &item.Frozen, &departedAt, &ex.declaredStorageGB, &ex.createdAt,
			&item.StoredChunks, &ex.vettingAssigned, &ex.gcPending); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "scan failed", nil, "", nil)
			return
		}
		if lastHeartbeat.Valid {
			item.LastHeartbeatTS = &lastHeartbeat.Time
		}
		if departedAt.Valid {
			item.DepartedAt = &departedAt.Time
		}
		if scoreComposite.Valid {
			item.ScoreComposite = &scoreComposite.Float64
		}
		// Vetting fields, gated exactly as providerStatusResponseBody gates
		// them (provider.go HandleStatus) — chunks_assigned/cap on
		// VETTING only, gc_pending on ACTIVE only.
		if item.Status == "VETTING" {
			cap := ex.declaredStorageGB * vettingChunksPerGB
			item.VettingChunkCap = &cap
			assigned := ex.vettingAssigned
			item.VettingChunksAssigned = &assigned
		}
		if item.Status == "ACTIVE" {
			gcPending := ex.gcPending
			item.VettingGCPending = &gcPending
		}
		items = append(items, item)
		extras = append(extras, ex)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "row iteration failed", nil, "", nil)
		return
	}

	var nextCursor *string
	if len(items) > limit {
		lastExtra := extras[limit-1]
		c := encodeReceiptsCursor(lastExtra.createdAt, items[limit-1].ProviderID)
		nextCursor = &c
		items = items[:limit]
	}

	resp := adminProvidersResponseBody{Total: total, Providers: items, NextCursor: nextCursor}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.2 — GET /api/v1/admin/repair/queue (getRepairQueue)
// ═══════════════════════════════════════════════════════════════════════

const (
	defaultRepairQueueLimit = 50
	maxRepairQueueLimit     = 100
	repairQueueCursorParts  = 3
)

type repairJobItemBody struct {
	JobID               uuid.UUID  `json:"job_id"`
	ChunkID             string     `json:"chunk_id"`
	SegmentID           uuid.UUID  `json:"segment_id"`
	ProviderID          *uuid.UUID `json:"provider_id"`
	TriggerType         string     `json:"trigger_type"`
	Priority            string     `json:"priority"`
	Status              string     `json:"status"`
	AvailableShardCount int        `json:"available_shard_count"`
	CreatedAt           time.Time  `json:"created_at"`
	StartedAt           *time.Time `json:"started_at"`
	CompletedAt         *time.Time `json:"completed_at"`
}

type repairQueueResponseBody struct {
	TotalQueued              int                 `json:"total_queued"`
	EmergencyQueued          int                 `json:"emergency_queued"`
	PermanentDepartureQueued int                 `json:"permanent_departure_queued"`
	PreWarningQueued         int                 `json:"pre_warning_queued"`
	Jobs                     []repairJobItemBody `json:"jobs"`
	NextCursor               *string             `json:"next_cursor"`
}

// encodeRepairQueueCursor / decodeRepairQueueCursor: this endpoint's own
// keyset needs three fields (priority, created_at, job_id — see
// RepairQueueHandler.HandleQueue's ORDER BY), unlike the two-field
// (timestamp, uuid) shape encodeReceiptsCursor/decodeReceiptsCursor already
// cover, so this file adds its own codec rather than stretching that one to
// fit a shape it wasn't built for.
func encodeRepairQueueCursor(priority string, ts time.Time, id uuid.UUID) string {
	raw := fmt.Sprintf("%s:%d:%s", priority, ts.UnixNano(), id.String())
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeRepairQueueCursor(cursor string) (priority string, ts time.Time, id uuid.UUID, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", time.Time{}, uuid.UUID{}, fmt.Errorf("api: decodeRepairQueueCursor: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", repairQueueCursorParts)
	if len(parts) != repairQueueCursorParts {
		return "", time.Time{}, uuid.UUID{}, fmt.Errorf("api: decodeRepairQueueCursor: malformed")
	}
	if !isValidRepairPriority(parts[0]) {
		return "", time.Time{}, uuid.UUID{}, fmt.Errorf("api: decodeRepairQueueCursor: bad priority")
	}
	nanos, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", time.Time{}, uuid.UUID{}, fmt.Errorf("api: decodeRepairQueueCursor: bad timestamp: %w", err)
	}
	pid, err := uuid.Parse(parts[2])
	if err != nil {
		return "", time.Time{}, uuid.UUID{}, fmt.Errorf("api: decodeRepairQueueCursor: bad uuid: %w", err)
	}
	return parts[0], time.Unix(0, nanos).UTC(), pid, nil
}

const (
	cursorPriorityOffset = 2
	cursorTimeOffset     = 1
)

// RepairQueueHandler serves GET /api/v1/admin/repair/queue.
type RepairQueueHandler struct {
	db *sql.DB
}

func NewRepairQueueHandler(db *sql.DB) *RepairQueueHandler {
	return &RepairQueueHandler{db: db}
}

func (h *RepairQueueHandler) HandleQueue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	limit := defaultRepairQueueLimit
	if l := q.Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed <= 0 || parsed > maxRepairQueueLimit {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, fmt.Sprintf("limit must be between 1 and %d", maxRepairQueueLimit), nil, "limit", nil)
			return
		}
		limit = parsed
	}

	// total_queued / emergency_queued / permanent_departure_queued /
	// pre_warning_queued reflect the REAL queue depth (NFR-027's
	// total_queued > 1,000 alert; FR-044/ADR-004's emergency_queued > 0
	// alert — see this file's header note on the corrected citation) —
	// always computed over status = 'QUEUED' regardless of the status/
	// priority filters applied below to the jobs list itself.
	priorityCounts := map[string]int{"EMERGENCY": 0, "PERMANENT_DEPARTURE": 0, "PRE_WARNING": 0}
	countRows, err := h.db.QueryContext(ctx, `SELECT priority, COUNT(*) FROM repair_jobs WHERE status = 'QUEUED' GROUP BY priority`)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "queue depth count failed", nil, "", nil)
		return
	}
	for countRows.Next() {
		var priority string
		var count int
		if err := countRows.Scan(&priority, &count); err != nil {
			_ = countRows.Close()
			WriteError(w, http.StatusInternalServerError, ErrInternal, "queue depth scan failed", nil, "", nil)
			return
		}
		priorityCounts[priority] = count
	}
	if err := countRows.Close(); err != nil {
		slog.Error("RepairQueueHandler.HandleQueue: close countRows", "error", err)
	}
	totalQueued := priorityCounts["EMERGENCY"] + priorityCounts["PERMANENT_DEPARTURE"] + priorityCounts["PRE_WARNING"]

	where := []string{"1=1"}
	args := []any{}

	statusFilter := "QUEUED" // OAS: "Filter by job status. Defaults to QUEUED."
	if s := q.Get("status"); s != "" {
		if !isValidRepairJobStatus(s) {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "status must be a valid RepairJobStatus", nil, "status", nil)
			return
		}
		statusFilter = s
	}
	args = append(args, statusFilter)
	where = append(where, fmt.Sprintf("status = $%d", len(args)))

	if p := q.Get("priority"); p != "" {
		if !isValidRepairPriority(p) {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "priority must be a valid RepairPriority", nil, "priority", nil)
			return
		}
		args = append(args, p)
		where = append(where, fmt.Sprintf("priority = $%d", len(args)))
	}

	if cursor := q.Get("cursor"); cursor != "" {
		cp, cts, cid, decErr := decodeRepairQueueCursor(cursor)
		if decErr != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid cursor", nil, "cursor", nil)
			return
		}
		args = append(args, cp, cts, cid)

		priorityArg := len(args) - cursorPriorityOffset
		timeArg := len(args) - cursorTimeOffset
		jobArg := len(args)

		where = append(where, fmt.Sprintf("(priority, created_at, job_id) > ($%d::repair_priority, $%d, $%d)",
			priorityArg,
			timeArg,
			jobArg,
		))
	}

	whereClause := strings.Join(where, " AND ")

	// Drain order (ADR-004, Paper 39; matches repair.DequeueNextJob's own
	// ORDER BY priority ASC, created_at ASC exactly — repair_priority's
	// declaration order in migrations/001_initial_schema.sql IS the
	// EMERGENCY-before-PERMANENT_DEPARTURE-before-PRE_WARNING priority
	// order, per that file's own "ENUM order = priority order for ORDER BY
	// ASC" comment).
	fetchArgs := append(append([]any{}, args...), limit+1)
	rows, err := h.db.QueryContext(ctx, `
		SELECT job_id, chunk_id, segment_id, provider_id, trigger_type, priority, status,
		       available_shard_count, created_at, started_at, completed_at
		FROM repair_jobs
		WHERE `+whereClause+`
		ORDER BY priority ASC, created_at ASC, job_id ASC
		LIMIT $`+strconv.Itoa(len(fetchArgs)), fetchArgs...)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "query failed", nil, "", nil)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("RepairQueueHandler.HandleQueue: close rows", "error", err)
		}
	}()

	items := make([]repairJobItemBody, 0, limit)
	for rows.Next() {
		var item repairJobItemBody
		var chunkIDRaw []byte
		var startedAt, completedAt sql.NullTime
		if err := rows.Scan(&item.JobID, &chunkIDRaw, &item.SegmentID, &item.ProviderID, &item.TriggerType,
			&item.Priority, &item.Status, &item.AvailableShardCount, &item.CreatedAt, &startedAt, &completedAt); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "scan failed", nil, "", nil)
			return
		}
		item.ChunkID = hex.EncodeToString(chunkIDRaw)
		if startedAt.Valid {
			item.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			item.CompletedAt = &completedAt.Time
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "row iteration failed", nil, "", nil)
		return
	}

	var nextCursor *string
	if len(items) > limit {
		last := items[limit-1]
		c := encodeRepairQueueCursor(last.Priority, last.CreatedAt, last.JobID)
		nextCursor = &c
		items = items[:limit]
	}

	resp := repairQueueResponseBody{
		TotalQueued:              totalQueued,
		EmergencyQueued:          priorityCounts["EMERGENCY"],
		PermanentDepartureQueued: priorityCounts["PERMANENT_DEPARTURE"],
		PreWarningQueued:         priorityCounts["PRE_WARNING"],
		Jobs:                     items,
		NextCursor:               nextCursor,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.3 — POST /api/v1/admin/repair/trigger (triggerRepair)
// ═══════════════════════════════════════════════════════════════════════

type manualRepairTriggerRequestBody struct {
	ChunkID     string     `json:"chunk_id"`
	SegmentID   uuid.UUID  `json:"segment_id"`
	TriggerType string     `json:"trigger_type"`
	ProviderID  *uuid.UUID `json:"provider_id"`
}

// ManualRepairTriggerHandler serves POST /api/v1/admin/repair/trigger.
type ManualRepairTriggerHandler struct {
	db      *sql.DB
	profile config.NetworkProfile
}

func NewManualRepairTriggerHandler(db *sql.DB, profile config.NetworkProfile) *ManualRepairTriggerHandler {
	return &ManualRepairTriggerHandler{db: db, profile: profile}
}

func (h *ManualRepairTriggerHandler) HandleTrigger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req manualRepairTriggerRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}

	chunkIDRaw, err := hex.DecodeString(req.ChunkID)
	if err != nil || len(chunkIDRaw) != 32 {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "chunk_id must be 64 lowercase hex characters", nil, "chunk_id", nil)
		return
	}
	var chunkID [32]byte
	copy(chunkID[:], chunkIDRaw)

	if req.SegmentID == uuid.Nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "segment_id is required", nil, "segment_id", nil)
		return
	}

	triggerType, ok := parseRepairTriggerType(req.TriggerType)
	if !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "trigger_type must be a valid RepairTriggerType", nil, "trigger_type", nil)
		return
	}

	var segmentExists bool
	if err := h.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM segments WHERE segment_id = $1)`, req.SegmentID).Scan(&segmentExists); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "segment lookup failed", nil, "", nil)
		return
	}
	if !segmentExists {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "segment_id not found", nil, "segment_id", nil)
		return
	}

	// IsVettingChunk() must be called before every EnqueueJob (DM §3
	// Invariant 6, ADR-030; enforced identically in
	// internal/repair/departure.go). repair.IsVettingChunk itself requires
	// a concrete providerID; provider_id is legitimately nullable here for
	// threshold-triggered repairs (no single departure caused the drop), so
	// the nil-provider branch below queries is_vetting_chunk directly by
	// chunk_id instead — the same invariant, checked the only way it can be
	// when no provider is named.
	var isVetting bool
	if req.ProviderID != nil {
		isVetting, err = repair.IsVettingChunk(ctx, h.db, chunkID, *req.ProviderID)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "vetting chunk check failed", nil, "", nil)
			return
		}
	} else {
		if err := h.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM chunk_assignments WHERE chunk_id = $1 AND is_vetting_chunk = TRUE)`, chunkIDRaw).Scan(&isVetting); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "vetting chunk check failed", nil, "", nil)
			return
		}
	}
	if isVetting {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "chunk is a synthetic vetting chunk; not eligible for repair (ADR-030)", nil, "chunk_id", nil)
		return
	}

	// available_shard_count: the live fragment count for this segment right
	// now (real, non-vetting shards only) — the same quantity
	// EnqueueRepairForRealChunks computes for departure-triggered repairs
	// (internal/repair/departure.go), computed directly here since a
	// manual admin trigger has no departure event to diff against.
	var availableShardCount int
	if err := h.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM chunk_assignments
		WHERE segment_id = $1 AND is_vetting_chunk = FALSE AND status IN ('ACTIVE', 'REPAIRING')`,
		req.SegmentID).Scan(&availableShardCount); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "shard count lookup failed", nil, "", nil)
		return
	}

	if err := repair.EnqueueJob(ctx, h.db, h.profile, chunkID, req.SegmentID, req.ProviderID, triggerType, availableShardCount); err != nil {
		if errors.Is(err, repair.ErrShardCountOutOfRange) {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest,
				fmt.Sprintf("available_shard_count (%d) is outside [%d, %d] for the active profile", availableShardCount, h.profile.DataShards, h.profile.TotalShards),
				nil, "", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, ErrInternal, "enqueue failed", nil, "", nil)
		return
	}

	// EnqueueJob (internal/repair) returns only an error, not the row it
	// just inserted — re-fetch the just-created job to build the response.
	// The most-recently-created QUEUED job for this (chunk_id, segment_id)
	// pair is this call's own row: a manual, single-admin-triggered action,
	// not a high-concurrency hot path.
	var item repairJobItemBody
	var respChunkIDRaw []byte
	var startedAt, completedAt sql.NullTime
	err = h.db.QueryRowContext(ctx, `
		SELECT job_id, chunk_id, segment_id, provider_id, trigger_type, priority, status,
		       available_shard_count, created_at, started_at, completed_at
		FROM repair_jobs
		WHERE chunk_id = $1 AND segment_id = $2 AND status = 'QUEUED'
		ORDER BY created_at DESC
		LIMIT 1`, chunkIDRaw, req.SegmentID,
	).Scan(&item.JobID, &respChunkIDRaw, &item.SegmentID, &item.ProviderID, &item.TriggerType,
		&item.Priority, &item.Status, &item.AvailableShardCount, &item.CreatedAt, &startedAt, &completedAt)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to read back created job", nil, "", nil)
		return
	}
	item.ChunkID = hex.EncodeToString(respChunkIDRaw)
	if startedAt.Valid {
		item.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		item.CompletedAt = &completedAt.Time
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(item)
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.4 — GET /api/v1/admin/audit/stats (getAuditStats)
// ═══════════════════════════════════════════════════════════════════════

const auditStatsDefaultWindow = 1 * time.Hour

type auditStatsResultsBody struct {
	Pass    int64 `json:"pass"`
	Fail    int64 `json:"fail"`
	Timeout int64 `json:"timeout"`
	Pending int64 `json:"pending"`
}

type auditStatsResponseBody struct {
	WindowStart time.Time             `json:"window_start"`
	WindowEnd   time.Time             `json:"window_end"`
	Challenges  int64                 `json:"challenges_issued"`
	Results     auditStatsResultsBody `json:"results"`
	PassRate    float64               `json:"pass_rate"`
	TimeoutRate float64               `json:"timeout_rate"`
	// ContentHashFailures: always 0 — see this file's header note on why no
	// query against the current schema can compute this field.
	ContentHashFailures int `json:"content_hash_failures"`
	JITFlagsRaised      int `json:"jit_flags_raised"`
}

// AuditStatsHandler serves GET /api/v1/admin/audit/stats.
type AuditStatsHandler struct {
	db *sql.DB
}

func NewAuditStatsHandler(db *sql.DB) *AuditStatsHandler {
	return &AuditStatsHandler{db: db}
}

func (h *AuditStatsHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	now := time.Now().UTC()
	windowStart := now.Add(-auditStatsDefaultWindow)
	windowEnd := now
	if from := q.Get("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "from must be ISO 8601", nil, "from", nil)
			return
		}
		windowStart = t
	}
	if to := q.Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "to must be ISO 8601", nil, "to", nil)
			return
		}
		windowEnd = t
	}

	where := []string{"abandoned_at IS NULL", "server_challenge_ts >= $1", "server_challenge_ts < $2"}
	args := []any{windowStart, windowEnd} // to is exclusive (OAS)

	if pid := q.Get("provider_id"); pid != "" {
		id, err := uuid.Parse(pid)
		if err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "provider_id must be a UUID", nil, "provider_id", nil)
			return
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("provider_id = $%d", len(args)))
	}

	whereClause := strings.Join(where, " AND ")

	var results auditStatsResultsBody
	var jitFlags, challenges int64
	err := h.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE audit_result = 'PASS'),
			COUNT(*) FILTER (WHERE audit_result = 'FAIL'),
			COUNT(*) FILTER (WHERE audit_result = 'TIMEOUT'),
			COUNT(*) FILTER (WHERE audit_result IS NULL),
			COUNT(*) FILTER (WHERE jit_flag = TRUE),
			COUNT(*)
		FROM audit_receipts
		WHERE `+whereClause, args...,
	).Scan(&results.Pass, &results.Fail, &results.Timeout, &results.Pending, &jitFlags, &challenges)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "audit stats query failed", nil, "", nil)
		return
	}

	// pass_rate = pass / (pass + fail + timeout) — OAS's own formula.
	var passRate float64
	if denom := results.Pass + results.Fail + results.Timeout; denom > 0 {
		passRate = float64(results.Pass) / float64(denom)
	}
	// timeout_rate: NFR-027's own wording is "TIMEOUT rate > 5% of
	// challenges in a 1-hour window" — of challenges (challenges_issued),
	// not of terminal (pass+fail+timeout) results only.
	var timeoutRate float64
	if challenges > 0 {
		timeoutRate = float64(results.Timeout) / float64(challenges)
	}

	resp := auditStatsResponseBody{
		WindowStart:         windowStart,
		WindowEnd:           windowEnd,
		Challenges:          challenges,
		Results:             results,
		PassRate:            passRate,
		TimeoutRate:         timeoutRate,
		ContentHashFailures: 0,
		JITFlagsRaised:      int(jitFlags),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.5 — GET /api/v1/admin/vetting/status (getVettingStatus)
// ═══════════════════════════════════════════════════════════════════════

type vettingSummaryBody struct {
	ChunksAssigned    int     `json:"chunks_assigned"`
	ChunkCap          int     `json:"chunk_cap"`
	CapUtilisationPct float64 `json:"cap_utilisation_pct"`
	ChunksPendingGC   int     `json:"chunks_pending_gc"`
}

type vettingStatusProviderItem struct {
	ProviderID             uuid.UUID          `json:"provider_id"`
	Status                 string             `json:"status"`
	ConsecutiveAuditPasses int                `json:"consecutive_audit_passes"`
	VettingSummary         vettingSummaryBody `json:"vetting_summary"`
	LastHeartbeatTS        *time.Time         `json:"last_heartbeat_ts"`
}

type vettingStatusResponseBody struct {
	TotalVettingProviders         int                         `json:"total_vetting_providers"`
	TotalSyntheticChunksActive    int64                       `json:"total_synthetic_chunks_active"`
	TotalSyntheticChunksPendingGC int                         `json:"total_synthetic_chunks_pending_gc"`
	Providers                     []vettingStatusProviderItem `json:"providers"`
}

const percentageScale = 100.0

// VettingStatusHandler serves GET /api/v1/admin/vetting/status.
type VettingStatusHandler struct {
	db *sql.DB
}

func NewVettingStatusHandler(db *sql.DB) *VettingStatusHandler {
	return &VettingStatusHandler{db: db}
}

func (h *VettingStatusHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	includeGCPendingOnly := false
	if v := q.Get("include_gc_pending_only"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "include_gc_pending_only must be a boolean", nil, "include_gc_pending_only", nil)
			return
		}
		includeGCPendingOnly = b
	}

	var totalVettingProviders int
	if err := h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM providers WHERE status = 'VETTING'`).Scan(&totalVettingProviders); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "vetting provider count failed", nil, "", nil)
		return
	}

	var totalSyntheticActive int64
	if err := h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM chunk_assignments WHERE is_vetting_chunk = TRUE AND status = 'ACTIVE'`).Scan(&totalSyntheticActive); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "synthetic chunk count failed", nil, "", nil)
		return
	}

	var totalSyntheticPendingGC int
	if err := h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM chunk_assignments WHERE is_vetting_chunk = TRUE AND status = 'PENDING_DELETION'`).Scan(&totalSyntheticPendingGC); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "pending GC count failed", nil, "", nil)
		return
	}

	// Base cohort: every VETTING provider, plus ACTIVE providers whose
	// synthetic chunk cleanup is incomplete (OAS's own description:
	// "aggregate vetting statistics across all VETTING providers, plus
	// per-provider detail for providers with non-zero chunks_pending_gc").
	// include_gc_pending_only then narrows this cohort further, in Go
	// below, to only rows with chunks_pending_gc > 0.
	rows, err := h.db.QueryContext(ctx, `
		SELECT p.provider_id, p.status, p.consecutive_audit_passes, p.last_heartbeat_ts, p.declared_storage_gb,
		       (SELECT COUNT(*) FROM chunk_assignments ca WHERE ca.provider_id = p.provider_id AND ca.is_vetting_chunk = TRUE AND ca.status = 'ACTIVE') AS chunks_assigned,
		       (SELECT COUNT(*) FROM chunk_assignments ca WHERE ca.provider_id = p.provider_id AND ca.is_vetting_chunk = TRUE AND ca.status = 'PENDING_DELETION') AS chunks_pending_gc
		FROM providers p
		WHERE p.status = 'VETTING'
		   OR (p.status = 'ACTIVE' AND EXISTS (
		         SELECT 1 FROM chunk_assignments ca2
		         WHERE ca2.provider_id = p.provider_id AND ca2.is_vetting_chunk = TRUE AND ca2.status = 'PENDING_DELETION'))
		ORDER BY p.created_at ASC`)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "vetting cohort query failed", nil, "", nil)
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("VettingStatusHandler.HandleStatus: close rows", "error", err)
		}
	}()

	items := make([]vettingStatusProviderItem, 0)
	for rows.Next() {
		var item vettingStatusProviderItem
		var lastHeartbeat sql.NullTime
		var declaredStorageGB, chunksAssigned, chunksPendingGC int
		if err := rows.Scan(&item.ProviderID, &item.Status, &item.ConsecutiveAuditPasses, &lastHeartbeat,
			&declaredStorageGB, &chunksAssigned, &chunksPendingGC); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "scan failed", nil, "", nil)
			return
		}
		if includeGCPendingOnly && chunksPendingGC == 0 {
			continue
		}
		if lastHeartbeat.Valid {
			item.LastHeartbeatTS = &lastHeartbeat.Time
		}
		chunkCap := declaredStorageGB * vettingChunksPerGB
		var utilisation float64
		if chunkCap > 0 {
			utilisation = float64(chunksAssigned) / float64(chunkCap) * percentageScale
		}
		item.VettingSummary = vettingSummaryBody{
			ChunksAssigned:    chunksAssigned,
			ChunkCap:          chunkCap,
			CapUtilisationPct: utilisation,
			ChunksPendingGC:   chunksPendingGC,
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "row iteration failed", nil, "", nil)
		return
	}

	resp := vettingStatusResponseBody{
		TotalVettingProviders:         totalVettingProviders,
		TotalSyntheticChunksActive:    totalSyntheticActive,
		TotalSyntheticChunksPendingGC: totalSyntheticPendingGC,
		Providers:                     items,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.10.6 — POST /api/v1/admin/vetting/gc/retry (retryVettingGC)
// ═══════════════════════════════════════════════════════════════════════

type vettingGCRetryRequestBody struct {
	ProviderID uuid.UUID `json:"provider_id"`
}

type vettingGCRetryResponseBody struct {
	ProviderID            uuid.UUID `json:"provider_id"`
	DeliveryAttempted     bool      `json:"delivery_attempted"`
	ChunksPendingGCBefore int       `json:"chunks_pending_gc_before"`
	ChunksPendingGCAfter  int       `json:"chunks_pending_gc_after"`
}

// VettingGCRetryHandler serves POST /api/v1/admin/vetting/gc/retry.
type VettingGCRetryHandler struct {
	db *sql.DB
}

func NewVettingGCRetryHandler(db *sql.DB) *VettingGCRetryHandler {
	return &VettingGCRetryHandler{db: db}
}

// countPendingGC returns providerID's current chunks_pending_gc — the
// count of synthetic chunk_assignments in PENDING_DELETION status.
func countPendingGC(ctx context.Context, db *sql.DB, providerID uuid.UUID) (int, error) {
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM chunk_assignments WHERE provider_id = $1 AND is_vetting_chunk = TRUE AND status = 'PENDING_DELETION'`,
		providerID,
	).Scan(&count)
	return count, err
}

func (h *VettingGCRetryHandler) HandleRetry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req vettingGCRetryRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	if req.ProviderID == uuid.Nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "provider_id is required", nil, "provider_id", nil)
		return
	}

	var status sql.NullString
	err := h.db.QueryRowContext(ctx, `SELECT status FROM providers WHERE provider_id = $1`, req.ProviderID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "provider_id not found", nil, "provider_id", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider lookup failed", nil, "", nil)
		return
	}

	chunksPendingGCBefore, err := countPendingGC(ctx, h.db, req.ProviderID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "pending GC count failed", nil, "", nil)
		return
	}

	// Must identify a provider with status = 'ACTIVE' and
	// chunks_pending_gc > 0 (OAS's own description of provider_id).
	if status.String != "ACTIVE" || chunksPendingGCBefore <= 0 {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest,
			"provider must be ACTIVE with chunks_pending_gc > 0", nil, "provider_id", nil)
		return
	}

	// delivery_attempted is always false: see this file's header note.
	// vettingchunk.DeliverGCInstruction (Milestone 14) does not exist yet
	// to call; the automatic background retry (once Milestone 14 lands)
	// continues regardless, matching the "provider offline" branch of
	// OAS's own documented 200 contract.
	resp := vettingGCRetryResponseBody{
		ProviderID:            req.ProviderID,
		DeliveryAttempted:     false,
		ChunksPendingGCBefore: chunksPendingGCBefore,
		ChunksPendingGCAfter:  chunksPendingGCBefore,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

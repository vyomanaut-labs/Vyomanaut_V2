// Package api is declared in doc.go.
// This file implements build.md Milestone 11 Phase 11.9 Session 11.9.1:
// POST /api/v1/audit/challenge, the AdminApiKey-gated manual out-of-cycle
// audit challenge dispatcher (FR-037, ADR-002, ADR-006, ADR-014).
//
// SCOPE: what this endpoint does and does not do. OAS's own path
// description says challenge dispatch "happens over libp2p to
// providers.last_known_multiaddrs" — but internal/p2p has only ever
// reserved the "/vyomanaut/audit-challenge/1.0.0" protocol ID string
// (internal/p2p/host.go, internal/p2p/types.go); no stream-level dispatch
// exists anywhere in this codebase yet, and building it is a networking
// concern far outside a REST-layer session. This handler's job ends at
// exactly what ADR-015's three-phase write model calls "Phase 1": it
// authorises the request, resolves the (provider_id, chunk_id) pair,
// generates the nonce, and writes the PENDING audit_receipts row via
// audit.WriteReceiptPhase1 (Milestone 7) — then returns 202 Accepted,
// which is the correct HTTP status for exactly this situation ("the
// request has been accepted for processing, but processing is not yet
// complete"). Actual network dispatch of the resulting challenge, and the
// eventual WriteReceiptRecordResponse/WriteReceiptPhase2 calls that
// adjudicate it, are the not-yet-built scheduler's job (a later
// milestone), consistent with OAS's own 202 response description: "the
// receipt will arrive asynchronously."
//
// [Flag, not actionable here] That same 202 description also says the
// receipt "will arrive asynchronously via POST /api/v1/audit/receipt" — but
// this file's own AuditChallengeDispatchResponse schema comment says
// AuditReceiptSubmitRequest/Response "were removed as the audit
// challenge/response is entirely over libp2p with no HTTP POST from the
// provider involved." OAS contradicts itself on this one point; the removal
// note is the more specific, more recently-written statement of the two, so
// it is treated as authoritative (no HTTP receipt-submission endpoint is
// implemented or assumed here) — flagged for an OAS text correction, not
// something this handler's own behaviour needs to resolve.
//
// DEDUP: "does not bypass the 24-hour deduplication window" (OAS, FR-037).
// OAS defines no 409 response for this endpoint — only 202/400/401/403/404
// — so a request that lands inside the window is not an error: it is
// answered with the SAME challenge_nonce/server_challenge_ts already on
// record for that (provider_id, chunk_id) pair (still 202), rather than
// writing — and the scheduler later having to reconcile — a second PENDING
// row for a chunk FR-037 says gets exactly one challenge per period. The
// deadline_ms figure is always freshly computed either way, since a
// provider's throughput sample can change between two calls even when the
// nonce does not.
//
// STATUS GATE: OAS's provider_id field description says "Must have status =
// ACTIVE or VETTING"; the explicit 403 case this session names is DEPARTED.
// PENDING_ONBOARDING is not separately checked for — a provider in that
// status cannot have any chunk_assignments row yet (chunk assignment only
// ever follows vetting), so it is rejected identically to any other
// nonexistent pairing, via the chunk-assignment lookup's own 404, without
// needing a second, redundant status branch here.
//
// [REF: OAS paths./api/v1/audit/challenge, components/schemas/
// AuditChallengeDispatchRequest/Response, FR-037, ADR-002, ADR-006,
// ADR-014, ADR-015, ADR-027, DM §4.2 §4.5 §4.7, build.md Phase 11.9]

package api

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/audit"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

const (
	// auditChallengeChunkSizeKB is the fixed shard size in kilobytes (DM §3
	// Invariant 7; ShardSize = 262,144 bytes = 256 KB in both demo and
	// production). Mirrors internal/audit/jit.go's own unexported
	// chunkSizeKB — restated here rather than imported, since that constant
	// isn't exported and this file needs the identical value for a related
	// but distinct formula (see auditDeadlineMsFactor below).
	auditChallengeChunkSizeKB = 256

	// auditDeadlineMsFactor is DM §4.2's own explicit deadline_ms formula
	// constant: deadline_ms = (chunk_size_kb / p95_throughput_kbps) × 1500.
	// DM §4.2 states this already folded into a single ms-scaled figure
	// (1.5 safety factor × 1000 ms/s) — unlike the JIT floor's separate
	// ×0.3×1000, which internal/audit/jit.go's own UNITS CORRECTION note had
	// to derive by hand because ARCH §20/§14 state that floor as a bare
	// "×0.3" with no seconds-to-ms conversion folded in. This constant is
	// used exactly as DM §4.2 gives it, with no re-derivation needed.
	auditDeadlineMsFactor = 1500
)

// auditChallengeDispatchRequestBody mirrors OAS
// AuditChallengeDispatchRequest.
type auditChallengeDispatchRequestBody struct {
	ProviderID string `json:"provider_id"`
	ChunkID    string `json:"chunk_id"` // 64 hex chars
}

// auditChallengeDispatchResponseBody mirrors OAS
// AuditChallengeDispatchResponse.
type auditChallengeDispatchResponseBody struct {
	ChallengeNonce    string    `json:"challenge_nonce"` // 66 hex chars
	ServerChallengeTS time.Time `json:"server_challenge_ts"`
	DeadlineMs        int64     `json:"deadline_ms"`
}

// AuditChallengeHandler serves POST /api/v1/audit/challenge. AdminApiKey
// authorisation is enforced by router.go's adminAuthMiddleware wrapper, not
// by this handler — consistent with every other AdminApiKey route in this
// package (e.g. ReadinessEvaluator.HandleReadiness).
type AuditChallengeHandler struct {
	db                 *sql.DB
	profile            config.NetworkProfile
	clusterSecretCache *audit.ClusterSecretCache
}

// NewAuditChallengeHandler constructs an AuditChallengeHandler. Callers must
// only construct one once clusterSecretCache.Load has succeeded at least
// once (IC §8's own fail-closed startup requirement) — router.go mirrors
// the same conditional-construction pattern already used for
// ownerDepositHandler/ownerWithdrawHandler when cfg.ClusterSecretCache is
// nil, registering stub501 instead rather than risking a nil dereference.
func NewAuditChallengeHandler(db *sql.DB, profile config.NetworkProfile, clusterSecretCache *audit.ClusterSecretCache) *AuditChallengeHandler {
	return &AuditChallengeHandler{db: db, profile: profile, clusterSecretCache: clusterSecretCache}
}

// HandleDispatch serves POST /api/v1/audit/challenge.
func (h *AuditChallengeHandler) HandleDispatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req auditChallengeDispatchRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	providerID, err := uuid.Parse(req.ProviderID)
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "provider_id must be a UUID", nil, "provider_id", nil)
		return
	}
	chunkIDRaw, err := hex.DecodeString(req.ChunkID)
	if err != nil || len(chunkIDRaw) != 32 {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "chunk_id must be 64 lowercase hex characters", nil, "chunk_id", nil)
		return
	}
	var chunkID [32]byte
	copy(chunkID[:], chunkIDRaw)

	// ── Provider gate: exists, and not DEPARTED (OAS 403; see this file's
	// header note on why PENDING_ONBOARDING needs no separate branch) ──────
	var (
		status         string
		p95Throughput  sql.NullFloat64
		multiaddrStale bool
	)
	err = h.db.QueryRowContext(ctx,
		`SELECT status, p95_throughput_kbps, multiaddr_stale FROM providers WHERE provider_id = $1`,
		providerID,
	).Scan(&status, &p95Throughput, &multiaddrStale)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusNotFound, ErrNotFound, "provider not found", nil, "provider_id", nil)
		return
	}
	if err != nil {
		slog.Error("AuditChallengeHandler.HandleDispatch: provider lookup", "error", err)
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider lookup failed", nil, "", nil)
		return
	}
	if status == "DEPARTED" {
		WriteError(w, http.StatusForbidden, ErrProviderDeparted, "provider has departed the network", nil, "provider_id", nil)
		return
	}

	// ── Chunk-assignment gate: this provider must actually hold this chunk,
	// and challenges must still be issued for it (DM §4.5: PENDING_DELETION
	// / DELETED assignments receive no further challenges) ─────────────────
	var (
		isVettingChunk bool
		segmentID      uuid.NullUUID
		assignStatus   string
	)
	err = h.db.QueryRowContext(ctx,
		`SELECT is_vetting_chunk, segment_id, status FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
		chunkIDRaw, providerID,
	).Scan(&isVettingChunk, &segmentID, &assignStatus)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusNotFound, ErrNotFound, "no matching chunk assignment for this provider", nil, "chunk_id", nil)
		return
	}
	if err != nil {
		slog.Error("AuditChallengeHandler.HandleDispatch: chunk assignment lookup", "error", err)
		WriteError(w, http.StatusInternalServerError, ErrInternal, "chunk assignment lookup failed", nil, "", nil)
		return
	}
	if assignStatus != "ACTIVE" && assignStatus != "REPAIRING" {
		WriteError(w, http.StatusNotFound, ErrNotFound, "chunk assignment is no longer active", nil, "chunk_id", nil)
		return
	}

	// file_id is nil for a synthetic vetting chunk (DM §4.7, DM §8.20;
	// ReceiptFields.FileID's own contract) and otherwise resolved via the
	// assignment's segment — chunk_assignments has no file_id column of its
	// own (DM §4.5).
	var fileID *uuid.UUID
	if !isVettingChunk {
		if !segmentID.Valid {
			slog.Error("AuditChallengeHandler.HandleDispatch: real chunk assignment missing segment_id", "chunk_id", req.ChunkID)
			WriteError(w, http.StatusInternalServerError, ErrInternal, "chunk assignment is inconsistent", nil, "", nil)
			return
		}
		var fID uuid.UUID
		if err := h.db.QueryRowContext(ctx, `SELECT file_id FROM segments WHERE segment_id = $1`, segmentID.UUID).Scan(&fID); err != nil {
			slog.Error("AuditChallengeHandler.HandleDispatch: segment lookup", "error", err)
			WriteError(w, http.StatusInternalServerError, ErrInternal, "segment lookup failed", nil, "", nil)
			return
		}
		fileID = &fID
	}

	deadlineMs, err := h.computeDeadlineMs(ctx, p95Throughput)
	if err != nil {
		slog.Error("AuditChallengeHandler.HandleDispatch: compute deadline", "error", err)
		WriteError(w, http.StatusInternalServerError, ErrInternal, "unable to compute audit deadline", nil, "", nil)
		return
	}

	// ── Dedup gate: FR-037 / ADR-002 / ADR-006 — this endpoint does NOT
	// bypass the one-challenge-per-chunk-per-window rule (see header note) ──
	var lastChallengeTS sql.NullTime
	var lastNonce []byte
	err = h.db.QueryRowContext(ctx, `
		SELECT server_challenge_ts, challenge_nonce FROM audit_receipts
		WHERE chunk_id = $1 AND provider_id = $2
		ORDER BY server_challenge_ts DESC
		LIMIT 1`,
		chunkIDRaw, providerID,
	).Scan(&lastChallengeTS, &lastNonce)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		slog.Error("AuditChallengeHandler.HandleDispatch: dedup lookup", "error", err)
		WriteError(w, http.StatusInternalServerError, ErrInternal, "dedup lookup failed", nil, "", nil)
		return
	}

	now := time.Now().UTC()
	if lastChallengeTS.Valid && now.Sub(lastChallengeTS.Time) < h.profile.PollingInterval {
		writeAuditChallengeResponse(w, lastNonce, lastChallengeTS.Time, deadlineMs)
		return
	}

	secret, versionByte, err := h.clusterSecretCache.CurrentSecret()
	if err != nil {
		slog.Error("AuditChallengeHandler.HandleDispatch: cluster secret unavailable", "error", err)
		WriteError(w, http.StatusInternalServerError, ErrInternal, "cluster audit secret unavailable", nil, "", nil)
		return
	}
	nonce := audit.ChallengeNonce(secret, versionByte, chunkID, now.UnixMilli())

	if _, err := audit.WriteReceiptPhase1(ctx, h.db, audit.ReceiptFields{
		ChunkID:           chunkID,
		FileID:            fileID,
		ProviderID:        providerID,
		ChallengeNonce:    nonce,
		ServerChallengeTs: now,
		AddressWasStale:   multiaddrStale,
	}); err != nil {
		slog.Error("AuditChallengeHandler.HandleDispatch: write receipt phase 1", "error", err)
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to record challenge dispatch", nil, "", nil)
		return
	}

	writeAuditChallengeResponse(w, nonce[:], now, deadlineMs)
}

// computeDeadlineMs implements DM §4.2's deadline_ms formula, substituting
// the network pool median when this provider's own p95_throughput_kbps is
// NULL or non-positive ("NULL = unestablished; application substitutes
// pool median" — the providers.p95_throughput_kbps column's own migration
// comment). A zero/negative throughput is treated identically to NULL: DM
// §4.2 documents a prior schema revision that defaulted this column to 0
// specifically because an unguarded division by it produces exactly the
// division-by-zero bug this branch exists to avoid.
func (h *AuditChallengeHandler) computeDeadlineMs(ctx context.Context, p95 sql.NullFloat64) (int64, error) {
	throughput := p95.Float64
	if !p95.Valid || p95.Float64 <= 0 {
		median, ok, err := poolMedianThroughputKbps(ctx, h.db)
		if err != nil {
			return 0, fmt.Errorf("pool median throughput: %w", err)
		}
		if !ok {
			return 0, fmt.Errorf("no established p95_throughput_kbps anywhere in the provider pool yet")
		}
		throughput = median
	}
	ms := math.Ceil((float64(auditChallengeChunkSizeKB) / throughput) * auditDeadlineMsFactor)
	return int64(ms), nil
}

// poolMedianThroughputKbps mirrors the identical PERCENTILE_CONT query
// already established at provider.go's own p95_throughput_kbps NULL
// substitution (Session 11.6.3's GET /api/v1/provider/{provider_id}/status)
// — a TRUE median, not an AVG()/mean, for the same reason
// scoring.PoolMedianRTO gives for its own (differently-scoped) median: a
// handful of unusually slow or fast providers would otherwise skew a mean.
// Restated here rather than extracted into a shared helper both files call,
// to avoid modifying provider.go's already-verified Phase 11.6 code for a
// two-call deduplication; ok is false only when no provider anywhere has an
// established sample yet (expected only very early in the network's life).
func poolMedianThroughputKbps(ctx context.Context, db *sql.DB) (float64, bool, error) {
	const query = `SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY p95_throughput_kbps) FROM providers WHERE p95_throughput_kbps IS NOT NULL`
	var median sql.NullFloat64
	if err := db.QueryRowContext(ctx, query).Scan(&median); err != nil {
		return 0, false, err
	}
	if !median.Valid || median.Float64 <= 0 {
		return 0, false, nil
	}
	return median.Float64, true, nil
}

// writeAuditChallengeResponse writes the 202 Accepted envelope shared by
// both the freshly-dispatched and the dedup-reuse paths through
// HandleDispatch.
func writeAuditChallengeResponse(w http.ResponseWriter, nonce []byte, serverChallengeTS time.Time, deadlineMs int64) {
	resp := auditChallengeDispatchResponseBody{
		ChallengeNonce:    hex.EncodeToString(nonce),
		ServerChallengeTS: serverChallengeTS,
		DeadlineMs:        deadlineMs,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(resp)
}

// Package api is declared in doc.go.
// This file implements build.md Milestone 11 Phase 11.7 Session 11.7.1:
// POST /api/v1/upload/assign.
//
// [FLAGGED — schema gap, ShardAssignment needs a chunk_id field] OAS's
// ShardAssignment schema has no chunk_id property, yet IC §4.1's capability
// token signing_input is bound to a specific chunk_id
// (SHA-256("vyomanaut-chunk-upload-cap-v1" || chunk_id || provider_id ||
// file_id || expiry_unix_ms)), and IC §4.1 step 5 says the provider
// "re-derives signing_input using the chunk_id received in the frame
// header" — i.e. the client must send the SAME chunk_id the token was
// signed over, or every upload fails signature verification. Real content
// hashing can't produce this value in advance: ADR-022's AONT step 2 draws
// a fresh random key per segment, so the eventual shard bytes (and their
// true SHA-256) are not knowable at assignment time, before the client has
// even performed the AONT-RS transform. The client has no source for this
// value except this response. Resolved here as: chunk_id is a
// microservice-assigned 32-byte identifier for the (segment, shard_index)
// slot, generated once at first assignment and persisted in
// chunk_assignments.chunk_id (already NOT NULL there), returned verbatim on
// every idempotent re-call. This is the same "code needs a field the OAS
// schema omits" situation as Phase 11.6's promised_return_at gap — flagged
// and added rather than left unimplementable. ShardAssignmentBody below adds
// ChunkID accordingly.
//
// [Decision — provider selection reuses internal/repair] OAS: "Selects
// providers using Power of Two Choices weighted by reliability score" +
// "Enforces the 20% ASN cap" is exactly internal/repair.
// SelectReplacementProvider's existing, already-tested algorithm (built for
// repair reassignment, Session 9.4.1) — same P2C-over-score-composite
// selection, same floor(TotalShards*ASNCapFraction) cap, same
// ErrNoEligibleReplacement exhaustion signal. internal/api sits above
// internal/repair in the import layering (confirmed already in Phase 11.6:
// "internal/api — not internal/repair — is the layer permitted to call both
// packages"), so reusing it directly here — rather than re-implementing P2C
// and the ASN cap a second time — is both permitted and the more consistent
// choice; a second, drifting copy of this algorithm would be a worse
// outcome. ErrNoEligibleReplacement is treated as this endpoint's own
// INSUFFICIENT_ASN_DIVERSITY signal.
//
// [Decision — idempotency skips the three gates on repeat calls] The
// TASK's three checks (readiness, escrow, ASN cap) and its "idempotent on
// file_id" note are two separate concerns; IC §4's own ERRATA describes a
// repeat call (after a provider returns CAPABILITY_EXPIRED) as returning
// "the same provider set... but generates new tokens with a fresh expiry" —
// no mention of re-validating readiness/escrow. A client mid-upload,
// retrying only because a token expired, should not be newly blocked by a
// transient readiness or escrow hiccup after the real assignment work is
// already done. Implemented as: if file_id already has persisted segments,
// skip straight to regenerating tokens.
//
// [Decision — escrow check uses available, not raw, balance] FR-014's own
// wording says "balance < cost_for_30_days(file_size)", but
// ownerBalanceAndReserved (built in Phase 11.5 for exactly this purpose —
// see its own doc comment) already establishes that "available" (balance
// minus every other ACTIVE file's reserved 30-day cost) is this codebase's
// operative check, not raw balance — using raw balance here would let an
// owner oversubscribe escrow across many files. Reused directly, same as
// Phase 11.6 reused Phase 11.5's helpers.
//
// [REF: OAS paths./api/v1/upload/assign, components/schemas/
// UploadAssignRequest/Response, SegmentAssignment, ShardAssignment,
// FR-007-FR-020, ADR-014, ADR-022, IC §4.1, build.md Phase 11.7
// Session 11.7.1]

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	localcrypto "github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
	"github.com/masamasaowl/Vyomanaut_V2/internal/repair"
)

// ── Capability token (IC §4.1) ──────────────────────────────────────────

const (
	capabilityTokenDomainPrefix = "vyomanaut-chunk-upload-cap-v1"
	capabilityTokenLifetime     = 1 * time.Hour
	capabilityTokenByteLen      = 72 // 8-byte expiry_unix_ms || 64-byte Ed25519 signature

	// Constants for the fixed binary sizes
	sha256Size = 32
	uint64Size = 8
)

// generateCapabilityToken implements IC §4.1's byte layout:
//
//	signing_input = SHA-256(domain_prefix || chunk_id || provider_id || expiry_unix_ms)
//	capability_token = expiry_unix_ms (8B) || Ed25519_sign(microservice_signing_key, signing_input)
//
// file_id is deliberately NOT part of this signing input — Design Council
// verdict ("Capability Token: Drop file_id, Not Add It to the Wire
// Format", ADR-072): chunk_id is 256 bits of fresh, microservice-generated
// randomness minted once per assignment and never reused across files, so
// it already carries the exact binding file_id would have provided. IC
// §4.1's UploadRequest wire format (chunk_id, shard_index,
// capability_token, chunk_data) has no file_id field at all — a provider
// daemon could never have verified it — so every real (non-vetting) upload
// failed capability-token verification (0x03 NOT_ASSIGNED) until this fix.
//
// crypto.SignBytes already performs the SHA-256-then-Ed25519-sign
// composition internally (IC §3.2's SIGNING_INPUT_RULE convention used
// throughout this package), so the raw, pre-hash field concatenation is
// passed directly — SignBytes hashing it is what produces IC §4.1's
// signing_input, not a second, additional hash.
func generateCapabilityToken(msSigningKey ed25519.PrivateKey, chunkID [32]byte, providerID uuid.UUID, issuedAt time.Time) [capabilityTokenByteLen]byte {
	expiryUnixMs := issuedAt.Add(capabilityTokenLifetime).UnixMilli()
	var expiryBytes [8]byte
	binary.BigEndian.PutUint64(expiryBytes[:], uint64(expiryUnixMs))

	input := make([]byte, 0, len(capabilityTokenDomainPrefix)+sha256Size+len(providerID)+uint64Size)
	input = append(input, []byte(capabilityTokenDomainPrefix)...)
	input = append(input, chunkID[:]...)
	input = append(input, providerID[:]...)
	input = append(input, expiryBytes[:]...)

	sig := localcrypto.SignBytes(msSigningKey, input)

	var token [capabilityTokenByteLen]byte
	copy(token[0:8], expiryBytes[:])
	copy(token[8:capabilityTokenByteLen], sig[:])
	return token
}

// ── Request/response bodies ─────────────────────────────────────────────

type uploadAssignRequestBody struct {
	FileID            uuid.UUID `json:"file_id"`
	NumSegments       int       `json:"num_segments"`
	OriginalSizeBytes int64     `json:"original_size_bytes"`
}

// ShardAssignmentBody mirrors OAS ShardAssignment, plus ChunkID — see this
// file's header note on why that field is a necessary addition.
type ShardAssignmentBody struct {
	ShardIndex      int       `json:"shard_index"`
	ProviderID      uuid.UUID `json:"provider_id"`
	Multiaddrs      []string  `json:"multiaddrs"`
	ASN             string    `json:"asn"`
	CapabilityToken string    `json:"capability_token"`
	ChunkID         string    `json:"chunk_id"`
}

type segmentAssignmentBody struct {
	SegmentIndex int                   `json:"segment_index"`
	SegmentID    uuid.UUID             `json:"segment_id"`
	Providers    []ShardAssignmentBody `json:"providers"`
}

type uploadAssignResponseBody struct {
	Assignments         []segmentAssignmentBody `json:"assignments"`
	MonthlyCostPaise    int64                   `json:"monthly_cost_paise"`
	RequiredEscrowPaise int64                   `json:"required_escrow_paise"`
}

// ── Handler ──────────────────────────────────────────────────────────────

const (
	minNumSegments = 1
	maxNumSegments = 10000
)

// UploadAssignHandler serves POST /api/v1/upload/assign (FR-007–FR-020,
// ADR-014, ADR-022).
type UploadAssignHandler struct {
	db         *sql.DB
	profile    config.NetworkProfile
	signingKey ed25519.PrivateKey // same microservice identity key as JWT/microservice_sig (IC §4.1)
	readiness  *ReadinessEvaluator
}

func NewUploadAssignHandler(db *sql.DB, profile config.NetworkProfile, signingKey ed25519.PrivateKey, readiness *ReadinessEvaluator) *UploadAssignHandler {
	return &UploadAssignHandler{db: db, profile: profile, signingKey: signingKey, readiness: readiness}
}

func (h *UploadAssignHandler) HandleAssign(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}

	var req uploadAssignRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	if req.NumSegments < minNumSegments || req.NumSegments > maxNumSegments {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, fmt.Sprintf("num_segments must be between %d and %d", minNumSegments, maxNumSegments), nil, "num_segments", nil)
		return
	}
	if req.OriginalSizeBytes < 1 {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "original_size_bytes must be positive", nil, "original_size_bytes", nil)
		return
	}

	monthlyCost := fileMonthlyCostPaiseForBytes(req.OriginalSizeBytes, h.profile)

	// Idempotency: a prior successful call already persisted segments for
	// this file_id — skip the three gates entirely (see file header) and
	// just refresh tokens.
	existing, err := h.loadExistingAssignments(ctx, req.FileID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to check existing assignment", nil, "", nil)
		return
	}
	if len(existing) > 0 {
		h.respondWithFreshTokens(w, existing, monthlyCost)
		return
	}

	// Check 1 — readiness gate.
	readinessResp, err := h.readiness.Evaluate(ctx)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "readiness evaluation failed", nil, "", nil)
		return
	}
	if !readinessResp.AllConditionsMet {
		writeNetworkNotReadyError(w)
		return
	}

	// Check 2 — escrow balance (available, not raw — see file header).
	balance, reserved, err := ownerBalanceAndReserved(ctx, h.db, h.profile, claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "escrow balance lookup failed", nil, "", nil)
		return
	}
	available := balance - reserved
	if available < monthlyCost {
		WriteError(w, http.StatusConflict, ErrInsufficientEscrow, "escrow balance insufficient for 30-day storage cost", nil, "", nil)
		return
	}

	// files row created now (placeholder ciphertext fields — see file.go's
	// header for the file/register handshake this sets up), satisfying
	// segments.file_id's FK before any segment can be inserted.
	if err := h.createPlaceholderFile(ctx, req.FileID, claims.Subject, req.OriginalSizeBytes); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to create file record", nil, "", nil)
		return
	}

	// Check 2.5 — per-provider chunk storage ceiling (NFR-044): exclude
	// providers already at/over the ceiling from every segment's candidate
	// pool below, and reject the whole request if too few eligible ACTIVE
	// providers remain once that exclusion is applied.
	overCeiling, ok := enforceProviderCapacity(ctx, w, h.db, chunkCeilingMaxChunks(h.profile), h.profile.MinActiveProviders)
	if !ok {
		return
	}

	// Check 3 — ASN cap, enforced per-shard by repair.SelectReplacementProvider.
	segments := make([]segmentAssignmentBody, 0, req.NumSegments)
	for segIdx := 0; segIdx < req.NumSegments; segIdx++ {
		segAssignment, availableASNs, err := h.assignSegment(ctx, req.FileID, segIdx, overCeiling)
		if errors.Is(err, repair.ErrNoEligibleReplacement) {
			writeInsufficientASNDiversityError(w, h.profile.TotalShards, availableASNs)
			return
		}
		if err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "shard assignment failed", nil, "", nil)
			return
		}
		segments = append(segments, segAssignment)
	}

	resp := uploadAssignResponseBody{Assignments: segments, MonthlyCostPaise: monthlyCost, RequiredEscrowPaise: monthlyCost}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// createPlaceholderFile inserts the files row that segments.file_id's FK
// requires, with real original_size_bytes (known from the request, needed
// for cost math regardless of registration state) but placeholder
// pointer_ciphertext/nonce/tag — file.go's register handler fills in the
// real values and uses pointer_ciphertext's emptiness as the "not yet
// registered" signal (see that file's header for the full reasoning).
func (h *UploadAssignHandler) createPlaceholderFile(ctx context.Context, fileID, ownerID uuid.UUID, originalSizeBytes int64) error {
	placeholderNonce := make([]byte, aesGCMNonceSize)
	placeholderTag := make([]byte, aesGCMTagSize)
	_, err := h.db.ExecContext(ctx, `
		INSERT INTO files (file_id, owner_id, pointer_ciphertext, pointer_nonce, pointer_tag, original_size_bytes)
		VALUES ($1, $2, ''::bytea, $3, $4, $5)`,
		fileID, ownerID, placeholderNonce, placeholderTag, originalSizeBytes)
	return err
}

// assignSegment creates one segment row and its TotalShards shard
// assignments. shard_index 0..profile.DataShards-1 are the systematic AONT
// data words; profile.DataShards..profile.TotalShards-1 are RS parity
// (never the hardcoded "0-15/16-55" OAS's schema descriptions use — this
// phase's own flagged note). excludeForCeiling seeds the exclude list with
// every provider already at/over the chunk storage ceiling (NFR-044,
// enforceProviderCapacity in HandleAssign) — computed once per request, not
// per segment, since it reflects each provider's real chunk allocation
// which a single new shard assignment (256 KB) does not meaningfully move.
func (h *UploadAssignHandler) assignSegment(ctx context.Context, fileID uuid.UUID, segIdx int, excludeForCeiling []uuid.UUID) (segmentAssignmentBody, int, error) {
	var segmentID uuid.UUID
	if err := h.db.QueryRowContext(ctx, `INSERT INTO segments (file_id, segment_index) VALUES ($1, $2) RETURNING segment_id`,
		fileID, segIdx).Scan(&segmentID); err != nil {
		return segmentAssignmentBody{}, 0, fmt.Errorf("api: assignSegment: insert segment: %w", err)
	}

	shards := make([]ShardAssignmentBody, 0, h.profile.TotalShards)
	excludeIDs := append([]uuid.UUID{}, excludeForCeiling...)
	now := time.Now()

	for shardIdx := 0; shardIdx < h.profile.TotalShards; shardIdx++ {
		providerID, err := repair.SelectReplacementProvider(ctx, h.db, h.profile, segmentID, excludeIDs)
		if err != nil {
			if errors.Is(err, repair.ErrNoEligibleReplacement) {
				availableASNs, countErr := h.countDistinctActiveASNs(ctx)
				if countErr != nil {
					availableASNs = 0
				}
				return segmentAssignmentBody{}, availableASNs, err
			}
			return segmentAssignmentBody{}, 0, fmt.Errorf("api: assignSegment: select provider: %w", err)
		}
		excludeIDs = append(excludeIDs, providerID)

		var chunkID [32]byte
		if _, err := rand.Read(chunkID[:]); err != nil {
			return segmentAssignmentBody{}, 0, fmt.Errorf("api: assignSegment: rand chunk_id: %w", err)
		}
		if _, err := h.db.ExecContext(ctx, `
			INSERT INTO chunk_assignments (chunk_id, is_vetting_chunk, segment_id, shard_index, provider_id)
			VALUES ($1, FALSE, $2, $3, $4)`,
			chunkID[:], segmentID, shardIdx, providerID,
		); err != nil {
			return segmentAssignmentBody{}, 0, fmt.Errorf("api: assignSegment: insert chunk_assignment: %w", err)
		}

		var multiaddrsJSON []byte
		var asn string
		if err := h.db.QueryRowContext(ctx, `SELECT last_known_multiaddrs, asn FROM providers WHERE provider_id = $1`, providerID).
			Scan(&multiaddrsJSON, &asn); err != nil {
			return segmentAssignmentBody{}, 0, fmt.Errorf("api: assignSegment: provider lookup: %w", err)
		}
		var multiaddrs []string
		_ = json.Unmarshal(multiaddrsJSON, &multiaddrs)

		token := generateCapabilityToken(h.signingKey, chunkID, providerID, now)

		shards = append(shards, ShardAssignmentBody{
			ShardIndex:      shardIdx,
			ProviderID:      providerID,
			Multiaddrs:      multiaddrs,
			ASN:             asn,
			CapabilityToken: hex.EncodeToString(token[:]),
			ChunkID:         hex.EncodeToString(chunkID[:]),
		})
	}

	return segmentAssignmentBody{SegmentIndex: segIdx, SegmentID: segmentID, Providers: shards}, 0, nil
}

func (h *UploadAssignHandler) countDistinctActiveASNs(ctx context.Context) (int, error) {
	var count int
	err := h.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT asn) FROM providers WHERE status = 'ACTIVE'`).Scan(&count)
	return count, err
}

// existingShardRow is one persisted chunk_assignments row for an
// already-assigned segment, joined with its provider's current multiaddrs
// and ASN (which may have changed since the original assignment — always
// re-fetched fresh, matching heartbeat's own "current" framing).
type existingShardRow struct {
	segmentIndex int
	segmentID    uuid.UUID
	shardIndex   int
	providerID   uuid.UUID
	chunkID      [32]byte
	multiaddrs   []string
	asn          string
}

// loadExistingAssignments returns every persisted real (non-vetting) shard
// assignment for fileID's segments, or an empty slice if fileID has none
// yet (the common, first-call case — not an error).
func (h *UploadAssignHandler) loadExistingAssignments(ctx context.Context, fileID uuid.UUID) ([]existingShardRow, error) {
	rows, err := h.db.QueryContext(ctx, `
		SELECT s.segment_index, s.segment_id, ca.shard_index, ca.provider_id, ca.chunk_id,
		       p.last_known_multiaddrs, p.asn
		FROM segments s
		JOIN chunk_assignments ca ON ca.segment_id = s.segment_id AND ca.is_vetting_chunk = FALSE
		JOIN providers p ON p.provider_id = ca.provider_id
		WHERE s.file_id = $1
		ORDER BY s.segment_index, ca.shard_index`, fileID)
	if err != nil {
		return nil, fmt.Errorf("api: loadExistingAssignments: %w", err)
	}

	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("loadExistingAssignments: close rows", "error", err)
		}
	}()

	var out []existingShardRow
	for rows.Next() {
		var row existingShardRow
		var chunkIDRaw, multiaddrsJSON []byte
		if err := rows.Scan(&row.segmentIndex, &row.segmentID, &row.shardIndex, &row.providerID, &chunkIDRaw,
			&multiaddrsJSON, &row.asn); err != nil {
			return nil, fmt.Errorf("api: loadExistingAssignments: scan: %w", err)
		}
		copy(row.chunkID[:], chunkIDRaw)
		_ = json.Unmarshal(multiaddrsJSON, &row.multiaddrs)
		out = append(out, row)
	}
	return out, rows.Err()
}

// respondWithFreshTokens rebuilds the UploadAssignResponse from persisted
// rows, regenerating every capability_token with a fresh 1-hour expiry
// (IC §4's ERRATA) without touching the provider set itself.
func (h *UploadAssignHandler) respondWithFreshTokens(w http.ResponseWriter, rows []existingShardRow, monthlyCost int64) {
	now := time.Now()
	segmentsByIndex := make(map[int]*segmentAssignmentBody)
	var order []int

	for _, row := range rows {
		seg, ok := segmentsByIndex[row.segmentIndex]
		if !ok {
			seg = &segmentAssignmentBody{SegmentIndex: row.segmentIndex, SegmentID: row.segmentID}
			segmentsByIndex[row.segmentIndex] = seg
			order = append(order, row.segmentIndex)
		}
		token := generateCapabilityToken(h.signingKey, row.chunkID, row.providerID, now)
		seg.Providers = append(seg.Providers, ShardAssignmentBody{
			ShardIndex:      row.shardIndex,
			ProviderID:      row.providerID,
			Multiaddrs:      row.multiaddrs,
			ASN:             row.asn,
			CapabilityToken: hex.EncodeToString(token[:]),
			ChunkID:         hex.EncodeToString(row.chunkID[:]),
		})
	}

	segments := make([]segmentAssignmentBody, 0, len(order))
	for _, idx := range order {
		segments = append(segments, *segmentsByIndex[idx])
	}

	resp := uploadAssignResponseBody{Assignments: segments, MonthlyCostPaise: monthlyCost, RequiredEscrowPaise: monthlyCost}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ── 503 error responses ─────────────────────────────────────────────────

// networkNotReadyErrorBody extends the standard error envelope with
// readiness_url — present in OAS's own NetworkNotReady example but not
// declared on the formal Error/allOf schema (schema vs. example mismatch;
// see this file's header). Built inline here rather than by extending the
// shared WriteError/errorBody used by every other handler in this package,
// to avoid rippling a rarely-needed field through every existing call site.
type networkNotReadyErrorBody struct {
	ErrorCode    ErrorCode `json:"error_code"`
	Message      string    `json:"message"`
	RequestID    string    `json:"request_id"`
	RetryAfter   int       `json:"retry_after"`
	ReadinessURL string    `json:"readiness_url"`
}

const networkNotReadyRetryAfterSeconds = 60

func writeNetworkNotReadyError(w http.ResponseWriter) {
	requestID, err := uuid.NewV7()
	requestIDStr := uuid.Nil.String()
	if err == nil {
		requestIDStr = requestID.String()
	}
	body := networkNotReadyErrorBody{
		ErrorCode:    ErrNetworkNotReady,
		Message:      "Upload rejected: network readiness conditions are not yet satisfied.",
		RequestID:    requestIDStr,
		RetryAfter:   networkNotReadyRetryAfterSeconds,
		ReadinessURL: "/api/v1/admin/readiness",
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", requestIDStr)
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(body)
}

const insufficientASNDiversityRetryAfterSeconds = 300

func writeInsufficientASNDiversityError(w http.ResponseWriter, totalShards, availableASNs int) {
	retryAfter := insufficientASNDiversityRetryAfterSeconds
	asns := availableASNs
	WriteError(w, http.StatusServiceUnavailable, ErrInsufficientASNDiversity,
		fmt.Sprintf("Cannot place %d shards while respecting the per-ASN cap. Current distinct ASNs: %d.", totalShards, availableASNs),
		&retryAfter, "", &asns)
}

// ── Per-provider chunk storage ceiling (NFR-044, build.md Phase 11.11) ──
//
// [Flagged and corrected — the given formula doesn't reproduce its own
// reference points] The originally-given task computed
// storage_advisory_gb = ceil(mttf_days ÷ 300 × 130). At mttf_days=300 this
// correctly gives 130 GB, but at mttf_days=180 it gives ceil(0.6*130) =
// 78 GB — not architecture.md §27.3's documented ~70 GB. The MTTF-to-
// storage-ceiling relationship is not linear (Giroire's formula scales
// BWavg with D/N in a way that doesn't reduce to simple proportionality in
// MTTF alone — ADR-004), so a straight-line formula between the two points
// silently produces a wrong number at one of its own two anchors.
// storageCeilingForMTTFDays below is a LOOKUP against the two documented
// reference points instead.
//
// [Flagged — no per-provider MTTF field exists anywhere in this schema]
// NFR-044's own text describes this ceiling as "derived from... the
// provider's declared MTTF tier" — but neither providers (migrations/
// 001_initial_schema.sql), ProviderRegisterRequest (OAS), nor
// config.NetworkProfile has any MTTF-related field, and no provider ever
// declares one at registration (checked all three directly). ADR-010
// confirms V2 is desktop-only, and architecture.md §27.3 itself labels 180
// days as "desktop minimum" / the V2 worst case — so the single ceiling
// actually enforceable today, for every V2 provider uniformly, is the
// 180-day/~70GB tier (activeChunkStorageCeilingGB). storageCeilingForMTTFDays
// itself still supports and is independently correct at both documented
// anchors (180d -> ~70GB, 300d -> ~130GB) — only "which MTTF tier applies to
// a given provider" is the flagged gap, not the lookup table itself. The
// 300-day/~130GB tier remains available for when a genuine per-provider
// MTTF declaration mechanism exists — a schema/OAS addition outside this
// session's file list.

const (
	// mttfTier180Days / mttfTier300Days / storageCeiling180DaysGB /
	// storageCeiling300DaysGB are architecture.md §27.3's two documented
	// reference points for the per-provider chunk storage ceiling.
	mttfTier180Days         = 180 // desktop minimum / worst case for V2 (ADR-010)
	mttfTier300Days         = 300 // planning target
	storageCeiling180DaysGB = 70
	storageCeiling300DaysGB = 130

	// nearCeilingThresholdFraction: no ADR/FR/OAS text defines what "near"
	// means for providers_near_ceiling_count (readiness.go) — 90% is an
	// engineering choice, not a documented requirement, flagged here rather
	// than left unimplemented.
	nearCeilingThresholdFraction = 0.90

	insufficientProviderCapacityRetryAfterSeconds = 3600
)

// Remove calculation from the hot path
const (
	mttfMidpointDays = (mttfTier180Days + mttfTier300Days) / 2
)

// storageCeilingForMTTFDays is architecture.md §27.3's two-point storage
// ceiling table as a LOOKUP, not a formula (see this section's header
// note). Values between the two documented anchors snap to the nearer one;
// values outside [180, 300] clamp to the nearest anchor.
func storageCeilingForMTTFDays(mttfDays int) int {
	switch {
	case mttfDays <= mttfTier180Days:
		return storageCeiling180DaysGB
	case mttfDays >= mttfTier300Days:
		return storageCeiling300DaysGB
	default:
		if mttfDays < mttfMidpointDays {
			return storageCeiling180DaysGB
		}
		return storageCeiling300DaysGB
	}
}

// activeChunkStorageCeilingGB returns the per-provider chunk storage
// ceiling actually enforced today — see this section's header note on why
// every V2 provider uniformly uses the 180-day tier absent a per-provider
// MTTF declaration mechanism.
func activeChunkStorageCeilingGB() int {
	return storageCeilingForMTTFDays(mttfTier180Days)
}

// chunkCeilingMaxChunks converts activeChunkStorageCeilingGB into a real
// (non-vetting) chunk_assignments count for profile's ShardSize (a
// compile-time constant, not profile-variable — migrations/README.md).
// Uses owner.go's existing bytesPerGB (2^30) — the same GB convention this
// package already uses for storage cost math — rather than introducing a
// second, conflicting "bytes per GB" constant for the same unit.
func chunkCeilingMaxChunks(profile config.NetworkProfile) int64 {
	ceilingBytes := int64(activeChunkStorageCeilingGB()) * bytesPerGB
	return ceilingBytes / int64(profile.ShardSize)
}

// providersAtOrOverChunkCount returns every provider currently holding at
// least maxChunks real (non-vetting), ACTIVE-or-REPAIRING chunk
// assignments — candidates to exclude from new shard assignment (NFR-044).
// maxChunks is an explicit parameter (rather than this function reading
// activeChunkStorageCeilingGB itself) purely so tests can exercise it
// against a small, practical count instead of architecture.md's real
// ~267,000-chunk (70 GB) threshold; HandleAssign always calls this with
// chunkCeilingMaxChunks(h.profile), the real value.
func providersAtOrOverChunkCount(ctx context.Context, db *sql.DB, maxChunks int64) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT provider_id
		FROM chunk_assignments
		WHERE is_vetting_chunk = FALSE AND status IN ('ACTIVE', 'REPAIRING')
		GROUP BY provider_id
		HAVING COUNT(*) >= $1`, maxChunks)
	if err != nil {
		return nil, fmt.Errorf("api: providersAtOrOverChunkCount: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("providersAtOrOverChunkCount: close rows", "error", err)
		}
	}()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("api: providersAtOrOverChunkCount: scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// eligibleActiveProviderCountAtOrUnder returns the count of ACTIVE
// providers NOT currently at/over maxChunks real chunk assignments — the
// pool repair.SelectReplacementProvider draws real shard candidates from
// once the ceiling exclusion (providersAtOrOverChunkCount) is applied.
func eligibleActiveProviderCountAtOrUnder(ctx context.Context, db *sql.DB, maxChunks int64) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM providers p
		WHERE p.status = 'ACTIVE'
		  AND p.provider_id NOT IN (
		      SELECT ca.provider_id FROM chunk_assignments ca
		      WHERE ca.is_vetting_chunk = FALSE AND ca.status IN ('ACTIVE', 'REPAIRING')
		      GROUP BY ca.provider_id
		      HAVING COUNT(*) >= $1
		  )`, maxChunks).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("api: eligibleActiveProviderCountAtOrUnder: %w", err)
	}
	return count, nil
}

// providersNearChunkCeilingCount returns the count of providers at or above
// nearCeilingThresholdFraction of maxChunks — an informational
// (non-gating) gauge surfaced on the readiness response (readiness.go).
func providersNearChunkCeilingCount(ctx context.Context, db *sql.DB, maxChunks int64) (int, error) {
	nearThreshold := int64(float64(maxChunks) * nearCeilingThresholdFraction)
	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT provider_id FROM chunk_assignments
			WHERE is_vetting_chunk = FALSE AND status IN ('ACTIVE', 'REPAIRING')
			GROUP BY provider_id
			HAVING COUNT(*) >= $1
		) near`, nearThreshold).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("api: providersNearChunkCeilingCount: %w", err)
	}
	return count, nil
}

// writeInsufficientProviderCapacityError writes the 503
// INSUFFICIENT_PROVIDER_CAPACITY response — Session 11.1.1's
// ErrInsufficientProviderCapacity, flagged there for an openapi.yaml
// addition (still outstanding; this endpoint's own request/response
// schema has no formal 503 entry for it either).
func writeInsufficientProviderCapacityError(w http.ResponseWriter) {
	retryAfter := insufficientProviderCapacityRetryAfterSeconds
	WriteError(w, http.StatusServiceUnavailable, ErrInsufficientProviderCapacity,
		"insufficient eligible provider capacity after applying the per-provider chunk storage ceiling (NFR-044)",
		&retryAfter, "", nil)
}

// enforceProviderCapacity applies NFR-044's per-provider chunk storage
// ceiling before shard assignment: it computes which ACTIVE providers are
// currently at/over maxChunks (to exclude from every segment's candidate
// pool below) and the resulting eligible pool size. If the eligible pool
// drops below minActiveProviders, it writes the 503 response itself and
// returns ok=false — the caller must stop processing the request without
// generating any assignments or touching the database further.
// maxChunks/minActiveProviders are explicit parameters (rather than this
// function reading h.profile directly) purely so tests can exercise the
// 503 path against a small, practical chunk count instead of
// architecture.md's real ~267,000-chunk (70 GB) threshold — HandleAssign
// always calls this with the real, profile-derived values.
func enforceProviderCapacity(ctx context.Context, w http.ResponseWriter, db *sql.DB, maxChunks int64, minActiveProviders int) (overCeiling []uuid.UUID, ok bool) {
	overCeiling, err := providersAtOrOverChunkCount(ctx, db, maxChunks)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider capacity check failed", nil, "", nil)
		return nil, false
	}
	eligible, err := eligibleActiveProviderCountAtOrUnder(ctx, db, maxChunks)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider capacity check failed", nil, "", nil)
		return nil, false
	}
	if eligible < minActiveProviders {
		writeInsufficientProviderCapacityError(w)
		return nil, false
	}
	return overCeiling, true
}
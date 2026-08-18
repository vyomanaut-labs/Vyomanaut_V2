// Package api is declared in doc.go.
// This file implements the data owner retrieval resolve endpoint
// (ADR-080 §2): POST /api/v1/owner/files/{file_id}/retrieve/resolve.
//
// WHY THIS FILE EXISTS. Until ADR-080, IC §4 had no data-owner read path
// at all — every shard read was microservice-initiated (§4.4.1 repair
// download authenticates the caller AS a microservice replica and rejects
// everyone else with 0x02 NOT_AUTHORISED). internal/client/retrieve was
// built at M15 against a PROPOSED, never-ratified endpoint that did not
// exist, so RetrieveFile had never once succeeded live. See ADR-080's
// Context for the full account.
//
// AUTHORIZATION MODEL (ADR-080 §1). This endpoint mints DOWNLOAD
// capability tokens that are structurally identical to IC §4.1's upload
// capability_token — same 72-byte layout, same Ed25519 signing key, same
// verification path shape on the daemon — but with a DISTINCT
// domain-separation prefix, so a token minted for one direction can never
// be replayed as the other. The provider verifies with the msPublicKey it
// already holds: no new key material, no new trust root.
//
// DISCLOSURE (ADR-080 §2). Returning provider multiaddrs to an
// authenticated owner is not a new disclosure category: POST
// /api/v1/upload/assign already returns exactly this field, from exactly
// this column (providers.last_known_multiaddrs), to exactly this audience.
// This endpoint is its symmetric read-side counterpart.
//
// REVOCATION. By non-issuance: the ACTIVE-status check below is what makes
// `rm` enforceable on the read path. Once a file leaves ACTIVE, no further
// tokens are minted for its chunks and outstanding ones expire on their
// own short clock. A bare-chunk_id protocol (the rejected M15 proposal)
// could not have done this — see ADR-080's "rejected alternative".
//
// [REF: ADR-080, IC §4.1 (the token model mirrored here), IC §4.4.1,
// ADR-036, ADR-073, FR-016, IC §5.9 RetrieveFile]

package api

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	localcrypto "github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
)

// ── Download capability token (ADR-080 §1) ──────────────────────────────

const (
	// downloadCapabilityTokenDomainPrefix is deliberately NOT
	// capabilityTokenDomainPrefix (IC §4.1's upload prefix). Domain
	// separation is the whole point: an upload token must never verify as
	// a download token, in either direction. Changing either string
	// without changing both sides' verifier is a wire break.
	downloadCapabilityTokenDomainPrefix = "vyomanaut-chunk-download-cap-v1"

	// downloadCapabilityTokenLifetime is short by design — revocation for
	// this protocol is "the microservice stops issuing", so the expiry IS
	// the revocation latency (ADR-080's Revocation note). Deliberately
	// shorter than IC §4.1's 1-hour upload lifetime: an upload holds a
	// stream open for one large write, whereas a retrieval resolves once
	// and then fans out reads that should all start promptly.
	//
	// [UNDERIVED — Q-ADR80-2, ADR-077 governance] This value is not
	// derived from any measured retrieval duration; it is a defensible
	// starting point, not a justified constant, and belongs in
	// NetworkProfile (demo/prod split) once a real figure exists.
	downloadCapabilityTokenLifetime = 15 * time.Minute

	// downloadCapabilityTokenByteLen matches IC §4.1's 72-byte layout
	// exactly: expiry_unix_ms(8) || Ed25519 signature(64).
	downloadCapabilityTokenByteLen = 72
)

// generateDownloadCapabilityToken mirrors generateCapabilityToken
// (internal/api/upload.go) field-for-field, differing ONLY in the domain
// prefix and lifetime:
//
//	signing_input    = domain_prefix || chunk_id || provider_id || expiry_unix_ms
//	download_token   = expiry_unix_ms (8B) || Ed25519_sign(ms_signing_key, signing_input)
//
// Every signed field is transmitted on the wire in Frame 1 (ADR-080 §1).
// That is not incidental: IC §4.4.1 shipped a signing formula over
// request_ts_ms, a field its own Frame 1 did not carry, so the responder
// could not verify it — the REPAIR-AUTH-TS-GAP finding, corrected in
// cmd/provider/handler_repair.go by extending that frame to 104 bytes.
// This protocol does not repeat that.
//
// localcrypto.SignBytes performs the SHA-256-then-Ed25519 composition
// internally (IC §3.2 SIGNING_INPUT_RULE), so the raw pre-hash
// concatenation is passed directly — exactly as upload.go does.
func generateDownloadCapabilityToken(msSigningKey ed25519.PrivateKey, chunkID [32]byte, providerID uuid.UUID, issuedAt time.Time) [downloadCapabilityTokenByteLen]byte {
	expiryUnixMs := issuedAt.Add(downloadCapabilityTokenLifetime).UnixMilli()
	var expiryBytes [8]byte
	binary.BigEndian.PutUint64(expiryBytes[:], uint64(expiryUnixMs))

	input := make([]byte, 0, len(downloadCapabilityTokenDomainPrefix)+sha256Size+len(providerID)+uint64Size)
	input = append(input, []byte(downloadCapabilityTokenDomainPrefix)...)
	input = append(input, chunkID[:]...)
	input = append(input, providerID[:]...)
	input = append(input, expiryBytes[:]...)

	sig := localcrypto.SignBytes(msSigningKey, input)

	var token [downloadCapabilityTokenByteLen]byte
	copy(token[0:8], expiryBytes[:])
	copy(token[8:downloadCapabilityTokenByteLen], sig[:])
	return token
}

// ── Response bodies ─────────────────────────────────────────────────────

// RetrieveShardBody is one shard's resolution: where to dial, and the
// token authorizing that specific read.
type RetrieveShardBody struct {
	ShardIndex     int       `json:"shard_index"`
	ProviderID     uuid.UUID `json:"provider_id"`
	ChunkID        string    `json:"chunk_id"`
	Multiaddrs     []string  `json:"multiaddrs"`
	MultiaddrStale bool      `json:"multiaddr_stale"`
	DownloadToken  string    `json:"download_token"`
}

// RetrieveSegmentBody is one segment's full shard set.
type RetrieveSegmentBody struct {
	SegmentIndex int                 `json:"segment_index"`
	SegmentID    uuid.UUID           `json:"segment_id"`
	Shards       []RetrieveShardBody `json:"shards"`
}

// RetrieveResolveResponseBody carries EVERY segment of the file in one
// response (ADR-080 §2's batching requirement). Per-segment resolution
// would cost ~1,365 serial REST round-trips for a 1 GB file at prod
// parameters before a single byte of shard data moved.
type RetrieveResolveResponseBody struct {
	FileID   uuid.UUID             `json:"file_id"`
	Segments []RetrieveSegmentBody `json:"segments"`
}

// ── Handler ─────────────────────────────────────────────────────────────

// RetrieveResolveHandler serves POST
// /api/v1/owner/files/{file_id}/retrieve/resolve.
type RetrieveResolveHandler struct {
	db         *sql.DB
	signingKey ed25519.PrivateKey
}

// NewRetrieveResolveHandler constructs the handler. signingKey is the
// microservice signing key — the same one generateCapabilityToken uses
// for upload tokens, and the same one whose public half every provider
// daemon already holds as msPublicKey.
func NewRetrieveResolveHandler(db *sql.DB, signingKey ed25519.PrivateKey) *RetrieveResolveHandler {
	return &RetrieveResolveHandler{db: db, signingKey: signingKey}
}

// HandleResolve authorizes the caller as the file's owner, confirms the
// file is retrievable, and returns every shard's dial address plus a
// download capability token.
func (h *RetrieveResolveHandler) HandleResolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims, ok := ClaimsFromContext(ctx)
	if !ok || claims.Role != "owner" {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "missing or wrong-role token", nil, "", nil)
		return
	}
	fileID, err := uuid.Parse(r.PathValue("file_id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "file_id must be a UUID", nil, "file_id", nil)
		return
	}

	// Ownership AND status in one query. Both are load-bearing: ownership
	// is the authorization gate, and the ACTIVE check is what makes `rm`
	// enforceable on the read path (ADR-080's Revocation note) — a
	// deleted file stops yielding tokens immediately.
	var ownerID uuid.UUID
	var status string
	err = h.db.QueryRowContext(ctx,
		`SELECT owner_id, status FROM files WHERE file_id = $1`, fileID).Scan(&ownerID, &status)
	if err == sql.ErrNoRows {
		WriteError(w, http.StatusNotFound, ErrNotFound, "file not found", nil, "file_id", nil)
		return
	}
	if err != nil {
		slog.Error("retrieve resolve: file lookup", "error", err, "file_id", fileID)
		WriteError(w, http.StatusInternalServerError, ErrInternal, "file lookup failed", nil, "", nil)
		return
	}
	if ownerID != claims.Subject {
		// Deliberately NOT_FOUND-shaped rather than a distinct "not
		// yours" code: a non-owner must not be able to probe which
		// file_ids exist. Same reasoning as ADR-080 §4's status-code
		// treatment on the wire protocol.
		WriteError(w, http.StatusNotFound, ErrNotFound, "file not found", nil, "file_id", nil)
		return
	}
	if status != "ACTIVE" {
		WriteError(w, http.StatusConflict, ErrInvalidRequest,
			fmt.Sprintf("file is not retrievable in status %s", status), nil, "file_id", nil)
		return
	}

	rows, err := h.loadShardsForRetrieval(ctx, fileID)
	if err != nil {
		slog.Error("retrieve resolve: load shards", "error", err, "file_id", fileID)
		WriteError(w, http.StatusInternalServerError, ErrInternal, "shard lookup failed", nil, "", nil)
		return
	}
	if len(rows) == 0 {
		WriteError(w, http.StatusNotFound, ErrNotFound, "file has no shard assignments", nil, "file_id", nil)
		return
	}

	// Success responses in this package are written with json.NewEncoder
	// directly (owner.go, upload.go) — there is no WriteJSON helper; only
	// the error path is centralised, in WriteError.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(h.buildResolveResponse(fileID, rows, time.Now()))
}

// retrievalShardRow is one chunk_assignments row joined with its
// provider's current dial information. A deliberate near-twin of
// upload.go's existingShardRow — multiaddrs are always re-read fresh
// rather than cached from assignment time, since a provider's addresses
// change between upload and retrieval.
type retrievalShardRow struct {
	segmentIndex   int
	segmentID      uuid.UUID
	shardIndex     int
	providerID     uuid.UUID
	chunkID        [32]byte
	multiaddrs     []string
	multiaddrStale bool
}

// loadShardsForRetrieval returns every real (non-vetting) shard
// assignment for fileID's segments, ordered by segment then shard.
//
// is_vetting_chunk = FALSE mirrors loadExistingAssignments exactly:
// synthetic vetting chunks are never part of a real file and must never
// be resolvable by an owner.
//
// Deleted assignments are excluded — a shard already marked for deletion
// must not yield a fresh token, for the same revocation reason the ACTIVE
// file check exists.
func (h *RetrieveResolveHandler) loadShardsForRetrieval(ctx context.Context, fileID uuid.UUID) ([]retrievalShardRow, error) {
	rows, err := h.db.QueryContext(ctx, `
		SELECT s.segment_index, s.segment_id, ca.shard_index, ca.provider_id, ca.chunk_id,
		       p.last_known_multiaddrs, p.multiaddr_stale
		FROM segments s
		JOIN chunk_assignments ca ON ca.segment_id = s.segment_id AND ca.is_vetting_chunk = FALSE
		JOIN providers p ON p.provider_id = ca.provider_id
		WHERE s.file_id = $1
		  AND ca.status NOT IN ('DELETED', 'PENDING_DELETION')
		ORDER BY s.segment_index, ca.shard_index`, fileID)
	if err != nil {
		return nil, fmt.Errorf("api: loadShardsForRetrieval: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("loadShardsForRetrieval: close rows", "error", err)
		}
	}()

	var out []retrievalShardRow
	for rows.Next() {
		var row retrievalShardRow
		var chunkIDRaw, multiaddrsJSON []byte
		if err := rows.Scan(&row.segmentIndex, &row.segmentID, &row.shardIndex, &row.providerID,
			&chunkIDRaw, &multiaddrsJSON, &row.multiaddrStale); err != nil {
			return nil, fmt.Errorf("api: loadShardsForRetrieval: scan: %w", err)
		}
		copy(row.chunkID[:], chunkIDRaw)
		_ = json.Unmarshal(multiaddrsJSON, &row.multiaddrs)
		out = append(out, row)
	}
	return out, rows.Err()
}

// buildResolveResponse groups rows into segments and mints one download
// token per shard. Factored out of HandleResolve so it is directly
// testable without a live database.
func (h *RetrieveResolveHandler) buildResolveResponse(fileID uuid.UUID, rows []retrievalShardRow, now time.Time) RetrieveResolveResponseBody {
	segmentsByIndex := make(map[int]*RetrieveSegmentBody)
	var order []int

	for _, row := range rows {
		seg, ok := segmentsByIndex[row.segmentIndex]
		if !ok {
			seg = &RetrieveSegmentBody{SegmentIndex: row.segmentIndex, SegmentID: row.segmentID}
			segmentsByIndex[row.segmentIndex] = seg
			order = append(order, row.segmentIndex)
		}
		token := generateDownloadCapabilityToken(h.signingKey, row.chunkID, row.providerID, now)
		seg.Shards = append(seg.Shards, RetrieveShardBody{
			ShardIndex:     row.shardIndex,
			ProviderID:     row.providerID,
			ChunkID:        hex.EncodeToString(row.chunkID[:]),
			Multiaddrs:     row.multiaddrs,
			MultiaddrStale: row.multiaddrStale,
			DownloadToken:  hex.EncodeToString(token[:]),
		})
	}

	segments := make([]RetrieveSegmentBody, 0, len(order))
	for _, idx := range order {
		segments = append(segments, *segmentsByIndex[idx])
	}
	return RetrieveResolveResponseBody{FileID: fileID, Segments: segments}
}

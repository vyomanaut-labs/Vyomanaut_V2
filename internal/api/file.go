// Package api is declared in doc.go.
// This file implements build.md Milestone 11 Phase 11.7 Sessions 11.7.2
// (POST /api/v1/file/register), 11.7.3 (GET /api/v1/file/{file_id}/pointer),
// and 11.7.4 (DELETE /api/v1/file/{file_id}).
//
// [Decision — "already registered" signal] files.status only has
// ACTIVE/DELETION_PENDING/DELETED (no fourth "assigned but not yet
// registered" value), and upload.go's HandleAssign already inserts the
// files row with status defaulting to ACTIVE before registration ever runs
// (required so segments.file_id's FK can be satisfied — see upload.go's
// header). So `status == 'ACTIVE'` alone cannot distinguish "freshly
// assigned, never registered" from "genuinely already registered" — the
// exact case Session 11.7.2's 409 needs to detect. pointer_ciphertext is
// the one NOT NULL files column with no fixed-length CHECK constraint
// (unlike pointer_nonce/pointer_tag, which are exactly 12/16 bytes even as
// placeholders), so its emptiness is used as the "not yet registered"
// signal: HandleAssign leaves it as a zero-length bytea; HandleRegister's
// 409 check is octet_length(pointer_ciphertext) > 0 AND status = 'ACTIVE'.
//
// [Corrected, F-16-1] owner_sig verification. This file's original
// (Session 11.7.2) approach followed what its own comment called
// "owner.go's OWN established convention" — a hand-built canonical-JSON-
// shaped byte string, verified via a bare ed25519.Verify call, deliberately
// distinct from provider.go's crypto.SignBytes/VerifyBytes hash-then-sign
// convention. That convention is incompatible with internal/crypto's own
// package doc, which states as a CRITICAL rule: "JSON serialisation MUST
// NOT be used for signing inputs — field ordering is not guaranteed across
// Go versions. All signing inputs must be constructed as a fixed-layout
// byte sequence." internal/client/upload/pointer.go's own header comment
// documents that its client-side signing was already corrected to a
// fixed-layout scheme per finding A-6 ("critical fix to the OAS's stale
// 'canonical JSON, keys sorted' description") — this file was never
// updated to match, so every real /api/v1/file/register call failed
// owner_sig verification deterministically, for every upload, until this
// fix. See ownerSigSigningInput's own doc comment for the corrected
// byte-layout, which now matches pointer.go's computeOwnerSig exactly and
// verifies via localcrypto.VerifyBytes, IC §3.2's actual composition.
// Caught by build.md Session 16.1.1's live end-to-end run, the same class
// of gap as F-070-13/ADR-073 — a client/server contract drift invisible to
// either side's own unit tests, since neither exercises the other's code.
//
// [Decision — file-delete "provider notification"] OAS's deleteFile
// description implies a live, synchronous P2P notification attempt at
// delete time ("providers_notified: Providers successfully notified AT THE
// TIME OF THE CALL"). No P2P dial/notify hook is available at this REST
// layer (internal/p2p exposes no exported "send a message to a provider"
// primitive, only low-level transport). Reachability is approximated by
// last_heartbeat_ts recency (within profile.HeartbeatInterval +
// profile.HeartbeatJitter — i.e. "still checking in on schedule"), matching
// FR-020's own actual enforcement mechanism: the provider daemon picks up
// PENDING_DELETION assignments on its own next heartbeat/startup check, not
// through a push notification this handler would send. A provider counted
// as "notified" here has not literally been contacted; it is one whose next
// heartbeat is expected imminently, which is the real delivery mechanism
// FR-020 describes.
//
// [REF: OAS paths./api/v1/file/register, /api/v1/file/{file_id}/pointer,
// /api/v1/file/{file_id}, components/schemas/FileRegisterRequest/Response,
// PointerFileResponse, FR-019, FR-020, ADR-020, ADR-022, NFR-014,
// build.md Phase 11.7 Sessions 11.7.2-11.7.4]

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	localcrypto "github.com/masamasaowl/Vyomanaut_V2/internal/crypto"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
)

// Named constants for crypto
const (
	aesGCMNonceSize = 12
	aesGCMTagSize   = 16
)

// ── Session 11.7.2 — File Register ──────────────────────────────────────

type fileRegisterRequestBody struct {
	FileID                uuid.UUID `json:"file_id"`
	PointerCiphertext     string    `json:"pointer_ciphertext"` // base64
	PointerNonce          string    `json:"pointer_nonce"`      // base64, 12 bytes
	PointerTag            string    `json:"pointer_tag"`        // base64, 16 bytes
	OriginalSizeBytes     int64     `json:"original_size_bytes"`
	DisplayNameCiphertext *string   `json:"display_name_ciphertext"` // base64, optional
	DisplayNameNonce      *string   `json:"display_name_nonce"`      // base64, optional, 12 bytes
	DisplayNameTag        *string   `json:"display_name_tag"`        // base64, optional, 16 bytes
	SchemaVersion         int       `json:"schema_version"`
	OwnerSig              string    `json:"owner_sig"` // hex, Ed25519Signature
}

type fileRegisterResponseBody struct {
	FileID     uuid.UUID `json:"file_id"`
	UploadedAt time.Time `json:"uploaded_at"`
}

// ownerSigDomainPrefix must match internal/client/upload/pointer.go's own
// constant of the same name exactly — internal/api cannot import a
// internal/client package (layering), so this is a deliberate, minimal
// duplication of one string literal, not a design split.
const ownerSigDomainPrefix = "vyomanaut-file-register-v1"

// ownerSigSigningInput builds the exact fixed-layout byte sequence
// internal/client/upload/pointer.go's computeOwnerSig signs (A-6), for use
// with localcrypto.VerifyBytes — which itself SHA-256s this input before
// the Ed25519 check, per IC §3.2's hash-then-sign composition.
//
// [Fixed — corrects a stale, never-updated verification scheme] This
// function replaces canonicalFileRegisterSigningInput, which built a
// JSON-shaped canonical object (alphabetical keys, quoted string values)
// and verified it via a bare ed25519.Verify call. internal/crypto's own
// package doc states, as a CRITICAL rule: "JSON serialisation MUST NOT be
// used for signing inputs — field ordering is not guaranteed across Go
// versions. All signing inputs must be constructed as a fixed-layout byte
// sequence." pointer.go's own header comment documents exactly this fix
// having already been applied client-side ("fixed-layout, NOT canonical
// JSON — A-6, critical fix to the OAS's stale 'canonical JSON, keys
// sorted' description") — this file (Session 11.7.2) predates that
// correction and was never brought in line with it, so every real
// owner_sig verification failed deterministically until now: not a
// single-request edge case, every /api/v1/file/register call, for every
// upload, on every provider network. Caught by build.md Session 16.1.1's
// live end-to-end run, the same way F-070-13/ADR-073 was.
//
// The two required inputs the client computes but this handler must
// reproduce from wire values: pointerCiphertextHash is SHA-256 of the raw
// (base64-decoded) pointer ciphertext, never the base64 string itself;
// displayNameBlockHash is SHA-256 of raw displayNameCiphertext ||
// displayNameNonce || displayNameTag concatenated — and critically,
// displayNameNonce must be a full 12 zero bytes (not an empty/nil slice)
// when the display name is absent, matching ownerSigInput.DisplayNameNonce's
// Go zero value ([12]byte{}) on the client side. A nil slice here would
// silently hash to a different, wrong value.
func ownerSigSigningInput(fileID uuid.UUID, pointerCiphertext, pointerNonce, pointerTag []byte, originalSizeBytes int64, displayNamePresent bool, displayNameCiphertext, displayNameNonce, displayNameTag []byte, schemaVersion int) []byte {
	dnNonce := displayNameNonce
	if len(dnNonce) == 0 {
		dnNonce = make([]byte, aesGCMNonceSize)
	}
	displayNameBlock := concatFileRegisterBytes(displayNameCiphertext, dnNonce, displayNameTag)
	displayNameBlockHash := sha256.Sum256(displayNameBlock)
	pointerCiphertextHash := sha256.Sum256(pointerCiphertext)

	var displayNamePresentByte [1]byte
	if displayNamePresent {
		displayNamePresentByte[0] = 1
	}
	var originalSizeBytesArr [8]byte
	binary.BigEndian.PutUint64(originalSizeBytesArr[:], uint64(originalSizeBytes))
	var schemaVersionBytes [4]byte
	binary.BigEndian.PutUint32(schemaVersionBytes[:], uint32(schemaVersion))

	return concatFileRegisterBytes(
		[]byte(ownerSigDomainPrefix),
		fileID[:],
		pointerCiphertextHash[:],
		pointerNonce,
		pointerTag,
		originalSizeBytesArr[:],
		displayNamePresentByte[:],
		displayNameBlockHash[:],
		schemaVersionBytes[:],
	)
}

// concatFileRegisterBytes is this file's own copy of the same trivial
// concatenation helper pointer.go defines locally (concatBytes) — internal/api
// cannot import internal/client/upload (layering), and the helper is too
// small to be worth promoting to a shared package for one caller on each side.
func concatFileRegisterBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// FileRegisterHandler serves POST /api/v1/file/register.
type FileRegisterHandler struct {
	db *sql.DB
}

func NewFileRegisterHandler(db *sql.DB) *FileRegisterHandler {
	return &FileRegisterHandler{db: db}
}

func (h *FileRegisterHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}

	var req fileRegisterRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	if req.SchemaVersion != 1 {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "schema_version must be 1", nil, "schema_version", nil)
		return
	}

	pointerCiphertext, ok := decodeBase64Field(w, "pointer_ciphertext", req.PointerCiphertext, -1)
	if !ok {
		return
	}
	pointerNonce, ok := decodeBase64Field(w, "pointer_nonce", req.PointerNonce, aesGCMNonceSize)
	if !ok {
		return
	}
	pointerTag, ok := decodeBase64Field(w, "pointer_tag", req.PointerTag, aesGCMTagSize)
	if !ok {
		return
	}
	var displayNameCiphertext, displayNameNonce, displayNameTag []byte
	if req.DisplayNameCiphertext != nil {
		displayNameCiphertext, ok = decodeBase64Field(w, "display_name_ciphertext", *req.DisplayNameCiphertext, -1)
		if !ok {
			return
		}
	}
	if req.DisplayNameNonce != nil {
		displayNameNonce, ok = decodeBase64Field(w, "display_name_nonce", *req.DisplayNameNonce, aesGCMNonceSize)
		if !ok {
			return
		}
	}
	if req.DisplayNameTag != nil {
		displayNameTag, ok = decodeBase64Field(w, "display_name_tag", *req.DisplayNameTag, aesGCMTagSize)
		if !ok {
			return
		}
	}

	var ownerID uuid.UUID
	var pointerCiphertextLen int
	var status string
	err := h.db.QueryRowContext(ctx,
		`SELECT owner_id, octet_length(pointer_ciphertext), status FROM files WHERE file_id = $1`, req.FileID,
	).Scan(&ownerID, &pointerCiphertextLen, &status)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusNotFound, ErrNotFound, "file_id was not created by a prior upload/assign call", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "file lookup failed", nil, "", nil)
		return
	}
	if ownerID != claims.Subject {
		WriteError(w, http.StatusForbidden, ErrUnauthorized, "file_id does not belong to this owner", nil, "", nil)
		return
	}
	// See file header: emptiness of pointer_ciphertext is the "not yet
	// registered" signal, since files.status is already ACTIVE from the
	// moment upload/assign created the row.
	if pointerCiphertextLen > 0 && status == "ACTIVE" {
		WriteError(w, http.StatusConflict, ErrFileAlreadyRegistered, "a pointer file is already registered for this file_id", nil, "", nil)
		return
	}

	var ownerPubKeyRaw []byte
	if err := h.db.QueryRowContext(ctx, `SELECT ed25519_public_key FROM owners WHERE owner_id = $1`, ownerID).Scan(&ownerPubKeyRaw); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "owner lookup failed", nil, "", nil)
		return
	}
	if len(ownerPubKeyRaw) != ed25519.PublicKeySize {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "stored owner public key has the wrong length", nil, "", nil)
		return
	}
	var ownerPubKey [32]byte
	copy(ownerPubKey[:], ownerPubKeyRaw)
	// decodeProviderSig (provider.go) is a generic 128-hex-char -> 64-byte
	// decoder despite its name; reused here for owner_sig rather than
	// duplicating the same decode+length-check logic.
	sigArr, ok := decodeProviderSig(req.OwnerSig)
	if !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "owner_sig must be 128 lowercase hex characters", nil, "owner_sig", nil)
		return
	}
	signingInput := ownerSigSigningInput(
		req.FileID, pointerCiphertext, pointerNonce, pointerTag, req.OriginalSizeBytes,
		req.DisplayNameCiphertext != nil, displayNameCiphertext, displayNameNonce, displayNameTag,
		req.SchemaVersion,
	)
	if !localcrypto.VerifyBytes(ownerPubKey, signingInput, sigArr) {
		WriteError(w, http.StatusUnauthorized, ErrInvalidBodySignature, "invalid owner_sig", nil, "", nil)
		return
	}

	var uploadedAt time.Time
	err = h.db.QueryRowContext(ctx, `
		UPDATE files
		SET pointer_ciphertext = $2,
		    pointer_nonce = $3,
		    pointer_tag = $4,
		    original_size_bytes = $5,
		    display_name_ciphertext = $6,
		    display_name_nonce = $7,
		    display_name_tag = $8,
		    schema_version = $9,
		    uploaded_at = NOW()
		WHERE file_id = $1
		RETURNING uploaded_at`,
		req.FileID, pointerCiphertext, pointerNonce, pointerTag, req.OriginalSizeBytes,
		nullableBytes(displayNameCiphertext), nullableBytes(displayNameNonce), nullableBytes(displayNameTag),
		req.SchemaVersion,
	).Scan(&uploadedAt)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to register pointer file", nil, "", nil)
		return
	}

	resp := fileRegisterResponseBody{FileID: req.FileID, UploadedAt: uploadedAt}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// decodeBase64Field decodes a base64 request field, writing a 400 and
// returning ok=false on failure. wantLen < 0 means "any length accepted".
func decodeBase64Field(w http.ResponseWriter, field, value string, wantLen int) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, field+" must be valid base64", nil, field, nil)
		return nil, false
	}
	if wantLen >= 0 && len(raw) != wantLen {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, field+" has the wrong decoded length", nil, field, nil)
		return nil, false
	}
	return raw, true
}

// nullableBytes passes nil through as SQL NULL (database/sql's standard nil
// handling) rather than an empty, non-NULL bytea.
func nullableBytes(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

// ── Session 11.7.3 — Pointer File Retrieval ─────────────────────────────

type pointerFileResponseBody struct {
	FileID                uuid.UUID `json:"file_id"`
	PointerCiphertext     string    `json:"pointer_ciphertext"`
	PointerNonce          string    `json:"pointer_nonce"`
	PointerTag            string    `json:"pointer_tag"`
	SchemaVersion         int       `json:"schema_version"`
	OriginalSizeBytes     int64     `json:"original_size_bytes"`
	DisplayNameCiphertext *string   `json:"display_name_ciphertext,omitempty"`
	DisplayNameNonce      *string   `json:"display_name_nonce,omitempty"`
	DisplayNameTag        *string   `json:"display_name_tag,omitempty"`
}

// PointerFileHandler serves GET /api/v1/file/{file_id}/pointer. The
// microservice never decrypts anything here (ADR-020, NFR-014) — every
// field below is returned exactly as stored, base64 re-encoded from the raw
// bytes on the way out.
type PointerFileHandler struct {
	db *sql.DB
}

func NewPointerFileHandler(db *sql.DB) *PointerFileHandler {
	return &PointerFileHandler{db: db}
}

func (h *PointerFileHandler) HandlePointer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}
	fileID, err := uuid.Parse(r.PathValue("file_id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "file_id must be a UUID", nil, "file_id", nil)
		return
	}

	var ownerID uuid.UUID
	var pointerCiphertext, pointerNonce, pointerTag []byte
	var schemaVersion int
	var originalSizeBytes int64
	var displayNameCiphertext, displayNameNonce, displayNameTag []byte
	err = h.db.QueryRowContext(ctx, `
		SELECT owner_id, pointer_ciphertext, pointer_nonce, pointer_tag, schema_version, original_size_bytes,
		       display_name_ciphertext, display_name_nonce, display_name_tag
		FROM files WHERE file_id = $1`, fileID,
	).Scan(&ownerID, &pointerCiphertext, &pointerNonce, &pointerTag, &schemaVersion, &originalSizeBytes,
		&displayNameCiphertext, &displayNameNonce, &displayNameTag)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusNotFound, ErrNotFound, "file not found", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "file lookup failed", nil, "", nil)
		return
	}
	if ownerID != claims.Subject {
		WriteError(w, http.StatusForbidden, ErrUnauthorized, "file_id does not belong to this owner", nil, "", nil)
		return
	}

	resp := pointerFileResponseBody{
		FileID:            fileID,
		PointerCiphertext: base64.StdEncoding.EncodeToString(pointerCiphertext),
		PointerNonce:      base64.StdEncoding.EncodeToString(pointerNonce),
		PointerTag:        base64.StdEncoding.EncodeToString(pointerTag),
		SchemaVersion:     schemaVersion,
		OriginalSizeBytes: originalSizeBytes,
	}
	if displayNameCiphertext != nil {
		s := base64.StdEncoding.EncodeToString(displayNameCiphertext)
		resp.DisplayNameCiphertext = &s
	}
	if displayNameNonce != nil {
		s := base64.StdEncoding.EncodeToString(displayNameNonce)
		resp.DisplayNameNonce = &s
	}
	if displayNameTag != nil {
		s := base64.StdEncoding.EncodeToString(displayNameTag)
		resp.DisplayNameTag = &s
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ── Session 11.7.4 — File Delete ────────────────────────────────────────

type fileDeleteResponseBody struct {
	FileID            uuid.UUID `json:"file_id"`
	AssignmentsMarked int       `json:"assignments_marked"`
	ProvidersNotified int       `json:"providers_notified"`
	ProvidersPending  int       `json:"providers_pending"`
	Status            string    `json:"status"`
}

// FileDeleteHandler serves DELETE /api/v1/file/{file_id} (FR-020).
type FileDeleteHandler struct {
	db      *sql.DB
	profile config.NetworkProfile
}

func NewFileDeleteHandler(db *sql.DB, profile config.NetworkProfile) *FileDeleteHandler {
	return &FileDeleteHandler{db: db, profile: profile}
}

func (h *FileDeleteHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}
	fileID, err := uuid.Parse(r.PathValue("file_id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "file_id must be a UUID", nil, "file_id", nil)
		return
	}

	var ownerID uuid.UUID
	var status string
	err = h.db.QueryRowContext(ctx, `SELECT owner_id, status FROM files WHERE file_id = $1`, fileID).Scan(&ownerID, &status)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusNotFound, ErrNotFound, "file not found", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "file lookup failed", nil, "", nil)
		return
	}
	if ownerID != claims.Subject {
		WriteError(w, http.StatusForbidden, ErrUnauthorized, "file_id does not belong to this owner", nil, "", nil)
		return
	}
	if status == "DELETED" {
		WriteError(w, http.StatusConflict, ErrFileAlreadyDeleted, "file is already deleted", nil, "", nil)
		return
	}

	// Soft-delete only: chunk_assignments/files rows are never physically
	// removed here — see this file's MARKS_PENDING_DELETION_NOT_HARD_DELETE
	// VERIFY intent. Every non-terminal assignment for this file's segments
	// is marked PENDING_DELETION in one statement.
	res, err := h.db.ExecContext(ctx, `
		UPDATE chunk_assignments
		SET status = 'PENDING_DELETION'
		WHERE segment_id IN (SELECT segment_id FROM segments WHERE file_id = $1)
		  AND status NOT IN ('PENDING_DELETION', 'DELETED')`,
		fileID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to mark assignments for deletion", nil, "", nil)
		return
	}
	assignmentsMarked64, err := res.RowsAffected()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to count marked assignments", nil, "", nil)
		return
	}
	assignmentsMarked := int(assignmentsMarked64)

	if _, err := h.db.ExecContext(ctx, `UPDATE files SET status = 'DELETED' WHERE file_id = $1`, fileID); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to mark file deleted", nil, "", nil)
		return
	}

	notified, pending, err := h.countNotifiedProviders(ctx, fileID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to summarize provider notification", nil, "", nil)
		return
	}

	resp := fileDeleteResponseBody{
		FileID:            fileID,
		AssignmentsMarked: assignmentsMarked,
		ProvidersNotified: notified,
		ProvidersPending:  pending,
		Status:            "DELETED",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// countNotifiedProviders splits the distinct providers holding
// PENDING_DELETION assignments for fileID into "notified" (reachability
// proxy: heartbeat seen within HeartbeatInterval+HeartbeatJitter, so the
// pending_deletion flag will be picked up on that imminent next heartbeat —
// see this file's header for why no live P2P notification is attempted
// here) and "pending" (everyone else, retried on their next heartbeat per
// FR-020, whenever that is).
func (h *FileDeleteHandler) countNotifiedProviders(ctx context.Context, fileID uuid.UUID) (notified, pending int, err error) {
	reachabilityWindowSeconds := (h.profile.HeartbeatInterval + h.profile.HeartbeatJitter).Seconds()
	err = h.db.QueryRowContext(ctx, `
		SELECT
		    COUNT(*) FILTER (WHERE p.last_heartbeat_ts IS NOT NULL AND p.last_heartbeat_ts > NOW() - ($2 * INTERVAL '1 second')),
		    COUNT(*) FILTER (WHERE p.last_heartbeat_ts IS NULL OR p.last_heartbeat_ts <= NOW() - ($2 * INTERVAL '1 second'))
		FROM (
		    SELECT DISTINCT provider_id
		    FROM chunk_assignments
		    WHERE segment_id IN (SELECT segment_id FROM segments WHERE file_id = $1)
		      AND status = 'PENDING_DELETION'
		) marked
		JOIN providers p ON p.provider_id = marked.provider_id`,
		fileID, reachabilityWindowSeconds,
	).Scan(&notified, &pending)
	return notified, pending, err
}

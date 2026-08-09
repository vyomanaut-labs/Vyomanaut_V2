// Package manage is declared in doc.go.
// This file implements the file list view (TASK step 1, FR-019): fetches
// GET /api/v1/owner/{owner_id}/files, decrypts display_name_ciphertext
// locally when present (falling back to the file_id string when absent),
// and renders the availability enum through AvailabilityLabel — never the
// raw enum string directly.
//
// Also declares this package's small authenticated-JSON HTTP client — a
// package-local twin of internal/client/upload's own apiClient (Session
// 15.2.1) and internal/client/retrieve's own copy (Session 15.3.1); see
// upload/assign.go's header comment for why no shared HTTP-client
// convention exists anywhere else in this codebase to import instead.
//
// [REF: FR-019, OAS FileListItem, listOwnerFiles, MVP §8.2 Phase 15.4
// Session 15.4.1]

package manage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"

	"github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
)

// ── Shared authenticated-JSON HTTP client (package-local twin) ────────────

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newAPIClient(baseURL, token string, httpClient *http.Client) *apiClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &apiClient{baseURL: baseURL, token: token, http: httpClient}
}

type apiError struct {
	ErrorCode  string `json:"error_code"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
	RetryAfter *int   `json:"retry_after"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s: %s (request_id=%s)", e.ErrorCode, e.Message, e.RequestID)
}

func (c *apiClient) doJSON(ctx context.Context, method, path string, reqBody, out any) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, nil, fmt.Errorf("manage: doJSON: encode request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("manage: doJSON: build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("manage: doJSON: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("manage: doJSON: read response body: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp, respBody, fmt.Errorf("manage: doJSON: decode response: %w", err)
		}
	}
	return resp, respBody, nil
}

func decodeAPIError(body []byte) *apiError {
	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err != nil || apiErr.ErrorCode == "" {
		return nil
	}
	return &apiErr
}

// Manager provides file-list, delete, and (Session 15.4.2) escrow calls.
type Manager struct {
	api *apiClient
}

// NewManager constructs a Manager.
func NewManager(baseURL, token string, httpClient *http.Client) *Manager {
	return &Manager{api: newAPIClient(baseURL, token, httpClient)}
}

// ── AvailabilityLabel ────────────────────────────────────────────────────

// AvailabilityLabel maps the API's raw Availability enum (OK/DEGRADED/
// CRITICAL) to data-owner-facing copy — never render the raw enum string
// directly.
//
// PRECONDITION (per this session's own TASK text): IC §14.2 is not yet
// merged into interface-contracts.md — filed locally as
// interface-contracts-section-14.md, pending push. Until it merges, this
// function is a placeholder pass-through (each enum value maps to itself),
// so applying the real mapping later is a one-file diff to this function
// body, not a re-implementation of every call site.
//
// [Note for review] This session's own reference material already includes
// what appears to be IC §14.2's full, apparently-finished content — quite
// possibly the very "pending push" file this precondition refers to. Left
// as a placeholder here anyway rather than silently landing content this
// session cannot itself confirm is approved; the real mapping, ready to
// swap in once confirmed, is:
//
//	OK       -> "Available"
//	DEGRADED -> "Degraded — repair in progress"
//	CRITICAL -> "Temporarily unavailable — emergency repair in progress"
func AvailabilityLabel(status string) string {
	switch status {
	case "OK", "DEGRADED", "CRITICAL":
		return status // placeholder pass-through — see doc comment
	default:
		return status
	}
}

// ── GET /api/v1/owner/{owner_id}/files ─────────────────────────────────────

type fileListItem struct {
	FileID                uuid.UUID `json:"file_id"`
	OriginalSizeBytes     int64     `json:"original_size_bytes"`
	UploadedAt            time.Time `json:"uploaded_at"`
	MonthlyCostPaise      int64     `json:"monthly_cost_paise"`
	Status                string    `json:"status"`
	Availability          string    `json:"availability"`
	AvailableShardCount   int       `json:"available_shard_count"`
	TotalShardCount       int       `json:"total_shard_count"`
	DisplayNameCiphertext *string   `json:"display_name_ciphertext,omitempty"`
	DisplayNameNonce      *string   `json:"display_name_nonce,omitempty"`
	DisplayNameTag        *string   `json:"display_name_tag,omitempty"`
}

type fileListResponse struct {
	Files []fileListItem `json:"files"`
}

// FileEntry is this package's rendered form of one file-list row: a
// decrypted (or fallback) display name and a label-mapped availability,
// ready to print.
type FileEntry struct {
	FileID            uuid.UUID
	DisplayName       string // decrypted name, or the file_id string when absent
	SizeBytes         int64
	UploadedAt        time.Time
	MonthlyCostPaise  int64
	AvailabilityLabel string
}

// ListFiles calls GET /api/v1/owner/{owner_id}/files and renders each row.
func (m *Manager) ListFiles(ctx context.Context, masterSecret [32]byte, ownerID uuid.UUID) ([]FileEntry, error) {
	var resp fileListResponse
	httpResp, rawBody, err := m.api.doJSON(ctx, http.MethodGet, "/api/v1/owner/"+ownerID.String()+"/files", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("manage: ListFiles: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return nil, fmt.Errorf("manage: ListFiles: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return nil, fmt.Errorf("manage: ListFiles: unexpected status %d", httpResp.StatusCode)
	}

	entries := make([]FileEntry, len(resp.Files))
	for i, f := range resp.Files {
		name := f.FileID.String() // fallback when no display name is present or decryption fails
		if f.DisplayNameCiphertext != nil && f.DisplayNameNonce != nil && f.DisplayNameTag != nil {
			if decrypted, err := decryptDisplayName(masterSecret, ownerID, f.FileID, *f.DisplayNameCiphertext, *f.DisplayNameNonce, *f.DisplayNameTag); err == nil {
				name = decrypted
			}
			// A decrypt failure (corrupted block, wrong master secret for
			// this row) falls back to the file_id string rather than
			// failing the whole list — one bad row should not hide every
			// other file from the owner.
		}
		entries[i] = FileEntry{
			FileID:            f.FileID,
			DisplayName:       name,
			SizeBytes:         f.OriginalSizeBytes,
			UploadedAt:        f.UploadedAt,
			MonthlyCostPaise:  f.MonthlyCostPaise,
			AvailabilityLabel: AvailabilityLabel(f.Availability),
		}
	}
	return entries, nil
}

// deriveFilenameKey derives the display-name AEAD key:
//
//	key = HKDF-SHA256(ikm=masterSecret, salt=ownerID, info="vyomanaut-filename-v1"||fileID)
//
// A package-local twin of internal/client/upload/pointer.go's own
// deriveFilenameKey (Session 15.2.1, same derivation used to encrypt this
// same field at upload time) — see that file's header comment on why
// internal/crypto has no exported DeriveFilenameKey to call instead.
func deriveFilenameKey(masterSecret, ownerID, fileID []byte) [32]byte {
	const prefix = "vyomanaut-filename-v1"
	info := make([]byte, 0, len(prefix)+len(fileID))
	info = append(info, prefix...)
	info = append(info, fileID...)
	r := hkdf.New(sha256.New, masterSecret, ownerID, info)
	var out [32]byte
	_, _ = r.Read(out[:]) // hkdf.Reader over SHA-256 never errors for a 32-byte read
	return out
}

// filenameAAD mirrors the AAD upload/pointer.go used when encrypting the
// display name (ownerID || fileID || schema_version) — decryption fails
// closed if this does not match exactly.
func filenameAAD(ownerID, fileID uuid.UUID) []byte {
	const pointerFileSchemaVersion = 1
	aad := make([]byte, 0, 16+16+4)
	aad = append(aad, ownerID[:]...)
	aad = append(aad, fileID[:]...)
	var schemaVersionBytes [4]byte
	binary.BigEndian.PutUint32(schemaVersionBytes[:], pointerFileSchemaVersion)
	aad = append(aad, schemaVersionBytes[:]...)
	return aad
}

func decryptDisplayName(masterSecret [32]byte, ownerID, fileID uuid.UUID, ciphertextB64, nonceB64, tagB64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decode display_name_ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil || len(nonce) != 12 {
		return "", fmt.Errorf("malformed display_name_nonce")
	}
	tag, err := base64.StdEncoding.DecodeString(tagB64)
	if err != nil || len(tag) != 16 {
		return "", fmt.Errorf("malformed display_name_tag")
	}
	var nonceArr [12]byte
	copy(nonceArr[:], nonce)
	full := append(append([]byte{}, ciphertext...), tag...)

	key := deriveFilenameKey(masterSecret[:], ownerID[:], fileID[:])
	plain, err := crypto.DecryptAEAD(key, nonceArr, filenameAAD(ownerID, fileID), full)
	if err != nil {
		return "", fmt.Errorf("decrypt display name: %w", err)
	}
	return string(plain), nil
}
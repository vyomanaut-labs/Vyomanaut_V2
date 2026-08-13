// Package upload is declared in doc.go.
// This file implements the assignment request (TASK step 3) and the small
// authenticated-JSON HTTP helper the rest of this package's REST calls
// (pointer.go's file/register call) share.
//
// [Design note] No client-side outbound HTTP pattern exists anywhere else
// in this codebase yet (checked cmd/provider, cmd/microservice,
// internal/payment before writing this — all HTTP client code found is
// server-side JWT issuance/validation, not a REST client). apiClient below
// is therefore authored fresh for this package, not copied from an
// existing convention. It is intentionally NOT a new top-level package
// (mvp.md §8.2's FILES inventory — A-7 — does not list one), so it lives
// here as this package's own unexported helper, in the same "package-local
// rather than a new shared package" spirit as vettingchunk's
// resolveProviderPeer twin (Milestone 14).
//
// [REF: OAS /api/v1/upload/assign, IC §5.9 pre-conditions, ADR-016,
// ADR-073, MVP §8.2 Phase 15.2 Session 15.2.1, FR-009, FR-014]

package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
)

// ── Shared authenticated-JSON HTTP client ──────────────────────────────────

// apiClient holds what every REST call in this package needs: the
// microservice base URL and the bearer JWT already obtained via the
// phone/OTP registration flow (not built by this package — see register.go
// in internal/client/account for the equivalent local-crypto half of
// account creation, and this file's header comment on why no such flow
// exists yet anywhere in this codebase).
type apiClient struct {
	baseURL string
	token   string // sent as `Authorization: Bearer <token>` (OAS BearerAuth)
	http    *http.Client
}

// newAPIClient constructs an apiClient. httpClient may be nil, in which
// case http.DefaultClient is used.
func newAPIClient(baseURL, token string, httpClient *http.Client) *apiClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &apiClient{baseURL: baseURL, token: token, http: httpClient}
}

// apiError mirrors the OAS Error schema. Its Error() method is used only
// for logging/wrapping; callers that need to branch on error_code compare
// ErrorCode directly rather than parsing Error()'s string.
type apiError struct {
	ErrorCode  string `json:"error_code"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
	RetryAfter *int   `json:"retry_after"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s: %s (request_id=%s)", e.ErrorCode, e.Message, e.RequestID)
}

// doJSON POSTs/DELETEs/GETs reqBody (nil for no body) as JSON to path and,
// on a 2xx response, decodes the response body into out (nil to discard
// it). It returns the raw *http.Response on any response the server
// actually sent, so callers can branch on StatusCode for the
// endpoint-specific error mapping (409/503/etc.) documented at each call
// site — doJSON itself does not interpret status codes beyond reading the
// body. The returned response's body is always fully drained and closed
// before doJSON returns; callers must not read httpResp.Body themselves.
func (c *apiClient) doJSON(ctx context.Context, method, path string, reqBody, out any) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, nil, fmt.Errorf("upload: doJSON: encode request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("upload: doJSON: build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("upload: doJSON: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("upload: doJSON: read response body: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 && out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp, respBody, fmt.Errorf("upload: doJSON: decode response: %w", err)
		}
	}
	return resp, respBody, nil
}

// decodeAPIError best-effort decodes an OAS Error envelope from a non-2xx
// response body. Returns nil if the body isn't a well-formed Error object
// (callers fall back to a generic status-code-only error in that case).
func decodeAPIError(body []byte) *apiError {
	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err != nil || apiErr.ErrorCode == "" {
		return nil
	}
	return &apiErr
}

// ── POST /api/v1/upload/assign ─────────────────────────────────────────────

// uploadAssignRequest mirrors OAS UploadAssignRequest.
type uploadAssignRequest struct {
	FileID            uuid.UUID `json:"file_id"`
	NumSegments       int       `json:"num_segments"`
	OriginalSizeBytes int64     `json:"original_size_bytes"`

	// Segments carries this call's real, already-computed content-hash
	// chunk_id per shard for one or more segments (ADR-073) — the client's
	// own chunk_id computation, never a server-generated value; see
	// requestAssignment and buildSegmentChunkIDRequests below for how this
	// is populated per call.
	Segments []segmentChunkIDsRequest `json:"segments"`
}

// segmentChunkIDsRequest mirrors OAS's per-segment chunk_ids addition
// (ADR-073) — one segment's real content-hash chunk_id per shard,
// shard_index order, hex-encoded.
type segmentChunkIDsRequest struct {
	SegmentIndex int      `json:"segment_index"`
	ChunkIDs     []string `json:"chunk_ids"`
}

// shardAssignment mirrors OAS ShardAssignment, including the
// server-issued capability_token (ERRATA-001, IC §4.1) — never re-derived
// client-side; see transfer.go for where this is used verbatim. ChunkID
// is the server's echo of what this package submitted in Segments above
// — decoded and defensively checked (transfer.go's pendingTasks) against
// this package's own SessionState.ChunkIDs record, never used as the
// wire chunk_id in place of it; see ADR-073 for why this package, not the
// server, is chunk_id's source of truth.
type shardAssignment struct {
	ShardIndex      int       `json:"shard_index"`
	ProviderID      uuid.UUID `json:"provider_id"`
	Multiaddrs      []string  `json:"multiaddrs"`
	ASN             string    `json:"asn"`
	CapabilityToken string    `json:"capability_token"` // 144 hex chars = 72 bytes
	ChunkID         string    `json:"chunk_id"`
}

// segmentAssignment mirrors OAS SegmentAssignment.
type segmentAssignment struct {
	SegmentIndex int               `json:"segment_index"`
	SegmentID    uuid.UUID         `json:"segment_id"`
	Providers    []shardAssignment `json:"providers"`
}

// uploadAssignResponse mirrors OAS UploadAssignResponse.
type uploadAssignResponse struct {
	Assignments         []segmentAssignment `json:"assignments"`
	MonthlyCostPaise    int64               `json:"monthly_cost_paise"`
	RequiredEscrowPaise int64               `json:"required_escrow_paise"`
}

// buildSegmentChunkIDRequests converts a (possibly partial) chunkIDs slice
// into the wire Segments shape — chunkIDs[i] == nil means segment i has
// not been encoded yet and is omitted from the request entirely (ADR-073:
// a segment's chunk_id cannot exist before that segment is encoded, so
// there is nothing to submit for it yet). UploadFile's per-segment loop
// passes a slice that fills in left-to-right as encoding proceeds;
// transferAll's CAPABILITY_EXPIRED retry and ResumeUpload pass a fully
// populated slice (every segment already encoded by the time either runs).
func buildSegmentChunkIDRequests(chunkIDs [][][32]byte) []segmentChunkIDsRequest {
	var out []segmentChunkIDsRequest
	for i, ids := range chunkIDs {
		if ids == nil {
			continue
		}
		hexIDs := make([]string, len(ids))
		for j, id := range ids {
			hexIDs[j] = fmt.Sprintf("%x", id)
		}
		out = append(out, segmentChunkIDsRequest{SegmentIndex: i, ChunkIDs: hexIDs})
	}
	return out
}

// requestAssignment calls POST /api/v1/upload/assign, submitting the
// caller's real, already-computed chunk_ids for whichever segments
// chunkIDs has populated (ADR-073 — see buildSegmentChunkIDRequests).
// Idempotent on file_id per the OAS's own description, extended by
// ADR-073 to be idempotent per-segment too: a segment already persisted
// server-side from an earlier call is never re-derived, only
// token-refreshed; the response always contains every segment persisted
// so far for fileID, not just the ones named in chunkIDs this call.
//
// Error semantics:
//   - ErrNetworkNotReady: HTTP 503, error_code NETWORK_NOT_READY (readiness
//     gate closed) — also covers the distinct INSUFFICIENT_ASN_DIVERSITY
//     503 sub-case (OAS): both are "not ready yet, retry later" from this
//     orchestrator's point of view, and IC §5.9 defines only one sentinel
//     for HTTP 503 here.
//   - ErrInsufficientEscrow: HTTP 409 (IC §5.9's own pre-condition — the
//     30-day escrow check is enforced server-side, not re-implemented
//     client-side).
func (o *Orchestrator) requestAssignment(ctx context.Context, fileID uuid.UUID, numSegments int, originalSizeBytes int64, chunkIDs [][][32]byte) (*uploadAssignResponse, error) {
	reqBody := uploadAssignRequest{
		FileID:            fileID,
		NumSegments:       numSegments,
		OriginalSizeBytes: originalSizeBytes,
		Segments:          buildSegmentChunkIDRequests(chunkIDs),
	}
	var respBody uploadAssignResponse
	httpResp, rawBody, err := o.api.doJSON(ctx, http.MethodPost, "/api/v1/upload/assign", reqBody, &respBody)
	if err != nil {
		return nil, fmt.Errorf("upload: requestAssignment: %w", err)
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		return &respBody, nil
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("upload: requestAssignment: %w", ErrNetworkNotReady)
	case http.StatusConflict:
		return nil, fmt.Errorf("upload: requestAssignment: %w", ErrInsufficientEscrow)
	default:
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return nil, fmt.Errorf("upload: requestAssignment: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return nil, fmt.Errorf("upload: requestAssignment: unexpected status %d", httpResp.StatusCode)
	}
}
